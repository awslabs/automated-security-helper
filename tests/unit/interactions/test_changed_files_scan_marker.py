# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan filtered to changed files says so on its results.

--changed-files-only keeps only the findings in files that changed against
--base-ref. A reporter that infers "fixed" from "not reported" -- the
aws-security-hub reporter archives findings a scan no longer produces -- must
not read the findings left out by that filter as fixed. Nothing on the results
model said the filter had run, so ``metadata.changed_files_only`` is set
on every scan, in single-directory mode and per workspace project: True when a
changed-file set was computed, False otherwise, including when the flag fell back
to a full scan (no git repository, or git could not answer), because then nothing
was left out. Explicit False lets a consumer tell a full scan from results that
predate the marker.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.core.exceptions import ScannerSelectionError
from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    _run_local_mode,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.workspace.execution import (
    ProjectScanSettings,
    execute_workspace,
)
from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan

pytestmark = pytest.mark.unit

#: The variables that make a scan record the container launcher's label. Unset
#: for every test, so the suite gives the same answers when it runs inside the
#: ASH image (which sets ASH_IN_CONTAINER); the container tests set them.
_CONTAINER_VARIABLES = ("ASH_IN_CONTAINER", "ASH_SCAN_SOURCE", "ASH_ACTUAL_SOURCE_DIR")


@pytest.fixture(autouse=True)
def _no_container_variables(monkeypatch):
    for name in _CONTAINER_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    # These tests stand in for git with a fixed root under tmp_path, and are
    # about what reaches the metadata, so the enclosing-repository check (which
    # reads the real filesystem above tmp_path) is stood in for too; it has its
    # own tests in tests/unit/utils/test_scan_source.py.
    monkeypatch.setattr(
        "automated_security_helper.utils.scan_source.repository_is_nested",
        lambda root: False,
    )


def _in_the_launchers_container(monkeypatch, label=None):
    monkeypatch.setenv("ASH_IN_CONTAINER", "YES")
    monkeypatch.setenv("ASH_ACTUAL_SOURCE_DIR", "/host/checkout")
    if label is not None:
        monkeypatch.setenv("ASH_SCAN_SOURCE", label)


def _orchestrator_metadata(opts) -> object:
    """Run single-directory local mode and return the metadata it gave the orchestrator.

    Both halves: what it handed ``create`` (nothing), and what it added once
    ``create`` had returned (``changed_files_only`` and ``scan_source``; see
    test_the_scanned_directory_is_worked_out_only_once_the_orchestrator_is_built).
    """
    orchestrator = MagicMock()
    orchestrator.execute_scan.return_value = AshAggregatedResults()
    orchestrator.config.fail_on_findings = False
    create = MagicMock(return_value=orchestrator)
    with patch(
        "automated_security_helper.core.orchestrator.ASHScanOrchestrator.create",
        create,
    ):
        with patch(
            "automated_security_helper.interactions.run_ash_scan.write_text_atomically"
        ):
            _run_local_mode(opts, MagicMock())
    metadata = dict(create.call_args.kwargs.get("metadata") or {})
    for added in orchestrator.add_metadata.call_args_list:
        assert not added.args, added
        metadata.update(added.kwargs)
    return metadata


def _repository_at(root: Path) -> Path:
    """*root*, holding a .git entry as a repository root does, for a stand-in git
    that names it as the root."""
    root.mkdir(parents=True, exist_ok=True)
    (root / ".git").mkdir()
    return root


def test_a_changed_files_scan_is_marked(tmp_path, monkeypatch):
    source = _repository_at(tmp_path / "repo")
    monkeypatch.setattr(
        "automated_security_helper.utils.get_scan_set.git_repository_root",
        lambda path, **kwargs: source,
    )
    monkeypatch.setattr(
        "automated_security_helper.utils.get_scan_set.get_changed_files",
        lambda base_ref, cwd: ["app.py"],
    )
    opts = ScanOptions(
        source_dir=source, output_dir=tmp_path / "out", changed_files_only=True
    )

    assert _orchestrator_metadata(opts) == {
        "changed_files_only": True,
        "scan_source": ".",
    }


def test_a_full_scan_is_marked_as_not_filtered(tmp_path, monkeypatch):
    """Explicit False, so a consumer can tell a full scan from results that
    predate the marker."""
    source = _repository_at(tmp_path / "repo")
    monkeypatch.setattr(
        "automated_security_helper.utils.get_scan_set.git_repository_root",
        lambda path, **kwargs: source,
    )
    opts = ScanOptions(source_dir=source, output_dir=tmp_path / "out")

    assert _orchestrator_metadata(opts) == {
        "changed_files_only": False,
        "scan_source": ".",
    }


def test_a_changed_files_request_that_fell_back_to_a_full_scan_is_marked_as_not_filtered(
    tmp_path, monkeypatch
):
    source = tmp_path / "repo"
    source.mkdir()
    monkeypatch.setattr(
        "automated_security_helper.utils.get_scan_set.git_repository_root",
        lambda path, **kwargs: None,
    )
    opts = ScanOptions(
        source_dir=source, output_dir=tmp_path / "out", changed_files_only=True
    )

    assert _orchestrator_metadata(opts) == {
        "changed_files_only": False,
        "scan_source": source.resolve().as_posix(),
    }


def test_the_scan_records_the_scanned_directory_within_its_repository(
    tmp_path, monkeypatch
):
    """Recorded while the directory exists, so a report made where it does not
    (ash merge on a collector, ash report elsewhere) reads the scan's answer."""
    repo = _repository_at(tmp_path / "repo")
    source = repo / "services" / "api"
    source.mkdir(parents=True)
    monkeypatch.setattr(
        "automated_security_helper.utils.get_scan_set.git_repository_root",
        lambda path, **kwargs: repo,
    )
    opts = ScanOptions(source_dir=source, output_dir=tmp_path / "out")

    assert _orchestrator_metadata(opts)["scan_source"] == "services/api"


def test_the_scanned_directory_is_worked_out_only_once_the_orchestrator_is_built(
    tmp_path, monkeypatch
):
    """Finding the repository starts git, so it waits for ``create`` to return.

    ``create`` is where a scanner selection that cancels itself, or an invalid
    configuration, stops the command, and a command line ASH refuses starts no
    process (test_usage_error_exit_code checks that from the CLI). The directory
    holds a .git entry, so its root is one git would be asked for.
    """
    source = _repository_at(tmp_path / "repo")
    asked = []

    def _root(path):
        asked.append(path)
        return source

    monkeypatch.setattr(
        "automated_security_helper.utils.get_scan_set.git_repository_root", _root
    )
    create = MagicMock(
        side_effect=ScannerSelectionError("--exclude-scanners cancels --scanners")
    )
    with patch(
        "automated_security_helper.core.orchestrator.ASHScanOrchestrator.create",
        create,
    ):
        with pytest.raises(SystemExit):
            _run_local_mode(
                ScanOptions(source_dir=source, output_dir=tmp_path / "out"),
                MagicMock(),
            )

    create.assert_called_once()
    assert asked == []


def test_inside_the_container_the_launchers_label_is_recorded(tmp_path, monkeypatch):
    """The container mounts the source at /src, where git often cannot see the
    repository; the host worked the label out and passed it in."""
    source = tmp_path / "src"
    source.mkdir()
    _in_the_launchers_container(monkeypatch, label="services/api")
    monkeypatch.setattr(
        "automated_security_helper.utils.get_scan_set.git_repository_root",
        lambda path, **kwargs: None,
    )
    opts = ScanOptions(source_dir=source, output_dir=tmp_path / "out")

    assert _orchestrator_metadata(opts)["scan_source"] == "services/api"


def test_inside_the_container_without_a_label_nothing_is_recorded(
    tmp_path, monkeypatch
):
    """As the legacy ./ash and Invoke-ASH wrappers start it: no label. Not
    "/src", which every such container scan would share as one scope, and not
    what git in the container says, which sees only the mount (a nested clone's
    mount reads as a repository root)."""
    source = tmp_path / "src"
    source.mkdir()
    _in_the_launchers_container(monkeypatch)
    monkeypatch.setattr(
        "automated_security_helper.utils.get_scan_set.git_repository_root",
        lambda path, **kwargs: source,
    )
    opts = ScanOptions(source_dir=source, output_dir=tmp_path / "out")

    assert _orchestrator_metadata(opts)["scan_source"] is None


def test_the_image_as_a_ci_job_image_records_the_directory_as_a_host_would(
    tmp_path, monkeypatch
):
    """A GitLab `image:` or GitHub `container:` run of the ASH image sets
    ASH_IN_CONTAINER but is not the launcher's: no label, and no /src mount."""
    source = tmp_path / "builds" / "group" / "project"
    source.mkdir(parents=True)
    monkeypatch.setenv("ASH_IN_CONTAINER", "YES")
    monkeypatch.setattr(
        "automated_security_helper.utils.get_scan_set.git_repository_root",
        lambda path, **kwargs: None,
    )
    opts = ScanOptions(source_dir=source, output_dir=tmp_path / "out")

    assert _orchestrator_metadata(opts)["scan_source"] == source.resolve().as_posix()


class _RecordingOrchestrator:
    seen: dict = {}

    def __init__(self, **kwargs):
        _RecordingOrchestrator.seen[Path(kwargs["source_dir"]).name] = kwargs.get(
            "metadata"
        )

    @classmethod
    def create(cls, **kwargs):
        return cls(**kwargs)

    def execute_scan(self, phases=None):
        model = AshAggregatedResults()
        model.sarif = SarifReport.model_validate({"version": "2.1.0", "runs": []})
        return model


def _one_project_plan(root: Path) -> WorkspacePlan:
    root.mkdir(parents=True)
    (root / "fixture.code-workspace").write_text(
        json.dumps({"folders": [{"path": "api"}]}), encoding="utf-8"
    )
    (root / "api").mkdir()
    return WorkspacePlan(
        workspace_file=(root / "fixture.code-workspace").as_posix(),
        workspace_root=root.as_posix(),
        projects=[
            ProjectPlan(
                key="api",
                relative_path="api",
                path=(root / "api").as_posix(),
                label="api",
                display_label="api",
                severity_threshold="MEDIUM",
            )
        ],
    )


def test_a_workspace_project_scanned_by_diff_is_marked(tmp_path, monkeypatch):
    root = tmp_path / "ws"
    plan = _one_project_plan(root)
    _repository_at(root)
    monkeypatch.setattr(
        "automated_security_helper.workspace.execution.git_repository_root",
        lambda path, **kwargs: root,
    )
    monkeypatch.setattr(
        "automated_security_helper.workspace.execution.get_changed_files",
        lambda base_ref, cwd: ["api/app.py"],
    )
    _RecordingOrchestrator.seen = {}

    execute_workspace(
        plan,
        ProjectScanSettings(
            output_dir=tmp_path / "out", phases=("scan",), changed_files_only=True
        ),
        orchestrator_factory=_RecordingOrchestrator.create,
    )

    assert _RecordingOrchestrator.seen["api"] == {
        "project_name": "api",
        "workspace_project": "api",
        "changed_files_only": True,
        "scan_source": "api",
    }


def test_a_workspace_project_scanned_in_full_is_marked_as_not_filtered(
    tmp_path, monkeypatch
):
    plan = _one_project_plan(tmp_path / "ws")
    monkeypatch.setattr(
        "automated_security_helper.workspace.execution.git_repository_root",
        lambda path, **kwargs: None,
    )
    _RecordingOrchestrator.seen = {}

    execute_workspace(
        plan,
        ProjectScanSettings(output_dir=tmp_path / "out", phases=("scan",)),
        orchestrator_factory=_RecordingOrchestrator.create,
    )

    assert _RecordingOrchestrator.seen["api"] == {
        "project_name": "api",
        "workspace_project": "api",
        "changed_files_only": False,
        "scan_source": (tmp_path / "ws" / "api").resolve().as_posix(),
    }


def test_a_workspace_project_in_the_container_never_takes_the_mount_label(
    tmp_path, monkeypatch
):
    """The launcher's label names the single-directory mount. A workspace project
    records its own directory, as git in the container sees it, or nothing."""
    root = tmp_path / "ws"
    plan = _one_project_plan(root)
    _repository_at(root)
    _in_the_launchers_container(monkeypatch, label=".")
    monkeypatch.setattr(
        "automated_security_helper.workspace.execution.git_repository_root",
        lambda path, **kwargs: root,
    )
    _RecordingOrchestrator.seen = {}

    execute_workspace(
        plan,
        ProjectScanSettings(output_dir=tmp_path / "out", phases=("scan",)),
        orchestrator_factory=_RecordingOrchestrator.create,
    )

    assert _RecordingOrchestrator.seen["api"]["scan_source"] == "api"


def test_a_workspace_project_under_a_mount_that_is_no_repository_root_records_nothing(
    tmp_path, monkeypatch
):
    """The host passed "" (a nested root, or no repository): git in the
    container, which sees only the mount, would still call the project "api"."""
    root = tmp_path / "ws"
    plan = _one_project_plan(root)
    _in_the_launchers_container(monkeypatch, label="")
    monkeypatch.setattr(
        "automated_security_helper.workspace.execution.git_repository_root",
        lambda path, **kwargs: root,
    )
    _RecordingOrchestrator.seen = {}

    execute_workspace(
        plan,
        ProjectScanSettings(output_dir=tmp_path / "out", phases=("scan",)),
        orchestrator_factory=_RecordingOrchestrator.create,
    )

    assert _RecordingOrchestrator.seen["api"]["scan_source"] is None
