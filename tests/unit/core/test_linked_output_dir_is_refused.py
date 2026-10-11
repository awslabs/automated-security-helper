# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A symlinked output directory is refused whatever the sandbox mode.

That covers the output directory itself, the ``analysis``, ``reports``,
``scanners`` and ``converted`` directories under it, and the files ASH writes there
by a fixed name (the logs and the results files), in single-directory, workspace,
container, nix and MCP scans. ASH clears those directories before a scan and writes
into them, and a sandbox mounts the output directory, so a link at any of them sends
the deletions and the writes wherever it points. The error names the link and tells
the operator to pass ``--output-dir``; MCP callers get a remedy they can act on.

Components above the output directory and outside the scanned tree are the
operator's own spelling (macOS's ``/tmp``, a home directory that links
elsewhere) and stay allowed; the controls below show that.

Where a test calls code that writes or deletes, the link points at a "host"
directory holding a marker file, and the test checks the directory is unchanged.
Where the code under test only reads, the assertion is on the refusal itself.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import RunMode
from automated_security_helper.core.exceptions import ASHValidationError
from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils import output_dir_links
from automated_security_helper.utils.output_dir_links import (
    OutputDirLinkRefused,
    linked_output_component,
)

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

# Spelled out rather than imported from the module, so that a name dropped from the
# module's lists fails here instead of dropping out of the test with it.
WORKING_DIRS = ("analysis", "reports", "scanners", "converted")
RESULT_FILES = (
    "ash_aggregated_results.json",
    "ash-ignore-report.txt",
    "ash-scan-set-files-list.txt",
)
LOG_FILES = ("ash.log", "ash.log.jsonl")


def open_no_follow(*args, **kwargs):
    return output_dir_links.open_no_follow(*args, **kwargs)


needs_symlinks = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)


@pytest.fixture
def layout(tmp_path):
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "app.py").write_text("print('hello')\n")
    host = tmp_path / "host"
    host.mkdir()
    (host / "keep.txt").write_text("host file\n")
    return SimpleNamespace(root=tmp_path, tree=tree, host=host)


def _untouched(host: Path) -> bool:
    return sorted(p.relative_to(host).as_posix() for p in host.rglob("*")) == [
        "keep.txt"
    ]


def _linked_output(layout) -> Path:
    """An output directory outside the tree that is itself a link."""
    output = layout.root / "out-link"
    output.symlink_to(layout.host, target_is_directory=True)
    return output


def _linked_entry(layout, name: str) -> Path:
    """A real output directory with one directory or file under it a link."""
    output = layout.root / "out"
    output.mkdir()
    (output / name).symlink_to(layout.host / name, target_is_directory=True)
    return output


# ---------------------------------------------------------------------------
# ash scan: run_ash_scan's own check, called directly
# ---------------------------------------------------------------------------


def _refuse(opts):
    from automated_security_helper.interactions import run_ash_scan

    printed: list = []
    with patch.object(
        run_ash_scan, "print", lambda *args, **_: printed.append(" ".join(args))
    ):
        with pytest.raises(run_ash_scan.OutputDirRefusedExit) as exited:
            run_ash_scan._refuse_symlinked_output_dir(opts)
    return exited.value, " ".join(printed)


def _options(layout, output: Path, mode: RunMode = RunMode.local, **kwargs):
    from automated_security_helper.interactions.run_ash_scan import ScanOptions

    return ScanOptions(
        source_dir=kwargs.pop("source_dir", layout.tree),
        output_dir=output,
        mode=mode,
        config_overrides=[f"sandbox.mode={kwargs.pop('sandbox', 'off')}"],
        **kwargs,
    )


MODES = [RunMode.local, RunMode.container, RunMode.nix]


@needs_symlinks
class TestTheScanCommandsCheck:
    @pytest.mark.parametrize("sandbox", ["off", "bwrap"])
    def test_a_linked_output_directory_is_refused(self, layout, sandbox):
        exited, printed = _refuse(
            _options(layout, _linked_output(layout), sandbox=sandbox)
        )

        assert exited.code == 1
        assert "out-link is a symlink" in exited.found
        assert "--output-dir" in exited.reason
        assert "--output-dir" in printed

    @pytest.mark.parametrize("name", WORKING_DIRS)
    def test_a_linked_working_directory_is_refused(self, layout, name):
        output = _linked_entry(layout, name)

        exited, _ = _refuse(_options(layout, output))

        assert f"{name} is a symlink" in exited.found

    @pytest.mark.parametrize("name", RESULT_FILES + LOG_FILES)
    def test_a_linked_file_ash_writes_there_is_refused(self, layout, name):
        output = layout.root / "out"
        output.mkdir()
        (output / name).symlink_to(layout.host / "keep.txt")

        exited, _ = _refuse(_options(layout, output))

        assert f"{name} is a symlink" in exited.found

    def test_a_link_in_the_tree_on_the_way_is_refused(self, layout):
        (layout.tree / ".ash").symlink_to(layout.host, target_is_directory=True)

        exited, _ = _refuse(_options(layout, layout.tree / ".ash" / "ash_output"))

        assert ".ash is a symlink" in exited.found

    @pytest.mark.parametrize("name", ["projects", ".workspace-spool"])
    def test_a_workspace_runs_own_directories_are_checked(self, layout, name):
        from automated_security_helper.workspace.plan import WorkspacePlan

        output = _linked_entry(layout, name)
        plan = WorkspacePlan(
            workspace_file=(layout.tree / "w.code-workspace").as_posix(),
            workspace_root=layout.tree.as_posix(),
            projects=[],
        )

        exited, _ = _refuse(_options(layout, output, workspace_plan=plan))

        assert f"{name} is a symlink" in exited.found

    def test_the_operators_own_spelling_above_the_output_is_allowed(self, layout):
        """The control: a link above an output directory outside the tree."""
        from automated_security_helper.interactions.run_ash_scan import (
            _refuse_symlinked_output_dir,
        )

        real = layout.root / "real"
        (real / "out" / "scanners").mkdir(parents=True)
        (layout.root / "parent-link").symlink_to(real, target_is_directory=True)

        _refuse_symlinked_output_dir(
            _options(layout, layout.root / "parent-link" / "out")
        )

    def test_a_scanned_directory_spelled_through_a_link_is_allowed(self, layout):
        """The control: the scanned directory itself is the operator's spelling."""
        from automated_security_helper.interactions.run_ash_scan import (
            _refuse_symlinked_output_dir,
        )

        link_root = layout.root / "link-to-tree"
        link_root.symlink_to(layout.tree, target_is_directory=True)

        _refuse_symlinked_output_dir(
            _options(layout, link_root / ".ash" / "ash_output", source_dir=link_root)
        )
        assert linked_output_component(link_root, link_root / "out") is None

    def test_ordinary_output_directories_are_allowed(self, layout):
        from automated_security_helper.interactions.run_ash_scan import (
            _refuse_symlinked_output_dir,
        )

        existing = layout.root / "out"
        for name in WORKING_DIRS:
            (existing / name).mkdir(parents=True)
        for name in RESULT_FILES + LOG_FILES:
            (existing / name).write_text("previous run\n")

        _refuse_symlinked_output_dir(_options(layout, existing))
        _refuse_symlinked_output_dir(
            _options(layout, layout.tree / ".ash" / "ash_output")
        )


# ---------------------------------------------------------------------------
# run_ash_scan itself, in every mode: the check runs before anything writes
# ---------------------------------------------------------------------------


class _PastTheCheck(Exception):
    """Raised by the first step after the check, if a scan gets that far."""


@needs_symlinks
@pytest.mark.parametrize("mode", MODES, ids=lambda m: m.value)
def test_run_ash_scan_refuses_before_the_logger_or_the_clean_up(
    layout, mode, monkeypatch
):
    """The logger opens ash.log there, and container and nix mode rmtree reports/."""
    from automated_security_helper.interactions import run_ash_scan

    def past(*_args, **_kwargs):
        raise _PastTheCheck(mode.value)

    monkeypatch.setattr(run_ash_scan, "_setup_logger", past)
    monkeypatch.setattr(run_ash_scan, "_discard_prior_run_artifacts", past)
    monkeypatch.setattr(run_ash_scan, "print", lambda *a, **k: None)

    with pytest.raises(run_ash_scan.OutputDirRefusedExit) as exited:
        run_ash_scan.run_ash_scan(
            source_dir=layout.tree,
            output_dir=_linked_output(layout),
            mode=mode,
            show_summary=False,
        )

    assert "out-link is a symlink" in exited.value.found


@needs_symlinks
@pytest.mark.parametrize("mode", [RunMode.container, RunMode.nix])
def test_the_clean_up_itself_refuses_and_deletes_nothing(layout, mode):
    """Beside its rmtree, for a caller that skipped run_ash_scan's check."""
    from automated_security_helper.interactions import run_ash_scan

    (layout.host / "reports").mkdir()
    (layout.host / "reports" / "important.md").write_text("x")
    output = _linked_output(layout)

    with patch.object(run_ash_scan, "print", lambda *a, **k: None):
        with pytest.raises(run_ash_scan.OutputDirRefusedExit):
            run_ash_scan._discard_prior_run_artifacts(
                _options(layout, output, mode), logging.getLogger("test")
            )

    assert (layout.host / "reports" / "important.md").read_text() == "x"
    assert (layout.host / "keep.txt").exists()


# ---------------------------------------------------------------------------
# The orchestrator, for callers that do not come through ash scan
# ---------------------------------------------------------------------------


def _orchestrator(source_dir: Path, output_dir: Path) -> ASHScanOrchestrator:
    orchestrator = ASHScanOrchestrator(
        source_dir=source_dir,
        output_dir=output_dir,
        config_path=None,
        config_overrides=None,
        no_cleanup=False,
        metadata=None,
        ash_plugin_modules=[],
    )
    orchestrator.config = AshConfig(project_name="test")
    assert str(orchestrator.config.sandbox.mode).endswith("off")
    return orchestrator


@needs_symlinks
class TestTheOrchestrator:
    def test_a_linked_output_directory_is_refused_with_the_sandbox_off(self, layout):
        orchestrator = _orchestrator(layout.tree, _linked_output(layout))

        with pytest.raises(ASHValidationError, match="--output-dir"):
            orchestrator.ensure_directories()

        assert _untouched(layout.host)

    @pytest.mark.parametrize("name", WORKING_DIRS)
    def test_a_linked_working_directory_is_refused_and_left_in_place(
        self, layout, name
    ):
        (layout.host / name).mkdir()
        (layout.host / name / "keep.txt").write_text("host file\n")
        output = _linked_entry(layout, name)

        with pytest.raises(ASHValidationError, match=f"{name} is a symlink"):
            _orchestrator(layout.tree, output).ensure_directories()

        assert (output / name).is_symlink()
        assert (layout.host / name / "keep.txt").exists()

    def test_a_reused_results_run_is_refused_too(self, layout, tmp_path):
        """--use-existing writes reports/, so a linked reports/ is refused there."""
        output = _linked_entry(layout, "reports")
        orchestrator = _orchestrator(layout.tree, output)
        existing = tmp_path / "previous.json"
        existing.write_text("{}")
        orchestrator.existing_results_path = existing

        with pytest.raises(ASHValidationError, match="reports is a symlink"):
            orchestrator.ensure_directories()

        assert _untouched(layout.host)

    def test_a_link_made_after_the_clean_up_is_not_taken_for_the_directory(
        self, layout, monkeypatch
    ):
        """Between the rmtree and the mkdir, a link appears at the name."""
        from automated_security_helper.core import orchestrator as module

        output = layout.root / "out"
        (output / "scanners").mkdir(parents=True)
        real_rmtree = shutil.rmtree

        def rmtree_then_link(path, *args, **kwargs):
            real_rmtree(path, *args, **kwargs)
            if Path(path).name == "scanners":
                Path(path).symlink_to(layout.host, target_is_directory=True)

        monkeypatch.setattr(module.shutil, "rmtree", rmtree_then_link)

        with pytest.raises(ASHValidationError):
            _orchestrator(layout.tree, output).ensure_directories()

        assert _untouched(layout.host)


# ---------------------------------------------------------------------------
# The check itself: junctions, and a redirection the walk cannot see
# ---------------------------------------------------------------------------


class TestJunctions:
    """os.path.isjunction exists from 3.12; before it, the reparse tag decides."""

    def test_the_reparse_tag_identifies_a_junction_without_isjunction(
        self, monkeypatch
    ):
        monkeypatch.delattr(os.path, "isjunction", raising=False)
        stats = {
            "junction": SimpleNamespace(
                st_file_attributes=0x400, st_reparse_tag=0xA0000003
            ),
            "symlink tag": SimpleNamespace(
                st_file_attributes=0x400, st_reparse_tag=0xA000000C
            ),
            "plain": SimpleNamespace(st_file_attributes=0x10, st_reparse_tag=0),
            "posix": SimpleNamespace(st_mode=0o40755),
        }
        monkeypatch.setattr(output_dir_links.os, "lstat", lambda p: stats[str(p)])

        assert output_dir_links.is_junction("junction")
        assert not output_dir_links.is_junction("symlink tag")
        assert not output_dir_links.is_junction("plain")
        assert not output_dir_links.is_junction("posix")

    def test_isjunction_is_used_where_it_exists(self, monkeypatch):
        monkeypatch.setattr(os.path, "isjunction", lambda p: True, raising=False)

        assert output_dir_links.is_junction("anything")

    @pytest.mark.skipif(sys.platform != "win32", reason="directory junctions are NTFS")
    def test_a_real_junction_is_refused(self, tmp_path):
        """No privilege is needed to create a junction, unlike a symlink."""
        import _winapi

        host = tmp_path / "host"
        host.mkdir()
        (host / "keep.txt").write_text("host file\n")
        output = tmp_path / "out"
        output.mkdir()
        _winapi.CreateJunction(str(host), str(output / "reports"))

        assert output_dir_links.is_junction(output / "reports")
        found = linked_output_component(None, output)
        assert found is not None and "reports is a directory junction" in found
        with pytest.raises(ASHValidationError, match="directory junction"):
            _orchestrator(tmp_path, output).ensure_directories()
        assert (host / "keep.txt").read_text() == "host file\n"

    def test_a_junction_is_named_as_one(self, tmp_path, monkeypatch):
        output = tmp_path / "out"
        (output / "reports").mkdir(parents=True)
        reports = os.fspath(output / "reports")
        monkeypatch.setattr(
            output_dir_links, "is_junction", lambda p: os.fspath(p) == reports
        )

        found = linked_output_component(None, output)

        assert found is not None and "reports is a directory junction" in found


@needs_symlinks
class TestTheSpellingOfThePaths:
    """Whether a component is below the scanned directory is decided by identity."""

    @pytest.fixture
    def alias(self, layout):
        alias = layout.root / "alias"
        alias.symlink_to(layout.tree, target_is_directory=True)
        (layout.tree / "build").symlink_to(layout.host, target_is_directory=True)
        return alias

    def test_the_scanned_directory_spelled_through_a_link(self, layout, alias):
        found = linked_output_component(alias, layout.tree / "build" / "ash")

        assert found is not None and "build is a symlink" in found

    def test_the_output_directory_spelled_through_a_link(self, layout, alias):
        found = linked_output_component(layout.tree, alias / "build" / "ash")

        assert found is not None and "build is a symlink" in found

    def test_ash_scan_refuses_it(self, layout, alias):
        exited, _ = _refuse(
            _options(layout, layout.tree / "build" / "ash", source_dir=alias)
        )

        assert "build is a symlink" in exited.found

    def test_the_sandbox_policy_refuses_it(self, layout, alias):
        from automated_security_helper.utils.sandbox.policy import (
            SandboxUnavailable,
            refuse_symlinked_output_dir,
        )

        with pytest.raises(SandboxUnavailable, match="build is a symlink"):
            refuse_symlinked_output_dir(alias, layout.tree / "build" / "ash")

    def test_a_dot_dot_or_doubled_separator_in_the_scanned_directory(
        self, layout, alias
    ):
        spelled = f"{layout.tree}/sub/..//"
        (layout.tree / "sub").mkdir()

        found = linked_output_component(spelled, layout.tree / "build" / "ash")

        assert found is not None and "build is a symlink" in found


@needs_symlinks
def test_a_redirection_the_walk_cannot_see_is_caught_by_the_real_path(
    layout, monkeypatch
):
    """The real path of an in-tree output is the root's real path plus its spelling."""
    (layout.tree / "build").symlink_to(layout.host, target_is_directory=True)
    monkeypatch.setattr(output_dir_links, "is_link", lambda p: False)

    found = linked_output_component(layout.tree, layout.tree / "build" / "out")

    assert found is not None and "resolves to" in found


# ---------------------------------------------------------------------------
# Opening in place: the logs and the other files ASH does not replace
# ---------------------------------------------------------------------------


@needs_symlinks
class TestOpeningInPlace:
    def test_a_link_at_the_name_is_refused_and_its_target_kept(self, tmp_path):
        victim = tmp_path / "victim.txt"
        victim.write_text("precious\n")
        (tmp_path / "ash.log").symlink_to(victim)

        with pytest.raises(OutputDirLinkRefused, match="ash.log is a symlink"):
            open_no_follow(tmp_path / "ash.log")
        with pytest.raises(OutputDirLinkRefused):
            open_no_follow(tmp_path / "ash.log", append=True)

        assert victim.read_text() == "precious\n"

    def test_a_regular_file_is_truncated_or_appended_to(self, tmp_path):
        path = tmp_path / "ash.log"
        path.write_text("old\n")
        with open_no_follow(path, append=True) as handle:
            handle.write("more\n")
        assert path.read_text() == "old\nmore\n"
        with open_no_follow(path) as handle:
            handle.write("new\n")
        assert path.read_text() == "new\n"

    def test_a_fifo_is_not_opened(self, tmp_path):
        """With a reader holding it open, so only the file-type check can refuse it."""
        fifo = tmp_path / "ash.log"
        os.mkfifo(fifo)
        reader = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
        try:
            with pytest.raises(OSError, match="not a regular file"):
                open_no_follow(fifo)
        finally:
            os.close(reader)

    @pytest.mark.parametrize("log_format", ["TABULAR", "JSONL"])
    @pytest.mark.parametrize("truncate", [True, False])
    def test_the_logger_does_not_write_through_a_linked_log(
        self, tmp_path, log_format, truncate
    ):
        """For the "ash" logger these are ash.log and ash.log.jsonl."""
        from automated_security_helper.utils.log import get_logger

        output = tmp_path / "out"
        output.mkdir()
        victim = tmp_path / "victim.txt"
        victim.write_text("precious\n")
        # A logger of its own, so the shared "ash" logger is left as it is.
        name = f"ash-link-test-{log_format}-{truncate}"
        suffix = ".log" if log_format == "TABULAR" else ".log.jsonl"
        (output / f"{name}{suffix}").symlink_to(victim)

        with pytest.raises(OutputDirLinkRefused):
            get_logger(
                name=name,
                output_dir=output,
                log_format=log_format,
                show_progress=False,
                use_color=False,
                truncate_log=truncate,
            )

        assert victim.read_text() == "precious\n"

    @pytest.mark.parametrize(
        "name", ["ash-ignore-report.txt", "ash-scan-set-files-list.txt"]
    )
    def test_the_scan_set_lists_are_not_written_through_a_link(self, tmp_path, name):
        from automated_security_helper.utils.get_scan_set import scan_set

        source = tmp_path / "src"
        source.mkdir()
        (source / "a.py").write_text("x = 1\n")
        output = tmp_path / "out"
        output.mkdir()
        # Dangling: scan_set reuses a list that exists, so only a link to nothing
        # reaches the write.
        victim = tmp_path / "victim.txt"
        (output / name).symlink_to(victim)

        with pytest.raises(OutputDirLinkRefused):
            scan_set(source=str(source), output=str(output))

        assert not victim.exists(), "the list was written through the link"


# ---------------------------------------------------------------------------
# Workspace mode: each project's output tree under <output>/projects/<key>
# ---------------------------------------------------------------------------


class _NeverBuilt:
    built: list = []

    @classmethod
    def create(cls, **kwargs):
        cls.built.append(kwargs)
        raise AssertionError("a project with a refused output tree was scanned")


def _workspace(root_dir: Path):
    from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan

    root = root_dir / "workspace"
    (root / "api").mkdir(parents=True)
    (root / "api" / "app.py").write_text("print('x')\n")
    workspace_file = root / "fixture.code-workspace"
    workspace_file.write_text(json.dumps({"folders": [{"path": "api"}]}))
    plan = WorkspacePlan(
        workspace_file=workspace_file.as_posix(),
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
    return root, plan


def _settings(output_dir: Path):
    from automated_security_helper.workspace.execution import ProjectScanSettings

    return ProjectScanSettings(
        output_dir=output_dir, phases=("scan",), max_parallel_projects=1
    )


@needs_symlinks
@pytest.mark.parametrize("linked", ["projects", "projects/api"])
class TestWorkspaceProjects:
    def _make_linked_output(self, layout, linked: str) -> Path:
        output = layout.root / "ws-out"
        link = output / linked
        link.parent.mkdir(parents=True)
        link.symlink_to(layout.host, target_is_directory=True)
        return output

    def test_the_project_fails_and_nothing_is_written(self, layout, linked):
        from automated_security_helper.models.workspace import ProjectRunStatus
        from automated_security_helper.workspace.execution import execute_workspace

        output = self._make_linked_output(layout, linked)
        _, plan = _workspace(layout.root)
        _NeverBuilt.built = []

        outcome = execute_workspace(
            plan, _settings(output), orchestrator_factory=_NeverBuilt.create
        )

        (project,) = outcome.payload.projects
        assert project.status is ProjectRunStatus.FAILED
        assert f"{Path(linked).name} is a symlink" in (project.error or "")
        assert "--output-dir" in (project.error or "")
        assert _NeverBuilt.built == []
        assert _untouched(layout.host)

    def test_the_mcp_workspace_tool_refuses_before_creating_anything(
        self, layout, linked
    ):
        from automated_security_helper.cli.mcp.workspace import (
            _prepare_project_outputs,
        )

        output = self._make_linked_output(layout, linked)
        _, plan = _workspace(layout.root)

        with pytest.raises(OutputDirLinkRefused, match="Pass output_dir"):
            _prepare_project_outputs(plan, _settings(output), clean_output=True)

        assert _untouched(layout.host)


@needs_symlinks
@pytest.mark.parametrize("linked", [".ash", ".ash/ash_output"])
def test_the_mcp_workspace_tool_checks_the_workspace_output_first(layout, linked):
    """The default output directory, under the workspace root, through a link."""
    from automated_security_helper.cli.mcp.workspace import _prepare_project_outputs

    root, plan = _workspace(layout.root)
    link = root / linked
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(layout.host, target_is_directory=True)

    with pytest.raises(OutputDirLinkRefused) as refused:
        _prepare_project_outputs(
            plan, _settings(root / ".ash" / "ash_output"), clean_output=True
        )

    assert f"{Path(linked).name} is a symlink" in refused.value.found
    assert "Pass output_dir" in str(refused.value)
    assert "--output-dir" not in str(refused.value)
    assert _untouched(layout.host)


# ---------------------------------------------------------------------------
# MCP: the scan tool's failure carries the reason, with an MCP remedy
# ---------------------------------------------------------------------------


@needs_symlinks
def test_an_mcp_scan_refused_for_its_output_directory_says_why(layout, monkeypatch):
    from automated_security_helper.cli.mcp.scan_target import (
        ASH_MCP_ALLOWED_ROOTS_ENV,
    )
    from automated_security_helper.cli.mcp_tools import _run_scan_async
    from automated_security_helper.core.resource_management.scan_registry import (
        MCScanStatus,
        ScanRegistry,
        ScanRegistryEntry,
    )
    from automated_security_helper.interactions import run_ash_scan

    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(layout.root))
    output = layout.tree / ".ash" / "ash_output"
    output.mkdir(parents=True)
    (output / "scanners").symlink_to(layout.host, target_is_directory=True)
    registry = MagicMock(spec=ScanRegistry)
    registry.get_scan.return_value = ScanRegistryEntry(
        scan_id="scan-1",
        directory_path=str(layout.tree),
        output_directory=str(output),
    )

    def past_the_check(_opts):
        raise _PastTheCheck("the scan went on past the output-directory check")

    monkeypatch.setattr(run_ash_scan, "_setup_logger", past_the_check)
    with patch(
        "automated_security_helper.cli.mcp_tools.get_scan_registry",
        return_value=registry,
    ):
        asyncio.run(
            _run_scan_async(
                scan_id="scan-1",
                directory_path=str(layout.tree),
                output_dir=str(output),
                severity_threshold="HIGH",
            )
        )

    (finished,) = [c for c in registry.mock_calls if c[0] == "finish_scan"]
    assert finished.args[1] is MCScanStatus.FAILED
    message = finished.args[2]
    assert "scanners is a symlink" in message
    assert "replace the link there with a directory" in message
    assert "--output-dir" not in message, "an MCP client has no --output-dir"
