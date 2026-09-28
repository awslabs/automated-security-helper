# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Workspace mode inside the container, and the folder named ``src``.

Why this file exists
--------------------
Container mode has exactly one bind mount. A workspace therefore mounts its
*root* at ``/src`` and every project is ``/src/<relative-path>``, which means the
in-container invocation cannot use ``--source-dir`` -- that flag is mutually
exclusive with ``--workspace``, and the container has to resolve the workspace
itself to reach the projects below the mount.

That arrangement re-enters a heuristic ASH already carries. ``sarif_utils``
strips the source directory's basename from a finding URI, because offline
opengrep emits ``<basename>/path/to/file``, but it skips the strip when the
source directory contains a child of the same name -- issue #361, whose canonical
case is source_dir ``/src`` with ``/src/src`` present. A workspace containing a
folder literally named ``src``, mounted at ``/src``, is exactly that shape.

The resolution is that the guard evaluates per project, because each project runs
with its own ``source_dir`` of ``/src/<project>``. Nothing in ``sarif_utils``
changes; what changes is that it is never handed the mount point as a source
directory in workspace mode. These tests pin both halves: the command assembly
that makes it so, and the guard's behaviour on the collision shape.

What is not tested here
-----------------------
No container is started. There is no OCI runtime in the unit environment, so this
covers the command ASH would run and the path handling that command implies, not
the run itself. An end-to-end containerised workspace scan needs a runner.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import ExecutionPhase, ExecutionStrategy
from automated_security_helper.interactions.run_ash_container import (
    _assemble_run_command,
)
from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    _workspace_relative_file,
)
from automated_security_helper.models.workspace import WorkspaceExitCode
from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan

AshConfig.model_rebuild()


def _plan(root: Path, *keys: str) -> WorkspacePlan:
    return WorkspacePlan(
        workspace_file=(root / "dev.code-workspace").as_posix(),
        workspace_root=root.as_posix(),
        projects=[
            ProjectPlan(
                key=key,
                relative_path=key,
                path=(root / key).as_posix(),
                label=key,
                display_label=key,
                severity_threshold="MEDIUM",
            )
            for key in keys
        ],
    )


def _run_command(source_dir: Path, output_dir: Path, **overrides: Any) -> List[str]:
    kwargs: Dict[str, Any] = {
        "oci_command_prefix": [],
        "resolved_oci_runner": "docker",
        "image_name": "ash:test",
        "source_dir": source_dir,
        "output_dir": output_dir,
        "offline": False,
        "debug": False,
        "color": False,
        "quiet": True,
        "progress": False,
        "verbose": False,
        "simple": True,
        "python_based_plugins_only": False,
        "cleanup": False,
        "inspect": False,
        "fail_on_findings": None,
        "phases": [ExecutionPhase.SCAN],
        "scanners": [],
        "exclude_scanners": [],
        "output_formats": [],
        "config": None,
        "config_overrides": [],
        "existing_results": None,
        "ash_plugin_modules": [],
        "strategy": ExecutionStrategy.PARALLEL,
        "ctx": None,
    }
    kwargs.update(overrides)
    return _assemble_run_command(**kwargs)


class TestWorkspaceRelativeFile:
    def test_the_definition_is_named_relative_to_the_root(self, tmp_path):
        plan = _plan(tmp_path, "api")
        opts = ScanOptions(
            source_dir=tmp_path, output_dir=tmp_path / "out", workspace_plan=plan
        )
        assert _workspace_relative_file(opts) == "dev.code-workspace"

    def test_single_directory_mode_has_no_relative_file(self, tmp_path):
        opts = ScanOptions(source_dir=tmp_path, output_dir=tmp_path / "out")
        assert _workspace_relative_file(opts) is None


class TestRunCommandAssembly:
    def test_single_directory_mode_still_passes_source_dir(self, tmp_path):
        command = _run_command(tmp_path, tmp_path / "out")
        assert "--source-dir" in command
        assert "--workspace" not in command

    def test_workspace_mode_passes_the_workspace_flag(self, tmp_path):
        command = _run_command(
            tmp_path, tmp_path / "out", workspace_relative_file="dev.code-workspace"
        )
        index = command.index("--workspace")
        assert command[index + 1] == "/src/dev.code-workspace"

    def test_workspace_mode_omits_source_dir(self, tmp_path):
        """The two flags are mutually exclusive; passing both exits 2."""
        command = _run_command(
            tmp_path, tmp_path / "out", workspace_relative_file="dev.code-workspace"
        )
        assert "--source-dir" not in command

    def test_the_workspace_root_is_the_single_mount(self, tmp_path):
        command = _run_command(
            tmp_path, tmp_path / "out", workspace_relative_file="dev.code-workspace"
        )
        mounts = [
            command[index + 1]
            for index, arg in enumerate(command)
            if arg == "--mount"
        ]
        source_mounts = [m for m in mounts if "destination=/src" in m]
        assert len(source_mounts) == 1
        assert f"source={tmp_path}" in source_mounts[0]

    def test_allow_missing_projects_is_forwarded(self, tmp_path):
        command = _run_command(
            tmp_path,
            tmp_path / "out",
            workspace_relative_file="dev.code-workspace",
            allow_missing_projects=True,
        )
        assert "--allow-missing-projects" in command

    def test_allow_missing_projects_is_absent_by_default(self, tmp_path):
        command = _run_command(
            tmp_path, tmp_path / "out", workspace_relative_file="dev.code-workspace"
        )
        assert "--allow-missing-projects" not in command

    def test_the_output_dir_is_still_mounted_at_out(self, tmp_path):
        command = _run_command(
            tmp_path, tmp_path / "out", workspace_relative_file="dev.code-workspace"
        )
        assert "/out" in command
        assert any(
            "destination=/out" in command[index + 1]
            for index, arg in enumerate(command)
            if arg == "--mount"
        )


class TestOutsideRootIsRefusedBeforeAnyContainerStarts:
    """Containment is decided before mode dispatch, asserted for container mode.

    Why this needs its own tests
    ----------------------------
    The containment check lives in the resolver and the resolver runs for every
    mode, so container mode's rejection is a consequence of a shared code path
    rather than of anything container-specific. That is a sound argument and it is
    still only an argument: nothing held the ordering. ``--mode container`` is
    resolved in ``cli.scan`` *above* the block that applies mode presets, and a
    later edit that moved workspace resolution below the mode branch -- or that
    resolved lazily inside the local-mode path only -- would leave container mode
    mounting an unvalidated root at ``/src`` with every existing test still green.

    The observable these assert on is therefore not "the resolver raised". It is
    that the process exits 4 and ``run_ash_container`` is never called, which is
    what "no container is started" actually means.

    The spy is installed at the container boundary, not at ``run_ash_scan``. A spy
    on ``run_ash_scan`` would be unreached in both the refusal case and the valid
    case, so both tests would pass against an implementation that never ran a
    container at all. The positive control below is what rules that out.
    """

    @pytest.fixture
    def _clear_ash_env(self, monkeypatch):
        for name in ("ASH_SOURCE_DIR", "ASH_OUTPUT_DIR", "ASH_CONFIG", "ASH_MODE"):
            monkeypatch.delenv(name, raising=False)

    @pytest.fixture
    def container_calls(self, monkeypatch, _clear_ash_env):
        """Record calls to ``run_ash_container`` instead of starting one."""
        from types import SimpleNamespace

        calls: list[dict[str, Any]] = []

        def _record(**kwargs):
            calls.append(kwargs)
            return SimpleNamespace(returncode=0, stdout="", stderr="", args=[])

        monkeypatch.setattr(
            "automated_security_helper.interactions.run_ash_scan.run_ash_container",
            _record,
            raising=True,
        )
        return calls

    @staticmethod
    def _workspace(root: Path, folders: list[str]) -> Path:
        path = root / "dev.code-workspace"
        path.write_text(
            json.dumps({"folders": [{"path": entry} for entry in folders]}),
            encoding="utf-8",
        )
        return path

    @staticmethod
    def _scan(*args: str):
        from typer.testing import CliRunner

        from automated_security_helper.cli.main import app

        return CliRunner().invoke(app, ["scan", *args])

    def test_a_contained_workspace_does_reach_the_container(
        self, tmp_path, container_calls
    ):
        """The positive control, without which the two refusals prove nothing.

        Container mode has to actually reach ``run_ash_container`` for "it was not
        reached" to mean anything. This also pins the mount: the single ``/src``
        source is the workspace root, so a rejected entry could not have been
        mounted even indirectly.
        """
        root = tmp_path / "ws"
        (root / "api").mkdir(parents=True)
        workspace = self._workspace(root, ["api"])

        self._scan("--workspace", str(workspace), "--mode", "container", "--no-run")

        assert len(container_calls) == 1
        assert Path(container_calls[0]["source_dir"]).resolve() == root.resolve()
        assert container_calls[0]["workspace_relative_file"] == "dev.code-workspace"

    def test_a_parent_traversal_entry_starts_no_container(
        self, tmp_path, container_calls
    ):
        """``../`` is rejected on the raw text, before anything is mounted."""
        root = tmp_path / "ws"
        root.mkdir(parents=True)
        (tmp_path / "outside").mkdir()
        workspace = self._workspace(root, ["../outside"])

        result = self._scan(
            "--workspace", str(workspace), "--mode", "container", "--no-run"
        )

        assert result.exit_code == WorkspaceExitCode.WORKSPACE_ERROR
        assert container_calls == []

    def test_an_absolute_path_outside_the_root_starts_no_container(
        self, tmp_path, container_calls
    ):
        """The other shape: no ``..``, but it canonicalises outside the root.

        Separate from the traversal case because the two are rejected by different
        checks -- the ``..`` scan runs on the raw string and this one on the
        resolved path -- so one passing does not imply the other.
        """
        root = tmp_path / "ws"
        root.mkdir(parents=True)
        outside = tmp_path / "outside"
        outside.mkdir()
        workspace = self._workspace(root, [outside.as_posix()])

        result = self._scan(
            "--workspace", str(workspace), "--mode", "container", "--no-run"
        )

        assert result.exit_code == WorkspaceExitCode.WORKSPACE_ERROR
        assert container_calls == []

    def test_a_symlink_out_of_the_root_starts_no_container(
        self, tmp_path, container_calls
    ):
        """A link is the case containment alone would accept.

        ``resolve()`` follows it, so the target is outside and the containment
        check catches this one -- but a link pointing *inside* the root would
        resolve to a contained path, which is why the resolver rejects the entry
        for being a symlink as well. Asserted here so container mode is known to
        inherit both halves.
        """
        root = tmp_path / "ws"
        root.mkdir(parents=True)
        outside = tmp_path / "outside"
        outside.mkdir()
        link = root / "aliased"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError):  # pragma: no cover - platform gate
            pytest.skip("symlink creation is unavailable on this platform")
        workspace = self._workspace(root, ["aliased"])

        result = self._scan(
            "--workspace", str(workspace), "--mode", "container", "--no-run"
        )

        assert result.exit_code == WorkspaceExitCode.WORKSPACE_ERROR
        assert container_calls == []

    def test_the_refusal_names_the_offending_entry(self, tmp_path, container_calls):
        """An operator has to be able to fix it, which means knowing which entry."""
        root = tmp_path / "ws"
        root.mkdir(parents=True)
        (tmp_path / "outside").mkdir()
        workspace = self._workspace(root, ["api", "../outside"])
        (root / "api").mkdir()

        result = self._scan(
            "--workspace", str(workspace), "--mode", "container", "--no-run"
        )

        assert result.exit_code == WorkspaceExitCode.WORKSPACE_ERROR
        assert "../outside" in result.output
        assert container_calls == []


def _sarif_with_uri(uri: str) -> SarifReport:
    return SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "ASH"}},
                    "results": [
                        {
                            "ruleId": "R1",
                            "level": "error",
                            "message": {"text": "fixture"},
                            "locations": [
                                {"physicalLocation": {"artifactLocation": {"uri": uri}}}
                            ],
                        }
                    ],
                }
            ],
        }
    )


def _context(
    source_dir: Path, output_dir: Path, *, ignore_paths: List[str] = ()
) -> PluginContext:
    from automated_security_helper.models.core import IgnorePathWithReason

    config = AshConfig(project_name=source_dir.name)
    config.global_settings.ignore_paths = [
        IgnorePathWithReason(path=path, reason="fixture") for path in ignore_paths
    ]
    return PluginContext(source_dir=source_dir, output_dir=output_dir, config=config)


def _survives(report: SarifReport) -> bool:
    """Whether the finding was kept once ignore paths were applied."""
    return bool(report.runs[0].results)


class TestSourceBasenameGuardIsPerProject:
    """The #361 guard, evaluated against each project rather than the mount point.

    The fixture mirrors the container layout: a workspace root standing in for
    ``/src``, containing a project literally named ``src`` alongside an ordinary
    one. In workspace mode the guard only ever sees a project directory, so the
    ``src``-inside-``/src`` collision is decided for the project named ``src``
    and cannot affect its siblings.

    Asserted through what the guard actually governs, which is *matching*, not the
    reported path. ``_normalize_sarif_uri`` produces the string that ignore paths
    and suppressions are compared against; the result's own ``artifactLocation``
    is left as the scanner wrote it. An earlier draft of these tests asserted on
    the reported URI and was wrong about the code -- worth stating, because the
    function name reads as though it rewrites the path.

    The discriminating ignore path is ``app.py``, which matches the stripped form
    and not the prefixed one.
    """

    @pytest.fixture
    def workspace(self, tmp_path):
        root = tmp_path / "src"  # stands in for the /src mount point
        for key in ("src", "api"):
            (root / key).mkdir(parents=True)
            (root / key / "app.py").write_text("print('x')\n", encoding="utf-8")
        (root / "dev.code-workspace").write_text(
            json.dumps({"folders": [{"path": "src"}, {"path": "api"}]}),
            encoding="utf-8",
        )
        return root

    def test_the_mount_point_itself_hits_the_guard(self, workspace, tmp_path):
        """Establishes that the collision shape is real before showing it avoided.

        source_dir is the mount point, which does contain a child named ``src``,
        so the basename strip is skipped, the normalised URI stays
        ``src/app.py``, and the ``app.py`` ignore path does not match. Without
        this the next two tests would be asserting nothing.
        """
        report = apply_suppressions_to_sarif(
            _sarif_with_uri("src/app.py"),
            _context(workspace, tmp_path / "out-root", ignore_paths=["app.py"]),
        )
        assert _survives(report)

    def test_the_project_named_src_is_decided_on_its_own_directory(
        self, workspace, tmp_path
    ):
        """source_dir is /src/src, which has no /src/src/src, so the strip applies."""
        report = apply_suppressions_to_sarif(
            _sarif_with_uri("src/app.py"),
            _context(workspace / "src", tmp_path / "out-src", ignore_paths=["app.py"]),
        )
        assert not _survives(report)

    def test_a_sibling_project_is_unaffected_by_the_folder_named_src(
        self, workspace, tmp_path
    ):
        """The collision belongs to one project; it must not leak to another."""
        report = apply_suppressions_to_sarif(
            _sarif_with_uri("api/app.py"),
            _context(workspace / "api", tmp_path / "out-api", ignore_paths=["app.py"]),
        )
        assert not _survives(report)

    def test_no_finding_is_dropped_when_nothing_is_ignored(self, workspace, tmp_path):
        """Whatever the guard decides about the prefix, no finding vanishes."""
        for index, source in enumerate(
            (workspace, workspace / "src", workspace / "api")
        ):
            report = apply_suppressions_to_sarif(
                _sarif_with_uri("src/app.py"),
                _context(source, tmp_path / f"out-{index}"),
            )
            assert _survives(report)

    def test_the_reported_uri_is_left_as_the_scanner_wrote_it(
        self, workspace, tmp_path
    ):
        """Pinned because the guard's name suggests otherwise.

        Normalisation feeds the ignore-path and suppression comparison only. If
        this ever starts rewriting the reported path, the workspace aggregator's
        project-relative-to-workspace-relative conversion has to be revisited,
        because it reads the same field.
        """
        report = apply_suppressions_to_sarif(
            _sarif_with_uri("src/app.py"),
            _context(workspace / "src", tmp_path / "out-uri"),
        )
        uri = (
            report.runs[0]
            .results[0]
            .locations[0]
            .physicalLocation.root.artifactLocation.uri
        )
        assert uri == "src/app.py"
