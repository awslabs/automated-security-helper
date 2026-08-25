# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Cross-project leakage of scanner plugin state, and the paths that separate it.

Why these tests exist
---------------------
A scanner plugin instance is mutable and the scan phase mutates it in place:
``.context`` and ``.results_dir`` are reassigned immediately before each call
(``core/phases/scanner_executor.py``), and ``.start_time``, ``.end_time``,
``.errors``, ``.output`` and ``.config`` are written during the scan itself.
Execution is a thread pool in one process, not subprocesses, so a reused instance
would carry one project's state into another -- and the observable symptom would
be findings filed against the wrong project, which is the worst possible way for
this to fail.

Workspace mode gets fresh instances because it gives each project its own
``PluginContext``, and ``ScanPhase._execute_phase`` constructs a new plugin
instance per class per invocation. That is a property of existing code rather
than something Phase 2a adds, which is exactly why it needs a test: nothing else
in the suite would notice if that construction moved out of ``_execute_phase``
and into engine setup, and the failure would be silent.

The second half of the file pins the output paths. Requirement: in workspace mode
raw scanner output lands under ``projects/<key>/scanners/<scanner>/<target_type>``
and single-project mode is byte-for-byte unchanged. Both fall out of giving each
project its own ``output_dir``, with no conditional in the scanner base -- which
is why single-project mode cannot regress: there is no branch to take.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Literal, Optional, Tuple
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.core import IgnorePathWithReason

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

# Every instance the scan phase constructs, in construction order. A list rather
# than a counter because the assertions need the instances themselves -- an
# instance count alone cannot tell a fresh instance from a reused one.
CONSTRUCTED: List["RecordingScanner"] = []


class RecordingScannerConfig(ScannerPluginConfigBase):
    name: str = "recording"
    enabled: bool = True


class RecordingScanner(ScannerPluginBase[RecordingScannerConfig]):
    """A scanner that records the mutable state it was handed, and mutates it.

    Real rather than a MagicMock: the point is that these attributes are ordinary
    pydantic fields on one object, so a mock would prove nothing about whether
    they can leak.
    """

    def model_post_init(self, context):
        if self.config is None:
            self.config = RecordingScannerConfig()
        result = super().model_post_init(context)
        CONSTRUCTED.append(self)
        return result

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[dict]]:
        raise NotImplementedError("RecordingScanner overrides scan() directly")

    def scan(
        self,
        target,
        target_type="source",
        global_ignore_paths=None,
        config=None,
        *args,
        **kwargs,
    ):
        # Mutate every attribute the executor and the scan template touch, so a
        # reused instance would be observable afterwards.
        self.start_time = datetime.now(timezone.utc)
        self.errors.append(f"error from {self.context.source_dir.name}")
        self.output.append(f"output from {self.context.source_dir.name}")
        self.end_time = datetime.now(timezone.utc)
        self.exit_code = 0
        return {
            "status": "passed",
            "seen_source_dir": self.context.source_dir.as_posix(),
        }


def _project_context(tmp_path, key: str, output_root: Path) -> PluginContext:
    """A per-project context of the shape the workspace executor builds."""
    source_dir = tmp_path / key
    (source_dir / "src").mkdir(parents=True, exist_ok=True)
    (source_dir / "src" / "app.py").write_text("print('x')\n", encoding="utf-8")
    project_output = output_root / "projects" / key
    project_output.mkdir(parents=True, exist_ok=True)
    return PluginContext(
        source_dir=source_dir,
        output_dir=project_output,
        config=AshConfig(project_name=key),
    )


def _run_scan_phase(context: PluginContext) -> AshAggregatedResults:
    """Run one project's scan phase with the recording scanner registered."""
    progress = MagicMock()
    progress.add_task.return_value = 1
    with patch(
        "automated_security_helper.core.phases.scan_phase.ScannerValidationManager"
    ) as MockValMgr:
        manager = MagicMock()
        checkpoint = MagicMock()
        checkpoint.has_issues.return_value = False
        checkpoint.get_missing_scanners.return_value = []
        checkpoint.get_unexpected_scanners.return_value = []
        checkpoint.errors = []
        checkpoint.discrepancies = []
        manager.validate_task_queue.return_value = checkpoint
        manager.validate_execution_completion.return_value = checkpoint
        manager.validate_result_completeness.return_value = checkpoint
        manager.report_execution_discrepancies.return_value = {}
        MockValMgr.return_value = manager

        phase = ScanPhase(
            plugin_context=context,
            plugins=[RecordingScanner],
            progress_display=progress,
        )
        phase.validation_manager = manager
        return phase.execute(aggregated_results=AshAggregatedResults())


@pytest.fixture(autouse=True)
def _reset_constructed():
    CONSTRUCTED.clear()
    yield
    CONSTRUCTED.clear()


class TestFreshInstancePerProject:
    def test_each_project_gets_its_own_scanner_instance(self, tmp_path):
        output_root = tmp_path / "out"
        for key in ("api", "web"):
            _run_scan_phase(_project_context(tmp_path, key, output_root))
        assert len(CONSTRUCTED) == 2
        assert CONSTRUCTED[0] is not CONSTRUCTED[1]

    def test_context_does_not_leak_between_projects(self, tmp_path):
        output_root = tmp_path / "out"
        for key in ("api", "web"):
            _run_scan_phase(_project_context(tmp_path, key, output_root))
        seen = [instance.context.source_dir.name for instance in CONSTRUCTED]
        assert seen == ["api", "web"]

    def test_results_dir_does_not_leak_between_projects(self, tmp_path):
        output_root = tmp_path / "out"
        for key in ("api", "web"):
            _run_scan_phase(_project_context(tmp_path, key, output_root))
        dirs = [instance.results_dir.as_posix() for instance in CONSTRUCTED]
        assert "projects/api/scanners/recording" in dirs[0]
        assert "projects/web/scanners/recording" in dirs[1]

    def test_config_does_not_leak_between_projects(self, tmp_path):
        output_root = tmp_path / "out"
        for key in ("api", "web"):
            _run_scan_phase(_project_context(tmp_path, key, output_root))
        assert CONSTRUCTED[0].config is not CONSTRUCTED[1].config

    def test_errors_do_not_leak_between_projects(self, tmp_path):
        """A shared mutable default would make the second project inherit the first."""
        output_root = tmp_path / "out"
        for key in ("api", "web"):
            _run_scan_phase(_project_context(tmp_path, key, output_root))
        assert CONSTRUCTED[0].errors == ["error from api"]
        assert CONSTRUCTED[1].errors == ["error from web"]

    def test_output_does_not_leak_between_projects(self, tmp_path):
        output_root = tmp_path / "out"
        for key in ("api", "web"):
            _run_scan_phase(_project_context(tmp_path, key, output_root))
        assert CONSTRUCTED[0].output == ["output from api"]
        assert CONSTRUCTED[1].output == ["output from web"]

    def test_timings_do_not_leak_between_projects(self, tmp_path):
        output_root = tmp_path / "out"
        for key in ("api", "web"):
            _run_scan_phase(_project_context(tmp_path, key, output_root))
        first, second = CONSTRUCTED
        assert first.start_time is not None and second.start_time is not None
        assert first.start_time is not second.start_time
        assert first.end_time is not second.end_time

    def test_each_project_observed_only_its_own_source_dir(self, tmp_path):
        """The observable symptom of a leak: a finding filed against the wrong tree."""
        output_root = tmp_path / "out"
        observed: List[str] = []
        for key in ("api", "web"):
            results = _run_scan_phase(_project_context(tmp_path, key, output_root))
            raw = results.additional_reports["recording"]["source"]["raw_results"]
            observed.append(Path(raw["seen_source_dir"]).name)
        assert observed == ["api", "web"]


class TestPerProjectOutputPaths:
    def test_two_projects_do_not_share_a_scanner_results_dir(self, tmp_path):
        """Requirement 5: the same scanner on two projects must not overwrite."""
        output_root = tmp_path / "out"
        for key in ("api", "web"):
            _run_scan_phase(_project_context(tmp_path, key, output_root))
        dirs = {instance.results_dir.as_posix() for instance in CONSTRUCTED}
        assert len(dirs) == 2

    def test_the_workspace_tree_matches_the_specified_shape(self, tmp_path):
        output_root = tmp_path / "out"
        _run_scan_phase(_project_context(tmp_path, "api", output_root))
        expected = output_root / "projects" / "api" / "scanners" / "recording"
        assert CONSTRUCTED[0].results_dir == expected

    def test_single_project_paths_are_unchanged(self, tmp_path):
        """Requirement 9. Nothing branches on workspace mode, so nothing can drift.

        A single-directory scan hands the scanner base an output_dir with no
        ``projects/`` component, and the base builds ``scanners/<name>`` under it
        exactly as it always did.
        """
        source_dir = tmp_path / "single"
        (source_dir / "src").mkdir(parents=True)
        (source_dir / "src" / "app.py").write_text("print('x')\n", encoding="utf-8")
        output_dir = tmp_path / "single-out"
        output_dir.mkdir()
        _run_scan_phase(
            PluginContext(
                source_dir=source_dir,
                output_dir=output_dir,
                config=AshConfig(project_name="single"),
            )
        )
        assert CONSTRUCTED[0].results_dir == output_dir / "scanners" / "recording"
        assert "projects" not in CONSTRUCTED[0].results_dir.parts

    def test_the_per_target_subdirectory_is_still_appended_by_the_scanner(
        self, tmp_path
    ):
        """The base sets scanners/<name>; the target_type layer is the scanner's own.

        Pinned because the requirement names the full
        ``scanners/<scanner>/<target_type>`` path, and the split between who
        contributes which segment is easy to get wrong when reading only the base.
        """
        output_root = tmp_path / "out"
        _run_scan_phase(_project_context(tmp_path, "api", output_root))
        base = CONSTRUCTED[0].results_dir
        assert (
            (base / "source")
            .as_posix()
            .endswith("projects/api/scanners/recording/source")
        )


class TestPluginManagerContextIsWriteOnly:
    """A global that would leak if anything read it, and does not because nothing does.

    ``ScanExecutionEngine.__init__`` calls ``ash_plugin_manager.set_context()`` on
    a module-level singleton. Under parallel projects the last writer wins, so if
    any consumer ever reads it, that consumer sees an arbitrary project's context.
    Today nothing reads it, which is why parallel projects are safe -- and this
    test is here so that stops being an accident. If someone adds a reader, they
    have to deal with this first.
    """

    def test_nothing_in_the_package_reads_the_singleton_context(self):
        root = Path(__file__).resolve().parents[3] / "automated_security_helper"
        readers: Dict[str, str] = {}
        for path in sorted(root.rglob("*.py")):
            for line_number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if "ash_plugin_manager.context" in stripped:
                    readers[f"{path.name}:{line_number}"] = stripped
        assert readers == {}, (
            "ash_plugin_manager.context is now read somewhere. It is a "
            "module-level singleton overwritten by every ScanExecutionEngine, so "
            "under parallel workspace projects the reader sees an arbitrary "
            "project's context. Give it thread-local storage, or pass the context "
            "explicitly, before relying on it: " + repr(readers)
        )
