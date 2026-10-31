"""Every scanner row says what happened to that scanner, in every output.

``ash_aggregated_results.json`` gives each scanner a row in ``scanner_results``, and
``ash.flat.json`` gives it one in ``scanner_metrics``. Before the report phase both
are rebuilt from the unified metrics, and the rebuild keeps each scanner's
``dependencies_satisfied``, ``excluded`` and ``exit_code`` as recorded. The flat
rows are computed from the rebuilt rows, so ``dependencies_missing`` and
``excluded`` match them. A SKIPPED or MISSING row also says why.

These tests run the scan phase over real scanner plugins, rebuild the rows the way
the engine does, and read the aggregated row, the flat row and the per-target report
for each case. They also reload the results from JSON and rebuild again, which is
what ``ash report`` and ``ash merge`` do, and expect the same rows.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.core.unified_metrics import (
    populate_metrics_from_unified_source,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
    ReportContentEmitter,
)
from automated_security_helper.schemas.sarif_schema_model import (
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.sandbox.scope import SandboxUnavailable

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


def _scanner_class(
    name: str,
    *,
    tool_found: bool = True,
    exit_code: int = 0,
    targets_attempted: int | None = None,
):
    """A scanner plugin whose tool lookup, exit code and target count the test sets."""

    class _Config(ScannerPluginConfigBase):
        pass

    class _Scanner(ScannerPluginBase):
        def model_post_init(self, context):
            if self.config is None:
                self.config = _Config(name=name)
            self.command = f"{name}-tool"
            super().model_post_init(context)

        def validate_plugin_dependencies(self) -> bool:
            return tool_found

        def _execute_scan(self, target, target_type, global_ignore_paths):
            raise NotImplementedError

        def scan(self, target, target_type, global_ignore_paths=None, config=None):
            self.exit_code = exit_code
            if targets_attempted is not None:
                self.targets_attempted = targets_attempted
            return SarifReport(
                version="2.1.0",
                runs=[Run(tool=Tool(driver=ToolComponent(name=name)), results=[])],
            )

    _Scanner.__name__ = f"{name.replace('-', '_')}_scanner"
    return _Scanner


@pytest.fixture
def context(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = tmp_path / "output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=get_default_config(),
    )


def _scan(context, plugins: List[type], **phase_kwargs) -> AshAggregatedResults:
    aggregated = AshAggregatedResults()
    phase = ScanPhase(
        plugin_context=context,
        plugins=plugins,
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )
    results = phase._execute_phase(
        aggregated_results=aggregated, parallel=False, **phase_kwargs
    )
    # What the execution engine does after the final suppression pass.
    return populate_metrics_from_unified_source(aggregated_results=results)


def _reloaded(results: AshAggregatedResults) -> AshAggregatedResults:
    """The results as ``ash report`` and ``ash merge`` read them back."""
    reloaded = AshAggregatedResults.model_validate_json(results.model_dump_json())
    return populate_metrics_from_unified_source(aggregated_results=reloaded)


def _flat(results: AshAggregatedResults, name: str) -> dict:
    rows = ReportContentEmitter(results).get_scanner_results()
    (row,) = [row for row in rows if row["scanner_name"] == name]
    return row


def _both(results):
    """The rows of one run, as written and as reloaded."""
    return [("as written", results), ("reloaded", _reloaded(results))]


def test_a_missing_scanner_row_says_its_tool_was_not_found(context):
    results = _scan(context, [_scanner_class("tool-a", tool_found=False)])

    for when, model in _both(results):
        row = model.scanner_results["tool-a"]
        assert row.status == ScannerStatus.MISSING, when
        assert row.dependencies_satisfied is False, f"{when}: {row!r}"
        assert row.excluded is False, when
        assert row.exit_code is None, f"{when}: the tool never ran: {row!r}"
        assert row.missing_reason and "tool-a-tool" in row.missing_reason, (
            f"{when}: {row.missing_reason!r}"
        )
        assert row.skipped_reason is None, when

        flat = _flat(model, "tool-a")
        assert flat["status"] == "MISSING", when
        assert flat["dependencies_missing"] is True, f"{when}: {flat!r}"
        assert flat["missing_reason"] == row.missing_reason, when


def test_an_excluded_scanner_row_says_it_was_excluded(context):
    results = _scan(
        context,
        [_scanner_class("tool-a"), _scanner_class("tool-b")],
        excluded_scanners=["tool-b"],
    )

    for when, model in _both(results):
        row = model.scanner_results["tool-b"]
        assert row.status == ScannerStatus.SKIPPED, when
        assert row.excluded is True, f"{when}: {row!r}"
        assert row.exit_code is None, when
        assert row.skipped_reason and "exclude" in row.skipped_reason, (
            f"{when}: {row.skipped_reason!r}"
        )
        assert row.missing_reason is None, when

        flat = _flat(model, "tool-b")
        assert flat["excluded"] is True, f"{when}: {flat!r}"
        assert flat["skipped_reason"] == row.skipped_reason, when


def test_a_scanner_left_out_of_the_allowlist_says_so(context):
    results = _scan(
        context,
        [_scanner_class("tool-a"), _scanner_class("tool-b")],
        enabled_scanners=["tool-a"],
    )

    for when, model in _both(results):
        row = model.scanner_results["tool-b"]
        assert row.status == ScannerStatus.SKIPPED, when
        assert row.excluded is True, when
        assert row.skipped_reason and "--scanners" in row.skipped_reason, (
            f"{when}: {row.skipped_reason!r}"
        )


def test_a_scanner_that_ran_records_its_tools_exit_code(context):
    results = _scan(context, [_scanner_class("tool-a", exit_code=1)])

    for when, model in _both(results):
        row = model.scanner_results["tool-a"]
        assert row.status == ScannerStatus.PASSED, when
        assert row.exit_code == 1, f"{when}: {row!r}"
        assert row.dependencies_satisfied is True, when
        assert row.missing_reason is None and row.skipped_reason is None, when


def test_a_tool_that_exited_non_zero_with_nothing_to_scan_keeps_its_exit_code(
    context,
):
    """Control: only a 0 the tool never produced is dropped, not a real failure."""
    results = _scan(
        context, [_scanner_class("tool-a", exit_code=2, targets_attempted=0)]
    )

    for when, model in _both(results):
        row = model.scanner_results["tool-a"]
        assert row.status == ScannerStatus.SKIPPED, f"{when}: {row!r}"
        assert row.exit_code == 2, f"{when}: {row!r}"


def test_a_scanner_with_nothing_to_scan_that_exited_zero_has_no_exit_code(context):
    results = _scan(
        context, [_scanner_class("tool-a", exit_code=0, targets_attempted=0)]
    )

    for when, model in _both(results):
        row = model.scanner_results["tool-a"]
        assert row.status == ScannerStatus.SKIPPED, f"{when}: {row!r}"
        assert row.exit_code is None, f"{when}: {row!r}"


def test_the_exit_code_is_the_highest_over_the_targets():
    """Not the first, the last or the lowest: one target's failure is the tool's."""
    model = AshAggregatedResults()
    model.additional_reports["tool-a"] = {
        "source": {"scanner_name": "tool-a", "status": "PASSED", "exit_code": 1},
        "converted": {"scanner_name": "tool-a", "status": "PASSED", "exit_code": 3},
        "archive": {"scanner_name": "tool-a", "status": "PASSED", "exit_code": 0},
    }

    results = populate_metrics_from_unified_source(aggregated_results=model)

    assert results.scanner_results["tool-a"].exit_code == 3


def test_a_missing_report_that_says_dependencies_were_absent_wins():
    """dependencies_recorded_satisfied: some MISSING report True and none False.

    Two targets, one recorded by ScanPhase's filtering-raised path (True) and one
    by an ordinary dependency failure (False): the dependencies were absent for the
    second, so the row must not say they were satisfied.
    """
    from automated_security_helper.core.unified_metrics import (
        dependencies_recorded_satisfied,
    )

    model = AshAggregatedResults()
    model.additional_reports["tool-a"] = {
        "None": {
            "scanner_name": "tool-a",
            "status": "MISSING",
            "dependencies_satisfied": True,
        },
        "source": {
            "scanner_name": "tool-a",
            "status": "MISSING",
            "dependencies_satisfied": False,
        },
    }

    assert dependencies_recorded_satisfied(model, "tool-a") is False
    results = populate_metrics_from_unified_source(aggregated_results=model)
    assert results.scanner_results["tool-a"].dependencies_satisfied is False


def test_a_missing_report_claiming_an_exit_code_rebuilds_to_none():
    """The rebuild's guard on its own: a MISSING scanner never ran its tool.

    A report written by an older version, or by a plugin that set its exit code
    without running anything, can still carry one; the executor's guard is the
    other half, checked by the auto-sandbox MISSING cell in
    tests/unit/core/phases/test_a_refused_sandbox_grades_the_scan.py.
    """
    model = AshAggregatedResults()
    model.additional_reports["tool-a"] = {
        "source": {
            "scanner_name": "tool-a",
            "status": "MISSING",
            "dependencies_satisfied": False,
            "exit_code": 2,
        }
    }

    results = populate_metrics_from_unified_source(aggregated_results=model)

    row = results.scanner_results["tool-a"]
    assert row.status == ScannerStatus.MISSING, row
    assert row.exit_code is None, row


def test_a_sandbox_refusal_with_no_classification_is_an_error_with_the_reason(context):
    """A bare SandboxUnavailable says only that the sandbox was refused, not that a
    backend is missing. An unclassified refusal grades the scan ERROR with the
    reason carried, never a silent MISSING: only an auto request with no working
    backend reads as a missing dependency."""
    with patch(
        "automated_security_helper.core.phases.scanner_executor.scanner_sandbox_scope",
        side_effect=SandboxUnavailable("sandbox refused (unclassified)"),
    ):
        results = _scan(context, [_scanner_class("tool-a")])

    report = results.additional_reports["tool-a"]["source"]
    assert report["status"] == "ERROR", report
    assert "sandbox refused (unclassified)" in str(report), report

    for when, model in _both(results):
        row = model.scanner_results["tool-a"]
        assert row.status == ScannerStatus.ERROR, (when, row)
        assert not row.missing_reason, f"{when}: {row.missing_reason!r}"
        assert row.exit_code is None, f"{when}: the tool never started: {row!r}"


def test_the_sandbox_refusal_is_recorded_for_a_plugin_with_no_reason_hooks(context):
    """The executor's own write of the refusal, with nothing else to supply it.

    For a ScannerPluginBase plugin the reason can also arrive through the plugin's
    own recording hooks, so removing the executor's write leaves that test passing.
    A plain class has none, so only the write can put the refusal on the container.
    The unclassified refusal grades the scan ERROR, with the reason carried on the
    container, and the scanner never runs.
    """
    from types import SimpleNamespace

    from automated_security_helper.core.phases.scanner_executor import (
        ScannerExecutor,
    )

    class _PlainScanner:
        def __init__(self):
            self.config = SimpleNamespace(
                name="plain-tool",
                enabled=True,
                options=SimpleNamespace(severity_threshold=None),
            )
            self.context = context
            self.dependencies_satisfied = True
            # Read by the executor after the scan, as the base class declares them.
            self.start_time = None
            self.end_time = None
            # The record is what shows the scanner never ran: the executor turns
            # a raise from scan() into an ERROR row too, so with ERROR expected
            # the raise alone can no longer tell a refusal from a run.
            self.ran: list = []

        def scan(self, *args, **kwargs):
            self.ran.append(args)
            raise AssertionError("a scanner that could not be sandboxed must not run")

    executor = ScannerExecutor(
        plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
    )
    scanner = _PlainScanner()
    with patch(
        "automated_security_helper.core.phases.scanner_executor.scanner_sandbox_scope",
        side_effect=SandboxUnavailable("sandbox refused (unclassified)"),
    ):
        (container,) = executor._execute_scanner(
            "plain-tool",
            scanner,
            [{"path": context.source_dir, "type": "source"}],
        )

    assert not scanner.ran, f"the scanner ran unsandboxed: {scanner.ran}"
    assert container.status == ScannerStatus.ERROR, container
    assert not container.missing_reason, container.missing_reason
    carried = [str(line) for line in container.errors]
    raw = container.raw_results if isinstance(container.raw_results, dict) else {}
    carried.extend(str(line) for line in (raw.get("errors") or []))
    assert any("sandbox refused (unclassified)" in line for line in carried), carried


def test_rows_of_scanners_that_ran_carry_no_reason(context):
    """Control: a reason is only for SKIPPED and MISSING."""
    results = _scan(context, [_scanner_class("tool-a")])

    row = results.scanner_results["tool-a"]
    assert row.status == ScannerStatus.PASSED
    assert row.missing_reason is None
    assert row.skipped_reason is None
    assert _flat(results, "tool-a")["missing_reason"] is None


# A scanner whose scan() finds its dependencies unavailable on one tree only. ScanPhase
# gives each scanner the source tree and, when the convert phase wrote files, the
# converted tree, and the executor records MISSING on the one container. No rule ran
# against that tree, so the row is MISSING too (contract clause 3i), and its reason
# says which tree, because the plugin's own reason does not and the other tree was
# scanned.

_GONE_REASON = "tool-a-tool needs a rule pack it could not load"


def _with_converted_files(context):
    """What the convert phase leaves behind: ScanPhase then scans the work dir too."""
    (context.work_dir / "notebook.py").write_text("y = 2\n", encoding="utf-8")


def _gone_on(*trees: str):
    cls = _scanner_class("tool-a")

    class _GoneOnSomeTrees(cls):
        def scan(self, target, target_type, global_ignore_paths=None, config=None):
            if target_type in trees:
                self.dependency_unavailable_reason = _GONE_REASON
                return False
            return super().scan(target, target_type, global_ignore_paths, config)

    _GoneOnSomeTrees.__name__ = cls.__name__
    return _GoneOnSomeTrees


def _assert_missing_row(when, model, reason):
    from automated_security_helper.interactions.run_ash_scan import (
        scan_incompleteness,
    )

    row = model.scanner_results["tool-a"]
    assert row.status == ScannerStatus.MISSING, f"{when}: {row!r}"
    assert row.dependencies_satisfied is False, f"{when}: {row!r}"
    assert row.missing_reason == reason, f"{when}: {row!r}"

    flat = _flat(model, "tool-a")
    assert flat["status"] == "MISSING", f"{when}: {flat!r}"
    assert flat["dependencies_missing"] is True, f"{when}: {flat!r}"
    assert flat["missing_reason"] == reason, f"{when}: {flat!r}"

    incomplete = scan_incompleteness(model, gate=True)
    assert ("tool-a", "MISSING") in incomplete.scanners, f"{when}: {incomplete!r}"
    assert dict(incomplete.missing_reasons).get("tool-a") == reason, (
        f"{when}: {incomplete!r}"
    )
    return row


def test_a_scanner_missing_only_on_the_converted_files_is_missing_and_says_where(
    context,
):
    _with_converted_files(context)
    results = _scan(context, [_gone_on("converted")])

    for when, model in _both(results):
        reports = model.additional_reports["tool-a"]
        assert reports["source"]["status"] == "PASSED", f"{when}: {reports!r}"
        assert reports["converted"]["status"] == "MISSING", f"{when}: {reports!r}"
        row = _assert_missing_row(
            when, model, f"on the converted files: {_GONE_REASON}"
        )
        assert row.exit_code == 0, f"{when}: the tool ran on the source files: {row!r}"


def test_a_scanner_missing_only_on_the_source_files_says_where(context):
    """The mirror case: the converted tree was scanned."""
    _with_converted_files(context)
    results = _scan(context, [_gone_on("source")])

    for when, model in _both(results):
        _assert_missing_row(when, model, f"on the source files: {_GONE_REASON}")


def test_a_scanner_missing_on_both_trees_keeps_its_reason_as_recorded(context):
    """Control: nothing was evaluated, so the row names no tree."""
    _with_converted_files(context)
    results = _scan(context, [_gone_on("source", "converted")])

    for when, model in _both(results):
        row = _assert_missing_row(when, model, _GONE_REASON)
        assert row.exit_code is None, f"{when}: the tool never ran: {row!r}"


def test_a_report_returned_without_its_dependencies_is_missing_and_says_where(
    context,
):
    """A scan() override that records its tool absent and returns a report anyway.

    The converted tree's report is PASSED with dependencies_satisfied false. The
    executor records the scanner's reason on it and logs it, as for a falsy return,
    and the row is MISSING with the tree named.
    """
    _with_converted_files(context)
    cls = _scanner_class("tool-a")

    class _ReportsAnyway(cls):
        def scan(self, target, target_type, global_ignore_paths=None, config=None):
            report = super().scan(target, target_type, global_ignore_paths, config)
            if target_type == "converted":
                self.dependencies_satisfied = False
                self.dependency_unavailable_reason = _GONE_REASON
            return report

    _ReportsAnyway.__name__ = cls.__name__
    with _ash_log() as records:
        results = _scan(context, [_ReportsAnyway])

    for when, model in _both(results):
        converted = model.additional_reports["tool-a"]["converted"]
        assert converted.get("dependencies_satisfied") is False, f"{when}: {converted}"
        _assert_missing_row(when, model, f"on the converted files: {_GONE_REASON}")
    _assert_logged(records, "tool-a", _GONE_REASON, logging.WARNING)


@pytest.mark.parametrize("where", ["elsewhere", "under HOME"])
def test_a_report_returned_without_its_dependencies_names_no_environment_value(
    context, where
):
    """Its reason and WARNING are redacted with the config's environment values,
    before the home directory is written as ~, as a falsy return's are: the
    plugin's reason can name a path the config read from the environment."""
    value = (
        "/nonexistent/ENVCANARY-reason/rules.yaml"
        if where == "elsewhere"
        else (Path.home() / "ENVCANARY-reason" / "rules.yaml").as_posix()
    )
    context.config._environment_values = [value]
    _with_converted_files(context)
    cls = _scanner_class("tool-a")

    class _ReportsAnyway(cls):
        def scan(self, target, target_type, global_ignore_paths=None, config=None):
            report = super().scan(target, target_type, global_ignore_paths, config)
            if target_type == "converted":
                self.dependencies_satisfied = False
                self.dependency_unavailable_reason = (
                    f"tool-a-tool could not load {value}"
                )
            return report

    _ReportsAnyway.__name__ = cls.__name__
    with _ash_log() as records:
        results = _scan(context, [_ReportsAnyway])

    for when, model in _both(results):
        row = model.scanner_results["tool-a"]
        assert row.status == ScannerStatus.MISSING, f"{when}: {row!r}"
        # The control: the plugin's reason is the row's.
        assert "could not load" in (row.missing_reason or ""), f"{when}: {row!r}"
        assert "ENVCANARY-reason" not in (row.missing_reason or ""), f"{when}: {row!r}"
    warned = [text for level, text in records if level >= logging.WARNING]
    assert any("could not load" in text for text in warned), warned
    for text in warned:
        assert "ENVCANARY-reason" not in text, text


@pytest.mark.parametrize(
    "limit,token",
    [
        pytest.param(1000000, "'1000000' s", id="large"),
        pytest.param(7.5, "'7.5' s", id="fraction"),
    ],
)
def test_a_killed_runs_error_prints_its_limit_whole(context, limit, token):
    """The executor's error for a scanner whose tool was killed at its
    timeout prints the limit whole, never '1e+06'."""
    from automated_security_helper.core.exceptions import ScannerError

    cls = _scanner_class("tool-a")

    class _Killed(cls):
        def scan(self, target, target_type, global_ignore_paths=None, config=None):
            self._record_timeout({"timed_out": True}, limit)
            raise ScannerError("its results file was missing")

    _Killed.__name__ = cls.__name__
    results = _scan(context, [_Killed])

    report = results.additional_reports["tool-a"]["source"]
    errors = report.get("errors") or report.get("raw_results", {}).get("errors")
    assert errors, report
    assert f"timed out after {token} on source and was killed" in errors[0], errors


# Each caller of the missing- and skipped-reason helpers hands them the config's
# environment values: a helper's DEBUG line for a hook that raises repeats the
# exception, and the stored reason is the plugin's own text. The helper
# cells (test_phase_helper_lines_carry_no_environment_value.py) call the
# helpers directly, so these drive each caller.

_HOOK_VALUE = "/nonexistent/ENVCANARY-hookv/rules.yaml"


@pytest.mark.parametrize(
    "where",
    [
        pytest.param("tool check", id="scan-phase-tool-check"),
        pytest.param("falsy return", id="executor-falsy-return"),
        pytest.param("report", id="executor-report-without-dependencies"),
    ],
)
def test_a_missing_reason_hook_that_raises_names_no_environment_value(context, where):
    context.config._environment_values = [_HOOK_VALUE]
    cls = _scanner_class("tool-a", tool_found=where != "tool check")

    class _Gone(cls):
        def scan(self, target, target_type, global_ignore_paths=None, config=None):
            if where == "falsy return":
                return False
            report = super().scan(target, target_type, global_ignore_paths, config)
            self.dependencies_satisfied = False
            return report

        def missing_dependency_reason(self):
            raise RuntimeError(f"could not read {_HOOK_VALUE}")

    _Gone.__name__ = cls.__name__
    with _ash_log(logging.DEBUG) as records:
        results = _scan(context, [_Gone])

    assert results.scanner_results["tool-a"].status == ScannerStatus.MISSING
    # The control: the hook raised, and its caller logged it.
    lines = [text for _, text in records if "recording the generic reason" in text]
    assert lines, records
    for text in lines:
        assert "could not read" in text, text
        assert "ENVCANARY-hookv" not in text, text


#: A value only the plugin's own ``_environment_values()`` gives.
_OWN_VALUE = "/nonexistent/ENVCANARY-ownv/keys"


@pytest.mark.parametrize(
    "where",
    [
        pytest.param("tool check", id="scan-phase-tool-check"),
        pytest.param("falsy return", id="executor-falsy-return"),
        pytest.param("report", id="executor-report-without-dependencies"),
    ],
)
def test_a_missing_reason_is_redacted_with_the_plugin_s_own_values(context, where):
    """Each caller redacts the plugin's reason with the run's values and the
    plugin's own (plugin_environment_values), as ash dependencies install does: a
    reason quoting a value only the plugin knows prints it on no row and in no
    WARNING."""
    context.config._environment_values = [_HOOK_VALUE]
    cls = _scanner_class("tool-a", tool_found=where != "tool check")

    class _OwnValues(cls):
        def _environment_values(self):
            return (*super()._environment_values(), _OWN_VALUE)

        def scan(self, target, target_type, global_ignore_paths=None, config=None):
            if where == "falsy return":
                return False
            report = super().scan(target, target_type, global_ignore_paths, config)
            self.dependencies_satisfied = False
            return report

        def missing_dependency_reason(self):
            return f"needs a key file under {_OWN_VALUE}"

    _OwnValues.__name__ = cls.__name__
    with _ash_log() as records:
        results = _scan(context, [_OwnValues])

    for when, model in _both(results):
        row = model.scanner_results["tool-a"]
        assert row.status == ScannerStatus.MISSING, f"{when}: {row!r}"
        # The control: the plugin's reason is the row's.
        assert "needs a key file under" in (row.missing_reason or ""), (
            f"{when}: {row!r}"
        )
        assert "ENVCANARY-ownv" not in (row.missing_reason or ""), f"{when}: {row!r}"
    warned = [text for level, text in records if level >= logging.WARNING]
    assert any("needs a key file under" in text for text in warned), warned
    for text in warned:
        assert "ENVCANARY-ownv" not in text, text


@pytest.mark.parametrize("hook", ["returns", "raises"])
def test_a_skipped_reason_names_no_environment_value(context, hook):
    """A tracking scanner that attempted no target: the executor asks its
    nothing_to_scan_reason and stores the answer as the row's skipped_reason."""
    context.config._environment_values = [_HOOK_VALUE]
    cls = _scanner_class("tool-a", targets_attempted=0)

    class _Nothing(cls):
        def nothing_to_scan_reason(self):
            if hook == "raises":
                raise RuntimeError(f"could not read {_HOOK_VALUE}")
            return f"no rules under {_HOOK_VALUE}"

    _Nothing.__name__ = cls.__name__
    with _ash_log(logging.DEBUG) as records:
        results = _scan(context, [_Nothing])

    for when, model in _both(results):
        row = model.scanner_results["tool-a"]
        assert row.status == ScannerStatus.SKIPPED, f"{when}: {row!r}"
        assert "ENVCANARY-hookv" not in (row.skipped_reason or ""), f"{when}: {row!r}"
        if hook == "returns":
            # The control: the plugin's reason is the row's.
            assert "no rules under" in (row.skipped_reason or ""), f"{when}: {row!r}"
    text = "\n".join(text for _, text in records)
    if hook == "raises":
        assert "recording the generic reason" in text, text
    assert "ENVCANARY-hookv" not in text, text


@pytest.mark.parametrize(
    "where",
    [
        pytest.param("tool check", id="scan-phase-tool-check"),
        pytest.param("falsy return", id="executor-falsy-return"),
    ],
)
def test_a_missing_reason_is_redacted_with_the_run_s_values_when_the_plugin_s_raise(
    context, where
):
    """A plugin whose own ``_environment_values()`` raises adds no value, and
    the run's values still redact its reason: the getter's failure costs the
    plugin's values, never the run's."""
    context.config._environment_values = [_HOOK_VALUE]
    cls = _scanner_class("tool-a", tool_found=where != "tool check")

    class _GetterRaises(cls):
        def _environment_values(self):
            if getattr(self, "_raise_values", False):
                raise RuntimeError("the plugin's values could not be read")
            return super()._environment_values()

        def validate_plugin_dependencies(self) -> bool:
            self._raise_values = True
            return super().validate_plugin_dependencies()

        def scan(self, target, target_type, global_ignore_paths=None, config=None):
            self._raise_values = True
            return False

        def missing_dependency_reason(self):
            return f"needs a key file under {_HOOK_VALUE}"

    _GetterRaises.__name__ = cls.__name__
    results = _scan(context, [_GetterRaises])

    for when, model in _both(results):
        row = model.scanner_results["tool-a"]
        assert row.status == ScannerStatus.MISSING, f"{when}: {row!r}"
        # The control: the plugin's reason is the row's.
        assert "needs a key file under" in (row.missing_reason or ""), (
            f"{when}: {row!r}"
        )
        assert "ENVCANARY-hookv" not in (row.missing_reason or ""), f"{when}: {row!r}"


def _own_values(cls):
    """*cls* with ``_environment_values()`` adding _OWN_VALUE to the run's."""

    class _OwnValues(cls):
        def _environment_values(self):
            return (*super()._environment_values(), _OWN_VALUE)

    _OwnValues.__name__ = cls.__name__
    return _OwnValues


def _no_own_value(texts):
    for text in texts:
        assert "ENVCANARY-ownv" not in str(text), text


@pytest.mark.parametrize(
    "where",
    [
        pytest.param("tool check", id="scan-phase-nothing-to-scan"),
        pytest.param("no target", id="executor-skipped-reason"),
    ],
)
def test_a_nothing_to_scan_reason_is_redacted_with_the_plugin_s_own_values(
    context, where
):
    """The plugin's nothing_to_scan_reason, asked by the scan phase for a
    scanner without its tool, and by the executor for one that attempted no
    target: the row and ash.log redact it with the plugin's own values too."""
    context.config._environment_values = [_HOOK_VALUE]
    if where == "tool check":
        cls = _scanner_class("tool-a", tool_found=False)
    else:
        cls = _scanner_class("tool-a", targets_attempted=0)

    class _Nothing(cls):
        def nothing_to_scan_reason(self):
            return f"no rules under {_OWN_VALUE}"

    _Nothing.__name__ = cls.__name__
    with _ash_log(logging.DEBUG) as records:
        results = _scan(context, [_own_values(_Nothing)])

    for when, model in _both(results):
        row = model.scanner_results["tool-a"]
        assert row.status == ScannerStatus.SKIPPED, f"{when}: {row!r}"
        # The control: the plugin's reason is the row's.
        assert "no rules under" in (row.skipped_reason or ""), f"{when}: {row!r}"
        _no_own_value([row.skipped_reason])
    assert any("no rules under" in text for _, text in records), records
    _no_own_value(text for _, text in records)


@pytest.mark.parametrize("ending", ["raises", "returns-none"])
def test_a_failed_scan_s_tool_lines_are_redacted_with_the_plugin_s_own_values(
    context, ending
):
    """What the tool wrote, kept in the report's errors and output when the
    scan fails or returns nothing, is redacted with the plugin's own values."""
    from automated_security_helper.core.exceptions import ScannerError

    cls = _scanner_class("tool-a")

    class _Failing(cls):
        def scan(self, target, target_type, global_ignore_paths=None, config=None):
            self.errors.append(f"cannot open {_OWN_VALUE}")
            self.output.append(f"reading {_OWN_VALUE}")
            if ending == "raises":
                raise ScannerError("the scan failed")
            return None

    _Failing.__name__ = cls.__name__
    results = _scan(context, [_own_values(_Failing)])

    report = results.additional_reports["tool-a"]["source"]
    raw = report.get("raw_results") or {}
    # The control: the tool's lines are kept.
    assert any("cannot open" in str(line) for line in raw.get("errors", [])), raw
    assert any("reading" in str(line) for line in raw.get("output", [])), raw
    _no_own_value(raw.get("errors", []))
    _no_own_value(raw.get("output", []))


@pytest.mark.parametrize(
    "where",
    [
        pytest.param("check", id="the-dependency-check-raises"),
        pytest.param("per-target", id="the-scan-raises"),
        pytest.param("sequential", id="the-run-loop-raises"),
        pytest.param("parallel", id="the-pool-raises"),
        pytest.param("loop-sequential", id="the-sequential-loop-handler"),
        pytest.param("loop-parallel", id="the-pool-future-handler"),
    ],
)
def test_a_scan_s_exception_text_is_redacted_with_the_plugin_s_own_values(
    context, where
):
    """A scan whose run raised: the exception's text in the report, the results
    container and ash.log is redacted with the plugin's own values too.
    Before the run, the plugin's dependency check raises in the scan phase;
    per-target, the plugin's scan() raises; in the run loops, the executor's
    per-scanner work raises before any target, sequentially and in the pool,
    and the run wrapper's handler records it. The loop handlers' own cases
    patch the wrapper itself, so the raise reaches the sequential loop's
    handler and the pool's handler for a future."""
    from unittest.mock import patch

    from automated_security_helper.core.phases.scanner_executor import (
        ScannerExecutor,
    )

    cls = _scanner_class("tool-a")

    class _Raising(cls):
        def validate_plugin_dependencies(self) -> bool:
            if where == "check":
                raise RuntimeError(f"cannot read {_OWN_VALUE}")
            return super().validate_plugin_dependencies()

        def scan(self, target, target_type, global_ignore_paths=None, config=None):
            raise RuntimeError(f"cannot read {_OWN_VALUE}")

    _Raising.__name__ = cls.__name__
    plugins = [_own_values(_Raising)]
    if where in ("parallel", "loop-parallel"):
        # One task runs sequentially; two go through the pool.
        plugins.append(_own_values(_Raising))
        plugins[-1].__name__ = "tool_b_scanner"

    def _execute(executor_self, scanner_name, scanner_plugin, scan_targets):
        raise RuntimeError(f"cannot read {_OWN_VALUE}")

    # The run wrapper catches what the per-scanner work raises, so the loop
    # handlers are reached only by a raise from the wrapper itself.
    patched = (
        "_safe_execute_scanner" if where.startswith("loop-") else "_execute_scanner"
    )
    with _ash_log(logging.DEBUG) as records:
        if where in ("check", "per-target"):
            results = _scan(context, plugins)
        else:
            with patch.object(
                ScannerExecutor, patched, autospec=True, side_effect=_execute
            ):
                aggregated = AshAggregatedResults()
                phase = ScanPhase(
                    plugin_context=context,
                    plugins=plugins,
                    progress_display=MagicMock(),
                    asharp_model=aggregated,
                )
                results = phase._execute_phase(
                    aggregated_results=aggregated,
                    parallel=where in ("parallel", "loop-parallel"),
                    max_workers=2,
                )
    texts = [text for _, text in records]
    # The control: the exception was logged.
    assert any("cannot read" in text for text in texts), texts
    _no_own_value(texts)
    _no_own_value([results.model_dump_json()])


class TestCdkNagSaysWhatIsMissing:
    """cdk-nag's tool is ASH's own Python, so a generic 'tool not found' is wrong."""

    @pytest.fixture
    def scanner(self, context):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
            CdkNagScanner,
        )

        return CdkNagScanner(context=context)

    def test_without_node(self, scanner):
        from automated_security_helper.plugin_modules.ash_builtin.scanners import (
            cdk_nag_scanner,
        )

        with (
            patch.object(cdk_nag_scanner, "_CDK_AVAILABLE", True),
            patch.object(cdk_nag_scanner, "find_executable", return_value=None),
        ):
            assert scanner.validate_plugin_dependencies() is False
            reason = scanner.missing_dependency_reason()

        assert "node" in reason, reason

    def test_without_the_cdk_packages(self, scanner):
        from automated_security_helper.plugin_modules.ash_builtin.scanners import (
            cdk_nag_scanner,
        )

        with patch.object(cdk_nag_scanner, "_CDK_AVAILABLE", False):
            assert scanner.validate_plugin_dependencies() is False
            reason = scanner.missing_dependency_reason()

        assert "ash dependencies install" in reason, reason

    @pytest.mark.parametrize("cdk_available", [False, True], ids=["no-cdk", "no-node"])
    def test_the_reason_cdk_nag_records_itself_wins(self, scanner, cdk_available):
        """A reason its own dependency check recorded is more specific than a guess."""
        from automated_security_helper.plugin_modules.ash_builtin.scanners import (
            cdk_nag_scanner,
        )

        scanner.dependency_unavailable_reason = "the reason cdk-nag recorded"
        with (
            patch.object(cdk_nag_scanner, "_CDK_AVAILABLE", cdk_available),
            patch.object(cdk_nag_scanner, "find_executable", return_value=None),
        ):
            reason = scanner.missing_dependency_reason()

        assert reason == "the reason cdk-nag recorded"


def test_the_reason_a_plugin_records_is_the_missing_reason(context):
    """dependency_unavailable_reason, when a scanner recorded one, wins."""
    cls = _scanner_class("tool-a", tool_found=False)

    class _Recorded(cls):
        def validate_plugin_dependencies(self) -> bool:
            self.dependency_unavailable_reason = "offline mode: no rule cache"
            return False

    _Recorded.__name__ = cls.__name__
    results = _scan(context, [_Recorded])

    assert results.scanner_results["tool-a"].missing_reason == (
        "offline mode: no rule cache"
    )


def test_a_reason_is_read_off_a_plugin_double_only_when_it_is_text(tmp_path):
    """A MagicMock answers every method with a Mock; that is not a reason."""
    from automated_security_helper.core.phases.scan_phase import (
        _missing_dependency_reason,
    )

    double = MagicMock()
    double.config.name = "double"
    reason = _missing_dependency_reason(double)
    assert isinstance(reason, str) and reason
    assert "double" in reason


def test_the_reason_fields_are_declared_in_the_schema():
    repo_root = Path(__file__).resolve().parents[3]
    schema = (
        repo_root / "automated_security_helper/schemas/AshAggregatedResults.json"
    ).read_text(encoding="utf-8")
    assert '"missing_reason"' in schema
    assert '"skipped_reason"' in schema


def test_a_scanner_another_shard_owns_says_so(context):
    results = _scan(
        context,
        [_scanner_class("tool-a"), _scanner_class("tool-b")],
        shard_index=0,
        shard_count=2,
    )

    skipped = [
        row
        for row in results.scanner_results.values()
        if row.status == ScannerStatus.SKIPPED
    ]
    assert len(skipped) == 1, results.scanner_results
    assert "another shard" in (skipped[0].skipped_reason or ""), skipped[0]
    assert skipped[0].excluded is True


def test_a_scanner_python_only_leaves_out_says_so(context):
    cls = _scanner_class("tool-a", tool_found=False)

    class _NotPython(cls):
        def is_python_only(self) -> bool:
            return False

    _NotPython.__name__ = cls.__name__
    results = _scan(context, [_NotPython], python_based_plugins_only=True)

    row = results.scanner_results["tool-a"]
    assert row.status == ScannerStatus.SKIPPED, row
    assert "--python-only" in (row.skipped_reason or ""), row.skipped_reason


def _home_forms() -> list[str]:
    import os

    home = str(Path.home())
    return sorted({home, os.path.realpath(home)})


def test_a_missing_reason_does_not_carry_the_home_directory(context, monkeypatch):
    """The reason reaches the results, ash.flat.json, MCP rows and cloud payloads.

    The reason names ASH's bin directory with the home directory written as ~
    ("not found on PATH or in ~/.ash/bin, /usr/local/bin"); ash.log keeps the
    absolute path.
    """
    monkeypatch.delenv("ASH_BIN_PATH", raising=False)
    from automated_security_helper.utils import subprocess_utils

    monkeypatch.setattr(
        subprocess_utils, "ASH_BIN_PATH", Path.home() / ".ash" / "bin", raising=False
    )
    results = _scan(context, [_scanner_class("tool-a", tool_found=False)])

    for when, model in _both(results):
        reason = model.scanner_results["tool-a"].missing_reason or ""
        assert "~/.ash/bin" in reason, f"{when}: {reason!r}"
        for home in _home_forms():
            assert home not in reason, f"{when}: {reason!r}"
            for report in model.additional_reports["tool-a"].values():
                assert home not in str(report.get("missing_reason")), (when, report)
            assert home not in str(_flat(model, "tool-a")["missing_reason"]), when


def test_a_recorded_reason_does_not_carry_the_home_directory(context):
    """A dependency check's own reason, such as the uv offline one, names paths too."""
    cls = _scanner_class("tool-a", tool_found=False)
    uv = f"{Path.home()}/.local/bin/uv"

    class _Recorded(cls):
        def validate_plugin_dependencies(self) -> bool:
            self.dependency_unavailable_reason = (
                f"Offline mode: tool-a-tool at {uv} cannot be used: too old."
            )
            return False

    _Recorded.__name__ = cls.__name__
    results = _scan(context, [_Recorded])

    reason = results.scanner_results["tool-a"].missing_reason
    assert (
        reason
        == "Offline mode: tool-a-tool at ~/.local/bin/uv cannot be used: too old."
    )


def _assert_no_home(when, text):
    for home in _home_forms():
        assert home not in text, f"{when}: {text!r}"


def test_a_reason_found_during_the_scan_does_not_carry_the_home_directory(context):
    """The executor's site: scan() finds its dependency gone and returns False."""
    cls = _scanner_class("tool-a")

    class _GoneAtScan(cls):
        def scan(self, target, target_type, global_ignore_paths=None, config=None):
            self.dependency_unavailable_reason = (
                f"tool-a-tool vanished from {Path.home()}/x"
            )
            return False

    _GoneAtScan.__name__ = cls.__name__
    results = _scan(context, [_GoneAtScan])

    for when, model in _both(results):
        row = model.scanner_results["tool-a"]
        assert row.status == ScannerStatus.MISSING, f"{when}: {row!r}"
        assert row.missing_reason == "tool-a-tool vanished from ~/x", (when, row)
        _assert_no_home(when, row.missing_reason)
        for report in model.additional_reports["tool-a"].values():
            _assert_no_home(when, str(report.get("missing_reason")))


def test_a_sandbox_refusal_does_not_carry_the_home_directory(context):
    """The executor's sandbox-refusal site. An unclassified refusal grades the scan
    ERROR with no missing_reason, so the reason lives in the recorded errors, and
    the home directory in it is written as a tilde wherever it appears."""
    refusal = f"bwrap at {Path.home()}/bin/bwrap refused"
    with patch(
        "automated_security_helper.core.phases.scanner_executor.scanner_sandbox_scope",
        side_effect=SandboxUnavailable(refusal),
    ):
        results = _scan(context, [_scanner_class("tool-a")])

    report = results.additional_reports["tool-a"]["source"]
    assert "~/bin/bwrap" in str(report), report
    _assert_no_home("report", str(report))

    for when, model in _both(results):
        row = model.scanner_results["tool-a"]
        assert row.status == ScannerStatus.ERROR, (when, row)
        assert not row.missing_reason, f"{when}: {row.missing_reason!r}"
        _assert_no_home(when, str(row))
        for report in model.additional_reports["tool-a"].values():
            _assert_no_home(when, str(report))


def test_ash_log_keeps_the_absolute_path_the_reports_write_as_tilde(
    context, monkeypatch
):
    """ScanPhase's WARNING is the ash.log line for a missing tool; it keeps the path.

    find_executable's own lines are DEBUG, below the file handler's INFO, so this
    warning is the only place ash.log says where ASH looked.
    """
    from automated_security_helper.utils import subprocess_utils
    from automated_security_helper.utils.log import ASH_LOGGER

    monkeypatch.delenv("ASH_BIN_PATH", raising=False)
    bin_dir = Path.home() / ".ash" / "bin"
    monkeypatch.setattr(subprocess_utils, "ASH_BIN_PATH", bin_dir, raising=False)

    with patch.object(ASH_LOGGER, "warning", wraps=ASH_LOGGER.warning) as warning:
        results = _scan(context, [_scanner_class("tool-a", tool_found=False)])

    logged = [
        str(call.args[0])
        for call in warning.call_args_list
        if call.args and "marking as MISSING" in str(call.args[0])
    ]
    assert logged and bin_dir.as_posix() in logged[0], logged
    assert "~/.ash/bin" in (results.scanner_results["tool-a"].missing_reason or "")


@pytest.mark.parametrize(
    "home,text,expected",
    [
        (
            "/home/u",
            "in /home/u/.ash/bin, /usr/local/bin",
            "in ~/.ash/bin, /usr/local/bin",
        ),
        ("/home/u", "at /home/u", "at ~"),
        ("/home/u", "/home/ub/.ash/bin", "/home/ub/.ash/bin"),
        ("/home/u", "/srv/home/u/x", "/srv/home/u/x"),
        ("/", "/usr/local/bin", "/usr/local/bin"),
        # A home inside a longer path is not the home: after "+", after "file://",
        # after another "/".
        ("/home/u", "/opt/a+/home/u/x", "/opt/a+/home/u/x"),
        ("/home/u", "file:///home/u/x", "file:///home/u/x"),
        ("/home/u", "//home/u/x", "//home/u/x"),
        ("/home/u", "(/home/u/x) HOME=/home/u", "(~/x) HOME=~"),
        # A relative HOME is not a home directory to rewrite.
        ("home/u", "/data/home/u/x", "/data/home/u/x"),
        # Windows: the not-found reason writes as_posix() paths, and the drive and
        # the directory names are case-insensitive.
        ("C:\\Users\\u", "or in C:/Users/u/.ash/bin, x", "or in ~/.ash/bin, x"),
        ("C:\\Users\\u", "at C:\\Users\\u\\.ash\\bin", "at ~\\.ash\\bin"),
        ("C:\\Users\\u", "at c:\\users\\u\\x", "at ~\\x"),
        ("C:\\Users\\u", "at C:/Users/U/x", "at ~/x"),
        ("C:\\Users\\u", "at C:/Users/ub/x", "at C:/Users/ub/x"),
        ("C:\\", "at C:\\x", "at C:\\x"),
        # Brackets, angle brackets and braces bound a path too, on either side.
        ("/home/u", "searched [/home/u/.ash/bin]", "searched [~/.ash/bin]"),
        ("/home/u", "at </home/u/x> {/home/u}", "at <~/x> {~}"),
        ("/home/u", "searched [/home/u] at </home/u>", "searched [~] at <~>"),
        # The docstring's limit: a name that goes on with a boundary character
        # is rewritten too, though it is not under the home directory.
        ("/home/u", "at /home/u]x/y", "at ~]x/y"),
        ("/home/u", "at /opt/a[/home/u/x", "at /opt/a[~/x"),
    ],
)
def test_home_as_tilde_replaces_only_the_whole_home_directory(
    monkeypatch, home, text, expected
):
    from pathlib import PurePosixPath, PureWindowsPath

    from automated_security_helper.core import constants
    from automated_security_helper.utils.get_shortest_name import home_as_tilde

    # A pure path of the simulated platform: a concrete Path("/home/u") is a
    # WindowsPath on Windows, whose str() is "\\home\\u", and home_as_tilde reads
    # no home in that, so the POSIX rows would fail there for the wrong reason.
    simulated = PureWindowsPath(home) if ":" in home else PurePosixPath(home)
    # The home comes from core.constants.usable_home, the one place ASH reads it.
    monkeypatch.setattr(constants, "usable_home", lambda: simulated)
    monkeypatch.setattr("os.path.realpath", lambda p: p)

    assert home_as_tilde(text) == expected


def test_home_as_tilde_replaces_the_resolved_home_too(monkeypatch):
    """A home that is a symlink: a reason can name either spelling."""
    from pathlib import PurePosixPath

    from automated_security_helper.core import constants
    from automated_security_helper.utils.get_shortest_name import home_as_tilde

    monkeypatch.setattr(constants, "usable_home", lambda: PurePosixPath("/home/u"))
    monkeypatch.setattr(
        "os.path.realpath", lambda p: "/data/home/u" if p == "/home/u" else p
    )

    assert home_as_tilde("in /data/home/u/.ash/bin and /home/u/x") == (
        "in ~/.ash/bin and ~/x"
    )


def test_a_unc_resolved_home_is_not_recognized(monkeypatch):
    """The docstring's "Not recognized: a UNC home", for the resolved spelling.

    A mapped drive resolves to its share. That spelling is neither "/"- nor
    drive-rooted, so it is not a form, and the share path stays as written; the
    drive spelling is still replaced.
    """
    from automated_security_helper.core import constants
    from automated_security_helper.utils.get_shortest_name import home_as_tilde

    monkeypatch.setattr(constants, "usable_home", lambda: Path("H:\\u"))
    monkeypatch.setattr(
        "os.path.realpath", lambda p: "\\\\srv\\share\\u" if p == "H:\\u" else p
    )

    assert home_as_tilde("at \\\\srv\\share\\u\\x and H:\\u\\y") == (
        "at \\\\srv\\share\\u\\x and ~\\y"
    )


def test_a_relative_home_rewrites_nothing(monkeypatch, tmp_path):
    """The real realpath of a relative HOME is the cwd joined to it: not a home."""
    from automated_security_helper.utils.get_shortest_name import home_as_tilde

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: Path("home/u")))
    under_cwd = f"at {tmp_path}/home/u/x"

    assert home_as_tilde("at home/u/x") == "at home/u/x"
    assert home_as_tilde(under_cwd) == under_cwd


def test_a_reason_with_a_closing_tag_does_not_crash_the_scan_phase(context):
    """ScanPhase logs a MISSING scanner's reason; a "[/x]" in it is data to Rich."""
    import io
    import logging

    from rich.console import Console
    from rich.logging import RichHandler

    from automated_security_helper.utils.log import ASH_LOGGER

    cls = _scanner_class("tool-a", tool_found=False)

    class _Recorded(cls):
        def validate_plugin_dependencies(self) -> bool:
            self.dependency_unavailable_reason = "no rule cache in /opt/[/x]/rules"
            return False

    _Recorded.__name__ = cls.__name__
    buffer = io.StringIO()
    saved_handlers, saved_level = list(ASH_LOGGER.handlers), ASH_LOGGER.level
    ASH_LOGGER.handlers = [
        RichHandler(
            console=Console(file=buffer, width=250, color_system=None), markup=True
        )
    ]
    ASH_LOGGER.setLevel(logging.INFO)
    try:
        results = _scan(context, [_Recorded])
    finally:
        ASH_LOGGER.handlers = saved_handlers
        ASH_LOGGER.setLevel(saved_level)

    assert results.scanner_results["tool-a"].status == ScannerStatus.MISSING
    assert "/opt/[/x]/rules" in buffer.getvalue()


# ash.log says what the row says. For each path that records a skipped_reason or a
# missing_reason, the row's own text appears verbatim in a log record that names the
# scanner, at INFO or above (the level of ash.log's file handler), and at WARNING or
# above for a MISSING scanner, as ScanPhase's dependency WARNING is. The reasons used
# here name no path, so home_as_tilde leaves the row's text and the log's alike.
# For a scanner MISSING on one tree only, the rule holds per target: the executor's
# WARNING names the tree and the reason in its own words, and the row's "on the <tree>
# files: " prefix, added when the row is built, is not in ash.log verbatim.


class _Records(logging.Handler):
    def __init__(self, level=logging.INFO):
        super().__init__(level=level)
        self.records: list[tuple[int, str]] = []

    def emit(self, record):
        self.records.append((record.levelno, record.getMessage()))


@contextmanager
def _ash_log(level=logging.INFO):
    from automated_security_helper.utils.log import ASH_LOGGER

    handler = _Records(level)
    saved_level = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(level)
    try:
        yield handler.records
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(saved_level)


def _assert_logged(records, scanner, reason, level=logging.INFO):
    assert reason, f"{scanner}'s row has no reason to look for"
    naming = [(lvl, text) for lvl, text in records if scanner in text]
    carrying = [text for lvl, text in naming if lvl >= level and reason in text]
    assert carrying, (
        f"no record at {logging.getLevelName(level)} or above names {scanner} with "
        f"its row's reason {reason!r}; the records naming it: {naming}"
    )


def test_an_excluded_scanner_is_logged_with_its_rows_reason(context):
    with _ash_log() as records:
        results = _scan(
            context,
            [_scanner_class("tool-a"), _scanner_class("tool-b")],
            excluded_scanners=["tool-b"],
        )

    row = results.scanner_results["tool-b"]
    assert row.status == ScannerStatus.SKIPPED, row
    _assert_logged(records, "tool-b", row.skipped_reason)


def test_a_scanner_another_shard_owns_is_logged_with_its_rows_reason(context):
    with _ash_log() as records:
        results = _scan(
            context,
            [_scanner_class("tool-a"), _scanner_class("tool-b")],
            shard_index=0,
            shard_count=2,
        )

    (name,) = [
        name
        for name, row in results.scanner_results.items()
        if row.status == ScannerStatus.SKIPPED
    ]
    reason = results.scanner_results[name].skipped_reason
    assert "another shard" in (reason or ""), reason
    _assert_logged(records, name, reason)


def test_a_scanner_left_out_of_the_allowlist_is_logged_with_its_rows_reason(context):
    """Control: _record_scanner_not_selected's line."""
    with _ash_log() as records:
        results = _scan(
            context,
            [_scanner_class("tool-a"), _scanner_class("tool-b")],
            enabled_scanners=["tool-a"],
        )

    _assert_logged(records, "tool-b", results.scanner_results["tool-b"].skipped_reason)


def test_a_missing_dependency_is_logged_with_its_rows_reason(context):
    """Control: ScanPhase's dependency WARNING."""
    cls = _scanner_class("tool-a", tool_found=False)

    class _Recorded(cls):
        def validate_plugin_dependencies(self) -> bool:
            self.dependency_unavailable_reason = "tool-a-tool needs its rule library"
            return False

    _Recorded.__name__ = cls.__name__
    with _ash_log() as records:
        results = _scan(context, [_Recorded])

    row = results.scanner_results["tool-a"]
    assert row.missing_reason == "tool-a-tool needs its rule library", row
    _assert_logged(records, "tool-a", row.missing_reason, logging.WARNING)


def test_a_scanner_with_nothing_to_scan_is_logged_with_its_rows_reason(context):
    """Control: ScanPhase's nothing-to-scan line, for a scanner whose tool is absent."""
    cls = _scanner_class("tool-a", tool_found=False)

    class _NothingToScan(cls):
        def nothing_to_scan_reason(self):
            return "no measurement input in the scanned files"

    _NothingToScan.__name__ = cls.__name__
    with _ash_log() as records:
        results = _scan(context, [_NothingToScan])

    row = results.scanner_results["tool-a"]
    assert row.status == ScannerStatus.SKIPPED, row
    _assert_logged(records, "tool-a", row.skipped_reason)


def test_a_sandbox_refusal_is_logged_with_its_rows_reason(context):
    """Control: the executor's sandbox-refusal ERROR.

    A refused sandbox is an ERROR row with no missing_reason; its reason rides the
    executor's ERROR line instead.
    """
    with (
        patch(
            "automated_security_helper.core.phases.scanner_executor.scanner_sandbox_scope",
            side_effect=SandboxUnavailable("sandbox refused (unclassified)"),
        ),
        _ash_log() as records,
    ):
        results = _scan(context, [_scanner_class("tool-a")])

    row = results.scanner_results["tool-a"]
    assert row.status == ScannerStatus.ERROR, row
    assert not row.missing_reason, row
    _assert_logged(records, "tool-a", "sandbox refused (unclassified)", logging.ERROR)


def test_a_dependency_found_gone_at_scan_time_is_logged_with_its_rows_reason(context):
    """The executor's MISSING: scan() returns False with a reason of its own."""
    cls = _scanner_class("tool-a")

    class _GoneAtScan(cls):
        def scan(self, target, target_type, global_ignore_paths=None, config=None):
            self.dependency_unavailable_reason = "tool-a-tool vanished during the scan"
            return False

    _GoneAtScan.__name__ = cls.__name__
    with _ash_log() as records:
        results = _scan(context, [_GoneAtScan])

    row = results.scanner_results["tool-a"]
    assert row.missing_reason == "tool-a-tool vanished during the scan", row
    _assert_logged(records, "tool-a", row.missing_reason, logging.WARNING)


def test_the_generic_reason_for_a_scan_that_returned_false_is_logged(context):
    """The executor's own wording, when the plugin's explanation raises."""
    cls = _scanner_class("tool-a")

    class _Unexplained(cls):
        def scan(self, target, target_type, global_ignore_paths=None, config=None):
            return False

        def missing_dependency_reason(self) -> str:
            raise RuntimeError("no explanation available")

    _Unexplained.__name__ = cls.__name__
    with _ash_log() as records:
        results = _scan(context, [_Unexplained])

    row = results.scanner_results["tool-a"]
    assert "reported its dependencies unavailable" in (row.missing_reason or ""), row
    _assert_logged(records, "tool-a", row.missing_reason, logging.WARNING)


def test_a_scanner_that_attempted_no_target_is_logged_with_its_rows_reason(context):
    """The executor's SKIPPED: the scan ran and evaluated nothing."""
    with _ash_log() as records:
        results = _scan(
            context, [_scanner_class("tool-a", exit_code=0, targets_attempted=0)]
        )

    row = results.scanner_results["tool-a"]
    assert row.status == ScannerStatus.SKIPPED, row
    _assert_logged(records, "tool-a", row.skipped_reason)


#: A value only the plain plugin's own ``_environment_values()`` names.
_PLAIN_OWN_VALUE = "/nonexistent/ENVCANARY-plainown/rules.yaml"


class _PlainConfig:
    """A plain config object, not a pydantic model carrying values: its text
    quotes the plugin's own value."""

    name = "plain-tool"

    def __str__(self):
        return f"PlainConfig(name=plain-tool, rules={_PLAIN_OWN_VALUE})"


class _PlainPlugin:
    """A plugin that is not a PluginBase, with a plain config and a value of its
    own."""

    def __init__(self):
        self.config = _PlainConfig()

    def _environment_values(self):
        return (_PLAIN_OWN_VALUE,)


def test_the_config_line_of_a_plain_plugin_is_redacted_with_its_own_values(
    context,
):
    """The executor's DEBUG line names the scanner's settings, never their
    values. For a plugin that is not a PluginBase, with a plain config that is
    no mapping, the line names only the config's type, so the plugin's own value
    never reaches it: the run's config holds none of them to redact."""
    phase = ScanPhase(
        plugin_context=context,
        plugins=[],
        progress_display=MagicMock(),
        asharp_model=AshAggregatedResults(),
    )
    with _ash_log(logging.DEBUG) as records:
        phase._safe_execute_scanner("plain-tool", _PlainPlugin(), [])
    texts = [text for _, text in records]

    # The control: the executor logged the plugin's config line.
    assert any(
        text.startswith("scanner_plugin.config setting: a _PlainConfig")
        for text in texts
    ), texts
    for text in texts:
        assert "ENVCANARY-plainown" not in text, text


def _own_067(cls):
    """*cls* whose own values add "067", an environment's spelling of the
    limit 67."""

    class _Own(cls):
        def _environment_values(self):
            return (*super()._environment_values(), "067")

    _Own.__name__ = cls.__name__
    return _Own


@pytest.mark.parametrize("site", ["kept-flag", "attribute-alone"])
def test_a_limit_the_plugin_s_own_value_spells_prints_no_number(context, site):
    """A scan that returned with its tool killed at 67 s, where the plugin's
    own value "067" is the environment's spelling of that limit: the limit's
    token names the option, never '67' s. The plugin's values choose the
    token's wording (timeout_limit_token) on the kept flag's reason and on the
    error for a plugin recording the attribute alone, so each site takes
    them."""
    cls = _scanner_class("tool-a")

    class _Killed(cls):
        def scan(self, target, target_type, global_ignore_paths=None, config=None):
            report = super().scan(target, target_type, global_ignore_paths, config)
            self._scan_timed_out_after = 67.0
            if site == "kept-flag":
                self._scan_kept_flag = ("timed_out", "its results file was missing")
            return report

    _Killed.__name__ = cls.__name__
    with _ash_log(logging.DEBUG) as records:
        results = _scan(context, [_own_067(_Killed)])
    texts = [text for _, text in records] + [results.model_dump_json()]

    # The control: the timeout reached the results with the option's name for
    # its limit.
    assert any(
        "timed out after the configured scan_timeout on source" in text
        for text in texts
    ), texts
    for text in texts:
        assert "'67' s" not in text, text
