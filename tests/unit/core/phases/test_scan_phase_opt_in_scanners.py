# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Opt-in scanners stay out of a run until the operator enables them.

Why this exists
---------------
The scan phase records a config-disabled scanner as SKIPPED, and every reporter,
summary counter and metrics table then shows that row. Measured on main before
this change: loading one extra scanner module whose scanner defaults to
``enabled: false`` changed a default scan of a one-file fixture from 10 rows
(``skipped=2``) to 11 (``skipped=3``), and the new row appeared in
``ash.summary.txt``, ``ash.summary.md``, ``ash.html`` and ``ash.flat.json``. So a
new builtin that is merely disabled by default changes every existing user's
output. ``ScannerPluginBase.OPT_IN`` is the marker that keeps such a scanner out
of the run entirely; ``core/scanner_opt_in.py`` holds the rule.

What these tests drive
----------------------
The real ``ScanPhase`` with the real ``ScannerExecutor``, then the real metrics
consolidation and the real shipped reporters over its results, so "omitted" is
asserted on what an operator reads, not on an internal list. The scanners are
plain subclasses handed to the phase as its plugin set and never registered in
the global plugin registry, so nothing here leaks into other tests.

Negative control
----------------
``test_negative_control_without_opt_in_the_scanner_is_recorded`` flips the
marker off on the same scanner and asserts the omission checks then FAIL, which
is what shows the omission assertions can see the row when it is there.
"""

from pathlib import Path
from typing import ClassVar, List, Literal
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.phases.report_phase import ReportPhase
from automated_security_helper.core.phases.scan_phase import (
    _BUILTIN_PLUGIN_MODULE_PREFIX,
    ScanPhase,
)
from automated_security_helper.core.progress import LiveProgressDisplay
from automated_security_helper.core.scanner_opt_in import (
    is_opt_in,
    opt_in_scanner_enabled,
    opt_in_scanner_name,
)
from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.core.unified_metrics import (
    get_unified_scanner_metrics,
    populate_metrics_from_unified_source,
)
from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    _compute_exit_code,
    incomplete_scanner_reason,
    incomplete_scanners,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.plugins.loader import load_plugins
from automated_security_helper.schemas.sarif_schema_model import SarifReport

OPT_IN_NAME = "dummy-optin"
CONTROL_NAME = "dummy-control"


def _sarif(tool: str, rule_id: str | None) -> SarifReport:
    results = []
    if rule_id is not None:
        results.append(
            {
                "ruleId": rule_id,
                "level": "warning",
                "message": {"text": f"{tool} test finding"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "app.py"},
                            "region": {"startLine": 1},
                        }
                    }
                ],
            }
        )
    return SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": tool}}, "results": results}],
        }
    )


class _OptInConfig(ScannerPluginConfigBase):
    name: Literal["dummy-optin"] = OPT_IN_NAME
    enabled: bool = False


class _ControlConfig(ScannerPluginConfigBase):
    name: Literal["dummy-control"] = CONTROL_NAME
    enabled: bool = True


class DummyOptInScanner(ScannerPluginBase[_OptInConfig]):
    """An opt-in scanner whose tool can be made to look absent."""

    OPT_IN: ClassVar[bool] = True
    tool_present: ClassVar[bool] = True
    scan_calls: ClassVar[List[str]] = []

    def model_post_init(self, context):
        if self.config is None:
            self.config = _OptInConfig()
        self.command = "dummy-optin-tool"
        super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        return type(self).tool_present

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError

    def scan(self, target, target_type, global_ignore_paths=None, config=None):
        type(self).scan_calls.append(target_type)
        return _sarif(OPT_IN_NAME, "DUMMY-OPTIN-001")


class DummyControlScanner(ScannerPluginBase[_ControlConfig]):
    """An ordinary scanner, so every run has something that ran."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = _ControlConfig()
        self.command = "dummy-control-tool"
        super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError

    def scan(self, target, target_type, global_ignore_paths=None, config=None):
        return _sarif(CONTROL_NAME, None)


class NotOptInTwin(DummyOptInScanner):
    """The opt-in scanner with the marker off: the negative control."""

    OPT_IN = False


@pytest.fixture(autouse=True)
def _reset_dummy_state():
    DummyOptInScanner.tool_present = True
    DummyOptInScanner.scan_calls = []
    yield
    DummyOptInScanner.tool_present = True
    DummyOptInScanner.scan_calls = []


def _context(tmp_path: Path, overrides=None) -> PluginContext:
    for sub in ("src", "out", "work"):
        (tmp_path / sub).mkdir(parents=True, exist_ok=True)
    (tmp_path / "src" / "app.py").write_text("print('hello')\n")
    config = get_default_config()
    for key, value in (overrides or {}).items():
        setattr(config.scanners, key, value)
    return PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=config,
    )


def _scan(context, plugins, enabled_scanners=None) -> AshAggregatedResults:
    aggregated = AshAggregatedResults()
    phase = ScanPhase(
        plugin_context=context,
        plugins=list(plugins),
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )
    results = phase._execute_phase(
        aggregated_results=aggregated,
        enabled_scanners=list(enabled_scanners or []),
        parallel=False,
    )
    return populate_metrics_from_unified_source(aggregated_results=results)


def _report_texts(context, results) -> dict:
    """Run every shipped reporter that is on by default; return {filename: text}."""
    load_plugins(plugin_context=context)
    reports_dir = context.output_dir / "reports"
    ReportPhase(
        plugins=ash_plugin_manager.plugin_modules(plugin_type="reporter"),
        plugin_context=context,
        progress_display=LiveProgressDisplay(show_progress=False),
        asharp_model=results,
    ).execute(
        report_dir=reports_dir,
        cli_output_formats=None,
        aggregated_results=results,
        python_based_plugins_only=False,
    )
    texts = {
        path.name: path.read_text(encoding="utf-8", errors="replace")
        for path in reports_dir.iterdir()
        if path.is_file()
    }
    assert texts, "the report phase wrote nothing, so no omission was checked"
    return texts


def _every_trace_of(name: str, context, results) -> List[str]:
    """Each place an operator could see *name*, for a run's results."""
    traces = []
    if name in results.scanner_results:
        traces.append("scanner_results")
    if name in (results.additional_reports or {}):
        traces.append("additional_reports")
    if name in ScannerStatisticsCalculator.extract_scanner_statistics(results):
        traces.append("scanner statistics")
    if any(m.scanner_name == name for m in get_unified_scanner_metrics(results)):
        traces.append("unified metrics")
    if name in (results.metadata.expected_scanners or []):
        traces.append("expected_scanners")
    if name in results.model_dump_json():
        traces.append("ash_aggregated_results.json")
    for filename, text in _report_texts(context, results).items():
        if name in text:
            traces.append(f"reports/{filename}")
    return traces


def _counters(results) -> dict:
    stats = results.metadata.summary_stats
    return {
        k: getattr(stats, k)
        for k in ("passed", "failed", "missing", "skipped", "error")
    }


# --------------------------------------------------------------------------- #
# Not enabled: omitted
# --------------------------------------------------------------------------- #


def test_an_opt_in_scanner_nobody_enabled_leaves_no_trace(tmp_path):
    context = _context(tmp_path)
    results = _scan(context, [DummyControlScanner, DummyOptInScanner])

    assert _every_trace_of(OPT_IN_NAME, context, results) == []
    assert DummyOptInScanner.scan_calls == []
    # The control ran and is reported, so the report check above was looking at
    # real reports rather than at an empty directory.
    assert results.scanner_results[CONTROL_NAME].status.value == "PASSED"
    assert CONTROL_NAME in _report_texts(context, results)["ash.summary.txt"]


def test_counters_match_a_run_without_the_scanner(tmp_path):
    with_opt_in = _scan(
        _context(tmp_path / "a"), [DummyControlScanner, DummyOptInScanner]
    )
    without = _scan(_context(tmp_path / "b"), [DummyControlScanner])

    assert _counters(with_opt_in) == _counters(without)
    assert sorted(with_opt_in.scanner_results) == sorted(without.scanner_results)
    assert incomplete_scanners(with_opt_in) == incomplete_scanners(without) == []


def test_negative_control_without_opt_in_the_scanner_is_recorded(tmp_path):
    """The same scanner with OPT_IN off is SKIPPED, and every check above sees it.

    If this ever stops producing traces, the omission tests above can no longer
    fail and prove nothing.
    """
    context = _context(tmp_path)
    results = _scan(context, [DummyControlScanner, NotOptInTwin])

    assert results.scanner_results[OPT_IN_NAME].status.value == "SKIPPED"
    traces = _every_trace_of(OPT_IN_NAME, context, results)
    for expected in (
        "scanner_results",
        "scanner statistics",
        "unified metrics",
        "ash_aggregated_results.json",
        "reports/ash.summary.txt",
        "reports/ash.summary.md",
        "reports/ash.html",
    ):
        assert expected in traces, (expected, traces)
    assert _counters(results)["skipped"] == 1


def test_omitted_before_the_shard_partition(tmp_path):
    """A shard split must not change because an unused opt-in scanner exists."""
    plugins_without = [DummyControlScanner]
    plugins_with = [DummyControlScanner, DummyOptInScanner]

    def shard(plugins, sub):
        context = _context(tmp_path / sub)
        aggregated = AshAggregatedResults()
        phase = ScanPhase(
            plugin_context=context,
            plugins=plugins,
            progress_display=MagicMock(),
            asharp_model=aggregated,
        )
        phase._execute_phase(
            aggregated_results=aggregated,
            parallel=False,
            shard_index=0,
            shard_count=2,
        )
        return phase._shard_assignment

    a = shard(plugins_with, "a")
    b = shard(plugins_without, "b")
    assert a.candidate_scanners == b.candidate_scanners == [CONTROL_NAME]
    assert a.assigned_scanners == b.assigned_scanners


def test_omitted_from_the_builtin_roster(tmp_path):
    """A builtin opt-in scanner's config field is on the roster; its absence is not a loss.

    The roster comes from ScannerConfigSegment's declared fields, and a real opt-in
    builtin declares one there. Simulated with an extra config entry and a class
    posing as a builtin, which is what gates the roster on.
    """

    class BuiltinOptIn(DummyOptInScanner):
        pass

    BuiltinOptIn.__module__ = f"{_BUILTIN_PLUGIN_MODULE_PREFIX}.scanners.fake"

    def roster(plugin):
        context = _context(tmp_path / plugin.__name__)
        setattr(
            context.config.scanners,
            OPT_IN_NAME,
            {"name": OPT_IN_NAME, "enabled": False},
        )
        return _scan(context, [DummyControlScanner, plugin]).metadata.expected_scanners

    assert OPT_IN_NAME not in roster(BuiltinOptIn)

    # Control: the same field stays on the roster for a scanner that is not
    # opt-in, so the filter is what removed it above.
    class BuiltinNotOptIn(NotOptInTwin):
        pass

    BuiltinNotOptIn.__module__ = f"{_BUILTIN_PLUGIN_MODULE_PREFIX}.scanners.fake"
    assert OPT_IN_NAME in roster(BuiltinNotOptIn)


# --------------------------------------------------------------------------- #
# Enabled: an ordinary scanner
# --------------------------------------------------------------------------- #


def test_enabled_in_config_it_runs_and_is_reported(tmp_path):
    context = _context(tmp_path)
    setattr(
        context.config.scanners, OPT_IN_NAME, {"name": OPT_IN_NAME, "enabled": True}
    )
    results = _scan(context, [DummyControlScanner, DummyOptInScanner])

    assert DummyOptInScanner.scan_calls == ["source"]
    assert results.scanner_results[OPT_IN_NAME].status.value == "FAILED"
    assert "DUMMY-OPTIN-001" in results.model_dump_json()
    reports = _report_texts(context, results)
    assert OPT_IN_NAME in reports["ash.summary.txt"]
    assert "DUMMY-OPTIN-001" in reports["ash.sarif"]


def test_named_in_the_selection_it_runs_even_though_config_says_disabled(tmp_path):
    """--scanners enables an opt-in scanner; see core/scanner_opt_in.py for why."""
    context = _context(tmp_path)
    results = _scan(
        context,
        [DummyControlScanner, DummyOptInScanner],
        enabled_scanners=[OPT_IN_NAME, CONTROL_NAME],
    )

    assert DummyOptInScanner.scan_calls == ["source"]
    assert results.scanner_results[OPT_IN_NAME].status.value == "FAILED"
    assert results.scanner_results[CONTROL_NAME].status.value == "PASSED"


def test_selection_matching_is_case_and_whitespace_insensitive(tmp_path):
    results = _scan(
        _context(tmp_path),
        [DummyControlScanner, DummyOptInScanner],
        enabled_scanners=[f"  {OPT_IN_NAME.upper()} "],
    )
    assert results.scanner_results[OPT_IN_NAME].status.value == "FAILED"


def test_a_selection_naming_only_others_leaves_it_out(tmp_path):
    """--scanners other: the opt-in scanner is neither run nor recorded SKIPPED."""
    results = _scan(
        _context(tmp_path),
        [DummyControlScanner, DummyOptInScanner],
        enabled_scanners=[CONTROL_NAME],
    )
    assert OPT_IN_NAME not in results.scanner_results
    assert DummyOptInScanner.scan_calls == []


def test_enabled_by_config_but_narrowed_away_it_is_skipped_like_any_scanner(tmp_path):
    """Once enabled, --scanners narrows it the way it narrows every scanner."""
    context = _context(tmp_path)
    setattr(
        context.config.scanners, OPT_IN_NAME, {"name": OPT_IN_NAME, "enabled": True}
    )
    results = _scan(
        context,
        [DummyControlScanner, DummyOptInScanner],
        enabled_scanners=[CONTROL_NAME],
    )
    assert results.scanner_results[OPT_IN_NAME].status.value == "SKIPPED"


@pytest.mark.parametrize("how", ["config", "selection"])
def test_enabled_but_tool_missing_is_missing_and_exits_1(tmp_path, how):
    DummyOptInScanner.tool_present = False
    context = _context(tmp_path)
    selection = None
    if how == "config":
        setattr(
            context.config.scanners,
            OPT_IN_NAME,
            {"name": OPT_IN_NAME, "enabled": True},
        )
    else:
        selection = [OPT_IN_NAME, CONTROL_NAME]
    results = _scan(context, [DummyControlScanner, DummyOptInScanner], selection)

    row = results.scanner_results[OPT_IN_NAME]
    assert row.status.value == "MISSING"
    assert DummyOptInScanner.scan_calls == []
    listed = incomplete_scanners(results)
    assert [name for name, _ in listed] == [OPT_IN_NAME]
    assert incomplete_scanner_reason(listed[0][1]) == "missing_dependencies"
    opts = ScanOptions(source_dir=context.source_dir, output_dir=context.output_dir)
    assert _compute_exit_code(results, opts, config_fail_on_findings=False) == 1


def test_not_enabled_and_tool_missing_is_still_omitted(tmp_path):
    """A missing tool for a scanner nobody asked for must not fail the scan."""
    DummyOptInScanner.tool_present = False
    context = _context(tmp_path)
    results = _scan(context, [DummyControlScanner, DummyOptInScanner])

    assert OPT_IN_NAME not in results.scanner_results
    assert incomplete_scanners(results) == []
    opts = ScanOptions(source_dir=context.source_dir, output_dir=context.output_dir)
    assert _compute_exit_code(results, opts, config_fail_on_findings=False) == 0


# --------------------------------------------------------------------------- #
# The rule itself
# --------------------------------------------------------------------------- #


def test_the_base_class_default_is_not_opt_in():
    assert ScannerPluginBase.OPT_IN is False
    assert is_opt_in(DummyControlScanner) is False
    assert "OPT_IN" not in ScannerPluginBase.model_fields


def test_a_bare_assignment_is_enough_once_the_base_declares_the_classvar():
    class Bare(DummyControlScanner):
        OPT_IN = True

    assert is_opt_in(Bare)
    assert "OPT_IN" not in Bare.model_fields


def test_a_mock_is_not_mistaken_for_an_opt_in_scanner():
    assert is_opt_in(MagicMock()) is False


@pytest.mark.parametrize(
    "plugin_config, selection, expected",
    [
        (None, None, False),
        ({"name": OPT_IN_NAME, "enabled": False}, None, False),
        ({"name": OPT_IN_NAME}, None, False),
        ({"name": OPT_IN_NAME, "enabled": True}, None, True),
        (_OptInConfig(enabled=True), None, True),
        (None, [OPT_IN_NAME], True),
        ({"name": OPT_IN_NAME, "enabled": False}, [OPT_IN_NAME], True),
        ({"name": OPT_IN_NAME, "enabled": False}, ["other"], False),
    ],
)
def test_opt_in_scanner_enabled(plugin_config, selection, expected):
    assert (
        opt_in_scanner_enabled(DummyOptInScanner, plugin_config, selection) is expected
    )


def test_a_scanner_that_is_not_opt_in_is_always_enabled_by_this_rule():
    assert opt_in_scanner_enabled(DummyControlScanner, {"enabled": False}, None)


def test_the_name_comes_from_config_then_the_declared_default():
    assert opt_in_scanner_name(DummyOptInScanner, None) == OPT_IN_NAME
    assert opt_in_scanner_name(DummyOptInScanner, {"name": "renamed"}) == "renamed"


def test_every_shipped_opt_in_scanner_defaults_to_disabled():
    """An opt-in scanner whose config defaults to enabled would run by default.

    That is the exact change to default output the marker exists to prevent, and
    nothing at runtime can tell a class default from an operator's choice, so it is
    pinned here for every scanner ASH ships.
    """
    from automated_security_helper.core.scanner_inventory import (
        _loaded_scanner_classes,
    )

    for cls in _loaded_scanner_classes():
        if not is_opt_in(cls):
            continue
        assert opt_in_scanner_enabled(cls, None, None) is False, cls.__name__


def test_the_shipped_default_check_catches_a_scanner_that_defaults_on():
    """The loop above has nothing to check until an opt-in scanner ships.

    This is what it would catch: the same call answers True for an opt-in class
    whose config defaults to enabled.
    """

    class _OnConfig(ScannerPluginConfigBase):
        name: Literal["dummy-on"] = "dummy-on"
        enabled: bool = True

    class DefaultsOn(DummyOptInScanner):
        config: _OnConfig | None = None

    assert opt_in_scanner_enabled(DefaultsOn, None, None) is True


# --------------------------------------------------------------------------- #
# Construction, exclusion, and the install label
# --------------------------------------------------------------------------- #


class RaisingOptInScanner(DummyOptInScanner):
    """An opt-in scanner whose constructor always raises."""

    def model_post_init(self, context):
        raise RuntimeError("constructor exploded")


class RecordingOptInScanner(DummyOptInScanner):
    """Records what config.enabled its constructor saw."""

    seen_enabled: ClassVar[List[bool]] = []

    def model_post_init(self, context):
        super().model_post_init(context)
        type(self).seen_enabled.append(self.config.enabled)


def test_an_unenabled_opt_in_scanner_is_never_constructed(tmp_path):
    """Dropped BEFORE construction: a raising constructor leaves no ERROR row.

    If the drop moved below construction, every default scan would carry an ERROR
    row for an opt-in scanner nobody asked for, and exit 1.
    """
    context = _context(tmp_path)
    results = _scan(context, [DummyControlScanner, RaisingOptInScanner])

    assert OPT_IN_NAME not in results.scanner_results
    assert not any("optin" in name for name in results.scanner_results)
    opts = ScanOptions(source_dir=context.source_dir, output_dir=context.output_dir)
    assert _compute_exit_code(results, opts, config_fail_on_findings=False) == 0


def test_an_enabled_opt_in_scanner_that_cannot_be_built_is_an_error_under_its_name(
    tmp_path,
):
    """Enabled, it is an ordinary scanner, including when its constructor raises.

    The row is keyed by the configured name, the name the roster, the shard
    partition and --exclude-scanners use, not by the class name.
    """
    context = _context(tmp_path)
    setattr(
        context.config.scanners, OPT_IN_NAME, {"name": OPT_IN_NAME, "enabled": True}
    )
    results = _scan(context, [DummyControlScanner, RaisingOptInScanner])

    assert results.scanner_results[OPT_IN_NAME].status.value == "ERROR"
    assert "raisingoptinscanner" not in results.scanner_results
    opts = ScanOptions(source_dir=context.source_dir, output_dir=context.output_dir)
    assert _compute_exit_code(results, opts, config_fail_on_findings=False) == 1


def test_the_constructor_already_sees_enabled_when_the_selection_names_it(tmp_path):
    """A scanner that reads config.enabled while it is built must see True.

    With a config entry, which is the dict a real builtin's typed config field
    always resolves to, and which here says disabled.
    """
    RecordingOptInScanner.seen_enabled = []
    context = _context(tmp_path)
    setattr(
        context.config.scanners, OPT_IN_NAME, {"name": OPT_IN_NAME, "enabled": False}
    )
    _scan(
        context,
        [DummyControlScanner, RecordingOptInScanner],
        enabled_scanners=[OPT_IN_NAME, CONTROL_NAME],
    )
    assert RecordingOptInScanner.seen_enabled == [True]


def test_exclusion_of_an_enabled_opt_in_scanner_is_an_ordinary_skip(tmp_path):
    context = _context(tmp_path)
    setattr(
        context.config.scanners, OPT_IN_NAME, {"name": OPT_IN_NAME, "enabled": True}
    )
    aggregated = AshAggregatedResults()
    phase = ScanPhase(
        plugin_context=context,
        plugins=[DummyControlScanner, DummyOptInScanner],
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )
    results = phase._execute_phase(
        aggregated_results=aggregated,
        excluded_scanners=[OPT_IN_NAME],
        parallel=False,
    )
    row = results.scanner_results[OPT_IN_NAME]
    assert row.status.value == "SKIPPED"
    assert row.excluded is True
    assert DummyOptInScanner.scan_calls == []


def test_excluding_an_opt_in_scanner_nobody_enabled_still_leaves_no_row(tmp_path):
    context = _context(tmp_path)
    aggregated = AshAggregatedResults()
    phase = ScanPhase(
        plugin_context=context,
        plugins=[DummyControlScanner, DummyOptInScanner],
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )
    results = phase._execute_phase(
        aggregated_results=aggregated,
        excluded_scanners=[OPT_IN_NAME],
        parallel=False,
    )
    assert OPT_IN_NAME not in results.scanner_results


def test_a_typo_in_the_selection_lists_the_opt_in_scanners(tmp_path, caplog):
    """'Registered scanners: ...' must not read as if an opt-in scanner did not exist."""
    from automated_security_helper.core.exceptions import ScannerSelectionError

    with pytest.raises(ScannerSelectionError) as exc:
        _scan(
            _context(tmp_path),
            [DummyControlScanner, DummyOptInScanner],
            enabled_scanners=["dummy-optn"],
        )
    assert f"opt-in, not enabled: {OPT_IN_NAME}" in str(exc.value)


def test_a_class_without_a_config_class_is_not_enabled():
    """No config class to read a default from means off, for an opt-in scanner."""

    class Bare:
        OPT_IN = True

    assert opt_in_scanner_enabled(Bare, None, None) is False
    assert opt_in_scanner_enabled(Bare, {}, None) is False
    assert opt_in_scanner_enabled(Bare, None, ["bare"]) is True


@pytest.mark.parametrize("opt_in", [True, False])
def test_dependencies_install_labels_opt_in_scanners(tmp_path, monkeypatch, opt_in):
    """ash dependencies install still provisions an opt-in scanner, and says so."""
    from types import SimpleNamespace

    from typer.testing import CliRunner

    from automated_security_helper.cli.dependencies import dependencies_app

    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    fake = MagicMock()
    fake.config = SimpleNamespace(name="fake-scanner")
    fake.command = "fake-scanner"
    fake.get_installation_commands.return_value = [["echo", "install"]]
    if opt_in:
        fake.OPT_IN = True
    monkeypatch.setattr(
        "automated_security_helper.cli.dependencies.load_plugins",
        lambda *_a, **_k: {},
    )
    monkeypatch.setattr(
        "automated_security_helper.cli.dependencies.ash_plugin_manager",
        SimpleNamespace(
            plugin_modules=lambda kind: (
                [lambda **_kw: fake] if kind == "scanner" else []
            )
        ),
    )
    ran = []
    monkeypatch.setattr(
        "automated_security_helper.cli.dependencies.run_command",
        lambda cmd, shell=False: ran.append(cmd) or 0,
    )
    result = CliRunner().invoke(
        dependencies_app,
        ["--plugin-type", "scanner", "--bin-path", str(tmp_path / "bin")],
    )
    assert ran == [["echo", "install"]]
    assert ("opt-in: runs only when" in result.output) is opt_in, result.output
