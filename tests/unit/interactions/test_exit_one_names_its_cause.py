"""Every way a finished scan exits 1 is named; only a missing result is a crash.

``_compute_exit_code`` exits 1 for five reasons a scan can have after it finished:
incomplete scanners, no scanner having run at all, incomplete conversion, a rule that
could not be evaluated, and a stale content database. ``print_incompleteness_message``
had arms for three of them. The other two -- every scanner SKIPPED, and an unevaluated
rule -- fell through to "ERROR (1) Exiting due to exception during ASH scan", although
nothing had raised. Reproduced on the base with
``ash scan --exclude-scanners <every scanner>``: the scan completed, wrote its reports,
and ended with that line.

The crash wording stays for the one case it describes: exit 1 with no results.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest
from rich.console import Console

import rich

from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.interactions.run_ash_scan import (
    ScanIncompleteExit,
    print_incompleteness_message,
    run_ash_scan,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def console(monkeypatch):
    console = Console(record=True, width=120, color_system=None)
    monkeypatch.setattr(rich, "_console", console)
    return console


def _text(console) -> str:
    return console.export_text()


def test_no_scanner_ran_has_its_own_message(console):
    print_incompleteness_message(
        [], [], no_scanner_ran=True, observed=[("bandit", "SKIPPED")]
    )
    out = _text(console)

    assert "no scanner ran" in out.lower(), out
    assert "bandit" in out
    assert "exception" not in out.lower(), out


def test_an_unevaluated_rule_has_its_own_message(console):
    print_incompleteness_message([], [], unevaluated_rules=["AwsSolutions-IAM5"])
    out = _text(console)

    assert "AwsSolutions-IAM5" in out, out
    assert "could not be evaluated" in out
    assert "exception" not in out.lower(), out


def test_nothing_recorded_is_the_crash_wording(console):
    print_incompleteness_message([], [])

    assert "exception" in _text(console).lower()


#: A recorded could-not-stop reason, as scanners_that_could_not_stop returns it.
_COULD_NOT_STOP_ROW = (
    "watched",
    "ASH could not stop the tool (pid 4242), which may still be running",
)


def test_a_tool_ash_could_not_stop_has_its_own_message(console):
    """A run that exits 1 only because a tool could not be stopped names that,
    not an exception that never happened. This arm is not behind the
    completeness gate, so it is reached with every gated list empty."""
    print_incompleteness_message([], [], could_not_stop=[_COULD_NOT_STOP_ROW])
    out = _text(console)

    assert "watched" in out, out
    assert "could not be stopped" in out, out
    assert "pid 4242" in out, out
    assert "exception" not in out.lower(), out


def test_the_could_not_stop_line_shows_beside_the_scanner_arm(console):
    """With the gate on, the incomplete-scanner arm's advice (install the tool,
    or decline the gate) does not cover this cause: the run fails whatever the
    gate says, so its line is printed alongside, not hidden behind the arm."""
    print_incompleteness_message(
        [("watched", "ERROR (124)")],
        [],
        could_not_stop=[_COULD_NOT_STOP_ROW],
    )
    out = _text(console)

    assert "did not evaluate everything" in out, out
    assert "could not be stopped" in out, out
    assert "pid 4242" in out, out


#: A MISSING scanner with its recorded reason, which takes the scanner arm's
#: other sentence ("for the reason under it").
_MISSING_ROW = ("watched", "MISSING")
_MISSING_REASONS = {"watched": "the watched tool is not installed"}


@pytest.mark.parametrize(
    "rows,reasons",
    [
        pytest.param([("watched", "ERROR (124)")], None, id="scanner-arm"),
        pytest.param(
            [_MISSING_ROW], _MISSING_REASONS, id="scanner-arm-missing-with-reasons"
        ),
        pytest.param(
            [ras.IncompleteConverter("jupyter", "it failed", ("input",))],
            None,
            id="converter-input-arm",
        ),
        pytest.param(
            [ras.IncompleteConverter("jupyter", "it failed", ("tool",))],
            None,
            id="converter-tool-arm",
        ),
        pytest.param(
            [ras.IncompleteConverter("jupyter", "it never ran")],
            None,
            id="converter-did-not-run-arm",
        ),
    ],
)
def test_the_gate_advice_is_withheld_while_a_tool_could_not_be_stopped(
    console, rows, reasons
):
    """The gated arms advise --no-fail-on-incomplete-scanners only when the
    gate can clear the exit: with a tool ASH could not stop, the run fails
    whatever the gate says, so naming the flag sends the operator to a setting
    that changes nothing here. The rest of each arm's advice stays, in both of
    the scanner arm's sentences."""
    converters = rows if isinstance(rows[0], ras.IncompleteConverter) else []
    scanners = rows if not converters else []
    print_incompleteness_message(
        scanners,
        converters,
        missing_reasons=reasons,
        could_not_stop=[_COULD_NOT_STOP_ROW],
    )
    out = _text(console)

    # The control: both arms printed, with the rest of their advice, and the
    # scanner arm in the sentence its rows take.
    assert "could not be stopped" in out, out
    if scanners:
        assert "did not evaluate everything" in out, out
        assert "--exclude-scanners" in out, out
        if reasons:
            assert "for the reason under it" in out, out
    else:
        assert "conversion was incomplete" in out, out
    assert "--no-fail-on-incomplete-scanners" not in out, out


@pytest.mark.parametrize(
    "rows,reasons,sentence",
    [
        pytest.param(
            [("watched", "ERROR (124)")],
            None,
            "dependencies were unavailable",
            id="scanner-arm",
        ),
        pytest.param(
            [_MISSING_ROW],
            _MISSING_REASONS,
            "for the reason under it",
            id="scanner-arm-missing-with-reasons",
        ),
    ],
)
def test_the_gate_advice_stays_when_every_tool_stopped(
    console, rows, reasons, sentence
):
    """The other side: with nothing left running, declining the gate does
    accept the partial scan, and each of the scanner arm's sentences says so."""
    print_incompleteness_message(rows, [], missing_reasons=reasons)
    out = _text(console)

    # The control: the sentence these rows take.
    assert sentence in out, out
    assert "--no-fail-on-incomplete-scanners" in out, out


#: A stale content database, as scan_incompleteness records it.
_STALE_DATABASE = SimpleNamespace(
    name="grype-db", message=lambda: "grype-db is 40 days old"
)

#: The exit-1 causes other than a tool ASH could not stop that are not behind
#: the completeness gate, each with what the operator opts out with instead.
_UNGATED = {
    "unevaluated-rule": {"unevaluated_rules": ["AwsSolutions-IAM5"]},
    "stale-database": {"stale_database_records": [_STALE_DATABASE]},
}


@pytest.mark.parametrize("cause", sorted(_UNGATED))
@pytest.mark.parametrize(
    "rows,reasons",
    [
        pytest.param([_MISSING_ROW], _MISSING_REASONS, id="missing-scanner"),
        pytest.param([("watched", "ERROR (124)")], None, id="error-scanner"),
        pytest.param(
            [ras.IncompleteConverter("jupyter", "it failed", ("tool",))],
            None,
            id="converter-tool",
        ),
    ],
)
def test_the_gate_advice_is_withheld_while_an_ungated_cause_fails_the_run(
    console, rows, reasons, cause
):
    """A rule that could not be evaluated and a stale content database fail
    the run whatever --fail-on-incomplete-scanners says (_compute_exit_code),
    as a tool ASH could not stop does. A MISSING scanner beside a stale
    grype-db was told to pass --no-fail-on-incomplete-scanners to accept a
    partial scan, which still exits 1. So the gated arms name the flag only
    when declining the gate clears the exit."""
    converters = rows if isinstance(rows[0], ras.IncompleteConverter) else []
    scanners = rows if not converters else []
    print_incompleteness_message(
        scanners, converters, missing_reasons=reasons, **_UNGATED[cause]
    )
    out = _text(console)

    # The control: the gated arm and the cause's own arm both printed, with
    # the rest of the gated arm's advice, still one list ending "or" its last
    # way out.
    if scanners:
        assert "did not evaluate everything" in out, out
        assert "targets, or exclude the scanners with --exclude-scanners." in " ".join(
            out.split()
        ), out
    else:
        assert "conversion was incomplete" in out, out
    assert (
        "could not be evaluated" in out
        if cause == "unevaluated-rule"
        else "past their declared age bound" in out
    ), out
    assert "--no-fail-on-incomplete-scanners" not in out, out


def _all_skipped_model() -> AshAggregatedResults:
    model = AshAggregatedResults()
    for name in ("bandit", "grype"):
        model.scanner_results[name] = ScannerTargetStatusInfo(
            status=ScannerStatus.SKIPPED,
            excluded=True,
            skipped_reason="excluded from this run (--exclude-scanners)",
        )
    model.metadata.expected_scanners = ["bandit", "grype"]
    return model


def test_a_run_where_every_scanner_was_skipped_does_not_claim_an_exception(
    monkeypatch, console, tmp_path
):
    model = _all_skipped_model()
    monkeypatch.setattr(
        ras, "_setup_logger", lambda opts: logging.getLogger("exit-one-cause")
    )
    monkeypatch.setattr(ras, "_run_local_mode", lambda opts, logger: (model, None))
    monkeypatch.setattr(ras, "time", SimpleNamespace(time=lambda: 1_000.0))
    source = tmp_path / "repo"
    (source / ".ash" / "ash_output").mkdir(parents=True)

    with pytest.raises(ScanIncompleteExit) as excinfo:
        run_ash_scan(
            source_dir=source,
            output_dir=source / ".ash" / "ash_output",
            progress=False,
        )

    out = _text(console)
    assert excinfo.value.incompleteness.no_scanner_ran
    assert "exception" not in out.lower(), out
    assert "no scanner ran" in out.lower(), out


def _could_not_stop_model() -> AshAggregatedResults:
    """One scanner that passed, whose recorded run ended with a tool ASH could
    not stop, the shape scanners_that_could_not_stop reads."""
    model = AshAggregatedResults()
    model.scanner_results["watched"] = ScannerTargetStatusInfo(
        status=ScannerStatus.PASSED,
        dependencies_satisfied=True,
        excluded=False,
    )
    model.metadata.expected_scanners = ["watched"]
    model.additional_reports["watched"] = {
        "source": {"could_not_stop": _COULD_NOT_STOP_ROW[1]}
    }
    return model


@pytest.mark.parametrize("gate", [False, True], ids=["gate declined", "gate on"])
def test_a_whole_run_prints_the_could_not_stop_line(
    monkeypatch, console, tmp_path, gate
):
    """Through run_ash_scan itself, so the wiring from the recorded state to the
    console arm is pinned: the arm alone passes with the call site dropping the
    field, and this run does not."""
    model = _could_not_stop_model()
    monkeypatch.setattr(
        ras, "_setup_logger", lambda opts: logging.getLogger("exit-one-cause")
    )
    monkeypatch.setattr(ras, "_run_local_mode", lambda opts, logger: (model, None))
    monkeypatch.setattr(ras, "time", SimpleNamespace(time=lambda: 1_000.0))
    source = tmp_path / "repo"
    (source / ".ash" / "ash_output").mkdir(parents=True)

    with pytest.raises(ScanIncompleteExit) as excinfo:
        run_ash_scan(
            source_dir=source,
            output_dir=source / ".ash" / "ash_output",
            progress=False,
            fail_on_incomplete_scanners=gate,
        )

    out = _text(console)
    assert excinfo.value.incompleteness.could_not_stop, excinfo.value.incompleteness
    assert "could not be stopped" in out, out
    assert "pid 4242" in out, out
    assert "exception" not in out.lower(), out
