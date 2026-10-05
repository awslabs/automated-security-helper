# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What ``ash scan`` prints after the table: next steps, the exit-code legend, the ERROR line.

Two layers. The printing helpers in run_ash_scan -- ``_print_summary``,
``_print_workspace_summary`` and ``print_incompleteness_message`` -- are rendered directly, one
snapshot per arm, so each arm's wording is pinned even where no realistic scan reaches it on its
own. Then ``run_ash_scan`` itself is run end to end with only the scan stubbed out
(``_run_local_mode`` returns a prepared model), which is the one place the exit-code legend and
the final ``ERROR (n)`` line are printed, and the only way to pin that the right arm is chosen
for each exit code.

Every helper here prints through the module-level ``rich.print``; ``route_rich_print`` points
it at a console with a pinned width. The scan clock is pinned too, because the "Completed in"
banner reads ``time.time()`` twice and the duration it prints would otherwise be whatever the
runner took.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest

from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.interactions.run_ash_scan import (
    ScanIncompleteExit,
    ScanOptions,
    _print_summary,
    _print_workspace_summary,
    print_incompleteness_message,
    run_ash_scan,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    SkippedProjectReason,
    WorkspaceExitCode,
    WorkspaceProjectResult,
    WorkspaceResults,
)
from automated_security_helper.workspace.execution import WorkspaceRunResult
from tests.snapshot.console.console_inputs import (
    WIDE,
    finding,
    incomplete_converter_rows_model,
    recording_console,
    rendered,
    route_rich_print,
    scan_results_model,
    stale_records,
)

# The summary is rendered from fixed inputs: the scan took 42.5s because the fixture
# says so.
pytestmark = pytest.mark.snapshot_masking(
    mask_durations=False, mask_duration_keys=False
)

SCAN_STARTED = 1_000.0
SCAN_FINISHED = 1_042.5


@pytest.fixture
def console(monkeypatch):
    console = recording_console(WIDE)
    route_rich_print(monkeypatch, console)
    return console


@pytest.fixture
def pinned_clock(monkeypatch):
    """For a whole ``run_ash_scan``: the first read starts the scan, every later one ends it."""
    reads = iter([SCAN_STARTED])
    monkeypatch.setattr(
        ras, "time", SimpleNamespace(time=lambda: next(reads, SCAN_FINISHED))
    )


@pytest.fixture
def finished_clock(monkeypatch):
    """For a summary helper called directly with ``SCAN_STARTED``: every read is the end."""
    monkeypatch.setattr(ras, "time", SimpleNamespace(time=lambda: SCAN_FINISHED))


@pytest.fixture
def layout(tmp_path):
    """A scanned tree with ASH's default output directory inside it."""
    source = tmp_path / "repo"
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True)
    return source, output


def _opts(layout, **overrides) -> ScanOptions:
    source, output = layout
    return ScanOptions(source_dir=source, output_dir=output, **overrides)


# --------------------------------------------------------------------------- _print_summary


def test_next_steps_with_actionable_findings(
    console, layout, finished_clock, text_snapshot
):
    model = scan_results_model()
    model.validation_checkpoints = [
        {
            "type": "config_warning",
            "message": "reporters.html.options.unknown_key is not a recognized option",
        }
    ]

    _print_summary(model, _opts(layout), SCAN_STARTED, actionable_findings=4)

    assert rendered(console) == text_snapshot("txt")


def test_next_steps_with_no_actionable_findings(
    console, layout, finished_clock, text_snapshot
):
    _print_summary(AshAggregatedResults(), _opts(layout), SCAN_STARTED, 0)

    assert rendered(console) == text_snapshot("txt")


def test_quiet_prints_only_the_actionable_block(
    console, layout, finished_clock, text_snapshot
):
    """``--quiet`` drops the banner and the file list but keeps the investigate steps."""
    _print_summary(scan_results_model(), _opts(layout, quiet=True), SCAN_STARTED, 4)

    assert rendered(console) == text_snapshot("txt")


# --------------------------------------------------------------------------- workspace summary


def _project(key: str, status: ProjectRunStatus, **fields) -> WorkspaceProjectResult:
    return WorkspaceProjectResult(
        project=key,
        relative_path=key,
        display_label=key,
        status=status,
        output_path="projects/" + key,
        **fields,
    )


def test_workspace_summary(layout, finished_clock, text_snapshot, monkeypatch):
    """One line per project, in workspace order, for every outcome a project can have.

    Rendered unwrapped: the workspace and output lines print absolute paths, because
    ``ScanOptions`` makes ``output_dir`` absolute, so their length depends on the machine.
    """
    console = recording_console(WIDE, soft_wrap=True)
    route_rich_print(monkeypatch, console)
    source, output = layout
    payload = WorkspaceResults(
        workspace_file=(source / "dev.code-workspace").as_posix(),
        workspace_root=source.as_posix(),
        exit_code=int(WorkspaceExitCode.ACTIONABLE_FINDINGS),
        unconvertible_finding_paths=3,
        projects=[
            _project(
                "docs",
                ProjectRunStatus.SKIPPED,
                skip_reason=SkippedProjectReason.NO_CHANGES,
            ),
            _project("legacy", ProjectRunStatus.FAILED, error="git clone missing"),
            _project(
                "api",
                ProjectRunStatus.COMPLETED,
                severity_threshold="MEDIUM",
                finding_count=7,
                actionable_finding_count=2,
                exceeds_threshold=True,
                duration_seconds=12.25,
            ),
            _project(
                "web",
                ProjectRunStatus.COMPLETED,
                severity_threshold="HIGH",
                finding_count=1,
                actionable_finding_count=0,
                exceeds_threshold=False,
                duration_seconds=3.5,
            ),
            _project(
                "tools",
                ProjectRunStatus.COMPLETED,
                finding_count=0,
                actionable_finding_count=0,
                exceeds_threshold=False,
                duration_seconds=0.75,
            ),
        ],
    )
    result = WorkspaceRunResult(
        results_path=output / "ash_aggregated_results.json",
        exit_code=payload.exit_code,
        payload=payload,
    )

    _print_workspace_summary(result, _opts(layout), SCAN_STARTED)

    assert rendered(console) == text_snapshot("txt")


# --------------------------------------------------------------------------- incompleteness


INCOMPLETE_SCANNERS = [
    ("cdk-nag", "PASSED (4 of 10 targets unevaluated)"),
    ("grype", "MISSING"),
    ("npm-audit", "ERROR"),
]
INCOMPLETE_CONVERTERS = [
    ("jupyter", "RuntimeError: nbconvert exited 1"),
    ("archive", "dependencies unavailable, so it never ran"),
]


@pytest.mark.parametrize(
    ("scanners", "converters", "stale"),
    [
        pytest.param(INCOMPLETE_SCANNERS, [], False, id="scanners"),
        # The scanner arm wins when both are non-empty; the converter rows are not printed.
        pytest.param(
            INCOMPLETE_SCANNERS,
            INCOMPLETE_CONVERTERS,
            False,
            id="scanners-and-converters",
        ),
        pytest.param([], INCOMPLETE_CONVERTERS, False, id="converters"),
        pytest.param([], [], True, id="stale-databases"),
        # Stale databases print first and alongside, not instead.
        pytest.param(INCOMPLETE_SCANNERS, [], True, id="stale-databases-and-scanners"),
        # Exit 1 with no recorded cause: the crash wording.
        pytest.param([], [], False, id="exception"),
    ],
)
def test_incompleteness_message(console, scanners, converters, stale, text_snapshot):
    records = [r for r in stale_records() if r.policy == "fail"] if stale else []

    print_incompleteness_message(scanners, converters, records)

    assert rendered(console) == text_snapshot("txt")


# --------------------------------------------------------------------------- run_ash_scan


@pytest.fixture
def stubbed_scan(monkeypatch, console, pinned_clock):
    """Replace the scan with a prepared model; everything after it runs for real."""

    def _with(model):
        monkeypatch.setattr(
            ras, "_setup_logger", lambda opts: logging.getLogger("snapshot.console")
        )
        monkeypatch.setattr(ras, "_run_local_mode", lambda opts, logger: (model, None))

    return _with


def _scan(layout, **kwargs):
    source, output = layout
    return run_ash_scan(source_dir=source, output_dir=output, progress=False, **kwargs)


def _clean_model() -> AshAggregatedResults:
    model = scan_results_model(with_incomplete_scanners=False)
    model.sarif.runs[0].results = [
        finding("checkov", "CKV_AWS_18", "LOW", "infra/bucket.yaml", 6, "Logging off")
    ]
    model.additional_reports = {
        name: report
        for name, report in model.additional_reports.items()
        if name in {"checkov", "syft"}
    }
    return model


def test_run_exits_2_on_actionable_findings(
    stubbed_scan, console, layout, text_snapshot
):
    """The only path that prints the exit-code legend, ending in "ERROR (2)"."""
    stubbed_scan(scan_results_model(with_incomplete_scanners=False))

    with pytest.raises(SystemExit) as exit_info:
        _scan(layout)

    assert exit_info.value.code == 2
    assert rendered(console) == text_snapshot("txt")


def test_run_exits_1_on_an_incomplete_scan(
    stubbed_scan, console, layout, text_snapshot
):
    stubbed_scan(scan_results_model())

    with pytest.raises(ScanIncompleteExit):
        _scan(layout)

    assert rendered(console) == text_snapshot("txt")


def test_run_exits_1_on_a_stale_content_database(
    stubbed_scan, console, layout, text_snapshot
):
    """Stale databases fail the scan even with the completeness gate off."""
    stubbed_scan(
        scan_results_model(with_incomplete_scanners=False, with_stale_databases=True)
    )

    with pytest.raises(ScanIncompleteExit):
        _scan(layout, fail_on_incomplete_scanners=False)

    assert rendered(console) == text_snapshot("txt")


def test_run_exits_1_when_conversion_was_incomplete(
    stubbed_scan, console, layout, text_snapshot
):
    model = _clean_model()
    model.converter_results = incomplete_converter_rows_model().converter_results
    stubbed_scan(model)

    with pytest.raises(ScanIncompleteExit):
        _scan(layout)

    assert rendered(console) == text_snapshot("txt")


def test_run_exits_1_with_no_results(stubbed_scan, console, layout, text_snapshot):
    """A scan that produced no model at all: the only route to the crash wording."""
    stubbed_scan(None)

    with pytest.raises(SystemExit) as exit_info:
        _scan(layout)

    assert exit_info.value.code == 1
    assert rendered(console) == text_snapshot("txt")


def test_run_exits_0_when_findings_do_not_fail_the_scan(
    stubbed_scan, console, layout, text_snapshot
):
    """``--no-fail-on-findings``: the investigate block still prints; no legend, no ERROR."""
    stubbed_scan(scan_results_model(with_incomplete_scanners=False))

    _scan(layout, fail_on_findings=False)

    assert rendered(console) == text_snapshot("txt")


def test_run_exits_0_on_a_clean_scan(stubbed_scan, console, layout, text_snapshot):
    stubbed_scan(_clean_model())

    _scan(layout)

    assert rendered(console) == text_snapshot("txt")
