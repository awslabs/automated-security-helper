# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What ``--output-formats <fmt>`` actually writes, for every format ASH accepts.

The defect these tests exist to prevent
---------------------------------------
``ReportPhase`` selected reporters by comparing the requested format names
against each reporter's ``config.extension``. Those are different kinds of
string: a format name is ``markdown``, an extension is the ``summary.md`` in
``ash.summary.md``. They coincide for exactly four reporters -- ``csv``,
``html``, ``sarif`` and ``yaml`` -- so for the rest the comparison matched
nothing, the reporter was skipped, and the run exited 0 having written no report
at all. ``ash scan --output-formats markdown`` produced an empty ``reports/``
directory and said nothing, while the closing summary still pointed the operator
at ``reports/ash.summary.md``.

Why no existing test caught it
------------------------------
There were tests that ``--output-formats`` reached ``ReportPhase`` (see
``tests/unit/cli/test_output_formats_fix.py``) and tests that each reporter
produces correct content. Nothing asserted the pair: *given this format name,
this file appears on disk*. The bug lived precisely in the gap between the flag
arriving and a file being written, so tests on either side of that gap both
passed.

So the central test here is table-driven over every ``ExportFormat`` member and
asserts the exact set of filenames produced. A format added later with no
reporter behind it fails :func:`test_expectations_cover_every_export_format`
rather than silently joining the set of formats that quietly do nothing.

Why the expectations are exact filenames, not "some file appeared"
-----------------------------------------------------------------
``extension`` still builds the output filename (``ash.{extension}``), and the
tempting fix for the selection bug was to set each reporter's ``extension`` to
its format name. That would have renamed ``ash.summary.md`` to ``ash.markdown``
and broken every consumer, document and test that reads the current names. The
filenames are therefore pinned as literals in :data:`EXPECTED_REPORTS` -- a fix
that repairs selection by renaming outputs fails this file loudly.

Driven through the real ``ReportPhase`` and the real plugin registry
-------------------------------------------------------------------
No mocked reporters. The subject is which of the *shipped* reporters a format
name selects, so a fake reporter with a hand-chosen name and extension would
assert only that the test's own fixture is self-consistent. These expectations
were measured against ``ash scan --output-formats <fmt>`` on a real source tree
and reproduce it exactly.
"""

import logging
from pathlib import Path
from typing import Dict, List, Optional, Sequence

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.reporter_plugin import (
    reporter_format_name,
    reporter_matches_requested_formats,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import ExportFormat
from automated_security_helper.core.phases.report_phase import (
    FORMAT_NO_REPORTER,
    FORMAT_REPORTER_UNAVAILABLE,
    ReportPhase,
    unsatisfied_output_formats,
)
from automated_security_helper.core.progress import LiveProgressDisplay
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.plugins.loader import load_plugins

# --------------------------------------------------------------------------- #
# The measured table.
# --------------------------------------------------------------------------- #

#: Every ``ExportFormat`` member, and the exact report filenames that naming it
#: on ``--output-formats`` must produce.
#:
#: Nine formats produce a file. Six produce none, and they are not
#: interchangeable -- see :data:`UNPRODUCIBLE` for which cause applies to each,
#: because "no reporter exists" and "the reporter is switched off" send an
#: operator to entirely different places.
#:
#: Before the selection fix only ``csv``, ``html`` and ``sarif`` produced
#: anything: the three whose extension happens to equal their format name and
#: which also ship enabled. ``yaml`` is the fourth name/extension coincidence but
#: ships disabled, so it produced nothing then and produces nothing now.
EXPECTED_REPORTS: Dict[ExportFormat, List[str]] = {
    ExportFormat.AGGREGATED: [],
    ExportFormat.TEXT: ["ash.summary.txt"],
    ExportFormat.FLAT_JSON: ["ash.flat.json"],
    ExportFormat.YAML: [],
    ExportFormat.CSV: ["ash.csv"],
    ExportFormat.HTML: ["ash.html"],
    ExportFormat.DICT: [],
    ExportFormat.JUNITXML: ["ash.junit.xml"],
    ExportFormat.MARKDOWN: ["ash.summary.md"],
    ExportFormat.SARIF: ["ash.sarif"],
    ExportFormat.ASFF: [],
    ExportFormat.OCSF: ["ash.ocsf.json"],
    ExportFormat.CYCLONEDX: ["ash.cdx.json"],
    ExportFormat.SPDX: [],
    ExportFormat.CUSTOM: [],
}

#: Why each non-producing format produces nothing.
#:
#: ``yaml`` and ``spdx`` ship ``enabled: bool = False``, so their reporters are
#: dropped by the enabled/dependency filter before the format filter is even
#: consulted. Repairing the format matching cannot make them emit, and a message
#: claiming ASH has no yaml reporter would be false -- the operator needs one line
#: of config, not a different tool.
#:
#: The other four name no reporter at all. ``aggregated`` and ``dict`` are
#: internal result shapes rather than report formats, ``asff`` is the payload the
#: Security Hub reporter publishes but that reporter is named
#: ``aws-security-hub``, and ``custom`` is a placeholder for third-party plugins.
UNPRODUCIBLE: Dict[ExportFormat, str] = {
    ExportFormat.AGGREGATED: FORMAT_NO_REPORTER,
    ExportFormat.DICT: FORMAT_NO_REPORTER,
    ExportFormat.ASFF: FORMAT_NO_REPORTER,
    ExportFormat.CUSTOM: FORMAT_NO_REPORTER,
    ExportFormat.YAML: FORMAT_REPORTER_UNAVAILABLE,
    ExportFormat.SPDX: FORMAT_REPORTER_UNAVAILABLE,
}

#: Reporters whose extension differs from their name. Selecting on extension
#: skipped every one of these, which is the population the bug affected. Kept as
#: an explicit list so :func:`test_selection_name_is_not_the_extension` fails if a
#: future change quietly makes the two equal by renaming an output file.
NAME_DIFFERS_FROM_EXTENSION = {
    "text": "summary.txt",
    "flat-json": "flat.json",
    "junitxml": "junit.xml",
    "markdown": "summary.md",
    "ocsf": "ocsf.json",
    "cyclonedx": "cdx.json",
    "spdx": "spdx.json",
}


# --------------------------------------------------------------------------- #
# Harness: a real ReportPhase over the real registry.
# --------------------------------------------------------------------------- #


def _run_report_phase(
    tmp_path: Path, requested: Optional[Sequence[object]]
) -> List[str]:
    """Run the real report phase for ``requested`` and return the filenames written.

    ``requested`` is passed straight through as ``cli_output_formats``, so a test
    can hand it plain strings or ``ExportFormat`` members and exercise the same
    normalisation production does.
    """
    output_dir = tmp_path / "out"
    context = PluginContext(
        source_dir=tmp_path,
        output_dir=output_dir,
        work_dir=output_dir / "work",
        config=AshConfig(),
    )
    ash_plugin_manager.set_context(context)
    load_plugins(plugin_context=context)

    phase = ReportPhase(
        plugins=ash_plugin_manager.plugin_modules(plugin_type="reporter"),
        plugin_context=context,
        progress_display=LiveProgressDisplay(show_progress=False),
        asharp_model=AshAggregatedResults(),
    )
    reports_dir = output_dir / "reports"
    phase.execute(
        report_dir=reports_dir,
        cli_output_formats=list(requested) if requested is not None else None,
        aggregated_results=AshAggregatedResults(),
        python_based_plugins_only=False,
    )
    return sorted(p.name for p in reports_dir.iterdir()) if reports_dir.exists() else []


def _reporter_instances(tmp_path: Path) -> List[object]:
    """Every shipped reporter, constructed the way ``ReportPhase`` constructs them."""
    output_dir = tmp_path / "out"
    config = AshConfig()
    context = PluginContext(
        source_dir=tmp_path,
        output_dir=output_dir,
        work_dir=output_dir / "work",
        config=config,
    )
    ash_plugin_manager.set_context(context)
    load_plugins(plugin_context=context)

    instances = []
    for cls in ash_plugin_manager.plugin_modules(plugin_type="reporter"):
        try:
            instances.append(
                cls(
                    context=context,
                    config=config.get_plugin_config(
                        plugin_type="reporter", plugin_name=cls.__name__.lower()
                    ),
                )
            )
        except Exception:  # noqa: BLE001 -- mirrors ReportPhase's own tolerance
            continue
    return instances


# --------------------------------------------------------------------------- #
# The central table-driven assertion.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "export_format",
    list(EXPECTED_REPORTS),
    ids=[fmt.value for fmt in EXPECTED_REPORTS],
)
def test_requested_format_writes_expected_files(export_format, tmp_path):
    """Naming one format writes exactly the files that format is responsible for.

    This is the assertion whose absence let the bug ship. Both halves matter: the
    expected file must appear (selection works) and no *other* file may appear (a
    format request is still a filter, not a suggestion).
    """
    written = _run_report_phase(tmp_path, [export_format.value])

    assert written == EXPECTED_REPORTS[export_format], (
        f"--output-formats {export_format.value} wrote {written}, expected "
        f"{EXPECTED_REPORTS[export_format]}"
    )


def test_expectations_cover_every_export_format():
    """Every ``ExportFormat`` member has a recorded expectation.

    The guard requirement: a format added to the enum without a reporter behind it
    must fail here. Without this, a new member would simply join the set of
    formats that are accepted by the CLI and quietly write nothing -- which is the
    original defect returning through the front door.
    """
    assert set(EXPECTED_REPORTS) == set(ExportFormat)


def test_unproducible_expectations_agree_with_the_table():
    """:data:`UNPRODUCIBLE` and :data:`EXPECTED_REPORTS` describe the same formats.

    Two tables that can disagree are worse than one, so this pins them together:
    a format is listed as unproducible if and only if it is expected to write no
    file.
    """
    expected_empty = {fmt for fmt, files in EXPECTED_REPORTS.items() if not files}

    assert set(UNPRODUCIBLE) == expected_empty


# --------------------------------------------------------------------------- #
# No output filename changed.
# --------------------------------------------------------------------------- #


def test_no_output_filename_changed(tmp_path):
    """Each reporter still writes ``ash.{extension}``, unchanged by this fix.

    The rejected alternative for the selection bug was to make ``extension`` equal
    the format name, which would have renamed seven output files. This asserts the
    filename is still derived from ``extension`` and not from the format name, so
    that alternative cannot be introduced later without failing a test.
    """
    for instance in _reporter_instances(tmp_path):
        name = reporter_format_name(instance)
        extension = getattr(instance.config, "extension", None)
        if name is None or extension is None:
            continue
        export_format = next(
            (fmt for fmt in ExportFormat if fmt.value == name),
            None,
        )
        if export_format is None or not EXPECTED_REPORTS[export_format]:
            continue

        assert f"ash.{extension}" in EXPECTED_REPORTS[export_format], (
            f"reporter '{name}' writes ash.{extension}, which is not the filename "
            f"pinned for format '{name}'"
        )


@pytest.mark.parametrize("name,extension", sorted(NAME_DIFFERS_FROM_EXTENSION.items()))
def test_selection_name_is_not_the_extension(name, extension, tmp_path):
    """For these reporters the name and extension still differ, and name selects.

    The bug's whole population. If a later change makes one of these equal -- by
    renaming an output file to match its format name -- this fails, because that
    change would be the rejected alternative arriving by another route.
    """
    instance = next(
        (i for i in _reporter_instances(tmp_path) if reporter_format_name(i) == name),
        None,
    )
    assert instance is not None, f"no reporter named '{name}'"
    assert instance.config.extension == extension
    assert instance.config.extension != name

    assert reporter_matches_requested_formats(instance, [name])
    # The extension must NOT select the reporter. This is the direct inverse of
    # the old behaviour and the tightest statement of the fix.
    assert not reporter_matches_requested_formats(instance, [extension])


# --------------------------------------------------------------------------- #
# A format that produces nothing must say so.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "export_format,reason",
    sorted(UNPRODUCIBLE.items(), key=lambda item: item[0].value),
    ids=[fmt.value for fmt in sorted(UNPRODUCIBLE, key=lambda f: f.value)],
)
def test_unproducible_format_is_diagnosed_with_its_cause(
    export_format, reason, tmp_path
):
    """A requested format that writes nothing is reported, with the right cause.

    Silence is the defect. Repairing the format matching fixes the seven
    extension-mismatched reporters but leaves six formats that still produce
    nothing, and those must not be silent either.
    """
    instances = _reporter_instances(tmp_path)
    selected = [
        i
        for i in instances
        if reporter_matches_requested_formats(i, [export_format.value])
        and getattr(i.config, "enabled", True)
    ]

    diagnosis = unsatisfied_output_formats(
        output_formats=[export_format.value],
        selected_instances=selected,
        all_instances=instances,
    )

    assert diagnosis == {export_format.value: reason}


def test_producible_format_is_not_diagnosed(tmp_path):
    """A format that will be written is not reported as unproducible.

    Guards the other direction: a diagnosis that fires for every format would
    satisfy the tests above while making the warning worthless.
    """
    instances = _reporter_instances(tmp_path)
    selected = [i for i in instances if reporter_format_name(i) == "markdown"]

    diagnosis = unsatisfied_output_formats(
        output_formats=["markdown"],
        selected_instances=selected,
        all_instances=instances,
    )

    assert diagnosis == {}


def test_no_request_diagnoses_nothing(tmp_path):
    """An empty request is not a request that was denied."""
    instances = _reporter_instances(tmp_path)

    assert unsatisfied_output_formats([], instances, instances) == {}
    assert unsatisfied_output_formats(None, instances, instances) == {}


def test_disabled_reporter_is_not_reported_as_missing(tmp_path):
    """``yaml`` is diagnosed as inactive, never as nonexistent.

    The distinction is the point of splitting the two reasons. Told that ASH has
    no yaml reporter, an operator would go looking for a plugin; told it is
    disabled, they edit one line of config.
    """
    instances = _reporter_instances(tmp_path)

    diagnosis = unsatisfied_output_formats(["yaml"], [], instances)

    assert diagnosis == {"yaml": FORMAT_REPORTER_UNAVAILABLE}
    assert diagnosis["yaml"] != FORMAT_NO_REPORTER


def test_unproducible_format_warns_on_the_operators_log(tmp_path, caplog):
    """The diagnosis reaches the log, naming the format and the cause.

    ``unsatisfied_output_formats`` being correct is worth nothing if the phase
    never emits it, so this drives the whole phase and reads the log rather than
    calling the helper.
    """
    with caplog.at_level(logging.WARNING):
        written = _run_report_phase(tmp_path, ["asff"])

    assert written == []
    assert "asff" in caplog.text
    assert "no reporter produces it" in caplog.text


def test_mixed_request_writes_what_it_can_and_warns_about_the_rest(tmp_path, caplog):
    """One unproducible format must not cost the operator their other reports.

    Warning rather than raising is a deliberate choice: erroring on ``asff`` here
    would discard the markdown report the same command asked for, and for
    ``ash scan`` the findings verdict along with it.
    """
    with caplog.at_level(logging.WARNING):
        written = _run_report_phase(tmp_path, ["markdown", "asff"])

    assert written == ["ash.summary.md"]
    assert "asff" in caplog.text


# --------------------------------------------------------------------------- #
# Shapes the requested list arrives in.
# --------------------------------------------------------------------------- #


def test_export_format_members_select_as_well_as_strings(tmp_path):
    """``ExportFormat`` members work, not only their ``.value`` strings.

    ``ScanExecutionEngine`` threads the enum through unconverted -- pinned by
    ``tests/unit/cli/test_output_formats_fix.py`` -- while the ``ash scan`` and
    ``ash merge`` paths convert to ``.value`` first. Both shapes reach the filter,
    so both are asserted here; a filter that handled only one would work from the
    CLI and fail from the engine, or the reverse.
    """
    assert _run_report_phase(tmp_path / "enum", [ExportFormat.MARKDOWN]) == [
        "ash.summary.md"
    ]
    assert _run_report_phase(tmp_path / "str", ["markdown"]) == ["ash.summary.md"]


def test_no_requested_formats_runs_every_enabled_reporter(tmp_path):
    """No ``--output-formats`` means the configured default set, not nothing.

    Asserted as a superset of the individually-requested files rather than an
    exact list: reporters with no ``ExportFormat`` at all (``github-ghas``,
    ``gitlab-sast``, ``gitlab-cyclonedx``, ``unused-suppressions``) also run here,
    and they are unreachable by name because no enum member selects them.
    """
    written = _run_report_phase(tmp_path, None)

    for files in EXPECTED_REPORTS.values():
        for filename in files:
            assert filename in written, f"{filename} missing from a default run"


def test_reporters_without_an_export_format_are_not_emitted_by_a_named_request(
    tmp_path,
):
    """Asking for one format must not drag in reporters nobody asked for.

    These four reporters have no corresponding ``ExportFormat``, so they cannot be
    requested by name. The fix must leave them skipped under an explicit request
    -- widening selection to "anything enabled" would publish GitHub and GitLab
    ingestion artefacts to operators who asked only for markdown.
    """
    written = _run_report_phase(tmp_path, ["markdown"])

    for filename in (
        "ash.ghas.sarif",
        "ash.gl-sast-report.json",
        "ash.gl-dependency-scanning-report.cdx.json",
        "ash.unused-suppressions.json",
    ):
        assert filename not in written


# --------------------------------------------------------------------------- #
# The second copy of the filter: workspace mode.
# --------------------------------------------------------------------------- #


def test_workspace_filter_shares_the_phase_predicate(tmp_path):
    """Workspace mode selects by name too, because it calls the same function.

    The bug existed in two places -- ``ReportPhase`` and
    ``workspace.reporting._matches_requested_formats`` -- each with its own copy of
    the extension comparison. Fixing only the first would have left a workspace
    scan of the same directory silently producing no markdown report. They now
    share one predicate; this asserts the workspace entry point agrees with it.
    """
    from automated_security_helper.workspace.reporting import (
        _matches_requested_formats,
    )

    markdown = next(
        (
            i
            for i in _reporter_instances(tmp_path)
            if reporter_format_name(i) == "markdown"
        ),
        None,
    )
    assert markdown is not None

    assert _matches_requested_formats(markdown, ["markdown"])
    assert not _matches_requested_formats(markdown, ["summary.md"])
    # Empty request still means every reporter.
    assert _matches_requested_formats(markdown, [])


# --------------------------------------------------------------------------- #
# The predicate's own edges.
# --------------------------------------------------------------------------- #


def test_reporter_without_a_name_never_matches_a_named_request():
    """An unnameable reporter is not emitted on the strength of someone's request.

    ``reporter_format_name`` returns ``None`` when a config carries no name.
    Treating that as "matches everything" would emit such a reporter for every
    format anyone asked for, which is the opposite of a filter.
    """

    class _Nameless:
        class config:  # noqa: N801 -- a stand-in for a config object
            extension = "thing.json"

    nameless = _Nameless()

    assert reporter_format_name(nameless) is None
    assert not reporter_matches_requested_formats(nameless, ["markdown"])
    # But an empty request is not a named request, so it still runs.
    assert reporter_matches_requested_formats(nameless, [])
