# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The per-project section the three human-readable reporters share.

Why this is one module and not three tables
-------------------------------------------
``html``, ``markdown`` and ``text`` all need to answer the same question -- which
project is in trouble -- and each renders it in its own markup. Written three
times, the three would drift: a column added to one, a status spelling changed in
another, a verdict computed slightly differently in the third. The rows are built
once here and only the rendering differs, so a change to *what* is reported lands
in all three at once and a change to *how* stays local to one function.

The rows come from the workspace payload, not from the findings
--------------------------------------------------------------
``exceeds_threshold`` and ``actionable_finding_count`` are read off
``model.workspace.projects``, where each project's own scan recorded them against
that project's own effective threshold. They are deliberately not recomputed from
the findings in the merged model.

Recomputing would apply one threshold to every project, and projects in a
workspace are independently configured -- a project with a HIGH threshold and a
project with a LOW one would be judged the same way. The section would then
disagree with the exit code for the same run, and an operator would have two
verdicts and no rule for which is authoritative. The whole invariant workspace
mode holds is that a project's verdict is what ``ash --source-dir P`` would
produce; re-deriving it here would break that in the most visible artefact.

The finding *counts* per project are also taken from the payload for the same
reason, with one consequence worth naming: they count unsuppressed findings as
the per-project scan counted them, which is not necessarily the number of rows a
reader can find for that project elsewhere in the same document if a reporter
filters differently. That is a real inconsistency, and it is the correct one --
the alternative makes the table disagree with the verdict beside it.

Failure modes and known limitations
-----------------------------------
* A project with no verdict -- skipped, or failed -- has no threshold and no
  counts. It appears with its status and its reason rather than being omitted:
  omitting it would let a project the operator asked for vanish from the one
  table they read, which is the silent-omission failure this feature exists
  against.
* ``Result`` states one reason, and where a project holds more than one the
  precedence is ``workspace_exit_code``'s rather than a second one invented here.
  So a project both over its threshold and missing a scanner reads ``FAILED``,
  not ``FAILED (incomplete)``; the missing scanner is in ``detail`` instead. The
  alternative -- ranking incompleteness first -- would have made the table name a
  different cause than the exit code did for the same project.
* ``display_label`` is not unique by construction (see ``ProjectPlan``), so the
  key is shown when the two differ. Showing only the label would make two
  projects indistinguishable in the table while the findings under them differ.
* Every value that reaches HTML is escaped. A label arrives from a project's own
  config file, which is untrusted text as far as this code is concerned.
"""

from __future__ import annotations

import html as html_escape
import re
from typing import Any, Dict, List, Optional, Sequence, TYPE_CHECKING

from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    SkippedProjectReason,
    is_workspace_scan,
)
from automated_security_helper.utils.severity_ladder import (
    SEVERITY_THRESHOLDS,
    normalize_threshold,
)
from automated_security_helper.utils.terminal_text import shown_on_one_line

if TYPE_CHECKING:  # pragma: no cover - typing only
    from automated_security_helper.models.asharp_model import AshAggregatedResults

#: The HTML section's anchor id, so a test and a stylesheet can find it without
#: matching on prose.
HTML_SECTION_ID = "workspace-projects"

#: Column order, shared by all three renderers so they cannot present the same
#: data in different orders.
COLUMNS = ("Project", "Status", "Findings", "Actionable", "Threshold", "Result")


def workspace_project_thresholds(model: "AshAggregatedResults") -> Dict[str, str]:
    """``{project key: threshold}`` for every project whose gate is recorded.

    Read off ``model.workspace.projects`` -- the per-project record carries the
    gate threshold its own scan used (``WorkspaceProjectResult.severity_threshold``
    is written from ``project.gate_threshold``, the workspace ceiling folded in).
    The merged results file carries no ``ash_config``, so a reporter grading a
    finding attributed to a project has no other source for the project's gate;
    reading ASH's default there made the merged JUnit and HTML reports grade
    every project against one threshold while each project's outcome and the
    exit code used its own.

    Built once per model rather than scanned per finding: the emitter grades
    each finding several times (summary, hotspots, cards, detailed findings)
    and the JUnit reporter once per result, so a per-call scan over the project
    list was findings times projects times passes on a large workspace.

    Every value is the ladder's own spelling (``normalize_threshold``), so the
    JUnit, HTML, Markdown and text reports grade a recorded ``"medium"`` alike;
    before this the JUnit reporter normalized the value and the emitter passed
    it to the case-sensitive ladder as stored, which read it as CRITICAL. A
    recorded value the ladder does not recognise is left out, so the finding
    falls back to the scanner's or the scan's gate as an unattributed finding
    does, instead of being graded by a gate nobody configured.

    Empty for a single-directory scan; a project that never ran (its threshold
    is recorded null) has no entry.
    """
    if not is_workspace_scan(model):
        return {}
    thresholds: Dict[str, str] = {}
    for project in model.workspace.projects:
        normalized = normalize_threshold(project.severity_threshold)
        if normalized is not None:
            thresholds[project.project] = normalized
    return thresholds


def workspace_project_scanner_thresholds(
    model: "AshAggregatedResults",
) -> Dict[str, Dict[str, str]]:
    """``{project key: {scanner name: threshold}}`` for every recorded scanner gate.

    Read off ``WorkspaceProjectResult.scanner_thresholds``, where each project's
    outcome recorded the threshold its verdict graded a scanner by when that is
    the scanner's own ``options.severity_threshold`` (the workspace ceiling folded
    in). A scanner with no entry was graded by the project's gate, which
    :func:`workspace_project_thresholds` gives. The merged results file carries
    no ``ash_config``, so a reporter grading a finding attributed to a project
    had no other source for the scanner's gate and judged every project's
    scanners at the project gate alone, which is not how the verdict judged a
    scanner that tightened or relaxed its own.

    Every value is the ladder's own spelling (``normalize_threshold``); a
    recorded value the ladder does not recognise is left out, as in
    :func:`workspace_project_thresholds`, so the finding falls back to the
    project's gate. Empty for a single-directory scan and for a workspace file
    written before the field existed.

    A scanner named in ``withheld_scanner_thresholds`` was graded by a threshold
    the scan read from an environment variable, which the file does not carry.
    It is listed here at the strictest gate (``ALL``) rather than left to the
    project's gate: the project's gate may be looser than the withheld one, and
    a finding the project's own count included would then read as a skipped case
    in the merged report. The strictest gate is the side that cannot hide it.
    """
    if not is_workspace_scan(model):
        return {}
    by_project: Dict[str, Dict[str, str]] = {}
    for project in model.workspace.projects:
        recorded = getattr(project, "scanner_thresholds", None) or {}
        gates: Dict[str, str] = {}
        for scanner, value in recorded.items():
            normalized = normalize_threshold(value)
            if normalized is not None:
                gates[str(scanner)] = normalized
        for scanner in getattr(project, "withheld_scanner_thresholds", None) or ():
            gates.setdefault(str(scanner), SEVERITY_THRESHOLDS[0])
        if gates:
            by_project[project.project] = gates
    return by_project


def workspace_policy_gates(model: "AshAggregatedResults") -> Dict[str, Optional[bool]]:
    """``{project key: policy_scanners_gate}`` for every project in the workspace.

    Whether a finding from a scanner only the workspace policy added decided
    that project's verdict. A reader grading such a finding (its
    ``properties.origin`` is ``workspace-policy``) reads this before the
    threshold: only an explicit False says the verdict excluded the finding from
    ``actionable_finding_count``, so grading it as a failure would contradict
    the project's own outcome and the exit code. Empty for a single-directory
    scan. None for a project in a workspace file written before the field
    existed: that file's verdict applied the gate before it wrote, so a reader
    treats None as gating and grades the finding by the threshold, the
    fail-closed side; a project the table does not list is read the same way.
    """
    if not is_workspace_scan(model):
        return {}
    gates: Dict[str, Optional[bool]] = {}
    for project in model.workspace.projects:
        value = getattr(project, "policy_scanners_gate", None)
        gates[project.project] = value if isinstance(value, bool) else None
    return gates


def _skip_is_error(reason: Any) -> bool:
    """Whether a project's recorded skip reason is an error skip.

    The reason arrives as the enum member, or as its plain string from a record
    built without validation; either is read through the enum's own property.
    A reason the enum does not name is not an error skip.
    """
    if reason is None:
        return False
    try:
        return SkippedProjectReason(reason).is_error
    except ValueError:
        return False


def workspace_project_rows(model: "AshAggregatedResults") -> List[Dict[str, Any]]:
    """One row per project, in workspace-file order, or ``[]`` for a single scan.

    Returning ``[]`` rather than raising for a non-workspace model is what lets
    every call site be a single ``if rows:`` -- the alternative is the same
    ``model.workspace is None`` test repeated in three reporters, which is one
    place for it to be spelled wrong.
    """
    if not is_workspace_scan(model):
        return []
    workspace = model.workspace

    rows: List[Dict[str, Any]] = []
    for project in workspace.projects:
        status = getattr(project.status, "value", project.status)
        # The reason matters more than the word "skipped": a no-changes skip is
        # a successful optimisation and an error skip is a project that was not
        # looked at, and they must not read the same.
        reason = getattr(project.skip_reason, "value", project.skip_reason)
        if project.status == ProjectRunStatus.FAILED:
            # The recorded status decides, ahead of every text field: a FAILED
            # project whose error is null or empty was still attempted and
            # produced no outcome, and workspace_exit_code fails the run for it.
            # Read from the text alone it fell through to PASSED; read after the
            # skip_reason arm, a FAILED project that also carried a skip reason
            # read SKIPPED.
            result = "FAILED"
        elif project.status == ProjectRunStatus.SKIPPED:
            # A SKIPPED project was never scanned: its counts are zero because
            # nothing ran, not because nothing was found. The status decides
            # ahead of the error text, so a skipped project that also carries an
            # error text reads SKIPPED, as workspace_exit_code reads it.
            result = f"SKIPPED ({reason})" if reason else "SKIPPED"
        elif project.skip_reason is not None:
            # Fallbacks for a record whose status does not say: the text fields.
            result = f"SKIPPED ({reason})"
        elif project.error:
            result = "FAILED"
        elif project.scan_incomplete:
            # Ahead of the threshold arm, in the order workspace_exit_code reads a
            # project (incomplete before findings, as a single-directory scan
            # does); the Actionable column still shows a breach.
            #
            # Without this arm a COMPLETED project carrying scan_incomplete=True,
            # no error and no threshold breach fell to the else and was emitted as
            # PASSED with its counts -- the same row a clean scan produces -- while
            # workspace_exit_code failed the run for that same project. The table
            # was the optimistic half of two disagreeing verdicts.
            #
            # The suffix is not decoration: the row's ``state`` below is derived
            # from result.startswith("FAILED"), so a name that does not start
            # with it changes the text and leaves the row green. Renaming this
            # string means changing that predicate in the same edit.
            result = "FAILED (incomplete)"
        elif project.exceeds_threshold:
            result = "FAILED"
        else:
            result = "PASSED"

        label = project.display_label
        # ``display_label`` already carries the key when two projects share a
        # label (``svc (apps-a)``); appending it again read ``svc (apps-a)
        # (apps-a)``.
        if label != project.project and not label.endswith(f" ({project.project})"):
            label = f"{label} ({project.project})"

        detail = project.error or project.skip_detail or ""
        if project.incomplete_scanners:
            # Named whenever the list is populated, not only when the incomplete
            # arm above won: an operator who switched fail_on_incomplete_scanners
            # off gets a PASSED or threshold-FAILED row, and the scanner that did
            # not run is the one fact the rest of the row cannot convey.
            unrun = "did not complete: " + ", ".join(project.incomplete_scanners)
            detail = f"{detail}; {unrun}" if detail else unrun
        partial = getattr(project, "partial_coverage_scanners", None) or []
        if partial:
            # Evaluated some of their targets and not the rest: a different fact
            # from a scanner that did not run, and the one the counts hide.
            note = "partial coverage: " + ", ".join(partial)
            detail = f"{detail}; {note}" if detail else note
        if getattr(project, "no_scanner_ran", False):
            # Every scanner was skipped, so nothing was measured; with the
            # completeness gate off the row would otherwise read PASSED with
            # zero findings, as a clean scan does.
            note = "no scanner ran"
            detail = f"{detail}; {note}" if detail else note
        unscanned = getattr(project, "inputs_not_scanned", None) or []
        if unscanned:
            note = "inputs not scanned: " + _unscanned_input_list(unscanned)
            detail = f"{detail}; {note}" if detail else note
        converters = getattr(project, "incomplete_converters", None) or {}
        if converters:
            # Named for the same reason: a converter that lost coverage (an
            # archive over an extraction limit, a tool that was absent) is the one
            # fact the counts in the row cannot convey.
            unconverted = "conversion incomplete: " + ", ".join(converters)
            detail = f"{detail}; {unconverted}" if detail else unconverted
        refusals = getattr(project, "converter_refusals", None) or []
        if refusals:
            # The inputs behind the converter verdict, and the refusals that leave
            # the scan complete (a member that is itself an archive, a link): the
            # unified file holds no per-project converter rows, so this row is
            # where a reader learns which input went unconverted in which project.
            unread = "inputs not converted: " + _refusal_list(refusals)
            detail = f"{detail}; {unread}" if detail else unread
        policy_findings = getattr(project, "policy_origin_finding_count", 0) or 0
        if policy_findings:
            # Whether those findings decided the verdict: with the gate off they are
            # reported and excluded from the Actionable column, which the counts
            # alone cannot say. Only an explicit False is "off": a file written
            # before the field existed applied the gate before it wrote.
            gating = (
                "do not gate this project"
                if getattr(project, "policy_scanners_gate", None) is False
                else "gate this project"
            )
            policy = (
                f"{policy_findings} finding(s) from workspace-policy scanners {gating}"
            )
            detail = f"{detail}; {policy}" if detail else policy
        stale = [
            str(record.get("name"))
            for record in (project.stale_content_databases or [])
            if isinstance(record, dict) and record.get("name")
        ]
        if stale:
            # Its own note, as in a single scan: the scanner ran, against a
            # database past its bound, and is not among those that did not complete.
            dated = "stale content database: " + ", ".join(stale)
            detail = f"{detail}; {dated}" if detail else dated

        # A project that was never scanned has no counts: its zeros are not a
        # finding of none, and a row of zeros reads as a clean scan.
        never_scanned = (
            project.status in (ProjectRunStatus.FAILED, ProjectRunStatus.SKIPPED)
            or project.skip_reason is not None
            or bool(project.error)
        )
        # How the Result column is styled: red for a project that failed or was
        # skipped by an error (the workspace exits non-zero for both), muted for
        # a skip that is a successful no-op. Whether a skip is an error is the
        # reason's own answer (``SkippedProjectReason.is_error``), as the
        # headline's coverage count reads it, not the rendered text of the row.
        if result.startswith("FAILED") or (
            result.startswith("SKIPPED") and _skip_is_error(project.skip_reason)
        ):
            state = "failed"
        elif result.startswith("SKIPPED"):
            state = "skipped"
        else:
            state = "passed"

        rows.append(
            {
                "project": label,
                "key": project.project,
                "status": str(status).upper(),
                "findings": "n/a" if never_scanned else project.finding_count,
                "actionable": "n/a"
                if never_scanned
                else project.actionable_finding_count,
                "threshold": project.severity_threshold or "n/a",
                "result": result,
                "state": state,
                "detail": detail,
            }
        )
    return rows


#: How many refused converter inputs a project's row names before counting the rest.
REFUSALS_SHOWN_IN_ROW = 5


def _refusal_text(record: Any) -> str:
    """One refused converter input as ``converter: subject (reason)``.

    The subject is the one ``utils/converter_refusals.py`` prints: the archive
    member when one was refused, the count of further members a record stands
    for, else the input's path. Marked when the completeness gate counts it.
    """
    path = getattr(record, "path", "")
    unlisted = getattr(record, "unlisted_members", None)
    member = getattr(record, "member", None)
    if unlisted is not None:
        subject = f"{unlisted} more members of '{path}'"
    elif member:
        subject = f"member '{member}' of '{path}'"
    else:
        subject = f"'{path}'"
    text = f"{getattr(record, 'converter', '')}: {subject} ({getattr(record, 'reason', '')})"
    if getattr(record, "scan_incomplete", False):
        text += " [scan incomplete]"
    return text


def _unscanned_input_list(records: Sequence[Any]) -> str:
    """The first :data:`REFUSALS_SHOWN_IN_ROW` inputs a scanner did not scan, then a count."""
    shown = [
        f"{getattr(record, 'scanner', '')}: '{getattr(record, 'path', '')}' "
        f"({getattr(record, 'reason', '')})"
        for record in records[:REFUSALS_SHOWN_IN_ROW]
    ]
    rest = len(records) - len(shown)
    if rest > 0:
        shown.append(f"and {rest} more")
    return ", ".join(shown)


def _refusal_list(records: Sequence[Any]) -> str:
    """The first :data:`REFUSALS_SHOWN_IN_ROW` refusals, then a count of the rest."""
    shown = [_refusal_text(record) for record in records[:REFUSALS_SHOWN_IN_ROW]]
    rest = len(records) - len(shown)
    if rest > 0:
        shown.append(f"and {rest} more")
    return ", ".join(shown)


def _shown(value: Any) -> str:
    """*value* as one shown line.

    A project's label is ``project_name`` from that project's own config file,
    and its threshold and detail carry the same file's and the scanners' text,
    so each is shown, not obeyed: a control character or a newline in it is
    written as an escape and a CI command form is broken, as every other
    repository-controlled value the three reporters print. Without this a
    label's newline started a line of its own in the text report (a CI log) and
    in the Markdown table.
    """
    return str(shown_on_one_line(str(value)))


def _cells(row: Dict[str, Any]) -> Sequence[str]:
    """One row's values in :data:`COLUMNS` order, each one shown line."""
    return (
        _shown(row["project"]),
        _shown(row["status"]),
        _shown(row["findings"]),
        _shown(row["actionable"]),
        _shown(row["threshold"]),
        _shown(row["result"]),
    )


def _notes(rows: List[Dict[str, Any]]) -> List[tuple[str, str]]:
    """``(label, detail)`` for every row whose detail is not empty, both shown.

    The detail (an error's text, the scanners that did not complete, a
    conversion gap, a stale database) is the actionable half of a FAILED row,
    and it was built for every row and emitted by none of the renderers.
    """
    return [
        (_shown(row["project"]), _shown(row["detail"])) for row in rows if row["detail"]
    ]


#: Markdown's syntax characters, and the table's column separator: each is kept
#: literal with a backslash, after ``<``, ``>`` and ``&`` become entities. The
#: same escaping the Markdown reporter applies to every other scanner-controlled
#: value (its ``_text``), which the table could not import without a cycle.
_MARKDOWN_SYNTAX = re.compile(r"([\\`*_\[\]{}#|~])")


def _markdown_cell(value: str) -> str:
    return _MARKDOWN_SYNTAX.sub(r"\\\1", html_escape.escape(value, quote=False))


def markdown_workspace_section(model: "AshAggregatedResults") -> List[str]:
    """The section as markdown lines, or ``[]`` when this is not a workspace scan.

    Lines rather than one string, because the markdown reporter assembles its
    document from a list and joins once; handing it a block would make it the only
    element that had to be spliced.
    """
    rows = workspace_project_rows(model)
    if not rows:
        return []

    lines = ["## Projects\n"]
    lines.append(
        "Each project is scanned independently and judged against its own "
        "threshold, so a workspace fails when any project does.\n"
    )
    lines.append("| " + " | ".join(COLUMNS) + " |")
    lines.append("| --- | --- | ---: | ---: | --- | --- |")
    for row in rows:
        # Kept literal in Markdown, pipe included: a pipe in a project label
        # would otherwise split the row into extra columns and silently shift
        # every value after it, and markup in it would render instead of read.
        lines.append(
            "| " + " | ".join(_markdown_cell(value) for value in _cells(row)) + " |"
        )
    lines.append("")
    notes = _notes(rows)
    if notes:
        lines.extend(
            f"- **{_markdown_cell(label)}**: {_markdown_cell(detail)}"
            for label, detail in notes
        )
        lines.append("")
    return lines


def text_workspace_section(
    model: "AshAggregatedResults", *, widths: Optional[Sequence[int]] = None
) -> List[str]:
    """The section as fixed-width plain-text lines, or ``[]`` for a single scan.

    Column widths are computed from the content rather than hardcoded, so a long
    project label widens its column instead of pushing every later column out of
    alignment. This lands in a CI job log, where a table a reader has to count
    columns in is worse than no table -- and misalignment in the neighbouring
    scanner table was a real defect once already, pinned by
    ``TestTextReporterColumnAlignment``.
    """
    rows = workspace_project_rows(model)
    if not rows:
        return []

    cells = [_cells(row) for row in rows]
    if widths is None:
        widths = [
            max(len(COLUMNS[index]), *(len(cell[index]) for cell in cells))
            for index in range(len(COLUMNS))
        ]

    def line(values: Sequence[str]) -> str:
        return "  ".join(
            value.ljust(widths[index]) for index, value in enumerate(values)
        )

    lines = ["", "PROJECTS", "-" * len(line(COLUMNS))]
    lines.append(line(COLUMNS))
    lines.append("-" * len(line(COLUMNS)))
    lines.extend(line(cell) for cell in cells)
    notes = _notes(rows)
    if notes:
        lines.append("")
        lines.extend(f"  {label}: {detail}" for label, detail in notes)
    lines.append("")
    return lines


def html_workspace_section(model: "AshAggregatedResults") -> str:
    """The section as an HTML fragment, or ``""`` when this is not a workspace scan.

    Every interpolated value goes through ``html.escape``. A project label comes
    from a project's own config file, so it is untrusted text: unescaped, a label
    containing markup would rewrite the surrounding report, and ASH self-scans
    this repository at MEDIUM where an unescaped interpolation is an actionable
    finding.
    """
    rows = workspace_project_rows(model)
    if not rows:
        return ""

    header = "".join(f"<th>{html_escape.escape(column)}</th>" for column in COLUMNS)
    body = []
    for row in rows:
        values = _cells(row)
        # The Result column carries the report stylesheet's status class, which
        # the row class alone never had a rule for.
        cells = "".join(
            f"<td>{html_escape.escape(cell)}</td>" for cell in values[:-1]
        ) + (f'<td class="status-{row["state"]}">{html_escape.escape(values[-1])}</td>')
        body.append(f'<tr class="{row["state"]}">{cells}</tr>')
    notes = "".join(
        f"<li><strong>{html_escape.escape(label)}</strong>: {html_escape.escape(detail)}</li>"
        for label, detail in _notes(rows)
    )
    notes_list = f'<ul class="project-notes">{notes}</ul>' if notes else ""

    return (
        f'<div class="section" id="{HTML_SECTION_ID}">'
        "<h2>Projects</h2>"
        "<p>Each project is scanned independently and judged against its own "
        "threshold, so a workspace fails when any project does.</p>"
        f"<table><thead><tr>{header}</tr></thead>"
        f"<tbody>{''.join(body)}</tbody></table>"
        f"{notes_list}"
        "</div>"
    )
