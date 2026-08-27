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
* ``display_label`` is not unique by construction (see ``ProjectPlan``), so the
  key is shown when the two differ. Showing only the label would make two
  projects indistinguishable in the table while the findings under them differ.
* Every value that reaches HTML is escaped. A label arrives from a project's own
  config file, which is untrusted text as far as this code is concerned.
"""

from __future__ import annotations

import html as html_escape
from typing import Any, Dict, List, Optional, Sequence, TYPE_CHECKING

from automated_security_helper.models.workspace import is_workspace_scan

if TYPE_CHECKING:  # pragma: no cover - typing only
    from automated_security_helper.models.asharp_model import AshAggregatedResults

#: The HTML section's anchor id, so a test and a stylesheet can find it without
#: matching on prose.
HTML_SECTION_ID = "workspace-projects"

#: Column order, shared by all three renderers so they cannot present the same
#: data in different orders.
COLUMNS = ("Project", "Status", "Findings", "Actionable", "Threshold", "Result")


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
        if project.skip_reason is not None:
            # The reason matters more than the word "skipped": a no-changes skip
            # is a successful optimisation and an error skip is a project that
            # was not looked at, and they must not read the same.
            reason = getattr(project.skip_reason, "value", project.skip_reason)
            result = f"SKIPPED ({reason})"
        elif project.error:
            result = "FAILED"
        elif project.exceeds_threshold:
            result = "FAILED"
        else:
            result = "PASSED"

        label = project.display_label
        if label != project.project:
            label = f"{label} ({project.project})"

        rows.append(
            {
                "project": label,
                "key": project.project,
                "status": str(status).upper(),
                "findings": project.finding_count,
                "actionable": project.actionable_finding_count,
                "threshold": project.severity_threshold or "n/a",
                "result": result,
                "detail": project.error or project.skip_detail or "",
            }
        )
    return rows


def _cells(row: Dict[str, Any]) -> Sequence[str]:
    """One row's values in :data:`COLUMNS` order, as strings."""
    return (
        str(row["project"]),
        str(row["status"]),
        str(row["findings"]),
        str(row["actionable"]),
        str(row["threshold"]),
        str(row["result"]),
    )


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
        # Escaped for markdown tables specifically: a pipe in a project label
        # would otherwise split the row into extra columns and silently shift
        # every value after it.
        lines.append(
            "| " + " | ".join(cell.replace("|", "\\|") for cell in _cells(row)) + " |"
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
        cells = "".join(f"<td>{html_escape.escape(cell)}</td>" for cell in _cells(row))
        css_class = "failed" if row["result"].startswith("FAILED") else "passed"
        body.append(f'<tr class="{css_class}">{cells}</tr>')

    return (
        f'<div class="section" id="{HTML_SECTION_ID}">'
        "<h2>Projects</h2>"
        "<p>Each project is scanned independently and judged against its own "
        "threshold, so a workspace fails when any project does.</p>"
        f"<table><thead><tr>{header}</tr></thead>"
        f"<tbody>{''.join(body)}</tbody></table>"
        "</div>"
    )
