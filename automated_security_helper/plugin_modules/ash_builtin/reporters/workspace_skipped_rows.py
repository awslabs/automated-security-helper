# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The skipped-project set, for the reporters whose output is one row per finding.

Why this module exists
----------------------
``csv``, ``junitxml`` and ``ocsf`` emit one record per finding. A skipped project
produced no findings, so it produced no record, so it was absent from those three
artefacts entirely -- and absent in the one way that cannot be noticed, since a
project with no rows reads exactly like a project that came back clean. The RFC
asks for the skipped set in the report payload *and* in every reporter's output;
the payload half holds (``WorkspaceResults.skipped_projects`` is a
``computed_field``, so it survives ``model_dump`` and reaches ``flat-json`` and
``yaml`` with no code in either reporter), and the three human-readable reporters
carry it because ``workspace_section`` renders a row per project rather than per
finding. These three were the gap.

Closing it means emitting a record that stands for a project rather than for a
finding. That is a synthetic row in a findings export, and the honest thing to say
about it is that a consumer which counts rows and calls the answer a finding count
will be wrong unless the row is marked. So every such record is marked, and marked
in the vocabulary its own format already has rather than in one invented here:

``csv``
    A ``workspace_row_type`` column, emitted only in workspace mode. CSV has no
    schema to borrow a status from, so a dedicated column is the format's own way
    to qualify a row. Workspace-only for the same reason ``workspace_project`` is:
    an unconditional column shifts every field after it, and a consumer reading a
    single-directory CSV by position would silently read the wrong one from then
    on. Real rows carry ``finding`` rather than an empty cell, so the filter can
    be written as a positive predicate and a blank cell is visibly wrong rather
    than quietly equivalent.

``junitxml``
    ``<skipped>``, which is JUnit's own statement that a test did not run. Every
    CI front end already counts it apart from ``<failure>`` and ``<error>``, so
    the exclusion costs a consumer nothing and a project row cannot turn a job
    red.

``ocsf``
    ``status_id`` 99, which the OCSF 1.1.0 Vulnerability Finding class defines as
    "not mapped -- see the ``status`` attribute, which contains a data source
    specific value" (https://schema.ocsf.io/1.1.0/classes/vulnerability_finding).
    3 ("Suppressed") was rejected: a suppressed finding is a finding somebody
    judged benign, so claiming one would assert that ASH looked at the project. 0
    ("Unknown") says only that the status is unknown, which is true but weaker
    than the value the schema reserves for precisely this -- a status the producer
    has and the schema does not model.

Each marker is a field a query can exclude on, not a convention buried in a
string. Alongside it, each synthetic record also carries nothing a severity
rollup could act on: the CSV row's ``severity`` cell is blank, the JUnit case is
skipped rather than failed, and the OCSF record is severity 1 (Informational) with
an empty ``vulnerabilities`` array. So a consumer that never learns about the
marker still does not acquire a phantom finding.

What is deliberately not done
-----------------------------
* No record is emitted for a project that FAILED. A failed project is disclosed
  through the exit code and through ``workspace_section``, and it is a different
  claim from a skip: nothing was concluded about it, rather than nothing was
  attempted. Widening this to failures would need its own marker and its own
  ruling; ``skipped_projects`` is what the RFC names.
* ``ocsf``'s error-response envelope (every finding failed to process or to
  serialise) does not carry these records. That envelope is not a findings array,
  and appending project rows to it would make a malformed document. The skip is
  still in the payload and in the other five reporters.
* The reason is carried as text, not as a second enum. A consumer that needs to
  branch on NO_CHANGES versus ERROR should read ``workspace.skipped_projects`` in
  the payload, which is typed; these rows exist so the project is *visible* in a
  findings export, not so the export becomes a second source of truth for it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from automated_security_helper.models.workspace import (
    SkippedProject,
    is_workspace_scan,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from automated_security_helper.models.asharp_model import AshAggregatedResults


def skipped_projects(model: AshAggregatedResults) -> list[SkippedProject]:
    """The skipped projects, or ``[]`` for a single-directory scan.

    Returning ``[]`` rather than raising for a non-workspace model is what lets
    every call site be a single ``for entry in skipped_projects(model):`` with no
    guard -- the alternative is the same ``is_workspace_scan`` test repeated in
    three reporters, which is one place for it to be spelled wrong.

    Read off the workspace block rather than recomputed from
    ``workspace.projects``. ``skipped_projects`` already applies the rule that a
    SKIPPED status without a ``skip_reason`` is not a reportable skip
    (``WorkspaceProjectResult.as_skipped_project``), and a second implementation
    of that rule here could disagree with the payload about which projects are in
    the set -- which is the one thing these rows exist to make consistent.
    """
    if not is_workspace_scan(model):
        return []
    return list(model.workspace.skipped_projects)


def skipped_project_detail(entry: SkippedProject) -> str:
    """One line naming the project, the reason, and the explanation.

    The reason is always present, because the two reasons must not read the same:
    a ``no-changes`` skip is a successful optimisation and an ``error`` skip is a
    project the operator asked for that was never looked at. A row saying only
    "skipped" collapses them, and an operator cannot then tell a fast clean run
    from a run that quietly examined nothing.

    The detail is appended when there is one and omitted when there is not, rather
    than rendered as an empty tail -- ``skip_detail`` is optional, and "``: ``"
    with nothing after it reads as a truncated message.
    """
    text = f"Project '{entry.project}' was not scanned ({entry.reason.value})"
    if entry.detail:
        return f"{text}: {entry.detail}"
    return text
