# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The workspace-mode exit-code contract and the skipped-projects payload.

Why this module exists
----------------------
A workspace scan can fail in ways a single-directory scan cannot: the workspace
definition itself can be malformed, one project's config can be invalid while
the others are fine, and a project can be skipped without that being a failure
at all. Callers -- CI jobs above all -- need to tell those apart from the
process exit status alone, before they have any output to parse. Modelling the
contract in one place means the CLI, the MCP server and the aggregator cannot
each invent their own numbering.

The contract
------------
Workspace mode EXTENDS the published ``ASH_EXIT_CODES`` rather than
reinterpreting any of it, so a caller that understands single-project ASH does
not have to relearn the first four codes:

* ``0`` success.
* ``1`` scan errors / scanner failures. A workspace-mode internal error -- ASH
  itself failed and reached no verdict -- is a case of this.
* ``2`` actionable findings at or above threshold. Workspace mode uses this for
  exactly that: a project exceeded its effective threshold, consistently with
  single-project mode.
* ``3`` invalid config or refused input. A project's own config being unusable is
  a case of this.
* ``4`` workspace definition or policy error -- the workspace file, a project
  path, or a workspace-level policy is not usable. NOTHING WAS SCANNED.

Codes 3 and 4 are both configuration problems and the split is deliberate: 4
means the operator's workspace file is wrong and no project could run, 3 means
one project is misconfigured. They route to different people.

Why 4, when the RFC's table said 2
----------------------------------
This is a deliberate deviation from the RFC, not a transcription error.

The RFC assigned "workspace definition or policy error" to exit code 2. But 2
was already published, in
``automated_security_helper.core.constants.ASH_EXIT_CODES``, as "actionable
findings at or above threshold" -- exposed as an MCP resource and pinned by
``tests/unit/cli/mcp/test_exit_codes_resource.py``. It is also the ordinary,
expected result of a scan that worked: ``_compute_exit_code`` in
``run_ash_scan`` returns 2 whenever there are actionable findings.

Overloading it would make two opposite outcomes indistinguishable. A malformed
workspace file means NOTHING WAS SCANNED; exit 2 means a scan completed and
found things worth reviewing. A CI job treating 2 as "review the findings"
would read a workspace that never ran as a successful scan with issues -- a
fail-open failure, and precisely the mode the RFC's own failure-semantics
section exists to reject, by the same argument it uses against "warn and skip"
for a missing project.

Extending the contract with an unused code keeps both meanings unambiguous and
breaks no existing consumer. Code 4 was confirmed unused across the package,
the scripts, the tests and the CI workflows before it was chosen.

``tests/unit/models/test_workspace_models.py`` asserts there is NO collision --
every value here agrees semantically with ``ASH_EXIT_CODES`` -- so changing
either side fails the suite.

One rejected alternative is worth naming, because a field survives from it.
Leaving the collision in place and disambiguating out of band -- via a status
field in the payload, and via the fact that a refused workspace writes no
results file -- does work, but it makes a consumer parse output before it can
interpret the status, and an exit code exists to be readable before that.
``WorkspaceResults.status`` remains as ordinary metadata: it still says plainly
whether any project ran, but nothing depends on it to tell two exit codes apart.

Note that ASH_EXIT_CODES' own code 1 is partly aspirational: a scanner at ERROR
does not produce exit 1 today, because ``_compute_exit_code`` returns 1 only
when ``results is None``. That happens to make it a good match for a
workspace-mode internal error.

The skipped-projects payload
----------------------------
``SkippedProject`` is one entry of ``workspace.skipped_projects``; the payload
is a list of them. The reason distinguishes an error skip from a ``no-changes``
skip, which matters because they mean opposite things: ``no-changes`` is a
successful optimisation and must not colour the exit status, while ``error``
means a project the operator asked for was not scanned. Collapsing the two
would let a broken project masquerade as an unchanged one -- a silent
false-negative in a security tool, which is the failure mode most worth
designing against.

The results payload
-------------------
``WorkspaceResults`` is what a workspace scan writes into
``ash_aggregated_results.json`` under the ``workspace`` key, and
``workspace_exit_code`` derives the process status from it. ``status`` says
whether any project ran -- ``"refused"`` when the definition or a
workspace-level policy was rejected, ``"completed"`` otherwise -- and
``refusal_detail`` carries the reason for a refusal. Both are ordinary metadata:
useful for a consumer that has the file open, not load-bearing for reading the
exit status, which stands on its own.

Precedence in ``workspace_exit_code``, and why it runs in this order
-------------------------------------------------------------------
``INVALID_PROJECT_CONFIG`` (3) > ``INTERNAL_ERROR`` (1) >
``ACTIONABLE_FINDINGS`` (2) > ``SUCCESS`` (0).

The same order as a single-directory scan, whose ``_compute_exit_code`` runs the
completeness pass before the threshold count: a workspace with an incomplete or
failed project exits 1 even when another project has findings. A gate told "2,
clear these and you are done" is misled when part of the scan measured nothing,
and with ``ash --source-dir P`` and P inside a workspace giving different answers
for the same project, neither could be read on its own.

What was rejected: findings above the unknown (2 > 1), which this module used
until 2026-10. Its reasoning was that a CI gate treating 1 as retryable
infrastructure trouble would retry a workspace with real findings and never block
on them, and that one project's absent tool should not hide another's findings.
Both still describe a gate that reads only the exit code. The findings are not
hidden: every project's ``exceeds_threshold`` and finding counts stay in the
payload and in every reporter, and a gate that must block on findings whatever
else happened reads them there. The ordering was chosen for parity with
single-directory mode.

3 stays above both because it is blocking and names one misconfigured project:
a more specific diagnosis, actionable by one person.

``INTERNAL_ERROR`` has two inputs, not one. A project that failed outright is
one; a project that completed with a scanner at ERROR or MISSING is the other,
carried on ``WorkspaceProjectResult.scan_incomplete``. They share a code because
they are the same kind of news -- neither says whether the code is clean -- and
because collapsing "we could not run it" into 0 is what let a workspace report a
project clean while ``ash --source-dir P`` on the same project exited 1.

``WORKSPACE_ERROR`` (4) does not appear in that ordering because it is not a
verdict over projects. It is returned when nothing was attempted at all, and
raised as ``WorkspaceDefinitionError`` before execution starts in every other
case.

A tolerated skip never colours the status
-----------------------------------------
A skip recorded by *resolution* -- a missing project tolerated under
``--allow-missing-projects`` (an ``ERROR`` skip), or a project with no changed
files (a ``NO_CHANGES`` skip) -- does not affect the status, whatever its
siblings did. Failing on the former would make the flag mean nothing, and
failing on the latter would make the optimisation useless. The project skipped
by ERROR is reported in the results payload, not in the exit code. A project that
fails during *execution* is ``FAILED``, not skipped, and does affect the status.

So when no project completed or failed, the ERROR skips are set aside and what
is left decides:

* A ``NO_CHANGES`` skip is left -- ASH asked git what changed in that project
  and git said nothing. Exit 0. This is the ordinary outcome of a precommit
  hook in a monorepo when the edit landed outside every project directory, and
  single-project mode exits 0 for exactly that case. It stays 0 when an
  optional project is also absent: a hook that exits 4 on every commit touching
  no project, and 0 on commits that do, would be worse than not having the
  optimisation.
* No ``NO_CHANGES`` skip is left -- the definition named no project, or every
  project it named was missing. Exit 4, because exiting 0 would report a clean
  result for code nothing examined.

Only a ``NO_CHANGES`` skip counts as examined, by identity. The model admits a
``SKIPPED`` entry with no ``skip_reason`` (``as_skipped_project`` leaves it out
of the payload), and a gate must not read an unexpected state as a pass: such an
entry neither counts as examined nor is set aside, so a run of only such entries
exits 4. A test written as "any entry whose reason is not ERROR" read that entry
as examined and exited 0.

History: before 2026-10-29 22:51Z the branch read ``entries and all(skip_reason is
NO_CHANGES)``, so one unchanged project beside a tolerated missing one exited 4
("nothing was scanned at all"); that rule was in force until the change that
introduced the set-aside, and is recorded for review.
"""

from __future__ import annotations

from enum import Enum, IntEnum
from typing import Annotated, Any, Dict, Iterable, List, Literal, Optional, Tuple

from pydantic import Field, PrivateAttr, computed_field

from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from automated_security_helper.utils.undecodable_text import RecordModel

from automated_security_helper.models.core import IgnoreFileExclusions


class WorkspaceExitCode(IntEnum):
    """Process exit statuses for a workspace-mode scan.

    An IntEnum so members can be handed straight to ``typer.Exit`` or
    ``sys.exit`` without conversion at the call site.

    Every value agrees with ``ASH_EXIT_CODES``; only ``WORKSPACE_ERROR`` is new.
    ``USAGE_ERROR`` is the CLI-wide code for a refused command line, listed here
    because a workspace-mode invocation can exit with it too.
    ``ACTIONABLE_FINDINGS`` is modelled here rather than left as a bare literal
    because workspace mode really does return it -- a project over its
    effective threshold -- and a call site should not have to hardcode 2.

    See the module docstring for why WORKSPACE_ERROR is 4 and not the 2 the RFC
    table assigned.
    """

    SUCCESS = 0
    INTERNAL_ERROR = 1
    ACTIONABLE_FINDINGS = 2
    INVALID_PROJECT_CONFIG = 3
    WORKSPACE_ERROR = 4
    # Not a verdict over projects either: the command line was refused before any
    # workspace was resolved. Taken from ASH_EXIT_CODES' own name, so the number
    # is defined once.
    USAGE_ERROR = ASH_EXIT_USAGE_ERROR


# Descriptions keyed by code, mirroring the shape of ASH_EXIT_CODES so the MCP
# resource can serialise either table the same way. The wording matches
# ASH_EXIT_CODES for every shared code, because they are the same codes --
# not a parallel vocabulary for them.
WORKSPACE_EXIT_CODES: Dict[int, str] = {
    WorkspaceExitCode.SUCCESS.value: "success",
    WorkspaceExitCode.INTERNAL_ERROR.value: "scan errors / scanner failures",
    WorkspaceExitCode.ACTIONABLE_FINDINGS.value: (
        "actionable findings at or above threshold"
    ),
    WorkspaceExitCode.INVALID_PROJECT_CONFIG.value: "invalid config or refused input",
    WorkspaceExitCode.WORKSPACE_ERROR.value: "workspace definition or policy error",
    WorkspaceExitCode.USAGE_ERROR.value: "usage error",
}


class SkippedProjectReason(str, Enum):
    """Why a project in the workspace was not scanned.

    The distinction is load-bearing: ``NO_CHANGES`` is a successful
    optimisation, ``ERROR`` is a project the operator asked for that did not
    run and that ``--allow-missing-projects`` tolerated. Neither colours the
    exit status; see "A tolerated skip never colours the status" in the module
    docstring for what decides when nothing was attempted.
    """

    NO_CHANGES = "no-changes"
    ERROR = "error"

    @property
    def is_error(self) -> bool:
        """True when the skip represents a failure rather than an optimisation."""
        return self is SkippedProjectReason.ERROR


class SkippedProject(RecordModel):
    """One entry of the ``workspace.skipped_projects`` payload."""

    project: Annotated[
        str,
        Field(
            ...,
            min_length=1,
            description=(
                "Workspace-relative path of the skipped project, which is also "
                "the key it is attributed under elsewhere in the results."
            ),
        ),
    ]
    reason: Annotated[
        SkippedProjectReason,
        Field(
            ..., description="Whether the project was skipped by error or as unchanged"
        ),
    ]
    detail: Annotated[
        Optional[str],
        Field(
            None,
            description="(Optional) Human-readable explanation of the skip",
        ),
    ] = None

    @property
    def is_error(self) -> bool:
        """True when this skip represents a failure rather than an optimisation."""
        return self.reason.is_error


class ProjectRunStatus(str, Enum):
    """What became of one project once execution started.

    ``SKIPPED`` covers both skip reasons and carries ``skip_reason`` to say
    which; ``FAILED`` is reserved for a project that was attempted and produced
    no verdict, which is the only one of the three that fails the workspace.
    """

    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"


class ProjectInputNotScanned(RecordModel):
    """One input a project's scanner found and did not scan, and why."""

    scanner: Annotated[str, Field(..., min_length=1, description="The scanner.")]
    path: Annotated[
        str,
        Field(
            ...,
            description=(
                "The input's workspace-relative path, '/' separated: the project's "
                "relative_path joined to the path the scanner recorded."
            ),
        ),
    ]
    reason: Annotated[str, Field(..., description="Why the scanner did not scan it.")]


class ProjectConverterRefusal(RecordModel):
    """One input a project's converter did not read or could not convert, and why.

    The record ``utils/converter_refusals.py`` builds from a single scan's
    ``converter_results`` rows, carried into the workspace results with the input's
    path made workspace-relative. The unified file holds no per-project converter
    rows (its ``converter_results`` is empty by design, because two projects run
    converters of the same name over paths relative to their own trees), so without
    this list the merged summaries could say that a project's conversion was
    incomplete and never which input went unconverted. ``scan_incomplete`` is the
    completeness gate's own reading of the record: an archive refused over an
    extraction limit, or a failed input no suppression accepted.
    """

    converter: Annotated[str, Field(..., min_length=1, description="The converter.")]
    path: Annotated[
        str,
        Field(
            ...,
            description=(
                "The input's workspace-relative path, '/' separated: the project's "
                "relative_path joined to the path the converter recorded, or the "
                "recorded path itself when the converter could only record it as "
                "absolute."
            ),
        ),
    ]
    member: Annotated[
        Optional[str],
        Field(None, description="The archive member refused, when one was."),
    ] = None
    reason: Annotated[str, Field(..., description="Why the converter did not read it.")]
    limit: Annotated[
        Optional[str],
        Field(
            None,
            description="The extraction limit an archive was refused over, when one was.",
        ),
    ] = None
    failed: Annotated[
        bool,
        Field(
            False,
            description=(
                "Whether this is a failed_inputs record (an input the converter "
                "could not convert) rather than a refused_inputs one."
            ),
        ),
    ] = False
    accepted: Annotated[
        bool,
        Field(
            False,
            description=(
                "Whether a suppression accepted this failed input, so the "
                "completeness gate waives it."
            ),
        ),
    ] = False
    scan_incomplete: Annotated[
        bool,
        Field(
            False,
            description=(
                "Whether the completeness gate counts this record: an archive "
                "refused over an extraction limit, or a failed input no suppression "
                "accepted."
            ),
        ),
    ] = False
    unlisted_members: Annotated[
        Optional[int],
        Field(
            None,
            ge=0,
            description="How many more members of the archive the record stands for.",
        ),
    ] = None


#: The code a scanner's rolled-up entry reads when its project's row recorded none and
#: the scanner did not complete: it produced no target report, so ``exit_code`` was
#: never set on the row. ASH's own stand-in for a run that did not complete (the
#: incomplete-run member of the judged codes), never the default 0 of an unset field
#: and never a tool's own exit. A SKIPPED scanner is a complete outcome and does not
#: read it.
SCANNER_EXIT_CODE_UNRECORDED = 125


class WorkspaceProjectResult(RecordModel):
    """One project's outcome, as it appears in the aggregated results."""

    # A refused value is not quoted in the error's text, as for the aggregated
    # results' other models (asharp_model.py).
    model_config = {"extra": "allow", "hide_input_in_errors": True}

    project: Annotated[
        str,
        Field(
            ...,
            min_length=1,
            description=(
                "The project key -- its workspace-relative path with separators "
                "replaced by dashes. Every other attribution in the results "
                "joins on this."
            ),
        ),
    ]
    relative_path: Annotated[
        str,
        Field(
            ...,
            min_length=1,
            description=(
                "The project's workspace-relative path, forward-slash separated. "
                "The coordinate system workspace-relative finding paths live in."
            ),
        ),
    ]
    display_label: Annotated[
        str,
        Field(..., min_length=1, description="What a human reads. Not unique."),
    ]
    status: Annotated[
        ProjectRunStatus,
        Field(
            ..., description="Whether the project completed, was skipped, or failed."
        ),
    ]
    severity_threshold: Annotated[
        Optional[str],
        Field(
            None,
            description=(
                "The threshold this project's verdict was judged against. Null "
                "for a project that never ran."
            ),
        ),
    ] = None
    scanner_thresholds: Annotated[
        Dict[str, str],
        Field(
            default_factory=dict,
            description=(
                "Per scanner name (as properties.scanner_name records it), the "
                "threshold the verdict graded that scanner's findings by when it "
                "is the scanner's own options.severity_threshold, with the "
                "workspace ceiling folded in; a scanner not listed was graded by "
                "severity_threshold. The unified results carry no ash_config, so "
                "a reader that regrades a finding (the merged reporters, the MCP "
                "result filters) has no other source for the scanner's gate and "
                "judged every project at ASH's default. A scanner whose own "
                "threshold the scan read from an environment variable is not "
                "listed either: the environment's value is not published here, "
                "as no report surface prints it, so a reader grades that scanner "
                "by severity_threshold; its name is in "
                "withheld_scanner_thresholds, so the reader can tell that grade "
                "from the verdict's. Empty in a workspace file written before "
                "the field existed."
            ),
        ),
    ]
    withheld_scanner_thresholds: Annotated[
        List[str],
        Field(
            default_factory=list,
            description=(
                "The scanners (as properties.scanner_name records them) whose own "
                "threshold the verdict graded by but whose value is withheld from "
                "scanner_thresholds because the scan read it from an environment "
                "variable. The names only, never the values. A reader that "
                "regrades a finding of such a scanner (threshold_for_scanner "
                "answers severity_threshold for it) is told here that the "
                "verdict's gate was another, undisclosed one, so it can defer to "
                "the carried actionable counts or flag the finding instead of "
                "silently grading it by the project gate. Empty when no threshold "
                "was withheld, and in a workspace file written before the field "
                "existed."
            ),
        ),
    ]
    finding_count: Annotated[
        int,
        Field(0, ge=0, description="Unsuppressed findings reported for the project."),
    ] = 0
    actionable_finding_count: Annotated[
        int,
        Field(
            0,
            ge=0,
            description=(
                "Findings at or above this project's own effective threshold."
            ),
        ),
    ] = 0
    policy_origin_finding_count: Annotated[
        int,
        Field(
            0,
            ge=0,
            description=(
                "How many of this project's unsuppressed findings came from a "
                "scanner only `workspace.additional_scanners` asked for, rather "
                "than one the project enables itself. Those findings carry "
                "`properties.origin: workspace-policy`, and unless "
                "`policy_scanners_gate` is set they are excluded from "
                "actionable_finding_count and cannot fail the project. A count "
                "of its own because that is what makes them 'reported "
                "separately': comparing finding_count against "
                "actionable_finding_count cannot tell a finding the policy "
                "contributed from one the severity threshold excluded."
            ),
        ),
    ] = 0
    policy_scanners_gate: Annotated[
        Optional[bool],
        Field(
            None,
            description=(
                "Whether findings from scanners only `workspace.additional_scanners` "
                "asked for decided this project's verdict (the policy's "
                "policy_scanners_gate, as the plan applied it). False means a "
                "policy-origin finding is reported and excluded from "
                "actionable_finding_count; a reader that regrades findings (the "
                "merged JUnit report, the MCP result filters) reads this to grade "
                "such a finding as the verdict did instead of as a failure. The "
                "executor always records True or False. None (absent) means a "
                "workspace file written before the field existed; such a file's "
                "verdict applied the gate, so a reader treats None as gating and "
                "grades a policy-origin finding by the threshold, the fail-closed "
                "side."
            ),
        ),
    ] = None
    exceeds_threshold: Annotated[
        bool,
        Field(
            False,
            description=(
                "Whether this project's own verdict is a failure. Stored rather "
                "than derived from actionable_finding_count because "
                "fail_on_findings can be off, in which case a project has "
                "actionable findings and still passes."
            ),
        ),
    ] = False
    duration_seconds: Annotated[
        float, Field(0.0, ge=0.0, description="Wall clock spent on this project.")
    ] = 0.0
    output_path: Annotated[
        str,
        Field(
            ...,
            min_length=1,
            description=(
                "Where this project's own subtree lives, relative to the "
                "workspace output directory."
            ),
        ),
    ]
    sarif_run_index: Annotated[
        Optional[int],
        Field(
            None,
            ge=0,
            description=(
                "Index of this project's run in the aggregated SARIF, so a "
                "consumer can extract one project by selecting a run. Null when "
                "the project contributed no run."
            ),
        ),
    ] = None
    scanners: Annotated[
        Dict[str, str],
        Field(
            default_factory=dict,
            description="Final status per scanner name, for this project alone.",
        ),
    ]
    scanner_reasons: Annotated[
        Dict[str, str],
        Field(
            default_factory=dict,
            # Carried in-process from the project run to the workspace rollup
            # (WorkspaceAggregator.add) and never dumped: the rolled-up
            # scanner_results entry is the public surface, so this map is not a
            # second copy of it in every project block.
            exclude=True,
            description=(
                "Why each SKIPPED, MISSING or ERROR scanner gave no result, for "
                "this project alone: a SKIPPED or MISSING row's skipped_reason or "
                "missing_reason, and the first error an ERROR scanner's reports "
                "recorded, such as a constructor that raised. A scanner that ran, "
                "or that recorded no reason, is not listed. Empty in a workspace "
                "file written before the field existed."
            ),
        ),
    ]
    incomplete_scanners: Annotated[
        List[str],
        Field(
            default_factory=list,
            description=(
                "Scanners this project was asked to run that did not complete -- "
                "ERROR or MISSING. Populated whether or not the completeness gate "
                "is on, because an operator who turned the gate off has accepted "
                "the risk and has not asked to be told the scan was complete. Read "
                "through the unified metrics rather than off `scanners`, so a "
                "scanner the operator excluded on a host that also lacks its tool "
                "reads SKIPPED here rather than MISSING. A scanner listed only for "
                "a stale content database is not here; see stale_content_databases."
            ),
        ),
    ]
    incomplete_scanner_details: Annotated[
        Dict[str, str],
        Field(
            default_factory=dict,
            description=(
                "Each incomplete scanner's display status as the completeness "
                "gate reports it -- the bare status, or the status followed by "
                "the unevaluated-target counts for a partial audit. Keyed by the "
                "names in incomplete_scanners; empty in results files written "
                "before the field existed, where a reader falls back to the "
                "status."
            ),
        ),
    ]
    partial_coverage_scanners: Annotated[
        List[str],
        Field(
            default_factory=list,
            description=(
                "The incomplete scanners whose recorded counts show a partial "
                "audit (some targets evaluated, some not), whatever status the "
                "writer graded. A coverage row for one carries the reason "
                "partial_coverage rather than its status token. Empty in results "
                "files written before the field existed."
            ),
        ),
    ]
    stale_content_databases: Annotated[
        List[Dict[str, Any]],
        Field(
            default_factory=list,
            description=(
                "Content databases past their declared age bound under "
                "content_db_staleness: fail, each as the single-scan MCP payload "
                "reports it. A stale database fails the project (scan_incomplete) "
                "whatever fail_on_incomplete_scanners says."
            ),
        ),
    ]
    unevaluated_rules: Annotated[
        List[str],
        Field(
            default_factory=list,
            description=(
                "Rules a scanner reported, at run level, that it could not "
                "evaluate, as the single-scan payload's unevaluated_rules lists "
                "them. A rule here fails the project (scan_incomplete) whatever "
                "fail_on_incomplete_scanners says: `ash --source-dir P` exits 1 on "
                "it, because the scan reports nothing about compliance with that "
                "rule. Empty in a workspace file written before the field existed."
            ),
        ),
    ]
    unstoppable_tools: Annotated[
        Dict[str, str],
        Field(
            default_factory=dict,
            description=(
                "Scanner name to reason, for each scanner whose run ended with a "
                "tool ASH could not stop, as the single-scan payload's "
                "could_not_stop rows record it. Such a tool may still write into "
                "the project's output after the verdict read it, so the project "
                "fails (scan_incomplete) whatever fail_on_incomplete_scanners "
                "says, as `ash --source-dir P` does. Empty in a workspace file "
                "written before the field existed."
            ),
        ),
    ]
    inputs_not_scanned: Annotated[
        List[ProjectInputNotScanned],
        Field(
            default_factory=list,
            description=(
                "Every input one of this project's scanners found and did not scan "
                "(an offline npm-audit's lockfiles, for instance), with the reason. "
                "The project's own results list them per target; the workspace "
                "results carry no per-target reports, so they are repeated here, "
                "for the merged summaries and the console. A scanner's status "
                "cannot say which input it skipped."
            ),
        ),
    ]
    no_scanner_ran: Annotated[
        bool,
        Field(
            False,
            description=(
                "Whether this project recorded scanners and not one of them reached "
                "a verdict -- every entry SKIPPED. A separate fact from "
                "incomplete_scanners rather than a member of it, because SKIPPED has "
                "to be tolerated one entry at a time: it is how --exclude-scanners "
                "and another shard's ownership are recorded. So the per-entry list "
                "is empty here while the project measured nothing. False for a "
                "project that recorded no scanners at all, which is what a "
                "convert-only run legitimately produces. Populated whether or not "
                "the completeness gate is on, for the same reason "
                "incomplete_scanners is."
            ),
        ),
    ] = False
    incomplete_converters: Annotated[
        Dict[str, str],
        Field(
            default_factory=dict,
            description=(
                "Converter name to reason, for each converter of this project that "
                "lost coverage: it crashed, could not convert some of its inputs, "
                "or its tool was absent with inputs to convert. The same rows "
                "`ash --source-dir P` fails on. Populated whether or not the "
                "completeness gate is on, for the same reason incomplete_scanners is."
            ),
        ),
    ]
    converter_refusals: Annotated[
        List[ProjectConverterRefusal],
        Field(
            default_factory=list,
            description=(
                "Every input one of this project's converters did not read or "
                "could not convert, as the project's own converter_results rows "
                "record them (refused_inputs and failed_inputs), with the input's "
                "path made workspace-relative. incomplete_converters names the "
                "converter and a summary reason; this names each input, so the "
                "merged summaries and the workspace table can say what went "
                "unconverted. Empty in a workspace file written before the field "
                "existed."
            ),
        ),
    ]
    scan_incomplete: Annotated[
        bool,
        Field(
            False,
            description=(
                "Whether the completeness facts above fail this project -- the "
                "incomplete scanners or converters it names, or having run no "
                "scanner at all. "
                "Stored rather than derived from them for the same reason "
                "exceeds_threshold is: fail_on_incomplete_scanners can be off, in "
                "which case a project has scanners that did not run and still "
                "passes. Always true for an unevaluated rule or a tool ASH could "
                "not stop: no setting silences those in `ash --source-dir P` "
                "either. A stale content database under a fail policy fails the "
                "project too, except when its scanner is one only the workspace "
                "policy added and policy_scanners_gate is off: then it is still "
                "listed in stale_content_databases but does not decide this flag, "
                "as that scanner's MISSING tool does not."
            ),
        ),
    ] = False
    ceiling_unreachable_findings: Annotated[
        Dict[str, int],
        Field(
            default_factory=dict,
            description=(
                "Per scanner, how many of this project's findings the workspace "
                "severity ceiling could not affect, because they carry no "
                "properties.issue_severity and are therefore judged from the "
                "SARIF level -- where `error` is read as critical and so is "
                "actionable at every threshold. Populated only when the ceiling "
                "actually tightened this project AND some of its findings were "
                "beyond that tightening's reach, so an empty mapping means the "
                "ceiling did what it says. An observation about these findings, "
                "not a claim about the scanner: it is recomputed every scan, so "
                "it stops appearing if a scanner starts emitting severity."
            ),
        ),
    ]
    ignore_file_exclusions: Annotated[
        Optional[IgnoreFileExclusions],
        Field(
            None,
            description=(
                "The project's own metadata.ignore_file_exclusions: whether its "
                ".gitignore and .ignore files were honored and how many files they "
                "removed from its scan set, keyed by path relative to the project. "
                "Null for a project that built no scan set (skipped, or failed "
                "before scanning)."
            ),
        ),
    ] = None
    skip_reason: Annotated[
        Optional[SkippedProjectReason],
        Field(None, description="Why the project was skipped, when it was."),
    ] = None
    skip_detail: Annotated[
        Optional[str],
        Field(None, description="Human-readable explanation of the skip."),
    ] = None
    error: Annotated[
        Optional[str],
        Field(None, description="What went wrong, for a FAILED project."),
    ] = None
    invalid_config: Annotated[
        bool,
        Field(
            False,
            description=(
                "Whether the failure was this project's own configuration. "
                "Separated from a general failure because it selects exit code "
                "3 rather than 1, and those route to different people."
            ),
        ),
    ] = False

    def threshold_for_scanner(self, scanner: Optional[str]) -> Optional[str]:
        """The threshold this project's verdict graded *scanner*'s findings by.

        The scanner's own entry in ``scanner_thresholds`` when it has one, else
        ``severity_threshold``: the same resolution the verdict made per finding
        (``aggregation.actionable_results_by_scanner`` with the project's scanner
        resolver). ``None`` for a project that never ran. Readers that regrade a
        finding attributed to this project call this instead of reading one of
        the two fields, so they cannot pick the project gate for a scanner the
        verdict judged by its own.

        One answer is knowingly not the verdict's: a scanner whose own threshold
        the scan read from an environment variable has no entry (the value is
        withheld) and answers ``severity_threshold`` here, as it always did.
        :meth:`scanner_threshold_is_withheld` says when that is so, and a reader
        that would otherwise grade such a finding by the project gate can defer
        to the carried actionable counts or flag it instead.
        """
        if scanner and scanner in self.scanner_thresholds:
            return self.scanner_thresholds[scanner]
        return self.severity_threshold

    def scanner_threshold_is_withheld(self, scanner: Optional[str]) -> bool:
        """Whether *scanner*'s own threshold graded the verdict but is withheld.

        True for a scanner named in ``withheld_scanner_thresholds``: the scan
        read its threshold from an environment variable, the value is not
        published, and :meth:`threshold_for_scanner` answers the project gate for
        it, which is not the gate the verdict used.
        """
        return bool(scanner) and scanner in self.withheld_scanner_thresholds

    def as_skipped_project(self) -> Optional[SkippedProject]:
        """This project as a ``skipped_projects`` payload entry, or None."""
        if self.status is not ProjectRunStatus.SKIPPED or self.skip_reason is None:
            return None
        return SkippedProject(
            project=self.project,
            reason=self.skip_reason,
            detail=self.skip_detail,
        )

    # Carried in-process from the project run to the workspace rollup
    # (WorkspaceAggregator.add) and never serialized: the rolled-up
    # scanner_results entry is the public surface. A private attribute, not a
    # field, because a declared field is listed in the published results schema
    # even when it is excluded from dumps.
    _scanner_exit_codes: Dict[str, Optional[int]] = PrivateAttr(default_factory=dict)

    def carry_scanner_exit_codes(self, codes: Dict[str, Optional[int]]) -> None:
        """Record the exit code each scanner's row recorded for this project.

        Read from the same row as the status in ``scanners``. A scanner that did not
        finish and whose row recorded none reads ``SCANNER_EXIT_CODE_UNRECORDED``; a
        skipped scanner whose row recorded none reads what its own row carries
        (``None``). Set after construction: a constructor argument is not accepted
        into it.
        """
        self._scanner_exit_codes = dict(codes)

    @property
    def carried_scanner_exit_codes(self) -> Dict[str, Optional[int]]:
        """The codes :meth:`carry_scanner_exit_codes` recorded; empty when none were."""
        return self._scanner_exit_codes

    # Carried the same way: the per-scanner split of actionable_finding_count,
    # graded by each scanner's own threshold and over the same findings the
    # verdict saw, so the rollup sums what the verdict counted instead of
    # re-deriving it from the run against one threshold. None, not empty, when
    # the outcome was built without it, so the rollup can tell "nothing carried"
    # from "every scanner counted zero".
    _scanner_actionable_counts: Optional[Dict[str, int]] = PrivateAttr(default=None)

    def carry_scanner_actionable_counts(self, counts: Dict[str, int]) -> None:
        """Record how actionable_finding_count splits across this project's scanners.

        Keyed as ``properties.scanner_name`` records the scanner, with the
        aggregator's name for a finding that names none. Set after construction,
        as :meth:`carry_scanner_exit_codes` is.
        """
        self._scanner_actionable_counts = dict(counts)

    @property
    def carried_scanner_actionable_counts(self) -> Optional[Dict[str, int]]:
        """The split :meth:`carry_scanner_actionable_counts` recorded; None when none was."""
        return self._scanner_actionable_counts

    # Carried the same way: each scanner row's (excluded, dependencies_satisfied)
    # pair, for the rollup's own two flags. Derived from the rolled-up status
    # instead, an operator-excluded scanner whose tool was also absent read
    # MISSING and not excluded, and a scanner that merely had nothing to scan
    # read excluded.
    _scanner_flags: Dict[str, Tuple[bool, bool]] = PrivateAttr(default_factory=dict)

    def carry_scanner_flags(self, flags: Dict[str, Tuple[bool, bool]]) -> None:
        """Record each scanner row's ``(excluded, dependencies_satisfied)`` for this project."""
        self._scanner_flags = dict(flags)

    @property
    def carried_scanner_flags(self) -> Dict[str, Tuple[bool, bool]]:
        """The pairs :meth:`carry_scanner_flags` recorded; empty when none were."""
        return self._scanner_flags


class WorkspaceResults(RecordModel):
    """Everything a workspace scan concluded, keyed under ``workspace``."""

    model_config = {"extra": "allow"}

    workspace_file: Annotated[
        str,
        Field(
            ..., min_length=1, description="Absolute path of the workspace definition."
        ),
    ]
    workspace_root: Annotated[
        str,
        Field(
            ...,
            min_length=1,
            description=(
                "Absolute path of the directory holding it. Every "
                "workspace-relative finding path is relative to this, and in "
                "container mode this is what was mounted at /src."
            ),
        ),
    ]
    status: Annotated[
        Literal["completed", "refused"],
        Field(
            "completed",
            description=(
                "Whether projects were scanned at all. The discriminator for the "
                "code-2 collision -- see the module docstring."
            ),
        ),
    ] = "completed"
    exit_code: Annotated[
        int, Field(..., description="The process status this run exited with.")
    ]
    projects: Annotated[
        List[WorkspaceProjectResult],
        Field(
            default_factory=list,
            description="Every project in workspace-file order, skipped ones included.",
        ),
    ]
    max_parallel_projects: Annotated[
        Optional[int],
        Field(None, ge=1, description="The outer concurrency bound this run used."),
    ] = None
    project_timeout: Annotated[
        Optional[float],
        Field(None, gt=0, description="The per-project time budget, when one was set."),
    ] = None
    wall_clock_seconds: Annotated[
        float, Field(0.0, ge=0.0, description="Wall clock for the whole workspace.")
    ] = 0.0
    unconvertible_finding_paths: Annotated[
        int,
        Field(
            0,
            ge=0,
            description=(
                "Number of findings that could not be given a workspace-relative "
                "path, because every location they offered was absolute and "
                "outside the project or traversed upward. One per finding, not "
                "per location. Counted rather than dropped: dropping a finding "
                "because its path is awkward is a silent false negative."
            ),
        ),
    ] = 0

    refusal_detail: Annotated[
        Optional[str],
        Field(
            None,
            description=(
                "Why the workspace was refused, for status='refused'. Null for a "
                "run that scanned anything."
            ),
        ),
    ] = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def skipped_projects(self) -> List[SkippedProject]:
        """The Phase 0 ``skipped_projects`` payload, derived from the projects.

        Derived rather than stored so the two cannot disagree, and a
        ``computed_field`` so it serialises -- a downstream consumer must be able
        to see that a project was dropped, and cannot read stderr.
        """
        entries = (project.as_skipped_project() for project in self.projects)
        return [entry for entry in entries if entry is not None]


def is_workspace_scan(model: Any) -> bool:
    """Whether *model* is the result of a workspace scan rather than one directory.

    The single discriminator every reporter uses to decide whether to emit
    workspace attribution. ``model.workspace`` is ``None`` for a single-directory
    scan, which is the contract ``AshAggregatedResults.workspace`` documents.

    Checked with ``isinstance`` rather than ``is not None``, and that is not
    defensiveness. Reporters are widely tested against ``MagicMock`` models, where
    ``getattr(model, "workspace")`` returns a truthy ``Mock`` -- so a truthiness
    test silently reads every mocked single-directory scan as a workspace one. The
    observable symptom was a ``KeyError`` on a column that had been added to a
    header but not to the rows, which is a loud failure; the same weakness in a
    reporter that tolerates a missing key would instead have added an empty
    project column to real single-directory output and gone unnoticed.
    """
    return workspace_of(model) is not None


def workspace_of(model: Any) -> Optional[WorkspaceResults]:
    """*model*'s workspace block, or ``None`` for a single-directory scan.

    The same test as :func:`is_workspace_scan`, returned as the value rather than
    as a bool, so a caller that goes on to read the block gets a type checker
    that knows it is not ``None``. ``if is_workspace_scan(model):`` followed by
    ``model.workspace.<attr>`` is correct at runtime but reads to mypy as a
    dereference of ``WorkspaceResults | None``, because a ``bool`` return carries
    no narrowing. Same ``isinstance`` rule, for the same ``MagicMock`` reason.
    """
    workspace = getattr(model, "workspace", None)
    if isinstance(workspace, WorkspaceResults):
        return workspace
    return None


def workspace_exit_code(
    projects: Iterable[WorkspaceProjectResult],
) -> WorkspaceExitCode:
    """Derive the process status from the per-project outcomes.

    See "Precedence" in the module docstring for the ordering and its rationale.

    Args:
        projects: Every project in the run, skipped ones included.

    Returns:
        The contract code, always as an enum member rather than a literal, so
        that a future renumbering cannot leave a stale integer behind. Never
        returns ``WORKSPACE_ERROR`` except for the nothing-was-attempted case;
        every other definition or policy failure is raised before execution.
    """
    entries = list(projects)

    completed = [
        entry for entry in entries if entry.status is ProjectRunStatus.COMPLETED
    ]
    failed = [entry for entry in entries if entry.status is ProjectRunStatus.FAILED]

    if not completed and not failed:
        # Nothing was attempted. A resolution-time ERROR skip (a missing project
        # --allow-missing-projects tolerated) never colours the status, whatever
        # its siblings did, so those are set aside first; the project is reported
        # in the payload, not in the exit code. See "A tolerated skip never
        # colours the status" in the module docstring.
        #
        # What counts as examined is a NO_CHANGES skip, and only that: ASH asked
        # git what changed in that project and git said nothing. That is a
        # successful no-op, the ordinary outcome of a precommit hook in a
        # monorepo where the edit landed outside every project directory, and
        # single-project mode exits 0 for exactly this case. It stays 0 beside
        # an absent optional project: a hook that exits 4 on every commit
        # touching no project and 0 on commits that do would be worse than not
        # having the optimisation.
        #
        # The test is for NO_CHANGES by identity, not for "not ERROR": the
        # model admits a SKIPPED entry with no skip_reason at all, and a gate
        # must not turn an unexpected state into a pass. Such an entry is
        # neither examined nor set aside, so it decides nothing on its own and
        # a run of only such entries exits 4.
        #
        # Nothing examined means no project was named, every project named was
        # missing, or no entry says a project was looked at: exiting 0 would
        # report a clean result for code nothing examined.
        examined = [
            entry
            for entry in entries
            if entry.skip_reason is SkippedProjectReason.NO_CHANGES
        ]
        if examined:
            return WorkspaceExitCode.SUCCESS
        return WorkspaceExitCode.WORKSPACE_ERROR

    if any(entry.invalid_config for entry in failed):
        return WorkspaceExitCode.INVALID_PROJECT_CONFIG
    if failed or any(entry.scan_incomplete for entry in completed):
        # A project that completed with a scanner at ERROR or MISSING belongs
        # here for the same reason a project that failed outright does: neither
        # tells us whether the code is clean.
        #
        # ABOVE ACTIONABLE_FINDINGS, as in single-project mode, whose
        # _compute_exit_code runs the completeness pass before the threshold
        # count and returns 1 when both hold. So `ash --source-dir P` and P
        # inside a workspace give the same answer, and a gate that clears 2 by
        # fixing findings is never told a scan was whole when part of it measured
        # nothing. See "Precedence" in the module docstring for the ordering this
        # replaced.
        #
        # WORKSPACE_ERROR (4) is unreachable from here by construction: this
        # branch requires a completed or failed project, and 4 is the
        # nothing-was-attempted answer.
        return WorkspaceExitCode.INTERNAL_ERROR
    if any(entry.exceeds_threshold for entry in completed):
        # ASH's long-standing "actionable findings" status, with the same meaning
        # it has in single-project mode. Named rather than written as 2, so that
        # renumbering the table cannot silently turn this into another code.
        return WorkspaceExitCode.ACTIONABLE_FINDINGS
    return WorkspaceExitCode.SUCCESS
