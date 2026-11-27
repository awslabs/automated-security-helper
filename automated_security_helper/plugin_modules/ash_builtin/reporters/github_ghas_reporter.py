# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
GitHub Advanced Security (GHAS) SARIF Reporter.

Produces a streamlined SARIF report optimized for GitHub Code Scanning.
Key differences from the generic SARIF reporter:

1. Ensures every rule has `properties["security-severity"]` set — GitHub uses
   this to display severity as Critical/High/Medium/Low instead of raw "Error".
2. Flattens rules from `tool.extensions[]` into `tool.driver.rules` so GitHub
   can reliably resolve rule references.
3. Strips verbose fields (full markdown help, relationships, deprecated fields)
   to reduce file size significantly.
4. Excludes suppressed findings (GitHub has its own dismissal workflow).

Workspace mode: per project, and every run of a multi-run model is emitted
--------------------------------------------------------------------------------
``report()`` used to read ``sarif.runs[0]`` and stop. Against the N-run SARIF a
workspace scan produces, that emitted the first project's findings and dropped
every other project: no exception, no warning, just a smaller file that a
reviewer had no way to tell was incomplete. A security reporter that
under-reports in silence is the worst thing this feature could ship.

The workspace driver declines to invoke this reporter at workspace level and
writes ``projects/<key>/reports/ash.ghas.sarif`` per project instead, each from
that project's own single-run scan, each anchored to that project's own root,
each uploadable on its own; ``tests/unit/workspace/test_workspace_reporting.py``
pins that declaration. But the declaration is not the only way the reporter is
reached: ``ash report --format github-ghas --output-dir <workspace output>``
hands it the unified N-run model directly, and so does any caller that holds
one. For that input every run is read.

GitHub code scanning ingests a SARIF document against *one* repository root and
resolves every result URI relative to it. A workspace is one such root when it is
a monorepo, which is the case an operator reporting over a workspace output
directory is in, so the one-run document this reporter emits for a multi-run
model carries each location in workspace-relative coordinates: the project's
path below the workspace root (``properties.workspace_project_path`` on the
run, which ``workspace/aggregation.py`` stamps) joined with the project-relative
URI, through the same helper the aggregator uses for
``properties.workspace_uri``. A URI that cannot be expressed that way (absolute
and outside its project) is left as the scanner wrote it, which is what the
aggregator does too.

What runs on a frame, and what does not
----------------------------------------
The per-result bookkeeping that is relational runs on a polars frame of one row
per emitted result, a column of rank on the gate's severity ladder, the rule id
and whether the result carries a location: each rule's most severe result (a
group-by minimum), the results kept under GitHub's cap on a run (a stable sort
on rank), the rules a result names kept ahead of those none does (a semi-join
flag and a stable sort) and the rules whose results carry no location (a filter
and a distinct). Every rule id enters a column through ``wire``, because a
scanner's rule id can hold a lone surrogate and a polars string is UTF-8.

Everything else reads one result's nested object and stays Python, because it
is not rows: the kind, suppression and qualified-rule tests (a model's
properties, with a fallback chain at each step), the slim copy of a result and
its locations (per-location URI rebasing against the project's base ids, whose
answer for the first placeable location is the aggregator's own and not
recomputed), the rule table (collisions are decided across components by name
and description, a handful of rows per scanner), the table of base ids and
every log line. The upload itself is done by the caller. The counts of open and
review results are two counters over a scan that has to call ``result_kind``
per result anyway, so a frame would add a copy and remove nothing.
"""

import json
import re
from pathlib import PurePosixPath
from typing import Any, Dict, Iterable, List, Literal, Optional, Tuple, TYPE_CHECKING
from urllib.parse import unquote

from pydantic import Field
from typing_extensions import Annotated

from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.core.report_identity import GHAS_DRIVER_NAME
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    ReporterWorkspaceBehaviour,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin
from automated_security_helper.utils.frame_ops import stable_top
from automated_security_helper.utils.frame_text import unwire, wire, wire_cell
from automated_security_helper.utils.get_ash_version import get_ash_version
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.finding_identity import CORRELATION_ID_PROPERTY
from automated_security_helper.utils.sarif_utils import (
    DEFAULT_RESULT_KIND,
    result_kind,
    result_rule_id,
    result_scanner_name,
    shared_correlation_ids,
    suppressions_in_effect,
)
from automated_security_helper.utils.severity_ladder import (
    SEVERITIES,
    effective_sarif_level,
    result_severity,
)

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults

# GitHub's SARIF upload limits, from "SARIF support for code scanning" (the
# "File compatibility" table, read 2026-10-30): "If any of these objects exceeds
# its maximum value the SARIF file is rejected." Results per run 25,000, rules per
# run 25,000, locations per result 1,000 of which "Only 100 locations will be
# included", tags per rule 20 of which "Only 10 tags will be included". The
# document emitted here stays under every one: locations and tags are cut at what
# GitHub keeps anyway, results past the cap are the least severe ones (GitHub
# itself keeps "the top 5,000 results ... prioritized by severity" of a run) and
# rules no emitted result names are cut first. The cuts are logged by what they cost:
# results at ERROR, rules at WARNING, and the locations and tags GitHub drops
# itself at DEBUG. The table's limit on the compressed size of the file is not
# checked here; a file over it is rejected by GitHub, with the whole upload lost.
_MAX_RESULTS_PER_RUN = 25000
_MAX_RULES_PER_RUN = 25000
_LOCATIONS_KEPT_PER_RESULT = 100
_TAGS_KEPT_PER_RULE = 10

#: The rule entry keys that describe a rule; two rules of one id whose entries
#: agree on these are one rule declared twice, not a collision.
_RULE_DESCRIPTION_KEYS = (
    "security_severity",
    "default_level",
    "short_description",
    "help_uri",
    "help_text",
    "tags",
)

# Mapping from ASH severity to security-severity score.
# These scores place findings into GitHub's severity buckets:
#   9.0-10.0 = Critical, 7.0-8.9 = High, 4.0-6.9 = Medium, 0.1-3.9 = Low
# Keyed by the gate's severity (utils.severity_ladder.result_severity), not by
# SARIF level, so an `error` the scan fails as critical scores 9.5, GitHub's
# Critical.
_SEVERITY_TO_SECURITY_SEVERITY: Dict[str, str] = {
    "CRITICAL": "9.5",
    "HIGH": "8.0",
    "MEDIUM": "6.0",
    "LOW": "3.0",
    "INFO": "1.0",
}


def _usable_security_severity(value: Any) -> Optional[str]:
    """*value* as the security-severity string GitHub reads, or None.

    GitHub's SARIF support documents the field as "a value that is greater than
    0.0 up to 10.0" and says "a value of 0.0 or any other value outside the given
    range is regarded as having no security severity". A scanner's rule can
    carry 0 (an advisory with no CVSS score), a non-numeric string, or a score
    out of range; passed through, that rule's alerts showed the SARIF level's
    severity on GitHub where ASH graded them by its own ladder. Such a value is
    treated as absent, so the gate-derived score is used instead.
    """
    if value is None:
        return None
    text = str(value).strip()
    try:
        score = float(text)
    except ValueError:
        return None
    if not (0.0 < score <= 10.0):
        return None
    return text


def _band(score: float) -> str:
    """GitHub's severity bucket for *score*, in the gate's spelling.

    Over 9.0 is critical, 7.0 to 8.9 high, 4.0 to 6.9 medium and 0.1 to 3.9
    low; INFO lands in the low bucket, which has no finer division.
    """
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _level_value(level: Any) -> str:
    """Render a SARIF level as its wire value.

    ``Level`` is a ``(str, Enum)`` mixin, so ``Enum.__str__`` wins and
    ``str(Level.error)`` is "Level.error" -- not a member of the SARIF 2.1.0
    level enum, and not a level the severity resolver knows. The field holds
    a member whenever it was not validated: a result or defaultConfiguration that
    omits the optional ``level`` key takes the field default, and assignment is
    unvalidated too. Writing that into the uploaded document hands GitHub a
    schema-invalid value at the field it reads to set alert severity, and drops
    the rule to the 6.0 Medium fallback on the way.
    """
    return str(getattr(level, "value", level))


def _scanner_identity(name: Any) -> str:
    """*name* as the identity every spelling of one scanner shares.

    A scanner is named in two places that nothing keeps in step: the tool
    component that declares its rules (``Trivy``) and the ``scanner_name``
    stamped on its results (``trivy``). Both are stripped and case-folded
    before they are compared, so a rule collision recorded under one spelling
    is found again under the other.
    """
    return str(name or "").strip().casefold()


def _component_scanner(component: Any) -> str:
    """The scanner name a tool component stands for.

    ``attach_scanner_details`` stamps one string three ways: the run's driver
    name, ``driver.properties.scanner_details.tool_name`` and each result's
    ``properties.scanner_name``. The stamp is read first, so a component whose
    ``name`` was later changed (a driver renamed by a merge, a rule pack folded
    in under its own name keeps no stamp) still matches its results; with no
    stamp the component's ``name`` is the scanner.
    """
    props = getattr(component, "properties", None)
    details = getattr(props, "scanner_details", None) if props is not None else None
    if details is None and props is not None:
        extra = getattr(props, "model_extra", None)
        details = extra.get("scanner_details") if isinstance(extra, dict) else None
    stamped = details.get("tool_name") if isinstance(details, dict) else None
    if isinstance(stamped, str) and stamped.strip():
        return stamped
    return str(getattr(component, "name", None) or "")


#: The kinds whose results a reader still has to judge (SARIF 3.27.9). A result of
#: either is left out of this file with every other non-failing kind; the count
#: per kind is logged, because a reader still has to judge them.
_UNJUDGED_KINDS = ("open", "review")


def _string_map(value: Any) -> Dict[str, str]:
    """*value*, a SARIF fingerprint map (a dict, or a model with extras), as
    ``{str: str}``; empty when it is neither."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        extra = getattr(value, "model_extra", None)
        value = extra if isinstance(extra, dict) else {}
    return {str(key): str(item) for key, item in value.items() if item is not None}


def _wire_id(rule_id: Optional[str]) -> Optional[str]:
    """A rule id as a frame cell: null for none or empty, else the id through
    :func:`wire` (a scanner's rule id can hold a lone surrogate, which a UTF-8
    string column refuses)."""
    return wire_cell(rule_id or None)


def _min_severity_by_rule(pairs: Iterable[Tuple[Optional[str], str]]) -> Dict[str, str]:
    """The most severe grade among *pairs* (rule id, severity) of each rule id;
    a pair with no rule id counts for no rule. A group-by over one row per
    result, taking the lowest rank on :data:`SEVERITIES` (most severe first)."""
    import polars as pl

    ids: List[Optional[str]] = []
    ranks: List[int] = []
    for rule_id, severity in pairs:
        ids.append(_wire_id(rule_id))
        ranks.append(SEVERITIES.index(severity))
    frame = pl.DataFrame(
        {"rule_id": ids, "rank": ranks}, schema={"rule_id": pl.String, "rank": pl.Int64}
    )
    grouped = (
        frame.filter(pl.col("rule_id").is_not_null())
        .group_by("rule_id", maintain_order=True)
        .agg(pl.col("rank").min())
    )
    return {unwire(rule_id): SEVERITIES[rank] for rule_id, rank in grouped.iter_rows()}


def _most_severe(
    graded: List[Tuple[str, Dict[str, Any]]], count: int
) -> List[Tuple[str, Dict[str, Any]]]:
    """The *count* most severe of *graded* (severity, slim result) pairs, in
    their original order within a severity (a stable sort).

    *graded* pairs each slim result with the severity the gate grades the
    source result at (:func:`result_severity`, which reads ``issue_severity``
    before the level). The slim copy carries only the SARIF level, where
    CRITICAL and HIGH are both ``error``, so ranking on the copy would tie
    them and could drop a later CRITICAL while an earlier HIGH stays.

    The ranking is a stable sort of a rank column; the pairs themselves, which
    hold nested dicts, stay on the host and are picked by position.
    """
    import polars as pl

    frame = pl.DataFrame(
        {
            "i": list(range(len(graded))),
            "rank": [SEVERITIES.index(severity) for severity, _ in graded],
        },
        schema={"i": pl.Int64, "rank": pl.Int64},
    )
    kept = stable_top(frame, "rank", count)["i"].to_list()
    return [graded[index] for index in kept]


def _rule_severities(graded: List[Tuple[str, Dict[str, Any]]]) -> Dict[str, str]:
    """The most severe grade among the results of each emitted rule id in
    *graded*."""
    return _min_severity_by_rule((slim.get("ruleId"), sev) for sev, slim in graded)


def _unlocated(slim_results: List[Dict[str, Any]]) -> Tuple[int, List[str]]:
    """How many of *slim_results* carry no ``locations``, and the sorted
    distinct rule ids of those (``<no rule>`` for one with no rule)."""
    import polars as pl

    frame = pl.DataFrame(
        {
            "rule_id": [_wire_id(slim.get("ruleId")) for slim in slim_results],
            "located": ["locations" in slim for slim in slim_results],
        },
        schema={"rule_id": pl.String, "located": pl.Boolean},
    )
    missing = frame.filter(~pl.col("located"))
    names = (
        missing.select(pl.col("rule_id").fill_null("<no rule>"))
        .unique()
        .sort("rule_id")["rule_id"]
    )
    return missing.height, [unwire(name) for name in names]


def _named_first(
    rule_ids: List[str], referenced: Iterable[Optional[str]]
) -> Tuple[List[int], int]:
    """The positions of *rule_ids*, those a result names (in *referenced*)
    first, each group in its original order, and how many are named. A
    semi-join flag and a stable sort on it."""
    import polars as pl

    named_ids = pl.Series(
        [wire(str(rule_id)) for rule_id in referenced if rule_id], dtype=pl.String
    )
    frame = pl.DataFrame(
        {"i": list(range(len(rule_ids))), "rule_id": [wire(r) for r in rule_ids]},
        schema={"i": pl.Int64, "rule_id": pl.String},
    ).with_columns(named=pl.col("rule_id").is_in(named_ids))
    ordered = stable_top(frame, "named", None, descending=True)
    return ordered["i"].to_list(), int(frame["named"].sum())


#: The base id the aggregator anchors each project's run to; the same spelling as
#: ``workspace/aggregation.py``'s ``PROJECT_ROOT_URI_BASE_ID``, repeated here so the
#: reporter module does not import the aggregator at import time.
PROJECT_ROOT_URI_BASE_ID = "PROJECTROOT"

_DRIVE_ANCHOR = re.compile(r"^[A-Za-z]:")


def _project_path_is_placeable(project_path: str) -> bool:
    """Whether a project path can sit below the workspace root.

    Rooted (``/x``, ``\\x``, ``C:``) or escaping (a ``..`` component) paths
    cannot, so a URI prefixed with one names nothing GitHub can resolve against
    the repository the document is uploaded for. The path is read
    percent-decoded as well as written, because it is joined into a URI that
    GitHub decodes: a component spelled ``%2e%2e`` is ``..`` to the consumer.
    """
    for spelling in (project_path, unquote(project_path)):
        text = spelling.strip().replace("\\", "/")
        if (
            text.startswith("/")
            or _DRIVE_ANCHOR.match(text)
            or ".." in PurePosixPath(text).parts
        ):
            return False
    return True


def _correlation_by_result(
    model: "AshAggregatedResults", runs: List[Any]
) -> Dict[int, str]:
    """``id(result)`` to its cross-scanner correlation id, for carrying results.

    The ids come from the flattened findings by the same positional pairing
    every shared id uses (``utils/sarif_utils.shared_correlation_ids``), over
    every result of *runs* in run order, which is the order the flattening
    walked. Keyed by object identity because the slim results are built per
    run, not over the flat list. Guarded like the shared-id read: a model whose
    flattening fails gives {} and every result is emitted without the property.
    """
    results = [result for run in runs for result in (run.results or [])]
    if not results:
        return {}
    try:
        ids = shared_correlation_ids(model, results)
    except Exception:  # noqa: BLE001 -- a missing annotation, never a lost report
        return {}
    return {
        id(result): value for result, value in zip(results, ids) if value is not None
    }


def _result_workspace_uri(result: Any) -> Optional[str]:
    """``properties.workspace_uri`` as the aggregator wrote it on *result*, or None."""
    props = getattr(result, "properties", None)
    if props is None:
        return None
    value = getattr(props, "workspace_uri", None)
    if value is None:
        extra = getattr(props, "model_extra", None)
        value = extra.get("workspace_uri") if isinstance(extra, dict) else None
    if isinstance(value, str) and value.strip():
        return value
    return None


def _run_project_path(run: Any) -> Optional[str]:
    """The project's path below the workspace root, from the run's properties.

    ``workspace/aggregation.py`` stamps ``workspace_project_path`` on every run
    it adds to the unified model. A single-directory scan's run carries no such
    property, so its URIs are left as they are. Read through ``model_extra`` as
    well as by attribute, because a ``PropertyBag`` allows extras and a key the
    schema does not declare lands there.
    """
    props = getattr(run, "properties", None)
    if props is None:
        return None
    value = getattr(props, "workspace_project_path", None)
    if value is None:
        extra = getattr(props, "model_extra", None)
        value = extra.get("workspace_project_path") if isinstance(extra, dict) else None
    if isinstance(value, str) and value.strip():
        return value
    return None


class GHASReporterConfigOptions(ReporterOptionsBase):
    exclude_suppressed: Annotated[
        bool,
        Field(
            description=(
                "When true (default), suppressed findings are excluded from the "
                "GHAS report. GitHub has its own dismissal workflow so suppressed "
                "findings are typically not needed."
            ),
        ),
    ] = True
    emit_automation_details: Annotated[
        bool,
        Field(
            description=(
                "When true, a workspace project's own report carries "
                "runAutomationDetails.id ash/<project key>/, the category GitHub "
                "files the upload under, so the per-project reports of one "
                "repository are kept apart. Off by default: an id in the file "
                "takes precedence over the category the upload-sarif action is "
                "given, so an upload that already names its category would be "
                "moved to a new one, leaving the old analysis's alerts open."
            ),
        ),
    ] = False


class GHASReporterConfig(ReporterPluginConfigBase):
    name: Literal["github-ghas"] = "github-ghas"
    extension: str = "ghas.sarif"
    enabled: bool = True
    options: GHASReporterConfigOptions = GHASReporterConfigOptions()


@ash_reporter_plugin
class GHASReporter(ReporterPluginBase[GHASReporterConfig]):
    """Produces a SARIF report optimized for GitHub Advanced Security Code Scanning.

    Per project in workspace mode; see the module docstring for why merging is
    wrong rather than merely unimplemented.
    """

    workspace_behaviour = ReporterWorkspaceBehaviour.PER_PROJECT

    def model_post_init(self, context):
        if self.config is None:
            self.config = GHASReporterConfig()
        return super().model_post_init(context)

    def report(self, model: "AshAggregatedResults") -> str | None:
        """Generate a GitHub-optimized SARIF report, or None if it cannot be built.

        None, and not an empty report, and that distinction is the point
        ------------------------------------------------------------------
        The handler below used to return ``_empty_report()``. That is a non-empty
        truthy string, so ``ReportPhase`` took its write branch: it wrote a
        schema-valid SARIF document asserting zero findings, logged the write at
        INFO, marked the reporter task green, and counted it among the successful
        reports. The bytes are identical to the legitimate-empty case at the top
        of this method -- ``TestEmptyAndErrorPaths`` asserts they differ now, and
        that assertion is the inversion of one that used to require them to match
        -- so the only thing separating "ASH could not transform these findings"
        from "this repository is clean" was one ERROR line in a log that nothing
        downstream reads.

        Returning None means ``ReportPhase`` writes no file. That is the
        conservative outcome for two independent reasons. Nothing is uploaded, so
        whatever GitHub Code Scanning already holds for this tool and category is
        left exactly as it was -- a weaker and more defensible claim than
        reasoning about how the platform reconciles an empty analysis, which is
        not observable from this repository. And a missing artefact is a loud
        failure in any pipeline step that uploads it, where a present one
        asserting zero findings is a silent pass.

        The two legitimate empty inputs below keep ``_empty_report()``: a model
        with no SARIF at all, and one with no runs, are genuinely nothing to
        report rather than a transform that failed.
        """
        try:
            sarif = model.sarif
            if not sarif or not sarif.runs:
                return self._empty_report()

            # Every run. A workspace's unified model carries one run per
            # project, and reading runs[0] alone emitted the first project's
            # findings and silently dropped every other project's (see the
            # module docstring).
            runs = list(sarif.runs)

            # The project path of each run of a workspace document, or {} for a
            # document that is not one. None refuses the document: a project
            # path that cannot sit below one repository root (absolute, or
            # escaping with "..") would mis-locate every finding of that run.
            project_paths = self._workspace_project_paths(model, runs)
            if project_paths is None:
                return None
            # Logged before the base-id refusal below, so a document refused for
            # its base ids still says how many open and review results it held.
            # A document refused for its project paths, above, returns first
            # and says nothing of them.
            self._log_unjudged_kinds(runs)
            uri_bases = self._merged_uri_base_ids(runs, project_paths)
            if uri_bases is None:
                return None

            # 1. Collect all rules from every run's driver and extensions,
            #    flattened. Two scanners can declare one rule id (grype and
            #    trivy both name a CVE; two linters one shared code) with
            #    different descriptions, help and scores. Flattened first-wins,
            #    the second scanner's alerts carried the first scanner's text
            #    and score, and the two scanners' results pooled into one
            #    severity. Such a colliding rule is declared under
            #    "<scanner>/<rule id>" and that scanner's results name it; the
            #    scanner whose name sorts first keeps the bare id, whatever
            #    order the components are listed in.
            rules_map: Dict[str, Dict[str, Any]] = {}
            qualified: Dict[Tuple[str, str], str] = {}
            components: List[Any] = []
            for run in runs:
                components.append(run.tool.driver)
                components.extend(run.tool.extensions or [])
            self._collect_rules(components, rules_map, qualified)

            # 2. The most severe of each rule's results, as the gate grades them
            #    (issue_severity, else the level), for rules whose scanner gave
            #    no security-severity. Only results this file emits count, so a
            #    suppressed CRITICAL left out of the upload does not raise its
            #    rule to 9.5 and make the rule's one remaining LOW alert show as
            #    Critical on GitHub. A rule all of whose results are left out
            #    keeps the score it would have with none (its default level,
            #    else 6.0); no alert in the file carries it.
            emitted_grades: List[Tuple[str, str]] = []
            for run in runs:
                for result in run.results or []:
                    rule_id = self._emitted_rule_id(result, qualified)
                    if not rule_id or self._left_out(result):
                        continue
                    emitted_grades.append((rule_id, result_severity(result)))
            rule_level_from_results: Dict[str, str] = _min_severity_by_rule(
                emitted_grades
            )

            # 3. Build slim results (excluding suppressed if configured). First,
            #    because a result naming a rule the run does not declare adds
            #    that rule to rules_map; the rules were built before it, so the
            #    result reached GitHub with no rule and no security-severity.
            #    Each run's results are located against its own project path,
            #    so a multi-run document reads against the workspace root.
            # The cross-scanner correlation id of each result, keyed by the
            # result object: the slim copy strips verbose fields, so without
            # this keep-list entry the id written at flatten time would
            # silently disappear from the upload.
            correlation = _correlation_by_result(model, runs)

            graded: List[Tuple[str, Dict[str, Any]]] = []
            for index, run in enumerate(runs):
                graded.extend(
                    self._build_slim_results(
                        run.results or [],
                        rules_map,
                        rule_level_from_results,
                        project_path=project_paths.get(index),
                        project_root=self._project_root(run),
                        qualified=qualified,
                        correlation=correlation,
                    )
                )
            slim_results = [slim for _, slim in graded]

            # A colliding rule declared under "<scanner>/<rule id>" is named by
            # the results whose scanner_name matches that scanner. One named by
            # no result is either a rule its scanner never fired, or a scanner
            # whose results carry another spelling of its name and so kept the
            # bare id (and the other scanner's text and score); the operator is
            # told which rules to look at.
            used_rule_ids = {result.get("ruleId") for result in slim_results}
            for (identity, rule_id), emitted_id in sorted(qualified.items()):
                if emitted_id not in used_rule_ids:
                    ASH_LOGGER.warning(
                        f"GHAS report: rule {rule_id} is declared differently by "
                        f"two scanners and the one named '{identity}' has it as "
                        f"{emitted_id}, but no result names {emitted_id}; results "
                        f"of that scanner whose scanner_name is not '{identity}' "
                        f"keep the id {rule_id}"
                    )

            # A result GitHub cannot display: none of its locations has a uri.
            # The result is still written (SARIF allows it, and dropping it
            # would under-report in silence), but GitHub's documentation says
            # "At least one location is required for code scanning to display
            # a result", so the operator is told which rules' alerts will not
            # appear.
            unlocated_count, unlocated = _unlocated(slim_results)
            if unlocated:
                ASH_LOGGER.warning(
                    f"GHAS report: {unlocated_count} "
                    "result(s) carry no location with a file, which GitHub code "
                    f"scanning does not display; rules: {', '.join(unlocated)}"
                )

            # GitHub rejects a run with more than 25,000 results; it keeps the
            # most severe itself when it truncates, so the same choice is made
            # here, and said.
            if len(slim_results) > _MAX_RESULTS_PER_RUN:
                ASH_LOGGER.error(
                    f"GHAS report: {len(slim_results)} results exceed GitHub's limit "
                    f"of {_MAX_RESULTS_PER_RUN} per run; the "
                    f"{len(slim_results) - _MAX_RESULTS_PER_RUN} least severe are "
                    "left out of the upload and are in the other reports"
                )
                kept = _most_severe(graded, _MAX_RESULTS_PER_RUN)
                slim_results = [slim for _, slim in kept]
                # Scored from the results still in the file, as step 2 says: a
                # rule whose results were all cut keeps the score it would
                # have with none, not the one its cut results gave it.
                rule_level_from_results = _rule_severities(kept)

            # 4. Ensure every rule has security-severity
            slim_rules = self._build_slim_rules(rules_map, rule_level_from_results)
            if len(slim_rules) > _MAX_RULES_PER_RUN:
                order, named_count = _named_first(
                    [rule["id"] for rule in slim_rules],
                    (result.get("ruleId") for result in slim_results),
                )
                slim_rules = [slim_rules[i] for i in order][:_MAX_RULES_PER_RUN]
                ASH_LOGGER.warning(
                    f"GHAS report: more than {_MAX_RULES_PER_RUN} rules, GitHub's "
                    "limit per run; rules no emitted result names are left out "
                    f"first ({named_count} named, {len(slim_rules) - named_count} "
                    "unnamed kept)"
                )

            # 5. Assemble the final SARIF structure
            out_run: Dict[str, Any] = {
                "tool": {
                    "driver": {
                        "name": GHAS_DRIVER_NAME,
                        "organization": "Amazon Web Services",
                        "version": get_ash_version(),
                        "informationUri": "https://github.com/awslabs/automated-security-helper",
                        "rules": slim_rules,
                    }
                },
                "results": slim_results,
            }

            # The base ids the locations may refer to: those of every run whose
            # URIs were not rebased (one run outside a workspace document, a
            # project's own upload among them, or a run of a multi-run document
            # that names no project). The URIs of a rebased run are
            # workspace-relative and refer to none.
            if uri_bases:
                out_run["originalUriBaseIds"] = uri_bases

            # automationDetails.id is the category GitHub files an upload
            # under. The N per-project documents a workspace scan writes are
            # identical in tool identity and carry none, so uploading them for
            # one repository makes each replace the previous project's
            # analysis. The project's key keeps them apart, on request: the
            # upload-sarif action fills automationDetails only on a run that
            # has none (github/codeql-action, upload-lib.ts,
            # populateRunAutomationDetails), so an id written here overrides
            # the category: an operator already gave it, and an upgrade that
            # wrote one unasked would move every such upload to a new category
            # and leave the old analysis's alerts open. A single-directory
            # scan and a unified workspace document carry none either way.
            if self._emits_automation_details():
                category = self._workspace_project(model)
                if category:
                    out_run["automationDetails"] = {"id": f"ash/{category}/"}

            report_dict = {
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "version": "2.1.0",
                "runs": [out_run],
            }

            return json.dumps(report_dict, separators=(",", ":"))

        except Exception as e:
            # Caught rather than propagated because an exception here aborts the
            # whole report phase and costs the operator every other reporter's
            # output. Returning None rather than an empty report is what keeps the
            # failure legible; see this method's docstring.
            ASH_LOGGER.error(f"Failed to create GHAS SARIF report: {e}")
            return None

    @staticmethod
    def _workspace_project_paths(
        model: "AshAggregatedResults", runs: list
    ) -> Optional[Dict[int, Optional[str]]]:
        """Each run's project path below the workspace root, by run index.

        ``{}`` when the document is not a workspace one, so no URI is rebased.
        That is decided from the model, as ``csv_reporter`` does with
        ``is_workspace_scan``, or from the document carrying more than one run
        (``ash report`` over a workspace output directory hands over the unified
        model), never from a stamp one run happens to carry: a project's own
        per-project document keeps its project-relative URIs and its base ids,
        which is what its own upload needs.

        None refuses the document. A workspace is one repository root only when
        it is a monorepo, and the model does not record which repository each
        project is in, so two things are checked instead. A project path that
        is absolute or escapes with ``..`` (a ``.code-workspace`` folder named
        ``../other``) cannot sit below the workspace root, so every finding of
        that run would be mis-located: refused, with the per-project document
        named. Several distinct project paths merge into one document, which is
        right for a monorepo and wrong for a workspace of separate repositories:
        logged once as a warning naming the per-project documents, because the
        model cannot tell the two apart and the operator can.
        """
        from automated_security_helper.models.workspace import is_workspace_scan

        if not runs or not (is_workspace_scan(model) or len(runs) > 1):
            return {}
        paths: Dict[int, Optional[str]] = {}
        for index, run in enumerate(runs):
            path = _run_project_path(run)
            if path is not None and not _project_path_is_placeable(path):
                key = GHASReporter._run_workspace_project(run) or path
                ASH_LOGGER.error(
                    f"The GHAS report over the workspace is not written: project "
                    f"'{key}' sits at '{path}', which is not below the workspace "
                    "root, so its findings cannot be located against one "
                    f"repository. Upload the project's own report, "
                    f"projects/{key}/reports/ash.ghas.sarif, instead."
                )
                return None
            paths[index] = path
        distinct = {path for path in paths.values() if path}
        if len(distinct) > 1:
            ASH_LOGGER.warning(
                f"The GHAS report merges {len(distinct)} projects below one "
                "workspace root into one document. GitHub resolves it against one "
                "repository, which is right for a monorepo; a workspace of "
                "separate repositories uploads each project's own "
                "projects/<key>/reports/ash.ghas.sarif instead."
            )
        return paths

    @staticmethod
    def _run_workspace_project(run: Any) -> Optional[str]:
        """The project key the aggregator stamped on *run*, or None."""
        props = getattr(run, "properties", None)
        if props is None:
            return None
        value = getattr(props, "workspace_project", None)
        if value is None:
            extra = getattr(props, "model_extra", None)
            value = extra.get("workspace_project") if isinstance(extra, dict) else None
        if isinstance(value, str) and value.strip():
            return value.strip()
        return None

    @staticmethod
    def _project_root(run: Any) -> Optional[str]:
        """The project's absolute path, read back from its ``PROJECTROOT`` base.

        The aggregator anchors each project's run with
        ``originalUriBaseIds.PROJECTROOT`` = the ``file://`` URI of the project
        directory (``workspace/aggregation.py``, ``project_root_uri``). It is the
        third argument ``to_workspace_uri`` needs to place an absolute URI inside
        the project; without it an absolute URI is kept as written.
        """
        bases = getattr(run, "originalUriBaseIds", None)
        if not isinstance(bases, dict):
            return None
        location = bases.get(PROJECT_ROOT_URI_BASE_ID)
        uri = getattr(location, "uri", None)
        if not isinstance(uri, str) or not uri.lower().startswith("file://"):
            return None
        text = unquote(uri[len("file://") :])
        if len(text) > 2 and text[0] == "/" and text[2] == ":":
            text = text[1:]
        text = text.rstrip("/")
        return text or None

    @staticmethod
    def _original_uri_base_ids(run: Any) -> Dict[str, Dict[str, str]]:
        """The run's ``originalUriBaseIds`` as plain dicts: each base's ``uri``
        and, when the base is itself anchored to another (SARIF 3.4.4, as
        ``{"SRCROOT": {"uri": "src/", "uriBaseId": "REPOROOT"}}``), its
        ``uriBaseId``; kept uri-only, a chained base was emitted as a relative
        base with nothing to resolve against."""
        bases = getattr(run, "originalUriBaseIds", None)
        if not isinstance(bases, dict):
            return {}
        out: Dict[str, Dict[str, str]] = {}
        for key, location in bases.items():
            uri = getattr(location, "uri", None)
            if not uri:
                continue
            entry = {"uri": str(uri)}
            base_id = getattr(location, "uriBaseId", None)
            if base_id:
                entry["uriBaseId"] = str(base_id)
            out[str(key)] = entry
        return out

    @staticmethod
    def _log_unjudged_kinds(runs: list) -> None:
        """Say how many results of each kind a reader still has to judge are left
        out of the file (:data:`_UNJUDGED_KINDS`).

        ``_left_out`` drops every result whose kind is not ``fail``, ``open`` and
        ``review`` included, and the file said nothing about them, so a reviewer
        comparing it with another report of the same scan found results that were
        not in the file. Only the count is logged, and only what this file does:
        whether those kinds belong in the file is a decision this method does
        not take, and what another report does with them depends on which
        reports are enabled.
        """
        counts = dict.fromkeys(_UNJUDGED_KINDS, 0)
        for run in runs:
            for result in run.results or []:
                kind = result_kind(result)
                if kind in counts:
                    counts[kind] += 1
        found = {kind: count for kind, count in counts.items() if count}
        if found:
            listed = ", ".join(
                f"{count} of kind '{kind}'" for kind, count in found.items()
            )
            ASH_LOGGER.warning(
                f"GHAS report: {listed} left out of the file, as every result whose "
                "kind is not 'fail' is"
            )

    def _used_uri_base_ids(self, run: Any) -> set:
        """The base ids the locations of *run*'s results refer to: the ones the
        file writes on a location (:meth:`_build_slim_locations`).

        Only what the file carries counts. A result the file leaves out
        (:meth:`_left_out`) writes no location, and neither does a location
        with no ``uri`` or one past the cap on locations per result; a base
        used only by those was declared all the same, and two runs that
        disagreed about it refused a document whose written results never
        referred to it.
        """
        used: set = set()
        for result in getattr(run, "results", None) or []:
            if self._left_out(result):
                continue
            written = 0
            for location in getattr(result, "locations", None) or []:
                physical = getattr(location, "physicalLocation", None)
                physical = getattr(physical, "root", physical)
                artifact = getattr(physical, "artifactLocation", None)
                if not getattr(artifact, "uri", None):
                    continue
                written += 1
                if written > _LOCATIONS_KEPT_PER_RESULT:
                    break
                base_id = getattr(artifact, "uriBaseId", None)
                if base_id:
                    used.add(str(base_id))
        return used

    def _merged_uri_base_ids(
        self, runs: list, project_paths: Dict[int, Optional[str]]
    ) -> Optional[Dict[str, Dict[str, str]]]:
        """The ``originalUriBaseIds`` of every run whose URIs are not rebased,
        merged into the one table the emitted run declares.

        A location keeps its ``uriBaseId`` when its run is not rebased below a
        workspace root, so the table must declare every base such a run uses; it
        used to be written for a one-run document only, and a multi-run
        document's unrebased runs referred to bases it never declared. Only the
        bases a result refers to are declared, with the base each of them is
        anchored to: a scanner's table can list bases none of its results use,
        and those added nothing to the file but a way for two runs to disagree.
        Two runs declaring one key differently cannot share a table: None
        refuses the document, and the log names the key, both declarations and
        the two runs (the same refusal as an unplaceable project path). A run
        that refers to a base id it does not declare, or declares with no uri,
        while another run declares it with one, is read against that run's
        entry and is warned about; the document is still written.
        """
        merged: Dict[str, Dict[str, str]] = {}
        first_run: Dict[str, int] = {}
        undeclared: List[Tuple[int, str]] = []
        for index, run in enumerate(runs):
            if project_paths.get(index):
                continue
            declared = GHASReporter._original_uri_base_ids(run)
            used = self._used_uri_base_ids(run)
            undeclared.extend(
                (index, key) for key in sorted(used) if key not in declared
            )
            needed: set = set()
            pending = [key for key in used if key in declared]
            while pending:
                key = pending.pop()
                if key in needed:
                    continue
                needed.add(key)
                anchor = declared[key].get("uriBaseId")
                if anchor in declared:
                    pending.append(anchor)
            for key, entry in declared.items():
                if key not in needed:
                    continue
                if key not in merged:
                    merged[key] = entry
                    first_run[key] = index
                elif merged[key] != entry:
                    ASH_LOGGER.error(
                        f"The GHAS report is not written: runs {first_run[key]} and "
                        f"{index} (counting from 0) declare the base id '{key}' "
                        f"differently, as {merged[key]} and {entry}, and one "
                        "document has one table of base ids. Upload each "
                        "project's own report instead."
                    )
                    return None
        # A run that refers to a base id it never declares, or declares with no
        # uri (:meth:`_original_uri_base_ids` drops such an entry), contributes
        # nothing to the table, and the document resolves that id with the entry
        # another run declared for it: a root the referring run did not name.
        # Said once per run and base, because the document is still written.
        for index, key in undeclared:
            if key in merged:
                ASH_LOGGER.warning(
                    f"GHAS report: run {index} (counting from 0) refers to the "
                    f"base id '{key}' without declaring a uri for it; the document "
                    f"declares it as {merged[key]} from run {first_run[key]}, and "
                    "that run's entry is what the locations of this run are read "
                    "against."
                )
        return merged

    def _emits_automation_details(self) -> bool:
        """Whether the operator asked for ``automationDetails`` (off by default)."""
        return bool(self.config and self.config.options.emit_automation_details)

    @staticmethod
    def _workspace_project(model: "AshAggregatedResults") -> Optional[str]:
        """The workspace project this document describes, or None.

        Read from the model's metadata alone, which a per-project scan stamps
        (``workspace/execution.py``). A unified model is one analysis of the
        workspace whatever its run count: one run is left when every other
        project was skipped, so a category read from that run's stamp came and
        went between two scans of one workspace, and it was the category of the
        project's own per-project document, whose URIs are project-relative
        where the unified document's are workspace-relative. GitHub then held
        two analyses of one project, each upload replacing the other's alerts.
        """
        project = getattr(getattr(model, "metadata", None), "workspace_project", None)
        if isinstance(project, str) and project.strip():
            return project.strip()
        return None

    @staticmethod
    def _emitted_rule_id(
        result: Any, qualified: Optional[Dict[Tuple[str, str], str]] = None
    ) -> Optional[str]:
        """The rule id *result* is emitted under: its own, or the qualified id
        its scanner's colliding rule was declared under (:meth:`_collect_rules`)."""
        rule_id = result_rule_id(result)
        if not rule_id or not qualified:
            return rule_id
        scanner = result_scanner_name(result)
        if scanner is None:
            return rule_id
        return qualified.get((_scanner_identity(scanner), rule_id), rule_id)

    def _collect_rules(
        self,
        components: Iterable[Any],
        rules_map: Dict[str, Dict[str, Any]],
        qualified: Optional[Dict[Tuple[str, str], str]] = None,
    ) -> None:
        """Collect the rules of *components* (ToolComponents) into the rules map.

        The declarations of one rule id are decided together, so the ids that
        come out do not depend on the order the components are listed in. A rule
        another component declares with the same description is the same rule.
        One declared differently is a collision: the scanner whose name sorts
        first (compared by :func:`_scanner_identity`, unnamed components last)
        keeps the bare id, and each other scanner's rule is entered under
        ``<component name>/<id>``. The pair (scanner identity, id) is recorded
        in *qualified* under the identity the results' ``scanner_name`` is
        compared by, so the results of that scanner name the qualified id
        (:meth:`_emitted_rule_id`) and keep their own description, help and
        score. A component repeating an id keeps its first declaration.
        """
        declared: Dict[str, Dict[str, Tuple[str, Dict[str, Any]]]] = {}
        for component in components:
            if not component or not component.rules:
                continue
            component_name = str(getattr(component, "name", None) or "")
            identity = _scanner_identity(_component_scanner(component))
            for rule in component.rules:
                by_scanner = declared.setdefault(rule.id, {})
                if identity not in by_scanner:
                    by_scanner[identity] = (
                        component_name,
                        self._rule_entry(rule, component_name),
                    )

        for rule_id, by_scanner in declared.items():
            owner = min(by_scanner, key=lambda name: (not name, name))
            owner_name, owner_entry = by_scanner[owner]
            rules_map[rule_id] = owner_entry
            for identity, (component_name, entry) in by_scanner.items():
                if identity == owner or not identity or qualified is None:
                    continue
                if all(
                    owner_entry.get(key) == entry.get(key)
                    for key in _RULE_DESCRIPTION_KEYS
                ):
                    continue
                emitted_id = f"{component_name}/{rule_id}"
                if emitted_id in rules_map:
                    continue
                entry["id"] = emitted_id
                qualified[(identity, rule_id)] = emitted_id
                rules_map[emitted_id] = entry
                ASH_LOGGER.debug(
                    f"GHAS report: rule {rule_id} is declared differently by "
                    f"{owner_name or 'another scanner'} and "
                    f"{component_name}; {component_name}'s is emitted as {emitted_id}"
                )

    @staticmethod
    def _rule_entry(rule: Any, component_name: str) -> Dict[str, Any]:
        """The rules_map entry for *rule* as *component_name* declares it."""
        # Extract existing security-severity if present
        security_severity = None
        rule_tags = []
        if rule.properties:
            props = rule.properties.model_extra or {}
            # Check both hyphenated (from native SARIF) and underscored (from ASH code)
            security_severity = _usable_security_severity(
                props.get("security-severity", props.get("security_severity"))
            )
            rule_tags = rule.properties.tags or []

        # Get the default level from the rule configuration
        default_level = None
        if rule.defaultConfiguration and rule.defaultConfiguration.level:
            default_level = _level_value(rule.defaultConfiguration.level)

        return {
            "id": rule.id,
            "component": component_name,
            "security_severity": security_severity,
            "default_level": default_level,
            "short_description": (
                rule.shortDescription.text if rule.shortDescription else None
            ),
            "help_uri": str(rule.helpUri) if rule.helpUri else None,
            "help_text": (rule.help.text if rule.help else None),
            "tags": list(rule_tags),
        }

    def _resolve_security_severity(
        self,
        rule_id: str,
        rules_map: Dict[str, Dict[str, Any]],
        rule_level_from_results: Dict[str, str],
    ) -> str:
        """Resolve the security-severity for a rule.

        Priority:
        1. Existing security-severity from the scanner, when it is usable
           (:func:`_usable_security_severity`) and lands in the same GitHub
           bucket as the gate's grade of the rule's most severe emitted result
        2. The most severe of the rule's results, as the gate grades them
        3. Derived from rule's defaultConfiguration.level, the gate's way
        4. Default to "6.0" (Medium)

        The results come before the rule's default level because they carry
        ``issue_severity``, which the gate reads first and a rule cannot. A
        scanner's own score is kept only when it agrees with the gate's bucket:
        the scan fails a result at the gate's severity, and every other ASH
        report shows that severity, so a rule the gate graded CRITICAL showing
        as Low on GitHub because the scanner's rule-level score said 3.1 made
        the one finding read two ways. Within the bucket the scanner's score is
        the more precise statement and is preserved.
        """
        rule_info = rules_map.get(rule_id)

        # 2 first, because 1 is checked against it. report() records
        #    severities here; a level is read the gate's way, so a caller passing
        #    one gets the same.
        from_results = rule_level_from_results.get(rule_id)
        if from_results and from_results not in _SEVERITY_TO_SECURITY_SEVERITY:
            from_results = result_severity({"level": from_results})

        # 1. The scanner's security-severity, if usable and in the gate's bucket
        scanner_score = (
            _usable_security_severity(rule_info["security_severity"])
            if rule_info
            else None
        )
        if scanner_score and (
            not from_results
            or _band(float(scanner_score))
            == _band(float(_SEVERITY_TO_SECURITY_SEVERITY[from_results]))
        ):
            return scanner_score

        # 2. Derive from the rule's results
        if from_results:
            return _SEVERITY_TO_SECURITY_SEVERITY[from_results]

        # 3. Derive from rule's defaultConfiguration.level
        if rule_info and rule_info["default_level"]:
            return _SEVERITY_TO_SECURITY_SEVERITY[
                result_severity({"level": rule_info["default_level"]})
            ]

        # 4. Default
        return "6.0"

    def _build_slim_rules(
        self,
        rules_map: Dict[str, Dict[str, Any]],
        rule_level_from_results: Dict[str, str],
    ) -> List[Dict[str, Any]]:
        """Build a minimal list of rule objects with security-severity guaranteed."""
        slim_rules = []
        for rule_id, rule_info in rules_map.items():
            severity = self._resolve_security_severity(
                rule_id, rules_map, rule_level_from_results
            )

            rule_dict: Dict[str, Any] = {"id": rule_id}

            if rule_info["short_description"]:
                rule_dict["shortDescription"] = {"text": rule_info["short_description"]}

            if rule_info["help_uri"]:
                rule_dict["helpUri"] = rule_info["help_uri"]

            if rule_info["help_text"]:
                rule_dict["help"] = {"text": rule_info["help_text"]}

            # Always set properties with security-severity. Tags are cut at the
            # ten GitHub includes; past twenty it rejects the file.
            properties: Dict[str, Any] = {"security-severity": severity}
            if rule_info["tags"]:
                if len(rule_info["tags"]) > _TAGS_KEPT_PER_RULE:
                    ASH_LOGGER.debug(
                        f"GHAS report: rule {rule_id}'s {len(rule_info['tags'])} tags "
                        f"are cut to the {_TAGS_KEPT_PER_RULE} GitHub includes"
                    )
                properties["tags"] = list(rule_info["tags"])[:_TAGS_KEPT_PER_RULE]
            rule_dict["properties"] = properties

            slim_rules.append(rule_dict)

        return slim_rules

    def _left_out(self, result: Any) -> bool:
        """Whether *result* is kept out of the file. One test for the results
        list and the rules' scores, so a result never scores a rule it is not in.

        Two kinds of result are left out. A result whose ``kind`` is not
        ``fail`` (SARIF 3.27.9: pass, open, review, notApplicable,
        informational) states no failing finding. GitHub's documented result
        properties do not include ``kind`` ("code scanning will only use the
        following supported properties"), so a copy that carried it, or that
        dropped it, was read under SARIF's default kind, fail, and a cdk-nag rule
        ASH marked notApplicable was an open alert; such a result stays in the
        other reports. And a suppressed result, under ``exclude_suppressed``
        (the default): suppressed means a suppression in effect
        (``suppressions_in_effect``); one ``rejected`` by the reviewer or still
        ``underReview`` has not taken effect (SARIF 3.35.4), the gate still fails
        the scan on the finding, and the file kept it out as if it were dismissed.
        """
        if result_kind(result) != DEFAULT_RESULT_KIND:
            return True
        return bool(
            self.config
            and self.config.options.exclude_suppressed
            and suppressions_in_effect(getattr(result, "suppressions", None))
        )

    def _build_slim_results(
        self,
        results: list,
        rules_map: Dict[str, Dict[str, Any]],
        rule_level_from_results: Dict[str, str],
        project_path: Optional[str] = None,
        project_root: Optional[str] = None,
        qualified: Optional[Dict[Tuple[str, str], str]] = None,
        correlation: Optional[Dict[int, str]] = None,
    ) -> List[Tuple[str, Dict[str, Any]]]:
        """Build a minimal list of result objects, each paired with the severity
        the gate grades its source result at (:func:`result_severity`).

        *project_path* is the results' project's path below the workspace root
        when they come from one run of a workspace document, and None otherwise;
        *project_root* the project's absolute path when the run is anchored to
        it; see :meth:`_build_slim_locations`. *qualified* maps (scanner
        identity, rule id) to the id a colliding rule was declared under.
        *correlation* maps ``id(result)`` to the result's cross-scanner
        correlation id (:func:`_correlation_by_result`); a result it names
        keeps the id in the slim copy's property bag.
        """
        slim_results: List[Tuple[str, Dict[str, Any]]] = []

        for result in results:
            # Skip suppressed findings if configured
            if self._left_out(result):
                continue

            # If this result references a rule we haven't seen, create a
            # synthetic entry so the rule list stays complete. report() builds
            # the rules from rules_map after this returns.
            rule_id = self._emitted_rule_id(result, qualified)
            if rule_id and rule_id not in rules_map:
                level_val = effective_sarif_level(result)
                rules_map[rule_id] = {
                    "id": rule_id,
                    "component": result_scanner_name(result) or "",
                    "security_severity": None,
                    "default_level": None,
                    "short_description": None,
                    "help_uri": None,
                    "help_text": None,
                    "tags": [],
                }
                rule_level_from_results.setdefault(rule_id, level_val)

            # Build slim result
            result_dict: Dict[str, Any] = {}

            if rule_id:
                result_dict["ruleId"] = rule_id

            # Map level. No kind: every result that reaches here is a failing
            # one (_left_out), which is SARIF's default.
            level_val = effective_sarif_level(result)
            result_dict["level"] = level_val

            # Suppressions, when the file keeps a suppressed result
            # (exclude_suppressed off). Dropped, the result reached GitHub as an
            # open alert indistinguishable from an unsuppressed one.
            suppressions = getattr(result, "suppressions", None)
            if suppressions:
                result_dict["suppressions"] = [
                    self._slim_suppression(suppression) for suppression in suppressions
                ]

            # Message
            if result.message and result.message.root and result.message.root.text:
                result_dict["message"] = {"text": result.message.root.text}
            else:
                result_dict["message"] = {"text": rule_id or "Finding detected"}

            # Locations — only physical location with uri and region
            locations = self._build_slim_locations(
                result.locations,
                project_path,
                workspace_uri=_result_workspace_uri(result) if project_path else None,
                project_root=project_root,
            )
            if locations:
                result_dict["locations"] = locations

            # Fingerprints. GitHub tracks an alert across uploads by
            # partialFingerprints (it "will attempt to use partialFingerprints
            # if they exist"); dropped from the slim copy, every alert of a
            # scanner that supplied them was re-keyed by line hash and reopened
            # when its line moved.
            for key in ("partialFingerprints", "fingerprints"):
                prints = _string_map(getattr(result, key, None))
                if prints:
                    result_dict[key] = prints

            # The cross-scanner correlation id, on the slim copy's keep list:
            # the one property this reporter carries over, so a consumer of the
            # upload can group two scanners' findings of one observation
            # (utils/finding_identity, "Correlation ids"). Absent for a result
            # with none, as every other surface omits it.
            correlation_id = (correlation or {}).get(id(result))
            if correlation_id:
                result_dict["properties"] = {CORRELATION_ID_PROPERTY: correlation_id}

            slim_results.append((result_severity(result), result_dict))

        return slim_results

    @staticmethod
    def _slim_suppression(suppression: Any) -> Dict[str, Any]:
        """The SARIF suppression object's kind, state and justification, each
        written only when the suppression has it: ``_level_value(None)`` is the
        text "None", which is no suppression kind (SARIF 3.35.3)."""
        slim: Dict[str, Any] = {}
        kind = getattr(suppression, "kind", None)
        if kind is not None:
            slim["kind"] = _level_value(kind)
        state = getattr(suppression, "state", None)
        if state is not None:
            slim["state"] = _level_value(state)
        justification = getattr(suppression, "justification", None)
        if justification:
            slim["justification"] = str(justification)
        return slim

    def _build_slim_locations(
        self,
        locations: Optional[list],
        project_path: Optional[str] = None,
        workspace_uri: Optional[str] = None,
        project_root: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Extract minimal location info.

        With *project_path*, each URI is expressed below the workspace root,
        because GitHub resolves every URI of the one document against the one
        repository it is uploaded for. The aggregator already did this once, for
        the result's first placeable location, and stored the answer as
        ``properties.workspace_uri``; that value is used for that location as it
        stands (*workspace_uri*), so the document agrees with the aggregator
        exactly, including for an absolute URI it placed inside the project.
        The other locations are recomputed by the same helper with the same
        inputs, the project's absolute path (*project_root*) included. A URI the
        helper cannot place (absolute and outside the project) is kept as the
        scanner wrote it.
        """
        if not locations:
            return []

        slim_locs = []
        first_placed_pending = workspace_uri is not None
        for loc in locations:
            if not loc.physicalLocation:
                continue

            phys = loc.physicalLocation
            # Handle the PhysicalLocation which may be wrapped in a RootModel
            phys_obj = phys.root if hasattr(phys, "root") else phys

            artifact_loc = getattr(phys_obj, "artifactLocation", None)
            region = getattr(phys_obj, "region", None)

            if not artifact_loc or not artifact_loc.uri:
                continue

            uri = str(artifact_loc.uri)
            artifact_dict: Dict[str, Any] = {"uri": uri}
            if project_path:
                from automated_security_helper.workspace.aggregation import (
                    to_workspace_uri,
                )

                # Rebased below the workspace root, so the base id the
                # aggregator anchored the project-relative URI to no longer
                # applies and is dropped with the rebase.
                rebased = to_workspace_uri(uri, project_path, project_root)
                if rebased is not None and first_placed_pending:
                    # The aggregator's own answer for the first location it
                    # could place: the same question, asked once.
                    rebased = workspace_uri
                    first_placed_pending = False
                artifact_dict["uri"] = rebased or uri
            else:
                # A base id a scanner anchored its own output to is kept with
                # the URI it qualifies; dropped, a URI relative to a declared
                # base read as relative to the repository root.
                base_id = getattr(artifact_loc, "uriBaseId", None)
                if base_id:
                    artifact_dict["uriBaseId"] = str(base_id)

            phys_dict: Dict[str, Any] = {"artifactLocation": artifact_dict}

            if region:
                region_dict: Dict[str, Any] = {}
                if region.startLine is not None:
                    region_dict["startLine"] = region.startLine
                if region.endLine is not None:
                    region_dict["endLine"] = region.endLine
                if region.startColumn is not None:
                    region_dict["startColumn"] = region.startColumn
                if region.endColumn is not None:
                    region_dict["endColumn"] = region.endColumn
                if region_dict:
                    phys_dict["region"] = region_dict

            slim_locs.append({"physicalLocation": phys_dict})

        # GitHub includes the first hundred locations of a result and rejects
        # a file with a result past a thousand; the rest are not uploaded.
        if len(slim_locs) > _LOCATIONS_KEPT_PER_RESULT:
            ASH_LOGGER.debug(
                f"GHAS report: a result's {len(slim_locs)} locations are cut to "
                f"the {_LOCATIONS_KEPT_PER_RESULT} GitHub includes"
            )
            slim_locs = slim_locs[:_LOCATIONS_KEPT_PER_RESULT]

        return slim_locs

    def _empty_report(self) -> str:
        """Return a valid but empty SARIF report."""
        return json.dumps(
            {
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": GHAS_DRIVER_NAME,
                                "organization": "Amazon Web Services",
                                "version": get_ash_version(),
                                "informationUri": "https://github.com/awslabs/automated-security-helper",
                                "rules": [],
                            }
                        },
                        "results": [],
                    }
                ],
            },
            separators=(",", ":"),
        )
