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
"""

import json
from typing import Any, Dict, List, Literal, Optional, TYPE_CHECKING

from pydantic import Field
from typing_extensions import Annotated

from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    ReporterWorkspaceBehaviour,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin
from automated_security_helper.utils.get_ash_version import get_ash_version
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.severity_ladder import (
    SEVERITIES,
    effective_sarif_level,
    result_severity,
)

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults

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


def _rule_id(result: Any) -> Optional[str]:
    """The id of the rule *result* names: its ruleId, else its rule.id.

    SARIF 2.1.0 lets a result name its rule either way (3.27.5, 3.27.7). Read
    as ruleId alone, a result naming it as rule.id was emitted with neither,
    and with no rule entry.
    """
    if result.ruleId:
        return result.ruleId
    rule = getattr(result, "rule", None)
    rule = getattr(rule, "root", rule)
    return getattr(rule, "id", None) or None


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

            # 1. Collect all rules from every run's driver and extensions,
            #    flattened
            rules_map: Dict[str, Dict[str, Any]] = {}
            for run in runs:
                self._collect_rules(run.tool.driver, rules_map)
                for ext in run.tool.extensions or []:
                    self._collect_rules(ext, rules_map)

            # 2. The most severe of each rule's results, as the gate grades them
            #    (issue_severity, else the level), for rules whose scanner gave
            #    no security-severity. Only results this file emits count, so a
            #    suppressed CRITICAL left out of the upload does not raise its
            #    rule to 9.5 and make the rule's one remaining LOW alert show as
            #    Critical on GitHub. A rule all of whose results are left out
            #    keeps the score it would have with none (its default level,
            #    else 6.0); no alert in the file carries it.
            rule_level_from_results: Dict[str, str] = {}
            for run in runs:
                for result in run.results or []:
                    rule_id = _rule_id(result)
                    if not rule_id or self._left_out(result):
                        continue
                    severity = result_severity(result)
                    current = rule_level_from_results.get(rule_id)
                    if current is None or SEVERITIES.index(severity) < SEVERITIES.index(
                        current
                    ):
                        rule_level_from_results[rule_id] = severity

            # 3. Build slim results (excluding suppressed if configured). First,
            #    because a result naming a rule the run does not declare adds
            #    that rule to rules_map; the rules were built before it, so the
            #    result reached GitHub with no rule and no security-severity.
            #    Each run's results are located against its own project path,
            #    so a multi-run document reads against the workspace root.
            slim_results: List[Dict[str, Any]] = []
            for run in runs:
                slim_results.extend(
                    self._build_slim_results(
                        run.results or [],
                        rules_map,
                        rule_level_from_results,
                        project_path=_run_project_path(run),
                    )
                )

            # 4. Ensure every rule has security-severity
            slim_rules = self._build_slim_rules(rules_map, rule_level_from_results)

            # 5. Assemble the final SARIF structure
            out_run: Dict[str, Any] = {
                "tool": {
                    "driver": {
                        "name": "ASH - Automated Security Helper",
                        "organization": "Amazon Web Services",
                        "version": get_ash_version(),
                        "informationUri": "https://github.com/awslabs/automated-security-helper",
                        "rules": slim_rules,
                    }
                },
                "results": slim_results,
            }

            # The base ids the run's locations may refer to, for a document
            # whose URIs were not rebased (one run, no project path). A
            # multi-run document's URIs are workspace-relative and refer to
            # none.
            if len(runs) == 1 and not _run_project_path(runs[0]):
                bases = self._original_uri_base_ids(runs[0])
                if bases:
                    out_run["originalUriBaseIds"] = bases

            # automationDetails.id is the category GitHub files an upload
            # under. The N per-project documents a workspace scan writes were
            # identical in tool identity and carried none, so uploading them
            # for one repository made each replace the previous project's
            # analysis. The project's key, when the scan has one, keeps them
            # apart; a single-directory scan is unchanged.
            category = self._workspace_project(model, runs)
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
    def _original_uri_base_ids(run: Any) -> Dict[str, Dict[str, str]]:
        """The run's ``originalUriBaseIds`` as plain dicts, uri only."""
        bases = getattr(run, "originalUriBaseIds", None)
        if not isinstance(bases, dict):
            return {}
        out: Dict[str, Dict[str, str]] = {}
        for key, location in bases.items():
            uri = getattr(location, "uri", None)
            if uri:
                out[str(key)] = {"uri": str(uri)}
        return out

    @staticmethod
    def _workspace_project(model: "AshAggregatedResults", runs: list) -> Optional[str]:
        """The workspace project this document describes, or None.

        A per-project scan records it on the model's metadata; a project's own
        run in a unified model carries it on the run's properties. A document
        over several projects is one analysis of the workspace and names none.
        """
        project = getattr(getattr(model, "metadata", None), "workspace_project", None)
        if isinstance(project, str) and project.strip():
            return project.strip()
        if len(runs) != 1:
            return None
        props = getattr(runs[0], "properties", None)
        if props is None:
            return None
        value = getattr(props, "workspace_project", None)
        if value is None:
            extra = getattr(props, "model_extra", None)
            value = extra.get("workspace_project") if isinstance(extra, dict) else None
        if isinstance(value, str) and value.strip():
            return value.strip()
        return None

    def _collect_rules(
        self, tool_component, rules_map: Dict[str, Dict[str, Any]]
    ) -> None:
        """Collect rules from a ToolComponent into the rules map."""
        if not tool_component or not tool_component.rules:
            return

        for rule in tool_component.rules:
            if rule.id in rules_map:
                continue

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

            rules_map[rule.id] = {
                "id": rule.id,
                "security_severity": security_severity,
                "default_level": default_level,
                "short_description": (
                    rule.shortDescription.text if rule.shortDescription else None
                ),
                "help_uri": str(rule.helpUri) if rule.helpUri else None,
                "help_text": (rule.help.text if rule.help else None),
                "tags": rule_tags,
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

            # Always set properties with security-severity
            properties: Dict[str, Any] = {"security-severity": severity}
            if rule_info["tags"]:
                properties["tags"] = rule_info["tags"]
            rule_dict["properties"] = properties

            slim_rules.append(rule_dict)

        return slim_rules

    def _left_out(self, result: Any) -> bool:
        """Whether *result* is kept out of the file: suppressed, under
        ``exclude_suppressed`` (the default). One test for the results list and
        the rules' scores, so a result never scores a rule it is not in."""
        return bool(
            self.config
            and self.config.options.exclude_suppressed
            and getattr(result, "suppressions", None)
        )

    def _build_slim_results(
        self,
        results: list,
        rules_map: Dict[str, Dict[str, Any]],
        rule_level_from_results: Dict[str, str],
        project_path: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Build a minimal list of result objects.

        *project_path* is the results' project's path below the workspace root
        when they come from one run of a workspace's unified model, and None for
        a single-directory scan; see :meth:`_build_slim_locations`.
        """
        slim_results = []

        for result in results:
            # Skip suppressed findings if configured
            if self._left_out(result):
                continue

            # If this result references a rule we haven't seen, create a
            # synthetic entry so the rule list stays complete. report() builds
            # the rules from rules_map after this returns.
            rule_id = _rule_id(result)
            if rule_id and rule_id not in rules_map:
                level_val = effective_sarif_level(result)
                rules_map[rule_id] = {
                    "id": rule_id,
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

            # Map level
            level_val = effective_sarif_level(result)
            result_dict["level"] = level_val

            # Kind, when it is not the default. SARIF reads an absent kind as
            # "fail", so a result ASH marked notApplicable (a cdk-nag rule that
            # was not evaluated) or pass was uploaded as a failing alert when
            # the slim copy dropped it.
            kind = getattr(result, "kind", None)
            if kind is not None:
                kind_val = _level_value(kind)
                if kind_val != "fail":
                    result_dict["kind"] = kind_val

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
            locations = self._build_slim_locations(result.locations, project_path)
            if locations:
                result_dict["locations"] = locations

            slim_results.append(result_dict)

        return slim_results

    @staticmethod
    def _slim_suppression(suppression: Any) -> Dict[str, Any]:
        """The SARIF suppression object's kind, state and justification."""
        slim: Dict[str, Any] = {
            "kind": _level_value(getattr(suppression, "kind", None))
        }
        state = getattr(suppression, "state", None)
        if state is not None:
            slim["state"] = _level_value(state)
        justification = getattr(suppression, "justification", None)
        if justification:
            slim["justification"] = str(justification)
        return slim

    def _build_slim_locations(
        self, locations: Optional[list], project_path: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Extract minimal location info.

        With *project_path*, each URI is expressed below the workspace root, the
        way the aggregator computes ``properties.workspace_uri``, because GitHub
        resolves every URI of the one document against the one repository it is
        uploaded for. A URI the helper cannot place (absolute and outside the
        project) is kept as the scanner wrote it.
        """
        if not locations:
            return []

        slim_locs = []
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
                artifact_dict["uri"] = to_workspace_uri(uri, project_path) or uri
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
                                "name": "ASH - Automated Security Helper",
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
