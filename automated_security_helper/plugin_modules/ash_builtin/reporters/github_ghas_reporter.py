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

Workspace mode: per project, never merged -- and this reporter is the reason the
whole reporter-behaviour contract exists
--------------------------------------------------------------------------------
``report()`` reads ``sarif.runs[0]`` and stops. Against the N-run SARIF a
workspace scan produces, that emits the first project's findings and drops every
other project: no exception, no warning, just a smaller file that a reviewer has
no way to tell is incomplete. A security reporter that under-reports in silence
is the worst thing this feature could ship, and it is why no workspace-level
report was emitted at all before Phase 2b.

The fix is not to make it iterate the runs. GitHub code scanning ingests a SARIF
document against *one* repository root: it resolves every result URI relative to
the repository the upload is attributed to. A merged document declaring N roots
either mis-locates results into paths that do not exist in the repo it was
uploaded for, or is rejected outright. Iterating would have replaced a silent
false negative with a silently mis-located finding, which is not better.

So the correct workspace answer is N documents, one per project, which is what
``projects/<key>/reports/ash.ghas.sarif`` already is -- each written from that
project's own single-run scan, each anchored to that project's own root, each
uploadable on its own. The workspace driver declines to invoke this reporter at
workspace level and records where the N artefacts are, so the absence of a
merged file is stated rather than silent.

``runs[0]`` is left in place deliberately. Under this contract the reporter is
never handed a multi-run model, so the index is correct for every input it can
receive, and rewriting it would imply a multi-project capability the format does
not have. ``tests/unit/workspace/test_workspace_reporting.py`` pins the
declaration, so a future change to MERGED reintroduces the bug loudly.
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

            run = sarif.runs[0]

            # 1. Collect all rules from driver and extensions, flattened
            rules_map: Dict[str, Dict[str, Any]] = {}
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
            slim_results = self._build_slim_results(
                run.results or [], rules_map, rule_level_from_results
            )

            # 4. Ensure every rule has security-severity
            slim_rules = self._build_slim_rules(rules_map, rule_level_from_results)

            # 5. Assemble the final SARIF structure
            report_dict = {
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
                                "rules": slim_rules,
                            }
                        },
                        "results": slim_results,
                    }
                ],
            }

            return json.dumps(report_dict, separators=(",", ":"))

        except Exception as e:
            # Caught rather than propagated because an exception here aborts the
            # whole report phase and costs the operator every other reporter's
            # output. Returning None rather than an empty report is what keeps the
            # failure legible; see this method's docstring.
            ASH_LOGGER.error(f"Failed to create GHAS SARIF report: {e}")
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
                security_severity = props.get(
                    "security-severity", props.get("security_severity")
                )
                if security_severity is not None:
                    security_severity = str(security_severity)
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
        1. Existing security-severity from the scanner (preserve as-is)
        2. The most severe of the rule's results, as the gate grades them
        3. Derived from rule's defaultConfiguration.level, the gate's way
        4. Default to "6.0" (Medium)

        The results come before the rule's default level because they carry
        ``issue_severity``, which the gate reads first and a rule cannot.
        """
        rule_info = rules_map.get(rule_id)

        # 1. Already has security-severity from scanner
        if rule_info and rule_info["security_severity"]:
            return rule_info["security_severity"]

        # 2. Derive from the rule's results. report() records severities here; a
        #    level is read the gate's way, so a caller passing one gets the same.
        from_results = rule_level_from_results.get(rule_id)
        if from_results:
            if from_results not in _SEVERITY_TO_SECURITY_SEVERITY:
                from_results = result_severity({"level": from_results})
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
    ) -> List[Dict[str, Any]]:
        """Build a minimal list of result objects."""
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

            # Message
            if result.message and result.message.root and result.message.root.text:
                result_dict["message"] = {"text": result.message.root.text}
            else:
                result_dict["message"] = {"text": rule_id or "Finding detected"}

            # Locations — only physical location with uri and region
            locations = self._build_slim_locations(result.locations)
            if locations:
                result_dict["locations"] = locations

            slim_results.append(result_dict)

        return slim_results

    def _build_slim_locations(self, locations: Optional[list]) -> List[Dict[str, Any]]:
        """Extract minimal location info."""
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

            phys_dict: Dict[str, Any] = {
                "artifactLocation": {"uri": str(artifact_loc.uri)}
            }

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
