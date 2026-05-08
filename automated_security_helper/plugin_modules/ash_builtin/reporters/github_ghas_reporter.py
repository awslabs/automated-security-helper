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
"""

import json
from typing import Any, Dict, List, Literal, Optional, TYPE_CHECKING

from pydantic import Field
from typing_extensions import Annotated

from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin
from automated_security_helper.utils.get_ash_version import get_ash_version
from automated_security_helper.utils.log import ASH_LOGGER

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults

# Mapping from SARIF level to security-severity score.
# These scores place findings into GitHub's severity buckets:
#   9.0-10.0 = Critical, 7.0-8.9 = High, 4.0-6.9 = Medium, 0.1-3.9 = Low
_LEVEL_TO_SECURITY_SEVERITY: Dict[str, str] = {
    "error": "8.0",
    "warning": "6.0",
    "note": "3.0",
    "none": "1.0",
}


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
    """Configuration for the GitHub Advanced Security SARIF reporter."""

    name: Literal["github-ghas"] = "github-ghas"
    extension: str = "ghas.sarif"
    enabled: bool = True
    options: GHASReporterConfigOptions = GHASReporterConfigOptions()


@ash_reporter_plugin
class GHASReporter(ReporterPluginBase[GHASReporterConfig]):
    """Produces a SARIF report optimized for GitHub Advanced Security Code Scanning."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = GHASReporterConfig()
        return super().model_post_init(context)

    def report(self, model: "AshAggregatedResults") -> str:
        """Generate a GitHub-optimized SARIF report."""
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

            # 2. Build a level lookup from results (for rules that have no
            #    defaultConfiguration.level, we infer from the result level)
            rule_level_from_results: Dict[str, str] = {}
            for result in run.results or []:
                if result.ruleId and result.ruleId not in rule_level_from_results:
                    level_val = result.level if result.level else "error"
                    rule_level_from_results[result.ruleId] = str(level_val)

            # 3. Ensure every rule has security-severity
            slim_rules = self._build_slim_rules(rules_map, rule_level_from_results)

            # 4. Build slim results (excluding suppressed if configured)
            slim_results = self._build_slim_results(
                run.results or [], rules_map, rule_level_from_results
            )

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
            ASH_LOGGER.error(f"Failed to create GHAS SARIF report: {e}")
            return self._empty_report()

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
                default_level = str(rule.defaultConfiguration.level)

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
        2. Derived from rule's defaultConfiguration.level
        3. Derived from the result.level of findings referencing this rule
        4. Default to "6.0" (Medium)
        """
        rule_info = rules_map.get(rule_id)

        # 1. Already has security-severity from scanner
        if rule_info and rule_info["security_severity"]:
            return rule_info["security_severity"]

        # 2. Derive from rule's defaultConfiguration.level
        if rule_info and rule_info["default_level"]:
            return _LEVEL_TO_SECURITY_SEVERITY.get(rule_info["default_level"], "6.0")

        # 3. Derive from result level
        result_level = rule_level_from_results.get(rule_id)
        if result_level:
            return _LEVEL_TO_SECURITY_SEVERITY.get(result_level, "6.0")

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
            if self.config and self.config.options.exclude_suppressed:
                if (
                    hasattr(result, "suppressions")
                    and result.suppressions
                    and len(result.suppressions) > 0
                ):
                    continue

            # If this result references a rule we haven't seen, create a
            # synthetic entry so the rule list stays complete
            if result.ruleId and result.ruleId not in rules_map:
                level_val = str(result.level) if result.level else "error"
                rules_map[result.ruleId] = {
                    "id": result.ruleId,
                    "security_severity": None,
                    "default_level": None,
                    "short_description": None,
                    "help_uri": None,
                    "help_text": None,
                    "tags": [],
                }
                rule_level_from_results.setdefault(result.ruleId, level_val)

            # Build slim result
            result_dict: Dict[str, Any] = {}

            if result.ruleId:
                result_dict["ruleId"] = result.ruleId

            # Map level
            level_val = str(result.level) if result.level else "error"
            result_dict["level"] = level_val

            # Message
            if result.message and result.message.root and result.message.root.text:
                result_dict["message"] = {"text": result.message.root.text}
            else:
                result_dict["message"] = {"text": result.ruleId or "Finding detected"}

            # Locations — only physical location with uri and region
            locations = self._build_slim_locations(result.locations)
            if locations:
                result_dict["locations"] = locations

            slim_results.append(result_dict)

        # After processing all results, add any synthetic rules we created
        # back into the slim rules list (handled by caller via rules_map mutation)

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
