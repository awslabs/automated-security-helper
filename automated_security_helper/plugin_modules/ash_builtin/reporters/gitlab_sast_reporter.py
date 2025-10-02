# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
from typing import Literal, TYPE_CHECKING

from automated_security_helper.utils.sarif_utils import get_finding_id

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin

from automated_security_helper.utils.get_ash_version import get_ash_version
from automated_security_helper.utils.log import ASH_LOGGER


class GitLabSASTReporterConfigOptions(ReporterOptionsBase):
    pass


class GitLabSASTReporterConfig(ReporterPluginConfigBase):
    name: Literal["gitlab-sast"] = "gitlab-sast"
    extension: str = "gl-sast-report.json"
    enabled: bool = True
    options: GitLabSASTReporterConfigOptions = GitLabSASTReporterConfigOptions()


@ash_reporter_plugin
class GitLabSASTReporter(ReporterPluginBase[GitLabSASTReporterConfig]):
    """Formats vulnerability findings report as GitLab SAST format."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = GitLabSASTReporterConfig()
        return super().model_post_init(context)

    def report(self, model: "AshAggregatedResults") -> str:
        try:
            # Extract vulnerabilities from SARIF report
            vulnerabilities = []

            if model.sarif and model.sarif.runs and model.sarif.runs[0].results:
                ASH_LOGGER.trace("Creating rule dict")
                for result in model.sarif.runs[0].results:
                    ASH_LOGGER.trace(f"Processing result: {result.ruleId}")

                    # Determine severity
                    severity = None
                    if result.level:
                        level_str = str(result.level).lower()
                        if level_str == "error":
                            severity = "High"
                        elif level_str == "warning":
                            severity = "Medium"
                        elif level_str == "note":
                            severity = "Low"
                        elif level_str == "none":
                            severity = None  # Don't include severity for info level

                    # Get location information
                    file_path = None
                    start_line = None
                    raw_source_code_extract = None

                    if result.locations and len(result.locations) > 0:
                        for location in result.locations:
                            if location.physicalLocation:
                                loc = location.physicalLocation
                                if (
                                    loc.root.artifactLocation
                                    and loc.root.artifactLocation.uri
                                ):
                                    file_path = loc.root.artifactLocation.uri
                                    if loc.root.region:
                                        if loc.root.region.startLine:
                                            start_line = loc.root.region.startLine
                                        if (
                                            loc.root.region.snippet
                                            and loc.root.region.snippet.text
                                        ):
                                            raw_source_code_extract = (
                                                loc.root.region.snippet.text
                                            )

                    # Get scanner name from properties
                    scanner_name = None
                    if result.properties:
                        props_dict = result.properties.model_dump(
                            by_alias=True,
                            exclude_none=True,
                            exclude_unset=True,
                            mode="json",
                        )

                        # Try to extract scanner name from various property fields
                        if "scanner_name" in props_dict:
                            scanner_name = props_dict["scanner_name"]
                        elif "scanner_details" in props_dict and isinstance(
                            props_dict["scanner_details"], dict
                        ):
                            scanner_details = props_dict["scanner_details"]
                            if "tool_name" in scanner_details:
                                scanner_name = scanner_details["tool_name"]
                        elif "tags" in props_dict and isinstance(
                            props_dict["tags"], list
                        ):
                            # Look for tool_name in tags
                            for tag in props_dict["tags"]:
                                if isinstance(tag, str) and tag.startswith(
                                    "tool_name::"
                                ):
                                    scanner_name = tag.replace("tool_name::", "")
                                    break

                    # Generate finding ID
                    finding_id = get_finding_id(
                        rule_id=result.ruleId,
                        file=file_path,
                        start_line=start_line,
                        end_line=start_line,
                    )

                    # Create identifiers
                    identifiers = []

                    # Rule identifier
                    if scanner_name:
                        identifiers.append(
                            {
                                "type": f"{scanner_name}-rule",
                                "name": f"{scanner_name} Rule {result.ruleId}",
                                "value": result.ruleId,
                            }
                        )

                    # Scanner identifier
                    if scanner_name:
                        identifiers.append(
                            {
                                "type": "scanner",
                                "name": f"{scanner_name} Scanner",
                                "value": scanner_name,
                            }
                        )

                    # ASH finding ID identifier
                    identifiers.append(
                        {
                            "type": "ash-finding-id",
                            "name": "ASH Finding ID",
                            "value": finding_id,
                        }
                    )

                    # Create location object
                    location = {"file": file_path, "start_line": start_line}

                    # Create details object
                    details = {}

                    # Add scanner detail
                    if scanner_name:
                        details["scanner"] = {
                            "name": "Scanner",
                            "type": "text",
                            "value": scanner_name,
                        }

                    # Add rule ID detail
                    details["rule_id"] = {
                        "name": "Rule ID",
                        "type": "text",
                        "value": result.ruleId,
                    }

                    # Add properties as JSON string
                    if result.properties:
                        props_dict = result.properties.model_dump(
                            by_alias=True,
                            exclude_none=True,
                            exclude_unset=True,
                            mode="json",
                        )
                        details["properties"] = {
                            "name": "Properties",
                            "type": "text",
                            "value": json.dumps(props_dict, indent=2),
                        }

                    # Add raw SARIF data
                    raw_sarif_data = result.model_dump(
                        by_alias=True,
                        exclude_none=True,
                        exclude_unset=True,
                        mode="json",
                    )
                    details["raw_data"] = {
                        "name": "Raw Data",
                        "type": "code",
                        "value": json.dumps(raw_sarif_data, separators=(",", ":")),
                        "lang": "json",
                    }

                    # Add tags as comma-separated string
                    if (
                        result.properties
                        and "tags" in props_dict
                        and isinstance(props_dict["tags"], list)
                    ):
                        details["tags"] = {
                            "name": "Tags",
                            "type": "text",
                            "value": ", ".join(str(tag) for tag in props_dict["tags"]),
                        }

                    # Add detected_at timestamp
                    details["detected_at"] = {
                        "name": "Detected At",
                        "type": "text",
                        "value": model.metadata.generated_at,
                    }

                    # Add location details
                    if start_line:
                        details["location_details"] = {
                            "name": "Location Details",
                            "type": "text",
                            "value": f"Line {start_line}",
                        }

                    # Create vulnerability object
                    vuln = {
                        "id": finding_id,
                        "identifiers": identifiers,
                        "location": location,
                        "name": result.ruleId,
                        "description": result.message.root.text,
                        "raw_source_code_extract": raw_source_code_extract
                        or f"Secret of type {result.ruleId.replace('SECRET-', '').replace('-', ' ').title()} detected"
                        if result.ruleId.startswith("SECRET-")
                        else result.message.root.text,
                        "details": details,
                    }

                    # Only add severity if it's not None (info level findings don't have severity)
                    if severity:
                        vuln["severity"] = severity

                    vulnerabilities.append(vuln)

            # Get current timestamp
            report_time_iso = model.metadata.generated_at.split("+")[0]

            # Determine scan status
            scan_status = (
                "success" if model.metadata.summary_stats.actionable == 0 else "failure"
            )

            # Create the final report structure matching the reference
            report_dict = {
                "version": "15.2.2",
                "vulnerabilities": vulnerabilities,
                "scan": {
                    "analyzer": {
                        "id": "ash",
                        "name": "Automated Security Helper (ASH)",
                        "version": get_ash_version(),
                        "vendor": {"name": "ASH"},
                        "url": "https://github.com/aws-samples/automated-security-helper",
                    },
                    "scanner": {
                        "id": "automated-security-helper",
                        "name": "Automated Security Helper",
                        "version": get_ash_version(),
                        "vendor": {"name": "ASH"},
                        "url": "https://github.com/awslabs/automated-security-helper",
                    },
                    "type": "sast",
                    "start_time": report_time_iso,
                    "end_time": report_time_iso,
                    "status": scan_status,
                },
            }

            return json.dumps(report_dict, separators=(",", ":"))

        except Exception as e:
            ASH_LOGGER.error(f"Failed to create GitLab SAST report: {str(e)}")
