# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import Literal, TYPE_CHECKING

from automated_security_helper.core.constants import ASH_REPO_URL
from automated_security_helper.schemas.sarif_schema_model import ReportingDescriptor
from automated_security_helper.utils.sarif_utils import get_finding_id

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin
import automated_security_helper.schemas.gitlab.sast as gl_sast

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
        # Get current timestamp in milliseconds since epoch
        report_time_iso = model.metadata.generated_at.rstrip("+00:00")
        ASH_LOGGER.debug(f"Report time: {report_time_iso}")

        try:
            gl_sast
            gl_status = (
                gl_sast.Status.success
                if model.metadata.summary_stats.actionable == 0
                else gl_sast.Status.failure
            )

            # Extract vulnerabilities from SARIF report
            vulnerabilities = []

            if model.sarif and model.sarif.runs and model.sarif.runs[0].results:
                ASH_LOGGER.trace("Creating rule dict")
                rule_dict = {
                    rule.id: rule
                    for rule in (model.sarif.runs[0].tool.driver.rules or [])
                }
                ASH_LOGGER.trace("Rule dict created, looping through run results")
                for result in model.sarif.runs[0].results:
                    ASH_LOGGER.trace(f"Processing result: {result.ruleId}")
                    severity_id = gl_sast.Severity.Low  # Default to LOW
                    result_rule: ReportingDescriptor | None = rule_dict.get(
                        result.ruleId, None
                    )
                    ASH_LOGGER.trace(f"Result rule: {result_rule}")

                    if result.suppressions and len(result.suppressions) > 0:
                        severity_id = gl_sast.Severity.Info
                    elif result.level:
                        level_str = str(result.level).lower()
                        if level_str == "error":
                            severity_id = gl_sast.Severity.High  # HIGH
                        elif level_str == "warning":
                            severity_id = gl_sast.Severity.Medium  # MEDIUM
                        elif level_str == "note":
                            severity_id = gl_sast.Severity.Low  # LOW
                        elif level_str == "none":
                            severity_id = gl_sast.Severity.Info

                    ASH_LOGGER.trace(f"Severity: {severity_id.value}")

                    # Add location information if available
                    ASH_LOGGER.trace("Adding location information")
                    result_location: gl_sast.Location = gl_sast.Location()
                    if result.locations and len(result.locations) > 0:
                        for location in result.locations:
                            if location.physicalLocation:
                                loc = location.physicalLocation
                                if (
                                    loc.root.artifactLocation
                                    and loc.root.artifactLocation.uri
                                ):
                                    result_location.file = loc.root.artifactLocation.uri
                                    if loc.root.region:
                                        if loc.root.region.startLine:
                                            result_location.start_line = (
                                                loc.root.region.startLine
                                            )
                                        if loc.root.region.endLine:
                                            result_location.end_line = (
                                                loc.root.region.endLine
                                            )
                    ASH_LOGGER.trace(
                        f"Location information added: {result_location.model_dump_json()}"
                    )

                    # Create vulnerability object with required fields
                    scanner_name = None
                    if result.properties and hasattr(result.properties, "scanner_name"):
                        scanner_name = result.properties.scanner_name
                    elif result.properties and hasattr(
                        result.properties, "scanner_details"
                    ):
                        if hasattr(result.properties.scanner_details, "tool_name"):
                            scanner_name = result.properties.scanner_details.tool_name
                    ASH_LOGGER.trace(f"Scanner name: {scanner_name}")
                    finding_id = get_finding_id(
                        rule_id=result.ruleId,
                        file=result_location.file,
                        start_line=result_location.start_line,
                        end_line=result_location.end_line,
                    )
                    ASH_LOGGER.trace(f"Finding ID: {finding_id}")
                    vuln = gl_sast.Vulnerability(
                        id=finding_id,
                        name=result.ruleId,
                        location=result_location,
                        category="sast",
                        description=result.message.root.text,
                        severity=severity_id,
                        identifiers=[
                            gl_sast.Identifier(
                                name=" - ".join(
                                    [
                                        item
                                        for item in [scanner_name, result.ruleId]
                                        if item
                                    ]
                                ),
                                type=(
                                    "ash_findings"
                                    if scanner_name is None
                                    else f"{scanner_name}_type"
                                ),
                                value=result.ruleId,
                                url=(
                                    str(result_rule.helpUri)
                                    if result_rule and result_rule.helpUri
                                    else None
                                ),
                            )
                        ],
                        details=(
                            result.properties.model_dump(
                                by_alias=True,
                                exclude_none=True,
                                exclude_unset=True,
                                mode="json",
                            )
                            if result.properties
                            else {}
                        ),
                        links=(
                            [
                                gl_sast.Link(
                                    name="",
                                    url=(str(result_rule.helpUri)),
                                )
                            ]
                            if result_rule and result_rule.helpUri
                            else None
                        ),
                    )

                    vulnerabilities.append(vuln)

            report = gl_sast.GitlabSastReport(
                scan=gl_sast.Scan(
                    type=gl_sast.Type.sast,
                    analyzer=gl_sast.Analyzer(
                        id="automated-security-helper",
                        name="Automated Security Helper",
                        version=get_ash_version(),
                        vendor=gl_sast.Vendor(
                            name="Amazon Web Services",
                        ),
                        url=ASH_REPO_URL,
                    ),
                    scanner=gl_sast.Scanner(
                        id="automated-security-helper",
                        name="Automated Security Helper",
                        version=get_ash_version(),
                        vendor=gl_sast.Vendor(
                            name="Amazon Web Services",
                        ),
                        url=ASH_REPO_URL,
                    ),
                    start_time=report_time_iso,
                    end_time=report_time_iso,
                    status=gl_status,
                    message="Scan completed successfully",
                ),
                vulnerabilities=vulnerabilities,
                version=get_ash_version(),
            )
            return report.model_dump_json(
                by_alias=True,
                exclude_none=True,
                exclude_unset=True,
            )

        except Exception as e:
            ASH_LOGGER.error(f"Failed to create GitLab SAST report: {str(e)}")
