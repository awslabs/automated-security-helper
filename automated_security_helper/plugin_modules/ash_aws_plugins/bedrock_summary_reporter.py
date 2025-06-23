# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import logging
import os
from collections import defaultdict
from pathlib import Path
from typing import Annotated, Dict, List, Literal, Any, TYPE_CHECKING

import boto3
import botocore.exceptions
from pydantic import Field

from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.plugin_modules.ash_aws_plugins.aws_utils import (
    retry_with_backoff,
    get_fallback_model,
    validate_bedrock_model,
)

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults


class BedrockSummaryReporterConfigOptions(ReporterOptionsBase):
    aws_region: Annotated[
        str | None,
        Field(
            pattern=r"(af|il|ap|ca|eu|me|sa|us|cn|us-gov|us-iso|us-isob)-(central|north|(north(?:east|west))|south|south(?:east|west)|east|west)-\d{1}"
        ),
    ] = os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
    aws_profile: str | None = os.environ.get("AWS_PROFILE", None)
    model_id: str = os.environ.get(
        "ASH_BEDROCK_MODEL_ID", "us.anthropic.claude-3-7-sonnet-20250219-v1:0"
    )
    temperature: float = float(os.environ.get("ASH_BEDROCK_TEMPERATURE", "0.5"))
    max_tokens: int = int(os.environ.get("ASH_BEDROCK_MAX_TOKENS", "4000"))
    top_p: float = 0.9
    max_findings_to_analyze: int = 10
    max_findings_per_severity: int = 5
    group_by_severity: bool = True
    add_section_headers: bool = True
    add_table_of_contents: bool = True
    enable_caching: bool = True
    output_markdown: bool = True
    output_file: str = "ash.bedrock.summary.md"
    # Retry configuration
    max_retries: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    # Fallback model configuration
    enable_fallback_models: bool = True
    # Output additional files with specific content
    output_executive_file: str = "bedrock-executive.md"
    output_technical_file: str = "bedrock-technical.md"
    # Include code snippets in the report
    include_code_snippets: bool = False
    # Summary style: executive, technical, or detailed
    summary_style: Literal["executive", "technical", "detailed"] = "executive"
    # Custom prompt to guide the AI analysis
    custom_prompt: str | None = None
    # List of scanner types to exclude from detailed analysis
    exclude_scanner_types: List[str] = ["SECRET"]
    # Include only actionable findings (not suppressed, above severity threshold)
    actionable_only: bool = True
    # Sections to include or exclude
    include_sections: List[str] = [
        "executive_summary",
        "risk_assessment",
        "technical_analysis",
        "remediation_guide",
        "compliance_impact",
    ]
    exclude_sections: List[str] = []
    # Industry-specific analysis
    industry_context: str | None = None
    compliance_frameworks: List[str] = []
    custom_context: str | None = None
    # Performance optimization
    summarize_findings: bool = False
    batch_processing: bool = False


class BedrockSummaryReporterConfig(ReporterPluginConfigBase):
    name: Literal["bedrock-summary-reporter"] = "bedrock-summary-reporter"
    extension: str = "bedrock.summary.md"
    enabled: bool = True
    options: BedrockSummaryReporterConfigOptions = BedrockSummaryReporterConfigOptions()


@ash_reporter_plugin
class BedrockSummaryReporter(ReporterPluginBase[BedrockSummaryReporterConfig]):
    """Generates a summary of security findings using Amazon Bedrock."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cache = {}
        self._secret_findings_exist = False

    def model_post_init(self, context):
        if self.config is None:
            self.config = BedrockSummaryReporterConfig()
        return super().model_post_init(context)

    def validate(self) -> bool:
        """Validate reporter configuration and requirements."""
        self.dependencies_satisfied = False

        # Check if AWS region is configured
        if self.config.options.aws_region is None:
            self._plugin_log(
                "AWS region is not configured. Set AWS_REGION environment variable or specify in config.",
                level=logging.WARNING,
                target_type="source",
                append_to_stream="stderr",
            )
            return self.dependencies_satisfied

        try:
            # Create AWS session
            session_params = {}
            if self.config.options.aws_profile:
                session_params["profile_name"] = self.config.options.aws_profile
            if self.config.options.aws_region:
                session_params["region_name"] = self.config.options.aws_region
            session = boto3.Session(**session_params)

            # Verify AWS credentials
            sts_client = session.client("sts")
            caller_id = sts_client.get_caller_identity()
            if "Account" not in caller_id:
                self._plugin_log(
                    "Invalid AWS credentials. Unable to get caller identity.",
                    level=logging.WARNING,
                    target_type="source",
                    append_to_stream="stderr",
                )
                return self.dependencies_satisfied

            # Check if Bedrock is available
            bedrock_client = session.client("bedrock")

            # Check if we can list models
            try:
                bedrock_client.list_foundation_models(maxResults=1)
            except botocore.exceptions.ClientError as e:
                error_code = e.response.get("Error", {}).get("Code")
                error_message = e.response.get("Error", {}).get("Message")
                self._plugin_log(
                    f"Error accessing Bedrock service: {error_code}: {error_message}",
                    level=logging.WARNING,
                    target_type="source",
                    append_to_stream="stderr",
                )
                return self.dependencies_satisfied

            # Validate the configured model
            model_id = self.config.options.model_id
            is_valid, error_message = validate_bedrock_model(bedrock_client, model_id)

            if not is_valid:
                self._plugin_log(
                    f"Configured model '{model_id}' is not valid: {error_message}",
                    level=logging.WARNING,
                    target_type="source",
                    append_to_stream="stderr",
                )

                # Check if fallback models are available
                if self.config.options.enable_fallback_models:
                    fallback_model = get_fallback_model(model_id)
                    if fallback_model and fallback_model != model_id:
                        is_valid, error_message = validate_bedrock_model(
                            bedrock_client, fallback_model
                        )
                        if is_valid:
                            self._plugin_log(
                                f"Fallback model '{fallback_model}' is available and will be used",
                                level=logging.INFO,
                                target_type="source",
                                append_to_stream="stderr",
                            )
                            # We can proceed with the fallback model
                            self.dependencies_satisfied = True
            else:
                # Primary model is valid
                self.dependencies_satisfied = True

        except botocore.exceptions.ClientError as e:
            error_code = e.response.get("Error", {}).get("Code")
            error_message = e.response.get("Error", {}).get("Message")
            self._plugin_log(
                f"AWS API error when validating Bedrock access: {error_code}: {error_message}",
                level=logging.WARNING,
                target_type="source",
                append_to_stream="stderr",
            )
        except Exception as e:
            self._plugin_log(
                f"Error when validating Bedrock access: {type(e).__name__}: {str(e)}",
                level=logging.WARNING,
                target_type="source",
                append_to_stream="stderr",
            )

        return self.dependencies_satisfied

    def report(self, model: "AshAggregatedResults") -> str:
        """Generate a summary report of findings using Amazon Bedrock."""
        if isinstance(self.config, dict):
            self.config = BedrockSummaryReporterConfig.model_validate(self.config)

        # Initialize Bedrock client
        session_params = {}
        if self.config.options.aws_profile:
            session_params["profile_name"] = self.config.options.aws_profile
        if self.config.options.aws_region:
            session_params["region_name"] = self.config.options.aws_region
        session = boto3.Session(**session_params)
        bedrock_runtime = session.client("bedrock-runtime")

        # Get findings from the SARIF model
        all_findings = []
        secret_findings = []
        indexed_findings = []

        if model.sarif and model.sarif.runs and len(model.sarif.runs) > 0:
            sarif_results = model.sarif.runs[0].results
            if sarif_results:
                for i, result in enumerate(sarif_results):
                    # Convert SARIF Result to dict
                    finding_dict = result.model_dump(
                        by_alias=True,
                        exclude_defaults=True,
                        exclude_unset=True,
                        mode="json",
                    )

                    # Add index to the finding
                    finding_dict["index"] = i + 1

                    # Extract key information for the indexed findings list
                    finding_info = {
                        "index": i + 1,
                        "rule_id": finding_dict.get("rule", {}).get("id", "Unknown"),
                        "level": finding_dict.get("level", "none"),
                        "message": (
                            finding_dict.get("message", {}).get(
                                "text", "No description available"
                            )
                            if isinstance(finding_dict.get("message"), dict)
                            else "No description available"
                        ),
                    }

                    # Extract location information
                    locations = []
                    if "locations" in finding_dict and finding_dict["locations"]:
                        for loc in finding_dict["locations"]:
                            if "physicalLocation" in loc:
                                phys_loc = loc["physicalLocation"]
                                location = {}

                                # Get file path
                                if (
                                    "artifactLocation" in phys_loc
                                    and "uri" in phys_loc["artifactLocation"]
                                ):
                                    location["file"] = phys_loc["artifactLocation"][
                                        "uri"
                                    ]

                                # Get line information
                                if "region" in phys_loc:
                                    region = phys_loc["region"]
                                    if "startLine" in region:
                                        location["startLine"] = region["startLine"]
                                    if "endLine" in region:
                                        location["endLine"] = region["endLine"]

                                locations.append(location)

                    finding_info["locations"] = locations
                    indexed_findings.append(finding_info)

                    # Check if this is from a secret scanner
                    is_secret_scanner = False
                    if (
                        "properties" in finding_dict
                        and "scanner_type" in finding_dict["properties"]
                    ):
                        is_secret_scanner = (
                            finding_dict["properties"]["scanner_type"]
                            in self.config.options.exclude_scanner_types
                        )

                    # Check if finding is actionable
                    is_actionable = True
                    if self.config.options.actionable_only:
                        # Check if suppressed
                        if (
                            "suppressions" in finding_dict
                            and finding_dict["suppressions"]
                        ):
                            is_actionable = False

                        # Check if below severity threshold
                        if (
                            "properties" in finding_dict
                            and "below_threshold" in finding_dict["properties"]
                        ):
                            if finding_dict["properties"]["below_threshold"]:
                                is_actionable = False

                    # Handle secret findings separately
                    if is_secret_scanner:
                        if is_actionable:
                            secret_findings.append(finding_dict)
                            self._secret_findings_exist = True
                    elif is_actionable:
                        all_findings.append(finding_dict)

        if not all_findings and not secret_findings:
            return "No actionable findings available in the SARIF report."

        # Generate report based on configuration
        summary = ""
        if self.config.options.add_section_headers:
            ASH_LOGGER.info("Generating structured report with section headers")
            summary = self._generate_report_with_headers(
                bedrock_runtime, model, all_findings, secret_findings, indexed_findings
            )
        else:
            ASH_LOGGER.info("Generating simple summary report")
            findings_to_analyze = all_findings[
                : self.config.options.max_findings_to_analyze
            ]
            summary = self._generate_summary(
                bedrock_runtime, model, findings_to_analyze, secret_findings
            )

        # Write summary to file if output_markdown is enabled
        if self.config.options.output_markdown:
            # Create reports directory
            reports_dir = Path(self.context.output_dir) / "reports"
            reports_dir.mkdir(parents=True, exist_ok=True)

            # Write main summary file
            output_path = reports_dir / self.config.options.output_file
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(summary)
            ASH_LOGGER.info(f"Bedrock summary written to {output_path}")

            # Extract and write executive summary if configured
            if (
                "executive_summary" in self.config.options.include_sections
                and "executive_summary" not in self.config.options.exclude_sections
            ):
                exec_summary = self._get_cached_or_generate(
                    "executive_summary_only",
                    lambda: self._generate_executive_summary(
                        bedrock_runtime, model, all_findings, secret_findings
                    ),
                )
                exec_path = reports_dir / self.config.options.output_executive_file
                with open(exec_path, "w", encoding="utf-8") as f:
                    f.write(f"# Executive Security Summary\n\n{exec_summary}")
                ASH_LOGGER.info(f"Executive summary written to {exec_path}")

            # Extract and write technical details if configured
            if (
                "technical_analysis" in self.config.options.include_sections
                and "technical_analysis" not in self.config.options.exclude_sections
            ):
                tech_summary = self._get_cached_or_generate(
                    "technical_summary_only",
                    lambda: self._generate_technical_analysis(
                        bedrock_runtime, model, all_findings
                    ),
                )
                tech_path = reports_dir / self.config.options.output_technical_file
                with open(tech_path, "w", encoding="utf-8") as f:
                    f.write(f"# Technical Security Analysis\n\n{tech_summary}")
                ASH_LOGGER.info(f"Technical analysis written to {tech_path}")

        return summary

    def _generate_report_with_headers(
        self,
        bedrock_runtime: Any,
        model: "AshAggregatedResults",
        findings: List[Dict[str, Any]],
        secret_findings: List[Dict[str, Any]],
        indexed_findings: List[Dict[str, Any]],
    ) -> str:
        """Generate a report with section headers for better organization."""
        # Apply summarization if configured
        if self.config.options.summarize_findings:
            ASH_LOGGER.info("Summarizing findings to reduce token usage")
            findings = self._summarize_findings(findings)

        # Start with a header and overview
        report = "# Security Scan Summary Report\n\n"

        # Add table of contents if configured
        if self.config.options.add_table_of_contents:
            report += "## Table of Contents\n\n"
            toc_items = []
            toc_counter = 1

            # Executive Summary
            if (
                "executive_summary" in self.config.options.include_sections
                and "executive_summary" not in self.config.options.exclude_sections
            ):
                toc_items.append(
                    f"{toc_counter}. [Executive Summary](#executive-summary)"
                )
                toc_counter += 1

            # Findings by Severity
            if (
                "technical_analysis" in self.config.options.include_sections
                and "technical_analysis" not in self.config.options.exclude_sections
            ):
                toc_items.append(
                    f"{toc_counter}. [Findings by Severity](#findings-by-severity)"
                )
                if self.config.options.group_by_severity:
                    severity_order = ["error", "warning", "note", "none"]
                    for severity in severity_order:
                        if any(
                            finding.get("level") == severity for finding in findings
                        ):
                            toc_items.append(
                                f"   - [{severity.capitalize()} Level Findings](#{severity.lower()}-level-findings)"
                            )
                toc_counter += 1

            # Secret Findings
            if (
                self._secret_findings_exist
                and "secret_findings" in self.config.options.include_sections
                and "secret_findings" not in self.config.options.exclude_sections
            ):
                toc_items.append(f"{toc_counter}. [Secret Findings](#secret-findings)")
                toc_counter += 1

            # Recommendations
            if (
                "remediation_guide" in self.config.options.include_sections
                and "remediation_guide" not in self.config.options.exclude_sections
            ):
                toc_items.append(f"{toc_counter}. [Recommendations](#recommendations)")
                toc_counter += 1

            # Risk Assessment
            if (
                "risk_assessment" in self.config.options.include_sections
                and "risk_assessment" not in self.config.options.exclude_sections
            ):
                toc_items.append(f"{toc_counter}. [Risk Assessment](#risk-assessment)")
                toc_counter += 1

            # Compliance Impact
            if (
                "compliance_impact" in self.config.options.include_sections
                and "compliance_impact" not in self.config.options.exclude_sections
                and self.config.options.compliance_frameworks
            ):
                toc_items.append(
                    f"{toc_counter}. [Compliance Impact](#compliance-impact)"
                )
                toc_counter += 1

            # Finding Details
            if "detailed_findings" not in self.config.options.exclude_sections:
                toc_items.append(f"{toc_counter}. [Finding Details](#finding-details)")

            # Add all TOC items to the report
            report += "\n".join(toc_items) + "\n\n"

        # Generate executive summary if included
        if (
            "executive_summary" in self.config.options.include_sections
            and "executive_summary" not in self.config.options.exclude_sections
        ):
            ASH_LOGGER.info("Generating executive summary")
            report += "## Executive Summary\n\n"
            exec_summary = self._get_cached_or_generate(
                "executive_summary",
                lambda: self._generate_executive_summary(
                    bedrock_runtime, model, findings, secret_findings
                ),
            )
            report += exec_summary + "\n\n"

        # Group findings by severity if configured and included
        if (
            "technical_analysis" in self.config.options.include_sections
            and "technical_analysis" not in self.config.options.exclude_sections
        ):
            report += "## Findings by Severity\n\n"

            if self.config.options.group_by_severity:
                severity_groups = defaultdict(list)
                for finding in findings:
                    severity = finding.get("severity", "none")
                    severity_groups[severity].append(finding)

                # Sort severities in order of importance
                severity_order = ["error", "warning", "note", "none"]

                # Generate section for each severity level
                for severity in severity_order:
                    if severity in severity_groups:
                        severity_findings = severity_groups[severity]
                        # Limit findings per severity to avoid overwhelming the model
                        limited_findings = severity_findings[
                            : self.config.options.max_findings_per_severity
                        ]

                        ASH_LOGGER.info(
                            f"Analyzing {len(limited_findings)} {severity} level findings"
                        )
                        report += f"### {severity.capitalize()} Level Findings\n\n"
                        severity_analysis = self._get_cached_or_generate(
                            f"severity_{severity}",
                            lambda: self._generate_severity_analysis(
                                bedrock_runtime, model, limited_findings, severity
                            ),
                        )
                        report += severity_analysis + "\n\n"
            else:
                # Process findings in batches if configured
                if (
                    self.config.options.batch_processing
                    and len(findings) > self.config.options.max_findings_to_analyze
                ):
                    ASH_LOGGER.info("Processing findings in batches")
                    findings_summary = self._get_cached_or_generate(
                        "findings_summary_batched",
                        lambda: self._process_findings_by_batch(
                            bedrock_runtime, model, findings
                        ),
                    )
                else:
                    # Simple list of findings without grouping
                    limited_findings = findings[
                        : self.config.options.max_findings_to_analyze
                    ]
                    findings_summary = self._get_cached_or_generate(
                        "findings_summary",
                        lambda: self._generate_findings_summary(
                            bedrock_runtime, model, limited_findings
                        ),
                    )
                report += findings_summary + "\n\n"

        # Add section for secret findings if they exist and included
        if (
            self._secret_findings_exist
            and "secret_findings" in self.config.options.include_sections
            and "secret_findings" not in self.config.options.exclude_sections
        ):
            report += "## Secret Findings\n\n"
            secret_advice = self._get_cached_or_generate(
                "secret_advice",
                lambda: self._generate_secret_advice(bedrock_runtime, secret_findings),
            )
            report += secret_advice + "\n\n"

        # Generate recommendations section if included
        if (
            "remediation_guide" in self.config.options.include_sections
            and "remediation_guide" not in self.config.options.exclude_sections
        ):
            ASH_LOGGER.info("Generating recommendations")
            report += "## Recommendations\n\n"
            recommendations = self._get_cached_or_generate(
                "recommendations",
                lambda: self._generate_recommendations(
                    bedrock_runtime, model, findings
                ),
            )
            report += recommendations + "\n\n"

        # Generate risk assessment if included
        if (
            "risk_assessment" in self.config.options.include_sections
            and "risk_assessment" not in self.config.options.exclude_sections
        ):
            ASH_LOGGER.info("Generating risk assessment")
            report += "## Risk Assessment\n\n"
            risk_assessment = self._get_cached_or_generate(
                "risk_assessment",
                lambda: self._generate_risk_assessment(
                    bedrock_runtime, model, findings
                ),
            )
            report += risk_assessment + "\n\n"

        # Generate compliance impact if included
        if (
            "compliance_impact" in self.config.options.include_sections
            and "compliance_impact" not in self.config.options.exclude_sections
            and self.config.options.compliance_frameworks
        ):
            ASH_LOGGER.info("Generating compliance impact analysis")
            report += "## Compliance Impact\n\n"
            compliance_impact = self._get_cached_or_generate(
                "compliance_impact",
                lambda: self._generate_compliance_impact(
                    bedrock_runtime, model, findings
                ),
            )
            report += compliance_impact + "\n\n"

        # Add detailed findings section with collapsible JSON if not excluded
        if "detailed_findings" not in self.config.options.exclude_sections:
            report += "## Finding Details\n\n"
            report += "This section contains detailed information about each finding referenced in the report.\n\n"

            # Add indexed findings table
            report += "### Finding Index Reference\n\n"
            report += (
                "| Index | Rule ID | Severity | File | Line Range | Description |\n"
            )
            report += (
                "|-------|---------|----------|------|------------|-------------|\n"
            )

            for finding in indexed_findings:
                index = finding.get("index", "")
                rule_id = finding.get("rule_id", "Unknown")
                level = finding.get("severity", "none").capitalize()

                # Get location info
                file_path = "Unknown"
                line_range = "Unknown"
                if finding.get("locations") and len(finding["locations"]) > 0:
                    location = finding["locations"][0]
                    file_path = location.get("file", "Unknown")
                    start_line = location.get("startLine", "?")
                    end_line = location.get("endLine", start_line)
                    line_range = (
                        f"{start_line}-{end_line}"
                        if start_line != end_line
                        else str(start_line)
                    )

                # Truncate message if too long
                message = finding.get("message", "No description available")
                if len(message) > 50:
                    message = message[:47] + "..."

                report += f"| {index} | {rule_id} | {level} | {file_path} | {line_range} | {message} |\n"

            report += "\n\n"

            # Add collapsible JSON for each finding
            report += "### Full Finding Details\n\n"
            report += (
                "<details>\n<summary>Click to expand full finding details</summary>\n\n"
            )

            for finding in indexed_findings:
                index = finding.get("index", "")
                rule_id = finding.get("rule_id", "Unknown")
                level = finding.get("level", "none").capitalize()

                report += f"#### Finding {index}: {rule_id} ({level})\n\n"

                # Get location info
                if finding.get("locations") and len(finding["locations"]) > 0:
                    location = finding["locations"][0]
                    file_path = location.get("file", "Unknown")
                    start_line = location.get("startLine", "?")
                    end_line = location.get("endLine", start_line)
                    report += (
                        f"**Location**: {file_path} (lines {start_line}-{end_line})\n\n"
                    )

                # Add the message
                report += f"**Description**: {finding.get('message', 'No description available')}\n\n"

                # Add code snippets if available and configured
                if self.config.options.include_code_snippets:
                    # Get the original finding from findings or secret_findings
                    original_finding = None
                    for f in findings + secret_findings:
                        if f.get("index") == index:
                            original_finding = f
                            break

                    if original_finding and "locations" in original_finding:
                        for loc in original_finding["locations"]:
                            if (
                                "physicalLocation" in loc
                                and "region" in loc["physicalLocation"]
                            ):
                                region = loc["physicalLocation"]["region"]
                                if "snippet" in region and "text" in region["snippet"]:
                                    report += f"**Code Snippet**:\n```\n{region['snippet']['text']}\n```\n\n"

                # Add collapsible JSON
                import json

                # Get the original finding from findings or secret_findings
                original_finding = None
                for f in findings + secret_findings:
                    if f.get("index") == index:
                        original_finding = f
                        break

                if original_finding:
                    report += "<details>\n<summary>Raw JSON</summary>\n\n```json\n"
                    report += json.dumps(original_finding, indent=2)
                # else:
                #     report += json.dumps(finding, indent=2)

                report += "\n```\n</details>\n\n"

            report += "</details>\n\n"

        return report

    def _get_cached_or_generate(self, key: str, generator_func):
        """Get a cached result or generate and cache it."""
        if not self.config.options.enable_caching:
            return generator_func()

        if key in self._cache:
            ASH_LOGGER.debug(f"Using cached result for {key}")
            return self._cache[key]

        result = generator_func()
        self._cache[key] = result
        return result

    def _generate_executive_summary(
        self,
        bedrock_runtime: Any,
        model: "AshAggregatedResults",
        findings: List[Dict[str, Any]],
        secret_findings: List[Dict[str, Any]],
    ) -> str:
        """Generate an executive summary of the scan results."""
        # Count findings by severity
        severity_counts = defaultdict(int)
        for finding in findings:
            severity = finding.get("level", "none")
            severity_counts[severity] += 1

        # Create a prompt for the executive summary
        user_message_content = f"""Generate an executive summary for a security scan with the following results:

SCAN OVERVIEW:
- Total actionable findings: {len(findings)}
- Secret findings: {len(secret_findings)}
- Scanners used: {", ".join([r for r in model.scanner_results])}

FINDINGS BY SEVERITY:
{", ".join([f"{severity}: {count}" for severity, count in severity_counts.items()])}

Provide a concise executive summary that highlights the most important aspects of the scan results.
"""

        return self._call_bedrock(
            bedrock_runtime,
            user_message_content,
            "You are a security expert providing a concise executive summary of security scan results.",
        )

    def _generate_severity_analysis(
        self,
        bedrock_runtime: Any,
        model: "AshAggregatedResults",
        findings: List[Dict[str, Any]],
        severity: str,
    ) -> str:
        """Generate analysis for findings of a specific severity."""
        if not findings:
            return f"No findings with {severity} level severity."

        # Create a prompt for severity-specific analysis
        user_message_content = f"""Analyze the following {severity} level security findings:

"""

        # Add findings details to the prompt
        for i, finding in enumerate(findings):
            message = finding.get("message", {})
            message_text = (
                message.get("text", "No description available")
                if isinstance(message, dict)
                else "No description available"
            )

            rule_id = ""
            if "rule" in finding and finding["rule"] and "id" in finding["rule"]:
                rule_id = finding["rule"]["id"]

            locations = []
            if "locations" in finding and finding["locations"]:
                for loc in finding["locations"]:
                    if (
                        "physicalLocation" in loc
                        and "artifactLocation" in loc["physicalLocation"]
                    ):
                        uri = loc["physicalLocation"]["artifactLocation"].get(
                            "uri", "Unknown"
                        )
                        locations.append(uri)

            user_message_content += f"""
FINDING {i + 1}:
- Rule ID: {rule_id}
- Message: {message_text}
- Locations: {", ".join(locations) if locations else "Unknown"}
"""

        user_message_content += f"""
Provide a concise analysis of these {severity} level findings, including:
1. Common patterns or issues
2. Potential impact
3. Brief remediation guidance
"""

        return self._call_bedrock(
            bedrock_runtime,
            user_message_content,
            f"You are a security expert analyzing {severity} level findings from a security scan.",
        )

    def _generate_secret_advice(
        self,
        bedrock_runtime: Any,
        secret_findings: List[Dict[str, Any]],
    ) -> str:
        """Generate advice for handling secret findings."""
        if not secret_findings:
            return "No secret findings detected."

        # Create a prompt for secret findings advice
        user_message_content = f"""The security scan has identified {len(secret_findings)} potential secrets in the codebase.

Provide a concise paragraph advising on:
1. The importance of removing secrets from code
2. Best practices for handling secrets
3. How to properly suppress false positives if needed
4. Recommended actions to take immediately

Keep the response focused and actionable.
"""

        return self._call_bedrock(
            bedrock_runtime,
            user_message_content,
            "You are a security expert providing advice on handling secrets found in code.",
        )

    def _generate_findings_summary(
        self,
        bedrock_runtime: Any,
        model: "AshAggregatedResults",
        findings: List[Dict[str, Any]],
    ) -> str:
        """Generate a summary of findings without grouping by severity."""
        if not findings:
            return "No findings to analyze."

        # Create a prompt for findings summary
        user_message_content = """Summarize the following security findings:

"""

        # Add findings details to the prompt
        for i, finding in enumerate(findings):
            message = finding.get("message", {})
            message_text = (
                message.get("text", "No description available")
                if isinstance(message, dict)
                else "No description available"
            )

            rule_id = ""
            if "rule" in finding and finding["rule"] and "id" in finding["rule"]:
                rule_id = finding["rule"]["id"]

            level = finding.get("level", "none")

            locations = []
            if "locations" in finding and finding["locations"]:
                for loc in finding["locations"]:
                    if (
                        "physicalLocation" in loc
                        and "artifactLocation" in loc["physicalLocation"]
                    ):
                        uri = loc["physicalLocation"]["artifactLocation"].get(
                            "uri", "Unknown"
                        )
                        locations.append(uri)

            user_message_content += f"""
FINDING {i + 1}:
- Rule ID: {rule_id}
- Level: {level}
- Message: {message_text}
- Locations: {", ".join(locations) if locations else "Unknown"}
"""

        user_message_content += """
Provide a concise summary of these findings, highlighting patterns and key issues.
"""

        return self._call_bedrock(
            bedrock_runtime,
            user_message_content,
            "You are a security expert summarizing findings from a security scan.",
        )

    def _generate_recommendations(
        self,
        bedrock_runtime: Any,
        model: "AshAggregatedResults",
        findings: List[Dict[str, Any]],
    ) -> str:
        """Generate recommendations based on all findings."""
        # Count findings by severity
        severity_counts = defaultdict(int)
        for finding in findings:
            severity = finding.get("level", "none")
            severity_counts[severity] += 1

        # Get a sample of the most severe findings
        severe_findings = []
        for severity in ["error", "warning"]:
            for finding in findings:
                if finding.get("level") == severity:
                    severe_findings.append(finding)
                    if (
                        len(severe_findings)
                        >= self.config.options.max_findings_to_analyze
                    ):
                        break
            if len(severe_findings) >= self.config.options.max_findings_to_analyze:
                break

        # If we don't have enough severe findings, add others
        if len(severe_findings) < self.config.options.max_findings_to_analyze:
            remaining_findings = [f for f in findings if f not in severe_findings]
            severe_findings.extend(
                remaining_findings[
                    : self.config.options.max_findings_to_analyze - len(severe_findings)
                ]
            )

        # Create a prompt for recommendations
        user_message_content = f"""Based on the security scan with the following results:

FINDINGS BY SEVERITY:
{", ".join([f"{severity}: {count}" for severity, count in severity_counts.items()])}

Sample findings:
"""

        # Add sample findings to the prompt
        for i, finding in enumerate(
            severe_findings[: self.config.options.max_findings_to_analyze]
        ):
            message = finding.get("message", {})
            message_text = (
                message.get("text", "No description available")
                if isinstance(message, dict)
                else "No description available"
            )

            rule_id = ""
            if "rule" in finding and finding["rule"] and "id" in finding["rule"]:
                rule_id = finding["rule"]["id"]

            level = finding.get("level", "none")

            locations = []
            if "locations" in finding and finding["locations"]:
                for loc in finding["locations"]:
                    if (
                        "physicalLocation" in loc
                        and "artifactLocation" in loc["physicalLocation"]
                    ):
                        uri = loc["physicalLocation"]["artifactLocation"].get(
                            "uri", "Unknown"
                        )
                        locations.append(uri)

            user_message_content += f"""
FINDING {i + 1}:
- Rule ID: {rule_id}
- Level: {level}
- Message: {message_text}
- Locations: {", ".join(locations) if locations else "Unknown"}
"""

        user_message_content += """
Provide actionable recommendations for addressing these security issues, including:
1. Prioritized next steps
2. Best practices to implement
3. Long-term security improvements
"""

        return self._call_bedrock(
            bedrock_runtime,
            user_message_content,
            "You are a security expert providing actionable recommendations based on security scan findings.",
        )

    def _call_bedrock(
        self, bedrock_runtime: Any, user_message: str, system_prompt: str
    ) -> str:
        """Make a call to Amazon Bedrock with error handling, retry logic, and fallback models."""
        # Prepare the prompt
        prepared_message = self._prepare_prompt(user_message)

        # Create messages array for the conversation
        messages = [{"role": "user", "content": [{"text": prepared_message}]}]

        # System prompt
        system = [{"text": system_prompt}]

        # Inference parameters
        inference_config = {
            "temperature": self.config.options.temperature,
            "maxTokens": self.config.options.max_tokens,
            "topP": self.config.options.top_p,
        }

        # Try with the primary model first
        model_id = self.config.options.model_id
        ASH_LOGGER.verbose(f"Attempting to use primary model: {model_id}")

        # Validate the model before trying to use it
        bedrock_client = boto3.client(
            "bedrock",
            region_name=self.config.options.aws_region,
        )
        is_valid, error_message = validate_bedrock_model(bedrock_client, model_id)

        if not is_valid:
            ASH_LOGGER.warning(
                f"Primary model {model_id} validation failed: {error_message}"
            )
            if self.config.options.enable_fallback_models:
                # Try fallback models
                return self._try_fallback_models(
                    bedrock_runtime,
                    bedrock_client,
                    model_id,
                    messages,
                    system,
                    inference_config,
                )
            else:
                return f"*Error: Primary model {model_id} validation failed: {error_message}*"

        # Try the primary model
        result = self._try_model_call(
            bedrock_runtime, model_id, messages, system, inference_config
        )

        # If the primary model failed and fallback is enabled, try fallback models
        if result.startswith("*Error") and self.config.options.enable_fallback_models:
            ASH_LOGGER.warning(
                f"Primary model {model_id} failed, trying fallback models"
            )
            return self._try_fallback_models(
                bedrock_runtime,
                bedrock_client,
                model_id,
                messages,
                system,
                inference_config,
            )

        return result

    def _try_fallback_models(
        self,
        bedrock_runtime: Any,
        bedrock_client: Any,
        failed_model_id: str,
        messages: List[Dict],
        system: List[Dict],
        inference_config: Dict,
    ) -> str:
        """Try fallback models when the primary model fails."""
        # Get a fallback model
        fallback_model = get_fallback_model(failed_model_id)
        if not fallback_model or fallback_model == failed_model_id:
            return f"*Error: No suitable fallback model found for {failed_model_id}*"

        ASH_LOGGER.info(f"Trying fallback model: {fallback_model}")

        # Validate the fallback model
        is_valid, error_message = validate_bedrock_model(bedrock_client, fallback_model)
        if not is_valid:
            ASH_LOGGER.warning(
                f"Fallback model {fallback_model} validation failed: {error_message}"
            )
            # Try another fallback model recursively
            return self._try_fallback_models(
                bedrock_runtime,
                bedrock_client,
                fallback_model,
                messages,
                system,
                inference_config,
            )

        # Try the fallback model
        fallback_result = self._try_model_call(
            bedrock_runtime, fallback_model, messages, system, inference_config
        )

        # If the fallback succeeded, use its result
        if not fallback_result.startswith("*Error"):
            ASH_LOGGER.info(f"Fallback model {fallback_model} succeeded")
            return fallback_result
        else:
            ASH_LOGGER.warning(f"Fallback model {fallback_model} also failed")
            # Try another fallback model recursively
            return self._try_fallback_models(
                bedrock_runtime,
                bedrock_client,
                fallback_model,
                messages,
                system,
                inference_config,
            )

    def _prepare_prompt(self, user_message: str) -> str:
        """Prepare the prompt with custom context and industry information."""
        # Apply custom prompt if provided
        if self.config.options.custom_prompt:
            user_message = f"{self.config.options.custom_prompt}\n\n{user_message}"

        # Add industry context if provided
        if (
            self.config.options.industry_context
            or self.config.options.compliance_frameworks
        ):
            context_info = "\nADDITIONAL CONTEXT:\n"
            if self.config.options.industry_context:
                context_info += f"- Industry: {self.config.options.industry_context}\n"
            if self.config.options.compliance_frameworks:
                context_info += f"- Compliance frameworks: {', '.join(self.config.options.compliance_frameworks)}\n"
            if self.config.options.custom_context:
                context_info += f"\n{self.config.options.custom_context}"
            user_message += context_info

        return user_message

    @retry_with_backoff()
    def _invoke_bedrock_model(self, bedrock_runtime: Any, **converse_args) -> dict:
        """Invoke the Bedrock model with retry logic."""
        return bedrock_runtime.converse(**converse_args)

    def _try_model_call(
        self,
        bedrock_runtime: Any,
        model_id: str,
        messages: List[Dict],
        system: List[Dict],
        inference_config: Dict,
    ) -> str:
        """Try to call a specific model with error handling."""
        try:
            # Additional model fields - customize based on model type
            additional_model_fields = {}
            if "claude" in model_id.lower():
                additional_model_fields["top_k"] = 200

            # Prepare the converse API call
            converse_args = {
                "modelId": model_id,
                "messages": messages,
                "system": system,
                "inferenceConfig": inference_config,
            }

            # Only add additionalModelRequestFields if we have any
            if additional_model_fields:
                converse_args["additionalModelRequestFields"] = additional_model_fields

            ASH_LOGGER.debug(f"Invoking Bedrock model {model_id}")

            # Use the converse API with retry logic
            response = self._invoke_bedrock_model(bedrock_runtime, **converse_args)

            # Extract the response content
            if response and "output" in response and "message" in response["output"]:
                message = response["output"]["message"]
                if "content" in message:
                    content_list = message["content"]
                    # Combine all text parts
                    full_text = ""
                    for content_item in content_list:
                        if "text" in content_item:
                            full_text += content_item["text"]
                    ASH_LOGGER.debug(
                        f"Successfully generated content with model {model_id}"
                    )
                    return full_text
                else:
                    ASH_LOGGER.warning(f"No content in message from model {model_id}")
            else:
                ASH_LOGGER.warning(
                    f"Invalid response structure from model {model_id}: {response}"
                )

            return "*Error: Unable to generate content from Bedrock response.*"
        except botocore.exceptions.ClientError as e:
            error_code = e.response.get("Error", {}).get("Code")
            error_message = e.response.get("Error", {}).get("Message")

            self._plugin_log(
                f"Bedrock API error ({error_code}) with model {model_id}: {error_message}",
                level=logging.WARNING,
                append_to_stream="stderr",
            )

            # Provide more specific error messages based on error code
            if error_code == "AccessDeniedException":
                return f"*Error: Access denied to model {model_id}. Check IAM permissions.*"
            elif error_code == "ResourceNotFoundException":
                return f"*Error: Model {model_id} not found. Check if the model ID is correct and available in your region.*"
            elif error_code == "ValidationException":
                return (
                    f"*Error: Validation error with model {model_id}: {error_message}*"
                )
            elif (
                error_code == "ThrottlingException"
                or error_code == "TooManyRequestsException"
            ):
                return f"*Error: Rate limit exceeded for model {model_id}. Try again later.*"
            else:
                return f"*Error: {error_message}*"
        except Exception as e:
            error_type = type(e).__name__
            self._plugin_log(
                f"Error calling Bedrock model {model_id}: {error_type}: {str(e)}",
                level=logging.WARNING,
                append_to_stream="stderr",
            )
            return f"*Error generating content with model {model_id}: {error_type}: {str(e)}*"

    def _generate_summary(
        self,
        bedrock_runtime: Any,
        model: "AshAggregatedResults",
        findings: List[Dict[str, Any]],
        secret_findings: List[Dict[str, Any]],
    ) -> str:
        """Generate a summary of findings using Amazon Bedrock (legacy method)."""
        # Create a prompt for the model
        user_message_content = f"""I need a security summary report for a codebase scan.

SCAN OVERVIEW:
- Total actionable findings: {len(findings)}
- Secret findings: {len(secret_findings)}
- Scanners used: {", ".join([r for r in model.scanner_results])}

FINDINGS SUMMARY:
"""

        # Add findings details to the prompt
        for i, finding in enumerate(
            findings[: self.config.options.max_findings_to_analyze]
        ):
            message = finding.get("message", {})
            message_text = (
                message.get("text", "No description available")
                if isinstance(message, dict)
                else "No description available"
            )

            rule_id = ""
            if "rule" in finding and finding["rule"] and "id" in finding["rule"]:
                rule_id = finding["rule"]["id"]

            level = finding.get("level", "none")

            locations = []
            if "locations" in finding and finding["locations"]:
                for loc in finding["locations"]:
                    if (
                        "physicalLocation" in loc
                        and "artifactLocation" in loc["physicalLocation"]
                    ):
                        uri = loc["physicalLocation"]["artifactLocation"].get(
                            "uri", "Unknown"
                        )
                        locations.append(uri)

            user_message_content += f"""
FINDING {i + 1}:
- Rule ID: {rule_id}
- Level: {level}
- Message: {message_text}
- Locations: {", ".join(locations) if locations else "Unknown"}
"""

        # Add note about secret findings if they exist
        if secret_findings:
            user_message_content += f"""
IMPORTANT: The scan also identified {len(secret_findings)} potential secrets in the codebase that should be addressed.
"""

        user_message_content += """
Please provide:
1. An executive summary of the security scan results
2. A breakdown of findings by severity
3. Key risk areas identified
4. Recommended next steps for remediation
5. If secrets were found, include a paragraph about handling secrets properly

Format your response in markdown.
"""

        return self._call_bedrock(
            bedrock_runtime,
            user_message_content,
            "You are a security expert specializing in code security analysis. Your task is to analyze security findings from the Automated Security Helper (ASH) tool and provide a concise, actionable summary report.",
        )

    def _generate_technical_analysis(
        self,
        bedrock_runtime: Any,
        model: "AshAggregatedResults",
        findings: List[Dict[str, Any]],
    ) -> str:
        """Generate a detailed technical analysis of findings."""
        if not findings:
            return "No findings to analyze."

        # Create a prompt for technical analysis
        user_message_content = """Generate a detailed technical analysis of the following security findings:

"""
        # Add findings details to the prompt
        for i, finding in enumerate(
            findings[: self.config.options.max_findings_to_analyze]
        ):
            message = finding.get("message", {})
            message_text = (
                message.get("text", "No description available")
                if isinstance(message, dict)
                else "No description available"
            )

            rule_id = ""
            if "rule" in finding and finding["rule"] and "id" in finding["rule"]:
                rule_id = finding["rule"]["id"]

            level = finding.get("level", "none")

            locations = []
            code_snippets = []
            if "locations" in finding and finding["locations"]:
                for loc in finding["locations"]:
                    if (
                        "physicalLocation" in loc
                        and "artifactLocation" in loc["physicalLocation"]
                    ):
                        uri = loc["physicalLocation"]["artifactLocation"].get(
                            "uri", "Unknown"
                        )
                        locations.append(uri)

                        # Extract code snippets if available and configured
                        if (
                            self.config.options.include_code_snippets
                            and "region" in loc["physicalLocation"]
                        ):
                            region = loc["physicalLocation"]["region"]
                            if "snippet" in region and "text" in region["snippet"]:
                                code_snippets.append(region["snippet"]["text"])

            user_message_content += f"""
FINDING {i + 1}:
- Rule ID: {rule_id}
- Level: {level}
- Message: {message_text}
- Locations: {", ".join(locations) if locations else "Unknown"}
"""
            if code_snippets and self.config.options.include_code_snippets:
                user_message_content += (
                    "- Code Snippet:\n```\n" + "\n".join(code_snippets[:3]) + "\n```\n"
                )

        user_message_content += """
Provide a detailed technical analysis including:
1. Root cause analysis for each finding
2. Specific remediation steps with code examples where appropriate
3. Testing recommendations to verify fixes
4. Security best practices related to these issues
"""

        return self._call_bedrock(
            bedrock_runtime,
            user_message_content,
            "You are a security expert providing detailed technical analysis of security findings.",
        )

    def _generate_risk_assessment(
        self,
        bedrock_runtime: Any,
        model: "AshAggregatedResults",
        findings: List[Dict[str, Any]],
    ) -> str:
        """Generate a risk assessment based on findings."""
        if not findings:
            return "No findings to assess risk."

        # Count findings by severity
        severity_counts = defaultdict(int)
        for finding in findings:
            severity = finding.get("level", "none")
            severity_counts[severity] += 1

        # Create a prompt for risk assessment
        user_message_content = f"""Generate a risk assessment based on the following security scan results:

FINDINGS BY SEVERITY:
{", ".join([f"{severity}: {count}" for severity, count in severity_counts.items()])}

Sample findings:
"""

        # Add sample findings to the prompt
        for i, finding in enumerate(findings[:5]):
            message = finding.get("message", {})
            message_text = (
                message.get("text", "No description available")
                if isinstance(message, dict)
                else "No description available"
            )

            rule_id = ""
            if "rule" in finding and finding["rule"] and "id" in finding["rule"]:
                rule_id = finding["rule"]["id"]

            level = finding.get("level", "none")

            user_message_content += f"""
FINDING {i + 1}:
- Rule ID: {rule_id}
- Level: {level}
- Message: {message_text}
"""

        user_message_content += """
Provide a risk assessment including:
1. Overall risk score (LOW/MEDIUM/HIGH/CRITICAL)
2. Risk breakdown by severity
3. Compliance impact assessment
4. Business impact analysis
"""

        # Add compliance frameworks if specified
        if self.config.options.compliance_frameworks:
            user_message_content += f"\nSpecifically address compliance impact for: {', '.join(self.config.options.compliance_frameworks)}"

        return self._call_bedrock(
            bedrock_runtime,
            user_message_content,
            "You are a security expert providing risk assessment based on security scan findings.",
        )

    def _summarize_findings(
        self,
        findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Summarize findings to reduce token usage."""
        if not self.config.options.summarize_findings or not findings:
            return findings

        # Group findings by rule ID
        grouped_findings = defaultdict(list)
        for finding in findings:
            rule_id = "unknown"
            if "rule" in finding and finding["rule"] and "id" in finding["rule"]:
                rule_id = finding["rule"]["id"]
            grouped_findings[rule_id].append(finding)

        # Create summarized findings
        summarized = []
        for rule_id, rule_findings in grouped_findings.items():
            if len(rule_findings) == 1:
                summarized.append(rule_findings[0])
            else:
                # Create a summary finding
                base_finding = rule_findings[0].copy()
                locations = []

                # Collect all locations
                for finding in rule_findings:
                    if "locations" in finding and finding["locations"]:
                        for loc in finding["locations"]:
                            if (
                                "physicalLocation" in loc
                                and "artifactLocation" in loc["physicalLocation"]
                            ):
                                uri = loc["physicalLocation"]["artifactLocation"].get(
                                    "uri", "Unknown"
                                )
                                if uri not in [loc.get("uri") for loc in locations]:
                                    locations.append({"uri": uri})

                # Update the base finding
                if "message" in base_finding and isinstance(
                    base_finding["message"], dict
                ):
                    base_finding["message"]["text"] = (
                        f"Found {len(rule_findings)} instances of this issue"
                    )

                # Add a note about summarization
                if "properties" not in base_finding:
                    base_finding["properties"] = {}
                base_finding["properties"]["summarized"] = True
                base_finding["properties"]["original_count"] = len(rule_findings)

                summarized.append(base_finding)

        return summarized

    def _process_findings_by_batch(
        self,
        bedrock_runtime: Any,
        model: "AshAggregatedResults",
        findings: List[Dict[str, Any]],
    ) -> str:
        """Process findings in batches to optimize token usage."""
        if (
            not self.config.options.batch_processing
            or len(findings) <= self.config.options.max_findings_to_analyze
        ):
            # If batch processing is disabled or not needed, use the standard method
            return self._generate_findings_summary(
                bedrock_runtime,
                model,
                findings[: self.config.options.max_findings_to_analyze],
            )

        # Process in batches
        batch_size = self.config.options.max_findings_to_analyze
        batches = [
            findings[i : i + batch_size] for i in range(0, len(findings), batch_size)
        ]

        batch_results = []
        for i, batch in enumerate(batches):
            ASH_LOGGER.info(f"Processing batch {i + 1} of {len(batches)}")
            batch_summary = self._generate_findings_summary(
                bedrock_runtime, model, batch
            )
            batch_results.append(batch_summary)

        # Combine batch results
        combined_prompt = f"""Synthesize the following batch summaries into a cohesive overall summary:

{chr(10).join([f"BATCH {i + 1}:\n{summary}" for i, summary in enumerate(batch_results)])}

Provide a unified summary that captures the key insights from all batches.
"""

        return self._call_bedrock(
            bedrock_runtime,
            combined_prompt,
            "You are a security expert synthesizing multiple security scan batch summaries.",
        )

    def _generate_compliance_impact(
        self,
        bedrock_runtime: Any,
        model: "AshAggregatedResults",
        findings: List[Dict[str, Any]],
    ) -> str:
        """Generate compliance impact analysis based on findings."""
        if not findings or not self.config.options.compliance_frameworks:
            return "No compliance frameworks specified for analysis."

        # Count findings by severity
        severity_counts = defaultdict(int)
        for finding in findings:
            severity = finding.get("level", "none")
            severity_counts[severity] += 1

        # Create a prompt for compliance impact analysis
        user_message_content = f"""Generate a compliance impact analysis for the following security scan results:

FINDINGS BY SEVERITY:
{", ".join([f"{severity}: {count}" for severity, count in severity_counts.items()])}

COMPLIANCE FRAMEWORKS TO ANALYZE:
{", ".join(self.config.options.compliance_frameworks)}

Sample findings:
"""

        # Add sample findings to the prompt
        for i, finding in enumerate(findings[:5]):
            message = finding.get("message", {})
            message_text = (
                message.get("text", "No description available")
                if isinstance(message, dict)
                else "No description available"
            )

            rule_id = ""
            if "rule" in finding and finding["rule"] and "id" in finding["rule"]:
                rule_id = finding["rule"]["id"]

            level = finding.get("level", "none")

            user_message_content += f"""
FINDING {i + 1}:
- Rule ID: {rule_id}
- Level: {level}
- Message: {message_text}
"""

        user_message_content += f"""
Provide a compliance impact analysis including:
1. How these findings may impact compliance with each framework ({", ".join(self.config.options.compliance_frameworks)})
2. Specific compliance requirements that may be violated
3. Recommended actions to maintain or restore compliance
"""

        # Add industry context if provided
        if self.config.options.industry_context:
            user_message_content += f"\nConsider the industry context: {self.config.options.industry_context}"

        return self._call_bedrock(
            bedrock_runtime,
            user_message_content,
            "You are a compliance expert analyzing security findings against regulatory frameworks.",
        )
