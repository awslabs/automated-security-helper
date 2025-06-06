# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import logging
import os
from collections import defaultdict
from pathlib import Path
from typing import Annotated, Dict, List, Literal, Any, TYPE_CHECKING

import boto3
from pydantic import Field

from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin
from automated_security_helper.utils.log import ASH_LOGGER

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
    model_id: str = "us.amazon.nova-pro-v1:0"
    temperature: float = 0.5
    max_findings_to_analyze: int = 10
    max_findings_per_severity: int = 5
    group_by_severity: bool = True
    add_section_headers: bool = True
    add_table_of_contents: bool = True
    enable_caching: bool = True
    output_markdown: bool = True
    output_file: str = "ash.bedrock.summary.md"
    # List of scanner types to exclude from detailed analysis
    exclude_scanner_types: List[str] = ["SECRET"]
    # Include only actionable findings (not suppressed, above severity threshold)
    actionable_only: bool = True


class BedrockSummaryReporterConfig(ReporterPluginConfigBase):
    name: Literal["bedrock-summary"] = "bedrock-summary"
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
        if self.config.options.aws_region is None:
            return self.dependencies_satisfied
        try:
            session = boto3.Session(
                profile_name=self.config.options.aws_profile,
                region_name=self.config.options.aws_region,
            )
            sts_client = session.client("sts")
            caller_id = sts_client.get_caller_identity()

            # Check if Bedrock is available
            bedrock_client = session.client("bedrock")
            bedrock_client.list_foundation_models(maxResults=1)

            self.dependencies_satisfied = "Account" in caller_id
        except Exception as e:
            self._plugin_log(
                f"Error when validating Bedrock access: {e}",
                level=logging.WARNING,
                target_type="source",
                append_to_stream="stderr",
            )
        finally:
            return self.dependencies_satisfied

    def report(self, model: "AshAggregatedResults") -> str:
        """Generate a summary report of findings using Amazon Bedrock."""
        if isinstance(self.config, dict):
            self.config = BedrockSummaryReporterConfig.model_validate(self.config)

        # Initialize Bedrock client
        session = boto3.Session(
            profile_name=self.config.options.aws_profile,
            region_name=self.config.options.aws_region,
        )
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
            output_path = (
                Path(self.context.output_dir)
                / "reports"
                / self.config.options.output_file
            )
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(summary)

            ASH_LOGGER.info(f"Bedrock summary written to {output_path}")

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
        # Start with a header and overview
        report = "# Security Scan Summary Report\n\n"

        # Add table of contents if configured
        if self.config.options.add_table_of_contents:
            report += "## Table of Contents\n\n"
            report += "1. [Executive Summary](#executive-summary)\n"
            report += "2. [Findings by Severity](#findings-by-severity)\n"
            if self.config.options.group_by_severity:
                severity_order = ["error", "warning", "note", "none"]
                for severity in severity_order:
                    if any(finding.get("level") == severity for finding in findings):
                        report += f"   - [{severity.capitalize()} Level Findings](#{severity.lower()}-level-findings)\n"
            if self._secret_findings_exist:
                report += "3. [Secret Findings](#secret-findings)\n"
                report += "4. [Recommendations](#recommendations)\n"
                report += "5. [Finding Details](#finding-details)\n\n"
            else:
                report += "3. [Recommendations](#recommendations)\n"
                report += "4. [Finding Details](#finding-details)\n\n"

        # Generate executive summary
        ASH_LOGGER.info("Generating executive summary")
        report += "## Executive Summary\n\n"
        exec_summary = self._get_cached_or_generate(
            "executive_summary",
            lambda: self._generate_executive_summary(
                bedrock_runtime, model, findings, secret_findings
            ),
        )
        report += exec_summary + "\n\n"

        # Group findings by severity if configured
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
            # Simple list of findings without grouping
            limited_findings = findings[: self.config.options.max_findings_to_analyze]
            findings_summary = self._get_cached_or_generate(
                "findings_summary",
                lambda: self._generate_findings_summary(
                    bedrock_runtime, model, limited_findings
                ),
            )
            report += findings_summary + "\n\n"

        # Add section for secret findings if they exist
        if self._secret_findings_exist:
            report += "## Secret Findings\n\n"
            secret_advice = self._get_cached_or_generate(
                "secret_advice",
                lambda: self._generate_secret_advice(bedrock_runtime, secret_findings),
            )
            report += secret_advice + "\n\n"

        # Generate recommendations section
        ASH_LOGGER.info("Generating recommendations")
        report += "## Recommendations\n\n"
        recommendations = self._get_cached_or_generate(
            "recommendations",
            lambda: self._generate_recommendations(bedrock_runtime, model, findings),
        )
        report += recommendations + "\n\n"

        # Add detailed findings section with collapsible JSON
        report += "## Finding Details\n\n"
        report += "This section contains detailed information about each finding referenced in the report.\n\n"

        # Add indexed findings table
        report += "### Finding Index Reference\n\n"
        report += "| Index | Rule ID | Severity | File | Line Range | Description |\n"
        report += "|-------|---------|----------|------|------------|-------------|\n"

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
        """Make a call to Amazon Bedrock with error handling."""
        try:
            # Create messages array for the conversation
            messages = [{"role": "user", "content": [{"text": user_message}]}]

            # System prompt
            system = [{"text": system_prompt}]

            # Inference parameters
            inference_config = {"temperature": self.config.options.temperature}

            # Additional model fields - customize based on model type
            additional_model_fields = {}
            if "claude" in self.config.options.model_id.lower():
                additional_model_fields["top_k"] = 200

            # Prepare the converse API call
            converse_args = {
                "modelId": self.config.options.model_id,
                "messages": messages,
                "system": system,
                "inferenceConfig": inference_config,
            }

            # Only add additionalModelRequestFields if we have any
            if additional_model_fields:
                converse_args["additionalModelRequestFields"] = additional_model_fields

            # Use the converse API
            response = bedrock_runtime.converse(**converse_args)

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
                    return full_text

            return "*Error: Unable to generate content from Bedrock response.*"
        except Exception as e:
            self._plugin_log(
                f"Error calling Bedrock: {e}",
                level=logging.WARNING,
                append_to_stream="stderr",
            )
            return f"*Error generating content: {str(e)}*"

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
