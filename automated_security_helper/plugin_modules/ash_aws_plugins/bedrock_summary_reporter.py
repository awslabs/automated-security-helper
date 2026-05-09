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
from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_pipeline import (
    BedrockModelClient,
    BedrockPromptBuilder,
    BedrockReportPipeline,
    ReportSection,
)

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults


class BedrockSummaryReporterConfigOptions(ReporterOptionsBase):
    aws_region: Annotated[
        str | None,
        Field(
            pattern=r"(af|il|ap|ca|eu|me|sa|us|cn|us-gov|us-iso|us-isob)-(central|north|(north(?:east|west))|south|south(?:east|west)|east|west)-\d{1}",
            description="AWS region to use for Bedrock. If not specified, the default region will be used. If specified, the region will be used for all Bedrock requests.",
        ),
    ] = os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
    aws_profile: Annotated[
        str | None,
        Field(
            description="AWS profile to use for Bedrock. If not specified, the default profile will be used.",
        ),
    ] = os.environ.get("AWS_PROFILE", None)
    model_id: Annotated[
        str,
        Field(
            description="Bedrock model ID to use for generating summaries.",
        ),
    ] = os.environ.get(
        "ASH_BEDROCK_MODEL_ID", "us.anthropic.claude-3-7-sonnet-20250219-v1:0"
    )
    temperature: Annotated[
        float,
        Field(
            description="Temperature parameter for the Bedrock model. Higher values make output more random.",
        ),
    ] = float(os.environ.get("ASH_BEDROCK_TEMPERATURE", "0.5"))
    max_tokens: Annotated[
        int,
        Field(
            description="Maximum number of tokens to generate in the response.",
        ),
    ] = int(os.environ.get("ASH_BEDROCK_MAX_TOKENS", "4000"))
    top_p: Annotated[
        float,
        Field(
            description="Top-p parameter for the Bedrock model. Controls diversity of generated text.",
        ),
    ] = 0.9
    max_findings_to_analyze: Annotated[
        int,
        Field(
            description="Maximum number of findings to include in the analysis.",
        ),
    ] = 10
    max_findings_per_severity: Annotated[
        int,
        Field(
            description="Maximum number of findings to include per severity level when grouping by severity.",
        ),
    ] = 5
    group_by_severity: Annotated[
        bool,
        Field(
            description="Whether to group findings by severity level in the report.",
        ),
    ] = True
    add_section_headers: Annotated[
        bool,
        Field(
            description="Whether to add section headers to the report for better organization.",
        ),
    ] = True
    add_table_of_contents: Annotated[
        bool,
        Field(
            description="Whether to add a table of contents to the report.",
        ),
    ] = True
    enable_caching: Annotated[
        bool,
        Field(
            description="Whether to cache Bedrock responses to avoid duplicate API calls.",
        ),
    ] = True
    output_markdown: Annotated[
        bool,
        Field(
            description="Whether to output the report as a markdown file.",
        ),
    ] = True
    output_file: Annotated[
        str,
        Field(
            description="Filename for the main output markdown report.",
        ),
    ] = "ash.bedrock.summary.md"
    # Retry configuration
    max_retries: Annotated[
        int,
        Field(
            description="Maximum number of retries for Bedrock API calls.",
        ),
    ] = 3
    base_delay: Annotated[
        float,
        Field(
            description="Base delay in seconds between retries (will be increased exponentially).",
        ),
    ] = 1.0
    max_delay: Annotated[
        float,
        Field(
            description="Maximum delay in seconds between retries.",
        ),
    ] = 60.0

    enable_fallback_models: Annotated[
        bool,
        Field(
            description="Whether to try fallback models if the primary model fails.",
        ),
    ] = True
    # Output additional files with specific content
    output_executive_file: Annotated[
        str,
        Field(
            description="Filename for the executive summary markdown report.",
        ),
    ] = "bedrock-executive.md"
    output_technical_file: Annotated[
        str,
        Field(
            description="Filename for the technical analysis markdown report.",
        ),
    ] = "bedrock-technical.md"

    include_code_snippets: Annotated[
        bool,
        Field(
            description="Whether to include code snippets in the report.",
        ),
    ] = False
    # Summary style: executive, technical, or detailed
    summary_style: Annotated[
        Literal["executive", "technical", "detailed"],
        Field(
            description="Style of summary to generate: executive (high-level), technical (detailed), or detailed (comprehensive).",
        ),
    ] = "executive"
    # Custom prompt to guide the AI analysis
    custom_prompt: Annotated[
        str | None,
        Field(
            description="Custom prompt to prepend to all Bedrock requests for more tailored analysis.",
        ),
    ] = None
    # List of scanner types to exclude from detailed analysis
    exclude_scanner_types: Annotated[
        List[str],
        Field(
            description="List of scanner types to exclude from detailed analysis (e.g., 'SECRET').",
        ),
    ] = ["SECRET"]
    # Include only actionable findings (not suppressed, above severity threshold)
    actionable_only: Annotated[
        bool,
        Field(
            description="Whether to include only actionable findings (not suppressed, above severity threshold).",
        ),
    ] = True
    # Sections to include or exclude
    include_sections: Annotated[
        List[str],
        Field(
            description="List of sections to include in the report.",
        ),
    ] = [
        "executive_summary",
        "risk_assessment",
        "technical_analysis",
        "remediation_guide",
        "compliance_impact",
    ]
    exclude_sections: Annotated[
        List[str],
        Field(
            description="List of sections to exclude from the report.",
        ),
    ] = []
    # Industry-specific analysis
    industry_context: Annotated[
        str | None,
        Field(
            description="Industry context to provide to the model for more relevant analysis.",
        ),
    ] = None
    compliance_frameworks: Annotated[
        List[str],
        Field(
            description="List of compliance frameworks to consider in the analysis.",
        ),
    ] = []
    custom_context: Annotated[
        str | None,
        Field(
            description="Custom context information to provide to the model.",
        ),
    ] = None
    # Performance optimization
    summarize_findings: Annotated[
        bool,
        Field(
            description="Whether to summarize findings to reduce token usage.",
        ),
    ] = False
    batch_processing: Annotated[
        bool,
        Field(
            description="Whether to process findings in batches for better performance with large datasets.",
        ),
    ] = False


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

    def validate_plugin_dependencies(self) -> bool:
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

        session_params: Dict[str, Any] = {}
        if self.config.options.aws_profile:
            session_params["profile_name"] = self.config.options.aws_profile
        if self.config.options.aws_region:
            session_params["region_name"] = self.config.options.aws_region
        bedrock_runtime = boto3.Session(**session_params).client("bedrock-runtime")

        all_findings, secret_findings, indexed_findings = self._extract_findings(model)

        if not all_findings and not secret_findings:
            return "No actionable findings available in the SARIF report."

        if self.config.options.add_section_headers:
            ASH_LOGGER.info("Generating structured report with section headers")
            summary = self._run_structured_report(
                bedrock_runtime, model, all_findings, secret_findings, indexed_findings
            )
        else:
            ASH_LOGGER.info("Generating simple summary report")
            summary = self._run_simple_report(
                bedrock_runtime,
                model,
                all_findings[: self.config.options.max_findings_to_analyze],
                secret_findings,
            )

        if self.config.options.output_markdown:
            self._write_markdown_files(
                bedrock_runtime, model, all_findings, secret_findings, summary
            )

        return summary

    # ------------------------------------------------------------------
    # Finding extraction
    # ------------------------------------------------------------------

    def _extract_findings(
        self, model: "AshAggregatedResults"
    ) -> "tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]":
        all_findings: List[Dict[str, Any]] = []
        secret_findings: List[Dict[str, Any]] = []
        indexed_findings: List[Dict[str, Any]] = []

        if not (model.sarif and model.sarif.runs):
            return all_findings, secret_findings, indexed_findings

        sarif_results = model.sarif.get_all_results()
        if not sarif_results:
            return all_findings, secret_findings, indexed_findings

        for i, result in enumerate(sarif_results):
            finding_dict = result.model_dump(
                by_alias=True, exclude_defaults=True, exclude_unset=True, mode="json"
            )
            finding_dict["index"] = i + 1
            indexed_findings.append(self._make_indexed_finding(i + 1, finding_dict))

            is_secret = self._is_secret_scanner(finding_dict)
            is_actionable = self._is_actionable(finding_dict)

            if is_secret:
                if is_actionable:
                    secret_findings.append(finding_dict)
                    self._secret_findings_exist = True
            elif is_actionable:
                all_findings.append(finding_dict)

        return all_findings, secret_findings, indexed_findings

    def _make_indexed_finding(
        self, index: int, finding_dict: Dict[str, Any]
    ) -> Dict[str, Any]:
        locations = []
        for loc in finding_dict.get("locations", []):
            phys = loc.get("physicalLocation", {})
            if not phys:
                continue
            entry: Dict[str, Any] = {}
            artifact = phys.get("artifactLocation", {})
            if artifact.get("uri"):
                entry["file"] = artifact["uri"]
            region = phys.get("region", {})
            if "startLine" in region:
                entry["startLine"] = region["startLine"]
            if "endLine" in region:
                entry["endLine"] = region["endLine"]
            locations.append(entry)

        msg = finding_dict.get("message", {})
        return {
            "index": index,
            "rule_id": (finding_dict.get("rule") or {}).get("id", "Unknown"),
            "level": finding_dict.get("level", "none"),
            "message": (
                msg.get("text", "No description available")
                if isinstance(msg, dict)
                else "No description available"
            ),
            "locations": locations,
        }

    def _is_secret_scanner(self, finding_dict: Dict[str, Any]) -> bool:
        props = finding_dict.get("properties", {})
        return props.get("scanner_type") in self.config.options.exclude_scanner_types

    def _is_actionable(self, finding_dict: Dict[str, Any]) -> bool:
        if not self.config.options.actionable_only:
            return True
        if finding_dict.get("suppressions"):
            return False
        if (finding_dict.get("properties") or {}).get("below_threshold"):
            return False
        return True

    # ------------------------------------------------------------------
    # Report runners
    # ------------------------------------------------------------------

    def _run_simple_report(
        self,
        bedrock_runtime: Any,
        model: "AshAggregatedResults",
        findings: List[Dict[str, Any]],
        secret_findings: List[Dict[str, Any]],
    ) -> str:
        opts = self.config.options
        builder = BedrockPromptBuilder()
        client = self._make_model_client(bedrock_runtime)
        prepared = builder.prepare_prompt(
            builder.legacy_summary(
                findings,
                secret_findings,
                list(model.scanner_results),
                opts.max_findings_to_analyze,
            ),
            custom_prompt=opts.custom_prompt,
            industry_context=opts.industry_context,
            compliance_frameworks=opts.compliance_frameworks,
            custom_context=opts.custom_context,
        )
        return self._get_cached_or_generate(
            "simple_summary",
            lambda: client.try_call(
                prepared,
                "You are a security expert specializing in code security analysis. "
                "Your task is to analyze security findings from the Automated Security Helper (ASH) tool "
                "and provide a concise, actionable summary report.",
            ),
        )

    def _run_structured_report(
        self,
        bedrock_runtime: Any,
        model: "AshAggregatedResults",
        findings: List[Dict[str, Any]],
        secret_findings: List[Dict[str, Any]],
        indexed_findings: List[Dict[str, Any]],
    ) -> str:
        opts = self.config.options
        builder = BedrockPromptBuilder()
        client = self._make_model_client(bedrock_runtime)

        if opts.summarize_findings:
            ASH_LOGGER.info("Summarizing findings to reduce token usage")
            findings = self._summarize_findings(findings)

        report = "# Security Scan Summary Report\n\n"
        report += self._build_toc(findings)

        included = set(opts.include_sections) - set(opts.exclude_sections)

        def _section_call(prompt: str, system: str, cache_key: str) -> str:
            prepared = builder.prepare_prompt(
                prompt,
                custom_prompt=opts.custom_prompt,
                industry_context=opts.industry_context,
                compliance_frameworks=opts.compliance_frameworks,
                custom_context=opts.custom_context,
            )
            return self._get_cached_or_generate(
                cache_key, lambda: client.try_call(prepared, system)
            )

        if "executive_summary" in included:
            ASH_LOGGER.info("Generating executive summary")
            report += "## Executive Summary\n\n"
            report += _section_call(
                builder.executive_summary(
                    findings, secret_findings, list(model.scanner_results)
                ),
                "You are a security expert providing a concise executive summary of security scan results.",
                "executive_summary",
            ) + "\n\n"

        if "technical_analysis" in included:
            report += "## Findings by Severity\n\n"
            if opts.group_by_severity:
                report += self._render_by_severity(findings, builder, client, opts)
            else:
                report += (
                    self._render_flat_findings(
                        bedrock_runtime, model, findings, builder, client, opts
                    )
                    + "\n\n"
                )

        if self._secret_findings_exist and "secret_findings" in included:
            report += "## Secret Findings\n\n"
            report += _section_call(
                builder.secret_advice(secret_findings),
                "You are a security expert providing advice on handling secrets found in code.",
                "secret_advice",
            ) + "\n\n"

        if "remediation_guide" in included:
            ASH_LOGGER.info("Generating recommendations")
            report += "## Recommendations\n\n"
            report += _section_call(
                builder.recommendations(findings, opts.max_findings_to_analyze),
                "You are a security expert providing actionable recommendations based on security scan findings.",
                "recommendations",
            ) + "\n\n"

        if "risk_assessment" in included:
            ASH_LOGGER.info("Generating risk assessment")
            report += "## Risk Assessment\n\n"
            report += _section_call(
                builder.risk_assessment(findings, opts.compliance_frameworks),
                "You are a security expert providing risk assessment based on security scan findings.",
                "risk_assessment",
            ) + "\n\n"

        if "compliance_impact" in included and opts.compliance_frameworks:
            ASH_LOGGER.info("Generating compliance impact analysis")
            report += "## Compliance Impact\n\n"
            report += _section_call(
                builder.compliance_impact(
                    findings, opts.compliance_frameworks, opts.industry_context
                ),
                "You are a compliance expert analyzing security findings against regulatory frameworks.",
                "compliance_impact",
            ) + "\n\n"

        if "detailed_findings" not in opts.exclude_sections:
            report += self._render_finding_details(
                findings, secret_findings, indexed_findings
            )

        return report

    def _render_by_severity(
        self,
        findings: List[Dict[str, Any]],
        builder: BedrockPromptBuilder,
        client: BedrockModelClient,
        opts: Any,
    ) -> str:
        severity_groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for f in findings:
            severity_groups[f.get("level", "none")].append(f)

        out = ""
        for severity in ("error", "warning", "note", "none"):
            if severity not in severity_groups:
                continue
            limited = severity_groups[severity][: opts.max_findings_per_severity]
            ASH_LOGGER.info(f"Analyzing {len(limited)} {severity} level findings")
            out += f"### {severity.capitalize()} Level Findings\n\n"
            prompt = builder.prepare_prompt(
                builder.severity_analysis(limited, severity),
                custom_prompt=opts.custom_prompt,
                industry_context=opts.industry_context,
                compliance_frameworks=opts.compliance_frameworks,
                custom_context=opts.custom_context,
            )
            # capture loop variable
            _sev = severity
            _prompt = prompt
            out += self._get_cached_or_generate(
                f"severity_{severity}",
                lambda: client.try_call(
                    _prompt,
                    f"You are a security expert analyzing {_sev} level findings from a security scan.",
                ),
            ) + "\n\n"
        return out

    def _render_flat_findings(
        self,
        bedrock_runtime: Any,
        model: "AshAggregatedResults",
        findings: List[Dict[str, Any]],
        builder: BedrockPromptBuilder,
        client: BedrockModelClient,
        opts: Any,
    ) -> str:
        if opts.batch_processing and len(findings) > opts.max_findings_to_analyze:
            return self._process_findings_by_batch(bedrock_runtime, model, findings)
        prompt = builder.prepare_prompt(
            builder.findings_summary(findings[: opts.max_findings_to_analyze]),
            custom_prompt=opts.custom_prompt,
            industry_context=opts.industry_context,
            compliance_frameworks=opts.compliance_frameworks,
            custom_context=opts.custom_context,
        )
        return self._get_cached_or_generate(
            "findings_flat",
            lambda: client.try_call(
                prompt,
                "You are a security expert summarizing findings from a security scan.",
            ),
        )

    def _render_finding_details(
        self,
        findings: List[Dict[str, Any]],
        secret_findings: List[Dict[str, Any]],
        indexed_findings: List[Dict[str, Any]],
    ) -> str:
        import json

        report = "## Finding Details\n\n"
        report += "This section contains detailed information about each finding referenced in the report.\n\n"
        report += "### Finding Index Reference\n\n"
        report += "| Index | Rule ID | Severity | File | Line Range | Description |\n"
        report += "|-------|---------|----------|------|------------|-------------|\n"

        for finding in indexed_findings:
            index = finding.get("index", "")
            rule_id = finding.get("rule_id", "Unknown")
            level = finding.get("level", "none").capitalize()
            file_path = "Unknown"
            line_range = "Unknown"
            if finding.get("locations"):
                loc = finding["locations"][0]
                file_path = loc.get("file", "Unknown")
                start = loc.get("startLine", "?")
                end = loc.get("endLine", start)
                line_range = f"{start}-{end}" if start != end else str(start)
            message = finding.get("message", "No description available")
            if len(message) > 50:
                message = message[:47] + "..."
            report += f"| {index} | {rule_id} | {level} | {file_path} | {line_range} | {message} |\n"

        report += "\n\n### Full Finding Details\n\n"
        report += (
            "<details>\n<summary>Click to expand full finding details</summary>\n\n"
        )

        raw_by_index = {f.get("index"): f for f in findings + secret_findings}

        for finding in indexed_findings:
            index = finding.get("index", "")
            rule_id = finding.get("rule_id", "Unknown")
            level = finding.get("level", "none").capitalize()
            report += f"#### Finding {index}: {rule_id} ({level})\n\n"

            if finding.get("locations"):
                loc = finding["locations"][0]
                file_path = loc.get("file", "Unknown")
                start = loc.get("startLine", "?")
                end = loc.get("endLine", start)
                report += f"**Location**: {file_path} (lines {start}-{end})\n\n"

            report += (
                f"**Description**: {finding.get('message', 'No description available')}\n\n"
            )

            original = raw_by_index.get(index)
            if self.config.options.include_code_snippets and original:
                for loc in original.get("locations", []):
                    phys = loc.get("physicalLocation", {})
                    snippet_text = (
                        phys.get("region", {}).get("snippet", {}).get("text")
                    )
                    if snippet_text:
                        report += f"**Code Snippet**:\n```\n{snippet_text}\n```\n\n"

            if original:
                report += "<details>\n<summary>Raw JSON</summary>\n\n```json\n"
                report += json.dumps(original, indent=2)
            report += "\n```\n</details>\n\n"

        report += "</details>\n\n"
        return report

    # ------------------------------------------------------------------
    # TOC builder
    # ------------------------------------------------------------------

    def _build_toc(self, findings: List[Dict[str, Any]]) -> str:
        opts = self.config.options
        if not opts.add_table_of_contents:
            return ""

        included = set(opts.include_sections) - set(opts.exclude_sections)
        items = []
        n = 1

        if "executive_summary" in included:
            items.append(f"{n}. [Executive Summary](#executive-summary)")
            n += 1
        if "technical_analysis" in included:
            items.append(f"{n}. [Findings by Severity](#findings-by-severity)")
            if opts.group_by_severity:
                for sev in ("error", "warning", "note", "none"):
                    if any(f.get("level") == sev for f in findings):
                        items.append(
                            f"   - [{sev.capitalize()} Level Findings](#{sev.lower()}-level-findings)"
                        )
            n += 1
        if self._secret_findings_exist and "secret_findings" in included:
            items.append(f"{n}. [Secret Findings](#secret-findings)")
            n += 1
        if "remediation_guide" in included:
            items.append(f"{n}. [Recommendations](#recommendations)")
            n += 1
        if "risk_assessment" in included:
            items.append(f"{n}. [Risk Assessment](#risk-assessment)")
            n += 1
        if "compliance_impact" in included and opts.compliance_frameworks:
            items.append(f"{n}. [Compliance Impact](#compliance-impact)")
            n += 1
        if "detailed_findings" not in opts.exclude_sections:
            items.append(f"{n}. [Finding Details](#finding-details)")

        return "## Table of Contents\n\n" + "\n".join(items) + "\n\n"

    # ------------------------------------------------------------------
    # Client factory
    # ------------------------------------------------------------------

    def _make_model_client(self, bedrock_runtime: Any) -> BedrockModelClient:
        opts = self.config.options
        return BedrockModelClient(
            bedrock_runtime=bedrock_runtime,
            model_id=opts.model_id,
            temperature=opts.temperature,
            max_tokens=opts.max_tokens,
            top_p=opts.top_p,
        )

    # ------------------------------------------------------------------
    # Markdown file writer
    # ------------------------------------------------------------------

    def _write_markdown_files(
        self,
        bedrock_runtime: Any,
        model: "AshAggregatedResults",
        all_findings: List[Dict[str, Any]],
        secret_findings: List[Dict[str, Any]],
        summary: str,
    ) -> None:
        opts = self.config.options
        included = set(opts.include_sections) - set(opts.exclude_sections)
        builder = BedrockPromptBuilder()
        client = self._make_model_client(bedrock_runtime)

        reports_dir = Path(self.context.output_dir) / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)

        output_path = reports_dir / opts.output_file
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(summary)
        ASH_LOGGER.info(f"Bedrock summary written to {output_path}")

        if "executive_summary" in included:
            prompt = builder.prepare_prompt(
                builder.executive_summary(
                    all_findings, secret_findings, list(model.scanner_results)
                ),
                custom_prompt=opts.custom_prompt,
                industry_context=opts.industry_context,
                compliance_frameworks=opts.compliance_frameworks,
                custom_context=opts.custom_context,
            )
            exec_content = self._get_cached_or_generate(
                "executive_summary_only",
                lambda: client.try_call(
                    prompt,
                    "You are a security expert providing a concise executive summary of security scan results.",
                ),
            )
            exec_path = reports_dir / opts.output_executive_file
            with open(exec_path, "w", encoding="utf-8") as f:
                f.write(f"# Executive Security Summary\n\n{exec_content}")
            ASH_LOGGER.info(f"Executive summary written to {exec_path}")

        if "technical_analysis" in included:
            tech_prompt = builder.prepare_prompt(
                builder.technical_analysis(
                    all_findings,
                    opts.max_findings_to_analyze,
                    opts.include_code_snippets,
                ),
                custom_prompt=opts.custom_prompt,
                industry_context=opts.industry_context,
                compliance_frameworks=opts.compliance_frameworks,
                custom_context=opts.custom_context,
            )
            tech_content = self._get_cached_or_generate(
                "technical_summary_only",
                lambda: client.try_call(
                    tech_prompt,
                    "You are a security expert providing detailed technical analysis of security findings.",
                ),
            )
            tech_path = reports_dir / opts.output_technical_file
            with open(tech_path, "w", encoding="utf-8") as f:
                f.write(f"# Technical Security Analysis\n\n{tech_content}")
            ASH_LOGGER.info(f"Technical analysis written to {tech_path}")

    # ------------------------------------------------------------------
    # Caching
    # ------------------------------------------------------------------

    def _get_cached_or_generate(self, key: str, generator_func):  # type: ignore[type-arg]
        """Get a cached result or generate and cache it."""
        if not self.config.options.enable_caching:
            return generator_func()
        if key in self._cache:
            ASH_LOGGER.debug(f"Using cached result for {key}")
            return self._cache[key]
        result = generator_func()
        self._cache[key] = result
        return result

    # ------------------------------------------------------------------
    # Findings utilities (tested directly by existing test suite)
    # ------------------------------------------------------------------

    def _summarize_findings(
        self,
        findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Summarize findings to reduce token usage."""
        if not self.config.options.summarize_findings or not findings:
            return findings

        grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for finding in findings:
            rule_id = "unknown"
            if "rule" in finding and finding["rule"] and "id" in finding["rule"]:
                rule_id = finding["rule"]["id"]
            grouped[rule_id].append(finding)

        summarized = []
        for _rule_id, rule_findings in grouped.items():
            if len(rule_findings) == 1:
                summarized.append(rule_findings[0])
                continue
            base = rule_findings[0].copy()
            seen_uris: List[str] = []
            locations: List[Dict[str, Any]] = []
            for f in rule_findings:
                for loc in f.get("locations", []):
                    uri = (
                        loc.get("physicalLocation", {})
                        .get("artifactLocation", {})
                        .get("uri")
                    )
                    if uri and uri not in seen_uris:
                        seen_uris.append(uri)
                        locations.append({"uri": uri})
            if "message" in base and isinstance(base["message"], dict):
                base["message"]["text"] = (
                    f"Found {len(rule_findings)} instances of this issue"
                )
            if "properties" not in base:
                base["properties"] = {}
            base["properties"]["summarized"] = True
            base["properties"]["original_count"] = len(rule_findings)
            summarized.append(base)
        return summarized

    def _process_findings_by_batch(
        self,
        bedrock_runtime: Any,
        model: "AshAggregatedResults",
        findings: List[Dict[str, Any]],
    ) -> str:
        """Process findings in batches to optimize token usage."""
        opts = self.config.options
        builder = BedrockPromptBuilder()
        client = self._make_model_client(bedrock_runtime)

        if not opts.batch_processing or len(findings) <= opts.max_findings_to_analyze:
            prompt = builder.prepare_prompt(
                builder.findings_summary(findings[: opts.max_findings_to_analyze]),
                custom_prompt=opts.custom_prompt,
                industry_context=opts.industry_context,
                compliance_frameworks=opts.compliance_frameworks,
                custom_context=opts.custom_context,
            )
            return client.try_call(
                prompt,
                "You are a security expert summarizing findings from a security scan.",
            )

        batch_size = opts.max_findings_to_analyze
        batches = [
            findings[i: i + batch_size] for i in range(0, len(findings), batch_size)
        ]
        batch_results = []
        for i, batch in enumerate(batches):
            ASH_LOGGER.info(f"Processing batch {i + 1} of {len(batches)}")
            prompt = builder.prepare_prompt(
                builder.findings_summary(batch),
                custom_prompt=opts.custom_prompt,
                industry_context=opts.industry_context,
                compliance_frameworks=opts.compliance_frameworks,
                custom_context=opts.custom_context,
            )
            batch_results.append(
                client.try_call(
                    prompt,
                    "You are a security expert summarizing findings from a security scan.",
                )
            )

        formatted = [f"BATCH {i + 1}:\n{s}" for i, s in enumerate(batch_results)]
        combined = (
            "Synthesize the following batch summaries into a cohesive overall summary:\n\n"
            + "\n".join(formatted)
            + "\n\nProvide a unified summary that captures the key insights from all batches.\n"
        )
        return client.try_call(
            combined,
            "You are a security expert synthesizing multiple security scan batch summaries.",
        )

    # ------------------------------------------------------------------
    # Backward-compat shims (existing tests call these methods directly)
    # ------------------------------------------------------------------

    def _call_bedrock(
        self, bedrock_runtime: Any, user_message: str, system_prompt: str
    ) -> str:
        """Thin shim retained for backward compatibility with existing tests."""
        opts = self.config.options
        builder = BedrockPromptBuilder()
        client = self._make_model_client(bedrock_runtime)

        bedrock_client = boto3.client("bedrock", region_name=opts.aws_region)
        is_valid, error_message = validate_bedrock_model(bedrock_client, opts.model_id)
        if not is_valid:
            if opts.enable_fallback_models:
                prepared = self._prepare_prompt(user_message)
                return self._try_fallback_models(
                    bedrock_runtime,
                    bedrock_client,
                    opts.model_id,
                    [{"role": "user", "content": [{"text": prepared}]}],
                    [{"text": system_prompt}],
                    {
                        "temperature": opts.temperature,
                        "maxTokens": opts.max_tokens,
                        "topP": opts.top_p,
                    },
                )
            return f"*Error: Primary model {opts.model_id} validation failed: {error_message}*"

        prepared = builder.prepare_prompt(
            user_message,
            custom_prompt=opts.custom_prompt,
            industry_context=opts.industry_context,
            compliance_frameworks=opts.compliance_frameworks,
            custom_context=opts.custom_context,
        )
        result = client.try_call(prepared, system_prompt)
        if result.startswith("*Error") and opts.enable_fallback_models:
            return self._try_fallback_models(
                bedrock_runtime,
                bedrock_client,
                opts.model_id,
                [{"role": "user", "content": [{"text": prepared}]}],
                [{"text": system_prompt}],
                {
                    "temperature": opts.temperature,
                    "maxTokens": opts.max_tokens,
                    "topP": opts.top_p,
                },
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
        fallback_model = get_fallback_model(failed_model_id)
        if not fallback_model or fallback_model == failed_model_id:
            return f"*Error: No suitable fallback model found for {failed_model_id}*"
        ASH_LOGGER.info(f"Trying fallback model: {fallback_model}")
        is_valid, _err = validate_bedrock_model(bedrock_client, fallback_model)
        if not is_valid:
            return self._try_fallback_models(
                bedrock_runtime,
                bedrock_client,
                fallback_model,
                messages,
                system,
                inference_config,
            )
        result = self._try_model_call(
            bedrock_runtime, fallback_model, messages, system, inference_config
        )
        if not result.startswith("*Error"):
            ASH_LOGGER.info(f"Fallback model {fallback_model} succeeded")
            return result
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
        opts = self.config.options
        return BedrockPromptBuilder().prepare_prompt(
            user_message,
            custom_prompt=opts.custom_prompt,
            industry_context=opts.industry_context,
            compliance_frameworks=opts.compliance_frameworks,
            custom_context=opts.custom_context,
        )

    def _invoke_bedrock_model(self, bedrock_runtime: Any, **converse_args) -> dict:  # type: ignore[type-arg]
        """Invoke the Bedrock model."""
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
        opts = self.config.options
        client = BedrockModelClient(
            bedrock_runtime=bedrock_runtime,
            model_id=model_id,
            temperature=inference_config.get("temperature", opts.temperature),
            max_tokens=inference_config.get("maxTokens", opts.max_tokens),
            top_p=inference_config.get("topP", opts.top_p),
        )
        prompt_text = ""
        if messages and messages[0].get("content"):
            first = messages[0]["content"]
            if first and isinstance(first[0], dict):
                prompt_text = first[0].get("text", "")
        system_text = ""
        if system and isinstance(system[0], dict):
            system_text = system[0].get("text", "")
        return client.try_call(prompt_text, system_text)

    def _generate_executive_summary(
        self,
        bedrock_runtime: Any,
        model: "AshAggregatedResults",
        findings: List[Dict[str, Any]],
        secret_findings: List[Dict[str, Any]],
    ) -> str:
        """Generate an executive summary of the scan results."""
        opts = self.config.options
        builder = BedrockPromptBuilder()
        prompt = builder.prepare_prompt(
            builder.executive_summary(
                findings, secret_findings, list(model.scanner_results)
            ),
            custom_prompt=opts.custom_prompt,
            industry_context=opts.industry_context,
            compliance_frameworks=opts.compliance_frameworks,
            custom_context=opts.custom_context,
        )
        return self._call_bedrock(
            bedrock_runtime,
            prompt,
            "You are a security expert providing a concise executive summary of security scan results.",
        )

    def _generate_summary(
        self,
        bedrock_runtime: Any,
        model: "AshAggregatedResults",
        findings: List[Dict[str, Any]],
        secret_findings: List[Dict[str, Any]],
    ) -> str:
        """Generate a summary of findings using Amazon Bedrock (legacy method)."""
        return self._run_simple_report(bedrock_runtime, model, findings, secret_findings)

    def _generate_technical_analysis(
        self,
        bedrock_runtime: Any,
        model: "AshAggregatedResults",
        findings: List[Dict[str, Any]],
    ) -> str:
        """Generate a detailed technical analysis of findings."""
        opts = self.config.options
        builder = BedrockPromptBuilder()
        prompt = builder.prepare_prompt(
            builder.technical_analysis(
                findings, opts.max_findings_to_analyze, opts.include_code_snippets
            ),
            custom_prompt=opts.custom_prompt,
            industry_context=opts.industry_context,
            compliance_frameworks=opts.compliance_frameworks,
            custom_context=opts.custom_context,
        )
        return self._call_bedrock(
            bedrock_runtime,
            prompt,
            "You are a security expert providing detailed technical analysis of security findings.",
        )

    def _generate_report_with_headers(
        self,
        bedrock_runtime: Any,
        model: "AshAggregatedResults",
        findings: List[Dict[str, Any]],
        secret_findings: List[Dict[str, Any]],
        indexed_findings: List[Dict[str, Any]],
    ) -> str:
        """Thin alias retained for backward compatibility."""
        return self._run_structured_report(
            bedrock_runtime, model, findings, secret_findings, indexed_findings
        )
