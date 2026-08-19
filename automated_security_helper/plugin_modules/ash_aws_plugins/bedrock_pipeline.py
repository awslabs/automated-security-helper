# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Pipeline collaborators for BedrockSummaryReporter.

Three focused classes replace the monolithic reporter internals:
  BedrockModelClient  — single boto3 contact point (try_call + error handling)
  BedrockPromptBuilder — pure prompt-template assembly, no I/O
  BedrockReportPipeline — iterates ReportSection configs, accumulates results
"""

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import botocore.exceptions

from automated_security_helper.utils.log import ASH_LOGGER


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class ReportSection:
    """Configuration for a single report section."""

    title: str
    cache_key: str
    system_prompt: str
    max_tokens: Optional[int] = None
    header_emoji: str = ""


# ---------------------------------------------------------------------------
# BedrockModelClient
# ---------------------------------------------------------------------------


class BedrockModelClient:
    """Wraps boto3 bedrock-runtime. Single point of contact with AWS."""

    def __init__(
        self,
        bedrock_runtime: Any,
        model_id: str,
        temperature: float,
        max_tokens: int,
        top_p: float,
    ) -> None:
        self._runtime = bedrock_runtime
        self._model_id = model_id
        self._temperature = temperature
        self._max_tokens = max_tokens
        self._top_p = top_p

    def try_call(self, prompt: str, system_prompt: str) -> str:
        """Invoke the model. Returns response text or an *Error: … string."""
        messages = [{"role": "user", "content": [{"text": prompt}]}]
        system = [{"text": system_prompt}]
        inference_config: Dict[str, Any] = {
            "temperature": self._temperature,
            "maxTokens": self._max_tokens,
            "topP": self._top_p,
        }

        converse_args: Dict[str, Any] = {
            "modelId": self._model_id,
            "messages": messages,
            "system": system,
            "inferenceConfig": inference_config,
        }
        if "claude" in self._model_id.lower():
            converse_args["additionalModelRequestFields"] = {"top_k": 200}

        try:
            ASH_LOGGER.debug(f"Invoking Bedrock model {self._model_id}")
            response = self._runtime.converse(**converse_args)

            if response and "output" in response and "message" in response["output"]:
                message = response["output"]["message"]
                content_list = message.get("content", [])
                full_text = "".join(
                    item["text"] for item in content_list if "text" in item
                )
                if full_text:
                    ASH_LOGGER.debug(f"Model {self._model_id} responded successfully")
                    return full_text

            ASH_LOGGER.warning(f"Invalid or empty response from model {self._model_id}")
            return "*Error: Unable to generate content from Bedrock response.*"

        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            msg = exc.response.get("Error", {}).get("Message", str(exc))
            ASH_LOGGER.warning(
                f"Bedrock API error ({code}) with model {self._model_id}: {msg}"
            )
            if code == "AccessDeniedException":
                return f"*Error: Access denied to model {self._model_id}. Check IAM permissions.*"
            if code == "ResourceNotFoundException":
                return f"*Error: Model {self._model_id} not found. Check model ID and region.*"
            if code == "ValidationException":
                return f"*Error: Validation error with model {self._model_id}: {msg}*"
            if code in ("ThrottlingException", "TooManyRequestsException"):
                return f"*Error: Rate limit exceeded for model {self._model_id}. Try again later.*"
            return f"*Error: {msg}*"

        except Exception as exc:
            error_type = type(exc).__name__
            ASH_LOGGER.warning(
                f"Error calling Bedrock model {self._model_id}: {error_type}: {exc}",
            )
            return f"*Error generating content with model {self._model_id}: {error_type}: {exc}*"


# ---------------------------------------------------------------------------
# BedrockPromptBuilder
# ---------------------------------------------------------------------------


class BedrockPromptBuilder:
    """Pure prompt-template assembly. No I/O, no config dependencies."""

    # ------------------------------------------------------------------
    # Prompt builders
    # ------------------------------------------------------------------

    def executive_summary(
        self,
        findings: List[Dict[str, Any]],
        secret_findings: List[Dict[str, Any]],
        scanner_results: List[str],
    ) -> str:
        severity_counts: Dict[str, int] = defaultdict(int)
        for f in findings:
            severity_counts[f.get("level", "none")] += 1

        counts_str = ", ".join(
            f"{sev}: {cnt}" for sev, cnt in severity_counts.items()
        )
        return (
            f"Generate an executive summary for a security scan with the following results:\n\n"
            f"SCAN OVERVIEW:\n"
            f"- Total actionable findings: {len(findings)}\n"
            f"- Secret findings: {len(secret_findings)}\n"
            f"- Scanners used: {', '.join(scanner_results)}\n\n"
            f"FINDINGS BY SEVERITY:\n{counts_str}\n\n"
            f"Provide a concise executive summary that highlights the most important aspects of the scan results.\n"
        )

    def severity_analysis(
        self, findings: List[Dict[str, Any]], severity: str
    ) -> str:
        if not findings:
            return f"No findings with {severity} level severity."

        lines = [f"Analyze the following {severity} level security findings:\n"]
        for i, finding in enumerate(findings):
            msg = self._extract_message(finding)
            rule_id = self._extract_rule_id(finding)
            locations = self._extract_locations(finding)
            lines.append(
                f"\nFINDING {i + 1}:\n"
                f"- Rule ID: {rule_id}\n"
                f"- Message: {msg}\n"
                f"- Locations: {', '.join(locations) if locations else 'Unknown'}\n"
            )
        lines.append(
            f"\nProvide a concise analysis of these {severity} level findings, including:\n"
            "1. Common patterns or issues\n"
            "2. Potential impact\n"
            "3. Brief remediation guidance\n"
        )
        return "".join(lines)

    def secret_advice(self, secret_findings: List[Dict[str, Any]]) -> str:
        if not secret_findings:
            return "No secret findings detected."
        return (
            f"The security scan has identified {len(secret_findings)} potential secrets in the codebase.\n\n"
            "Provide a concise paragraph advising on:\n"
            "1. The importance of removing secrets from code\n"
            "2. Best practices for handling secrets\n"
            "3. How to properly suppress false positives if needed\n"
            "4. Recommended actions to take immediately\n\n"
            "Keep the response focused and actionable.\n"
        )

    def findings_summary(self, findings: List[Dict[str, Any]]) -> str:
        if not findings:
            return "No findings to analyze."

        lines = ["Summarize the following security findings:\n"]
        for i, finding in enumerate(findings):
            msg = self._extract_message(finding)
            rule_id = self._extract_rule_id(finding)
            level = finding.get("level", "none")
            locations = self._extract_locations(finding)
            lines.append(
                f"\nFINDING {i + 1}:\n"
                f"- Rule ID: {rule_id}\n"
                f"- Level: {level}\n"
                f"- Message: {msg}\n"
                f"- Locations: {', '.join(locations) if locations else 'Unknown'}\n"
            )
        lines.append(
            "\nProvide a concise summary of these findings, highlighting patterns and key issues.\n"
        )
        return "".join(lines)

    def recommendations(
        self,
        findings: List[Dict[str, Any]],
        max_findings: int,
    ) -> str:
        severity_counts: Dict[str, int] = defaultdict(int)
        for f in findings:
            severity_counts[f.get("level", "none")] += 1

        # Prioritise most severe findings first
        severe: List[Dict[str, Any]] = []
        for sev in ("error", "warning"):
            for f in findings:
                if f.get("level") == sev:
                    severe.append(f)
                    if len(severe) >= max_findings:
                        break
            if len(severe) >= max_findings:
                break
        remaining = [f for f in findings if f not in severe]
        severe.extend(remaining[: max(0, max_findings - len(severe))])

        counts_str = ", ".join(
            f"{sev}: {cnt}" for sev, cnt in severity_counts.items()
        )
        lines = [
            f"Based on the security scan with the following results:\n\n"
            f"FINDINGS BY SEVERITY:\n{counts_str}\n\n"
            "Sample findings:\n"
        ]
        for i, finding in enumerate(severe[:max_findings]):
            msg = self._extract_message(finding)
            rule_id = self._extract_rule_id(finding)
            level = finding.get("level", "none")
            locations = self._extract_locations(finding)
            lines.append(
                f"\nFINDING {i + 1}:\n"
                f"- Rule ID: {rule_id}\n"
                f"- Level: {level}\n"
                f"- Message: {msg}\n"
                f"- Locations: {', '.join(locations) if locations else 'Unknown'}\n"
            )
        lines.append(
            "\nProvide actionable recommendations for addressing these security issues, including:\n"
            "1. Prioritized next steps\n"
            "2. Best practices to implement\n"
            "3. Long-term security improvements\n"
        )
        return "".join(lines)

    def technical_analysis(
        self,
        findings: List[Dict[str, Any]],
        max_findings: int,
        include_code_snippets: bool,
    ) -> str:
        if not findings:
            return "No findings to analyze."

        lines = ["Generate a detailed technical analysis of the following security findings:\n"]
        for i, finding in enumerate(findings[:max_findings]):
            msg = self._extract_message(finding)
            rule_id = self._extract_rule_id(finding)
            level = finding.get("level", "none")
            locations = self._extract_locations(finding)
            code_snippets = self._extract_code_snippets(finding) if include_code_snippets else []

            lines.append(
                f"\nFINDING {i + 1}:\n"
                f"- Rule ID: {rule_id}\n"
                f"- Level: {level}\n"
                f"- Message: {msg}\n"
                f"- Locations: {', '.join(locations) if locations else 'Unknown'}\n"
            )
            if code_snippets and include_code_snippets:
                lines.append("- Code Snippet:\n```\n" + "\n".join(code_snippets[:3]) + "\n```\n")

        lines.append(
            "\nProvide a detailed technical analysis including:\n"
            "1. Root cause analysis for each finding\n"
            "2. Specific remediation steps with code examples where appropriate\n"
            "3. Testing recommendations to verify fixes\n"
            "4. Security best practices related to these issues\n"
        )
        return "".join(lines)

    def risk_assessment(
        self,
        findings: List[Dict[str, Any]],
        compliance_frameworks: List[str],
    ) -> str:
        if not findings:
            return "No findings to assess risk."

        severity_counts: Dict[str, int] = defaultdict(int)
        for f in findings:
            severity_counts[f.get("level", "none")] += 1

        counts_str = ", ".join(
            f"{sev}: {cnt}" for sev, cnt in severity_counts.items()
        )
        lines = [
            f"Generate a risk assessment based on the following security scan results:\n\n"
            f"FINDINGS BY SEVERITY:\n{counts_str}\n\n"
            "Sample findings:\n"
        ]
        for i, finding in enumerate(findings[:5]):
            msg = self._extract_message(finding)
            rule_id = self._extract_rule_id(finding)
            level = finding.get("level", "none")
            lines.append(
                f"\nFINDING {i + 1}:\n"
                f"- Rule ID: {rule_id}\n"
                f"- Level: {level}\n"
                f"- Message: {msg}\n"
            )
        lines.append(
            "\nProvide a risk assessment including:\n"
            "1. Overall risk score (LOW/MEDIUM/HIGH/CRITICAL)\n"
            "2. Risk breakdown by severity\n"
            "3. Compliance impact assessment\n"
            "4. Business impact analysis\n"
        )
        if compliance_frameworks:
            lines.append(
                f"\nSpecifically address compliance impact for: {', '.join(compliance_frameworks)}"
            )
        return "".join(lines)

    def compliance_impact(
        self,
        findings: List[Dict[str, Any]],
        compliance_frameworks: List[str],
        industry_context: Optional[str],
    ) -> str:
        if not findings or not compliance_frameworks:
            return "No compliance frameworks specified for analysis."

        severity_counts: Dict[str, int] = defaultdict(int)
        for f in findings:
            severity_counts[f.get("level", "none")] += 1

        counts_str = ", ".join(
            f"{sev}: {cnt}" for sev, cnt in severity_counts.items()
        )
        fw_str = ", ".join(compliance_frameworks)
        lines = [
            f"Generate a compliance impact analysis for the following security scan results:\n\n"
            f"FINDINGS BY SEVERITY:\n{counts_str}\n\n"
            f"COMPLIANCE FRAMEWORKS TO ANALYZE:\n{fw_str}\n\n"
            "Sample findings:\n"
        ]
        for i, finding in enumerate(findings[:5]):
            msg = self._extract_message(finding)
            rule_id = self._extract_rule_id(finding)
            level = finding.get("level", "none")
            lines.append(
                f"\nFINDING {i + 1}:\n"
                f"- Rule ID: {rule_id}\n"
                f"- Level: {level}\n"
                f"- Message: {msg}\n"
            )
        lines.append(
            f"\nProvide a compliance impact analysis including:\n"
            f"1. How these findings may impact compliance with each framework ({fw_str})\n"
            "2. Specific compliance requirements that may be violated\n"
            "3. Recommended actions to maintain or restore compliance\n"
        )
        if industry_context:
            lines.append(f"\nConsider the industry context: {industry_context}")
        return "".join(lines)

    def legacy_summary(
        self,
        findings: List[Dict[str, Any]],
        secret_findings: List[Dict[str, Any]],
        scanner_results: List[str],
        max_findings: int,
    ) -> str:
        lines = [
            f"I need a security summary report for a codebase scan.\n\n"
            f"SCAN OVERVIEW:\n"
            f"- Total actionable findings: {len(findings)}\n"
            f"- Secret findings: {len(secret_findings)}\n"
            f"- Scanners used: {', '.join(scanner_results)}\n\n"
            "FINDINGS SUMMARY:\n"
        ]
        for i, finding in enumerate(findings[:max_findings]):
            msg = self._extract_message(finding)
            rule_id = self._extract_rule_id(finding)
            level = finding.get("level", "none")
            locations = self._extract_locations(finding)
            lines.append(
                f"\nFINDING {i + 1}:\n"
                f"- Rule ID: {rule_id}\n"
                f"- Level: {level}\n"
                f"- Message: {msg}\n"
                f"- Locations: {', '.join(locations) if locations else 'Unknown'}\n"
            )
        if secret_findings:
            lines.append(
                f"\nIMPORTANT: The scan also identified {len(secret_findings)} potential secrets "
                "in the codebase that should be addressed.\n"
            )
        lines.append(
            "\nPlease provide:\n"
            "1. An executive summary of the security scan results\n"
            "2. A breakdown of findings by severity\n"
            "3. Key risk areas identified\n"
            "4. Recommended next steps for remediation\n"
            "5. If secrets were found, include a paragraph about handling secrets properly\n\n"
            "Format your response in markdown.\n"
        )
        return "".join(lines)

    def prepare_prompt(
        self,
        user_message: str,
        custom_prompt: Optional[str],
        industry_context: Optional[str],
        compliance_frameworks: List[str],
        custom_context: Optional[str],
    ) -> str:
        if custom_prompt:
            user_message = f"{custom_prompt}\n\n{user_message}"
        if industry_context or compliance_frameworks:
            context_info = "\nADDITIONAL CONTEXT:\n"
            if industry_context:
                context_info += f"- Industry: {industry_context}\n"
            if compliance_frameworks:
                context_info += f"- Compliance frameworks: {', '.join(compliance_frameworks)}\n"
            if custom_context:
                context_info += f"\n{custom_context}"
            user_message += context_info
        return user_message

    # ------------------------------------------------------------------
    # Private helpers (pure extraction, no side-effects)
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_message(finding: Dict[str, Any]) -> str:
        msg = finding.get("message", {})
        if isinstance(msg, dict):
            return msg.get("text", "No description available")
        return "No description available"

    @staticmethod
    def _extract_rule_id(finding: Dict[str, Any]) -> str:
        rule = finding.get("rule")
        if rule and isinstance(rule, dict):
            return rule.get("id", "")
        return ""

    @staticmethod
    def _extract_locations(finding: Dict[str, Any]) -> List[str]:
        uris = []
        for loc in finding.get("locations", []):
            phys = loc.get("physicalLocation", {})
            artifact = phys.get("artifactLocation", {})
            uri = artifact.get("uri")
            if uri:
                uris.append(uri)
        return uris

    @staticmethod
    def _extract_code_snippets(finding: Dict[str, Any]) -> List[str]:
        snippets = []
        for loc in finding.get("locations", []):
            phys = loc.get("physicalLocation", {})
            region = phys.get("region", {})
            snippet = region.get("snippet", {})
            text = snippet.get("text")
            if text:
                snippets.append(text)
        return snippets


# ---------------------------------------------------------------------------
# BedrockReportPipeline
# ---------------------------------------------------------------------------


class BedrockReportPipeline:
    """
    Iterates a list of ReportSection configs, calls the client for each,
    and accumulates results keyed by cache_key.
    """

    def __init__(
        self,
        client: BedrockModelClient,
        prompt_builder: BedrockPromptBuilder,
        sections: List[ReportSection],
        cache: Dict[str, str],
        enable_caching: bool,
    ) -> None:
        self._client = client
        self._builder = prompt_builder
        self._sections = sections
        self._cache = cache
        self._enable_caching = enable_caching

    def run(self, prompts: Dict[str, str]) -> Dict[str, str]:
        """
        Execute all sections. Returns {cache_key: generated_content}.
        Sections whose prompt is missing are skipped.
        """
        results: Dict[str, str] = {}
        for section in self._sections:
            key = section.cache_key
            prompt = prompts.get(key)
            if prompt is None:
                continue
            content = self._get_or_generate(key, prompt, section.system_prompt)
            results[key] = content
        return results

    def _get_or_generate(self, key: str, prompt: str, system_prompt: str) -> str:
        if self._enable_caching and key in self._cache:
            ASH_LOGGER.debug(f"Cache hit for section {key!r}")
            return self._cache[key]
        result = self._client.try_call(prompt, system_prompt)
        if self._enable_caching:
            self._cache[key] = result
        return result
