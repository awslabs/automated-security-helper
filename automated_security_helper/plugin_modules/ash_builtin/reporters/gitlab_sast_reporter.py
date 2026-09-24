# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, TYPE_CHECKING

from automated_security_helper.utils.sarif_utils import get_finding_id

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    ReporterWorkspaceBehaviour,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin

from automated_security_helper.utils.get_ash_version import get_ash_version
from automated_security_helper.utils.log import ASH_LOGGER
from pydantic import Field
from typing import Annotated

# The GitLab security-report schema version this reporter's output conforms to, and
# the single place that states it.
#
# It was an inline literal in the report dict, which left CI free to disagree with it:
# the schema-compliance step in .github/actions/run-scan-test/action.yml fetched
# sast-report-format.json from the schemas repo's `master`, so the gate validated
# these reports against whatever GitLab had merged most recently. Measured 2026-09-17,
# `master` was 15.2.5 and differed from 15.2.2 -- 1,030 bytes and a different digest.
#
# Today the drift is loosening rather than tightening: 15.2.5 adds CVSS 4.0 vectors
# and raises code_flows.items.maxItems from 10 to 30, and this reporter emits neither
# field, so nothing failed. A tightening change would have failed the gate for a
# reason unrelated to ASH's code. Reading the version from here makes the gate check
# the contract the report actually claims.
#
# Bumping it means checking the new schema against what build_sast_report emits,
# because the version string is a claim about this file's output and not a preference.
GITLAB_SAST_SCHEMA_VERSION = "15.2.2"


class GitLabSASTReporterConfigOptions(ReporterOptionsBase):
    exclude_suppressed: Annotated[
        bool,
        Field(
            description=(
                "When true, suppressed findings are excluded entirely from the "
                "GitLab SAST report. When false (default), suppressed findings "
                "are included with Info severity and the suppression reason in "
                "the solution field."
            ),
        ),
    ] = False


class GitLabSASTReporterConfig(ReporterPluginConfigBase):
    name: Literal["gitlab-sast"] = "gitlab-sast"
    extension: str = "gl-sast-report.json"
    enabled: bool = True
    options: GitLabSASTReporterConfigOptions = GitLabSASTReporterConfigOptions()


@ash_reporter_plugin
class GitLabSASTReporter(ReporterPluginBase[GitLabSASTReporterConfig]):
    """Formats vulnerability findings report as GitLab SAST format.

    Workspace mode: per project, one artefact each, never merged.

    Not for the reason ``github_ghas`` is per project -- this reporter already
    iterates every run correctly (see the ``runs[0]``-only regression pinned in
    ``tests/unit/plugin_modules/test_reporter_regression.py``), so a merged
    document would contain every finding. It is per project because of what the
    document *is*: ``gl-sast-report.json`` is consumed as
    ``artifacts:reports:sast`` for one GitLab project, and its
    ``location.file`` paths are resolved against that project's repository root.
    A merged report uploaded for one project would show findings at paths that do
    not exist in it.

    ``projects/<key>/reports/`` gives one report per project, each already
    correct for its own upload, which is also the shape a monorepo pipeline with
    a job per project wants.
    """

    workspace_behaviour = ReporterWorkspaceBehaviour.PER_PROJECT

    def model_post_init(self, context):
        if self.config is None:
            self.config = GitLabSASTReporterConfig()
        return super().model_post_init(context)

    def report(self, model: "AshAggregatedResults") -> str:
        """The GitLab SAST document for *model*, always as a string.

        Never returns None, and the reason is that ``ReportPhase`` gates all file
        writing on the truthiness of this return. A falsy return produced no
        ``gl-sast-report.json`` at all and a "No report generated" note logged at
        DEBUG, so GitLab's SAST widget showed nothing rather than an error -- the
        most expensive possible outcome for a reporter whose whole job is to make
        findings visible. Where the transform cannot complete, the artefact still
        exists and its own ``scan.status`` and ``scan.messages`` say it is not
        trustworthy.
        """
        # Collected before the per-result loop so a failure here -- a model whose
        # SARIF cannot even be enumerated -- is distinguishable from a failure
        # transforming one result.
        try:
            all_results = model.sarif.get_all_results() if model.sarif else []
        except Exception as e:
            ASH_LOGGER.error(f"Failed to read SARIF results: {str(e)}")
            return self._failure_report(
                model, f"ASH could not read the SARIF results: {str(e)}"
            )

        vulnerabilities: List[Dict[str, Any]] = []
        skipped_results = 0
        if all_results:
            ASH_LOGGER.trace("Creating rule dict")
            for index, result in enumerate(all_results):
                # Scoped to one result so that a result this reporter cannot
                # transform costs that result rather than the entire report. The
                # exception set is open -- results arrive from third-party
                # scanners through an optional-everywhere schema -- so the
                # alternative is enumerating the ways one result can be
                # malformed, and missing one of them loses the run again.
                try:
                    vuln = self._vulnerability_for(result, model)
                except Exception as e:  # noqa: BLE001 -- see above
                    skipped_results += 1
                    ASH_LOGGER.error(
                        f"Skipping SARIF result {index} in the GitLab SAST "
                        f"report, which could not be transformed: {str(e)}"
                    )
                    continue
                if vuln is not None:
                    vulnerabilities.append(vuln)

        try:
            return self._assemble_report(model, vulnerabilities, skipped_results)
        except Exception as e:
            ASH_LOGGER.error(f"Failed to create GitLab SAST report: {str(e)}")
            return self._failure_report(
                model, f"ASH could not assemble the GitLab SAST report: {str(e)}"
            )

    def _vulnerability_for(
        self, result, model: "AshAggregatedResults"
    ) -> Dict[str, Any] | None:
        """One SARIF result as a GitLab vulnerability, or None to omit it.

        None means "deliberately excluded" -- a suppressed finding under
        ``exclude_suppressed`` -- and is the only omission that is not counted as
        a skip, because the operator asked for it.
        """
        # `ruleId` is optional in SARIF 2.1.0 and defaults to None, so bind it
        # once here and read the binding at every site below. Reading
        # `result.ruleId` directly is what made one null rule id lose the whole
        # report: the raw_source_code_extract expression called .startswith() on
        # it for every result, not only for secret findings.
        #
        # Empty rather than a placeholder, which is where this differs from
        # html_reporter's `result.ruleId or "UNKNOWN"`. That one is display text;
        # a GitLab identifier `value` is a matching key, so a placeholder would
        # collapse every rule-less finding in the project onto one invented rule
        # and make them look like recurrences of each other. The identifier is
        # omitted instead -- see the guard further down.
        rule_id = result.ruleId or ""
        # Same reasoning for the message: `text` is optional beside `markdown`,
        # and `message` itself is reached through a RootModel wrapper.
        message_root = getattr(result.message, "root", None)
        message_text = getattr(message_root, "text", None) or ""

        # Check if finding is suppressed
        is_suppressed = (
            hasattr(result, "suppressions")
            and result.suppressions
            and len(result.suppressions) > 0
        )

        # Optionally exclude suppressed findings entirely
        if is_suppressed and self.config and self.config.options.exclude_suppressed:
            ASH_LOGGER.trace(f"Skipping suppressed finding: {rule_id}")
            return None

        ASH_LOGGER.trace(f"Processing result: {rule_id}")

        # Determine severity
        severity = None
        if result.level:
            # Read `.value` before str(): Level is a (str, Enum) mixin, so
            # str(Level.error) is "Level.error", no branch below matches, severity
            # stays None, and the `if severity:` guard further down drops the key
            # entirely -- the vulnerability reaches the GitLab Security Dashboard
            # with nothing to triage or gate on. The field holds a member whenever
            # it was not validated, which includes every result that omitted the
            # optional level key.
            level_str = str(getattr(result.level, "value", result.level)).lower()
            if level_str == "error":
                severity = "High"
            elif level_str == "warning":
                severity = "Medium"
            elif level_str == "note":
                severity = "Low"
            elif level_str == "none":
                severity = None

        # Suppressed findings: downgrade to Info with solution
        suppression_solution = None
        if is_suppressed:
            severity = "Info"
            justification = result.suppressions[0].justification or "No reason provided"
            suppression_solution = (
                f"This finding was suppressed by ASH: {justification}. "
                "You can dismiss this vulnerability in the "
                "GitLab Security Dashboard."
            )

        # Get location information
        file_path = None
        start_line = None
        raw_source_code_extract = None

        if result.locations and len(result.locations) > 0:
            for location in result.locations:
                if location.physicalLocation:
                    loc = location.physicalLocation
                    if loc.root.artifactLocation and loc.root.artifactLocation.uri:
                        file_path = loc.root.artifactLocation.uri
                        if loc.root.region:
                            if loc.root.region.startLine:
                                start_line = loc.root.region.startLine
                            if loc.root.region.snippet and loc.root.region.snippet.text:
                                raw_source_code_extract = loc.root.region.snippet.text

        # Get scanner name from properties
        scanner_name = None
        props_dict: Dict[str, Any] = {}
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
            elif "tags" in props_dict and isinstance(props_dict["tags"], list):
                # Look for tool_name in tags
                for tag in props_dict["tags"]:
                    if isinstance(tag, str) and tag.startswith("tool_name::"):
                        scanner_name = tag.replace("tool_name::", "")
                        break

        # Generate finding ID
        finding_id = get_finding_id(
            rule_id=rule_id,
            file=file_path,
            start_line=start_line,
            end_line=start_line,
        )

        # Create identifiers
        identifiers: List[Dict[str, Any]] = []

        # Rule identifier. Gated on the rule id as well as the scanner because
        # `identifiers[].value` is minLength 1 in the GitLab security-report
        # schema, so a result with no rule id has no rule identifier to declare --
        # emitting one with an empty value would make the whole report invalid
        # rather than that one entry useless.
        if scanner_name and rule_id:
            identifiers.append(
                {
                    "type": f"{scanner_name}-rule",
                    "name": f"{scanner_name} Rule {rule_id}",
                    "value": rule_id,
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
        location_obj = {"file": file_path, "start_line": start_line}

        # Create details object
        details: Dict[str, Any] = {}

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
            "value": rule_id,
        }

        # Add properties as JSON string
        if result.properties:
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
        if "tags" in props_dict and isinstance(props_dict["tags"], list):
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

        # Which string goes in raw_source_code_extract, as two explicit branches.
        #
        # This was a conditional expression, and `or` binds tighter than `if`, so
        # it grouped as `(snippet or "Secret of type ...") if
        # rule_id.startswith("SECRET-") else message_text` -- meaning .startswith
        # ran for every result, not only for secret findings. That is how one
        # result with a null rule id raised AttributeError and cost the whole
        # report.
        #
        # The selection itself is deliberately unchanged, including that a
        # non-secret finding does NOT prefer its snippet over its message text.
        # Whether that is the right preference for a field the schema documents as
        # a source excerpt is a separate question from removing the crash, and
        # answering it here would alter this reporter's output for every located
        # non-secret finding. TestSecretExtractSelection pins both branches.
        if rule_id.startswith("SECRET-"):
            secret_kind = rule_id.replace("SECRET-", "").replace("-", " ").title()
            source_extract = (
                raw_source_code_extract or f"Secret of type {secret_kind} detected"
            )
        else:
            source_extract = message_text

        # Create vulnerability object
        vuln: Dict[str, Any] = {
            "id": finding_id,
            "identifiers": identifiers,
            "location": location_obj,
            "description": message_text,
            "raw_source_code_extract": source_extract,
            "details": details,
        }

        # The key is omitted for a result with no rule id, not set to None, which
        # is how `severity` below and the rule identifier above already treat an
        # answer they do not have. The schema types `name` as a string and does not
        # require it, so there are two states it describes -- a name, or no key --
        # and `null` is a third; of the three it is the one that asserts the
        # vulnerability is named and blank.
        #
        # Validating the emitted document does not catch a null here. The model in
        # `schemas.gitlab.sast` is generated from the schema, and the generator
        # renders a non-required string as `Optional[str]`, so `None` passes. The
        # test for this asserts on the key's absence for that reason.
        if rule_id:
            vuln["name"] = rule_id

        # Only add severity if it's not None
        if severity:
            vuln["severity"] = severity

        # Add solution for suppressed findings
        if suppression_solution:
            vuln["solution"] = suppression_solution

        return vuln

    def _assemble_report(
        self,
        model: "AshAggregatedResults",
        vulnerabilities: List[Dict[str, Any]],
        skipped_results: int,
    ) -> str:
        """The finished document for a transform that ran to completion."""
        # Get current timestamp
        report_time_iso = model.metadata.generated_at.split("+")[0]

        # A report that dropped findings must not read as a clean scan. GitLab's
        # SAST widget and any pipeline gate read `status` and nothing else, so
        # "success" on a partial transform is exactly the false negative this
        # reporter exists to prevent -- the count below is what makes the shortfall
        # legible to a human reading the artefact.
        messages: List[Dict[str, str]] = []
        if skipped_results:
            messages.append(
                {
                    "level": "warn",
                    "value": (
                        f"{skipped_results} SARIF result(s) could not be converted "
                        "to GitLab vulnerabilities and are absent from this "
                        "report. It is incomplete; see the ASH log for each error."
                    ),
                }
            )

        # Determine scan status
        scan_status = (
            "success"
            if model.metadata.summary_stats.actionable == 0 and not skipped_results
            else "failure"
        )

        # Create the final report structure matching the reference
        report_dict: Dict[str, Any] = {
            "version": GITLAB_SAST_SCHEMA_VERSION,
            "vulnerabilities": vulnerabilities,
            "scan": self._scan_section(report_time_iso, scan_status, messages),
        }

        return json.dumps(report_dict, separators=(",", ":"))

    def _failure_report(self, model: "AshAggregatedResults", detail: str) -> str:
        """A schema-valid report that states its own transform failed.

        Emitted instead of returning None because ``ReportPhase`` writes no file
        for a falsy return, which left GitLab's SAST widget empty rather than
        erroring. Emitted instead of an empty success document because that is
        byte-identical to a genuinely clean scan: the only thing separating the
        two would be one log line, and nothing downstream reads the log. So the
        artefact exists, ``status`` is "failure", and a fatal ``messages`` entry
        names the error that produced it.
        """
        return json.dumps(
            {
                "version": GITLAB_SAST_SCHEMA_VERSION,
                "vulnerabilities": [],
                "scan": self._scan_section(
                    self._scan_timestamp(model),
                    "failure",
                    [{"level": "fatal", "value": detail}],
                ),
            },
            separators=(",", ":"),
        )

    @staticmethod
    def _scan_timestamp(model: "AshAggregatedResults") -> str:
        """The scan timestamp, in the format the schema's pattern requires.

        Guarded because the failure path can be reached *because* the model is
        unreadable, and a fallback report that raises while building itself puts
        the run straight back into the silent-loss case it exists to escape.
        """
        try:
            return str(model.metadata.generated_at).split("+")[0]
        except Exception:  # noqa: BLE001 -- see the docstring
            return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")

    @staticmethod
    def _scan_section(
        timestamp: str, status: str, messages: List[Dict[str, str]]
    ) -> Dict[str, Any]:
        """The ``scan`` object, shared so the two exit paths cannot describe ASH
        differently."""
        scan: Dict[str, Any] = {
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
            "start_time": timestamp,
            "end_time": timestamp,
            "status": status,
        }
        if messages:
            scan["messages"] = messages
        return scan
