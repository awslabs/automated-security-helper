# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Tuple, TYPE_CHECKING

from automated_security_helper.utils.sarif_utils import (
    get_finding_id,
    suppressions_in_effect,
)

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    ReporterWorkspaceBehaviour,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.shared_finding_ids import (
    shared_ids_by_position,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin

from automated_security_helper.utils.error_text import error_text
from automated_security_helper.utils.get_ash_version import get_ash_version
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.severity_ladder import result_severity
from automated_security_helper.utils.undecodable_text import recorded
from pydantic import Field
from typing import Annotated

#: The SARIF result kinds that state no problem: the rule was evaluated and
#: passed, did not apply, or produced information only. Such a result is not a
#: vulnerability and is left out of the report; written as one, a cdk-nag rule
#: that was not evaluated became an Info vulnerability on the dashboard.
_NON_FINDING_KINDS = frozenset({"pass", "notApplicable", "informational"})

#: The GitLab security-report schema's maxLength for ``vulnerabilities[].solution``
#: (schemas/gitlab/sast.py, the generated model). A suppression's justification is
#: copied into the solution, and one long justification made the whole report
#: invalid.
_SOLUTION_MAX_LENGTH = 7000

#: The prefix of a secret finding's rule id, read once, so a rule such as
#: SECRET-SECRET-KEYWORD keeps the rest of its name (``replace`` took every
#: occurrence and described it as type Keyword).
_SECRET_RULE_PREFIX = "SECRET-"

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
        # Exception text goes through error_text, as ReportPhase does for a
        # reporter's own failure: a pydantic ValidationError quotes the input it
        # refused, which can be a scanned file's text, and str(e) wrote it as it
        # was into scan.messages and the log.
        try:
            # Read field by field below, so a name set on a result after it was
            # validated is read from a copy in the record form.
            all_results = recorded(model.sarif).get_all_results() if model.sarif else []
        except Exception as e:
            ASH_LOGGER.error(f"Failed to read SARIF results: {error_text(e)}")
            return self._failure_report(
                model, f"ASH could not read the SARIF results: {error_text(e)}"
            )

        vulnerabilities: List[Dict[str, Any]] = []
        skipped_results = 0
        if all_results:
            shared_ids = self._shared_finding_ids(model, all_results)
            legacy_ids_seen: Dict[str, int] = {}
            ASH_LOGGER.trace("Creating rule dict")
            for index, result in enumerate(all_results):
                if self._is_not_a_finding(result):
                    continue
                # Scoped to one result so that a result this reporter cannot
                # transform costs that result rather than the entire report. The
                # exception set is open -- results arrive from third-party
                # scanners through an optional-everywhere schema -- so the
                # alternative is enumerating the ways one result can be
                # malformed, and missing one of them loses the run again.
                try:
                    vuln = self._vulnerability_for(result, model, shared_ids[index])
                except Exception as e:  # noqa: BLE001 -- see above
                    skipped_results += 1
                    ASH_LOGGER.error(
                        f"Skipping SARIF result {index} in the GitLab SAST "
                        f"report, which could not be transformed: {error_text(e)}"
                    )
                    continue
                if vuln is not None:
                    if shared_ids[index] is None:
                        self._distinct_legacy_id(vuln, legacy_ids_seen)
                    vulnerabilities.append(vuln)

        try:
            return self._assemble_report(model, vulnerabilities, skipped_results)
        except Exception as e:
            ASH_LOGGER.error(f"Failed to create GitLab SAST report: {error_text(e)}")
            return self._failure_report(
                model,
                f"ASH could not assemble the GitLab SAST report: {error_text(e)}",
            )

    @staticmethod
    def _is_not_a_finding(result: Any) -> bool:
        """Whether *result*'s ``kind`` says no problem was found (SARIF 3.27.9:
        pass, notApplicable, informational). An absent kind is ``fail``."""
        kind = getattr(result, "kind", None)
        kind_value = str(getattr(kind, "value", kind) or "fail")
        return kind_value in _NON_FINDING_KINDS

    @staticmethod
    def _message_text(result: Any) -> str:
        """The result's message as text: its ``text``, else its ``markdown``, else
        the ``id`` of the message string it names, else "".

        SARIF lets a message be given by ``id`` alone, resolved against the
        rule's ``messageStrings``; read as ``text`` alone, such a result had an
        empty description and source extract.
        """
        message_root = getattr(getattr(result, "message", None), "root", None)
        for field in ("text", "markdown", "id"):
            value = getattr(message_root, field, None)
            if isinstance(value, str) and value:
                return value
        return ""

    @staticmethod
    def _shared_finding_ids(
        model: "AshAggregatedResults", all_results: List[Any]
    ) -> List[str | None]:
        """The id every other ASH report gives each result, by position.

        ``to_flat_vulnerabilities`` builds one flattened finding per SARIF result
        in ``get_all_results`` order, and its id (``utils/finding_identity``)
        reads the scanner, the rule, the file, the line, the column, the
        fingerprints and the message, with an occurrence counter for findings
        that still collide. The legacy ``get_finding_id`` this reporter used
        hashed the rule, file and line only, so two distinct findings of one rule
        at one line shared an "unique" id and an ASH finding-id identifier, and
        the id differed from the one in every other report of the same scan.

        None at every position when the flattening fails or cannot be paired,
        and at a position whose flattened row does not describe its result
        (another rule, file or line), so a model this cannot read, and a result
        the flattening drifted from, keep the legacy id rather than taking
        another finding's; see :func:`shared_ids_by_position`. The pairing runs
        inside the guard too: it reads each result's locations, and a result
        whose locations misbehave is a legacy id at that position, never an
        exception out of ``report()`` with no artefact written.
        """
        try:
            flat = list(model.to_flat_vulnerabilities())
            return shared_ids_by_position(flat, all_results)
        except Exception as e:  # noqa: BLE001 -- a fallback, see the docstring
            ASH_LOGGER.debug(f"Could not derive shared finding ids: {str(e)}")
            return [None] * len(all_results)

    @staticmethod
    def _distinct_legacy_id(vuln: Dict[str, Any], seen: Dict[str, int]) -> None:
        """Give the second and later findings that fell back to one legacy id an
        id of their own.

        The legacy id hashes the rule, the file and the line, so two distinct
        findings of one rule at one line (a flattening this could not pair them
        with) shared the ``id`` and the ASH finding-id identifier, and GitLab,
        which deduplicates on either, kept one. The shared ids carry an occurrence
        counter for such pairs (``utils/finding_identity``), as the OCSF report's
        fallback uids do; this is the same counter for this report's fallback.
        The first finding keeps the legacy id as it was, so an id that never
        collided does not change between two pipelines of the same tree.
        """
        identifier = vuln["id"]
        count = seen.get(identifier, 0)
        seen[identifier] = count + 1
        if not count:
            return
        distinct = get_finding_id(rule_id=f"{identifier}::occurrence::{count}")
        vuln["id"] = distinct
        for entry in vuln.get("identifiers", []):
            if entry.get("type") == "ash-finding-id":
                entry["value"] = distinct

    def _vulnerability_for(
        self, result, model: "AshAggregatedResults", shared_id: str | None = None
    ) -> Dict[str, Any] | None:
        """One SARIF result as a GitLab vulnerability, or None to omit it.

        None means "deliberately excluded" -- a suppressed finding under
        ``exclude_suppressed`` -- and is the only omission that is not counted as
        a skip, because the operator asked for it. *shared_id* is the finding's
        id in every other report (:meth:`_shared_finding_ids`); without one the
        legacy rule-file-line id is used.
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
        # Same reasoning for the message: `text` is optional beside `markdown`
        # and an `id`, and `message` itself is reached through a RootModel
        # wrapper.
        message_text = self._message_text(result)

        # Check if finding is suppressed: by a suppression in effect. One
        # rejected or under review has not taken effect (SARIF 3.35.4) and the
        # gate still counts the finding, so the report shows it as the gate does.
        suppressions = suppressions_in_effect(getattr(result, "suppressions", None))
        is_suppressed = bool(suppressions)

        # Optionally exclude suppressed findings entirely
        if is_suppressed and self.config and self.config.options.exclude_suppressed:
            ASH_LOGGER.trace(f"Skipping suppressed finding: {rule_id}")
            return None

        ASH_LOGGER.trace(f"Processing result: {rule_id}")

        # Determine severity: the gate's reading (issue_severity, else the level,
        # error being Critical), in GitLab's spelling, so the Security Dashboard
        # shows a finding at the band the scan failed it at, and a severity a
        # scanner declared counts.
        severity = result_severity(result).title()

        # Suppressed findings: downgrade to Info with solution. The reason is
        # the first suppression in effect that gives one: ASH's own reasoned
        # suppression can sit after a scanner's bare one, and reading the first
        # entry alone said "No reason provided" beside it.
        suppression_solution = None
        if is_suppressed:
            severity = "Info"
            justification = next(
                (
                    str(getattr(s, "justification", None)).strip()
                    for s in suppressions
                    if str(getattr(s, "justification", None) or "").strip()
                ),
                "No reason provided",
            )
            suppression_solution = (
                f"This finding was suppressed by ASH: {justification}. "
                "You can dismiss this vulnerability in the "
                "GitLab Security Dashboard."
            )
            if len(suppression_solution) > _SOLUTION_MAX_LENGTH:
                # The schema caps the field; a cut reason beats an invalid report.
                suppression_solution = (
                    suppression_solution[: _SOLUTION_MAX_LENGTH - 3] + "..."
                )

        # Get location information
        file_path = None
        start_line = None
        raw_source_code_extract = None

        # The FIRST location with a file, and that location's own line and
        # snippet. The loop used to run over every location and overwrite the
        # file each time without resetting the line and snippet, so a result
        # with two locations was reported at the last location's file with an
        # earlier location's line and source excerpt, a position that exists in
        # neither.
        if result.locations and len(result.locations) > 0:
            for location in result.locations:
                if not location.physicalLocation:
                    continue
                loc = location.physicalLocation
                if loc.root.artifactLocation and loc.root.artifactLocation.uri:
                    file_path = loc.root.artifactLocation.uri
                    if loc.root.region:
                        if loc.root.region.startLine:
                            start_line = loc.root.region.startLine
                        if loc.root.region.snippet and loc.root.region.snippet.text:
                            raw_source_code_extract = loc.root.region.snippet.text
                    break

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

            # The scanner name, from the first of three places that has one:
            # scanner_name, scanner_details.tool_name, a tool_name:: tag. Read
            # as an elif chain keyed on key presence, an empty scanner_name or
            # a scanner_details without tool_name ended the lookup with nothing
            # and dropped the scanner and rule identifiers.
            scanner_name = props_dict.get("scanner_name") or None
            if not scanner_name:
                scanner_details = props_dict.get("scanner_details")
                if isinstance(scanner_details, dict):
                    scanner_name = scanner_details.get("tool_name") or None
            if not scanner_name and isinstance(props_dict.get("tags"), list):
                # Look for tool_name in tags
                for tag in props_dict["tags"]:
                    if isinstance(tag, str) and tag.startswith("tool_name::"):
                        scanner_name = tag[len("tool_name::") :] or None
                        break
            if scanner_name is not None and not isinstance(scanner_name, str):
                scanner_name = str(scanner_name)

        # The finding's id: the one every other report gives it, else the legacy
        # rule-file-line hash.
        finding_id = shared_id or get_finding_id(
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

        # No identifier for the scanner itself. GitLab deduplicates two findings
        # that share a location fingerprint and any one identifier other than
        # CWE or WASC, so a `{type: scanner, value: <scanner>}` identifier that
        # every finding of one scanner carried made two different rules firing
        # at one file and line into duplicates, and the Security Dashboard kept
        # the first. The scanner is already named by the rule identifier's type
        # above, by `details.scanner` and by `scan.scanner`.

        # ASH finding ID identifier
        identifiers.append(
            {
                "type": "ash-finding-id",
                "name": "ASH Finding ID",
                "value": finding_id,
            }
        )

        # Create location object. Only the fields that have a value: the GitLab
        # security-report schema types `file` as a string and `start_line` as a
        # number, so `"file": null` for a result with no artifact URI or region
        # fails validation of the whole report, where an empty `location` object
        # is valid and says what is true, that the finding has no file position.
        location_obj: Dict[str, Any] = {}
        if file_path:
            location_obj["file"] = file_path
        if start_line is not None:
            location_obj["start_line"] = start_line

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
        if rule_id.startswith(_SECRET_RULE_PREFIX):
            secret_kind = rule_id[len(_SECRET_RULE_PREFIX) :].replace("-", " ").title()
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
        report_time_iso = self._scan_timestamp(model)

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

        # The same holds for a scan that did less than it was asked to: a
        # scanner at ERROR or MISSING, a converter that did not run, a rule a
        # scanner could not evaluate, a content database past its bound, a tool
        # that could not be stopped. Each produced no findings for what it did
        # not cover, so a report that said "success" with no message was
        # byte-identical to a clean scan of the same tree. The messages are
        # always written; whether the gaps also fail the scan is the question
        # the exit code asks, under the operator's fail_on_incomplete_scanners
        # as the recorded config carries it (a command-line override is not
        # recorded, so the two can differ there), so a pip install without the
        # cdk extra that the operator has accepted does not read "failure" here
        # while the scan exits 0.
        coverage_messages, scan_incomplete = self._coverage(model)
        messages.extend(coverage_messages)

        # Determine scan status. "success" says the scan ran to completion and
        # this report carries everything it found.
        # Findings do not make it a failure; GitLab's analyzers report
        # "success" with a full vulnerabilities array, and the value "failure"
        # is what the transform-failure and incomplete-scan paths use, so a
        # scan that completed with findings was indistinguishable from one
        # that broke. The findings themselves decide the exit code elsewhere.
        scan_status = (
            "success" if not skipped_results and not scan_incomplete else "failure"
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

    @classmethod
    def _coverage(
        cls, model: "AshAggregatedResults"
    ) -> Tuple[List[Dict[str, str]], bool]:
        """The ``warn`` messages for everything the scan did not cover, and
        whether that makes the scan incomplete under the operator's gate.

        Both come from ``scan_incompleteness``, the object the exit code reads
        its own answer from. The messages are read with the gate on, so every
        fact is reported whatever ``fail_on_incomplete_scanners`` says: GitLab's
        widget reads this report, not the exit code. The status is read with
        the gate as :meth:`_completeness_gate` resolves it, from the same
        object's truth value, never re-derived from the messages: a report that
        asked only "did every scanner complete" said ``success`` for a scan
        that exited 1 because a rule was not evaluated, a converter did not
        run, a content database was stale or a tool could not be stopped, and
        would drift again at the next arm the exit code grows.

        Guarded, the import included, because a model this cannot read, or a
        scan module that cannot be imported, is not a reason to lose the
        vulnerabilities already transformed: an exception out of here would
        reach ``report()`` and become ``_failure_report`` with no
        vulnerabilities at all. But a coverage this could not read is not a
        coverage this can vouch for, so the failure is a ``warn`` message of
        its own, logged at WARNING, and the scan reads as incomplete under a
        gate that is on; it was logged at DEBUG and read as ``success``.
        """
        gate = cls._completeness_gate(model)
        try:
            from automated_security_helper.interactions.run_ash_scan import (
                scan_incompleteness,
            )

            facts = scan_incompleteness(model, gate=True)
            incomplete = (
                bool(facts) if gate else bool(scan_incompleteness(model, gate=False))
            )
            messages = cls._coverage_messages(facts)
        except Exception as e:  # noqa: BLE001 -- see the docstring
            ASH_LOGGER.warning(
                "Scanner coverage could not be determined for the GitLab SAST "
                f"report: {error_text(e)}"
            )
            return (
                [
                    {
                        "level": "warn",
                        "value": (
                            "Scanner coverage could not be determined; this "
                            "report cannot say whether the scan was complete."
                        ),
                    }
                ],
                gate,
            )
        return messages, incomplete

    @staticmethod
    def _coverage_messages(facts: Any) -> List[Dict[str, str]]:
        """One ``warn`` message per fact of *facts*, a ``ScanIncompleteness``.

        Every field that makes the object truthy has a message here, so a
        reader of the report alone learns each reason the exit code would give.
        """
        rows = [
            (str(name), str(getattr(status, "value", status)))
            for name, status in facts.scanners
        ]
        messages = [
            {
                "level": "warn",
                "value": (
                    f"Scanner {name} did not complete ({status}); its findings "
                    "are absent from this report."
                ),
            }
            for name, status in rows
        ]
        if facts.no_scanner_ran:
            messages.append(
                {
                    "level": "warn",
                    "value": (
                        "No scanner reached a verdict; this report describes a "
                        "tree that was not scanned."
                    ),
                }
            )
        for converter in facts.converters:
            name = getattr(converter, "name", None) or converter[0]
            reason = getattr(converter, "reason", None) or converter[1]
            messages.append(
                {
                    "level": "warn",
                    "value": (
                        f"Converter {name} did not complete ({reason}); the "
                        "inputs it would have converted were not scanned."
                    ),
                }
            )
        for rule in facts.unevaluated_rules:
            messages.append(
                {
                    "level": "warn",
                    "value": (
                        f"Rule {rule} could not be evaluated; what it would have "
                        "found is absent from this report."
                    ),
                }
            )
        for record in facts.stale_content_databases:
            scanner = getattr(record, "scanner", None) or "a scanner"
            database = getattr(record, "name", None) or "content database"
            messages.append(
                {
                    "level": "warn",
                    "value": (
                        f"Scanner {scanner} ran against a content database "
                        f"({database}) past its declared age bound; its findings "
                        "may be out of date."
                    ),
                }
            )
        for name, reason in facts.could_not_stop:
            messages.append(
                {
                    "level": "warn",
                    "value": (
                        f"Scanner {name}'s tool could not be stopped ({reason}); "
                        "it may still have been writing when this report was "
                        "taken."
                    ),
                }
            )
        return messages

    @staticmethod
    def _completeness_gate(model: "AshAggregatedResults") -> bool:
        """Whether an incomplete scanner fails this scan, as the operator set it.

        ``run_ash_scan._resolve_fail_on_incomplete_scanners`` answers the exit
        code's question from the command line, then the config the scan ran
        under, then the config file, then the model default (on). The command
        line is not recorded in the results, so this reads the two sources the
        model carries: ``ash_config.fail_on_incomplete_scanners`` when it is a
        real bool (a ``MagicMock`` model answers with a truthy non-answer, and
        a partially built one with None), else the default the resolver falls
        back to. A MISSING cdk-nag the operator accepted with
        ``fail_on_incomplete_scanners: false`` is then a warning in the report
        and not a ``failure`` beside an exit code of 0.
        """
        value = getattr(
            getattr(model, "ash_config", None), "fail_on_incomplete_scanners", None
        )
        return value if isinstance(value, bool) else True

    @staticmethod
    def _scan_timestamp(model: "AshAggregatedResults") -> str:
        """The scan timestamp in UTC, in the format the schema's pattern requires.

        The schema documents ``start_time`` and ``end_time`` as UTC values of the
        form ``yyyy-mm-ddThh:mm:ss``. ``generated_at`` is an ISO 8601 string with
        an offset; the old ``split("+")[0]`` kept a negative offset (which fails
        the pattern) and, for a positive one, labelled local wall time as UTC.
        The value is parsed and converted instead; a naive one is read as UTC.

        Guarded because the failure path can be reached *because* the model is
        unreadable, and a fallback report that raises while building itself puts
        the run straight back into the silent-loss case it exists to escape.
        """
        try:
            raw = str(model.metadata.generated_at).strip()
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
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
