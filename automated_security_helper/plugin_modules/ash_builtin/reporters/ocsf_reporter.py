# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import Any, Literal, TYPE_CHECKING

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    ReporterWorkspaceBehaviour,
)
from automated_security_helper.models.flat_vulnerability import (
    extract_workspace_project,
)
from automated_security_helper.models.workspace import SkippedProject
from automated_security_helper.plugin_modules.ash_builtin.reporters.workspace_skipped_rows import (
    skipped_project_detail,
    skipped_projects,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin
from automated_security_helper.schemas.ocsf.ocsf_vulnerability_finding import (
    VulnerabilityFinding,
    Vulnerability,
    # Cve,
    Metadata,
    Product,
    FindingInfo,
    ActivityId,
    SeverityId,
    StatusId,
)
from automated_security_helper.schemas.sarif_schema_model import Result, Suppression
from automated_security_helper.utils.get_ash_version import get_ash_version
import json
import re
from datetime import datetime, timezone
import uuid
from typing import Optional, List, Tuple
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sarif_utils import suppressions_in_effect
from automated_security_helper.utils.severity_ladder import result_severity

#: OCSF severity_id for each ASH severity (OCSF: 1 Informational, 2 Low,
#: 3 Medium, 4 High, 5 Critical).
_OCSF_SEVERITY_ID = {
    "CRITICAL": SeverityId.integer_5,
    "HIGH": SeverityId.integer_4,
    "MEDIUM": SeverityId.integer_3,
    "LOW": SeverityId.integer_2,
    "INFO": SeverityId.integer_1,
}


#: Prefix for the ``metadata.labels`` entry carrying workspace attribution.
#: ``key:value`` is OCSF's conventional shape for a label, and the prefix is what
#: lets a SIEM query for it without matching a project name by accident.
WORKSPACE_PROJECT_LABEL_PREFIX = "workspace_project:"

#: Marks a record that stands for a skipped project rather than for a finding.
#: Same ``key:value`` shape as the project label, so one SIEM query form covers
#: both; a fixed string rather than a prefix because there is nothing per-record to
#: carry -- the project is already on its own label.
SKIPPED_PROJECT_LABEL = "ash_row_type:workspace_skipped_project"

#: The free-form ``status`` accompanying ``status_id`` 99. OCSF defines 99 as "not
#: mapped -- see the ``status`` attribute, which contains a data source specific
#: value", so this string is what that lookup is meant to find.
SKIPPED_PROJECT_STATUS = "Skipped"

#: Prefix for a skipped project's ``finding_info.uid``. Deterministic, unlike a
#: real finding's fresh uuid4, so a re-run of the same workspace produces the same
#: identifier and a SIEM deduplicates rather than accumulating one record per run
#: for a project that keeps being skipped.
SKIPPED_PROJECT_UID_PREFIX = "ash-workspace-skipped-project:"

#: The ``activity_name`` for ``activity_id`` 1 of the OCSF vulnerability_finding
#: class, whose activities are Unknown (0), Create (1), Update (2), Close (3) and
#: Other (99). Every record this reporter emits is the creation of a finding.
#: The name was "Scan", which is not an activity of the class, beside the id 1.
ACTIVITY_NAME = "Create"

#: A CVE identifier, the only value OCSF's ``cve.uid`` is defined to hold.
_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

#: The namespace every finding's ``finding_info.uid`` is derived under. A uid was
#: a fresh uuid4 on every run, so the same finding reached a SIEM under a new
#: identifier each scan: the SIEM accumulated duplicates and could never update or
#: close one. A uuid5 over the finding's identity is a UUID (what consumers and the
#: existing tests expect) and the same across runs for the same finding.
_FINDING_UID_NAMESPACE = uuid.uuid5(
    uuid.NAMESPACE_URL, "https://github.com/awslabs/automated-security-helper/ocsf"
)


def _finding_uid(key: str) -> str:
    """The deterministic ``finding_info.uid`` for an identity *key*."""
    return str(uuid.uuid5(_FINDING_UID_NAMESPACE, key))


def _identity_key(result: Any, rule_id: str, message_text: Optional[str] = None) -> str:
    """A finding's identity from the result alone: rule, message, file and lines.

    The fallback for a result the run-level flattening did not give an id (a
    direct call of the finding builder, or a model that cannot be flattened).
    Every read is guarded, because this is called on the error paths too.
    """
    parts: List[str] = [str(rule_id)]
    try:
        text = message_text
        if text is None:
            root = getattr(getattr(result, "message", None), "root", None)
            text = getattr(root, "text", None)
        parts.append(str(text or ""))
    except Exception:  # noqa: BLE001 -- see the docstring
        parts.append("")
    try:
        for location in getattr(result, "locations", None) or []:
            physical = getattr(location, "physicalLocation", None)
            loc = getattr(physical, "root", physical)
            artifact = getattr(loc, "artifactLocation", None)
            region = getattr(loc, "region", None)
            parts.append(str(getattr(artifact, "uri", None) or ""))
            parts.append(str(getattr(region, "startLine", None) or ""))
            parts.append(str(getattr(region, "endLine", None) or ""))
    except Exception:  # noqa: BLE001 -- see the docstring
        pass
    return "|".join(parts)


def _shared_finding_ids(
    model: "AshAggregatedResults", all_results: List[Any]
) -> List[Optional[str]]:
    """The id every other ASH report gives each result, by position, else None.

    ``to_flat_vulnerabilities`` builds one flattened finding per SARIF result in
    ``get_all_results`` order (``utils/finding_identity``: scanner, rule, file,
    line, column, fingerprints, message, an occurrence counter for findings that
    still collide), so the uid derived from it is the same string the GitLab
    SAST report and the flat JSON report carry, and distinct for two identical
    results in one run.
    """
    try:
        flat = model.to_flat_vulnerabilities()
    except Exception as e:  # noqa: BLE001 -- a fallback, see _identity_key
        ASH_LOGGER.debug(f"Could not derive shared finding ids: {str(e)}")
        return [None] * len(all_results)
    ids = [getattr(item, "id", None) for item in flat[: len(all_results)]]
    if len(ids) != len(all_results) or not all(
        isinstance(item, str) and item for item in ids
    ):
        return [None] * len(all_results)
    return ids


def _rule_id(result: Any) -> Optional[str]:
    """The id of the rule *result* names: its ruleId, else its rule.id.

    SARIF 2.1.0 lets a result name its rule either way (3.27.5, 3.27.7). Read
    as ruleId alone, a result naming it as rule.id was emitted as "Unknown Rule".
    """
    rule_id = getattr(result, "ruleId", None)
    if rule_id:
        return rule_id
    rule = getattr(result, "rule", None)
    rule = getattr(rule, "root", rule)
    return getattr(rule, "id", None) or None


def _metadata_with_labels(metadata: Metadata, *labels: str) -> Metadata:
    """*metadata* with *labels* appended, as a copy.

    Copied rather than mutated in place: one ``Metadata`` instance is shared across
    every record in the report, so appending to its ``labels`` would give every
    record every other record's labels -- each one individually plausible, and the
    whole report useless for routing.

    Why ``labels`` and not a declared ``metadata`` field
    ---------------------------------------------------
    The RFC asked for the project "in metadata", and OCSF's ``Metadata`` sets
    ``extra="forbid"``. Worse than forbidding, pydantic's ``model_copy(update=...)``
    *silently drops* a key the schema does not declare -- so the obvious
    implementation would have produced findings with no attribution at all and no
    error to show for it. ``labels`` is the schema's own slot for free-form
    annotation, is indexed by SIEMs, and needs no schema extension.
    """
    existing = metadata.labels
    merged = list(existing) if isinstance(existing, list) else []
    for label in labels:
        if label not in merged:
            merged.append(label)
    return metadata.model_copy(update={"labels": merged})


def _metadata_for_project(metadata: Metadata, result: Result) -> Metadata:
    """*metadata* with this finding's workspace project recorded in ``labels``.

    Returns the shared object unchanged for a single-directory scan, so that
    output is byte-identical and no needless copies are made.
    """
    project = extract_workspace_project(result)
    if not project:
        return metadata
    return _metadata_with_labels(metadata, f"{WORKSPACE_PROJECT_LABEL_PREFIX}{project}")


class OCSFReporterConfigOptions(ReporterOptionsBase):
    pass


class OCSFReporterConfig(ReporterPluginConfigBase):
    name: Literal["ocsf"] = "ocsf"
    extension: str = "ocsf.json"
    enabled: bool = True
    options: OCSFReporterConfigOptions = OCSFReporterConfigOptions()


@ash_reporter_plugin
class OcsfReporter(ReporterPluginBase[OCSFReporterConfig]):
    """Formats results as an array of Open Cybersecurity Schema Framework (OCSF) VulnerabilityFinding objects.

    Workspace mode: one merged artefact, with the project carried in each
    finding's ``metadata``.

    ``metadata`` rather than ``resources`` or the finding title, because OCSF's
    ``Metadata`` object is where provenance belongs and a SIEM ingesting these
    can index on it without parsing a string. Each finding gets its own copy: the
    array is flat, an event is routed individually, and a project stated once at
    the top of the file would be lost the moment a consumer split the array --
    which is the normal way a SIEM ingests one.

    A skipped project gets one record of its own, because it has no findings and
    would otherwise be absent from this array in the one way a reader cannot
    notice. It is marked ``status_id`` 99 -- OCSF's "not mapped, see ``status``" --
    with ``status`` ``Skipped``, severity 1 (Informational), an empty
    ``vulnerabilities`` array, and a ``metadata.labels`` entry naming it a project
    record. See ``workspace_skipped_rows`` for why 99 rather than 3 (Suppressed) or
    0 (Unknown), and for what makes the record filterable.
    """

    workspace_behaviour = ReporterWorkspaceBehaviour.MERGED

    def model_post_init(self, context):
        if self.config is None:
            self.config = OCSFReporterConfig()
        return super().model_post_init(context)

    def _create_vulnerability_from_result(self, result: Result) -> Vulnerability:
        """Extract vulnerability data from SARIF result.

        Args:
            result: SARIF result object

        Returns:
            Vulnerability object with data extracted from SARIF result
        """
        rule_id = "Unknown Rule"
        try:
            # Safely extract rule ID first for logging context
            try:
                rule_id = _rule_id(result) or rule_id
            except Exception as e:
                ASH_LOGGER.debug(f"Error extracting rule ID: {str(e)}")

            ASH_LOGGER.debug(
                f"Creating vulnerability from SARIF result for rule: {rule_id}"
            )

            # Safely extract message text
            desc = ""
            try:
                if result.message and result.message.root and result.message.root.text:
                    desc = result.message.root.text
                ASH_LOGGER.debug(
                    f"Extracted message text for {rule_id}: {len(desc)} characters"
                )
            except Exception as e:
                ASH_LOGGER.debug(
                    f"Error extracting message text for {rule_id}: {str(e)}"
                )
                desc = "No description available"

            # The gate's severity (issue_severity, else the level, error being
            # CRITICAL), not the SARIF level ("ERROR").
            severity = result_severity(result)

            # Create vulnerability object with required fields
            vuln_dict = {
                "desc": desc,
                "title": rule_id,
                "severity": severity,
            }

            # Add a CVE only when the rule id is one. OCSF defines ``cve.uid``
            # as the CVE identifier; a scanner rule id (a bandit or checkov
            # rule) published there told a SIEM that every finding was a known
            # CVE. The rule id is the vulnerability's ``title`` either way.
            try:
                if rule_id and _CVE_ID.match(rule_id):
                    vuln_dict["cve"] = {
                        "uid": rule_id.upper(),
                        "desc": desc,
                    }
            except Exception as e:
                ASH_LOGGER.debug(f"Error creating CVE information: {str(e)}")

            # Add location information if available
            affected_code = []
            location_count = 0
            try:
                if result.locations and len(result.locations) > 0:
                    location_count = len(result.locations)
                    ASH_LOGGER.debug(
                        f"Processing {location_count} locations for {rule_id}"
                    )

                    for i, location in enumerate(result.locations):
                        try:
                            if (
                                location.physicalLocation
                                and location.physicalLocation.root
                            ):
                                loc = location.physicalLocation.root

                                # Safely extract file path
                                file_path = None
                                try:
                                    if (
                                        loc.artifactLocation
                                        and loc.artifactLocation.uri
                                    ):
                                        file_path = loc.artifactLocation.uri
                                        ASH_LOGGER.debug(
                                            f"Extracted file path for {rule_id} location {i}: {file_path}"
                                        )
                                except Exception as e:
                                    ASH_LOGGER.debug(
                                        f"Error extracting file path for {rule_id} location {i}: {str(e)}"
                                    )
                                    continue

                                if file_path:
                                    try:
                                        file_name = (
                                            file_path.split("/")[-1]
                                            if "/" in file_path
                                            else file_path
                                        )

                                        file_dict = {
                                            "name": file_name,
                                            "path": file_path,
                                            "type_id": 1,  # Regular file
                                        }

                                        code_dict = {"file": file_dict}

                                        # Safely extract region information
                                        try:
                                            if loc.region:
                                                if (
                                                    hasattr(loc.region, "startLine")
                                                    and loc.region.startLine
                                                ):
                                                    code_dict["start_line"] = (
                                                        loc.region.startLine
                                                    )
                                                    ASH_LOGGER.debug(
                                                        f"Extracted start line for {rule_id} location {i}: {loc.region.startLine}"
                                                    )
                                                if (
                                                    hasattr(loc.region, "endLine")
                                                    and loc.region.endLine
                                                ):
                                                    code_dict["end_line"] = (
                                                        loc.region.endLine
                                                    )
                                                    ASH_LOGGER.debug(
                                                        f"Extracted end line for {rule_id} location {i}: {loc.region.endLine}"
                                                    )
                                        except Exception as e:
                                            ASH_LOGGER.debug(
                                                f"Error extracting region info for {rule_id} location {i}: {str(e)}"
                                            )

                                        affected_code.append(code_dict)
                                        ASH_LOGGER.debug(
                                            f"Successfully processed location {i} for {rule_id}"
                                        )
                                    except Exception as e:
                                        ASH_LOGGER.debug(
                                            f"Error processing file information for {rule_id} location {i}: {str(e)}"
                                        )
                                        continue
                        except Exception as e:
                            ASH_LOGGER.debug(
                                f"Error processing {rule_id} location {i}: {str(e)}"
                            )
                            continue
                else:
                    ASH_LOGGER.debug(f"No locations found for {rule_id}")
            except Exception as e:
                ASH_LOGGER.debug(f"Error processing locations for {rule_id}: {str(e)}")

            ASH_LOGGER.debug(
                f"Created {len(affected_code)} affected code entries from {location_count} locations for {rule_id}"
            )

            if affected_code:
                vuln_dict["affected_code"] = affected_code

            vulnerability = Vulnerability(**vuln_dict)
            ASH_LOGGER.debug(f"Successfully created vulnerability object for {rule_id}")
            return vulnerability

        except Exception as e:
            ASH_LOGGER.error(
                f"Critical error creating vulnerability from result {rule_id}: {str(e)}"
            )
            # Return minimal vulnerability object as fallback
            fallback_vuln = Vulnerability(
                desc="Error processing vulnerability details",
                title=rule_id if rule_id != "Unknown Rule" else "Unknown Rule",
                severity="MEDIUM",
            )
            ASH_LOGGER.debug(f"Created fallback vulnerability object for {rule_id}")
            return fallback_vuln

    def _determine_status_from_suppressions(
        self, suppressions: Optional[List[Suppression]], rule_id: str = "Unknown"
    ) -> Tuple[Optional[StatusId], Optional[str], Optional[str]]:
        """Analyze suppressions and return appropriate status.

        Args:
            suppressions: List of SARIF suppressions or None
            rule_id: Rule ID for logging context

        Returns:
            Tuple of (status_id, status_detail) where:
            - status_id: StatusId enum value or None
            - status_detail: String with suppression details or None
            - status: String with suppression status correlating to the returned status_id

        Only a suppression in effect closes the finding. One ``rejected`` by the
        reviewer or still ``underReview`` has not taken effect (SARIF 3.35.4),
        and the exit code and the per-scanner counts read it that way
        (``sarif_utils.suppressions_in_effect``), so the record reads it the same
        way instead of reporting a finding the scan failed on as closed. Such a
        suppression is also left out of ``status_detail``, which explains why the
        finding is closed.
        """
        suppressions = suppressions_in_effect(suppressions)
        if not suppressions:
            # No suppression in effect - finding is active/open
            ASH_LOGGER.debug(
                f"No suppression in effect for {rule_id} - marking as active"
            )
            return StatusId.integer_1, None, "New"

        suppression_count = len(suppressions)
        ASH_LOGGER.debug(f"Processing {suppression_count} suppressions for {rule_id}")

        try:
            # Has suppressions - finding is suppressed/closed
            status_details = []
            processed_suppressions = 0
            failed_suppressions = 0

            for i, suppression in enumerate(suppressions):
                try:
                    detail_parts = []

                    # Safely extract kind
                    try:
                        if suppression.kind:
                            kind_value = str(suppression.kind).split(".")[-1]
                            detail_parts.append(f"kind: {kind_value}")
                            ASH_LOGGER.debug(
                                f"Extracted suppression kind for {rule_id} suppression {i}: {kind_value}"
                            )
                    except Exception as e:
                        ASH_LOGGER.debug(
                            f"Error extracting suppression kind for {rule_id} suppression {i}: {str(e)}"
                        )

                    # Safely extract state
                    try:
                        if suppression.state:
                            state_value = str(suppression.state).split(".")[-1]
                            detail_parts.append(f"state: {state_value}")
                            ASH_LOGGER.debug(
                                f"Extracted suppression state for {rule_id} suppression {i}: {state_value}"
                            )
                    except Exception as e:
                        ASH_LOGGER.debug(
                            f"Error extracting suppression state for {rule_id} suppression {i}: {str(e)}"
                        )

                    # Safely extract justification
                    try:
                        if (
                            suppression.justification
                            and suppression.justification.strip()
                        ):
                            justification = suppression.justification.strip()
                            detail_parts.append(f"justification: {justification}")
                            ASH_LOGGER.debug(
                                f"Extracted suppression justification for {rule_id} suppression {i}: {len(justification)} characters"
                            )
                    except Exception as e:
                        ASH_LOGGER.debug(
                            f"Error extracting suppression justification for {rule_id} suppression {i}: {str(e)}"
                        )

                    if detail_parts:
                        status_details.append("; ".join(detail_parts))
                        processed_suppressions += 1
                        ASH_LOGGER.debug(
                            f"Successfully processed suppression {i} for {rule_id}"
                        )
                    else:
                        # If no details could be extracted, add a generic entry
                        status_details.append(f"suppression_{i}")
                        processed_suppressions += 1
                        ASH_LOGGER.warning(
                            f"No details extracted for {rule_id} suppression {i}, using generic entry"
                        )

                except Exception as e:
                    failed_suppressions += 1
                    ASH_LOGGER.warning(
                        f"Error processing individual suppression {i} for {rule_id}: {str(e)}"
                    )
                    status_details.append(f"suppression_{i}_error")
                    continue

            # Log suppression processing statistics
            ASH_LOGGER.debug(
                f"Suppression processing for {rule_id}: {processed_suppressions} successful, {failed_suppressions} failed"
            )

            if failed_suppressions > 0:
                ASH_LOGGER.warning(
                    f"Failed to process {failed_suppressions}/{suppression_count} suppressions for {rule_id}"
                )

            status_detail = (
                " | ".join(status_details) if status_details else "Suppressed"
            )
            ASH_LOGGER.debug(
                f"Determined suppressed status for {rule_id} with detail: {status_detail[:100]}{'...' if len(status_detail) > 100 else ''}"
            )
            return StatusId.integer_3, status_detail, "Suppressed"

        except Exception as e:
            ASH_LOGGER.error(
                f"Critical error processing suppressions for {rule_id}: {str(e)}"
            )
            return StatusId.integer_0, "Unknown suppression status", "Unknown"

    def _create_vulnerability_finding(
        self,
        result: Result,
        metadata: Metadata,
        current_time_ms: int,
        shared_id: Optional[str] = None,
    ) -> VulnerabilityFinding:
        """Build individual VulnerabilityFinding object.

        Args:
            result: SARIF result object
            metadata: OCSF metadata object
            current_time_ms: Current timestamp in milliseconds
            shared_id: the finding's id in every other report
                (:func:`_shared_finding_ids`); the uid is derived from it, else
                from the result's own identity (:func:`_identity_key`)

        Returns:
            VulnerabilityFinding object for the individual result
        """
        # Extract rule ID early for logging context
        rule_id = "Unknown Rule"
        try:
            rule_id = _rule_id(result) or rule_id
        except Exception:  # nosec B110 — graceful fallback when ruleId attribute missing
            pass

        ASH_LOGGER.debug(f"Creating VulnerabilityFinding for {rule_id}")

        try:
            # Create vulnerability from result (this method has its own error handling)
            ASH_LOGGER.debug(f"Creating vulnerability object for {rule_id}")
            vulnerability = self._create_vulnerability_from_result(result)

            # Determine status from suppressions (this method has its own error handling)
            ASH_LOGGER.debug(f"Determining suppression status for {rule_id}")
            status_id, status_detail, status = self._determine_status_from_suppressions(
                getattr(result, "suppressions", None), rule_id
            )

            # severity_id from the gate's severity too, so a finding the scan
            # fails as critical reaches a SIEM as critical.
            severity_id = _OCSF_SEVERITY_ID[result_severity(result)]

            # Create unique finding info for this result
            ASH_LOGGER.debug(f"Creating finding info for {rule_id}")
            message_text = "No description"
            rule_part = rule_id  # Use already extracted rule_id

            try:
                # Safely extract message text
                if result.message and result.message.root and result.message.root.text:
                    message_text = result.message.root.text
                ASH_LOGGER.debug(
                    f"Extracted message text for finding info {rule_id}: {len(message_text)} characters"
                )
            except Exception as e:
                ASH_LOGGER.debug(
                    f"Error extracting message text for finding info {rule_id}: {str(e)}"
                )

            # Create descriptive title with proper truncation
            try:
                # Extract location info for more descriptive titles
                location_info = ""
                try:
                    if result.locations and len(result.locations) > 0:
                        first_location = result.locations[0]
                        if (
                            first_location.physicalLocation
                            and first_location.physicalLocation.root
                            and first_location.physicalLocation.root.artifactLocation
                            and first_location.physicalLocation.root.artifactLocation.uri
                        ):
                            file_path = first_location.physicalLocation.root.artifactLocation.uri
                            file_name = (
                                file_path.split("/")[-1]
                                if "/" in file_path
                                else file_path
                            )
                            location_info = f" in {file_name}"
                            ASH_LOGGER.debug(
                                f"Extracted location info for {rule_id} title: {location_info}"
                            )
                except Exception as e:
                    ASH_LOGGER.debug(
                        f"Error extracting location for {rule_id} title: {str(e)}"
                    )

                # Create title with rule, location, and message
                title_prefix = f"{rule_part}{location_info} - "
                remaining_chars = max(
                    0, 120 - len(title_prefix)
                )  # Increased max length for more descriptive titles

                if len(message_text) <= remaining_chars:
                    title = f"{rule_part}{location_info} - {message_text}"
                else:
                    title = f"{rule_part}{location_info} - {message_text[:remaining_chars]}..."
                    ASH_LOGGER.debug(
                        f"Truncated title for {rule_id} from {len(message_text)} to {len(title)} characters"
                    )

                ASH_LOGGER.debug(
                    f"Created title for {rule_id}: {title[:50]}{'...' if len(title) > 50 else ''}"
                )
            except Exception as e:
                ASH_LOGGER.debug(
                    f"Error creating title for {rule_id}, using fallback: {str(e)}"
                )
                title = f"{rule_part} - {message_text}"[:120]

            # Create finding info with error handling
            ASH_LOGGER.debug(f"Creating FindingInfo object for {rule_id}")
            identity = shared_id or _identity_key(result, rule_id, message_text)
            try:
                finding_uid = _finding_uid(identity)
                finding_info = FindingInfo(
                    uid=finding_uid,
                    title=title,
                    desc=message_text,
                )
                ASH_LOGGER.debug(
                    f"Created FindingInfo for {rule_id} with UID: {finding_uid}"
                )
            except Exception as e:
                ASH_LOGGER.warning(
                    f"Error creating FindingInfo for {rule_id}, using minimal version: {str(e)}"
                )
                fallback_uid = _finding_uid(f"{identity}|fallback-info")
                finding_info = FindingInfo(
                    uid=fallback_uid,
                    title="Error creating finding title",
                    desc="Error extracting finding description",
                )
                ASH_LOGGER.debug(
                    f"Created fallback FindingInfo for {rule_id} with UID: {fallback_uid}"
                )

            # Create OCSF vulnerability finding
            ASH_LOGGER.debug(f"Creating VulnerabilityFinding object for {rule_id}")
            vulnerability_finding_dict = {
                "activity_id": ActivityId.integer_1,  # Create
                "activity_name": ACTIVITY_NAME,
                "severity_id": severity_id,
                "type_uid": 200201,  # Vulnerability Finding type ID
                "class_uid": 2002,  # Vulnerability Finding class ID
                "category_uid": 2,  # Vulnerability Finding category ID
                "category_name": "Findings",
                "time": current_time_ms,
                "metadata": _metadata_for_project(metadata, result),
                "finding_info": finding_info,
                "vulnerabilities": [vulnerability],
            }

            # Add status information if available
            if status_id is not None:
                vulnerability_finding_dict["status_id"] = status_id
                ASH_LOGGER.debug(f"Added status_id for {rule_id}: {status_id}")
            if status is not None:
                vulnerability_finding_dict["status"] = status
                ASH_LOGGER.debug(f"Added status_id for {rule_id}: {status_id}")
            if status_detail is not None:
                vulnerability_finding_dict["status_detail"] = status_detail
                ASH_LOGGER.debug(
                    f"Added status_detail for {rule_id}: {status_detail[:50]}{'...' if len(status_detail) > 50 else ''}"
                )

            vuln_finding = VulnerabilityFinding(**vulnerability_finding_dict)
            ASH_LOGGER.debug(f"Successfully created VulnerabilityFinding for {rule_id}")
            return vuln_finding

        except Exception as e:
            ASH_LOGGER.error(
                f"Critical error creating VulnerabilityFinding for {rule_id}: {str(e)}"
            )
            # Create minimal fallback finding. It keeps what can still be read
            # of the finding: the gate's severity and the workspace project,
            # each guarded on its own. A fallback that hardcoded LOW and the
            # shared metadata turned a CRITICAL finding of one project into a
            # LOW record of no project.
            try:
                ASH_LOGGER.debug(
                    f"Creating fallback VulnerabilityFinding for {rule_id}"
                )
                try:
                    fallback_severity = result_severity(result)
                    fallback_severity_id = _OCSF_SEVERITY_ID[fallback_severity]
                except Exception:  # noqa: BLE001 -- the fallback's own fallback
                    fallback_severity = "LOW"
                    fallback_severity_id = SeverityId.integer_2
                try:
                    fallback_metadata = _metadata_for_project(metadata, result)
                except Exception:  # noqa: BLE001 -- the fallback's own fallback
                    fallback_metadata = metadata

                fallback_vulnerability = Vulnerability(
                    desc="Error processing vulnerability details",
                    title=rule_id if rule_id != "Unknown Rule" else "Unknown Rule",
                    severity=fallback_severity,
                )

                fallback_finding_info = FindingInfo(
                    uid=_finding_uid(
                        f"{shared_id or _identity_key(result, rule_id)}|fallback"
                    ),
                    title=f"Error processing finding {rule_id}",
                    desc="An error occurred while processing this security finding",
                )

                fallback_finding = VulnerabilityFinding(
                    activity_id=ActivityId.integer_1,
                    activity_name=ACTIVITY_NAME,
                    severity_id=fallback_severity_id,
                    status_id=StatusId.integer_0,  # Unknown
                    type_uid=200201,
                    class_uid=2002,
                    category_uid=2,
                    category_name="Findings",
                    time=current_time_ms,
                    metadata=fallback_metadata,
                    finding_info=fallback_finding_info,
                    vulnerabilities=[fallback_vulnerability],
                )
                ASH_LOGGER.debug(f"Created fallback VulnerabilityFinding for {rule_id}")
                return fallback_finding
            except Exception as fallback_error:
                ASH_LOGGER.error(
                    f"Failed to create fallback VulnerabilityFinding for {rule_id}: {str(fallback_error)}"
                )
                raise Exception(
                    f"Unable to create VulnerabilityFinding for {rule_id}: {str(e)}"
                )

    def _create_skipped_project_finding(
        self, entry: SkippedProject, metadata: Metadata, current_time_ms: int
    ) -> VulnerabilityFinding:
        """One record standing for a project that was never scanned.

        ``vulnerabilities`` is required by the class, so the record cannot omit it
        -- but an empty array is both the honest value and the filter: a consumer
        summing vulnerability counts across the array never sees this record.

        ``severity_id`` 1 is Informational, deliberately not 0 (Unknown). Unknown
        severity is a thing a scanner says about a finding it could not rank, and
        some pipelines escalate it; this is not a finding at all, and Informational
        is the bucket that neither escalates nor disappears.

        No ``try``/``except`` here, unlike the finding builder. That one wraps
        untrusted scanner output whose shape varies; every value here comes from a
        validated ``SkippedProject``, so a failure would be a bug in this code and
        should surface rather than be swallowed into a fallback record that says
        less than the real one.
        """
        return VulnerabilityFinding(
            activity_id=ActivityId.integer_1,
            activity_name=ACTIVITY_NAME,
            # Informational: the record reports a fact about the run, not a risk.
            severity_id=SeverityId.integer_1,
            # 99 is OCSF's "not mapped -- see `status`". See the module constants.
            status_id=StatusId.integer_99,
            status=SKIPPED_PROJECT_STATUS,
            status_detail=skipped_project_detail(entry),
            type_uid=200201,
            class_uid=2002,
            category_uid=2,
            category_name="Findings",
            time=current_time_ms,
            metadata=_metadata_with_labels(
                metadata,
                f"{WORKSPACE_PROJECT_LABEL_PREFIX}{entry.project}",
                SKIPPED_PROJECT_LABEL,
            ),
            finding_info=FindingInfo(
                uid=f"{SKIPPED_PROJECT_UID_PREFIX}{entry.project}",
                title=f"Project '{entry.project}' was not scanned",
                desc=skipped_project_detail(entry),
            ),
            vulnerabilities=[],
        )

    def _serialize_skipped_project_findings(
        self, findings: list[VulnerabilityFinding]
    ) -> list[dict[str, Any]]:
        """*findings* as dumped dicts, with the same options the real records use.

        Same ``by_alias``/``exclude_none``/``exclude_unset`` triple, so a project
        record and a finding record are shaped alike and a consumer needs one
        parser rather than two. ``vulnerabilities=[]`` survives ``exclude_unset``
        because it is passed explicitly, which is what keeps the required attribute
        present.
        """
        return [
            finding.model_dump(
                by_alias=True,
                exclude_none=True,
                exclude_unset=True,
            )
            for finding in findings
        ]

    def report(self, model: "AshAggregatedResults") -> str:
        """Format ASH model in Open Cybersecurity Schema Framework (OCSF) format.

        Returns an array of VulnerabilityFinding objects, one per SARIF result,
        plus one per skipped workspace project.
        """
        ASH_LOGGER.info("Starting OCSF report generation")

        # Get current timestamp in milliseconds since epoch
        current_time_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        ASH_LOGGER.debug(f"Report timestamp: {current_time_ms}")

        # Create base OCSF product metadata
        product = Product(
            name="Automated Security Helper",
            vendor_name="Amazon Web Services",
            version=get_ash_version(),
        )

        metadata = Metadata(
            product=product,
            version="1.1.0",  # OCSF schema version
            logged_time=current_time_ms,
        )
        ASH_LOGGER.debug(f"Created OCSF metadata with ASH version: {get_ash_version()}")

        # Built before the four no-findings early returns below, because those are
        # exactly the cases that lose the disclosure: a workspace whose scanned
        # projects all came back clean has no results, and returning a bare `[]`
        # there would make the artefact say nothing at all about a project the
        # operator asked for. Kept in its own list rather than appended to
        # `vulnerability_findings` so that every statistic and failure rate below
        # still counts real findings only -- merging here would inflate the success
        # rate with records that never went through the fragile builder.
        skipped_project_findings = [
            self._create_skipped_project_finding(entry, metadata, current_time_ms)
            for entry in skipped_projects(model)
        ]
        skipped_project_data = self._serialize_skipped_project_findings(
            skipped_project_findings
        )

        def _only_skipped_projects() -> str:
            """The array when there are no findings at all.

            ``json.dumps([], indent=2)`` is ``"[]"``, so a scan with nothing to
            report and nothing skipped produces the exact string it always has --
            which matters, because a consumer may well be comparing against it.
            """
            return json.dumps(skipped_project_data, indent=2, default=str)

        # Create array of individual VulnerabilityFinding objects
        vulnerability_findings = []
        total_results_count = 0
        failed_results_count = 0
        suppressed_findings_count = 0
        active_findings_count = 0

        # Check if we have SARIF data to process
        if not model.sarif:
            ASH_LOGGER.info("No SARIF data found in model - returning empty array")
            return _only_skipped_projects()

        if not model.sarif.runs:
            ASH_LOGGER.info("No SARIF runs found in model - returning empty array")
            return _only_skipped_projects()

        all_results = model.sarif.get_all_results()

        if not all_results:
            ASH_LOGGER.info("No SARIF results found in any run - returning empty array")
            return _only_skipped_projects()

        total_results_count = len(all_results)
        ASH_LOGGER.info(
            f"Processing {total_results_count} SARIF results for OCSF report"
        )
        shared_ids = _shared_finding_ids(model, all_results)

        for i, result in enumerate(all_results):
            rule_id = _rule_id(result) or f"result_{i}"
            ASH_LOGGER.debug(
                f"Processing SARIF result {i + 1}/{total_results_count}: {rule_id}"
            )

            try:
                # Create individual VulnerabilityFinding for this result
                finding = self._create_vulnerability_finding(
                    result, metadata, current_time_ms, shared_id=shared_ids[i]
                )
                vulnerability_findings.append(finding)

                # Track finding status for statistics
                if (
                    hasattr(finding, "status_id")
                    and finding.status_id == StatusId.integer_3
                ):
                    suppressed_findings_count += 1
                    ASH_LOGGER.debug(
                        f"Created suppressed vulnerability finding for {rule_id}"
                    )
                else:
                    active_findings_count += 1
                    ASH_LOGGER.debug(
                        f"Created active vulnerability finding for {rule_id}"
                    )

            except Exception as e:
                failed_results_count += 1
                ASH_LOGGER.error(
                    f"Error creating vulnerability finding for result {rule_id}: {str(e)}"
                )
                ASH_LOGGER.debug(
                    f"Failed result details - Rule ID: {rule_id}, Level: {getattr(result, 'level', None)}, Suppressions: {len(getattr(result, 'suppressions', []) or [])}"
                )
                continue

        processed_results_count = len(vulnerability_findings)

        # Log comprehensive processing statistics
        if total_results_count > 0:
            success_rate = (processed_results_count / total_results_count) * 100
            ASH_LOGGER.info(
                f"OCSF report processing complete: {processed_results_count}/{total_results_count} findings created successfully ({success_rate:.1f}% success rate)"
            )
            ASH_LOGGER.info(
                f"Finding status breakdown: {active_findings_count} active, {suppressed_findings_count} suppressed"
            )

            if failed_results_count > 0:
                failure_rate = (failed_results_count / total_results_count) * 100
                ASH_LOGGER.warning(
                    f"{failed_results_count} findings failed to process and were skipped ({failure_rate:.1f}% failure rate)"
                )
        else:
            ASH_LOGGER.debug("No SARIF results to process")

        # Handle case where all findings failed to process
        if total_results_count > 0 and processed_results_count == 0:
            ASH_LOGGER.error(
                "All SARIF results failed to process - returning error response"
            )
            # processed_results_count, which is 0 here, not the total: the
            # response adds its two counts into a total, so passing the total
            # as the processed count doubled it and stated a 50% success rate
            # for a run in which every result failed.
            return self._create_error_response(
                "All findings failed to process",
                current_time_ms,
                processed_results_count,
                failed_results_count,
            )

        # If no findings were created from empty input, return empty array
        if not vulnerability_findings:
            ASH_LOGGER.info(
                "No vulnerability findings created from SARIF results - returning empty array"
            )
            return _only_skipped_projects()

        try:
            # Convert array of findings to JSON
            ASH_LOGGER.debug(
                f"Serializing {len(vulnerability_findings)} findings to JSON"
            )
            findings_data = []
            serialization_failures = 0

            for i, finding in enumerate(vulnerability_findings):
                finding_id = "Unknown"
                try:
                    if hasattr(finding, "finding_info") and hasattr(
                        finding.finding_info, "uid"
                    ):
                        finding_id = finding.finding_info.uid

                    ASH_LOGGER.debug(
                        f"Serializing finding {i + 1}/{len(vulnerability_findings)}: {finding_id}"
                    )
                    finding_data = finding.model_dump(
                        by_alias=True,
                        exclude_none=True,
                        exclude_unset=True,
                    )
                    findings_data.append(finding_data)
                    ASH_LOGGER.debug(f"Successfully serialized finding {finding_id}")
                except Exception as e:
                    serialization_failures += 1
                    ASH_LOGGER.error(
                        f"Error serializing individual finding {finding_id}: {str(e)}"
                    )
                    continue

            if serialization_failures > 0:
                serialization_failure_rate = (
                    serialization_failures / len(vulnerability_findings)
                ) * 100
                ASH_LOGGER.warning(
                    f"{serialization_failures} findings failed to serialize and were excluded from output ({serialization_failure_rate:.1f}% serialization failure rate)"
                )

            # If all findings failed to serialize, return error response
            if len(findings_data) == 0 and len(vulnerability_findings) > 0:
                ASH_LOGGER.error(
                    "All findings failed to serialize - returning error response"
                )
                return self._create_error_response(
                    "All findings failed to serialize",
                    current_time_ms,
                    processed_results_count,
                    processed_results_count,  # All processed findings failed to serialize
                )

            # Appended AFTER the all-failed check, deliberately. The error response
            # is not a findings array -- it is a single-element envelope carrying
            # processing statistics -- so mixing project records into it would
            # produce a document neither shape describes. A skip lost there is
            # still in the payload and in the other five reporters, and a run where
            # every finding failed to serialise has a larger problem to report.
            findings_data.extend(skipped_project_data)

            final_json = json.dumps(findings_data, indent=2, default=str)
            # Counted apart from the findings rather than folded in, for the same
            # reason the records are marked in the output: a log line that called
            # them findings would be the first place the conflation appeared.
            ASH_LOGGER.info(
                f"Successfully generated OCSF report with "
                f"{len(findings_data) - len(skipped_project_data)} findings and "
                f"{len(skipped_project_data)} skipped-project records "
                f"({len(final_json)} characters)"
            )
            return final_json

        except Exception as e:
            ASH_LOGGER.error(f"Failed to serialize OCSF findings array: {str(e)}")
            return self._create_error_response(
                f"Failed to create OCSF report: {str(e)}",
                current_time_ms,
                processed_results_count,
                failed_results_count,
            )

    def _create_error_response(
        self,
        error_message: str,
        current_time_ms: int,
        processed_count: int,
        failed_count: int,
    ) -> str:
        """Create standardized error response with processing statistics.

        Args:
            error_message: Description of the error
            current_time_ms: Current timestamp in milliseconds
            processed_count: Number of successfully processed results
            failed_count: Number of failed results

        Returns:
            JSON string containing error response with statistics
        """
        ASH_LOGGER.debug(f"Creating error response: {error_message}")
        ASH_LOGGER.debug(
            f"Error response statistics - Processed: {processed_count}, Failed: {failed_count}"
        )

        try:
            total_count = processed_count + failed_count
            success_rate = (
                (processed_count / total_count) * 100 if total_count > 0 else 0
            )

            error_response = {
                "error": error_message,
                "metadata": {
                    "product": {
                        "name": "Automated Security Helper",
                        "vendor_name": "Amazon Web Services",
                        "version": get_ash_version(),
                    },
                    "version": "1.1.0",
                    "logged_time": current_time_ms,
                },
                "processing_statistics": {
                    "processed_results_count": processed_count,
                    "failed_results_count": failed_count,
                    "total_results_count": total_count,
                    "success_rate_percent": round(success_rate, 1),
                },
            }

            error_json = json.dumps([error_response], indent=2, default=str)
            ASH_LOGGER.debug(f"Created error response ({len(error_json)} characters)")
            return error_json

        except Exception as e:
            # Fallback to minimal error response if even error response creation fails
            ASH_LOGGER.error(f"Failed to create detailed error response: {str(e)}")
            fallback_response = json.dumps(
                [
                    {
                        "error": "Critical error in OCSF reporter - unable to create detailed error response"
                    }
                ],
                indent=2,
            )
            ASH_LOGGER.debug(
                f"Created fallback error response ({len(fallback_response)} characters)"
            )
            return fallback_response
