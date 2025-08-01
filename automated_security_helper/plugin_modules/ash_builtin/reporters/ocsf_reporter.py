# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import Literal, TYPE_CHECKING

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
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
from datetime import datetime, timezone
import uuid
from typing import Optional, List, Tuple
from automated_security_helper.utils.log import ASH_LOGGER


class OCSFReporterConfigOptions(ReporterOptionsBase):
    pass


class OCSFReporterConfig(ReporterPluginConfigBase):
    name: Literal["ocsf"] = "ocsf"
    extension: str = "ocsf.json"
    enabled: bool = True
    options: OCSFReporterConfigOptions = OCSFReporterConfigOptions()


@ash_reporter_plugin
class OcsfReporter(ReporterPluginBase[OCSFReporterConfig]):
    """Formats results as an array of Open Cybersecurity Schema Framework (OCSF) VulnerabilityFinding objects."""

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
                if result.ruleId:
                    rule_id = result.ruleId
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

            # Safely extract severity level
            severity = "MEDIUM"  # Default
            try:
                if result.level:
                    # result.level is already the string value from the enum
                    severity = result.level.upper()
                    ASH_LOGGER.debug(
                        f"Extracted severity level for {rule_id}: {severity}"
                    )
            except Exception as e:
                ASH_LOGGER.debug(
                    f"Error extracting severity level for {rule_id}, using default MEDIUM: {str(e)}"
                )

            # Create vulnerability object with required fields
            vuln_dict = {
                "desc": desc,
                "title": rule_id,
                "severity": severity,
            }

            # Add CVE if rule ID exists and is valid
            try:
                if rule_id and rule_id != "Unknown Rule":
                    vuln_dict["cve"] = {
                        "uid": rule_id,
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
        """
        if not suppressions or len(suppressions) == 0:
            # No suppressions - finding is active/open
            ASH_LOGGER.debug(f"No suppressions found for {rule_id} - marking as active")
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
        self, result: Result, metadata: Metadata, current_time_ms: int
    ) -> VulnerabilityFinding:
        """Build individual VulnerabilityFinding object.

        Args:
            result: SARIF result object
            metadata: OCSF metadata object
            current_time_ms: Current timestamp in milliseconds

        Returns:
            VulnerabilityFinding object for the individual result
        """
        # Extract rule ID early for logging context
        rule_id = "Unknown Rule"
        try:
            if result.ruleId:
                rule_id = result.ruleId
        except Exception:
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

            # Map SARIF severity levels to OCSF severity IDs
            ASH_LOGGER.debug(f"Mapping severity level for {rule_id}")
            severity_id = SeverityId.integer_2  # Default to LOW
            try:
                if result.level:
                    # result.level is already the string value from the enum
                    level_str = result.level.lower()
                    if level_str == "error":
                        severity_id = SeverityId.integer_4  # HIGH
                    elif level_str == "warning":
                        severity_id = SeverityId.integer_3  # MEDIUM
                    elif level_str == "note":
                        severity_id = SeverityId.integer_2  # LOW
                    elif level_str == "none":
                        severity_id = SeverityId.integer_1  # INFORMATIONAL
                    ASH_LOGGER.debug(
                        f"Mapped severity for {rule_id}: {level_str} -> {severity_id}"
                    )
                else:
                    ASH_LOGGER.debug(
                        f"No severity level found for {rule_id}, using default LOW"
                    )
            except Exception as e:
                ASH_LOGGER.debug(
                    f"Error mapping severity level for {rule_id}, using default LOW: {str(e)}"
                )

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
            try:
                finding_uid = str(uuid.uuid4())
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
                fallback_uid = str(uuid.uuid4())
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
                "activity_id": ActivityId.integer_1,  # SCAN activity
                "activity_name": "Scan",
                "severity_id": severity_id,
                "type_uid": 200201,  # Vulnerability Finding type ID
                "class_uid": 2002,  # Vulnerability Finding class ID
                "category_uid": 2,  # Vulnerability Finding category ID
                "category_name": "Findings",
                "time": current_time_ms,
                "metadata": metadata,
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
            # Create minimal fallback finding
            try:
                ASH_LOGGER.debug(
                    f"Creating fallback VulnerabilityFinding for {rule_id}"
                )
                fallback_vulnerability = Vulnerability(
                    desc="Error processing vulnerability details",
                    title=rule_id if rule_id != "Unknown Rule" else "Unknown Rule",
                    severity="MEDIUM",
                )

                fallback_finding_info = FindingInfo(
                    uid=str(uuid.uuid4()),
                    title=f"Error processing finding {rule_id}",
                    desc="An error occurred while processing this security finding",
                )

                fallback_finding = VulnerabilityFinding(
                    activity_id=ActivityId.integer_1,
                    activity_name="Scan",
                    severity_id=SeverityId.integer_2,  # LOW
                    status_id=StatusId.integer_0,  # Unknown
                    type_uid=200201,
                    class_uid=2002,
                    category_uid=2,
                    category_name="Findings",
                    time=current_time_ms,
                    metadata=metadata,
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

    def report(self, model: "AshAggregatedResults") -> str:
        """Format ASH model in Open Cybersecurity Schema Framework (OCSF) format.

        Returns an array of VulnerabilityFinding objects, one per SARIF result.
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

        # Create array of individual VulnerabilityFinding objects
        vulnerability_findings = []
        total_results_count = 0
        failed_results_count = 0
        suppressed_findings_count = 0
        active_findings_count = 0

        # Check if we have SARIF data to process
        if not model.sarif:
            ASH_LOGGER.info("No SARIF data found in model - returning empty array")
            return json.dumps([], indent=2)

        if not model.sarif.runs:
            ASH_LOGGER.info("No SARIF runs found in model - returning empty array")
            return json.dumps([], indent=2)

        if not model.sarif.runs[0].results:
            ASH_LOGGER.info(
                "No SARIF results found in first run - returning empty array"
            )
            return json.dumps([], indent=2)

        total_results_count = len(model.sarif.runs[0].results)
        ASH_LOGGER.info(
            f"Processing {total_results_count} SARIF results for OCSF report"
        )

        for i, result in enumerate(model.sarif.runs[0].results):
            rule_id = getattr(result, "ruleId", None) or f"result_{i}"
            ASH_LOGGER.debug(
                f"Processing SARIF result {i + 1}/{total_results_count}: {rule_id}"
            )

            try:
                # Create individual VulnerabilityFinding for this result
                finding = self._create_vulnerability_finding(
                    result, metadata, current_time_ms
                )
                vulnerability_findings.append(finding)

                # Track finding status for statistics
                if (
                    hasattr(finding, "status_id")
                    and finding.status_id == StatusId.integer_4
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
            return self._create_error_response(
                "All findings failed to process",
                current_time_ms,
                total_results_count,
                failed_results_count,
            )

        # If no findings were created from empty input, return empty array
        if not vulnerability_findings:
            ASH_LOGGER.info(
                "No vulnerability findings created from SARIF results - returning empty array"
            )
            return json.dumps([], indent=2)

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

            final_json = json.dumps(findings_data, indent=2, default=str)
            ASH_LOGGER.info(
                f"Successfully generated OCSF report with {len(findings_data)} findings ({len(final_json)} characters)"
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
