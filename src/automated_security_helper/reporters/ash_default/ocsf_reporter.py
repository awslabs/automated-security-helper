# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import Literal, TYPE_CHECKING

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import ASHARPModel
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin
from automated_security_helper.schemas.ocsf.vulnerability_finding import (
    VulnerabilityFinding,
    Vulnerability,
    # Cve,
    Metadata,
    Product,
    FindingInfo,
    ActivityId,
    SeverityId,
)
from automated_security_helper.utils.get_ash_version import get_ash_version
import json
from datetime import datetime, timezone
import uuid
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
    """Formats results as Open Cybersecurity Schema Framework (OCSF) format."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = OCSFReporterConfig()
        return super().model_post_init(context)

    def report(self, model: "ASHARPModel") -> str:
        """Format ASH model in Open Cybersecurity Schema Framework (OCSF) format."""
        # Get current timestamp in milliseconds since epoch
        current_time_ms = int(datetime.now(timezone.utc).timestamp() * 1000)

        # Create base OCSF product metadata
        product = Product(
            name="Automated Security Helper",
            vendor_name="Amazon Web Services",
            version=get_ash_version(),
        )

        metadata = Metadata(
            product=product,
            version="1.0.0",  # OCSF schema version
            logged_time=current_time_ms,
        )

        # Extract vulnerabilities from SARIF report
        vulnerabilities = []
        highest_severity_id = SeverityId.integer_0  # Default to INFO

        if model.sarif and model.sarif.runs and model.sarif.runs[0].results:
            for result in model.sarif.runs[0].results:
                # Map SARIF severity levels to OCSF severity IDs
                severity_id = SeverityId.integer_2  # Default to LOW
                if result.level:
                    level_str = str(result.level).lower()
                    if level_str == "error":
                        severity_id = SeverityId.integer_4  # HIGH
                        if severity_id > highest_severity_id:
                            highest_severity_id = severity_id
                    elif level_str == "warning":
                        severity_id = SeverityId.integer_3  # MEDIUM
                        if severity_id > highest_severity_id:
                            highest_severity_id = severity_id
                    elif level_str == "note":
                        severity_id = SeverityId.integer_2  # LOW
                        if severity_id > highest_severity_id:
                            highest_severity_id = severity_id
                    elif level_str == "none":
                        severity_id = SeverityId.integer_1  # INFORMATIONAL
                        if severity_id > highest_severity_id:
                            highest_severity_id = severity_id

                # Create vulnerability object with required fields
                vuln_dict = {
                    "desc": (
                        result.message.root.text
                        if result.message and result.message.root
                        else ""
                    ),
                    "title": result.ruleId or "Unknown Rule",
                    "severity": str(result.level).upper() if result.level else "MEDIUM",
                }

                # Add CVE if rule ID exists
                if result.ruleId:
                    vuln_dict["cve"] = {
                        "uid": result.ruleId,
                        "desc": (
                            result.message.root.text
                            if result.message and result.message.root
                            else ""
                        ),
                    }

                # Add location information if available
                affected_code = []
                if result.locations and len(result.locations) > 0:
                    for location in result.locations:
                        if location.physicalLocation:
                            loc = location.physicalLocation
                            if (
                                loc.root.artifactLocation
                                and loc.root.artifactLocation.uri
                            ):
                                file_path = loc.root.artifactLocation.uri
                                file_name = file_path.split("/")[-1]

                                file_dict = {
                                    "name": file_name,
                                    "path": file_path,
                                    "type_id": "1",  # Regular file
                                }

                                code_dict = {"file": file_dict}

                                if loc.root.region:
                                    if loc.root.region.startLine:
                                        code_dict["start_line"] = (
                                            loc.root.region.startLine
                                        )
                                    if loc.root.region.endLine:
                                        code_dict["end_line"] = loc.root.region.endLine

                                affected_code.append(code_dict)

                if affected_code:
                    vuln_dict["affected_code"] = affected_code

                # Create Vulnerability object
                try:
                    vuln = Vulnerability(**vuln_dict)
                    vulnerabilities.append(vuln)
                except Exception as e:
                    ASH_LOGGER.error(f"Error creating vulnerability object: {str(e)}")
                    continue

        # If no vulnerabilities found, create a placeholder
        if not vulnerabilities:
            vulnerabilities = [
                Vulnerability(
                    desc="No vulnerabilities found",
                    title="No Issues Detected",
                    severity="INFO",
                )
            ]
            highest_severity_id = SeverityId.integer_0  # INFO

        # Create finding info with required fields
        finding_info = FindingInfo(
            uid=str(uuid.uuid4()),
            title=f"ASH Security Scan - {model.metadata.project_name if model.metadata and model.metadata.project_name else 'Unknown Project'}",
            desc=f"Security scan performed by Automated Security Helper found {len(vulnerabilities)} potential issues",
        )

        # Create OCSF vulnerability finding with all required fields
        try:
            vulnerability_finding = VulnerabilityFinding(
                activity_id=ActivityId.integer_1,  # SCAN activity
                activity_name="Scan",
                severity_id=highest_severity_id,
                type_uid=200201,  # Vulnerability Finding type ID
                class_uid=2002,  # Vulnerability Finding class ID
                category_uid=2,  # Vulnerability Finding category ID
                time=current_time_ms,
                metadata=metadata,
                finding_info=finding_info,
                vulnerabilities=vulnerabilities,
            )

            # Convert to JSON
            return vulnerability_finding.model_dump_json(
                # by_alias=True,
                # exclude_none=True,
                # exclude_unset=True,
            )
        except Exception as e:
            ASH_LOGGER.error(f"Failed to create OCSF report: {str(e)}")
            # If there's an error creating the VulnerabilityFinding, return a simplified JSON
            return json.dumps(
                {
                    "error": f"Failed to create OCSF report: {str(e)}",
                    "metadata": {
                        "product": {
                            "name": "Automated Security Helper",
                            "vendor_name": "Amazon Web Services",
                            "version": get_ash_version(),
                        },
                        "version": "1.0.0",
                        "logged_time": current_time_ms,
                    },
                    "vulnerabilities_count": len(vulnerabilities),
                },
                indent=2,
                default=str,
            )
