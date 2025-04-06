# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import junit_xml

from automated_security_helper.models.asharp_model import ASHARPModel
from automated_security_helper.outputs.interfaces import IOutputFormatter


class JUnitXMLFormatter(IOutputFormatter):
    """Formats results as JUnitXML."""

    def format(self, model: ASHARPModel) -> str:
        """Format ASH model in JUnitXML.

        Creates a test suite for each finding type, with individual findings as test cases.
        Failed findings are represented as failed tests with appropriate error messages.
        """
        all_test_suites = []
        grouped_findings = model.group_findings_by_type()

        for finding_type, findings in grouped_findings.items():
            test_cases = []
            for finding in findings:
                # Create test case name from finding details
                test_name = (
                    f"{finding.name} [{finding.rule_id}]"
                    if finding.rule_id
                    else finding.name
                )
                test_case = junit_xml.TestCase(
                    name=test_name,
                    classname=finding_type,
                    elapsed_sec=0,
                    timestamp=finding.detection_time.isoformat()
                    if finding.detection_time
                    else None,
                )

                # Add failure details for findings that need remediation
                if finding.status != "resolved":
                    test_case.add_failure_info(
                        message=f"Security finding: {finding.severity} severity",
                        output=finding.description,
                        stdout="\n".join(finding.remediation_steps)
                        if hasattr(finding, "remediation_steps")
                        else finding.remediation,
                    )

                # Add additional metadata in system-out
                metadata = []
                if hasattr(finding, "vulnerability_type"):
                    metadata.append(f"Vulnerability Type: {finding.vulnerability_type}")
                if hasattr(finding, "cwe_id") and finding.cwe_id:
                    metadata.append(f"CWE: {finding.cwe_id}")
                if hasattr(finding, "cvss_score") and finding.cvss_score is not None:
                    metadata.append(f"CVSS Score: {finding.cvss_score}")
                if metadata:
                    test_case.stdout = "\n".join(metadata)

                test_cases.append(test_case)

            # Create test suite for this finding type
            test_suite = junit_xml.TestSuite(
                name=finding_type,
                test_cases=test_cases,
                package=model.name,
                timestamp=model.scan_time.isoformat() if model.scan_time else None,
            )
            all_test_suites.append(test_suite)

        # Return the XML string representation of all test suites
        return junit_xml.to_xml_string(all_test_suites)
