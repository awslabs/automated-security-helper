# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from datetime import datetime, timezone
from junitparser import (
    Error,
    JUnitXml,
    Skipped,
    TestCase,
    TestSuite,
)

from automated_security_helper.models.asharp_model import ASHARPModel
from automated_security_helper.models.interfaces import IOutputReporter
import defusedxml


class JUnitXMLReporter(IOutputReporter):
    """Formats results as JUnitXML."""

    def __init__(self):
        super().__init__()
        defusedxml.defuse_stdlib()

    def format(self, model: ASHARPModel) -> str:
        """Format ASH model in JUnitXML.

        Creates a test suite for each finding type, with individual findings as test cases.
        Failed findings are represented as failed tests with appropriate error messages.
        """
        report = JUnitXml(name="ASH Scan Report")

        # Process SARIF report @ model.sarif
        if model.sarif is not None:
            for result in model.sarif.runs[0].results:
                # Create test case name from SARIF result details
                test_name = (
                    f"{result.message.root} [{result.ruleId}]"
                    if result.ruleId
                    else result.message.root
                )
                test_case = TestCase(
                    name=test_name,
                    classname=result.ruleId,
                )

                # Add failure details for failed findings
                if result.level == "error" or result.kind == "fail":
                    test_case.result = [
                        Error(message=result.message.root, type_="error")
                    ]
                elif result.level == "warning":
                    test_case.result = [
                        Error(message=result.message.root, type_="warning")
                    ]
                elif result.kind not in ["notApplicable", "informational"]:
                    test_case.result = [Skipped(message=result.message.root)]

                # Add additional metadata in system-out
                metadata = []
                if hasattr(result, "properties"):
                    for key, value in result.properties.items():
                        metadata.append(f"{key}: {value}")
                if metadata:
                    test_case.stdout = "\n".join(metadata)

                # Create test suite for this finding type
                test_suite = TestSuite(
                    name=result.ruleId,
                    test_cases=[test_case],
                    package=model.name,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                )
                report.add_testsuite(test_suite)

        # Return the XML string representation of all test suites
        return report.tostring()
