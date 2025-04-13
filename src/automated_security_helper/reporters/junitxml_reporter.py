# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import Any
from junitparser import (
    Error,
    JUnitXml,
    Skipped,
    TestCase,
    TestSuite,
)

import defusedxml

from automated_security_helper.config.ash_config import ASHConfig


class JUnitXMLReporter:
    """Formats results as JUnitXML."""

    def __init__(self):
        super().__init__()
        defusedxml.defuse_stdlib()

    def format(self, model: Any) -> str:
        """Format ASH model in JUnitXML.

        Creates a test suite for each finding type, with individual findings as test cases.
        Failed findings are represented as failed tests with appropriate error messages.
        """
        from automated_security_helper.models.asharp_model import ASHARPModel

        if not isinstance(model, ASHARPModel):
            raise ValueError(f"{self.__class__.__name__} only supports ASHARPModel")

        report = JUnitXml(name="ASH Scan Report")
        ash_config: ASHConfig = ASHConfig.model_validate(model.ash_config)
        test_suite = TestSuite(
            name="ASH Scan - " + ash_config.project_name,
        )

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
                if hasattr(result, "properties") and result.properties is not None:
                    for key, value in result.properties.model_dump().items():
                        metadata.append(f"{key}: {value}")
                if metadata:
                    test_case.system_out = "\n".join(metadata)

                # Create test suite for this finding type
                test_suite.add_testcase(test_case)

        report.add_testsuite(test_suite)
        # Return the XML string representation of all test suites
        report_bytes: bytes = report.tostring()
        return report_bytes.decode("utf-8")
