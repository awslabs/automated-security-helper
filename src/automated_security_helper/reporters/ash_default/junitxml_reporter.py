# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import Any, Literal


from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin


import defusedxml
import warnings


class JUnitXMLReporterConfigOptions(ReporterOptionsBase):
    pass


class JUnitXMLReporterConfig(ReporterPluginConfigBase):
    name: Literal["junitxml"] = "junitxml"
    extension: str = "junit.xml"
    enabled: bool = True
    options: JUnitXMLReporterConfigOptions = JUnitXMLReporterConfigOptions()


@ash_reporter_plugin
class JunitXmlReporter(ReporterPluginBase[JUnitXMLReporterConfig]):
    """Formats results as JUnitXML."""

    def model_post_init(self, context):
        with warnings.catch_warnings():
            defusedxml.defuse_stdlib()
        if self.config is None:
            self.config = JUnitXMLReporterConfig()
        return super().model_post_init(context)

    def report(self, model: Any) -> str:
        """Format ASH model in JUnitXML.

        Creates a test suite for each finding type, with individual findings as test cases.
        Failed findings are represented as failed tests with appropriate error messages.
        """
        from automated_security_helper.models.asharp_model import ASHARPModel
        from automated_security_helper.config.ash_config import AshConfig

        if not isinstance(model, ASHARPModel):
            raise ValueError(f"{self.__class__.__name__} only supports ASHARPModel")

        from junitparser import (
            Error,
            JUnitXml,
            Skipped,
            TestCase,
            TestSuite,
        )

        report = JUnitXml(name="ASH Scan Report")
        ash_config: AshConfig = AshConfig.model_validate(model.ash_config)
        test_suite = TestSuite(
            name="ASH Scan - " + ash_config.project_name,
        )

        # Process SARIF report @ model.sarif
        if model.sarif is not None:
            for result in model.sarif.runs[0].results:
                # Create test case name from SARIF result details
                test_name = (
                    f"{result.message.root.text} [{result.ruleId}]"
                    if result.ruleId
                    else result.message.root.text
                )
                test_case = TestCase(
                    name=test_name,
                    classname=result.ruleId,
                )

                # Add failure details for failed findings
                if result.level == "error" or result.kind == "fail":
                    test_case.result = [
                        Error(message=result.message.root.text, type_="error")
                    ]
                elif result.level == "warning":
                    test_case.result = [
                        Error(message=result.message.root.text, type_="warning")
                    ]
                elif result.kind not in ["notApplicable", "informational"]:
                    test_case.result = [Skipped(message=result.message.root.text)]

                # Add additional metadata in system-out
                metadata = []
                if hasattr(result, "properties") and result.properties is not None:
                    for key, value in result.properties.model_dump(
                        by_alias=True
                    ).items():
                        metadata.append(f"{key}: {value}")
                if metadata:
                    test_case.system_out = "\n".join(metadata)

                # Create test suite for this finding type
                test_suite.add_testcase(test_case)

        report.add_testsuite(test_suite)
        # Return the XML string representation of all test suites
        report_bytes: bytes = report.tostring()
        return report_bytes.decode("utf-8")
