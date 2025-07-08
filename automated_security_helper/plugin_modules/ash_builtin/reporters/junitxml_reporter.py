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


import defusedxml
import warnings


class JUnitXMLReporterConfigOptions(ReporterOptionsBase):
    # Consider findings as failures only if they're at or above the scanner's severity threshold
    respect_severity_threshold: bool = True


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

    def report(self, model: "AshAggregatedResults") -> str:
        """Format ASH model in JUnitXML.

        Creates a test suite for each finding type, with individual findings as test cases.
        Failed findings are represented as failed tests with appropriate error messages.
        """
        from junitparser import (
            Error,
            JUnitXml,
            Skipped,
            TestCase,
            TestSuite,
        )

        report = JUnitXml(name="ASH Scan Report")

        test_suite_dict = {}

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
                if result.suppressions and len(result.suppressions) > 0:
                    test_case.result = [
                        Skipped(
                            message=suppression.justification,
                            type_="suppression",
                        )
                        for suppression in result.suppressions
                    ]
                else:
                    # Determine if finding is actionable based on severity threshold
                    is_actionable = True

                    # First check if the finding has a below_threshold property
                    if self.config.options.respect_severity_threshold and hasattr(
                        result, "properties"
                    ):
                        if result.properties and hasattr(
                            result.properties, "below_threshold"
                        ):
                            is_actionable = not result.properties.below_threshold
                        elif (
                            result.properties
                            and "below_threshold"
                            in result.properties.__pydantic_extra__
                        ):
                            is_actionable = not result.properties.__pydantic_extra__[
                                "below_threshold"
                            ]

                    # If no below_threshold property, check if we can determine it from the level
                    # This is a fallback for cases where the below_threshold property isn't set
                    if is_actionable and self.config.options.respect_severity_threshold:
                        # Get the threshold from properties if available
                        threshold = None
                        if hasattr(result, "properties") and result.properties:
                            if hasattr(result.properties, "severity_threshold"):
                                threshold = result.properties.severity_threshold
                            elif (
                                "severity_threshold"
                                in result.properties.__pydantic_extra__
                            ):
                                threshold = result.properties.__pydantic_extra__[
                                    "severity_threshold"
                                ]

                        # If we have a threshold and level, check if the finding is actionable
                        if threshold and result.level:
                            level = result.level.lower()
                            # Simple mapping of SARIF levels to severity thresholds
                            if threshold == "CRITICAL" and level != "error":
                                is_actionable = False
                            elif threshold == "HIGH" and level not in ["error"]:
                                is_actionable = False
                            elif threshold == "MEDIUM" and level not in [
                                "error",
                                "warning",
                            ]:
                                is_actionable = False

                    # Only mark as error if it's actionable
                    if is_actionable:
                        if result.level == "error" or result.kind == "fail":
                            test_case.result = [
                                Error(message=result.message.root.text, type_="error")
                            ]
                        elif result.level == "warning":
                            test_case.result = [
                                Error(message=result.message.root.text, type_="warning")
                            ]
                    else:
                        # Mark as skipped if below threshold
                        test_case.result = [
                            Skipped(
                                message="Finding is below configured severity threshold",
                                type_="threshold",
                            )
                        ]
                # elif result.kind not in ["notApplicable", "informational"]:
                #     pass

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
                actual_scanner = "ash"
                if "scanner_name" in result.properties.__pydantic_extra__:
                    actual_scanner = result.properties.__pydantic_extra__[
                        "scanner_name"
                    ]
                elif result.properties and result.properties.tags:
                    for tag in result.properties.tags:
                        if tag.startswith("tool_name::"):
                            actual_scanner = tag.split("::")[1]
                            break
                if (
                    actual_scanner == "ash"
                    and result.properties
                    and hasattr(result.properties, "scanner_details")
                ):
                    if hasattr(result.properties.scanner_details, "tool_name"):
                        actual_scanner = result.properties.scanner_details.tool_name
                if actual_scanner not in test_suite_dict:
                    test_suite_dict[actual_scanner] = TestSuite(name=actual_scanner)
                test_suite_dict[actual_scanner].add_testcase(test_case)

        for scanner, test_suite in test_suite_dict.items():
            report.add_testsuite(test_suite)
        # Return the XML string representation of all test suites
        report_bytes: bytes = report.tostring()
        return report_bytes.decode("utf-8")
