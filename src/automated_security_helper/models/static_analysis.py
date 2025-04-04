# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Models for Static Analysis findings."""

from typing import Annotated, List
from pydantic import BaseModel, Field

# Import base classes using relative imports
from automated_security_helper.models.core import BaseFinding
from automated_security_helper.models.data_interchange import SecurityReport


class StaticAnalysisFinding(BaseFinding):
    """Model for static analysis security findings."""

    source_file: Annotated[
        str, Field(description="Source file where the issue was found")
    ]
    line_number: Annotated[
        int, Field(description="Line number where the issue was found")
    ] = None
    code_snippet: Annotated[str, Field(description="Relevant code snippet")] = None
    remediation_advice: Annotated[
        str, Field(description="Suggested fix for the issue")
    ] = None


class StaticAnalysisStatistics(BaseModel):
    """Statistics for static analysis scan results."""

    files_scanned: Annotated[
        int, Field(description="Total number of files scanned")
    ] = 0
    lines_of_code: Annotated[
        int, Field(description="Total number of lines of code")
    ] = 0
    total_findings: Annotated[int, Field(description="Total number of findings")] = 0
    findings_by_type: Annotated[
        dict, Field(description="Count of findings by severity level")
    ] = {}
    scan_duration_seconds: Annotated[
        float, Field(description="Duration of scan in seconds")
    ] = 0.0


class StaticAnalysisReport(SecurityReport):
    """Container for static analysis findings."""

    findings: Annotated[List[StaticAnalysisFinding], Field()] = []
    statistics: Annotated[StaticAnalysisStatistics, Field()] = (
        StaticAnalysisStatistics()
    )

    def group_findings_by_file(self):
        """Group findings by source file."""
        grouped_findings = {}
        for finding in self.findings:
            if finding.source_file not in grouped_findings:
                grouped_findings[finding.source_file] = []
            grouped_findings[finding.source_file].append(finding)
        return grouped_findings
