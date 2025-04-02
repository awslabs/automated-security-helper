# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Models for Dynamic Analysis findings."""

from typing import Annotated, Any, List, Optional, Dict
from pydantic import BaseModel, Field
from automated_security_helper.models.core import BaseFinding


class DynamicAnalysisFinding(BaseFinding):
    """Model for dynamic analysis security findings."""

    endpoint: str = Field(..., description="Affected endpoint or URL")
    request_method: str = Field(..., description="HTTP method used")
    request_headers: Optional[Dict[str, str]] = Field(
        None, description="Request headers"
    )
    request_body: Optional[str] = Field(None, description="Request body")
    response_status: int = Field(..., description="HTTP response status code")
    reproduction_steps: Optional[List[str]] = Field(
        None, description="Steps to reproduce the issue"
    )


class DynamicAnalysisScanCoverage(BaseModel):
    endpoints_tested: int = 0
    auth_tested: bool = False
    input_vectors_tested: List[Any] = []


class DynamicAnalysisReport(BaseModel):
    """Container for dynamic analysis findings."""

    scanner_name: Annotated[
        str, Field(..., description="Name of the dynamic analysis tool")
    ]
    target_url: Annotated[str, Field(..., description="Base URL that was scanned")]
    scan_timestamp: Annotated[
        str, Field(..., description="Timestamp when scan was performed")
    ]
    findings: Annotated[List[DynamicAnalysisFinding], Field()] = []
    scan_coverage: Annotated[
        DynamicAnalysisScanCoverage, Field(description="Coverage metrics for the scan")
    ] = DynamicAnalysisScanCoverage()
