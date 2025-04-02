# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Models for Dependency Scanning findings."""

from typing import Annotated, List, Optional, Dict
from pydantic import BaseModel, Field
from automated_security_helper.models.core import BaseFinding


class DependencyVulnerability(BaseFinding):
    """Model for dependency security findings."""

    package_name: str = Field(..., description="Name of the vulnerable package")
    package_version: str = Field(..., description="Version of the vulnerable package")
    ecosystem: str = Field(..., description="Package ecosystem (e.g., npm, pip, maven)")
    dependency_type: str = Field(..., description="Direct or transitive dependency")
    fixed_version: Optional[str] = Field(
        None, description="Version that fixes the vulnerability"
    )
    dependency_path: List[str] = Field(
        default_factory=list, description="Path to dependency in dependency tree"
    )
    cves: List[str] = Field(
        default_factory=list, description="Associated CVE identifiers"
    )


class DependencyScanReport(BaseModel):
    """Container for dependency scanning findings."""

    scanner_name: str = Field(..., description="Name of the dependency scanning tool")
    manifest_file: str = Field(..., description="Path to dependency manifest file")
    scan_timestamp: str = Field(..., description="Timestamp when scan was performed")
    findings: Annotated[List[DependencyVulnerability], Field()] = []
    dependencies: Annotated[
        Dict[str, str],
        Field(
            description="Dependencies as keys and their version number as the corresponding value"
        ),
    ] = {}
