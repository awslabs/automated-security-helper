# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Models for Container Scanning findings."""

from typing import Annotated, List, Optional
from pydantic import BaseModel, Field
from automated_security_helper.models.core import BaseFinding


class ContainerVulnerability(BaseFinding):
    """Model for container security findings."""

    package_name: str = Field(..., description="Name of the vulnerable package")
    installed_version: str = Field(..., description="Currently installed version")
    layer_id: Optional[str] = Field(
        None, description="ID of the affected container layer"
    )
    fixed_version: Optional[str] = Field(
        None, description="Version that fixes the vulnerability"
    )
    base_image_name: Optional[str] = Field(
        None, description="Base image name if vulnerability is from base image"
    )


class ContainerScanReport(BaseModel):
    """Container for container scanning findings."""

    findings: List[ContainerVulnerability] = Field(default_factory=list)
    scanner_name: str = Field(..., description="Name of the container scanning tool")
    registry: Optional[str] = Field(None, description="Container registry scanned")
    scan_timestamp: str = Field(..., description="Timestamp when scan was performed")
    image_name: Annotated[str, Field(description="Name of the container image")] = None
    image_tag: Annotated[str, Field(description="Tag of the container image")] = None
    definition: Annotated[
        str,
        Field(
            description="Definition of the container image, e.g. the Dockerfile that created it."
        ),
    ] = None
