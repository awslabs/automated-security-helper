"""Models for Infrastructure as Code Scanning findings."""

from enum import Enum
from typing import Annotated, List, Optional, Dict, Set, Union
import datetime
from pydantic import BaseModel, Field, ConfigDict, field_validator
from automated_security_helper.models.core import BaseFinding
from automated_security_helper.models.data_interchange import SecurityReport

__all__ = [
    "ComplianceFramework",
    "IaCFinding",
    "IaCReport",
    "IaCVulnerability",
    "IaCScanReport",
]


class ComplianceFramework(str, Enum):
    """Standard compliance frameworks."""

    CIS = "CIS"
    HIPAA = "HIPAA"
    NIST = "NIST"
    SOC2 = "SOC2"
    PCI = "PCI"


class IaCFinding(BaseFinding):
    """Model for Infrastructure as Code security findings."""

    resource_name: str = Field(..., description="Name of the affected resource")
    resource_type: Annotated[str, Field(description="Type of cloud resource")] = None
    expected_value: Optional[str] = Field(
        None, description="Expected configuration value"
    )
    actual_value: Optional[str] = Field(None, description="Current configuration value")
    compliance_frameworks: Set[Union[ComplianceFramework, str]] = Field(
        default_factory=set, description="Compliance frameworks this violation impacts"
    )
    remediation_terraform: Optional[str] = Field(
        None, description="Terraform remediation steps"
    )
    remediation_cloudformation: Optional[str] = Field(
        None, description="CloudFormation remediation steps"
    )
    resource_impact: str = Field(
        default="Unknown",
        description="Description of how this violation impacts the resource",
    )
    dependent_resources: List[str] = Field(
        default_factory=list,
        description="Resources that may be impacted by this violation",
    )
    estimated_cost_impact: Optional[float] = Field(
        None, description="Estimated monthly cost impact in USD"
    )
    rule_id: str = Field(..., description="Identifier of the violated rule")
    template_validation_errors: List[str] = Field(
        default_factory=list,
        description="Any template validation errors related to this finding",
    )


class IaCVulnerability(IaCFinding):
    """Model for Infrastructure as Code vulnerabilities, extending IaCFinding."""

    model_config = ConfigDict(arbitrary_types_allowed=True)
    violation_details: Dict[str, str] = Field(
        default_factory=dict, description="Details about the security violation"
    )


class IaCScanReport(SecurityReport):
    """Report containing Infrastructure as Code scan results."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_default=True,
        arbitrary_types_allowed=True,
        extra="forbid",
    )

    findings: List[IaCVulnerability] = Field(
        default_factory=list, description="List of IaC vulnerabilities"
    )
    scan_type: str = Field(default="iac", description="Type of security scan")
    template_type: str = Field(
        ..., description="Type of IaC template (e.g., cloudformation, terraform)"
    )
    template_path: str = Field(
        ..., min_length=1, description="Path to the scanned template file"
    )
    resources_checked: Annotated[
        Dict[str, int], Field(description="Count of each type of resource checked")
    ] = {}

    timestamp: Annotated[
        datetime.datetime,
        Field(
            description="When the report was generated",
        ),
    ] = datetime.datetime.now(datetime.timezone.utc)

    @field_validator("template_type")
    @classmethod
    def validate_template_type(cls, v: str) -> str:
        """Validate template type."""
        valid_types = {"cloudformation", "terraform", "kubernetes", "docker"}
        if v.lower() not in valid_types:
            raise ValueError(f"Template type must be one of {sorted(valid_types)}")
        return v.lower()

    @field_validator("template_path")
    @classmethod
    def validate_template_path(cls, v: str) -> str:
        """Validate template path."""
        if not v or not v.strip():
            raise ValueError("Template path cannot be empty")
        return v.strip()


class IaCReport(BaseModel):
    """Container for IaC scanning findings."""

    findings: List[IaCFinding] = Field(default_factory=list)
    scanner_name: str = Field(..., description="Name of the IaC scanning tool")
    template_format: str = Field(
        ..., description="Format of IaC templates (e.g., CloudFormation, Terraform)"
    )
    scan_timestamp: str = Field(..., description="Timestamp when scan was performed")
    template_path: str = Field(..., description="Path to the analyzed template")
    resources_analyzed: Dict[str, int] = Field(
        default_factory=dict, description="Count of each type of resource analyzed"
    )
    compliance_summary: Dict[ComplianceFramework, Dict[str, int]] = Field(
        default_factory=dict,
        description="Summary of compliance violations by framework",
    )
