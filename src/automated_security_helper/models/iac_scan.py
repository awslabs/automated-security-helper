"""Models for Infrastructure as Code Scanning findings."""

from enum import Enum
from typing import Annotated, List, Optional, Dict, Union
from pydantic import Field, ConfigDict
from automated_security_helper.models.core import BaseFinding
from automated_security_helper.models.data_interchange import SecurityReport

__all__ = [
    "ComplianceFramework",
    "IaCFinding",
    "IaCVulnerability",
    "IaCScanReport",
    "CheckResultType",
]


class ComplianceFramework(str, Enum):
    """Standard compliance frameworks."""

    CIS = "CIS"
    HIPAA = "HIPAA"
    NIST = "NIST"
    SOC2 = "SOC2"
    PCI = "PCI"


class CheckResultType(str, Enum):
    """Types of check results from IaC scanning."""

    FAILED = "failed_checks"
    PASSED = "passed_checks"
    SKIPPED = "skipped_checks"
    ERROR = "parsing_errors"


class IaCFinding(BaseFinding):
    """Model for Infrastructure as Code security findings."""

    resource_name: str = Field(..., description="Name of the affected resource")
    resource_type: Annotated[str, Field(description="Type of cloud resource")] = None
    expected_value: Optional[str] = Field(
        None, description="Expected configuration value"
    )
    actual_value: Optional[str] = Field(None, description="Current configuration value")
    compliance_frameworks: Annotated[
        List[Union[ComplianceFramework, str]],
        Field(description="Compliance frameworks this violation impacts"),
    ] = []
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
    check_result_type: CheckResultType = Field(
        default=CheckResultType.FAILED,
        description="Type of check result (failed, passed, skipped, error)",
    )


class IaCScanReport(SecurityReport):
    """Report containing Infrastructure as Code scan results."""

    findings: Annotated[
        List[IaCVulnerability],
        Field(default_factory=list, description="List of IaC vulnerabilities"),
    ] = []
    iac_framework: Annotated[
        str,
        Field(
            description="Infrastructure-as-Code framework (e.g., Amazon CloudFormation, Terraform, AWS CDK, Helm)",
            examples=[
                "cloudformation",
                "terraform",
                "kubernetes",
                "docker",
                "helm",
                "cdk",
            ],
        ),
    ] = None
    resources_checked: Annotated[
        Dict[str, int],
        Field(
            description="Count of each type of resource checked if the information is available from the scanner."
        ),
    ] = {}
