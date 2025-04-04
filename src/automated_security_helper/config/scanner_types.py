from pydantic import BaseModel, ConfigDict, Field
from typing import Annotated, Literal, Union

from automated_security_helper.models.core import SCANNER_TYPES


# Base models
class ScannerOptions(BaseModel):
    """Base model for scanner options."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        arbitrary_types_allowed=True,
        extra="allow",
    )
    enabled: Annotated[bool, Field(description="Whether the component is enabled")] = (
        True
    )


class ScannerBaseConfig(ScannerOptions):
    """Base configuration model with common settings."""

    name: Annotated[
        str,
        Field(
            min_length=1,
            description="Name of the component using letters, numbers, underscores and hyphens. Must begin with a letter.",
            pattern=r"^[a-zA-Z][\w-]+$",
        ),
    ] = None
    enabled: Annotated[bool, Field(description="Whether the component is enabled")] = (
        True
    )
    type: Annotated[
        SCANNER_TYPES,
        Field(description=f"Type of scanner. Valid options include: {SCANNER_TYPES}"),
    ] = "UNKNOWN"


# SAST Scanner Models
class CustomScannerConfig(ScannerBaseConfig):
    model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)

    name: Annotated[
        str,
        Field(
            ...,
            description="The name of the custom scanner.",
        ),
    ]
    type: SCANNER_TYPES = "CUSTOM"
    custom: Annotated[
        Union[bool, ScannerOptions], Field(description="Configure custom scanner")
    ] = ScannerOptions()


class BanditScannerConfig(ScannerBaseConfig):
    """Bandit SAST scanner configuration."""

    name: Literal["bandit"] = "bandit"
    type: SCANNER_TYPES = "SAST"
    bandit: Annotated[
        Union[bool, ScannerOptions], Field(description="Enable Bandit scanner")
    ] = ScannerOptions()


class CdkNagPacks(BaseModel):
    model_config = ConfigDict(extra="allow")

    AwsSolutionsChecks: Annotated[
        bool,
        Field(description="Runs the AwsSolutionsChecks NagPack included with CDK Nag."),
    ] = True
    HIPAASecurityChecks: Annotated[
        bool,
        Field(
            description="Runs the HIPAASecurityChecks NagPack included with CDK Nag."
        ),
    ] = False
    NIST80053R4Checks: Annotated[
        bool,
        Field(description="Runs the NIST80053R4Checks NagPack included with CDK Nag."),
    ] = False
    NIST80053R5Checks: Annotated[
        bool,
        Field(description="Runs the NIST80053R5Checks NagPack included with CDK Nag."),
    ] = False
    PCIDSS321Checks: Annotated[
        bool,
        Field(description="Runs the PCIDSS321Checks NagPack included with CDK Nag."),
    ] = False


class CdkNagScannerConfigOptions(ScannerOptions):
    """CDK Nag IAC SAST scanner options."""

    nag_packs: Annotated[
        CdkNagPacks,
        Field(
            description="CDK Nag packs to enable",
        ),
    ] = CdkNagPacks()


class CdkNagScannerConfig(ScannerBaseConfig):
    """CDK Nag IAC SAST scanner configuration."""

    name: Literal["cdk-nag"] = "cdk-nag"
    type: SCANNER_TYPES = "IAC"
    cdknag: Annotated[
        Union[bool, CdkNagScannerConfigOptions],
        Field(description="Enable CDK Nag IAC scanner", alias="cdk-nag"),
    ] = CdkNagScannerConfigOptions()


class CfnNagScannerConfig(ScannerBaseConfig):
    """CFN Nag IAC SAST scanner configuration."""

    name: Literal["cfn-nag"] = "cfn-nag"
    type: SCANNER_TYPES = "IAC"
    cfnnag: Annotated[
        Union[bool, ScannerOptions],
        Field(description="Enable CFN Nag IAC scanner", alias="cfn-nag"),
    ] = ScannerOptions()


class NpmAuditScannerConfig(ScannerBaseConfig):
    """JS/TS Dependency scanner configuration."""

    name: Literal["npm-audit"] = "npm-audit"
    type: SCANNER_TYPES = "DEPENDENCY"
    npmaudit: Annotated[
        Union[bool, ScannerOptions],
        Field(
            description="Enable NPM/PNPM/Yarn Audit dependency scanner",
            alias="npm-audit",
        ),
    ] = ScannerOptions()


class GitSecretsScannerConfig(ScannerBaseConfig):
    """Git Secrets scanner configuration."""

    name: Literal["git-secret"] = "git-secret"
    type: SCANNER_TYPES = "SECRETS"
    gitsecrets: Annotated[
        Union[bool, ScannerOptions],
        Field(description="Enable Git Secrets scanner", alias="git-secrets"),
    ] = ScannerOptions()


class SemgrepScannerConfig(ScannerBaseConfig):
    """Semgrep SAST scanner configuration."""

    name: Literal["semgrep"] = "semgrep"
    type: SCANNER_TYPES = "SAST"
    semgrep: Annotated[
        Union[bool, ScannerOptions], Field(description="Enable Semgrep scanner")
    ] = ScannerOptions()


class CheckovScannerConfig(ScannerBaseConfig):
    """Checkov SAST/IaC scanner configuration."""

    name: Literal["checkov"] = "checkov"
    type: SCANNER_TYPES = "IAC"
    checkov: Annotated[
        Union[bool, ScannerOptions], Field(description="Enable Checkov scanner")
    ] = ScannerOptions()


class GrypeScannerConfig(ScannerBaseConfig):
    """Grype SAST scanner configuration."""

    name: Literal["grype"] = "grype"
    type: SCANNER_TYPES = "SAST"
    grype: Annotated[
        Union[bool, ScannerOptions], Field(description="Enable Grype scanner")
    ] = ScannerOptions()


class SyftScannerConfig(ScannerBaseConfig):
    """Syft SBOM scanner configuration."""

    name: Literal["syft"] = "syft"
    type: SCANNER_TYPES = "SBOM"
    syft: Annotated[
        Union[bool, ScannerOptions], Field(description="Enable Syft scanner")
    ] = ScannerOptions()
