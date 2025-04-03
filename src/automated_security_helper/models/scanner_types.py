from pydantic import BaseModel, ConfigDict, Field
from typing import Annotated, Literal, Union


# Base models
class ScannerOptions(BaseModel):
    """Base model for scanner options."""

    model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)

    enabled: Annotated[bool, Field(description="Whether the scanner is enabled")] = True


class CustomScannerOptions(ScannerOptions):
    """CDK Nag IAC SAST scanner options."""


# SAST Scanner Models
class ScannerConfigBase(BaseModel):
    model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)

    name: Annotated[
        str,
        Field(
            description="The name of the scanner.",
        ),
    ]


class CustomScannerConfig(BaseModel):
    model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)

    name: Annotated[
        str,
        Field(
            ...,
            description="The name of the scanner.",
        ),
    ]

    custom: Annotated[
        Union[bool, ScannerOptions], Field(description="Configure custom scanner")
    ] = ScannerOptions()


class BanditScannerConfig(ScannerConfigBase):
    """Bandit SAST scanner configuration."""

    name: Literal["bandit"] = "bandit"
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


class CdkNagScannerConfig(ScannerConfigBase):
    """CDK Nag IAC SAST scanner configuration."""

    name: Literal["cdk-nag"] = "cdk-nag"
    cdknag: Annotated[
        Union[bool, CdkNagScannerConfigOptions],
        Field(description="Enable CDK Nag IAC scanner", alias="cdk-nag"),
    ] = CdkNagScannerConfigOptions()


class CfnNagScannerConfig(ScannerConfigBase):
    """CFN Nag IAC SAST scanner configuration."""

    name: Literal["cfn-nag"] = "cfn-nag"
    cfnnag: Annotated[
        Union[bool, ScannerOptions],
        Field(description="Enable CFN Nag IAC scanner", alias="cfn-nag"),
    ] = ScannerOptions()


class NpmAuditScannerConfig(ScannerConfigBase):
    """JS/TS Dependency scanner configuration."""

    name: Literal["npm-audit"] = "npm-audit"
    npmaudit: Annotated[
        Union[bool, ScannerOptions],
        Field(
            description="Enable NPM/PNPM/Yarn Audit dependency scanner",
            alias="npm-audit",
        ),
    ] = ScannerOptions()


class GitSecretsScannerConfig(ScannerConfigBase):
    """Git Secrets scanner configuration."""

    name: Literal["git-secret"] = "git-secret"
    gitsecrets: Annotated[
        Union[bool, ScannerOptions],
        Field(description="Enable Git Secrets scanner", alias="git-secrets"),
    ] = ScannerOptions()


class SemgrepScannerConfig(ScannerConfigBase):
    """Semgrep SAST scanner configuration."""

    name: Literal["semgrep"] = "semgrep"
    semgrep: Annotated[
        Union[bool, ScannerOptions], Field(description="Enable Semgrep scanner")
    ] = ScannerOptions()


class CheckovScannerConfig(ScannerConfigBase):
    """Checkov SAST/IaC scanner configuration."""

    name: Literal["checkov"] = "checkov"
    checkov: Annotated[
        Union[bool, ScannerOptions], Field(description="Enable Checkov scanner")
    ] = ScannerOptions()


class GrypeScannerConfig(ScannerConfigBase):
    """Grype SAST scanner configuration."""

    name: Literal["grype"] = "grype"
    grype: Annotated[
        Union[bool, ScannerOptions], Field(description="Enable Grype scanner")
    ] = ScannerOptions()


class SyftScannerConfig(ScannerConfigBase):
    """Syft SBOM scanner configuration."""

    name: Literal["syft"] = "syft"
    syft: Annotated[
        Union[bool, ScannerOptions], Field(description="Enable Syft scanner")
    ] = ScannerOptions()
