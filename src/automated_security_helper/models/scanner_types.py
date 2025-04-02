from pydantic import BaseModel, ConfigDict, Field
from typing import Annotated, Dict, Union


# Base models
class ScannerOptions(BaseModel):
    """Base model for scanner options."""

    enabled: Annotated[bool, Field(description="Whether the scanner is enabled")] = True


# SAST Scanner Models
class CustomScanner(BaseModel):
    model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)

    __pydantic_extra__: Dict[str, Union[bool, ScannerOptions]] = Field(init=False)


class BanditScanner(CustomScanner):
    """Bandit SAST scanner configuration."""

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


class CdkNagScannerOptions(ScannerOptions):
    """CDK Nag IAC SAST scanner options."""

    nag_packs: Annotated[
        CdkNagPacks,
        Field(
            description="CDK Nag packs to enable",
        ),
    ] = CdkNagPacks()


class CdkNagScanner(CustomScanner):
    """CDK Nag IAC SAST scanner configuration."""

    cdknag: Annotated[
        Union[bool, CdkNagScannerOptions],
        Field(description="Enable CDK Nag IAC scanner", alias="cdk-nag"),
    ] = CdkNagScannerOptions()


class CfnNagScanner(CustomScanner):
    """CFN Nag IAC SAST scanner configuration."""

    cfnnag: Annotated[
        Union[bool, ScannerOptions],
        Field(description="Enable CFN Nag IAC scanner", alias="cfn-nag"),
    ] = ScannerOptions()


class NpmAuditScanner(CustomScanner):
    """JS/TS Dependency scanner configuration."""

    npmaudit: Annotated[
        Union[bool, ScannerOptions],
        Field(
            description="Enable NPM/PNPM/Yarn Audit dependency scanner",
            alias="npm-audit",
        ),
    ] = ScannerOptions()


class GitSecretsScanner(CustomScanner):
    """Git Secrets scanner configuration."""

    npmaudit: Annotated[
        Union[bool, ScannerOptions],
        Field(description="Enable Git Secrets scanner", alias="git-secrets"),
    ] = ScannerOptions()


class SemgrepScanner(CustomScanner):
    """Semgrep SAST scanner configuration."""

    semgrep: Annotated[
        Union[bool, ScannerOptions], Field(description="Enable Semgrep scanner")
    ] = ScannerOptions()


class CheckovScanner(CustomScanner):
    """Checkov SAST/IaC scanner configuration."""

    checkov: Annotated[
        Union[bool, ScannerOptions], Field(description="Enable Checkov scanner")
    ] = ScannerOptions()


class GrypeScanner(CustomScanner):
    """Grype SAST scanner configuration."""

    grype: Annotated[
        Union[bool, ScannerOptions], Field(description="Enable Grype scanner")
    ] = ScannerOptions()


class SyftScanner(CustomScanner):
    """Syft SBOM scanner configuration."""

    syft: Annotated[
        Union[bool, ScannerOptions], Field(description="Enable Syft scanner")
    ] = ScannerOptions()
