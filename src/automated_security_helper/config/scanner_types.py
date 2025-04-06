from pydantic import BaseModel, ConfigDict, Field
from typing import Annotated, Literal

from automated_security_helper.models.core import SCANNER_TYPES


# Base models
class BaseScannerOptions(BaseModel):
    """Base model for scanner options."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        arbitrary_types_allowed=True,
        extra="allow",
    )


class ScannerBaseConfig(BaseModel):
    """Base configuration model with common settings."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        arbitrary_types_allowed=True,
        extra="allow",
    )

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
    options: Annotated[BaseScannerOptions, Field(description="Scanner options")] = (
        BaseScannerOptions()
    )


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
    options: Annotated[
        BaseScannerOptions, Field(description="Configure custom scanner")
    ] = BaseScannerOptions()


class BanditScannerConfig(ScannerBaseConfig):
    """Bandit SAST scanner configuration."""

    name: Literal["bandit"] = "bandit"
    type: SCANNER_TYPES = "SAST"
    options: Annotated[
        BaseScannerOptions, Field(description="Configure Bandit scanner")
    ] = BaseScannerOptions()


class JupyterNotebookScannerConfig(ScannerBaseConfig):
    """Jupyter Notebook (.ipynb) SAST scanner configuration."""

    name: Literal["jupyter"] = "jupyter"
    type: SCANNER_TYPES = "SAST"
    options: Annotated[
        BaseScannerOptions, Field(description="Configure Jupyter Notebook scanner")
    ] = BaseScannerOptions()


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


class CdkNagScannerConfigOptions(BaseScannerOptions):
    """CDK Nag IAC SAST scanner options."""

    nag_packs: Annotated[
        CdkNagPacks,
        Field(
            description="CDK Nag packs to enable",
        ),
    ] = CdkNagPacks()


class CdkNagScannerConfig(ScannerBaseConfig):
    """CDK Nag IAC SAST scanner configuration."""

    name: Literal["cdknag"] = "cdknag"
    type: SCANNER_TYPES = "IAC"
    options: Annotated[
        CdkNagScannerConfigOptions,
        Field(description="Enable CDK Nag IAC scanner"),
    ] = CdkNagScannerConfigOptions()


class CfnNagScannerConfig(ScannerBaseConfig):
    """CFN Nag IAC SAST scanner configuration."""

    name: Literal["cfnnag"] = "cfnnag"
    type: SCANNER_TYPES = "IAC"
    options: Annotated[
        BaseScannerOptions,
        Field(description="Enable CFN Nag IAC scanner"),
    ] = BaseScannerOptions()


class NpmAuditScannerConfig(ScannerBaseConfig):
    """JS/TS Dependency scanner configuration."""

    name: Literal["npmaudit"] = "npmaudit"
    type: SCANNER_TYPES = "DEPENDENCY"
    options: Annotated[
        BaseScannerOptions,
        Field(
            description="Enable NPM/PNPM/Yarn Audit dependency scanner",
        ),
    ] = BaseScannerOptions()


class GitSecretsScannerConfig(ScannerBaseConfig):
    """Git Secrets scanner configuration."""

    name: Literal["gitsecrets"] = "gitsecrets"
    type: SCANNER_TYPES = "SECRETS"
    options: Annotated[
        BaseScannerOptions,
        Field(description="Enable Git Secrets scanner"),
    ] = BaseScannerOptions()


class SemgrepScannerConfig(ScannerBaseConfig):
    """Semgrep SAST scanner configuration."""

    name: Literal["semgrep"] = "semgrep"
    type: SCANNER_TYPES = "SAST"
    options: Annotated[
        BaseScannerOptions, Field(description="Configure Semgrep scanner")
    ] = BaseScannerOptions()


class CheckovScannerConfig(ScannerBaseConfig):
    """Checkov SAST/IaC scanner configuration."""

    name: Literal["checkov"] = "checkov"
    type: SCANNER_TYPES = "IAC"
    options: Annotated[
        BaseScannerOptions, Field(description="Configure Checkov scanner")
    ] = BaseScannerOptions()


class GrypeScannerConfig(ScannerBaseConfig):
    """Grype SAST scanner configuration."""

    name: Literal["grype"] = "grype"
    type: SCANNER_TYPES = "SAST"
    options: Annotated[
        BaseScannerOptions, Field(description="Configure Grype scanner")
    ] = BaseScannerOptions()


class SyftScannerConfig(ScannerBaseConfig):
    """Syft SBOM scanner configuration."""

    name: Literal["syft"] = "syft"
    type: SCANNER_TYPES = "SBOM"
    options: Annotated[
        BaseScannerOptions, Field(description="Configure Syft scanner")
    ] = BaseScannerOptions()
