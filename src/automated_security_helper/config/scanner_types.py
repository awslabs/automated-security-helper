from typing import (
    Annotated,
    Literal,
    TypeVar,
)
from pydantic import BaseModel, ConfigDict, Field

from automated_security_helper.core.constants import SCANNER_TYPES
from automated_security_helper.base.scanner import ScannerBaseConfig
from automated_security_helper.base.options import BaseScannerOptions

T = TypeVar("T", bound="ScannerBaseConfig")


class BasePluginOptions(BaseModel):
    """Base class for plugin options."""

    enabled: bool = True


class CustomScannerConfig(ScannerBaseConfig):
    model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)

    name: Annotated[
        str,
        Field(
            ...,
            description="The name of the custom scanner.",
        ),
    ]
    enabled: Annotated[
        bool,
        Field(
            description="Whether the custom scanner is enabled.",
        ),
    ] = True
    type: SCANNER_TYPES = "CUSTOM"
    options: Annotated[
        BaseScannerOptions, Field(description="Configure custom scanner")
    ] = BaseScannerOptions()


class NpmAuditScannerConfig(ScannerBaseConfig):
    """JS/TS Dependency scanner configuration."""

    name: Literal["npm-audit"] = "npm-audit"
    enabled: Annotated[
        bool,
        Field(
            description="Whether the custom scanner is enabled.",
        ),
    ] = True
    type: SCANNER_TYPES = "DEPENDENCY"
    options: Annotated[
        BaseScannerOptions,
        Field(
            description="Enable NPM/PNPM/Yarn Audit dependency scanner",
        ),
    ] = BaseScannerOptions()


class GitSecretsScannerConfig(ScannerBaseConfig):
    """Git Secrets scanner configuration."""

    name: Literal["git-secrets"] = "git-secrets"
    enabled: Annotated[
        bool,
        Field(
            description="Whether the custom scanner is enabled.",
        ),
    ] = True
    type: SCANNER_TYPES = "SECRETS"
    options: Annotated[
        BaseScannerOptions,
        Field(description="Enable Git Secrets scanner"),
    ] = BaseScannerOptions()


class SemgrepScannerConfig(ScannerBaseConfig):
    """Semgrep SAST scanner configuration."""

    name: Literal["semgrep"] = "semgrep"
    enabled: Annotated[
        bool,
        Field(
            description="Whether the custom scanner is enabled.",
        ),
    ] = True
    type: SCANNER_TYPES = "SAST"
    options: Annotated[
        BaseScannerOptions, Field(description="Configure Semgrep scanner")
    ] = BaseScannerOptions()


class GrypeScannerConfig(ScannerBaseConfig):
    """Grype SAST scanner configuration."""

    name: Literal["grype"] = "grype"
    enabled: Annotated[
        bool,
        Field(
            description="Whether the custom scanner is enabled.",
        ),
    ] = True
    type: SCANNER_TYPES = "SAST"
    options: Annotated[
        BaseScannerOptions, Field(description="Configure Grype scanner")
    ] = BaseScannerOptions()


class SyftScannerConfig(ScannerBaseConfig):
    """Syft SBOM scanner configuration."""

    name: Literal["syft"] = "syft"
    enabled: Annotated[
        bool,
        Field(
            description="Whether the custom scanner is enabled.",
        ),
    ] = True
    type: SCANNER_TYPES = "SBOM"
    options: Annotated[
        BaseScannerOptions, Field(description="Configure Syft scanner")
    ] = BaseScannerOptions()


class CfnNagScannerConfig(ScannerBaseConfig):
    """CFN Nag IAC SAST scanner configuration."""

    name: Literal["cfn-nag"] = "cfn-nag"
    enabled: Annotated[
        bool,
        Field(
            description="Whether the custom scanner is enabled.",
        ),
    ] = True
    type: SCANNER_TYPES = "IAC"
    options: Annotated[
        BaseScannerOptions,
        Field(description="Enable CFN Nag IAC scanner"),
    ] = BaseScannerOptions()
