from typing import (
    Annotated,
    Literal,
)
from pydantic import BaseModel, ConfigDict, Field

from automated_security_helper.core.constants import SCANNER_TYPES
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.base.options import ScannerOptionsBase


class BasePluginOptions(BaseModel):
    """Base class for plugin options."""

    enabled: bool = True


class CustomScannerConfig(ScannerPluginConfigBase):
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
        ScannerOptionsBase, Field(description="Configure custom scanner")
    ] = ScannerOptionsBase()


class NpmAuditScannerConfig(ScannerPluginConfigBase):
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
        ScannerOptionsBase,
        Field(
            description="Enable NPM/PNPM/Yarn Audit dependency scanner",
        ),
    ] = ScannerOptionsBase()


class SemgrepScannerConfig(ScannerPluginConfigBase):
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
        ScannerOptionsBase, Field(description="Configure Semgrep scanner")
    ] = ScannerOptionsBase()


class GrypeScannerConfig(ScannerPluginConfigBase):
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
        ScannerOptionsBase, Field(description="Configure Grype scanner")
    ] = ScannerOptionsBase()


class SyftScannerConfig(ScannerPluginConfigBase):
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
        ScannerOptionsBase, Field(description="Configure Syft scanner")
    ] = ScannerOptionsBase()


class CfnNagScannerConfig(ScannerPluginConfigBase):
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
        ScannerOptionsBase,
        Field(description="Enable CFN Nag IAC scanner"),
    ] = ScannerOptionsBase()
