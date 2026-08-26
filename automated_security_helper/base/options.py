from pydantic import BaseModel, ConfigDict, Field
from typing import Annotated, Literal

from automated_security_helper.core.constants import ASH_DEFAULT_SEVERITY_LEVEL


class BuilderOptionsBase(BaseModel):
    """Base class for builder options."""

    model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)


class PluginOptionsBase(BaseModel):
    """Base class for plugin options."""

    model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)


class ConverterOptionsBase(PluginOptionsBase):
    """Base class for converter options."""


class ScannerOptionsBase(PluginOptionsBase):
    """Base class for scanner options."""

    severity_threshold: Annotated[
        Literal["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"] | None,
        Field(
            description=f"Minimum severity level to consider findings as failures. This is a scanner-level override of the default severity-level within ASH of {ASH_DEFAULT_SEVERITY_LEVEL}."
        ),
    ] = None

    # Lives on the base rather than on individual scanners because the hang it
    # prevents is a property of the shared subprocess path, not of any one tool.
    # detect-secrets previously carried its own copy of this option, which is why
    # it was the only scanner that timed out cleanly while the rest could run
    # unbounded. 300 matches the default it chose.
    scan_timeout: Annotated[
        int | None,
        Field(
            description=(
                "Maximum time in seconds to allow this scanner's tool invocation "
                "to run before it is killed. Set to null to leave the scanner "
                "unbounded, which risks a scan that never completes."
            ),
            ge=1,
        ),
    ] = 1800


class ReporterOptionsBase(PluginOptionsBase):
    """Base class for reporter options."""
