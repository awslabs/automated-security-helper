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


class ReporterOptionsBase(PluginOptionsBase):
    """Base class for reporter options."""
