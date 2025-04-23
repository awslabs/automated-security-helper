from pydantic import BaseModel, ConfigDict, Field
from typing import Annotated, Literal

from automated_security_helper.core.constants import ASH_DEFAULT_SEVERITY_LEVEL


class BuilderOptionsBase(BaseModel):
    """Base class for builder options."""

    model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)


class ConverterOptionsBase(BaseModel):
    """Base class for converter options."""

    model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)


class ScannerOptionsBase(BaseModel):
    """Base class for scanner options."""

    model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)

    severity_threshold: Annotated[
        Literal["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"] | None,
        Field(
            description=f"Minimum severity level to consider findings as failures. This is a scanner-level override of the default severity-level within ASH of {ASH_DEFAULT_SEVERITY_LEVEL}."
        ),
    ] = None


class ReporterOptionsBase(BaseModel):
    """Base class for reporter options."""

    model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)
