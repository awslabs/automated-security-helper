from pydantic import BaseModel, ConfigDict


class BuilderOptionsBase(BaseModel):
    """Base class for builder options."""

    model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)


class ConverterOptionsBase(BaseModel):
    """Base class for converter options."""

    model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)


class ScannerOptionsBase(BaseModel):
    """Base class for scanner options."""

    model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)


class ReporterOptionsBase(BaseModel):
    """Base class for reporter options."""

    model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)
