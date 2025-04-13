from pydantic import BaseModel, ConfigDict


class BaseScannerOptions(BaseModel):
    """Base class for scanner options."""

    model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)


class BaseConverterOptions(BaseModel):
    """Base class for converter options."""

    model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)


class BaseParserOptions(BaseModel):
    """Base class for parser options."""

    model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)


class BaseReporterOptions(BaseModel):
    """Base class for reporter options."""

    model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)
