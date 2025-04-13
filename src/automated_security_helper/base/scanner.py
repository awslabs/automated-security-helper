from automated_security_helper.base.options import BaseScannerOptions


from pydantic import BaseModel, ConfigDict, Field


from typing import Annotated, Dict


class ScannerBaseConfig(BaseModel):
    """Base converter configuration model with common settings."""

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
    options: Annotated[BaseScannerOptions, Field(description="Scanner options")] = (
        BaseScannerOptions()
    )


class ParserConfig(ScannerBaseConfig):
    """Configuration model for scanner result parsers."""

    output_format: Annotated[
        str,
        Field(description="Expected output format from the scanner"),
    ]
    finding_key: Annotated[
        str,
        Field(description="Key used to identify individual findings in the output"),
    ] = "findings"
    severity_mapping: Annotated[
        Dict[str, str],
        Field(
            description="Mapping of scanner-specific severity levels to standardized levels"
        ),
    ] = {}
    location_mapping: Annotated[
        Dict[str, str],
        Field(
            description="Mapping of scanner-specific location fields to standardized fields"
        ),
    ] = {}
