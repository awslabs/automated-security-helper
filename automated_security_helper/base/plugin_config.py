from automated_security_helper.base.options import PluginOptionsBase
from pydantic import BaseModel, ConfigDict, Field
from typing import Annotated


class PluginConfigBase(BaseModel):
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
    options: Annotated[PluginOptionsBase, Field(description="Scanner options")] = (
        PluginOptionsBase()
    )
