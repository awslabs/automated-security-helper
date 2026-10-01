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


def declared_plugin_name(plugin_class: type) -> str | None:
    """The name a plugin declares for itself, read from its config class.

    Every plugin class has a ``config`` field typed with its own config class,
    and that class's ``name`` default (``github-ghas``, ``cdk-nag``) is the key
    the plugin is configured under, the name in ``AshConfig.json``, and what
    ``generate_reporter_docs.py`` lists. Read from the field default, not by
    instantiating the config class, so a config class with required fields
    still answers.

    Returns None when the class declares no config class or no string name, so
    the caller can fall back to another spelling.
    """
    import typing

    field = (getattr(plugin_class, "model_fields", None) or {}).get("config")
    if field is None:
        return None
    annotation = field.annotation
    candidates = [a for a in typing.get_args(annotation) if a is not type(None)]
    for candidate in candidates or [annotation]:
        name_field = (getattr(candidate, "model_fields", None) or {}).get("name")
        default = getattr(name_field, "default", None)
        if isinstance(default, str) and default:
            return default
    return None


def plugin_config_key(plugin_class: type) -> str:
    """The name to look a plugin's config up by: its declared name.

    Falls back to the lowercased class name only for a plugin that declares no
    name, which is what every caller passed before.
    """
    return (
        declared_plugin_name(plugin_class)
        or getattr(plugin_class, "__name__", "Unknown").lower()
    )
