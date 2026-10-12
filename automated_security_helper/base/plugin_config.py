from automated_security_helper.base.options import PluginOptionsBase
from pydantic import BaseModel, ConfigDict, Field, ValidatorFunctionWrapHandler
from typing import Annotated, Any, Optional, get_args


class PluginConfigBase(BaseModel):
    """Base converter configuration model with common settings."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        arbitrary_types_allowed=True,
        extra="allow",
        # A refused value can be a secret read from the environment, and an
        # error's text goes wherever the error is shown. Every plugin config
        # inherits this.
        hide_input_in_errors=True,
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


def declared_config_model(
    plugin_class: type, base_config: type[PluginConfigBase]
) -> Optional[type[PluginConfigBase]]:
    """The config model a plugin declares, such as ``ScannerPluginBase[XConfig]``.

    Read from the ``config`` field's resolved annotation,
    ``Union[XConfig, <base_config>, None]``. None for a plugin that declares no
    model, or declares ``base_config`` itself.
    """
    field = (getattr(plugin_class, "model_fields", None) or {}).get("config")
    if field is None:
        return None
    for candidate in get_args(field.annotation):
        if (
            isinstance(candidate, type)
            and issubclass(candidate, base_config)
            and candidate is not base_config
        ):
            return candidate
    return None


def config_validated_by_declared_model(
    plugin_class: type,
    base_config: type[PluginConfigBase],
    value: Any,
    handler: ValidatorFunctionWrapHandler,
) -> Any:
    """``value`` for a plugin's ``config`` field, validated by the plugin's own model.

    For the wrap validator on ``config`` in the reporter, scanner and converter
    bases. Pydantic tries each type in the field's union in turn, so given a
    section the plugin's own model refused, it built ``base_config`` from it and
    raised nothing, and every validator on the plugin's model and its options was
    skipped. So a value that is not already the plugin's model is validated by
    it, and the ValidationError reaches the caller, which records that plugin as
    failed and goes on with the others. A config of another class is validated
    by the fields it set. A plugin that declares no model of its own takes any
    config of ``base_config``, as before.
    """
    declared = declared_config_model(plugin_class, base_config)
    if declared is None or value is None or isinstance(value, declared):
        return handler(value)
    if isinstance(value, BaseModel):
        value = value.model_dump(exclude_unset=True)
    return declared.model_validate(value)


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
