import typing
from typing import Annotated, Any, ClassVar, Iterable, List, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, model_validator

from automated_security_helper.base.options import PluginOptionsBase
from pydantic import ValidatorFunctionWrapHandler
from typing import get_args
from automated_security_helper.utils.redacted_model import RedactedSection
from automated_security_helper.utils.unknown_keys import (
    UNKNOWN_KEY_NOTE,
    known_keys,
    misplaced_key_problems,
    tolerated_notes,
)


class PluginConfigBase(RedactedSection):
    """Base converter configuration model with common settings."""

    # Unknown keys are refused by _refuse_unknown_section_keys. Extras are
    # allowed only so that a results file holding one keeps it
    # (utils/unknown_keys.py); the schema says what a config file may contain.
    model_config = ConfigDict(
        str_strip_whitespace=True,
        arbitrary_types_allowed=True,
        extra="allow",
        # A refused value can be a secret read from the environment, and an
        # error's text goes wherever the error is shown. Every plugin config
        # inherits this.
        hide_input_in_errors=True,
        json_schema_extra={"additionalProperties": False},
    )

    #: The config segment a section of this kind sits in, for messages.
    SECTION_SEGMENT: ClassVar[str] = "plugins"
    #: Declared in the body of each generic base, which stands in for a
    #: plugin's own config where that cannot be known. Not inherited: a
    #: plugin's config class is not generic. See _refuse_unknown_section_keys.
    GENERIC_SECTION: ClassVar[bool] = True

    @model_validator(mode="before")
    @classmethod
    def _refuse_unknown_section_keys(cls, data: Any, info: ValidationInfo) -> Any:
        """Refuse a key at the section level that the plugin does not declare.

        Kept, it was never read: ``scanners.bandit.severity_threshold: HIGH``
        beside ``enabled: true`` loaded, and bandit gated at the global
        threshold, because the option belongs under ``options``. The message
        says to move an option there, and names any other key as unknown.

        As for options (base/options.py), the generic bases record nothing when
        a results file is read: a community plugin's section is validated
        against one of them as a branch of a union, which then keeps the plain
        mapping, and a note recorded there would survive the discarded branch.
        A loaded plugin's section is checked against its own config class once
        the plugins are loaded (config/plugin_option_check.py).
        """
        if not isinstance(data, dict):
            return data
        notes = tolerated_notes(info)
        if notes is not None and cls.__dict__.get("GENERIC_SECTION", False):
            return data
        where = section_location(cls)
        problems = section_key_problems(cls, data, where)
        if not problems:
            return data
        if notes is not None:
            # One note per kept key, naming the section and not the key: a stored
            # key is the results file's data (UNKNOWN_KEY_NOTE), where a config
            # file's refusal names it.
            notes.extend(
                f"{UNKNOWN_KEY_NOTE} in '{where}'"
                for _ in unknown_section_keys(cls, data)
            )
            return data
        raise ValueError(" ".join(problems))

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


def _options_class(config_class: type[BaseModel]) -> type[BaseModel] | None:
    """The options model a plugin config class declares, or None."""
    field = config_class.model_fields.get("options")
    if field is None:
        return None
    for candidate in typing.get_args(field.annotation) or (field.annotation,):
        if isinstance(candidate, type) and issubclass(candidate, BaseModel):
            return candidate
    return None


def config_validated_by_declared_model(
    plugin_class: type,
    base_config: type[PluginConfigBase],
    value: Any,
    handler: ValidatorFunctionWrapHandler,
    info: Optional[ValidationInfo] = None,
) -> Any:
    """``value`` for a plugin's ``config`` field, validated by the plugin's own model.

    For the wrap validator on ``config`` in the reporter, scanner and converter
    bases. Pydantic tries each type in the field's union in turn, so given a
    section the plugin's own model refused, it built ``base_config`` from it and
    raised nothing, and every validator on the plugin's model and its options was
    skipped. So a value that is not already the plugin's model is validated by
    it, and the ValidationError reaches the caller, which records that plugin as
    failed and goes on with the others. A config of another class is validated
    by the fields it set, and by its ``name`` whether or not it set one: a
    subclass declares its ``name`` as a default, which the dump of the fields it
    set leaves out, so a config that names another plugin would otherwise be
    read as this plugin's, with the ``enabled`` it set. A subclass of
    ``base_config`` named for another plugin is refused, and so is a subclass of
    the plugin's own model named for another plugin: the name is compared before
    the check for the plugin's own model, which a subclass passes. The name of
    a config of another class is written into the plugin's config only when the
    plugin declares a name to compare it with. A plugin that declares no model
    of its own takes any config of ``base_config``, as before.

    ``info`` is the wrap validator's ValidationInfo. When given, the plugin's own
    model validates under the same validation context as the field would have.
    """
    declared = declared_config_model(plugin_class, base_config)
    if declared is None or value is None:
        return handler(value)
    expected = None
    if isinstance(value, BaseModel):
        name = getattr(value, "name", None)
        expected = declared_plugin_name(plugin_class)
        if (
            name is not None
            and expected is not None
            and name != expected
            and type(value) is not base_config
            and type(value) is not declared
        ):
            raise ValueError(
                f"name: the config is {type(value).__name__}, named {name!r}, "
                f"which is not this plugin's name, {expected!r}"
            )
    if isinstance(value, declared):
        return handler(value)
    if isinstance(value, BaseModel):
        # By alias, as the declared model reads its input: a field it declares
        # under an alias would otherwise be dumped by name and left to its default.
        given = value.model_dump(exclude_unset=True, by_alias=True)
        if name is not None and expected is not None:
            given["name"] = name
        value = given
    return declared.model_validate(
        value, context=info.context if info is not None else None
    )


def section_location(config_class: type[BaseModel]) -> str:
    """``scanners.bandit``: where a section of ``config_class`` sits in a config."""
    segment = getattr(config_class, "SECTION_SEGMENT", "plugins")
    name_field = config_class.model_fields.get("name")
    name = getattr(name_field, "default", None)
    return f"{segment}.{name}" if isinstance(name, str) and name else segment


def unknown_section_keys(config_class: type[BaseModel], section: Any) -> List[str]:
    """The keys of ``section`` that ``config_class`` does not declare."""
    if not isinstance(section, dict):
        return []
    known = known_keys(config_class)
    return [key for key in section if isinstance(key, str) and key not in known]


def section_key_problems(
    config_class: type[BaseModel], section: Any, where: str
) -> List[str]:
    """Messages for the keys of ``section`` that ``config_class`` does not declare.

    The one check behind the model validator, the loaded-plugin check
    (config/plugin_option_check.py) and ``ash config validate``
    (config/config_validator.py), so all three say the same thing.
    """
    unknown = unknown_section_keys(config_class, section)
    if not unknown:
        return []
    known = known_keys(config_class)
    options_class = _options_class(config_class)
    option_keys = known_keys(options_class) if options_class is not None else set()
    return misplaced_key_problems(unknown, known, option_keys, where)


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


def split_plugin_names(items: Iterable[Optional[str]]) -> List[str]:
    """The names a ``--scanners`` or ``--exclude-scanners`` list selects.

    Each item may hold several comma-separated names, so ``["bandit, semgrep"]`` and
    ``["bandit", "semgrep"]`` select the same two. Every name is stripped; a ``None``
    item is skipped. An empty name is kept, as the scan engine always kept it, so a
    selection of nothing but commas is refused the way a misspelled one is rather
    than read as no selection. Case is kept too: callers compare names
    case-insensitively and print them as given.

    ``ScanExecutionEngine`` and the workspace pre-check that refuses an
    unresolvable selection before any project starts both read selections through
    this, so the pre-check judges the names each project's scan will use.
    """
    return [
        name.strip() for item in items if item is not None for name in item.split(",")
    ]


def plugin_config_key(plugin_class: type) -> str:
    """The name to look a plugin's config up by: its declared name.

    Falls back to the lowercased class name only for a plugin that declares no
    name, which is what every caller passed before.
    """
    return (
        declared_plugin_name(plugin_class)
        or getattr(plugin_class, "__name__", "Unknown").lower()
    )


#: The spellings of false a string ``enabled`` is read as. The same set the
#: config resolver reads for its own switches (``resolve_config._FALSE_SPELLINGS``),
#: kept here because that module cannot be imported from this one.
_DISABLED_SPELLINGS = frozenset({"0", "off", "f", "false", "n", "no"})


def section_enabled(plugin_config: Any) -> bool:
    """Whether a plugin's config section leaves it enabled.

    The one reading of ``enabled`` the phases share: the pre-filter dependency
    skip, the constructor-failure row's ``excluded`` flag, the filtered-out
    row and the not-selected test of a scanner all ask this, so they cannot
    disagree. Read from the dict ``get_plugin_config`` returns as well as from
    a model; an absent section or an absent key means the default, enabled.

    A section an external plugin keeps is never validated, so ``enabled`` can be
    the text of an environment reference (``"false"``, ``"no"``, ``"0"``). Text
    is read the way the plugin's own ``enabled: bool`` field would read it, not by
    truthiness, which called every non-empty string enabled: a spelling of false
    disables the plugin, an empty or whitespace-only string is off (a bool field
    would refuse it, and an empty value is not a choice to run), and any other text
    leaves it enabled (a scanner that silently does not run is the worse error).
    """
    if plugin_config is None:
        return True
    if isinstance(plugin_config, dict):
        enabled = plugin_config.get("enabled", True)
    else:
        enabled = getattr(plugin_config, "enabled", True)
    if isinstance(enabled, str):
        spelled = enabled.strip().lower()
        return bool(spelled) and spelled not in _DISABLED_SPELLINGS
    return bool(enabled)
