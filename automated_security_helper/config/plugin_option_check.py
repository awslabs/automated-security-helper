# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Refuse unknown options for plugins loaded from ``ash_plugin_modules``.

A built-in plugin's config section is a typed field of ``ScannerConfigSegment``,
``ReporterConfigSegment`` or ``ConverterConfigSegment``, so its options are
checked when the config loads (``PluginOptionsBase._refuse_unknown_options``).
Any other section is kept as a plain mapping, because the config model cannot
know which plugins will be loaded. It became the plugin's config model only when
the plugin was constructed, inside the phase's ``try``: an unknown option there
was at best an ERROR row for that one plugin, and before options refused unknown
keys it was simply kept and never read.

:func:`refuse_unknown_plugin_options` runs once the plugins are loaded and
before anything is converted or scanned (``ScanExecutionEngine.__init__``), so
an unknown option of a loaded plugin stops the run with exit 3, as one of a
built-in plugin does. A section that no loaded plugin reads cannot be checked:
it may be for a plugin this run does not load. It is left as it is.
"""

from __future__ import annotations

import typing
from typing import Any, Callable, Iterable, Mapping

from pydantic import BaseModel, ValidationError

from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP
from automated_security_helper.utils.unknown_keys import known_keys

_SEGMENTS = {
    "converter": "converters",
    "scanner": "scanners",
    "reporter": "reporters",
}


def _config_class(plugin_class: type) -> type[BaseModel] | None:
    """The plugin's own config model: the first BaseModel in its ``config`` type."""
    field = (getattr(plugin_class, "model_fields", None) or {}).get("config")
    if field is None:
        return None
    for candidate in typing.get_args(field.annotation) or (field.annotation,):
        if isinstance(candidate, type) and issubclass(candidate, BaseModel):
            return candidate
    return None


def _options_class(config_class: type[BaseModel]) -> type[BaseModel] | None:
    field = config_class.model_fields.get("options")
    if field is None:
        return None
    annotation = field.annotation
    for candidate in typing.get_args(annotation) or (annotation,):
        if isinstance(candidate, type) and issubclass(candidate, BaseModel):
            return candidate
    return None


def _read_from_environment(value: Any) -> bool:
    """Whether ``value`` came from an environment reference in a config file.

    Either the loader's marker for text it read from the environment or from a
    reference's default (``utils.redacted_model.EnvResolvedScalar``, which an
    external plugin's section keeps as the segment models never validate it),
    or a reference the loader left as written, ``${VAR}`` (a name a config file
    may not read, or one it could not resolve; ``ash_config.ENV_REFERENCE_PATTERN``).
    """
    from automated_security_helper.config.ash_config import ENV_REFERENCE_PATTERN
    from automated_security_helper.utils.redacted_model import EnvResolvedScalar

    if isinstance(value, EnvResolvedScalar):
        return True
    return isinstance(value, str) and ENV_REFERENCE_PATTERN.match(value) is not None


def _enabled_problems(
    config_class: type[BaseModel], section: Any, where: str, plugin: str
) -> list[str]:
    """The refusal of a section's ``enabled`` value its config class cannot hold.

    A built-in plugin's section is typed, so ``enabled: maybe`` is refused when
    the config loads. A loaded plugin's section is a plain mapping until the
    plugin is built, so the declared type of ``enabled`` is checked here, with
    the same message the model gives, and the key is named by its location.

    A value the config file read from the environment, or a reference the
    loader left as written (``_read_from_environment``), is not checked here:
    it takes the path the rest of the configuration gives an environment-read
    scalar. The plugin's own config model names the variable, never the value,
    when the plugin is built, and an off-host reporter whose section sets
    ``enabled`` to such a value is warned of by the type it set and is not run
    (core/phases/report_phase.py), while the scan goes on. Refused here, the
    whole run ended with exit 3 at configuration time for a value the file
    reads from the environment, where before this check it warned and ran.
    """
    if not isinstance(section, dict) or "enabled" not in section:
        return []
    field = config_class.model_fields.get("enabled")
    if field is None:
        return []
    value = section["enabled"]
    if _read_from_environment(value):
        return []
    # Through the plugin's own config class, as it is built, so a validator on
    # the field runs. The class may require other fields or hold a model-level
    # check, so only the errors located at ``enabled`` count. A type the class
    # cannot build a schema for (a schema error is a TypeError) is not a value
    # problem and is left to the plugin's own build.
    try:
        config_class.model_validate({"enabled": value})
    except ValidationError as error:
        return [
            f"{where}.enabled ({plugin}): {item.get('msg', '')}"
            for item in error.errors()
            if tuple(item.get("loc", ()))[:1] == ("enabled",)
        ]
    except (TypeError, ValueError):
        return []
    return []


def _option_problems(
    options_class: type[BaseModel], options: Any, where: str, plugin: str
) -> list[str]:
    """The plugin's own validation errors for ``options``, located at ``where``.

    Validating with the options model, rather than only comparing keys, keeps
    the plugin's own messages: ferret-scan refuses ``debug`` with "Use
    'ferret_debug: true' instead", which its model's validator raises before
    the generic unknown-key check runs. It also refuses a value of the wrong
    type at load, as the config model does for a built-in plugin, and so does
    an ``options`` value that is not a mapping at all.
    """
    try:
        options_class.model_validate(options)
    except ValidationError as error:
        problems = []
        for item in error.errors():
            location = ".".join(str(part) for part in item.get("loc", ()) if part != "")
            message = item.get("msg", "")
            problems.append(
                f"{where}{'.' + location if location else ''} ({plugin}): {message}"
            )
        return problems
    return []


def options_checked_at_scan_note(config_data: Any, shown: Any = None) -> str | None:
    """The sentence ``ash config lint`` prints for sections it cannot check.

    ``ash config validate`` and ``ash config lint`` read the config file without
    loading the plugins ``ash_plugin_modules`` names, so for a section that is not
    a built-in plugin's they cannot know which plugin reads it or what options it
    declares. A scan checks them when it loads the plugins
    (``refuse_unknown_plugin_options``). None when every section is a built-in
    plugin's.

    Each section is named as ``shown`` holds its key at the same position:
    ``config_data`` as ``environment_record.with_environment_values_shown``
    returns it, a key read from the environment shown as ``<value>``. None
    names each key as it is.
    """
    from automated_security_helper.config.environment_record import (
        ENVIRONMENT_VALUE_SHOWN,
    )
    from automated_security_helper.config.plugin_section_names import (
        declared_section_names,
        folded_section_name,
    )

    if shown is None:
        shown = config_data
    from automated_security_helper.config.ash_config import (
        ConverterConfigSegment,
        ReporterConfigSegment,
        ScannerConfigSegment,
    )

    if not isinstance(config_data, dict):
        return None
    built_in: dict[str, type[BaseModel]] = {
        "converters": ConverterConfigSegment,
        "scanners": ScannerConfigSegment,
        "reporters": ReporterConfigSegment,
    }
    sections: list[str] = []
    for segment_name, segment_cls in built_in.items():
        segment = config_data.get(segment_name)
        if not isinstance(segment, dict):
            continue
        declared = known_keys(segment_cls)
        # Any spelling of a declared plugin's name is that plugin's section:
        # the model folds it in and checks it (plugin_section_names), so the
        # note is not true of it.
        declared_folds = set(declared_section_names(segment_name))
        shown_segment = shown.get(segment_name) if isinstance(shown, dict) else None
        # Keys paired by position: two keys read from the environment are both
        # `<value>` in the copy. A copy that does not line up names every key so.
        shown_keys = (
            [str(key) for key in shown_segment]
            if isinstance(shown_segment, dict) and len(shown_segment) == len(segment)
            else [ENVIRONMENT_VALUE_SHOWN] * len(segment)
        )
        sections.extend(
            f"{segment_name}.{shown_key}"
            for key, shown_key in zip(segment, shown_keys)
            if isinstance(key, str)
            and key not in declared
            and folded_section_name(key) not in declared_folds
        )
    if not sections:
        return None
    return (
        f"The options of {', '.join(sorted(sections))} are not checked here: no "
        "built-in plugin is configured under that name, and the plugins named in "
        "ash_plugin_modules are not loaded here, so what they declare is unknown. "
        "A scan checks the options of every section a loaded plugin reads when it "
        "loads the plugins, and refuses an unknown or invalid one with exit code 3."
    )


def refuse_unknown_options_of_registered(
    config: Any,
    manager: Any,
    builds: Callable[[str, type], bool] | None = None,
) -> None:
    """refuse_unknown_plugin_options for the plugins ``manager`` has registered.

    For a command that builds registered plugins from their sections of the
    configuration (``ash dependencies install``, ``ash plugin list``), before it
    builds any: a configuration with an unknown or refused option of a plugin
    the command builds is then refused, exit 3, as the scan engine and ``ash
    report`` refuse it, and the refusal names no value or key read from the
    environment.

    Args:
        config: The run's ``AshConfig``.
        manager: The plugin manager the caller imported.
        builds: Whether the command builds a plugin, by its type (``scanner``,
            ...) and class. The problems of a plugin it does not build are
            reported at info and do not refuse the configuration. None: every
            registered plugin is built (``ash plugin list``).
    """
    refuse_unknown_plugin_options(
        config,
        {
            plugin_type: list(manager.plugin_modules(plugin_type))
            for plugin_type in _SEGMENTS
        },
        builds=builds,
    )


def refuse_unknown_plugin_options(
    config: Any,
    plugins: Mapping[str, Iterable[type]],
    builds: Callable[[str, type], bool] | None = None,
) -> None:
    """Raise ``ASHConfigValidationError`` for an option a loaded plugin refuses.

    An option it does not declare, or a value its model refuses, with the
    plugin's own message where it has one; and a key at the section level,
    beside ``enabled``, that its config class does not declare
    (``base.plugin_config.section_key_problems``), as the config model refuses
    one for a built-in plugin.

    Args:
        config: The run's ``AshConfig``.
        plugins: Loaded plugin classes by type (``converter``, ``scanner``,
            ``reporter``), as ``ScanExecutionEngine.plugins`` holds them.
        builds: As for refuse_unknown_options_of_registered: the problems of a
            plugin for which it is false are logged at info instead. None: all
            refuse.
    """
    from automated_security_helper.base.plugin_config import (
        plugin_config_key,
        section_key_problems,
    )
    from automated_security_helper.config.ash_config import (
        plugin_section_claims,
        plugin_section_key,
        reduced_plugin_name,
    )
    from automated_security_helper.config.config_validator import redact_values
    from automated_security_helper.utils.error_text import carry_environment_values

    # The values and keys the config's files read from the environment
    # (AshConfig._environment_values): a section's key is printed in a location
    # and in an unknown-key message, so neither line below names them, as the
    # config model's refusals do not.
    environment_values = getattr(config, "_environment_values", None) or []
    problems: list[str] = []
    # Problems of a plugin the command does not build (``builds``).
    not_built: list[str] = []
    checked = set()
    for plugin_type, segment_name in _SEGMENTS.items():
        segment = getattr(config, segment_name, None)
        if segment is None:
            continue
        sections = dict(getattr(segment, "model_extra", None) or {})
        if not sections:
            continue
        # The keys get_plugin_config indexes, declared sections first (it reads
        # the segment's model_dump(by_alias=True)), so the check reads the one
        # section the lookup reads for a plugin and no other spelling of it.
        dumped = segment.model_dump(by_alias=True)
        claims = plugin_section_claims(dumped)
        for plugin_class in plugins.get(plugin_type, ()) or ():
            config_class = _config_class(plugin_class)
            if config_class is None:
                continue
            options_class = _options_class(config_class)
            name = plugin_config_key(plugin_class)
            wanted = reduced_plugin_name(name)
            found = (
                problems
                if builds is None or builds(plugin_type, plugin_class)
                else not_built
            )
            # The lookup takes the plugin's own name when it is a key, else the
            # first key that claims the reduced name (plugin_section_key). A
            # section that lookup does not return is never read by the plugin,
            # and is warned of as a shared name where the lookup runs.
            key = name if name in dumped else plugin_section_key(dumped, wanted, claims)
            if key is None or key not in sections:
                continue
            section = sections[key]
            checked.add((segment_name, key))
            # A key beside "enabled" that the plugin's config does not
            # declare, as the config model refuses one for a built-in.
            found.extend(
                section_key_problems(config_class, section, f"{segment_name}.{key}")
            )
            found.extend(
                _enabled_problems(
                    config_class,
                    section,
                    f"{segment_name}.{key}",
                    f"{plugin_type} '{key}'",
                )
            )
            options = section.get("options") if isinstance(section, dict) else None
            # None is no options. Any other value that is not a mapping is
            # refused by the options model, as a built-in plugin's is at load.
            if options_class is None or options is None:
                continue
            found.extend(
                _option_problems(
                    options_class,
                    options,
                    f"{segment_name}.{key}.options",
                    f"{plugin_type} '{key}'",
                )
            )
        for key in sections:
            if (segment_name, key) not in checked:
                # NO_MARKUP: the key is data the file wrote.
                ASH_LOGGER.debug(
                    redact_values(
                        f"Options in {segment_name}.{key} were not checked: no "
                        f"loaded {plugin_type} plugin reads that section.",
                        environment_values,
                    ),
                    extra=NO_MARKUP,
                )
    if not_built:
        # NO_MARKUP: the locations and messages hold the file's keys.
        ASH_LOGGER.info(
            redact_values(
                "Not refused, as this run does not build the plugins they belong "
                "to; a scan that loads them refuses the configuration: "
                + " ".join(not_built),
                environment_values,
            ),
            extra=NO_MARKUP,
        )
    if problems:
        # The text is redacted as written, so a value a complete escape code
        # splits is not found in it. The values ride on the error: its printers
        # (error_text) strip the codes and redact with them again.
        refusal = ASHConfigValidationError(
            redact_values(
                "Configuration validation failed: " + " ".join(problems),
                environment_values,
            )
        )
        carry_environment_values(refusal, environment_values)
        raise refusal
