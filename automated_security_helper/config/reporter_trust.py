# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Reporter options a config file in the scanned tree may not choose.

The AWS reporters send findings to a service: Security Hub in an account and
region, a Bedrock model in a region, an S3 bucket and key prefix, a CloudWatch
Logs group and stream. Their profile option picks the credentials they use, and
the Bedrock reporter writes its summaries to the files its options name, joined
to the reports directory, so an absolute path or ``..`` writes elsewhere. When the
config was built from a file inside the scanned tree (``config/sandbox_grants.py``
decides that), or from a file an MCP client delivered (``untrusted_config``), those
options come from the trusted base instead: the defaults, an operator config
outside the tree, and ``--config-overrides``. Each section a reporter reads under
any spelling ``AshConfig.get_plugin_config`` accepts is covered, and the values
that are not honored are named in one warning. Under the MCP server the default
``denied_paths`` refuse a client's file that sets one of them, and the overrides
``resolve_config`` is handed there are the client's, so none is replayed.

A reporter names these options in ``ReporterPluginBase.destination_options``.
The built-in AWS reporters' declarations are also listed here, in
``REPORTER_DESTINATION_OPTIONS``, because ``resolve_config`` runs before any plugin
package is imported, and importing one registers its plugins for the whole
process. tests/unit/config/test_reporter_destinations_from_repo_config.py holds
each declaration equal to its entry. A reporter a plugin module adds
(``ash_plugin_modules``, ``--ash-plugin-modules``, ``ASH_PLUGIN_MODULES``) is known
only once the scan imports the module. ``resolve_config`` records the in-tree files
and the trusted base on the config (``AshConfig._in_tree_config_files`` and
``_trusted_reporter_base``), and ``confine_declared_reporter_destinations``, which
``ScanExecutionEngine`` and ``ash report`` call once the plugin modules are loaded
and before any reporter is built, applies the same rule to every loaded reporter's
declared options, with the same warning.

Under the MCP server such a reporter's options are not refused, as the built-ins'
are by the default ``denied_paths``: a client's file is checked at resolution,
before the module that declares them is imported. The file resolves, and the
value is replaced by the trusted base's, as for a file inside the tree. An
operator who wants such a file refused lists the option in the profile's own
``denied_paths``.

Whether such a reporter runs at all is the operator's choice too, since each of
them sends findings off the host when it runs. So ``enabled`` of a built-in AWS
reporter, and of a reporter a plugin module adds that declares
``destination_options``, follows the same rule: where the trusted base has the
reporter off (by its own ``enabled``, or by the reporter's default when it sets
none), a file inside the tree or one an MCP client delivered does not turn it on,
whether it writes ``enabled: true`` or leaves the section out while the
reporter's default is on (a file that replaces the operator's config would
otherwise return the reporter to that default). ``enabled: false`` only narrows
what is sent, so it applies from any config (``turns_a_reporter_off``). A reporter that declares no ``destination_options``
writes only local files, and its ``enabled`` still applies from the tree. Under
the MCP server the default ``denied_paths`` also refuse a client's file that turns
a built-in AWS reporter on, and every other option of the Bedrock reporter, which
chooses what is sent to the model; ``enabled: false`` is accepted there, in a
delivered file (``client_config_policy._writes_a_tightening``) and in a client's
runtime overrides (``runtime_patch._turns_an_off_host_reporter_off``). The reporters' other options
(formatting, model parameters) still apply from the tree.
"""

from __future__ import annotations

from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
)

from pydantic import BaseModel

from automated_security_helper.config.config_sources import describe_config_path
from automated_security_helper.config.untrusted_source import (
    IN_TREE_OR_DELIVERED,
    UntrustedSource,
)
from automated_security_helper.utils.log import ASH_LOGGER

if TYPE_CHECKING:
    from automated_security_helper.config.ash_config import AshConfig

#: How long a reporter keeps calling its service, with the operator's credentials,
#: when the service refuses it: the operator's to set, as where it calls is. Their
#: caps are in the reporters' options models (``ash_aws_plugins.aws_utils``).
_RETRY_OPTIONS: Tuple[str, ...] = ("max_retries", "base_delay", "max_delay")

#: What the Bedrock reporter sends to the model, besides where it sends it: source
#: from the scanned tree and instructions (``include_code_snippets``,
#: ``custom_prompt``), text added to the prompts (``industry_context``,
#: ``compliance_frameworks``, ``custom_context``), which findings and how many
#: (``exclude_scanner_types``, which keeps secret findings out by default,
#: ``actionable_only``, ``max_findings_to_analyze``, ``max_findings_per_severity``,
#: ``summarize_findings``, ``batch_processing``), and whether another model than
#: ``model_id`` may receive them (``enable_fallback_models``).
_BEDROCK_CONTENT_OPTIONS: Tuple[str, ...] = (
    "include_code_snippets",
    "custom_prompt",
    "exclude_scanner_types",
    "actionable_only",
    "max_findings_to_analyze",
    "max_findings_per_severity",
    "summarize_findings",
    "batch_processing",
    "industry_context",
    "compliance_frameworks",
    "custom_context",
    "enable_fallback_models",
)

#: The options of each built-in reporter that pick where findings go or which
#: credentials send them: each reporter's ``destination_options``. Where each is
#: used is listed in the PR that added this. The Bedrock reporter's
#: ``_BEDROCK_CONTENT_OPTIONS`` choose what is sent to the model with them.
#: Security Hub's ``findings_scope``
#: (which findings it imports and may archive) and ``archive_resolved_findings``
#: are listed before its options model defines them, so that no repository's or
#: client's config can set them once it does; the reporter declares each when its
#: model gains it.
REPORTER_DESTINATION_OPTIONS: Dict[str, Tuple[str, ...]] = {
    "aws-security-hub": (
        "aws_region",
        "aws_profile",
        "account_id",
        "archive_resolved_findings",
        "findings_scope",
    ),
    "bedrock-summary-reporter": (
        "aws_region",
        "aws_profile",
        "model_id",
        "output_file",
        "output_executive_file",
        "output_technical_file",
        *_BEDROCK_CONTENT_OPTIONS,
        *_RETRY_OPTIONS,
    ),
    "cloudwatch-logs": (
        "aws_region",
        "log_group_name",
        "log_stream_name",
        *_RETRY_OPTIONS,
    ),
    "s3": ("aws_region", "aws_profile", "bucket_name", "key_prefix", *_RETRY_OPTIONS),
}

#: Each built-in reporter's own default for ``enabled``, for the reporters whose
#: ``enabled`` is the operator's choice: those in ``REPORTER_DESTINATION_OPTIONS``.
#: It is what a reporter gets when no config section sets ``enabled``. Listed
#: here because the reporters' models are in a plugin package that
#: ``resolve_config`` does not import;
#: tests/unit/config/test_reporter_destinations_from_repo_config.py holds each
#: value equal to the reporter's config model.
REPORTER_ENABLED_DEFAULTS: Dict[str, bool] = {
    "aws-security-hub": True,
    "bedrock-summary-reporter": True,
    "cloudwatch-logs": True,
    "s3": True,
}

_MISSING = object()


def turns_a_reporter_off(value: Any) -> bool:
    """Whether ``enabled: value``, written in an untrusted config, only turns a reporter off.

    Only ``false`` itself. A value pydantic would also read as false (``0``,
    ``"no"``) is not taken as one here, so it is confined like ``true``.
    """
    return value is False


def _reads_as_off(value: Any) -> bool:
    """Whether the reporter reads ``enabled: value`` as off, as its config model does.

    For the trusted base's value, which the operator may have written in any
    form the reporter's model accepts (``"no"``, ``0``). A value the model would
    refuse counts as on, so it confines nothing.
    """
    from pydantic import TypeAdapter, ValidationError

    try:
        return TypeAdapter(bool).validate_python(value) is False
    except ValidationError:
        return False


def _as_dict(section: Any) -> Optional[Dict[str, Any]]:
    if isinstance(section, dict):
        return dict(section)
    if hasattr(section, "model_dump"):
        return section.model_dump(by_alias=True)
    return None


def _as_section(section: Any) -> Dict[str, Any]:
    """A section of the config being confined, a null or other non-mapping one as empty.

    Left as it is, ``reporters: {s3: null}`` builds the reporter from its own
    defaults (``get_plugin_config`` returns None), which may be on and point
    elsewhere than the trusted base, so it is confined as a section that sets
    nothing.
    """
    return _as_dict(section) or {}


def confine_reporter_destinations(
    config: "AshConfig",
    trusted_config: "AshConfig",
    config_overrides: Optional[Sequence[str]],
    in_tree: Sequence[Path],
    source: UntrustedSource = IN_TREE_OR_DELIVERED,
) -> None:
    """Replace the destination options an in-tree file set with the trusted base's.

    Records the files and the trusted base on ``config`` for
    ``confine_declared_reporter_destinations``.

    Args:
        config: The resolved AshConfig, changed in place.
        trusted_config: The trusted base ``resolve_config`` built for the sandbox
            settings: the defaults, or the operator's config outside the tree.
        config_overrides: ``--config-overrides``. Those under ``reporters`` are
            replayed onto ``trusted_config``, the same way the sandbox overrides
            are, so an override still sets these options.
        in_tree: The config files inside the tree, named in the warning.
        source: Why those files are not the operator's, and the fix, for the
            warning.
    """
    from automated_security_helper.config.resolve_config import (
        apply_config_overrides,
    )

    reporter_overrides = [
        override
        for override in config_overrides or []
        if override.partition("=")[0].removesuffix("+").strip().split(".")[0]
        == "reporters"
    ]
    if reporter_overrides:
        trusted_config = apply_config_overrides(trusted_config, reporter_overrides)
    config._in_tree_config_files = tuple(in_tree)
    config._trusted_reporter_base = trusted_config
    _confine(
        config,
        trusted_config,
        REPORTER_DESTINATION_OPTIONS,
        REPORTER_ENABLED_DEFAULTS,
        in_tree,
        source,
    )


def confine_declared_reporter_destinations(
    config: "AshConfig",
    reporter_classes: Iterable[type],
    source: UntrustedSource = IN_TREE_OR_DELIVERED,
) -> None:
    """Apply ``confine_reporter_destinations`` to the options loaded reporters declare.

    For the reporters a plugin module adds, which ``resolve_config`` cannot see:
    their declared options, and ``enabled`` of each that declares any. Call it
    once the plugin modules are imported and before any reporter is built. Does
    nothing for a config with no file inside the tree, and repeats nothing
    already done for a built-in reporter: its options already hold the trusted
    base's values.

    Args:
        config: The config ``resolve_config`` returned, changed in place.
        reporter_classes: The reporter classes the plugin manager loaded.
        source: As for ``confine_reporter_destinations``; ``ash merge`` passes
            the one it passed there.
    """
    from automated_security_helper.config.ash_config import AshConfig

    if not isinstance(config, AshConfig):
        return
    trusted_config = config._trusted_reporter_base
    if trusted_config is None:
        return
    reporter_classes = list(reporter_classes)
    _confine(
        config,
        trusted_config,
        declared_destination_options(reporter_classes),
        declared_enabled_defaults(reporter_classes),
        config._in_tree_config_files,
        source,
    )


def declared_destination_options(
    reporter_classes: Iterable[type],
) -> Dict[str, Tuple[str, ...]]:
    """Each reporter's declared destination options, by the name its config is under.

    The name is ``plugin_config_key``'s, which ``ReportPhase`` looks the config up
    by. An option with an alias is listed under the alias as well, since a config
    file writes the alias.
    """
    from automated_security_helper.base.plugin_config import plugin_config_key

    found: Dict[str, Tuple[str, ...]] = {}
    for reporter_class in reporter_classes:
        declared = getattr(reporter_class, "destination_options", None) or ()
        if isinstance(declared, str):
            declared = (declared,)
        names = [name for name in declared if isinstance(name, str) and name]
        if not names:
            continue
        key = plugin_config_key(reporter_class)
        spellings = list(found.get(key, ()))
        for name in names:
            for spelling in (name, *_aliases(reporter_class, name)):
                if spelling not in spellings:
                    spellings.append(spelling)
        found[key] = tuple(spellings)
    return found


def declared_enabled_defaults(reporter_classes: Iterable[type]) -> Dict[str, bool]:
    """Each reporter's default for ``enabled``, by the name its config is under.

    Only the reporters that declare ``destination_options``: one that declares
    none writes only local files, so whether it runs is not a choice of where
    findings go. The default is the one the reporter's own config model gives
    (the most derived of the models its ``config`` field accepts, which is the
    one a reporter built with no config section gets), and true when there is
    none, as for ``ReporterPluginConfigBase``.
    """
    from automated_security_helper.base.plugin_config import plugin_config_key

    found: Dict[str, bool] = {}
    for reporter_class in reporter_classes:
        if not declared_destination_options([reporter_class]):
            continue
        default = True
        models = [
            model
            for model in _config_models(reporter_class)
            if "enabled" in model.model_fields
        ]
        if models:
            own = max(models, key=lambda model: len(model.__mro__))
            field = own.model_fields["enabled"]
            default = field.get_default(call_default_factory=True) is not False
        found[plugin_config_key(reporter_class)] = default
    return found


def _models(annotation: Any) -> List[type[BaseModel]]:
    """The pydantic models ``annotation`` names, through any Union or Optional."""
    import typing

    found: List[type[BaseModel]] = []
    pending: List[Any] = [annotation]
    while pending:
        item = pending.pop()
        if isinstance(item, type) and issubclass(item, BaseModel):
            found.append(item)
        else:
            pending.extend(typing.get_args(item))
    return found


def _config_models(reporter_class: type) -> List[type[BaseModel]]:
    """The config models of ``reporter_class``'s ``config`` field."""
    config_field = (getattr(reporter_class, "model_fields", None) or {}).get("config")
    return [] if config_field is None else _models(config_field.annotation)


def _aliases(reporter_class: type, option: str) -> List[str]:
    """The aliases of field ``option`` in any options model of ``reporter_class``'s config."""
    from pydantic import AliasChoices

    aliases: List[str] = []
    for config_model in _config_models(reporter_class):
        options_field = config_model.model_fields.get("options")
        if options_field is None:
            continue
        for options_model in _models(options_field.annotation):
            field = options_model.model_fields.get(option)
            if field is None:
                continue
            candidates: List[Any] = [field.alias]
            if isinstance(field.validation_alias, AliasChoices):
                candidates.extend(field.validation_alias.choices)
            else:
                candidates.append(field.validation_alias)
            for alias in candidates:
                if isinstance(alias, str) and alias != option and alias not in aliases:
                    aliases.append(alias)
    return aliases


def _confine(
    config: "AshConfig",
    trusted_config: "AshConfig",
    destinations: Mapping[str, Sequence[str]],
    enabled_defaults: Mapping[str, bool],
    in_tree: Sequence[Path],
    source: UntrustedSource = IN_TREE_OR_DELIVERED,
) -> None:
    """Set each reporter's ``destinations`` options, and ``enabled`` where the
    trusted base turns it off, to the trusted base's, with one warning."""
    ignored = _confine_options(config, trusted_config, destinations)
    ignored.extend(
        _confine_enabled(
            config,
            trusted_config,
            enabled_defaults,
            from_trusted_only=source.enabled_from_trusted_only,
        )
    )
    if not ignored:
        return
    files = ", ".join(describe_config_path(path) for path in in_tree)
    ASH_LOGGER.warning(
        f"Ignoring {', '.join(ignored)} from {files}: {source.reason}, and these "
        "options choose whether findings are sent, where they are sent or written, "
        f"and which credentials send them. Set them with {source.remedy}."
    )


def _sections_of(config: "AshConfig", plugin: str) -> List[str]:
    """The keys of ``config``'s reporter sections that ``plugin``'s lookup reads."""
    from automated_security_helper.config.ash_config import (
        plugin_key_lookup_names,
        reduced_plugin_name,
    )

    reduced = reduced_plugin_name(plugin)
    extras = config.reporters.__pydantic_extra__ or {}
    return [key for key in extras if reduced in plugin_key_lookup_names(key)]


def _confine_options(
    config: "AshConfig",
    trusted_config: "AshConfig",
    destinations: Mapping[str, Sequence[str]],
) -> List[str]:
    """Set each reporter's ``destinations`` options to the trusted base's.

    An option is matched under every mix of ``-`` and ``_`` in its name, since a
    config merge reads them as the same key (``config_sources._resolve_dict_key``):
    each spelling the config writes is replaced by the spellings the trusted base
    writes, with their values. Returns the spellings the config set to a value
    the trusted base does not give them, as dotted keys.
    """
    extras = config.reporters.__pydantic_extra__
    ignored: List[str] = []
    if not extras:
        return ignored
    for plugin, option_names in destinations.items():
        trusted_section = _as_dict(trusted_config.get_plugin_config("reporter", plugin))
        trusted_options = dict((trusted_section or {}).get("options") or {})
        for key in _sections_of(config, plugin):
            section = _as_section(extras[key])
            options = dict(section.get("options") or {})
            changed = False
            for name in option_names:
                written = _spellings(options, name)
                wanted = {
                    k: trusted_options[k] for k in _spellings(trusted_options, name)
                }
                if {k: options[k] for k in written} == wanted:
                    continue
                for spelling in written:
                    if options[spelling] != wanted.get(spelling, _MISSING):
                        ignored.append(f"reporters.{key}.options.{spelling}")
                    options.pop(spelling)
                options.update(wanted)
                changed = True
            if changed:
                section["options"] = options
                extras[key] = section
    return ignored


def _spellings(options: Mapping[Any, Any], name: str) -> List[str]:
    """The keys of ``options`` that are ``name`` with ``-`` and ``_`` folded."""
    folded = name.replace("-", "_")
    return [
        key
        for key in options
        if isinstance(key, str) and key.replace("-", "_") == folded
    ]


def _confine_enabled(
    config: "AshConfig",
    trusted_config: "AshConfig",
    enabled_defaults: Mapping[str, bool],
    from_trusted_only: bool = False,
) -> List[str]:
    """Turn off each reporter of ``enabled_defaults`` that the trusted base has off.

    A section's value is its ``enabled``, or the reporter's default when it sets
    none. Where the trusted base's value is off, each of ``config``'s sections
    the lookup reads whose value is not ``false`` gets ``enabled: false``, and
    the key of each that wrote a value is returned. A config with no section for
    the reporter gets one that turns it off, unless the reporter's default
    already does. Nothing changes where the trusted base has the reporter on.

    With ``from_trusted_only`` (``UntrustedSource.enabled_from_trusted_only``),
    the trusted base's value applies in both directions: ``config``'s
    ``enabled: false`` is replaced as well (``_take_trusted_enabled``).
    """
    extras = config.reporters.__pydantic_extra__
    ignored: List[str] = []
    if extras is None:
        return ignored
    for plugin, default in enabled_defaults.items():
        trusted_section = _as_dict(trusted_config.get_plugin_config("reporter", plugin))
        trusted_off = _reads_as_off((trusted_section or {}).get("enabled", default))
        if from_trusted_only:
            ignored.extend(
                _take_trusted_enabled(config, plugin, default, not trusted_off)
            )
            continue
        if not trusted_off:
            continue
        keys = _sections_of(config, plugin)
        if not keys:
            if not _reads_as_off(default):
                extras[plugin] = {"enabled": False}
            continue
        for key in keys:
            section = _as_section(extras[key])
            current = section.get("enabled", _MISSING)
            if turns_a_reporter_off(current) or (
                current is _MISSING and _reads_as_off(default)
            ):
                continue
            if current is not _MISSING:
                ignored.append(f"reporters.{key}.enabled")
            section["enabled"] = False
            extras[key] = section
    return ignored


def _take_trusted_enabled(
    config: "AshConfig", plugin: str, default: bool, wanted: bool
) -> List[str]:
    """Give each of ``config``'s sections for ``plugin`` the trusted base's ``enabled``.

    ``wanted`` is the trusted base's value as the reporter reads it, its default
    where the trusted base sets none. A section whose ``enabled`` the reporter
    reads differently has its key returned; one that writes none is set only
    where the reporter's default differs from ``wanted``. A config with no
    section for the reporter gets one in that case too.
    """
    extras = config.reporters.__pydantic_extra__
    ignored: List[str] = []
    if extras is None:
        return ignored
    keys = _sections_of(config, plugin)
    if not keys:
        if _reads_as_off(default) == wanted:
            extras[plugin] = {"enabled": wanted}
        return ignored
    for key in keys:
        section = _as_section(extras[key])
        current = section.get("enabled", _MISSING)
        if current is _MISSING:
            if _reads_as_off(default) != wanted:
                continue
        elif current is wanted:
            continue
        elif _reads_as_off(current) == wanted:
            ignored.append(f"reporters.{key}.enabled")
        section["enabled"] = wanted
        extras[key] = section
    return ignored
