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

Whether such a reporter runs at all is the operator's choice too, in both
directions, since each of them sends findings off the host when it runs and the
operator decides which destinations get them. So ``enabled`` of a built-in AWS
reporter, and of a reporter a plugin module adds that declares
``destination_options``, comes from the trusted base, or from the reporter's own
default where the trusted base sets none: a file inside the tree, one an MCP
client delivered or named, a client's runtime overrides and a shard's recorded
config neither turn one on nor turn one off, and a value of theirs the reporter
reads differently is ignored with the warning. Leaving the section out does not
return the reporter to its default either, where that differs from the trusted
base. A reporter that declares no ``destination_options`` writes only local files,
and its ``enabled`` still applies from the tree. Under the MCP server the default
``denied_paths`` also refuse a client's file that turns a built-in AWS reporter on,
and every other setting of its section. A client's ``enabled: false`` is not
refused there, in a delivered file (``client_config_policy._writes_a_tightening``)
or in its runtime overrides (``runtime_patch._turns_an_off_host_reporter_off``),
but it takes no effect: the confinement above replaces it. The reporters' other
options (formatting, model parameters) still apply from the tree.
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
#: ``summarize_findings``, ``batch_processing``), whether another model than
#: ``model_id`` may receive them (``enable_fallback_models``), and which of the
#: reporter's calls, each sending findings, are made: the simple report or the
#: sectioned one (``add_section_headers``), the files written with calls of their
#: own (``output_markdown``), the sections asked for (``include_sections``,
#: ``exclude_sections``) and a call per severity (``group_by_severity``).
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
    "add_section_headers",
    "output_markdown",
    "include_sections",
    "exclude_sections",
    "group_by_severity",
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
    "aws-security-hub": False,
    "bedrock-summary-reporter": False,
    "cloudwatch-logs": False,
    "s3": False,
}

_MISSING = object()


def turns_a_reporter_off(value: Any) -> bool:
    """Whether ``enabled: value``, written by an MCP client, only asks to turn a reporter off.

    Only ``false`` itself: a value pydantic would also read as false (``0``,
    ``"no"``) is refused like ``true``. ``false`` is not refused, since it asks
    for nothing beyond the server's config, but it does not take effect either:
    ``_confine_enabled`` takes ``enabled`` from the trusted base.
    """
    return value is False


def _reads_as(value: Any) -> Optional[bool]:
    """``enabled: value`` as the reporter's config model reads it, or None if it refuses it."""
    from pydantic import TypeAdapter, ValidationError

    try:
        return TypeAdapter(bool).validate_python(value)
    except ValidationError:
        return None


def _reads_as_off(value: Any) -> bool:
    """Whether the reporter does not run with ``enabled: value``.

    For the trusted base's value, which the operator may have written in any
    form the reporter's model accepts (``"no"``, ``0``). A value the model would
    refuse (``"disabled"``, ``null``) counts as off: the operator's own config
    could not build the reporter with it, so it did not turn the reporter on,
    and a config that is not the operator's does not either.
    """
    return _reads_as(value) is not True


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
    in_tree_documents: Iterable[Any] = (),
) -> None:
    """Replace the destination options an in-tree file set with the trusted base's.

    Records the files, the reporter section keys they wrote and the trusted base
    on ``config`` for ``confine_declared_reporter_destinations``.

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
        in_tree_documents: Those files' documents as they were parsed. The
            warning quotes a section as they spelled it (``written_reporter_keys``).
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
    config._in_tree_reporter_keys = written_reporter_keys(in_tree_documents)
    _confine(
        config,
        trusted_config,
        REPORTER_DESTINATION_OPTIONS,
        REPORTER_ENABLED_DEFAULTS,
        in_tree,
        source,
    )


def confine_off_host_reporters_to_overrides(
    config: "AshConfig",
    files: Sequence[Path],
    config_overrides: Optional[Sequence[str]],
    source: UntrustedSource,
) -> None:
    """Take the off-host reporters' ``enabled`` and destinations from the defaults and overrides.

    For a command given stored results, which do not record which tree was
    scanned: ``ash report`` and ``ash merge``. ``resolve_config`` holds a config
    file to the repository's rules when the file is inside a git checkout or the
    working directory, but a ``--config`` (or, for ``ash report``, ``ASH_CONFIG``)
    file outside both may still be the scanned tree's own ``.ash/.ash.yaml``, as
    when CI scans a directory and reports or merges from another. Here ``files`` are held to those rules for the
    reporters ``REPORTER_DESTINATION_OPTIONS`` and ``REPORTER_ENABLED_DEFAULTS``
    list, with ``source`` naming why and the fix in the warning. The trusted base
    is ASH's defaults with the reporter overrides replayed onto it, so an override
    still turns a reporter on and aims it. The files' other settings, a local
    reporter's options among them, are kept.

    The record ``confine_declared_reporter_destinations`` reads is replaced, so a
    reporter a plugin module declares is held to the same base. A file
    ``resolve_config`` already held stays named, with the section spellings it
    recorded.
    """
    from automated_security_helper.config.ash_config import AshConfig

    if not files:
        return
    already = list(config._in_tree_config_files)
    written = config._in_tree_reporter_keys
    confine_reporter_destinations(
        config,
        AshConfig(),
        config_overrides,
        [*already, *(path for path in files if path not in already)],
        source=source,
    )
    config._in_tree_reporter_keys = written


def written_reporter_keys(documents: Iterable[Any]) -> Tuple[str, ...]:
    """The keys of the ``reporters`` sections ``documents`` write, in order, once each.

    A workspace project's config has the operator's config merged over it, final
    per field, and a section both write is kept under the operator's spelling
    (``config_sources.deep_merge``). A warning names the project's file, so it
    quotes the section under the spelling that file wrote (``_quoted``).
    """
    keys: List[str] = []
    for document in documents:
        reporters = document.get("reporters") if isinstance(document, dict) else None
        if not isinstance(reporters, dict):
            continue
        for key in reporters:
            if isinstance(key, str) and key not in keys:
                keys.append(key)
    return tuple(keys)


def _quoted(key: str, plugin: str, written: Sequence[str]) -> str:
    """``key``, the confined config's section for ``plugin``, as a file not the
    operator's wrote it: ``key`` itself when such a file wrote it or none wrote a
    section the lookup reads for ``plugin``, else the first such spelling."""
    from automated_security_helper.config.ash_config import (
        plugin_key_lookup_names,
        reduced_plugin_name,
    )

    if key in written:
        return key
    reduced = reduced_plugin_name(plugin)
    return next(
        (
            spelling
            for spelling in written
            if reduced in plugin_key_lookup_names(spelling)
        ),
        key,
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
    """Set each reporter's ``destinations`` options, and the ``enabled`` of each
    reporter of ``enabled_defaults``, to the trusted base's, with one warning."""
    ignored = _confine_options(
        config,
        trusted_config,
        destinations,
        fill_missing=source.fills_missing_sections,
    )
    ignored.extend(_confine_enabled(config, trusted_config, enabled_defaults))
    if not ignored:
        return
    files = ", ".join(describe_config_path(path) for path in in_tree)
    ASH_LOGGER.warning(
        f"Ignoring {', '.join(ignored)} from {files}: {source.reason}, and these "
        "options choose whether findings are sent, where they are sent or written, "
        f"and which credentials send them. {source.remedy}"
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
    fill_missing: bool = True,
) -> List[str]:
    """Set each reporter's ``destinations`` options to the trusted base's.

    An option is matched under every mix of ``-`` and ``_`` in its name, since a
    config merge reads them as the same key (``config_sources._resolve_dict_key``):
    each spelling the config writes is replaced by the spellings the trusted base
    writes, with their values. With ``fill_missing``
    (``UntrustedSource.fills_missing_sections``), a config with no section for a
    reporter gets one holding the trusted base's values, where it sets any: a
    file that replaces the operator's config and leaves the section out would
    otherwise drop them. Returns the spellings the config set to a value the
    trusted base does not give them, as dotted keys, each under the section
    spelling the files not the operator's wrote (``_quoted``).
    """
    extras = config.reporters.__pydantic_extra__
    ignored: List[str] = []
    if extras is None:
        return ignored
    tree_keys = config._in_tree_reporter_keys
    for plugin, option_names in destinations.items():
        trusted_section = _as_dict(trusted_config.get_plugin_config("reporter", plugin))
        trusted_options = dict((trusted_section or {}).get("options") or {})
        keys = _sections_of(config, plugin)
        if not keys:
            if not fill_missing:
                continue
            kept = {
                spelling: trusted_options[spelling]
                for name in option_names
                for spelling in _spellings(trusted_options, name)
            }
            if kept:
                extras[plugin] = {"options": kept}
            continue
        for key in keys:
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
                        section_key = _quoted(key, plugin, tree_keys)
                        ignored.append(f"reporters.{section_key}.options.{spelling}")
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
) -> List[str]:
    """Give each reporter of ``enabled_defaults`` the trusted base's ``enabled``.

    In both directions: the config being confined neither turns one of these
    reporters on nor turns one off. The wanted value is the trusted base's as
    the reporter reads it (``_reads_as_off``), or the reporter's default where
    the trusted base sets none. Each of ``config``'s sections the lookup reads
    is given it, and the key of each whose ``enabled`` the reporter reads
    differently, or would refuse, is returned. A section that writes no
    ``enabled`` is set only where the reporter's default differs from the wanted
    value, and a config with no section for the reporter gets one in that case.
    A key is returned under the section spelling the files not the operator's
    wrote (``_quoted``).
    """
    extras = config.reporters.__pydantic_extra__
    ignored: List[str] = []
    if extras is None:
        return ignored
    tree_keys = config._in_tree_reporter_keys
    for plugin, default in enabled_defaults.items():
        trusted_section = _as_dict(trusted_config.get_plugin_config("reporter", plugin))
        wanted = not _reads_as_off((trusted_section or {}).get("enabled", default))
        keys = _sections_of(config, plugin)
        if not keys and _reads_as_off(default) == wanted:
            extras[plugin] = {"enabled": wanted}
        for key in keys:
            section = _as_section(extras[key])
            current = section.get("enabled", _MISSING)
            if current is _MISSING:
                if _reads_as_off(default) != wanted:
                    continue
            elif current is wanted:
                continue
            elif _reads_as(current) != wanted:
                ignored.append(f"reporters.{_quoted(key, plugin, tree_keys)}.enabled")
            section["enabled"] = wanted
            extras[key] = section
    return ignored
