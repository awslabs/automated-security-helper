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
any spelling ``AshConfig.get_plugin_config`` accepts is covered, except a section
named exactly as another loaded reporter, which is that reporter's own. The values
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
base. A reporter that declares no ``destination_options`` and does not send findings
off the host writes only local files, and its ``enabled`` still applies from the
tree. One that does send them is not left out: ``ash report`` and ``ash merge`` take
its whole section from the defaults and the overrides (below). Under the MCP server
the default ``denied_paths`` also refuse a client's file that turns a built-in AWS reporter on,
and every other setting of its section. A client's ``enabled: false`` is not
refused there, in a delivered file (``client_config_policy._writes_a_tightening``)
or in its runtime overrides (``runtime_patch._turns_an_off_host_reporter_off``),
but it takes no effect: the confinement above replaces it. The reporters' other
options (formatting, model parameters) still apply from the tree.

``ash report`` and ``ash merge`` read stored results, which do not record which tree
was scanned, so for them every config file they are given is held to this rule
(``confine_off_host_reporters_to_overrides``). A reporter that sends findings off the
host is built from ``reporter_section``, which gives it the operator view that
``resolve_config`` recorded (``AshConfig._operator_reporters``) instead of
``reporters``; a ``--config`` file outside every tree that extends a file inside one
is in that view. The rule therefore applies to the view as well, and the section the
reporter is built from is already the confined one. An ``options`` value that is not
a mapping holds no destination and is replaced like one. A reporter that sends
findings off the host and declares no ``destination_options`` cannot say which of
its options name where it sends, so the whole of its section comes from the defaults
and the overrides, ``enabled`` included. A scan keeps its operator view as it is: the
view holds what the operator's own chain files wrote, which the trusted base does not.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Collection,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
)

from pydantic import BaseModel

from automated_security_helper.config.sandbox_grants import described
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
        *_RETRY_OPTIONS,
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


def _options_of(section: Mapping[str, Any]) -> Dict[str, Any]:
    """The ``options`` of a reporter section as a mapping; a value of another kind as empty.

    A reporter's options model takes a mapping, so an ``options`` value of any
    other kind (a string, a list, a number) names no option and no destination.
    """
    options = section.get("options")
    return dict(options) if isinstance(options, dict) else {}


def _options_malformed(section: Mapping[str, Any]) -> bool:
    """Whether ``section`` has an ``options`` value that is set and is not a mapping."""
    options = section.get("options")
    return options is not None and not isinstance(options, dict)


def confine_reporter_destinations(
    config: "AshConfig",
    trusted_config: "AshConfig",
    config_overrides: Optional[Sequence[str]],
    in_tree: Sequence[Path],
    source: UntrustedSource = IN_TREE_OR_DELIVERED,
    in_tree_documents: Iterable[Any] = (),
    *,
    from_overrides: bool = False,
    in_tree_keys: Sequence[str] = (),
    environment_paths: Collection[Path] = (),
) -> None:
    """Replace the destination options an in-tree file set with the trusted base's.

    Records the files, the reporter section keys they wrote, the trusted base and
    the *source* on ``config`` for ``confine_declared_reporter_destinations``.

    Args:
        config: The resolved AshConfig, changed in place.
        trusted_config: The trusted base ``resolve_config`` built for the sandbox
            settings: the defaults, or the operator's config outside the tree.
        config_overrides: ``--config-overrides``. Those under ``reporters`` are
            replayed onto ``trusted_config``, the same way the sandbox overrides
            are, so an override still sets these options. One that does not
            apply to the trusted base is dropped with a warning, as for the
            operator view (``resolve_config._with_reporter_overrides``); the
            reporters then keep the base's settings for it.
        in_tree: The config files inside the tree, named in the warning.
        source: Why those files are not the operator's, and the fix, for the
            warning.
        in_tree_documents: Those files' documents as they were parsed. The
            warning quotes a section as they spelled it (``written_reporter_keys``).
        from_overrides: The command takes an off-host reporter's settings from the
            defaults and the overrides alone (``ash report``, ``ash merge``). The
            operator view ``resolve_config`` recorded is confined as well, on a
            copy (a view that is not an AshConfig is refused with a TypeError), and
            ``confine_declared_reporter_destinations`` gives a reporter with no
            declared destination options the trusted base's whole section. A
            reporter that sends findings off the host and is on by default takes
            ``enabled`` only from an ``enabled`` the trusted base sets; the file's
            is replaced by ``false`` otherwise.
        in_tree_keys: Section spellings the files wrote that were recorded
            before this call (``config._in_tree_reporter_keys``). They are used
            along with the ones parsed from *in_tree_documents* while the
            warning is built, so a section is quoted as the file wrote it.
        environment_paths: Those of *in_tree* the environment chose (a base an
            ``extends`` entry named with a value read from the environment, and
            every base below it), which the warning names ``<value>``.
    """
    from automated_security_helper.config.resolve_config import (
        _with_reporter_overrides,
    )

    # Read first, so a view of the wrong kind is refused before anything is recorded.
    view = _operator_view(config) if from_overrides else None
    reporter_overrides = [
        override
        for override in config_overrides or []
        if override.partition("=")[0].removesuffix("+").strip().split(".")[0]
        == "reporters"
    ]
    if reporter_overrides:
        # The replay the operator view uses. An override the scan's own apply
        # resolved under the repository's spelling of a section the trusted base
        # spells another way is folded onto the trusted base's key first; without
        # it the replay refuses the only spelling the scan's apply accepted, and
        # the scan cannot run. An override that applied to the resolved config
        # but not to the trusted base is dropped with a warning instead of
        # refusing the whole load.
        trusted_config = _with_reporter_overrides(
            trusted_config, reporter_overrides, config
        )
    config._untrusted_membership_source = source
    config._in_tree_config_files = tuple(in_tree)
    config._trusted_reporter_base = trusted_config
    config._in_tree_reporter_keys = tuple(
        dict.fromkeys([*in_tree_keys, *written_reporter_keys(in_tree_documents)])
    )
    if from_overrides:
        config._reporters_from_overrides = True
        if view is not None:
            # A copy: the scanner views recorded beside it hold the original.
            config._operator_reporters = view.model_copy(deep=True)
    _confine(
        config,
        trusted_config,
        REPORTER_DESTINATION_OPTIONS,
        REPORTER_ENABLED_DEFAULTS,
        in_tree,
        source,
        # The four built-in reporters all send findings off the host.
        off_host=tuple(REPORTER_ENABLED_DEFAULTS),
        environment_paths=environment_paths,
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

    ``reporter_section`` gives an off-host reporter the operator view
    ``resolve_config`` recorded (``AshConfig._operator_reporters``), and a file
    outside every tree that extends one inside is in it. The same rule is applied
    to that view, on a copy, so the section a reporter is built from is already
    the confined one and needs no second read. ``config`` is marked so that
    ``confine_declared_reporter_destinations`` does the same for the reporters a
    plugin module adds, and gives one that declares no destination options the
    trusted base's whole section.
    """
    from automated_security_helper.config.ash_config import AshConfig

    if not files:
        return
    already = list(config._in_tree_config_files)
    confine_reporter_destinations(
        config,
        AshConfig(),
        config_overrides,
        [*already, *(path for path in files if path not in already)],
        source=source,
        from_overrides=True,
        # The spellings ``resolve_config`` recorded are in use while the
        # confinement names what it ignored, and are the ones left afterward.
        in_tree_keys=config._in_tree_reporter_keys,
    )


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
    source: Optional[UntrustedSource] = None,
) -> None:
    """Apply ``confine_reporter_destinations`` to the options loaded reporters declare.

    For the reporters a plugin module adds, which ``resolve_config`` cannot see:
    their declared options, and ``enabled`` of each that declares any. Call it
    once the plugin modules are imported and before any reporter is built. Does
    nothing for a config with no file inside the tree, and repeats nothing
    already done for a built-in reporter: its options already hold the trusted
    base's values.

    For a config ``confine_off_host_reporters_to_overrides`` handled, the operator
    view is confined too, and a reporter that sends findings off the host and
    declares no destination options is given the trusted base's whole section.

    Args:
        config: The config ``resolve_config`` returned, changed in place.
        reporter_classes: The reporter classes the plugin manager loaded.
        source: As for ``confine_reporter_destinations``; ``ash merge`` passes
            the one it passed there. With none, the source recorded on ``config``
            beside the record this step confines by
            (``AshConfig._untrusted_membership_source``), so it speaks as the
            last call of ``confine_reporter_destinations`` did: the sentence and
            remedy for a file whose name walk stopped before the end, the
            command's own source for ``ash report``, otherwise
            ``IN_TREE_OR_DELIVERED``.
    """
    from automated_security_helper.base.plugin_config import plugin_config_key
    from automated_security_helper.config.ash_config import AshConfig

    if not isinstance(config, AshConfig):
        return
    trusted_config = config._trusted_reporter_base
    if trusted_config is None:
        return
    if source is None:
        source = config._untrusted_membership_source or IN_TREE_OR_DELIVERED
    reporter_classes = list(reporter_classes)
    _confine(
        config,
        trusted_config,
        declared_destination_options(reporter_classes),
        declared_enabled_defaults(reporter_classes),
        config._in_tree_config_files,
        source,
        # Only where the command takes an off-host reporter's settings from the
        # overrides alone: a scan builds such a reporter from its operator view.
        whole_sections=(
            declared_off_host_sections(reporter_classes)
            if config._reporters_from_overrides
            else ()
        ),
        off_host=declared_off_host_reporters(reporter_classes),
        reporters=[plugin_config_key(reporter) for reporter in reporter_classes],
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


def declared_off_host_sections(reporter_classes: Iterable[type]) -> Tuple[str, ...]:
    """The names, as ``plugin_config_key`` gives them, of the off-host reporters that list no destinations.

    A reporter that sets ``sends_off_host`` and declares no ``destination_options``
    sends findings off the host, but nothing says which of its options name where.
    Its whole section is the operator's (``operator_only_options``), so a command
    that takes an off-host reporter's settings from the overrides takes all of
    this section from them.
    """
    from automated_security_helper.base.plugin_config import plugin_config_key

    found: List[str] = []
    for reporter_class in reporter_classes:
        if getattr(reporter_class, "sends_off_host", False) is not True:
            continue
        if declared_destination_options([reporter_class]):
            continue
        key = plugin_config_key(reporter_class)
        if key not in found:
            found.append(key)
    return tuple(found)


def declared_off_host_reporters(reporter_classes: Iterable[type]) -> Tuple[str, ...]:
    """The names, as ``plugin_config_key`` gives them, of the reporters that send findings off the host.

    Whether or not they declare destination options. ``_confine_enabled`` holds
    only these to the opt-in: a reporter that writes only local files is not.
    """
    from automated_security_helper.base.plugin_config import plugin_config_key

    found: List[str] = []
    for reporter_class in reporter_classes:
        if getattr(reporter_class, "sends_off_host", False) is not True:
            continue
        key = plugin_config_key(reporter_class)
        if key not in found:
            found.append(key)
    return tuple(found)


def declared_enabled_defaults(reporter_classes: Iterable[type]) -> Dict[str, bool]:
    """Each reporter's default for ``enabled``, by the name its config is under.

    Only the reporters that declare ``destination_options``: one that declares
    none and sends nothing off the host writes only local files, so whether it
    runs is not a choice of where findings go. (One that declares none and does
    send findings off the host is covered by ``declared_off_host_sections``
    instead, for the commands that take such a reporter's section from the
    overrides.) The default is the one the reporter's own config model gives
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
    """The aliases of field ``option`` in any options model of ``reporter_class``'s config.

    An ``AliasPath`` is listed by its first key: pydantic reads the field from the
    value nested under that key, so a config that writes the key sets the option.
    """
    from pydantic import AliasChoices, AliasPath

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
                if isinstance(alias, AliasPath):
                    alias = alias.path[0] if alias.path else None
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
    whole_sections: Sequence[str] = (),
    off_host: Collection[str] = (),
    environment_paths: Collection[Path] = (),
    reporters: Collection[str] = (),
) -> None:
    """Set each reporter's ``destinations`` options, and the ``enabled`` of each
    reporter of ``enabled_defaults``, to the trusted base's, with one warning.

    ``reporters`` names every reporter loaded, whether or not it is covered here,
    so that a section named exactly as one is not confined as another's
    (``_sections_of``).

    The whole section of each reporter of ``whole_sections`` is set to the trusted
    base's. For a config ``confine_off_host_reporters_to_overrides`` handled, the
    operator view recorded on it is confined the same way, and what it ignored is
    named once, beside what ``config`` did. ``off_host`` names the reporters of
    ``enabled_defaults`` that send findings off the host: for such a config, only
    these are held to the opt-in (``_confine_enabled``). For every config, they
    are also the reporters that run only for the boolean true
    (``off_host_reporter_refused``), so none is given a true that is not one."""
    targets = [config]
    view = _operator_view(config) if config._reporters_from_overrides else None
    if view is not None:
        targets.append(view)
    ignored: List[str] = []
    replaced: List[str] = []
    # The spellings the files wrote are recorded on ``config`` alone. A copy of the
    # operator view has none of its own, so every target is quoted with these.
    tree_keys = config._in_tree_reporter_keys
    # A section named exactly as one of these is that reporter's own, whatever
    # another reporter's lookup could read.
    loaded = {
        *reporters,
        *destinations,
        *enabled_defaults,
        *whole_sections,
        *off_host,
    }
    for target in targets:
        found = _confine_options(
            target,
            trusted_config,
            destinations,
            fill_missing=source.fills_missing_sections,
            drop_malformed=config._reporters_from_overrides,
            tree_keys=tree_keys,
            loaded=loaded,
        )
        found.extend(
            _confine_enabled(
                target,
                trusted_config,
                enabled_defaults,
                off_host=off_host if config._reporters_from_overrides else (),
                tree_keys=tree_keys,
                fill_missing=source.fills_missing_sections,
                requires_true=off_host,
                loaded=loaded,
            )
        )
        found.extend(
            _confine_whole_sections(
                target,
                trusted_config,
                whole_sections,
                replaced,
                tree_keys,
                loaded=loaded,
            )
        )
        named = list(ignored)
        ignored.extend(key for key in found if key not in named)
    if not ignored:
        return
    # A file reached through a value read from the environment is named
    # ``<value>``, as the other confinement warnings name it: the path holds the
    # value. The paths recorded on ``config`` after this step ran
    # (record_operator_reporters) count too, for a later call of this function.
    files = described(
        in_tree, {*environment_paths, *config._repository_config_environment_paths}
    )
    ASH_LOGGER.warning(
        f"Ignoring {', '.join(ignored)} from {files}: {source.reason}, and these "
        "options choose whether findings are sent, where they are sent or written, "
        f"and which credentials send them. {source.remedy}"
    )
    # A reporter whose whole section was replaced above has been named, with this
    # source's remedy. Building it reads the section again, finds the config's
    # now-empty one outside the operator's view, and would name it a second time
    # with the remedy for a scan, which ``ash report`` and ``ash merge`` do not
    # honor (``reporter_section``).
    for plugin in replaced:
        if plugin not in config._off_host_sections_warned:
            config._off_host_sections_warned.append(plugin)


def _operator_view(config: "AshConfig") -> Optional["AshConfig"]:
    """The operator view recorded on ``config``, or None for a config that is the operator's own.

    ``record_operator_reporters`` records an AshConfig, together with the scanner
    views for it. An object of another kind is a programming error, so it is
    refused by name. Reading it as "no view" would give ``None`` a second
    meaning (this config is trusted) while the scanner views recorded beside it
    stayed set.
    """
    from automated_security_helper.config.ash_config import AshConfig

    view = config._operator_reporters
    if view is None or isinstance(view, AshConfig):
        return view
    raise TypeError(
        f"the operator view recorded on the config is a {type(view).__name__}, "
        "not an AshConfig"
    )


def _sections_of(
    config: "AshConfig", plugin: str, loaded: Collection[str] = ()
) -> List[str]:
    """The keys of ``config``'s reporter sections that ``plugin``'s lookup reads.

    A key named exactly as another reporter of *loaded* is that reporter's own
    section, which its lookup reads by that name, so it is left out even when both
    names reduce to the same string (``bedrock-summary`` and
    ``bedrock-summary-reporter``). Confining it as ``plugin``'s would replace the
    other reporter's options and ``enabled`` with ``plugin``'s.
    """
    from automated_security_helper.config.ash_config import (
        plugin_key_lookup_names,
        reduced_plugin_name,
    )

    reduced = reduced_plugin_name(plugin)
    extras = config.reporters.__pydantic_extra__ or {}
    return [
        key
        for key in extras
        if reduced in plugin_key_lookup_names(key)
        and (key == plugin or key not in loaded)
    ]


def _confine_options(
    config: "AshConfig",
    trusted_config: "AshConfig",
    destinations: Mapping[str, Sequence[str]],
    fill_missing: bool = True,
    drop_malformed: bool = False,
    tree_keys: Optional[Sequence[str]] = None,
    loaded: Collection[str] = (),
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
    spelling the files not the operator's wrote (``_quoted``). A spelling that
    holds the value the trusted base gives under its other spelling of the name
    is rewritten to the base's spelling and not returned.

    An ``options`` value that is not a mapping holds no option, so it reads as
    empty, and no error is raised for it. With ``drop_malformed`` it is replaced
    by the mapping of the trusted base's options and named in the return value
    (``reporters.<section>.options``), so none of what it held survives in the
    section. Without it the section is left as written, whatever the trusted base
    sets, so a reporter built from this section meets the value in its model,
    which refuses it. A reporter that sends findings off the host is built from
    the operator view when one is recorded (``reporter_section``), and does not
    read this section.

    *tree_keys* are the section spellings the files wrote (``_quoted``); by
    default the ones recorded on *config*. *loaded* names the reporters whose own
    sections are not another's (``_sections_of``).
    """
    extras = config.reporters.__pydantic_extra__
    ignored: List[str] = []
    if extras is None:
        return ignored
    if tree_keys is None:
        tree_keys = config._in_tree_reporter_keys
    for plugin, option_names in destinations.items():
        trusted_section = _as_dict(trusted_config.get_plugin_config("reporter", plugin))
        trusted_options = _options_of(trusted_section or {})
        keys = _sections_of(config, plugin, loaded)
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
            options = _options_of(section)
            changed = False
            if _options_malformed(section):
                if not drop_malformed:
                    # Left as written, whatever the base sets: a reporter built
                    # from this section is refused by its model, and no
                    # destination can be kept in it.
                    continue
                ignored.append(f"reporters.{_quoted(key, plugin, tree_keys)}.options")
                changed = True
            for name in option_names:
                written = _spellings(options, name)
                wanted = {
                    k: trusted_options[k] for k in _spellings(trusted_options, name)
                }
                if {k: options[k] for k in written} == wanted:
                    continue
                for spelling in written:
                    if not _holds_base_value(options[spelling], spelling, wanted):
                        section_key = _quoted(key, plugin, tree_keys)
                        ignored.append(f"reporters.{section_key}.options.{spelling}")
                    options.pop(spelling)
                options.update(wanted)
                changed = True
            if changed:
                section["options"] = options
                extras[key] = section
    return ignored


def _confine_whole_sections(
    config: "AshConfig",
    trusted_config: "AshConfig",
    plugins: Sequence[str],
    replaced: Optional[List[str]] = None,
    tree_keys: Optional[Sequence[str]] = None,
    loaded: Collection[str] = (),
) -> List[str]:
    """Give each reporter of ``plugins`` the trusted base's whole section.

    For the reporters that send findings off the host and list no destination
    options: nothing says which of their options name where they send, so none of
    the section is the config's to choose, ``enabled`` included. Each of
    ``config``'s sections the lookup reads is replaced by a copy of the trusted
    base's section for the reporter, or by an empty one where the trusted base
    has none (an off-host reporter then does not run: ``off_host_reporter_refused``).
    A section already equal to it is left as it is. Returns the keys replaced, as
    ``reporters.<section>``, under the spelling the files not the operator's wrote
    (``_quoted``). The names of the reporters it replaced a section of are added to
    ``replaced`` when given. *tree_keys* are the section spellings the files wrote;
    by default the ones recorded on *config*. *loaded* names the reporters whose
    own sections are not another's (``_sections_of``).
    """
    extras = config.reporters.__pydantic_extra__
    ignored: List[str] = []
    if extras is None:
        return ignored
    if tree_keys is None:
        tree_keys = config._in_tree_reporter_keys
    for plugin in plugins:
        wanted = _as_dict(trusted_config.get_plugin_config("reporter", plugin)) or {}
        for key in _sections_of(config, plugin, loaded):
            if _as_section(extras[key]) == wanted:
                continue
            ignored.append(f"reporters.{_quoted(key, plugin, tree_keys)}")
            extras[key] = copy.deepcopy(wanted)
            if replaced is not None and plugin not in replaced:
                replaced.append(plugin)
    return ignored


def _spellings(options: Mapping[Any, Any], name: str) -> List[str]:
    """The keys of ``options`` that are ``name`` with ``-`` and ``_`` folded."""
    folded = name.replace("-", "_")
    return [
        key
        for key in options
        if isinstance(key, str) and key.replace("-", "_") == folded
    ]


def _holds_base_value(value: Any, spelling: str, wanted: Mapping[str, Any]) -> bool:
    """Whether ``value``, written under ``spelling``, is what the trusted base gives.

    *wanted* maps each spelling of the option that the trusted base writes to its
    value. A config merge reads the ``-`` and ``_`` spellings of a name as one key,
    so a value equal to the base's under its other spelling is the base's value.
    """
    if spelling in wanted:
        return bool(value == wanted[spelling])
    return bool(wanted) and all(value == base for base in wanted.values())


def _confine_enabled(
    config: "AshConfig",
    trusted_config: "AshConfig",
    enabled_defaults: Mapping[str, bool],
    off_host: Collection[str] = (),
    tree_keys: Optional[Sequence[str]] = None,
    fill_missing: bool = True,
    requires_true: Collection[str] = (),
    loaded: Collection[str] = (),
) -> List[str]:
    """Give each reporter of ``enabled_defaults`` the trusted base's ``enabled``.

    In both directions: the config being confined neither turns one of these
    reporters on nor turns one off. The wanted value is the trusted base's as
    the reporter reads it (``_reads_as_off``), or the reporter's default where
    the trusted base sets none. Each of ``config``'s sections the lookup reads
    is given it, and the key of each whose ``enabled`` the reporter reads
    differently, or would refuse, is returned. A section that writes no
    ``enabled`` is set only where the reporter's default differs from the wanted
    value, and a config with no section for the reporter gets one in that case,
    unless *fill_missing* is false (``UntrustedSource.fills_missing_sections``):
    a recorded config that leaves a reporter out is not given a section.
    A key is returned under the section spelling the files not the operator's
    wrote (``_quoted``).

    A reporter of *requires_true* runs only for the boolean true
    (``off_host_reporter_refused``). Where the trusted base's ``enabled`` reads as
    on without being true (``1``, ``"yes"``), the sections are given that value
    itself and not a true: the reporter is refused with the base's own value, as
    it is under the base alone, and the report step names the value's type.

    ``off_host`` (``ash report``, ``ash merge``) names the reporters of
    ``enabled_defaults`` that send findings off the host, for a command that takes
    their settings from the overrides. One of them that is on by default and has
    no ``enabled`` in the trusted base is not given the value its default would
    match. It runs only for an ``enabled: true`` in its section
    (``off_host_reporter_refused``), and the defaults and the overrides set none.
    Giving the section the default would write that ``true`` itself, and keeping a
    file's ``enabled: true`` (it equals the default) would pass it on as the
    operator's word. The file's ``enabled`` is replaced by ``false`` instead, so
    the reporter is refused until an override enables it, and the section does not
    read as one that sets options and leaves ``enabled`` out. Only a file's
    ``enabled`` that the reporter does not already read as ``false`` is returned as
    ignored: a ``false`` stays as it was written. A reporter that is not in
    ``off_host`` keeps the rule above: it writes only local files, so its default
    is not an opt-in.

    *tree_keys* are the section spellings the files wrote; by default the ones
    recorded on *config*. *loaded* names the reporters whose own sections are not
    another's (``_sections_of``).
    """
    extras = config.reporters.__pydantic_extra__
    ignored: List[str] = []
    if extras is None:
        return ignored
    if tree_keys is None:
        tree_keys = config._in_tree_reporter_keys
    for plugin, default in enabled_defaults.items():
        trusted_section = _as_dict(trusted_config.get_plugin_config("reporter", plugin))
        base_enabled = (trusted_section or {}).get("enabled", default)
        wanted = not _reads_as_off(base_enabled)
        given: Any = wanted
        if plugin in requires_true and wanted and base_enabled is not True:
            given = base_enabled
        keys = _sections_of(config, plugin, loaded)
        if fill_missing and not keys and _reads_as_off(default) == wanted:
            extras[plugin] = {"enabled": given}
        for key in keys:
            section = _as_section(extras[key])
            current = section.get("enabled", _MISSING)
            if (
                plugin in off_host
                and wanted
                and "enabled" not in (trusted_section or {})
            ):
                if current is not _MISSING:
                    section["enabled"] = False
                    extras[key] = section
                    if _reads_as(current) is not False:
                        ignored.append(
                            f"reporters.{_quoted(key, plugin, tree_keys)}.enabled"
                        )
                continue
            if current is _MISSING:
                if _reads_as_off(default) != wanted:
                    continue
            elif current is given:
                continue
            elif _reads_as(current) != wanted:
                ignored.append(f"reporters.{_quoted(key, plugin, tree_keys)}.enabled")
            section["enabled"] = given
            extras[key] = section
    return ignored
