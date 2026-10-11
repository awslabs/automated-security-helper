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
``denied_paths``. Other options of these reporters (``enabled``, formatting, model
parameters) still apply from the tree.
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

from automated_security_helper.config.config_sources import describe_config_path
from automated_security_helper.utils.log import ASH_LOGGER

if TYPE_CHECKING:
    from automated_security_helper.config.ash_config import AshConfig

#: The options of each built-in reporter that pick where findings go or which
#: credentials send them: each reporter's ``destination_options``. Where each is
#: used is listed in the PR that added this.
REPORTER_DESTINATION_OPTIONS: Dict[str, Tuple[str, ...]] = {
    "aws-security-hub": ("aws_region", "aws_profile", "account_id"),
    "bedrock-summary-reporter": (
        "aws_region",
        "aws_profile",
        "model_id",
        "output_file",
        "output_executive_file",
        "output_technical_file",
    ),
    "cloudwatch-logs": ("aws_region", "log_group_name", "log_stream_name"),
    "s3": ("aws_region", "aws_profile", "bucket_name", "key_prefix"),
}

_MISSING = object()


def _as_dict(section: Any) -> Optional[Dict[str, Any]]:
    if isinstance(section, dict):
        return dict(section)
    if hasattr(section, "model_dump"):
        return section.model_dump(by_alias=True)
    return None


def confine_reporter_destinations(
    config: "AshConfig",
    trusted_config: "AshConfig",
    config_overrides: Optional[Sequence[str]],
    in_tree: Sequence[Path],
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
    _confine(config, trusted_config, REPORTER_DESTINATION_OPTIONS, in_tree)


def confine_declared_reporter_destinations(
    config: "AshConfig", reporter_classes: Iterable[type]
) -> None:
    """Apply ``confine_reporter_destinations`` to the options loaded reporters declare.

    For the reporters a plugin module adds, which ``resolve_config`` cannot see.
    Call it once the plugin modules are imported and before any reporter is built.
    Does nothing for a config with no file inside the tree, and repeats nothing
    already done for a built-in reporter: its options already hold the trusted
    base's values.

    Args:
        config: The config ``resolve_config`` returned, changed in place.
        reporter_classes: The reporter classes the plugin manager loaded.
    """
    from automated_security_helper.config.ash_config import AshConfig

    if not isinstance(config, AshConfig):
        return
    trusted_config = config._trusted_reporter_base
    if trusted_config is None:
        return
    _confine(
        config,
        trusted_config,
        declared_destination_options(reporter_classes),
        config._in_tree_config_files,
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


def _aliases(reporter_class: type, option: str) -> List[str]:
    """The aliases of field ``option`` in any options model of ``reporter_class``'s config."""
    import typing

    from pydantic import AliasChoices, BaseModel

    def models(annotation: Any) -> List[type[BaseModel]]:
        found: List[type[BaseModel]] = []
        pending: List[Any] = [annotation]
        while pending:
            item = pending.pop()
            if isinstance(item, type) and issubclass(item, BaseModel):
                found.append(item)
            else:
                pending.extend(typing.get_args(item))
        return found

    config_field = (getattr(reporter_class, "model_fields", None) or {}).get("config")
    if config_field is None:
        return []
    aliases: List[str] = []
    for config_model in models(config_field.annotation):
        options_field = config_model.model_fields.get("options")
        if options_field is None:
            continue
        for options_model in models(options_field.annotation):
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
    in_tree: Sequence[Path],
) -> None:
    """Set each reporter's ``destinations`` options to the trusted base's, with one warning."""
    from automated_security_helper.config.ash_config import (
        plugin_key_lookup_names,
        reduced_plugin_name,
    )

    extras = config.reporters.__pydantic_extra__
    if not extras:
        return
    ignored: List[str] = []
    for plugin, option_names in destinations.items():
        trusted_section = _as_dict(trusted_config.get_plugin_config("reporter", plugin))
        trusted_options = dict((trusted_section or {}).get("options") or {})
        reduced = reduced_plugin_name(plugin)
        for key in list(extras):
            if reduced not in plugin_key_lookup_names(key):
                continue
            section = _as_dict(extras[key])
            if section is None:
                continue
            options = dict(section.get("options") or {})
            changed = False
            for name in option_names:
                wanted = trusted_options.get(name, _MISSING)
                current = options.get(name, _MISSING)
                if current == wanted:
                    continue
                if current is not _MISSING:
                    ignored.append(f"reporters.{key}.options.{name}")
                if wanted is _MISSING:
                    options.pop(name, None)
                else:
                    options[name] = wanted
                changed = True
            if changed:
                section["options"] = options
                extras[key] = section
    if not ignored:
        return
    files = ", ".join(describe_config_path(path) for path in in_tree)
    ASH_LOGGER.warning(
        f"Ignoring {', '.join(ignored)} from {files}: that config is inside the "
        "scanned tree or was delivered by an MCP client, and these options choose "
        "where findings are sent or written and which credentials send them. Set "
        "them with --config-overrides or a config file outside the tree."
    )
