# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner's own config file, and which part of it the tool uses, come from the operator.

Why this exists
---------------
bandit, grype and syft each read a config file of their own, and that file can
leave findings out: bandit's ``skips`` and ``exclude_dirs``, grype's ``ignore``
and ``only-fixed``, syft's ``exclude``. opengrep's and semgrep's ``config``
chooses the rules they run, from the registry, a URL the tool fetches, or a
path it reads (opengrep's ``patterns`` replaces them all), and their
``metrics`` whether they send usage data; ``metrics: off`` only narrows that, so
any config may set it (``TIGHTENING_VALUES``). ASH used to find such a file by
name in the source directory (``.bandit``, ``bandit.yaml``, ``.grype.yaml``,
``.syft.yaml`` and others), and took ``scanners.<name>.options.config_file``
from whatever config the repository carried. So the repository being scanned
chose what its own scan reported. A repository's tool configs are now ignored
unless the operator sets them, as checkov's and ferret-scan's already are
(``config/path_trust.py``).

ferret-scan's ``profile`` and ``use_default_config`` are the same kind of choice
made a different way: they pick which part of the config ASH passes ferret-scan is
used. With ferret-scan 2.5.3 on one set of test files, the bundled config reported
111 findings, its ``quick`` profile 30 and six of its profiles none; ``redaction``
and ``secure-redaction`` also have ferret-scan write redacted copies of the files
it scans into its working directory. ``use_default_config: false`` swaps the
bundled config for an empty one, which leaves out findings the bundled config's
validators report.

snyk-code's ``honor_tree_exclusions`` is the third kind. ``snyk code test`` reads
the ``.snyk`` and ``.dcignore`` files in the tree it tests and leaves out the
files they name, with no option to stop it, so the scanner does not run on a tree
that has one (``ash_snyk_plugins/snyk_code_scanner.tree_exclusion_files``) unless
this option, the operator's, accepts them.

What happens now
----------------
* When the config was built from a file inside the scanned tree, or from a file
  an MCP client delivered, ``config_file`` of each scanner in
  ``SCANNER_CONFIG_FILE_OPTIONS``, and each option in
  ``SCANNER_CONFIG_CHOICE_OPTIONS``, comes from the trusted base ``resolve_config``
  builds (the defaults, or an operator config outside the tree), with
  ``--config-overrides`` replayed onto it (``confine_scanner_config_files``). An
  operator who wants a repository's own file names it with
  ``--config-overrides``; that path is used even inside the tree, because the
  operator chose it. Under the MCP server the default ``denied_paths`` refuse a
  client's file that names one, and the overrides ``resolve_config`` is handed
  there are the client's, so none is replayed.
* The scanners no longer look for a config file by name.
* Each of them hands its tool an explicit config, the operator's or an empty one
  ASH writes outside the scanned tree (``empty_tool_config``), so the tool does
  not pick a file up from the tree on its own either (see each scanner's
  ``_process_config_options``).

The same rule as reporter destinations (``config/reporter_trust.py``), which this
follows.

Failure modes and known limitations
-----------------------------------
* A repository that relied on its own file now scans without it, and the scan's
  warnings name the option that was ignored. The CHANGELOG says how to keep it:
  name the file with ``--config-overrides`` or in an operator config.
* checkov's and ferret-scan's ``config_file``, detect-secrets' ``baseline_file``
  and ``file://`` plugins and filters, and trivy-repo's ``ignore_file`` and
  ``secret_config_file`` are covered here too, for a file outside the tree;
  ``config/path_trust.py`` still refuses one inside the tree whoever names it.
  A baseline or tool config the scanner finds by name in the tree is
  ``path_trust``'s, not this module's.
* ferret-scan's ``checks``, ``confidence_levels`` and ``exclude_patterns`` still
  apply from a repository's config, as other scanners' own filter options do:
  they are ASH options the config states, not a choice inside the tool's config.
  Under the MCP server ``checks`` and ``confidence_levels`` are default
  ``denied_paths`` entries, and an ``exclude_patterns`` entry a client's config
  adds is reported rather than applied (``config/client_scanner_exclusions.py``).
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Sequence, Tuple

from automated_security_helper.config.untrusted_source import (
    IN_TREE_OR_DELIVERED,
    UntrustedSource,
)
from automated_security_helper.utils.log import ASH_LOGGER

if TYPE_CHECKING:
    from automated_security_helper.config.ash_config import AshConfig

#: Scanners whose own config is the operator's choice, and the options that set
#: it: bandit's, grype's and syft's config file, the rules opengrep and semgrep
#: run (``config``: a registry entry, a URL or a path, fetched or read by the
#: tool; opengrep's ``patterns``, run in place of every rule config) and whether
#: they send usage metrics (``metrics``).
SCANNER_CONFIG_FILE_OPTIONS: Dict[str, Tuple[str, ...]] = {
    "bandit": ("config_file",),
    "grype": ("config_file",),
    "syft": ("config_file",),
    "opengrep": ("config", "metrics", "patterns"),
    "semgrep": ("config", "metrics"),
    # Files the tool reads that config/path_trust.py refuses inside the scanned
    # tree. A file outside it is the operator's to name, not the repository's.
    "checkov": ("config_file",),
    "ferret-scan": ("config_file",),
    "detect-secrets": ("baseline_file",),
    "trivy-repo": ("ignore_file", "secret_config_file"),
}

#: Values of a confined option that only narrow what the tool does, so a
#: repository's or a client's config may still set them: opengrep and semgrep
#: with ``metrics: off`` send no usage data.
TIGHTENING_VALUES: Dict[Tuple[str, str], Tuple[Any, ...]] = {
    ("opengrep", "metrics"): ("off",),
    ("semgrep", "metrics"): ("off",),
}

#: detect-secrets ``scan_settings`` lists whose entries may name a file the
#: worker loads code from (``file://<path>``).
_SETTINGS_FILE_LISTS: Tuple[str, ...] = ("plugins_used", "filters_used")

#: Options that choose which part of a scanner's own config the tool uses, or
#: whether it applies the exclusion files it reads from the tree itself, each
#: with its default, which is what applies when the operator sets nothing.
SCANNER_CONFIG_CHOICE_OPTIONS: Dict[str, Dict[str, Any]] = {
    "ferret-scan": {"profile": None, "use_default_config": True},
    "snyk-code": {"honor_tree_exclusions": False},
}

_MISSING = object()


def _confined_options() -> Dict[str, Dict[str, Any]]:
    confined: Dict[str, Dict[str, Any]] = {
        scanner: dict.fromkeys(names)
        for scanner, names in SCANNER_CONFIG_FILE_OPTIONS.items()
    }
    for scanner, defaults in SCANNER_CONFIG_CHOICE_OPTIONS.items():
        confined.setdefault(scanner, {}).update(defaults)
    return confined


def _trusted_option(options: Any, name: str) -> Any:
    """``options[name]`` under either spelling of the key, as a plugin section holds it.

    A plugin scanner's section is a plain dict, so an override written
    ``ignore-file`` stays spelled that way after it is replayed.
    """
    from automated_security_helper.config.config_sources import _resolve_dict_key

    if not isinstance(options, dict):
        return _MISSING
    return options.get(_resolve_dict_key(options, name), _MISSING)


def _or_default(value: Any, default: Any) -> Any:
    return default if value is _MISSING or value is None else value


def _options_of(section: Any) -> Any:
    if isinstance(section, dict):
        options = section.get("options")
        return options if isinstance(options, dict) else None
    return getattr(section, "options", None)


def _get(options: Any, name: str) -> Any:
    if isinstance(options, dict):
        return options.get(name, _MISSING)
    return getattr(options, name, _MISSING)


def _set(options: Any, name: str, value: Any, default: Any) -> None:
    if isinstance(options, dict):
        if value is _MISSING:
            options.pop(name, None)
        else:
            options[name] = value
    else:
        setattr(options, name, _or_default(value, default))


def confine_scanner_config_files(
    config: "AshConfig",
    trusted_config: "AshConfig",
    config_overrides: Optional[Sequence[str]],
    in_tree: Sequence[Path],
    source: UntrustedSource = IN_TREE_OR_DELIVERED,
) -> None:
    """Replace the tool config choices an in-tree or delivered file made with the trusted base's.

    Args:
        config: The resolved AshConfig, changed in place.
        trusted_config: The trusted base ``resolve_config`` built for the sandbox
            settings: the defaults, or the operator's config outside the tree.
        config_overrides: ``--config-overrides``. Those under ``scanners`` are
            replayed onto ``trusted_config``, as the reporter overrides are in
            ``confine_reporter_destinations``, so an override still sets these.
        in_tree: The config files inside the tree, named in the warning.
        source: Why those files are not the operator's, and the fix, for the
            warning.
    """
    from automated_security_helper.config.client_scanner_exclusions import (
        _scanner_sections,
    )
    from automated_security_helper.config.config_sources import describe_config_path
    from automated_security_helper.config.resolve_config import (
        apply_config_overrides,
    )

    scanner_overrides = [
        override
        for override in config_overrides or []
        if override.partition("=")[0].removesuffix("+").strip().split(".")[0]
        == "scanners"
    ]
    if scanner_overrides:
        trusted_config = apply_config_overrides(trusted_config, scanner_overrides)

    ignored: List[str] = []
    for scanner, option_defaults in _confined_options().items():
        trusted_section = trusted_config.get_plugin_config("scanner", scanner)
        trusted_options = (trusted_section or {}).get("options") or {}
        for key, section in _scanner_sections(config, scanner):
            options = _options_of(section)
            if options is None:
                continue
            for name, default in option_defaults.items():
                wanted = _trusted_option(trusted_options, name)
                written = _get(options, name)
                current = _or_default(written, default)
                if current in TIGHTENING_VALUES.get((scanner, name), ()):
                    continue
                if current == _or_default(wanted, default):
                    if written is None and default is not None:
                        # An explicit null reads as the default here, but the
                        # plugin would get None; give it the trusted value.
                        _set(options, name, wanted, default)
                    continue
                if current != default:
                    ignored.append(f"scanners.{key}.options.{name}")
                _set(options, name, wanted, default)
    ignored.extend(_confine_settings_files(config, trusted_config))
    if ignored:
        files = ", ".join(describe_config_path(path) for path in in_tree)
        ASH_LOGGER.warning(
            f"Ignoring {', '.join(sorted(set(ignored)))} from {files}: these choose "
            "a scanner's own configuration, which is the operator's choice, and "
            f"{source.reason}. Set them with {source.remedy}."
        )


def _entry_path(entry: Any) -> Any:
    if isinstance(entry, dict):
        return entry.get("path")
    return getattr(entry, "path", None)


def _entry_dump(entry: Any) -> Any:
    if hasattr(entry, "model_dump"):
        return entry.model_dump(mode="json", exclude_none=True)
    return {k: v for k, v in dict(entry).items() if v is not None}


def _confine_settings_files(
    config: "AshConfig", trusted_config: "AshConfig"
) -> List[str]:
    """Drop the detect-secrets ``file://`` plugins and filters the trusted base lacks.

    detect-secrets loads a plugin or filter named ``file://<path>`` from that
    file. ``config/path_trust.py`` refuses such a file inside the scanned tree;
    one outside it is the operator's to name, so an entry the trusted base
    (``--config-overrides`` replayed) does not have is dropped. Entries that
    name one of detect-secrets' own plugins are left alone.
    """
    from automated_security_helper.config.client_scanner_exclusions import (
        _scanner_sections,
    )

    trusted_section = trusted_config.get_plugin_config("scanner", "detect-secrets")
    trusted_settings = ((trusted_section or {}).get("options") or {}).get(
        "scan_settings"
    ) or {}
    ignored: List[str] = []
    for key, section in _scanner_sections(config, "detect-secrets"):
        options = _options_of(section)
        if options is None:
            continue
        settings = _get(options, "scan_settings")
        if settings in (_MISSING, None):
            continue
        for list_name in _SETTINGS_FILE_LISTS:
            entries = (
                settings.get(list_name)
                if isinstance(settings, dict)
                else getattr(settings, list_name, None)
            )
            if not entries:
                continue
            trusted_entries = [
                _entry_dump(entry)
                for entry in (
                    trusted_settings.get(list_name)
                    if isinstance(trusted_settings, dict)
                    else getattr(trusted_settings, list_name, None)
                )
                or []
            ]
            kept = []
            for entry in entries:
                path = _entry_path(entry)
                if (
                    isinstance(path, str)
                    and path.startswith("file://")
                    and _entry_dump(entry) not in trusted_entries
                ):
                    ignored.append(
                        f"scanners.{key}.options.scan_settings.{list_name}[].path"
                    )
                    continue
                kept.append(entry)
            if len(kept) != len(entries):
                if isinstance(settings, dict):
                    settings[list_name] = kept
                else:
                    setattr(settings, list_name, kept)
    return ignored


def empty_tool_config(name: str, content: str, *, context: Any) -> Path:
    """A config file that sets nothing, for a tool that would otherwise find its own.

    Handed to a tool that would otherwise look for its config file in its
    working directory or under the scan target on its own. Written in the
    scanner run's own directory outside the scanned tree, created fresh and
    removed when the run ends (``utils/tool_config_dir``), never in the results
    directory, which is inside the tree in the default layout.

    Args:
        name: The file's name (``grype-empty.yaml``); the tool may read its
            format from the extension.
        content: What the file holds, which sets nothing for that tool.
        context: The scanner's PluginContext, whose scanned tree the file is
            kept out of.
    """
    from automated_security_helper.utils.tool_config_dir import write_tool_config

    return write_tool_config(name, content, context=context)
