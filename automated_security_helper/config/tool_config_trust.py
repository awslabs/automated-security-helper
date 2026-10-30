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

``tool_version``, which every scanner and converter that installs its tool with
uv or pip may have, chooses which release runs: the one uv installs and the one
already on PATH that ASH accepts. A specifier set is the only value accepted from
any source (``base/options.tool_version_constraint``); which one applies is the
operator's choice too, for every scanner and converter section, built in or added
by a plugin module (``confine_tool_versions``). The plugins read the value they
are given, so this one step covers each of them, and a plugin added later is
covered without a gate of its own.

trivy's and trivy-repo's ``disable_telemetry`` decides whether trivy sends
anonymous usage data to its vendor on an online scan. Like opengrep's and semgrep's
``metrics``,
only the value that stops it applies from any config (``TIGHTENING_VALUES``);
``false`` is the operator's.

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
from typing import TYPE_CHECKING, Any, Dict, List, Literal, Optional, Sequence, Tuple

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
#: with ``metrics: off`` send no usage data, and neither do trivy and trivy-repo
#: with ``disable_telemetry: true``. Only a value the file writes counts: a file
#: that leaves the option out keeps the operator's choice.
TIGHTENING_VALUES: Dict[Tuple[str, str], Tuple[Any, ...]] = {
    ("opengrep", "metrics"): ("off",),
    ("semgrep", "metrics"): ("off",),
    ("trivy-repo", "disable_telemetry"): (True,),
    ("trivy", "disable_telemetry"): (True,),
}

#: detect-secrets ``scan_settings`` lists whose entries may name a file the
#: worker loads code from (``file://<path>``).
_SETTINGS_FILE_LISTS: Tuple[str, ...] = ("plugins_used", "filters_used")

#: Options that choose which part of a scanner's own config the tool uses,
#: whether it applies the exclusion files it reads from the tree itself, or
#: whether it sends usage data to its vendor, each with its default, which is
#: what applies when the operator sets nothing.
SCANNER_CONFIG_CHOICE_OPTIONS: Dict[str, Dict[str, Any]] = {
    # respect_gitignore has ferret-scan skip the files the tree's own .gitignore
    # names, so a repository's config could choose which of its files the scan
    # reads; off by default, as the scanner declares it.
    "ferret-scan": {
        "profile": None,
        "use_default_config": True,
        "respect_gitignore": False,
    },
    "snyk-code": {"honor_tree_exclusions": False},
    "trivy-repo": {"disable_telemetry": True},
    "trivy": {"disable_telemetry": True},
}

#: Options of every scanner and converter section, built in or added by a plugin
#: module, that only the operator sets: ``tool_version`` chooses which release of
#: the tool ASH installs and which one already on PATH it accepts
#: (``confine_tool_versions``).
OPERATOR_ONLY_PLUGIN_OPTIONS: Tuple[str, ...] = ("tool_version",)

#: The config sections ``confine_tool_versions`` walks, each with the plugin type
#: ``AshConfig.get_plugin_config`` reads it by.
_PLUGIN_SEGMENTS: Tuple[Tuple[str, Literal["scanner", "converter"]], ...] = (
    ("scanners", "scanner"),
    ("converters", "converter"),
)

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


def _wrote(options: Any, name: str, written: Any) -> bool:
    """Whether the config set ``name`` itself, rather than leaving it to its default.

    A plugin's section is a dict holding only what was written. A built-in
    scanner's options are a model, whose unset fields read as their defaults,
    so its ``model_fields_set`` says which were written.
    """
    if written is _MISSING or written is None:
        return False
    fields_set = getattr(options, "model_fields_set", None)
    return fields_set is None or name in fields_set


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
        # An override the scan's own apply resolved under the repository's
        # spelling of a section the trusted base spells another way is folded
        # onto the trusted base's key first (the lockout fold the scanner view
        # replay uses); without it the replay refuses the only spelling the
        # scan's apply accepted, and the scan cannot run.
        from automated_security_helper.config.resolve_config import (
            _folded_onto_trusted,
        )

        scanner_overrides = _folded_onto_trusted(
            trusted_config, scanner_overrides, config, section="scanners"
        )
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
                if _wrote(options, name, written) and current in TIGHTENING_VALUES.get(
                    (scanner, name), ()
                ):
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
        tail = (
            f"{source.scanner_steps_note}."
            if source.scanner_steps_note
            else source.remedy
        )
        ASH_LOGGER.warning(
            f"Ignoring {', '.join(sorted(set(ignored)))} from {files}: these choose "
            "a scanner's own configuration, which is the operator's choice, and "
            f"{source.reason}. {tail}"
        )


def _plugin_sections(segment: Any) -> List[Tuple[str, Any]]:
    """Every section of a ``scanners`` or ``converters`` segment, by the key a file uses.

    The built-in sections under their alias, then each section a plugin module
    adds (``extra="allow"``), so a plugin ASH does not ship is covered too.
    """
    by_key = {
        (field.alias or name): name
        for name, field in type(segment).model_fields.items()
    }
    extra = getattr(segment, "__pydantic_extra__", None) or {}
    found: List[Tuple[str, Any]] = []
    for key in list(by_key) + [key for key in extra if key not in by_key]:
        section = getattr(segment, by_key[key]) if key in by_key else extra.get(key)
        if section is not None:
            found.append((key, section))
    return found


def _spellings_in(options: Any, name: str) -> List[str]:
    """The keys ``options`` holds ``name`` under: either spelling in a plugin's dict."""
    if isinstance(options, dict):
        return [key for key in options if key.replace("-", "_") == name]
    if name in type(options).model_fields or name in (
        getattr(options, "__pydantic_extra__", None) or {}
    ):
        return [name]
    return []


def _field_default(options: Any, name: str) -> Any:
    """The default an options model gives ``name``; None for a plugin's dict."""
    if isinstance(options, dict):
        return None
    field = type(options).model_fields.get(name)
    return None if field is None or field.is_required() else field.get_default()


def confine_tool_versions(
    config: "AshConfig",
    trusted_config: "AshConfig",
    config_overrides: Optional[Sequence[str]],
    in_tree: Sequence[Path],
    source: UntrustedSource = IN_TREE_OR_DELIVERED,
) -> None:
    """Replace the ``tool_version`` a config that is not the operator's set, in place.

    ``tool_version`` chooses which release of a scanner's or converter's tool uv
    installs and which one already on PATH is accepted. For every section of
    ``scanners`` and ``converters`` (``OPERATOR_ONLY_PLUGIN_OPTIONS``), built in
    or added by a plugin module, under either spelling of the key, the value
    comes from the trusted base with ``--config-overrides`` replayed; where that
    sets none, the plugin's own default applies. A value equal to the trusted
    one is kept, so a repository config that repeats the operator's value is
    unchanged. Each value that is not kept is named in one warning.

    The plugins read the value as before (``_get_tool_version_constraint``),
    so they receive the operator's value or their default, on every route that
    resolves a config: a scan, a workspace project, the MCP server and
    ``ash merge`` (``resolve_config.confine_to_trusted_base``).

    Args:
        config: The resolved AshConfig, changed in place.
        trusted_config: The trusted base ``resolve_config`` built: the defaults,
            or the operator's config outside the tree.
        config_overrides: The operator's ``--config-overrides``. Those under
            ``scanners`` and ``converters`` are replayed onto ``trusted_config``.
        in_tree: The config files that are not the operator's, named in the
            warning.
        source: Why those files are not the operator's, and the fix, for the
            warning.
    """
    from automated_security_helper.config.resolve_config import (
        apply_config_overrides,
    )

    sections = {segment for segment, _kind in _PLUGIN_SEGMENTS}
    replayed = [
        override
        for override in config_overrides or []
        if override.partition("=")[0].removesuffix("+").strip().split(".")[0]
        in sections
    ]
    if replayed:
        # The scanners entries are folded onto the trusted base's own section
        # spellings as confine_scanner_config_files folds them; the converters
        # entries are replayed as written (the fold keeps a record for the
        # reporters and scanners segments only).
        from automated_security_helper.config.resolve_config import (
            _folded_onto_trusted,
        )

        replayed = _folded_onto_trusted(
            trusted_config, replayed, config, section="scanners"
        )
        trusted_config = apply_config_overrides(trusted_config, replayed)

    ignored: List[str] = []
    for segment, kind in _PLUGIN_SEGMENTS:
        config_segment = getattr(config, segment)
        seen: set[str] = set()
        for key, section in _plugin_sections(config_segment):
            seen.add(key)
            options = _options_of(section)
            trusted_section = trusted_config.get_plugin_config(kind, key)
            trusted_options = (trusted_section or {}).get("options") or {}
            if options is None:
                # A plugin section with no options mapping (or one that is not
                # a mapping): the operator's pin still applies, so the mapping
                # is made for it.
                if isinstance(section, dict):
                    for name in OPERATOR_ONLY_PLUGIN_OPTIONS:
                        wanted = _trusted_option(trusted_options, name)
                        if wanted is _MISSING or wanted is None:
                            continue
                        section.setdefault("options", {})
                        if isinstance(section["options"], dict):
                            section["options"][name] = wanted
                        else:
                            # A value that is not a mapping cannot hold the
                            # pin; the plugin will refuse it when it reads its
                            # options, and the operator's pin is not in force
                            # until then, so say so rather than drop it
                            # silently.
                            ASH_LOGGER.warning(
                                f"{segment}.{key}.options is not a mapping, so "
                                f"the operator's {name} pin cannot be restored "
                                "into it; the plugin reads its options from "
                                "this value as written."
                            )
                continue
            for name in OPERATOR_ONLY_PLUGIN_OPTIONS:
                default = _field_default(options, name)
                wanted = _trusted_option(trusted_options, name)
                spellings = _spellings_in(options, name)
                if not spellings and wanted is not _MISSING and wanted is not None:
                    # A plugin section's dict holds only what was written: an
                    # omitted tool_version left the plugin on its default
                    # constraint in place of the operator's pin.
                    _set(options, name, wanted, default)
                    continue
                for spelling in spellings:
                    written = _get(options, spelling)
                    current = _or_default(written, default)
                    if current == _or_default(wanted, default):
                        if written is None and default is not None:
                            _set(options, spelling, wanted, default)
                        continue
                    if current != default:
                        ignored.append(f"{segment}.{key}.options.{name}")
                    _set(options, spelling, wanted, default)
        # A plugin section the trusted base pins that the config does not hold
        # at all: the plugin still runs (its module is loaded whatever the
        # config says), so the pin is written into a section made for it.
        extra = getattr(config_segment, "__pydantic_extra__", None)
        if isinstance(extra, dict):
            for key, trusted_section in _plugin_sections(
                getattr(trusted_config, segment)
            ):
                if key in seen or not isinstance(trusted_section, dict):
                    continue
                trusted_options = _options_of(trusted_section) or {}
                pins: Dict[str, Any] = {}
                for name in OPERATOR_ONLY_PLUGIN_OPTIONS:
                    wanted = _trusted_option(trusted_options, name)
                    if wanted is not _MISSING and wanted is not None:
                        pins[name] = wanted
                if pins:
                    extra[key] = {"options": pins}
    if ignored:
        from automated_security_helper.config.config_sources import (
            describe_config_path,
        )

        files = ", ".join(describe_config_path(path) for path in in_tree)
        ASH_LOGGER.warning(
            f"Ignoring {', '.join(sorted(set(ignored)))} from {files}: tool_version "
            "chooses which release of a tool ASH installs and accepts, which is the "
            f"operator's choice, and {source.reason}. The operator's value, or the "
            f"tool's default constraint, applies instead. {source.remedy}"
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


def empty_tool_directory(name: str, *, context: Any) -> Path:
    """An empty directory, for a tool that reads what a directory it is given holds.

    ``empty_tool_config``'s counterpart for a directory (trivy-repo's
    ``--module-dir``, gitleaks' ``--gitleaks-ignore-path``): made new, so nothing
    is in it, in the same directory of the scanner run's own outside the scanned
    tree, and removed with it.

    Args:
        name: The directory's name (``trivy-modules``).
        context: The scanner's PluginContext, whose scanned tree the directory is
            kept out of.
    """
    from automated_security_helper.utils.tool_config_dir import (
        make_tool_config_directory,
    )

    return make_tool_config_directory(name, context=context)
