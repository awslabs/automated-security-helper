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
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Literal,
    NamedTuple,
    Optional,
    Sequence,
    Tuple,
)

from automated_security_helper.config.untrusted_source import (
    IN_TREE_OR_DELIVERED,
    UntrustedSource,
)
from automated_security_helper.core.exceptions import (
    ASHConfigValidationError,
    ASHRespelledOverrideError,
)
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP
from automated_security_helper.utils.terminal_text import shown_on_one_line

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


def is_tightening_value(scanner: str, option: str, value: Any) -> bool:
    """Whether ``value`` is one of the ``TIGHTENING_VALUES`` of ``scanner``'s ``option``.

    Compared as JSON values, not with Python equality: ``1 == True`` and
    ``1.0 == True`` in Python, so ``disable_telemetry: 1`` is not the listed
    ``true``. A value that is not JSON data at all (a YAML date) matches none.
    """
    from automated_security_helper.config.runtime_patch import _same_json_value

    for listed in TIGHTENING_VALUES.get((scanner, option), ()):
        try:
            if _same_json_value(value, listed):
                return True
        except (TypeError, ValueError, RecursionError):
            # Not JSON data, or nested past what the encoder will follow.
            return False
    return False


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


class DroppedOverride(NamedTuple):
    """An override the trusted base could not take, as ``replay_overrides_onto`` left it out."""

    #: The override's key path as replayed (after the fold onto the trusted
    #: base's spelling), without its value.
    key: str
    #: The refusal's text, which names keys and never values.
    reason: str
    #: Its position in the list ``replay_overrides_onto`` was given, so the
    #: caller can read the override as the operator typed it (``landings_of``).
    index: int


class Replay(NamedTuple):
    """The trusted base with the overrides it could take, and the ones it could not."""

    config: "AshConfig"
    dropped: List[DroppedOverride]


def _dropped(override: str, error: Exception, index: int) -> DroppedOverride:
    return DroppedOverride(override.partition("=")[0], str(error), index)


def replay_overrides_onto(
    trusted_config: "AshConfig", overrides: Sequence[str]
) -> Replay:
    """The trusted base with the operator's ``overrides`` replayed onto it.

    Each confinement step replays the operator's ``--config-overrides`` onto
    the trusted base, so an override sets a confined value whatever the file
    says. The overrides already applied to the resolved config, so one that
    only the trusted base refuses (a value its section's model refuses there)
    changes nothing on that base. Applied as one set, such an override refused
    the whole set and aborted the resolution. The whole list applies at once
    first, so overrides that are valid only together all land. When that is
    refused, each override is left out in turn: the ones whose removal alone
    makes the list validate are the ones the base cannot take, and the rest
    still land together (several are dropped at once when removing either of
    them repairs the list, which errs toward refusing). When no single removal
    repairs it (two or more independent failures), the overrides apply one at
    a time and each one the base refuses drops only itself. This is the search
    ``resolve_config._with_scanner_overrides`` runs for the operator view.

    The result lists the dropped overrides. The value such an override set is
    the operator's own on the resolved config, and the confinement leaves it
    alone (``_covered``, by where ``landings_of`` says the override landed), so
    a dropped override never turns into a replaced value. ``warn_dropped`` says which ones were dropped. A respelled section
    (``ASHRespelledOverrideError``) is still refused, as the reporters replay
    refuses it: the scan does not resolve under a spelling the operator did
    not type
    (tests/unit/config/test_a_respelled_reporter_override_fails_the_scan.py).
    """
    from automated_security_helper.config.resolve_config import (
        apply_config_overrides,
    )

    overrides = list(overrides)
    if not overrides:
        return Replay(trusted_config, [])
    try:
        return Replay(apply_config_overrides(trusted_config, overrides), [])
    except ASHRespelledOverrideError:
        raise
    except ASHConfigValidationError as error:
        failure = error
    culprits: List[int] = []
    for index in range(len(overrides)):
        try:
            apply_config_overrides(
                trusted_config, overrides[:index] + overrides[index + 1 :]
            )
        except ASHRespelledOverrideError:
            raise
        except ASHConfigValidationError:
            continue
        culprits.append(index)
    if culprits:
        remainder = [
            override
            for index, override in enumerate(overrides)
            if index not in culprits
        ]
        try:
            replayed = apply_config_overrides(trusted_config, remainder)
        except ASHRespelledOverrideError:
            raise
        except ASHConfigValidationError:
            pass
        else:
            return Replay(
                replayed,
                [_dropped(overrides[index], failure, index) for index in culprits],
            )
    replayed = trusted_config
    dropped: List[DroppedOverride] = []
    for index, override in enumerate(overrides):
        try:
            replayed = apply_config_overrides(replayed, [override])
        except ASHRespelledOverrideError:
            raise
        except ASHConfigValidationError as error:
            dropped.append(_dropped(override, error, index))
    return Replay(replayed, dropped)


def warn_dropped(
    trusted_config: "AshConfig", dropped: Sequence[DroppedOverride]
) -> None:
    """One warning for each override the trusted base could not take.

    The key and the refusal's text can name a section key the trusted file
    read from the environment (the fold rewrites an override onto it), so both
    are redacted with that file's values. The value the override set is never
    printed.
    """
    if not dropped:
        return
    from automated_security_helper.config.config_validator import redact_values
    from automated_security_helper.utils.error_text import config_environment_values
    from automated_security_helper.utils.log import NO_MARKUP

    values = config_environment_values(trusted_config)
    for item in dropped:
        ASH_LOGGER.warning(
            f"The override at {redact_values(item.key, values)} is one the trusted "
            f"configuration cannot take ({redact_values(item.reason, values)}), so "
            "it is not replayed onto it; the value it set stays as the operator "
            "wrote it, and the other overrides are replayed.",
            extra=NO_MARKUP,
        )


class Landing(NamedTuple):
    """Where an override the trusted base could not take landed on the resolved config."""

    #: The override's first key: ``scanners`` or ``converters``.
    segment: str
    #: The section key the override landed on, as the resolved configuration
    #: holds it; None when the override sets the whole segment. Not the
    #: spelling the trusted base uses (the fold respells the override onto
    #: that), and not every section that folds with it: a file can hold
    #: ``ferret_scan`` and ``ferret-scan`` both, and the scan's own apply
    #: puts the override on the one it resolves the typed spelling to. More
    #: than one key only when no typed spelling can tell them apart.
    sections: Optional[FrozenSet[str]]
    #: The key path below the section, as the override wrote it.
    below: Tuple[str, ...]
    #: Whether it appended to a list (``key+=item``) rather than set.
    append: bool
    #: The value it set or appended, parsed. The operator's own, so it is never
    #: printed or logged.
    value: Any


def _landed_key(held: Sequence[str], typed: str) -> Optional[str]:
    """The key among ``held`` that the scan's own apply puts a section typed ``typed`` on.

    That is ``config_sources._resolve_dict_key``'s rule, the exact key first and
    then its ``-``/``_`` twin; a spelling that matches neither is refused by
    the apply, so none of ``held`` is the answer then.
    """
    from automated_security_helper.config.config_sources import _resolve_dict_key

    landed = _resolve_dict_key(dict.fromkeys(held), typed)
    return landed if landed in held else None


def landings_of(
    config: "AshConfig", typed: Sequence[str], dropped: Sequence[DroppedOverride]
) -> List[Landing]:
    """Where each of the ``dropped`` overrides landed on the resolved ``config``.

    ``typed`` is the list the replay was given before the fold respelled it
    onto the trusted base's section keys, as the operator wrote it: the scan's
    own apply resolved those texts against ``config``, whose section keys the
    repository's file chose, so the section an override changed is the one its
    typed spelling resolves to there. The replayed key (``DroppedOverride.key``)
    may name the trusted base's spelling of a section instead, which is not
    necessarily a key ``config`` holds, and a file that holds a section under
    two spellings has only one of them changed by the override.
    """
    from automated_security_helper.config.ash_config import section_fold_key
    from automated_security_helper.config.resolve_config import _parse_config_value

    known = {segment for segment, _kind in _PLUGIN_SEGMENTS}
    found: List[Landing] = []
    for item in dropped:
        if not 0 <= item.index < len(typed):
            continue
        written, _separator, raw = typed[item.index].partition("=")
        written_parts = written.removesuffix("+").strip().split(".")
        replayed_parts = item.key.removesuffix("+").strip().split(".")
        segment = replayed_parts[0]
        sections: Optional[FrozenSet[str]] = None
        if len(replayed_parts) > 1:
            held = (
                [key for key, _section in _plugin_sections(getattr(config, segment))]
                if segment in known
                else []
            )
            fold = section_fold_key(replayed_parts[1])
            same = [key for key in held if section_fold_key(key) == fold]
            if len(same) > 1 and len(written_parts) > 1:
                landed = _landed_key(same, written_parts[1])
                same = [landed] if landed else same
            sections = frozenset(same or [replayed_parts[1]])
        found.append(
            Landing(
                segment,
                sections,
                tuple(replayed_parts[2:]),
                item.key.rstrip().endswith("+"),
                _parse_config_value(raw),
            )
        )
    return found


def _relation(landing: Landing, segments: Sequence[str]) -> Optional[bool]:
    """How a landing relates to the path ``segments``: None when it is not on it.

    True when the landing is exactly that path, False when it is the path or a
    mapping above it (the value at ``segments`` is the one it set, or part of
    the one it set). A section key matches by the key the override landed on;
    an option name under either of ``-`` and ``_``.
    """
    if not segments or landing.segment != segments[0]:
        return None
    if landing.sections is None:
        return False
    if len(segments) < 2 or segments[1] not in landing.sections:
        return None
    below = segments[2:]
    if len(landing.below) > len(below):
        return None
    for part, segment in zip(landing.below, below):
        if part.replace("-", "_") != segment.replace("-", "_"):
            return None
    return len(landing.below) == len(below)


def _covered(
    landings: Sequence[Landing],
    segments: Sequence[str],
    *,
    except_appends: bool = False,
) -> bool:
    """Whether a dropped override set the value at ``segments``, or a mapping above it.

    The value such an override set is the operator's own, and the trusted base
    holds nothing to put in its place, so the confinement leaves it. With
    ``except_appends``, an override that appended to a list at exactly
    ``segments`` does not count: the list holds the repository's items too,
    which ``_appended`` and ``_with_appended`` confine.
    """
    for landing in landings:
        relation = _relation(landing, segments)
        if relation is None:
            continue
        if except_appends and relation and landing.append:
            continue
        return True
    return False


def _appended(landings: Sequence[Landing], segments: Sequence[str]) -> List[Landing]:
    """The dropped overrides that appended to the list at exactly ``segments``."""
    return [
        landing
        for landing in landings
        if landing.append and _relation(landing, segments)
    ]


def _with_appended(base: Any, appended: Sequence[Landing]) -> Any:
    """``base`` with what each of ``appended`` added, as the apply adds it.

    An append extends a list, starts one where the document holds none, and
    sets the value where the document holds anything else
    (``resolve_config._apply_config_override``).
    """
    value = base
    for landing in appended:
        items = landing.value if isinstance(landing.value, list) else [landing.value]
        if isinstance(value, list):
            value = [*value, *items]
        elif value is _MISSING or value is None:
            value = list(items)
        else:
            value = landing.value
    return value


def _options_mapping(section: Any) -> Dict[str, Any]:
    """The ``options`` of a trusted plugin section as a mapping.

    A section that is not a mapping (a plugin section the operator's file wrote
    as a scalar or a list), or whose ``options`` is not one, holds no option, so
    it reads as empty instead of raising out of the confinement.
    """
    if not isinstance(section, dict):
        return {}
    options = section.get("options")
    return options if isinstance(options, dict) else {}


def _trusted_values(options: Dict[str, Any], names: Iterable[str]) -> Dict[str, Any]:
    """The trusted base's value for each of ``names`` it sets, under either spelling."""
    found: Dict[str, Any] = {}
    for name in names:
        wanted = _trusted_option(options, name)
        if wanted is not _MISSING and wanted is not None:
            found[name] = wanted
    return found


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
    so its ``model_fields_set`` says which were written. That holds for a
    freshly parsed config only: ``_file_wrote`` answers for a resolved one.
    """
    if written is _MISSING or written is None:
        return False
    fields_set = getattr(options, "model_fields_set", None)
    return fields_set is None or name in fields_set


def _file_wrote(config: "AshConfig", segments: Sequence[str], written: Any) -> bool:
    """Whether the config set the option at ``segments`` itself, rather than
    leaving it to its default, read from the resolved ``config``.

    ``apply_config_overrides`` rebuilds the config, which puts every field in
    ``model_fields_set``, so one unrelated override made every in-tree
    tightening value read as written (``_wrote``). It stamps a record of the
    paths the operator supplied, which ``recorded_config._sets`` reads in
    place of ``model_fields_set`` on a rebuilt config and reads as ``_wrote``
    does on a freshly parsed one.
    """
    if written is _MISSING or written is None:
        return False
    from automated_security_helper.config.recorded_config import _sets

    return _sets(config, list(segments))


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

    A plugin scanner's section the file leaves out (or holds without an options
    mapping) is given the trusted base's values for these options, since the
    file replaces the operator's config rather than adding to it. The warning
    names only an option the file wrote.

    An override the trusted base cannot take (``replay_overrides_onto``) leaves
    the value it set on the resolved config alone, at the one section it
    landed on (``landings_of``). An override that only appended to a list
    (``key+=item``) leaves the repository's own items in that list too, so the
    list is confined as for any other override, with the operator's appended
    items put back after the trusted base's.

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

    scanner_overrides = [
        override
        for override in config_overrides or []
        if override.partition("=")[0].removesuffix("+").strip().split(".")[0]
        == "scanners"
    ]
    landings: List[Landing] = []
    if scanner_overrides:
        # An override the scan's own apply resolved under the repository's
        # spelling of a section the trusted base spells another way is folded
        # onto the trusted base's key first (the lockout fold the scanner view
        # replay uses); without it the replay refuses the only spelling the
        # scan's apply accepted, and the scan cannot run.
        from automated_security_helper.config.resolve_config import (
            _folded_onto_trusted,
        )

        typed = scanner_overrides
        scanner_overrides = _folded_onto_trusted(
            trusted_config, scanner_overrides, config, section="scanners"
        )
        replay = replay_overrides_onto(trusted_config, scanner_overrides)
        trusted_config = replay.config
        landings = landings_of(config, typed, replay.dropped)
        # This step reports every scanners override the base could not take;
        # confine_tool_versions replays the same list and reports only the
        # others, so one dropped override is one warning.
        warn_dropped(trusted_config, replay.dropped)

    ignored: List[str] = []
    extra = getattr(config.scanners, "__pydantic_extra__", None)
    for scanner, option_defaults in _confined_options().items():
        trusted_section = trusted_config.get_plugin_config("scanner", scanner)
        trusted_options = _options_mapping(trusted_section)
        # A plugin scanner's section the config leaves out, or holds with no
        # options mapping, is given the trusted base's confined values whole:
        # a file inside the tree replaces the operator's config, so leaving
        # the section out would drop the operator's choices for that scanner
        # (confine_tool_versions gives tool_version the same way). A built-in
        # scanner's section is a typed field and is always present.
        trusted_values = _trusted_values(trusted_options, option_defaults)
        sections = _scanner_sections(config, scanner)
        if not sections:
            if trusted_values and isinstance(extra, dict):
                extra[scanner] = {"options": dict(trusted_values)}
            continue
        for key, section in sections:
            # A value an override the trusted base could not take set is the
            # operator's own; there is nothing of the base's to put in its place.
            if _covered(landings, ("scanners", key)):
                continue
            options = _options_of(section)
            if options is None:
                if (
                    trusted_values
                    and isinstance(section, dict)
                    and section.get("options") is None
                ):
                    section["options"] = dict(trusted_values)
                continue
            for name, default in option_defaults.items():
                path = ("scanners", key, "options", name)
                # An override that set the option (or the mapping it is in)
                # leaves the operator's value; one that only appended to a
                # list leaves the repository's items beside the operator's,
                # which are confined below with the operator's re-admitted.
                if _covered(landings, path, except_appends=True):
                    continue
                appended = _appended(landings, path)
                wanted = _with_appended(
                    _trusted_option(trusted_options, name), appended
                )
                written = _get(options, name)
                current = _or_default(written, default)
                wrote = _file_wrote(config, path, written)
                if wrote and is_tightening_value(scanner, name, current):
                    continue
                if current == _or_default(wanted, default):
                    if written is None and default is not None:
                        # An explicit null reads as the default here, but the
                        # plugin would get None; give it the trusted value.
                        _set(options, name, wanted, default)
                    continue
                # Only a value the file wrote is named in the warning: a
                # built-in scanner's options model reads an unwritten option as
                # the model's own default (opengrep's config as ``p/ci``), which
                # is not the file's choice, though it still gives way to the
                # operator's value. A list that holds only what the operator's
                # own appended override added is no choice of the file's.
                own_items = _with_appended(_MISSING, appended) if appended else None
                if current != default and wrote and current != own_items:
                    ignored.append(f"scanners.{key}.options.{name}")
                _set(options, name, wanted, default)
    ignored.extend(_confine_settings_files(config, trusted_config, landings))
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
        # A key that is not a string (a YAML `1:` under a plugin's options) is
        # no spelling of the option; skipped, where str.replace raised.
        return [
            key
            for key in options
            if isinstance(key, str) and key.replace("-", "_") == name
        ]
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

    A ``tool_version`` an override set that the trusted base cannot take
    (``replay_overrides_onto``) stays as the operator wrote it. The warning for
    such a ``scanners`` override is ``confine_scanner_config_files``'s, which
    replays the same entries first on every route; the ones under
    ``converters`` are reported here.

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
    from automated_security_helper.config.ash_config import section_fold_key

    sections = {segment for segment, _kind in _PLUGIN_SEGMENTS}
    replayed = [
        override
        for override in config_overrides or []
        if override.partition("=")[0].removesuffix("+").strip().split(".")[0]
        in sections
    ]
    landings: List[Landing] = []
    if replayed:
        # The scanners entries are folded onto the trusted base's own section
        # spellings as confine_scanner_config_files folds them; the converters
        # entries are replayed as written (the fold keeps a record for the
        # reporters and scanners segments only).
        from automated_security_helper.config.resolve_config import (
            _folded_onto_trusted,
        )

        typed = replayed
        replayed = _folded_onto_trusted(
            trusted_config, replayed, config, section="scanners"
        )
        replay = replay_overrides_onto(trusted_config, replayed)
        trusted_config = replay.config
        landings = landings_of(config, typed, replay.dropped)
        # confine_scanner_config_files replays the scanners entries of this
        # same list and reports the ones the base could not take (both steps
        # run on every route), so only the others are reported here.
        warn_dropped(
            trusted_config,
            [
                item
                for item in replay.dropped
                if item.key.removesuffix("+").strip().split(".")[0] != "scanners"
            ],
        )

    ignored: List[str] = []
    for segment, kind in _PLUGIN_SEGMENTS:
        config_segment = getattr(config, segment)
        # Sections seen, by the identity their spellings fold under: the base
        # may spell a section another way (``ferret_scan`` beside
        # ``ferret-scan``), and a section made for the pin must not be made
        # twice.
        seen: set[Tuple[str, str]] = set()
        for key, section in _plugin_sections(config_segment):
            seen.add(section_fold_key(key))
            if _covered(landings, (segment, key)):
                continue
            options = _options_of(section)
            trusted_section = trusted_config.get_plugin_config(kind, key)
            trusted_options = _options_mapping(trusted_section)
            if options is None:
                # A plugin section with no options mapping (or one that is not
                # a mapping): the operator's pin still applies, so the mapping
                # is made for it.
                if isinstance(section, dict):
                    for name in OPERATOR_ONLY_PLUGIN_OPTIONS:
                        wanted = _trusted_option(trusted_options, name)
                        if wanted is _MISSING or wanted is None:
                            continue
                        if _covered(landings, (segment, key, "options", name)):
                            continue
                        if section.get("options") is None:
                            # No options key, or ``options:`` left empty, which
                            # reads as None: neither holds a mapping for the
                            # pin to land in, so one is made.
                            section["options"] = {}
                        if isinstance(section["options"], dict):
                            section["options"][name] = wanted
                        else:
                            # A value that is not a mapping cannot hold the
                            # pin; the plugin will refuse it when it reads its
                            # options, and the operator's pin is not in force
                            # until then, so say so rather than drop it
                            # silently. The key is the file's text, so the
                            # whole message is shown on one line, with the
                            # key's controls escaped, and handed to the log as
                            # the shown text: a message built by embedding a
                            # shown key in an f-string is a plain str again,
                            # which the console shows a second time, doubling
                            # the backslash of every escape.
                            ASH_LOGGER.warning(
                                shown_on_one_line(
                                    f"{segment}.{key}.options is not a mapping, "
                                    f"so the operator's {name} pin cannot be "
                                    "restored into it; the plugin reads its "
                                    "options from this value as written."
                                ),
                                extra=NO_MARKUP,
                            )
                continue
            for name in OPERATOR_ONLY_PLUGIN_OPTIONS:
                if _covered(landings, (segment, key, "options", name)):
                    continue
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
                if section_fold_key(key) in seen or not isinstance(
                    trusted_section, dict
                ):
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
    config: "AshConfig",
    trusted_config: "AshConfig",
    landings: Sequence[Landing] = (),
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
    trusted_settings = _options_mapping(trusted_section).get("scan_settings") or {}
    ignored: List[str] = []
    for key, section in _scanner_sections(config, "detect-secrets"):
        if _covered(landings, ("scanners", key, "options", "scan_settings")):
            continue
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
