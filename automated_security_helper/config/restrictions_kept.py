# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What an operator file in another git checkout still sets for the trusted base,
and what no config but the operator's may loosen.

Why this exists
---------------
A config file inside any git checkout, not only the scanned one, cannot grant
(``config/sandbox_grants.py``). An ``ASH_CONFIG`` or ``trusted_config_path`` file
that sits in a checkout other than the scanned one is therefore not the trusted
base the scanned repository's config is held to; ``resolve_config`` builds that
base from the defaults instead (``trusted_base_config``). Taking the whole file
out of the base also took out what the file sets to restrict. An operator who
keeps ``ASH_CONFIG`` in a dotfiles checkout and lowers an archive extraction
limit there found the repository's config capped at the default, not at the
operator's value.

What is kept
------------
``keep_restrictions`` narrows the base with the settings of the file that only
restrict, and nothing else. They are the settings the confinement steps already
let a file the repository wrote set, because they cannot widen anything:
- each archive extraction limit (``config/archive_limits.py``), at the lower of
  the file's value and the base's;
- a scanner option set to a value that only narrows what the tool does
  (``TIGHTENING_VALUES``: semgrep and opengrep ``metrics: off``, trivy
  ``disable_telemetry: true``), when the file wrote it;
- a ``network_scanners`` list, as a limit (``SandboxConfig.network_limit``): a
  scanner outside it gets no network. The list is not kept as a list, because a
  list replaces the scanners' declared needs and so can add network.
Every other setting of the file falls to the defaults with its grants.

The operator's floors
---------------------
``keep_operator_floors`` runs in ``resolve_config``'s confinement block, for every
config that is not the operator's: a file inside the scanned tree or a git
checkout, one an MCP client delivered, and an MCP client's overrides. It reads
the trusted base with the operator's ``--config-overrides`` replayed, which is
the value ``set_by_operator`` compares with, and changes the resolved config in
place. Such a config replaces the operator's config rather than adding to it, so
a section or option it leaves out comes back as the plugin's default. For these
settings that default would run or send more than the operator chose. An
off-host scanner the operator turns off (the eight ``/scanners/<name>/**``
sections of ``ALWAYS_DENIED_PATHS``) stays off. A delivered file cannot write
those sections, so it always leaves them out, and an in-tree file that sets
``enabled: true`` is named in a warning. Such a config may still turn one of
them off.

mcp-config's five checks resolve to the operator's value or the config's,
whichever is on. Its two prefix lists keep only the entries under one of the
operator's prefixes, compared with the scanner's own URL and command-path
matching. An empty list, or one with nothing left, keeps the operator's list, and
an operator who sets no list accepts any.

What is not done here
---------------------
A file an MCP client delivered keeps nothing here: its base is the defaults, so
the caller does not call ``keep_restrictions`` for it. ``keep_operator_floors``
holds it, like every config that is not the operator's, to the operator's
floors. A file outside every checkout is the operator's own and is the base
whole. The file's sandbox mode is carried by ``trusted_base_config`` on its own,
as it was.

``honor_ignore_files`` is not kept in either direction. ``false`` makes the scan
read the paths a repository's ``.gitignore`` and ``.ignore`` files leave out
(``node_modules/``, ``.venv/``, ``.env``), so it widens what a scan reads and
what the operator's reporters can send off the host; the confinement step
(``confine_honor_ignore_files``) therefore takes it from the base, and a file
in another checkout sets it only through ``--no-honor-ignore-files`` or
``--config-overrides``.

Limits
------
- No warning names a setting that fell to the defaults; the base is built before
  any file is compared with it.
- The limit from a ``network_scanners`` list is read off the base by
  ``resolve_config`` right after ``trusted_base_config`` returns and handed to
  ``confine_sandbox_grants``, because the later rebuilds of the trusted sandbox
  settings (the file's own sandbox section, the operator's overrides) do not
  carry a private attribute. An operator override of ``network_scanners``
  replaces the limit, as an override replaces the other base values.
"""

from __future__ import annotations

import copy
import posixpath
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    FrozenSet,
    List,
    NamedTuple,
    Optional,
    Sequence,
    Tuple,
)

from automated_security_helper.config.tool_config_trust import (
    TIGHTENING_VALUES,
    _MISSING,
    Landing,
    _covered,
    _file_wrote,
    _get,
    _options_mapping,
    _options_of,
    _same_option_value,
    _set,
    _spellings_in,
    _trusted_option,
    _wrote,
    landings_of,
    replay_overrides_onto,
)
from automated_security_helper.config.untrusted_source import (
    IN_TREE_OR_DELIVERED,
    UntrustedSource,
)
from automated_security_helper.base.extraction_limits import EXTRACTION_LIMIT_OPTIONS
from automated_security_helper.models.vocab import PluginKind
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.mcp_config.model import (
    command_prefix_matches,
    split_url,
    url_prefix_matches,
)

if TYPE_CHECKING:
    from automated_security_helper.config.ash_config import AshConfig


def keep_restrictions(base: "AshConfig", source: "AshConfig") -> None:
    """Narrow *base*, changed in place, with what *source* sets that only restricts.

    Args:
        base: A trusted base that is not *source*: the defaults, or a config
            copied for the purpose. It is changed; *source* is not.
        source: The operator's config from a file in another git checkout.
    """
    _keep_archive_limits(base, source)
    _keep_tightening_values(base, source)
    _keep_network_limit(base, source)


def _keep_archive_limits(base: "AshConfig", source: "AshConfig") -> None:
    held = base.converters.archive.options
    given = source.converters.archive.options
    for name in EXTRACTION_LIMIT_OPTIONS:
        setattr(held, name, min(getattr(held, name), getattr(given, name)))


def _keep_tightening_values(base: "AshConfig", source: "AshConfig") -> None:
    from automated_security_helper.config.client_scanner_exclusions import (
        _scanner_sections,
    )

    for (scanner, name), values in TIGHTENING_VALUES.items():
        for _key, section in _scanner_sections(source, scanner):
            options = _options_of(section)
            written = _get(options, name)
            if not _wrote(options, name, written) or written not in values:
                continue
            for _held_key, held_section in _scanner_sections(base, scanner):
                held = _options_of(held_section)
                if held is not None:
                    _set(held, name, written, None)


def _keep_network_limit(base: "AshConfig", source: "AshConfig") -> None:
    listed = source.sandbox.network_scanners
    if listed is None:
        return
    held = base.sandbox.network_limit
    base.sandbox.network_limit = (
        list(listed) if held is None else [name for name in held if name in listed]
    )


def keep_operator_floors(
    config: "AshConfig",
    trusted_config: "AshConfig",
    config_overrides: Optional[Sequence[str]],
    in_tree: Sequence[Path],
    source: UntrustedSource = IN_TREE_OR_DELIVERED,
) -> None:
    """Hold a config that is not the operator's to the operator's floors, in place.

    A floor is a setting such a config may narrow but not loosen past the
    operator's value, or past the plugin's default where the operator sets none.
    The config replaces the operator's config rather than adding to it, so a
    section or option it leaves out takes the operator's value, and a value it
    writes that loosens a floor is replaced by the operator's. One warning names
    each value the config wrote and this step replaced; an omission is not the
    config's choice and is not named.

    Args:
        config: The resolved AshConfig, changed in place.
        trusted_config: The trusted base ``resolve_config`` built for the sandbox
            settings: the defaults, or the operator's config outside the tree. It
            is only read.
        config_overrides: ``--config-overrides``. Those under ``scanners`` and
            ``converters`` are replayed onto ``trusted_config``, as
            ``confine_scanner_config_files`` replays them, so an override still
            sets a floor.
        in_tree: The config files that are not the operator's, named in the
            warning.
        source: Why those files are not the operator's, and the fix, for the
            warning.
    """
    from automated_security_helper.config.config_sources import describe_config_path

    typed = [
        override
        for override in config_overrides or []
        if override.partition("=")[0].removesuffix("+").strip().split(".")[0]
        in ("scanners", "converters")
    ]
    landings: List[Landing] = []
    if typed:
        # The fold respells a scanners override onto the trusted base's own
        # section key, as confine_scanner_config_files does, and leaves the rest
        # as written. confine_scanner_config_files already reports each scanners
        # override the base could not take, so none is reported again here.
        from automated_security_helper.config.resolve_config import (
            _folded_onto_trusted,
        )

        folded = _folded_onto_trusted(trusted_config, typed, config, section="scanners")
        replay = replay_overrides_onto(trusted_config, folded)
        trusted_config = replay.config
        landings = landings_of(config, typed, replay.dropped)

    ignored: List[str] = []
    ignored.extend(_keep_switches_off(config, trusted_config, landings))
    ignored.extend(_keep_option_floors(config, trusted_config, landings))
    if ignored:
        files = ", ".join(describe_config_path(path) for path in in_tree)
        tail = (
            f"{source.scanner_steps_note}."
            if source.scanner_steps_note
            else source.remedy
        )
        ASH_LOGGER.warning(
            f"Ignoring {', '.join(sorted(set(ignored)))} from {files}: a config "
            "that is not the operator's may narrow these but not loosen them past "
            f"the operator's values, and {source.reason}. {tail}"
        )


def _keep_switches_off(
    config: "AshConfig", trusted_config: "AshConfig", landings: Sequence[Landing]
) -> List[str]:
    """Keep off each off-host scanner the operator turned off; return what was named.

    The scanners are the eight whose whole section is an always-denied path. The
    operator's off is kept where the config leaves the section out and where it
    sets ``enabled`` on; a config may still turn one of them off. Both sides are
    read with ``section_enabled``, the reading the run uses.
    """
    from automated_security_helper.base.plugin_config import section_enabled
    from automated_security_helper.config.client_scanner_exclusions import (
        _scanner_sections,
    )
    from automated_security_helper.config.runtime_patch import SECTION_FLOOR_ENTRIES

    ignored: List[str] = []
    extra = getattr(config.scanners, "__pydantic_extra__", None)
    for scanner in sorted(entry.split("/")[2] for entry in SECTION_FLOOR_ENTRIES):
        trusted_section = trusted_config.get_plugin_config(PluginKind.SCANNER, scanner)
        if section_enabled(trusted_section):
            continue
        sections = _scanner_sections(config, scanner)
        if not sections:
            # Only a plugin scanner's section can be missing: a built-in
            # scanner's is a typed field and is always present.
            if isinstance(extra, dict):
                extra[scanner] = {"enabled": False}
            continue
        for key, section in sections:
            path = ("scanners", key, "enabled")
            # A value an override the trusted base could not take set is the
            # operator's own; there is nothing of the base's to put in its place.
            if _covered(landings, path) or not section_enabled(section):
                continue
            if isinstance(section, dict):
                wrote = "enabled" in section
                section["enabled"] = False
            else:
                wrote = _file_wrote(config, path, section.enabled)
                section.enabled = False
            if wrote:
                ignored.append(f"scanners.{key}.enabled")
    return ignored


# ---------------------------------------------------------------------------
# Option floors
# ---------------------------------------------------------------------------

#: How a floor narrows. ``TRUE_NARROWS``: the check is on when either side has it
#: on. ``URL_PREFIXES`` and ``COMMAND_PREFIXES``: a list keeps only the entries
#: under one of the operator's prefixes, compared the way mcp-config compares them.
TRUE_NARROWS = "true-narrows"
URL_PREFIXES = "url-prefixes"
COMMAND_PREFIXES = "command-prefixes"


class Floor(NamedTuple):
    """One option of a scanner that a config that is not the operator's may only narrow."""

    #: How the option narrows: one of the rule constants above.
    rule: str
    #: The plugin's own default, which is the operator's value where the operator
    #: sets none.
    default: Any
    #: The type a value read from a plugin's plain section is validated as.
    kind: Any
    #: The values a rule names, for the rules that name some.
    members: FrozenSet[str] = frozenset()


#: The floors, keyed by (scanner, option). A nested option is dotted. Each default
#: is the plugin's own, which ``tests/unit/config`` pins against its options model.
OPERATOR_FLOORS: Dict[Tuple[str, str], Floor] = {
    ("mcp-config", "forbid_privilege_escalation"): Floor(TRUE_NARROWS, True, bool),
    ("mcp-config", "forbid_unpinned_runners"): Floor(TRUE_NARROWS, True, bool),
    ("mcp-config", "forbid_auto_approval"): Floor(TRUE_NARROWS, True, bool),
    ("mcp-config", "flag_env_secrets"): Floor(TRUE_NARROWS, True, bool),
    ("mcp-config", "require_local"): Floor(TRUE_NARROWS, False, bool),
    ("mcp-config", "remote_url_prefixes"): Floor(URL_PREFIXES, [], List[str]),
    ("mcp-config", "allowed_command_prefixes"): Floor(COMMAND_PREFIXES, [], List[str]),
}

#: What ``_floored`` answers when the config's value already meets the floor.
_UNCHANGED = object()


def _keep_option_floors(
    config: "AshConfig", trusted_config: "AshConfig", landings: Sequence[Landing]
) -> List[str]:
    """Hold each floored option of the config to the operator's value; return what was named.

    The operator's value is read from the trusted base's section under either
    spelling of each key, and is the plugin's default where the operator sets none.
    A section or option the config leaves out takes the value the floor gives the
    default. A value the config wrote that a floor changes is named. A value either
    side holds that the scanner would refuse is left for the scanner.
    """
    from automated_security_helper.config.client_scanner_exclusions import (
        _scanner_sections,
    )

    ignored: List[str] = []
    extra = getattr(config.scanners, "__pydantic_extra__", None)
    for (scanner, option), floor in OPERATOR_FLOORS.items():
        parts = option.split(".")
        operator = _operator_value(trusted_config, scanner, parts, floor)
        if operator is _MISSING:
            continue
        sections = _scanner_sections(config, scanner)
        if not sections:
            new = _floored(floor, operator, copy.deepcopy(floor.default))
            if new is not _UNCHANGED and isinstance(extra, dict):
                extra[scanner] = {"options": _nested(parts, copy.deepcopy(new))}
            continue
        for key, section in sections:
            options = _options_of(section)
            if options is None:
                # A section with no options mapping reads as the plugin's defaults;
                # anything else is no section of options at all.
                if not (isinstance(section, dict) and section.get("options") is None):
                    continue
                holder, spelling, raw = None, None, _MISSING
            else:
                holder, spelling, raw = _locate(options, parts)
            path = ("scanners", key, "options", *parts)
            # A value an override the trusted base could not take set is the
            # operator's own; there is nothing of the base's to put in its place.
            if _covered(landings, path):
                continue
            current = _typed(floor, raw)
            if current is _MISSING:
                continue
            new = _floored(floor, operator, current)
            if new is _UNCHANGED:
                continue
            wrote = (
                spelling is not None
                if isinstance(holder, dict)
                else _file_wrote(config, path, raw)
            )
            if options is None:
                section["options"] = _nested(parts, copy.deepcopy(new))
            else:
                _put(options, parts, new)
            if wrote:
                ignored.append(f"scanners.{key}.options.{option}")
    return ignored


def _operator_value(
    trusted_config: "AshConfig", scanner: str, parts: Sequence[str], floor: Floor
) -> Any:
    """The operator's value of the option at ``parts``; _MISSING when it is one the scanner refuses."""
    value: Any = _options_mapping(
        trusted_config.get_plugin_config(PluginKind.SCANNER, scanner)
    )
    for part in parts:
        value = _trusted_option(value, part)
        if value is _MISSING:
            break
    return _typed(floor, value)


def _typed(floor: Floor, raw: Any) -> Any:
    """``raw`` as the floor's kind: the plugin's default where it holds no value,
    and _MISSING where the scanner would refuse the value it holds."""
    from pydantic import TypeAdapter, ValidationError

    if raw is _MISSING or raw is None:
        return copy.deepcopy(floor.default)
    try:
        return TypeAdapter(floor.kind).validate_python(raw)
    except ValidationError:
        return _MISSING


def _read(level: Any, spelling: str) -> Any:
    return level[spelling] if isinstance(level, dict) else getattr(level, spelling)


def _locate(options: Any, parts: Sequence[str]) -> Tuple[Any, Optional[str], Any]:
    """Where the option at ``parts`` is held under ``options``.

    Returns the mapping or model that holds the last part, the spelling it is held
    under, and its value. A plugin's dict holds either spelling of a key and a
    model holds the field by name. The holder is None when a level on the way is
    missing, and the spelling is None when the holder lacks the last part; the value
    is then _MISSING.
    """
    level = options
    for part in parts[:-1]:
        spellings = _spellings_in(level, part)
        child = _read(level, spellings[0]) if spellings else None
        if child is None:
            return None, None, _MISSING
        level = child
    spellings = _spellings_in(level, parts[-1])
    if not spellings:
        return level, None, _MISSING
    return level, spellings[0], _read(level, spellings[0])


def _put(options: Any, parts: Sequence[str], value: Any) -> None:
    """Set the option at ``parts`` under ``options`` to a copy of ``value``.

    A mapping level the option's path lacks is made; a model level cannot be.
    """
    level = options
    for part in parts[:-1]:
        spellings = _spellings_in(level, part)
        child = _read(level, spellings[0]) if spellings else None
        if child is None:
            if not isinstance(level, dict):
                return
            child = {}
            level[spellings[0] if spellings else part] = child
        level = child
    spellings = _spellings_in(level, parts[-1])
    _set(level, spellings[0] if spellings else parts[-1], copy.deepcopy(value), None)


def _nested(parts: Sequence[str], value: Any) -> Dict[str, Any]:
    for part in reversed(parts):
        value = {part: value}
    return value


def _floored(floor: Floor, operator: Any, current: Any) -> Any:
    """The value the config's ``current`` becomes under the operator's floor.

    ``_UNCHANGED`` when ``current`` already meets it. Values are compared as a
    config file spells them, so that 1 is not True.
    """
    if floor.rule == TRUE_NARROWS:
        new: Any = bool(operator) or bool(current)
    elif floor.rule == URL_PREFIXES:
        new = _narrowed(list(current), list(operator), _url_under)
    elif floor.rule == COMMAND_PREFIXES:
        new = _narrowed(list(current), list(operator), _command_under)
    else:
        raise ValueError(f"unknown floor rule {floor.rule!r}")
    return _UNCHANGED if _same_option_value(new, current) else new


def _narrowed(
    current: List[str],
    operator: List[str],
    under: Callable[[str, Sequence[str]], bool],
) -> List[str]:
    """A prefix list held to the operator's.

    An operator list that is empty accepts any list. A list that is empty, or has
    no entry under the operator's, takes the operator's: left empty it would turn
    the scanner's check off.
    """
    if not operator:
        return current
    if not current:
        return list(operator)
    kept = [entry for entry in current if under(entry, operator)]
    return kept or list(operator)


def _url_under(entry: str, operator: Sequence[str]) -> bool:
    """Whether the URL prefix ``entry`` is under one of the operator's.

    The scanner's own comparison (``check_remote``): both are normalized the way it
    does, with the scheme and host in lower case, and compared on a URL boundary.
    Every URL ``entry`` admits then starts with an operator prefix on a boundary
    too, so the operator's prefixes admit it.
    """

    def normalized(prefix: str) -> str:
        return (split_url(prefix) or ("", None, prefix))[2]

    return any(
        url_prefix_matches(normalized(entry), normalized(prefix)) for prefix in operator
    )


def _command_under(entry: str, operator: Sequence[str]) -> bool:
    """Whether the command prefix ``entry`` is under one of the operator's.

    A ``.`` prefix admits no command, so keeping it only narrows. Every command path
    the entry admits is the normalized entry or starts with it and a ``/``, which
    the operator's prefix then admits too.
    """
    path = posixpath.normpath(entry.replace("\\", "/"))
    return path == "." or any(
        command_prefix_matches(path, prefix) for prefix in operator
    )
