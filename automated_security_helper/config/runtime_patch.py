"""Runtime JSON-Patch overrides with allowlist enforcement.

This module is the security boundary for runtime config mutation issued through
the MCP streamable-HTTP transport. Callers pass a list of RFC 6902 JSON-Patch
ops; this module decides — based on `RuntimeOverridesConfig` — whether the
patch is permitted, and (if so) returns a freshly validated `AshConfig`.

Defense-in-depth checks (in order):

1. Allowlist must be `enabled` (default is False).
2. Patch document, serialized as JSON, must be <= 64 KiB.
3. `move` and `copy` ops are rejected outright (they let an attacker exfiltrate
   one part of the config into another, sidestepping path checks), and so is
   any op at the root pointer unless `allowed_paths` names the root
   explicitly: an op on the whole document sets, clears or reads every field
   at once, so no per-field rule in (5) or (6) can constrain it.
4. Each op's `path` must match at least one entry in `allowed_paths`.
5. Each op's `path` must NOT overlap any entry in `denied_paths`, which always
   holds `ALWAYS_DENIED_PATHS` whatever a profile lists (denied wins).
   Both sides denote subtrees, so an entry fires for three shapes of write:
   the pointer it names, anything below that pointer (`/-`, `/0`, a nested
   key), and any ancestor, because a write at an ancestor supplies or deletes
   the denied descendant along with everything else in that subtree.
6. For `add` / `replace` ops, the value must not match any regex in
   `denied_value_patterns` whose key overlaps the op's path under the same
   subtree reading as (5).
7. The result, after applying the patch, must validate as a full `AshConfig`.

A single failing op aborts the entire patch. The base config is never mutated.

A whole-document override (`select_profile(override_yaml=...)`) is gated by
`apply_runtime_override`, which expresses the override as the patch that turns
the base into it and sends that patch through `apply_runtime_patch`. There is no
second copy of these rules: an override is permitted exactly when that patch is.
"""

from __future__ import annotations

import copy
import fnmatch
import json
import re
import secrets
from dataclasses import replace
from typing import (
    AbstractSet,
    Any,
    Dict,
    FrozenSet,
    List,
    Mapping,
    NamedTuple,
    Optional,
    Pattern,
    Sequence,
    Set,
    Tuple,
)

import jsonpatch
from pydantic import ValidationError
from pydantic_core import to_jsonable_python

from automated_security_helper.config.ash_config import (
    ALWAYS_DENIED_PATHS,
    AshConfig,
    RuntimeOverridesConfig,
    plugin_key_lookup_names,
    reduced_plugin_name,
)
from automated_security_helper.config.environment_record import (
    ENVIRONMENT_VALUE_SHOWN,
    with_environment_values_shown,
)
from automated_security_helper.utils.error_text import error_text
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP

#: The always-denied entries that cover a whole scanner section
#: (``/scanners/<name>/**``). A scanner exclusion that resolution moves out of the
#: options is not refused by these alone (``_writes_a_moved_exclusion``,
#: ``config_document_denials``'s ``moved``); every other entry still applies to it,
#: an operator's own entry for the option among them.
SECTION_FLOOR_ENTRIES: FrozenSet[str] = frozenset(
    entry
    for entry in ALWAYS_DENIED_PATHS
    if re.fullmatch(r"/scanners/[^/*?\[\]]+/\*\*", entry)
)


_MAX_PATCH_BYTES = 64 * 1024
_FORBIDDEN_OPS = {"move", "copy"}

#: Where a configuration holds the policy these rules enforce.
_POLICY_PLACE = ("global_settings", "mcp", "runtime_overrides")


class _PolicyNames:
    """How a refusal names the policy's own entries: each ``denied_paths`` entry,
    and each ``denied_value_patterns`` key and regex.

    The policy is the operator's, and its file can read any of them from the
    environment, while the refusal goes to the MCP client. Each is named as the
    copy ``environment_record.with_environment_values_shown`` gives of the policy
    at its place in ``config`` (``AshConfig._environment_references``), so one read
    from the environment is ``<value>``, however short, and one the file wrote is
    named as it is. Without ``config`` there is no record of what came from the
    environment (``places_known`` is False), so every entry, key and regex is
    named ``<value>``, and an invalid regex's refusal gives re.error's position
    only. One exception in both modes: a ``denied_paths`` entry equal to one of
    ``RuntimeOverridesConfig()``'s own defaults is the shipped policy's text,
    published in the docs and the schema, so it is named as written, whether
    or not it was read from the environment. The mode that knows less names no
    entry differently from the one that knows where each came from.
    """

    def __init__(
        self, allowlist: RuntimeOverridesConfig, config: AshConfig | None
    ) -> None:
        self.places_known = config is not None
        self._paths: Dict[str, str]
        self._patterns: Dict[str, Tuple[str, str]]
        shipped = set(RuntimeOverridesConfig().denied_paths)
        if config is None:
            # No record of what came from the environment: the accessors answer
            # from these maps and their fallback alone, so nothing else is
            # built. Entries equal to the shipped defaults are named as
            # written; everything else falls back to ``<value>``.
            self._paths = {
                entry: entry for entry in allowlist.denied_paths if entry in shipped
            }
            self._patterns = {}
            return
        references = tuple(getattr(config, "_environment_references", ()) or ())
        # A reference sits at the index its file wrote the entry at. The list of
        # a policy ``client_config_policy.effective_policy`` returned starts with
        # the shipped defaults, which moves every entry the operator listed to a
        # later index, where no reference is. The operator's own list is kept on
        # that copy, in the order it was written, so it is what the references
        # are matched against. An entry of the policy that is not in it is a
        # shipped default, which the maps below name as written.
        listed = (
            getattr(allowlist, "_listed_denied_paths", None)
            if getattr(allowlist, "_effective", False)
            else None
        )
        denied_paths = list(allowlist.denied_paths if listed is None else listed)
        patterns = dict(allowlist.denied_value_patterns)
        # Each entry by its own index: an entry the file wrote that holds the
        # text of one read from the environment is named as written. Shown as
        # `<value>/...` beside the path the client's op quotes, it would tell the
        # client the value.
        shown = with_environment_values_shown(
            {"denied_paths": denied_paths, "denied_value_patterns": patterns},
            references,
            at=_POLICY_PLACE,
            exact_indices=True,
        )
        shown_paths = shown.get("denied_paths")
        if not (
            isinstance(shown_paths, list) and len(shown_paths) == len(denied_paths)
        ):
            # Not the copy of the list: name every entry as read from the
            # environment.
            shown_paths = [ENVIRONMENT_VALUE_SHOWN] * len(denied_paths)
        self._paths = {}
        for entry, shown_entry in zip(denied_paths, shown_paths):
            # A shipped default's text is public, wherever the entry came from.
            self._paths.setdefault(
                entry, entry if entry in shipped else str(shown_entry)
            )
        shown_patterns = shown.get("denied_value_patterns")
        if isinstance(shown_patterns, dict) and len(shown_patterns) == len(patterns):
            pairs = list(shown_patterns.items())
        else:
            pairs = [(ENVIRONMENT_VALUE_SHOWN, ENVIRONMENT_VALUE_SHOWN)] * len(patterns)
        self._patterns = {
            key: (str(shown_key), str(shown_pattern))
            for key, (shown_key, shown_pattern) in zip(patterns, pairs)
        }

    def _as_written_or_hidden(self, as_written: str) -> str:
        """``as_written`` where the maps were built from a config, else ``<value>``."""
        return as_written if self.places_known else ENVIRONMENT_VALUE_SHOWN

    def denied_path(self, entry: str) -> str:
        return self._paths.get(entry, self._as_written_or_hidden(entry))

    def pattern_path(self, key: str) -> str:
        return self._patterns.get(key, (self._as_written_or_hidden(key), ""))[0]

    def pattern(self, key: str, pattern: str) -> str:
        return self._patterns.get(key, ("", self._as_written_or_hidden(pattern)))[1]


class RuntimePatchDeniedError(Exception):
    """Raised when a runtime patch is rejected by the allowlist.

    The message names the op by its name and path (``_op_and_path``), never by
    its value: it reaches the client and the log, and an op can carry anything
    the client sends. ``op`` keeps the whole op for a caller that needs it.
    """

    def __init__(self, op: Dict[str, Any] | None, rule: str) -> None:
        self.op = op
        self.rule = rule
        named = "None" if op is None else _op_and_path(op)
        super().__init__(f"Patch op {named} denied by rule: {rule}")


def _op_and_path(op: Any) -> str:
    """``op`` as an error names it: its op name and its path, and nothing else."""
    if not isinstance(op, dict):
        return f"of type {type(op).__name__}"
    name, path = op.get("op"), op.get("path")
    named = repr(name) if isinstance(name, str) else "with no op name"
    return named + (f" at {path!r}" if isinstance(path, str) else " with no path")


def _unescape_pointer_segment(seg: str) -> str:
    """Unescape an RFC 6901 JSON-Pointer segment.

    Order matters: `~1` must decode to `/` and `~0` to `~`. Decoding `~0` first
    would turn the literal `~01` into `/` instead of the correct `~1`.
    """
    return seg.replace("~1", "/").replace("~0", "~")


def _path_segments(path: str) -> List[str]:
    """Split a JSON-Pointer path into segments and unescape per RFC 6901.

    Empty string means root.
    """
    if not path:
        return []
    if path[0] != "/":
        # JSON-Pointer paths must start with '/' (or be empty for root).
        return [_unescape_pointer_segment(path)]
    return [_unescape_pointer_segment(s) for s in path[1:].split("/")]


def _match_segments(pattern_segs: List[str], path_segs: List[str]) -> bool:
    """Match a glob pattern's segments against a path's segments.

    Rules:
      * `**` matches zero or more whole segments (greedy subtree wildcard).
      * `*` alone matches exactly one whole segment.
      * Otherwise the segment is fnmatch'd (so `aws_*` matches `aws_region`).
    """
    # Standard glob match with `**` support, as a forward pass over the
    # pattern: `positions` is every index of `path_segs` the pattern's
    # segments so far can have consumed up to. Iterative on purpose: the
    # recursive matcher this replaces ran one frame per segment and raised
    # RecursionError for a pointer with thousands of segments, which fits in
    # the 64 KiB a client may send, escaping the RuntimePatchDeniedError
    # contract with an uncaught exception.
    return _glob_positions(pattern_segs, path_segs, stop_at_end=False)


def _glob_positions(
    pattern_segs: List[str], path_segs: List[str], stop_at_end: bool
) -> bool:
    """The forward glob pass shared by `_match_segments` and
    `_pattern_reaches_into`.

    With `stop_at_end` False the pattern must consume exactly the path: True
    when, after every pattern segment, the path's end is a reachable position.
    With it True the pattern may run past the path: True as soon as the path's
    end is reachable, however many pattern segments are left (the pattern
    names the location or one beneath it).
    """
    end = len(path_segs)
    positions = {0}
    for segment in pattern_segs:
        if stop_at_end and end in positions:
            return True
        if segment == "**":
            # zero or more segments: every position at or after one reached.
            positions = set(range(min(positions), end + 1))
        elif segment == "*":
            positions = {j + 1 for j in positions if j < end}
        else:
            # Use fnmatch to support partial-segment globs like `aws_*`.
            positions = {
                j + 1
                for j in positions
                if j < end and fnmatch.fnmatchcase(path_segs[j], segment)
            }
        if not positions:
            return False
    return end in positions


def _pattern_reaches_into(pattern_segs: List[str], subtree_segs: List[str]) -> bool:
    """Test whether a pattern matches any location at or below a concrete path.

    `_match_segments` answers the narrower question "does this pattern match
    exactly this path", which is why a denylist built on it was not
    subtree-closed: the pattern still had segments left when the path ran out,
    so an entry naming a descendant never fired for a write at an ancestor.

    `subtree_segs` is a concrete path, not a pattern; only `pattern_segs` is
    globbed. The one difference from `_match_segments` is the end condition:
    once the pattern has consumed every segment of the concrete path it names
    this location or one beneath it, either way a location the write at
    `subtree_segs` reaches, however many pattern segments are left; a pattern
    exhausted while the path continues names a strict ancestor, outside the
    path's subtree. Iterative like `_match_segments`, and for the same reason.
    """
    return _glob_positions(pattern_segs, subtree_segs, stop_at_end=True)


def _path_matches(pattern: str, path: str) -> bool:
    """Test whether `path` matches a glob `pattern` under JSON-Pointer rules.

    Both pattern and path go through RFC 6901 unescape via `_path_segments`, so
    a pattern segment of `~1foo` correctly matches a path segment of `~1foo`
    (decoded to `/foo`), and `**` handles the `/-` array-append marker as a
    plain literal segment.
    """
    if pattern == path:
        return True
    return _match_segments(_path_segments(pattern), _path_segments(path))


def _subtree_pattern(pattern: str) -> List[str]:
    """Read a policy pattern as the subtree it names, not as one pointer."""
    return _path_segments(pattern) + ["**"]


def _policy_covers_op_path(pattern: str, path: str) -> bool:
    """Test whether a policy entry and an op's write can touch the same field.

    Both are read as subtrees, so this is true when the op writes at the
    pattern, anywhere below it, or at any ancestor of it. The ancestor
    direction is the one that matters most: `add` and `replace` at an existing
    object member replace that member's whole value (RFC 6902 4.1), and
    `remove` deletes it, so a write above a policy entry sets or clears that
    entry whether or not the op's value happens to mention it. That is why
    this predicate ignores the op's value -- a `replace` that omits a denied
    descendant still wipes it, and a `remove` carries no value at all.
    """
    return _pattern_reaches_into(_subtree_pattern(pattern), _path_segments(path))


def _fold_separators(pointer: str) -> str:
    """``pointer`` with every '-' read as '_'.

    Config merging treats a key spelled with '-' and the same key spelled with
    '_' as one key, one segment at a time (``config_sources._resolve_dict_key``),
    so a denial has to hold for every mix of the two. Replacing over the whole
    pointer is the same as replacing per segment: '/' separates segments, and
    the RFC 6901 escapes contain neither character.
    """
    return pointer.replace("-", "_")


_PLUGIN_SECTIONS = frozenset({"scanners", "reporters", "converters"})
_GLOB_CHARS = frozenset("*?[")
#: Config keys of the plugins in the packages under
#: ``automated_security_helper.plugin_modules``, per section. A table rather than
#: an import: importing a plugin package runs its code and registers its
#: plugins in the process-wide ``ash_plugin_manager`` for the rest of the
#: process, which checking a patch has no reason to do.
#: ``tests/unit/config/test_runtime_patch.py`` imports the packages in a
#: subprocess and checks this table against them.
_SHIPPED_PLUGIN_KEYS: Dict[str, FrozenSet[str]] = {
    "scanners": frozenset(
        {
            "actionlint",
            "bandit",
            "cdk-nag",
            "cfn-guard",
            "cfn-lint",
            "cfn-nag",
            "checkov",
            "detect-secrets",
            "ferret-scan",
            "gitleaks",
            "grype",
            "npm-audit",
            "opengrep",
            "semgrep",
            "snyk-code",
            "syft",
            "trivy",
            "trivy-repo",
            "zizmor",
        }
    ),
    "reporters": frozenset(
        {
            "aws-security-hub",
            "bedrock-summary-reporter",
            "cloudwatch-logs",
            "csv",
            "cyclonedx",
            "flat-json",
            "github-ghas",
            "gitlab-cyclonedx",
            "gitlab-sast",
            "html",
            "junitxml",
            "markdown",
            "ocsf",
            "s3",
            "sarif",
            "spdx",
            "text",
            "unused-suppressions",
            "yaml",
        }
    ),
    "converters": frozenset({"archive", "jupyter"}),
}

#: Config keys of known plugins, per plugin section.
PluginKeys = Mapping[str, AbstractSet[str]]


def known_plugin_keys(config: AshConfig | None = None) -> PluginKeys:
    """Config keys of the plugins a glob denial is matched over, per plugin section.

    The plugins that ship with ASH (``_SHIPPED_PLUGIN_KEYS``), the plugin
    sections' declared fields and their aliases, and the keys ``config``'s plugin
    sections already use. ``config`` is the trusted base a runtime patch applies
    to, so an operator who configures a plugin's section in the profile makes
    its key known. Nothing is imported, so building the set changes no plugin
    registration.

    A plugin outside this set (one from ``ash_plugin_modules`` or an installed
    plugin package whose section the profile does not configure) is covered by
    a glob denial only under a spelling the glob matches as written. A literal
    denial covers every spelling of it, since that needs no list of keys.
    """
    from automated_security_helper.config.ash_config import (
        ConverterConfigSegment,
        ReporterConfigSegment,
        ScannerConfigSegment,
    )

    keys: Dict[str, Set[str]] = {
        section: set(found) for section, found in _SHIPPED_PLUGIN_KEYS.items()
    }
    for section, model in (
        ("scanners", ScannerConfigSegment),
        ("reporters", ReporterConfigSegment),
        ("converters", ConverterConfigSegment),
    ):
        for name, field in model.model_fields.items():
            keys[section].add(name)
            if field.alias:
                keys[section].add(field.alias)
        if config is not None:
            keys[section] |= set(getattr(config, section).model_dump(by_alias=True))
    return keys


def _key_named_by(
    plugin: str, written: str, section: str, plugin_keys: PluginKeys
) -> str | None:
    """A config key that pattern segment ``plugin`` names and whose plugin reads ``written``.

    ``AshConfig.get_plugin_config`` gives a plugin the section under any key in
    ``plugin_key_lookup_names`` of its key, so ``BedrockSummary`` is read as
    ``bedrock-summary-reporter``'s config when no section uses that exact name. A
    literal segment names one key, itself, and needs no list. A glob names every
    key it matches, as written or with '-' read as '_', and those are looked for
    among ``plugin_keys``.
    """
    names = plugin_key_lookup_names(written)
    if not _GLOB_CHARS.intersection(plugin):
        reduced = reduced_plugin_name(plugin)
        return plugin if reduced and reduced in names else None
    folded_glob = _fold_separators(plugin)
    for key in sorted(plugin_keys.get(section, ())):
        if not (
            fnmatch.fnmatchcase(key, plugin)
            or fnmatch.fnmatchcase(_fold_separators(key), folded_glob)
        ):
            continue
        reduced = reduced_plugin_name(key)
        if reduced and reduced in names:
            return key
    return None


def _respellings(pattern: str, path: str, plugin_keys: PluginKeys) -> List[str]:
    """``path`` with its plugin segment spelled as a key ``pattern`` names, where one reads it.

    Respelling lets the usual matching run on a path the lookup would read as a
    plugin the pattern names. The pattern's section segment may be a glob too
    (``/*/trivy-repo/...``); each plugin section it matches is tried. A section
    segment of ``**`` is tried too: standing for the one section segment, it puts
    the pattern's next segment at the plugin key (``/**/trivy-repo/**``), and
    matched as written that segment reads the key in one spelling only. A plugin
    segment of ``*`` or ``**`` already matches every segment.
    """
    pattern_segs = _path_segments(pattern)
    path_segs = _path_segments(path)
    if len(pattern_segs) < 2 or len(path_segs) < 2:
        return []
    section_glob, plugin = pattern_segs[0], pattern_segs[1]
    section, written = path_segs[0], path_segs[1]
    if section not in _PLUGIN_SECTIONS or plugin in ("*", "**") or written == plugin:
        return []
    if not fnmatch.fnmatchcase(section, section_glob):
        return []
    key = _key_named_by(plugin, written, section, plugin_keys)
    if key is None or key == written:
        return []
    return [
        "/"
        + "/".join(
            _escape_pointer_segment(segment)
            for segment in [section, key, *path_segs[2:]]
        )
    ]


def _denial_spellings(
    pattern: str, path: str, plugin_keys: PluginKeys
) -> Tuple[Tuple[str, str], ...]:
    """The (pattern, path) pairs a denial is matched over.

    As written, then folded, then, when the path's plugin segment is read as a
    plugin the pattern names under another spelling, the respelled path as
    written and folded. As written comes first so a glob whose character class
    contains '-' keeps its meaning; every other pair only adds matches, so it
    can only refuse more.
    """
    pairs = [(pattern, path), (_fold_separators(pattern), _fold_separators(path))]
    for respelled in _respellings(pattern, path, plugin_keys):
        pairs.append((pattern, respelled))
        pairs.append((_fold_separators(pattern), _fold_separators(respelled)))
    return tuple(pairs)


def _denied_path_reason(
    denied: str, path: str, plugin_keys: PluginKeys, shown: str | None = None
) -> str | None:
    """Explain how a `denied_paths` entry blocks a write at `path`, or None.

    The refusal has to name the entry that caused it: subtree closure rejects
    writes that used to succeed, and an operator who set `/global_settings`
    wholesale cannot act on a message that does not say which descendant of it
    is off limits. It names the entry as ``shown`` (``_PolicyNames``), the
    entry itself when None.
    """
    named = denied if shown is None else shown
    for pattern, target in _denial_spellings(denied, path, plugin_keys):
        if not _policy_covers_op_path(pattern, target):
            continue
        if _path_matches(pattern, target):
            return f"path {path!r} matches denied_paths entry {named!r}"
        if _match_segments(_subtree_pattern(pattern), _path_segments(target)):
            return f"path {path!r} is inside denied_paths entry {named!r}"
        return (
            f"path {path!r} writes a subtree that contains denied_paths entry {named!r}"
        )
    return None


def _writes_a_moved_exclusion(op: Dict[str, Any]) -> bool:
    """Whether ``op`` only writes a scanner exclusion that resolution moves out of the options.

    An ``add`` or ``replace`` of an option in
    ``client_scanner_exclusions.SCANNER_EXCLUSION_OPTIONS`` (or, for a list
    option, of entries appended to it) whose value the move takes out whole
    (``moves_all_of``). Every route this gate guards leaves a client's change
    with the client: ``select_profile``'s ``patch_ops`` and ``override_yaml``
    write the session's client copy, and the workspace tools'
    ``config_overrides`` are resolved as the client's
    (``apply_client_config_rules``'s ``client_overrides``). Resolution then moves
    the entries out of the scanner's options before it runs, as it does for a
    delivered file, so the always-denied entries that cover a whole scanner
    section (``SECTION_FLOOR_ENTRIES``) do not refuse the op. ``allowed_paths``,
    every other ``denied_paths`` entry and the value patterns still apply.
    """
    from automated_security_helper.config.client_scanner_exclusions import (
        exclusion_option_at,
        moves_all_of,
    )

    if op.get("op") not in {"add", "replace"} or "value" not in op:
        return False
    located = exclusion_option_at(_path_segments(op.get("path", "")))
    if located is None:
        return False
    spec, entry = located
    return moves_all_of(spec, op["value"], entry=entry)


def _check_op_paths(
    op: Dict[str, Any],
    *,
    allowlist: RuntimeOverridesConfig,
    plugin_keys: PluginKeys,
    config: AshConfig | None,
    names: _PolicyNames | None,
) -> None:
    """Refuse *op* unless allowed_paths allows its path and no denied_paths entry
    covers it. ``config`` and ``names`` have no default, as check_runtime_ops'
    ``config`` has none: a caller with neither passes None for each, the
    degraded mode, on purpose."""
    path = op.get("path", "")
    if not any(_path_matches(p, path) for p in allowlist.allowed_paths):
        raise RuntimePatchDeniedError(op, f"path {path!r} not in allowed_paths")
    if _turns_an_off_host_reporter_off(op, config):
        return
    moved = _writes_a_moved_exclusion(op)
    if names is None:
        names = _PolicyNames(allowlist, config)
    # denied_paths always holds ALWAYS_DENIED_PATHS (RuntimeOverridesConfig's
    # validator adds any a profile's own list leaves out), the archive extraction
    # limits among them.
    for denied in allowlist.denied_paths:
        if moved and denied in SECTION_FLOOR_ENTRIES:
            continue
        reason = _denied_path_reason(
            denied, path, plugin_keys, names.denied_path(denied)
        )
        if reason is not None:
            raise RuntimePatchDeniedError(op, reason)


def _walk_string_leaves(value: Any, compiled: Pattern[str]) -> bool:
    """Recursively scan str leaves of a JSON-like value for a regex match.

    Returns True if any string leaf matches `compiled`. Lists and dicts are
    traversed; non-string scalars (None, bool, int, float) are skipped because
    the regex is defined over text.

    Walking the structure (instead of `json.dumps`-and-search) prevents an
    attacker from hiding a forbidden token in a list/dict value when the regex
    was intended for a flat string field.
    """
    if isinstance(value, str):
        return compiled.search(value) is not None
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(k, str) and compiled.search(k) is not None:
                return True
            if _walk_string_leaves(v, compiled):
                return True
        return False
    if isinstance(value, list):
        return any(_walk_string_leaves(item, compiled) for item in value)
    return False


def _check_value_pattern(
    op: Dict[str, Any],
    *,
    allowlist: RuntimeOverridesConfig,
    plugin_keys: PluginKeys,
    names: _PolicyNames | None,
) -> None:
    """Refuse an add or replace whose value a denied_value_patterns regex bound
    to its path matches. ``names`` has no default: None, on purpose, names
    every key and regex ``<value>``."""
    # `test` is read-only — it neither leaks data nor mutates state, so the
    # value-pattern denylist (which exists to block writing forbidden values)
    # does not apply.
    if op.get("op") not in {"add", "replace"}:
        return
    path = op.get("path", "")
    # Distinguish "value key missing" from "value: null". A missing key is
    # invalid for add/replace and will be rejected by jsonpatch later; an
    # explicit None can be a legitimate value to clear a field.
    if "value" not in op:
        return
    value = op["value"]
    # The keys are pointer *patterns*, so each one binds to a subtree rather
    # than to one exact pointer. An exact dict lookup on the op's own pointer
    # covered neither direction: a regex registered for a parent did not see a
    # value written at a child, and a value written at a parent carries every
    # child the regex was registered for.
    if names is None:
        names = _PolicyNames(allowlist, None)
    for pattern_path, pattern in allowlist.denied_value_patterns.items():
        if not any(
            _policy_covers_op_path(bound, target)
            for bound, target in _denial_spellings(pattern_path, path, plugin_keys)
        ):
            continue
        # Named by their place in the policy: either can be a value its file
        # read from the environment.
        shown_path = names.pattern_path(pattern_path)
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            # re.error's own text quotes a part of the pattern ("unknown group
            # name 'x'", "bad character range z-a"), and the refusal goes to the
            # client. A pattern the policy's file wrote whole is the operator's
            # text, so its reason is given; one with any part read from the
            # environment, or one checked with no record of where it came from,
            # gets the type and the position only. Not chained, so a traceback of
            # the refusal does not print that text either.
            written = (
                names.places_known and names.pattern(pattern_path, pattern) == pattern
            )
            reason = str(exc) if written else f"re.error at position {exc.pos}"
            raise RuntimePatchDeniedError(
                op,
                f"denied_value_patterns regex for {shown_path!r} is invalid: {reason}",
            ) from None
        if _walk_string_leaves(value, compiled):
            raise RuntimePatchDeniedError(
                op,
                f"value at {path!r} matches denied_value_patterns regex "
                f"{names.pattern(pattern_path, pattern)!r} bound to {shown_path!r}",
            )


class DocumentDenial(NamedTuple):
    """One field a config document sets that a denial refuses."""

    #: The field as the document spells it: dotted for a leaf, the pointer for a
    #: ``patch`` op.
    key: str
    #: The JSON pointer written.
    pointer: str
    #: Which rule refused it, and how.
    reason: str
    #: True for a ``patch`` op, which is refused whatever it writes.
    from_patch: bool


def _document_writes(document: Any) -> List[Tuple[str, Dict[str, Any], str]]:
    """The writes a config document makes, as (key, JSON-Patch op, kind).

    ``kind`` is "leaf" for a value the document sets, "key" for a mapping key it
    writes (the op's value is the key itself, so a value pattern sees keys as it
    does inside a patch op's value), and "patch" for a ``patch`` op, taken as
    written with a ``move``'s source as a ``remove`` and a ``test`` writing
    nothing. A mapping with nothing in it sets nothing. ``extends`` names bases,
    which are files of their own, so it is skipped.
    """
    from automated_security_helper.config.config_sources import (
        EXTENDS_KEY,
        PATCH_KEY,
    )

    writes: List[Tuple[str, Dict[str, Any], str]] = []

    def pointer_of(segments: List[str]) -> str:
        return "/" + "/".join(_escape_pointer_segment(s) for s in segments)

    def leaves(segments: List[str], value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if isinstance(key, str):
                    op = {
                        "op": "add",
                        "path": pointer_of([*segments, key]),
                        "value": key,
                    }
                    writes.append((".".join([*segments, key]), op, "key"))
                leaves([*segments, str(key)], child)
            return
        op = {"op": "add", "path": pointer_of(segments), "value": value}
        writes.append((".".join(segments), op, "leaf"))

    if not isinstance(document, dict):
        return writes
    for key, value in document.items():
        if key == EXTENDS_KEY:
            continue
        if key == PATCH_KEY:
            for op in value if isinstance(value, list) else []:
                if not isinstance(op, dict) or op.get("op") == "test":
                    continue
                if op.get("op") == "move" and isinstance(op.get("from"), str):
                    remove = {"op": "remove", "path": op["from"]}
                    writes.append((op["from"], remove, "patch"))
                if isinstance(op.get("path"), str):
                    writes.append((op["path"], op, "patch"))
            continue
        if isinstance(key, str):
            op = {"op": "add", "path": pointer_of([key]), "value": key}
            writes.append((key, op, "key"))
        leaves([str(key)], value)
    return writes


_PLUGIN_TYPES = {
    "scanners": "scanner",
    "reporters": "reporter",
    "converters": "converter",
}


def _walk(value: Any, segments: Sequence[str]) -> Tuple[bool, Any]:
    """The value under ``segments`` of ``value``, matching keys with '-' and '_' folded."""
    from automated_security_helper.config.config_sources import _resolve_dict_key

    for segment in segments:
        if not isinstance(value, dict):
            return False, None
        key = _resolve_dict_key(value, segment)
        if key not in value:
            return False, None
        value = value[key]
    return True, value


def _trusted_value(
    config: AshConfig, dump: Dict[str, Any], pointer: str, plugin_keys: PluginKeys
) -> Tuple[bool, Any]:
    """The value ``config`` has where ``pointer`` writes, as ASH would read it.

    Under a plugin section that is the section the plugin itself reads: the key
    names a plugin (as written, '-'/'_'-folded, or under a spelling the lookup
    reads), and ``config.get_plugin_config`` gives that plugin's section, the same
    function a scan uses. Where the key could name more than one plugin, every one
    has to agree. (False, None) when nothing is there, which counts as a change.
    """
    segments = _path_segments(pointer)
    if len(segments) < 2 or segments[0] not in _PLUGIN_TYPES:
        return _walk(dump, segments)
    section, written = segments[0], segments[1]
    from automated_security_helper.config.config_sources import _resolve_dict_key

    raw_section = dump.get(section)
    present: Dict[str, Any] = raw_section if isinstance(raw_section, dict) else {}
    folded = _resolve_dict_key(present, written)
    if folded in present:
        plugins = [folded]
    else:
        names = plugin_key_lookup_names(written)
        plugins = sorted(
            key
            for key in plugin_keys.get(section, ())
            if (reduced := reduced_plugin_name(key)) and reduced in names
        )
    found = []
    for plugin in plugins:
        read = config.get_plugin_config(_PLUGIN_TYPES[section], plugin)  # type: ignore[arg-type]
        found.append(_walk(_as_json(read) if read is not None else None, segments[2:]))
    if not found or not all(present_ for present_, _ in found):
        return False, None
    values = {json.dumps(value, sort_keys=True) for _, value in found}
    return (True, found[0][1]) if len(values) == 1 else (False, None)


def _as_json(value: Any) -> Any:
    """``value`` as it would read back from JSON, so a parsed file and a dump compare."""
    return json.loads(json.dumps(value, default=str))


def _covered(patterns: Sequence[str], pointer: str, plugin_keys: PluginKeys) -> bool:
    """Whether ``pointer`` is at or under one of ``patterns``, under every spelling."""
    return bool(pointer) and any(
        _path_matches(pattern, target)
        or _match_segments(_subtree_pattern(pattern), _path_segments(target))
        for each in patterns
        for pattern, target in _denial_spellings(each, pointer, plugin_keys)
    )


def _key_pattern_reason(
    pointer: str,
    key: str,
    allowlist: RuntimeOverridesConfig,
    plugin_keys: PluginKeys,
    names: _PolicyNames,
) -> str | None:
    """Which value pattern refuses mapping key ``key`` written at ``pointer``, or None.

    Only a pattern whose subtree contains ``pointer`` applies. A pattern bound
    below it describes the values under the key, not the key itself. Each
    pattern's key and regex are named as ``names`` gives them (``_PolicyNames``):
    either can be a value the policy's file read from the environment.
    """
    for pattern_path, pattern in allowlist.denied_value_patterns.items():
        if not _covered([pattern_path], pointer, plugin_keys):
            continue
        shown_path = names.pattern_path(pattern_path)
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            written = (
                names.places_known and names.pattern(pattern_path, pattern) == pattern
            )
            reason = str(exc) if written else f"re.error at position {exc.pos}"
            return (
                f"denied_value_patterns regex for {shown_path!r} is invalid: {reason}"
            )
        if compiled.search(key):
            return (
                f"key {key!r} at {pointer!r} matches denied_value_patterns regex "
                f"{names.pattern(pattern_path, pattern)!r} bound to {shown_path!r}"
            )
    return None


def config_document_denials(
    document: Any,
    *,
    allowlist: RuntimeOverridesConfig,
    config: AshConfig | None = None,
    exempt: Sequence[str] = (),
    inert: Sequence[str] = (),
    repeats_trusted: bool = False,
    moved: Sequence[str] = (),
) -> List[DocumentDenial]:
    """The fields ``document`` sets that ``allowlist``'s denials refuse.

    ``denied_paths`` and ``denied_value_patterns`` only, matched exactly as for a
    runtime patch op (every '-'/'_' mix and every spelling the plugin lookup
    reads, including through a glob). ``enabled`` and ``allowed_paths`` do not
    apply: a config file is not a runtime override, and those two decide which
    overrides a client may make at all.

    ``config`` is the trusted config. Its plugin sections add to the keys a glob
    denial is matched over, and a leaf whose value equals what ``config`` has at
    the same place (``_trusted_value``) changes nothing, so it is not refused: an
    ``ash config init`` file writes the defaults. With ``repeats_trusted`` (a
    session's client-patched profile, which is the trusted profile with the
    client's checked patch applied), neither is a mapping key ``config`` already
    has there, which a value pattern would otherwise refuse for every key the
    copy repeats. Any other document gets no such exemption: ``config`` is a full
    dump, so it has every key of ASH's schema. A ``patch`` op is refused whatever
    it writes.

    A write at or under a pattern in ``exempt`` is not checked against
    ``denied_paths``, though value patterns still apply to it. A write at or
    under a pattern in ``inert`` is not checked at all: it names a field with no
    effect in this document. A write at or under a pointer in ``moved`` is a
    scanner exclusion that resolution moves out of the options before any
    scanner runs (``client_scanner_exclusions.moved_exclusion_pointers``): the
    entries that cover a whole scanner section (``SECTION_FLOOR_ENTRIES``) do not
    refuse it, and every other entry and value pattern still does.
    """
    plugin_keys = known_plugin_keys(config)
    # The policy's entries as each refusal names them (``_PolicyNames``): a
    # denial's reason can reach the client that delivered the document.
    names = _PolicyNames(allowlist, config)
    dump = (
        _as_json(config.model_dump(mode="json", by_alias=True))
        if config is not None
        else None
    )
    # The leaves the trusted config read from the environment: never exempt by
    # equality, since a document that repeats such a value would learn, from
    # the absence of a refusal, that the value was right.
    environment_pointers = (
        _environment_read_pointers(config, dump)
        if config is not None and dump is not None
        else []
    )
    # A client-patched copy is the trusted profile written whole, so a leaf it
    # repeats can differ from ``dump`` only in how it is written: a defaulted key
    # the writer left out, a spelling the model normalizes. Such a leaf is also
    # compared as the model reads the whole document (validated, then dumped as
    # ``dump`` is), so a repeat in another serialization is not a change, while a
    # value the client changed still differs after validation. Read once, on the
    # first leaf that needs it (``read_tried``); a document the model refuses
    # leaves ``read`` None and gets no exemption.
    read: Optional[Tuple[AshConfig, Dict[str, Any]]] = None
    read_tried = False

    def as_read(pointer: str) -> Tuple[bool, Any]:
        nonlocal read, read_tried
        if not read_tried:
            read_tried = True
            try:
                validated = AshConfig.model_validate(document)
                read = (
                    validated,
                    _as_json(validated.model_dump(mode="json", by_alias=True)),
                )
            except Exception:  # noqa: BLE001 -- an unreadable copy is compared as written
                read = None
        if read is None:
            return False, None
        return _trusted_value(read[0], read[1], pointer, plugin_keys)

    denials: List[DocumentDenial] = []
    for key, op, kind in _document_writes(document):
        path = op["path"]
        if _covered(inert, path, plugin_keys):
            continue
        reason: str | None = None
        if kind == "key":
            reason = _key_pattern_reason(
                path, op["value"], allowlist, plugin_keys, names
            )
        else:
            if not _covered(exempt, path, plugin_keys):
                floor_lifted = kind == "leaf" and _covered(moved, path, plugin_keys)
                reason = next(
                    (
                        found
                        for denied in allowlist.denied_paths
                        if not (floor_lifted and denied in SECTION_FLOOR_ENTRIES)
                        and (
                            found := _denied_path_reason(
                                denied, path, plugin_keys, names.denied_path(denied)
                            )
                        )
                    ),
                    None,
                )
            if reason is None:
                try:
                    _check_value_pattern(
                        op, allowlist=allowlist, plugin_keys=plugin_keys, names=names
                    )
                except RuntimePatchDeniedError as exc:
                    reason = exc.rule
        if reason is None:
            continue
        if kind != "patch" and config is not None and dump is not None:
            present, value = _trusted_value(config, dump, path, plugin_keys)
            # A leaf whose trusted value came from the environment gets no
            # exemption in either comparison: an equal value there is the one
            # oracle a denied field must not answer.
            environment_read = kind != "key" and _covered(
                environment_pointers, path, plugin_keys
            )
            # Both comparisons are of JSON values (_same_json_value): Python's
            # == says True == 1 and 1 == 1.0, which exempted a write that
            # changes a denied leaf's type.
            if (
                present
                and not environment_read
                and (
                    (kind == "key" and repeats_trusted)
                    or (
                        kind != "key" and _same_json_value(value, _as_json(op["value"]))
                    )
                )
            ):
                continue
            if present and not environment_read and kind != "key" and repeats_trusted:
                read_present, read_value = as_read(path)
                if read_present and _same_json_value(value, read_value):
                    continue
        denials.append(DocumentDenial(key, path, reason, kind == "patch"))
    return denials


def _environment_read_pointers(config: AshConfig, dump: Dict[str, Any]) -> List[str]:
    """The JSON pointers, in ``dump``'s keys, of the values ``config``'s files read
    from the environment: the leaves ``config_document_denials``' repeat
    exemption never applies to.

    From the record's value rewrites (``_written_references``) and the
    references the load kept (``_environment_references``), each placed in the
    dump as a runtime patch's pointers name it (config_validator.dumped_path). A
    reference with no place in the dump names no leaf.
    """
    from automated_security_helper.config.config_validator import dumped_path

    paths: List[Tuple[Any, ...]] = []
    for rewrite in getattr(config, "_written_references", None) or []:
        if getattr(rewrite, "kind", None) == "value":
            paths.append(tuple(rewrite.path))
    for reference in getattr(config, "_environment_references", None) or ():
        if not getattr(reference, "key", False):
            paths.append(tuple(getattr(reference, "path", ()) or ()))
    pointers: List[str] = []
    for path in paths:
        if not path:
            continue
        at = dumped_path(config, dump, path)
        if at:
            pointers.append(
                "/" + "/".join(_escape_pointer_segment(str(segment)) for segment in at)
            )
    return list(dict.fromkeys(pointers))


def _built_in_reporter_names() -> frozenset:
    """``reduced_plugin_name`` of every section the reporters model declares.

    Those are ASH's built-in reporters, each of which writes its report on the
    host. Any other section is read by a reporter a plugin module brings: the
    AWS reporters, or another plugin's, which declares nothing about where it
    sends findings.
    """
    from automated_security_helper.config.ash_config import ReporterConfigSegment

    names = set()
    for field_name, field in ReporterConfigSegment.model_fields.items():
        for name in (field_name, field.alias):
            if name and reduced_plugin_name(name):
                names.add(reduced_plugin_name(name))
    return frozenset(names)


def _is_off_host_section(key: str) -> bool:
    """Whether reporters section ``key`` is not read as a built-in reporter's.

    ``get_plugin_config`` reads a section under any key in
    ``plugin_key_lookup_names``, so a spelling of a built-in reporter's name is
    that reporter's section, and every other key is some other reporter's.
    """
    return not plugin_key_lookup_names(key) & _built_in_reporter_names()


def _off_host_reporter_section(op: Dict[str, Any]) -> str | None:
    """The reporters section ``op`` writes or reads that only the operator may set, or None.

    An off-host reporter sends findings where its section says (a bucket, a log
    group, a Region, a profile), with the server's credentials, so a client that
    sets it can have them sent to itself, and one that reads it learns where the
    operator sends them. A section counts unless it is a built-in reporter's
    (``_is_off_host_section``), and every op on it counts.

    The reporters section, and the whole document, hold every section: an add or
    replace there counts when its value has such a section, a ``test`` there
    reads them all, and a ``remove`` of the reporters section clears them.
    """
    segments = _path_segments(op.get("path", ""))
    op_name = op.get("op")
    if not segments or segments == ["reporters"]:
        if op_name == "test":
            return "reporters"
        if op_name == "remove":
            return "reporters" if segments else None
        value = op.get("value")
        sections = (
            value.get("reporters")
            if not segments and isinstance(value, dict)
            else value
        )
        if isinstance(sections, dict):
            for key in sections:
                if isinstance(key, str) and _is_off_host_section(key):
                    return key
        return None
    if segments[0] != "reporters":
        return None
    return segments[1] if _is_off_host_section(segments[1]) else None


def _turns_an_off_host_reporter_off(
    op: Dict[str, Any], config: AshConfig | None
) -> bool:
    """Whether ``op`` only sets ``enabled: false`` on a reporter that sends findings off the host.

    The reporters in ``reporter_trust.REPORTER_ENABLED_DEFAULTS``, under any
    spelling the plugin lookup reads. It asks for nothing beyond the profile, so
    it is not refused under a ``denied_paths`` entry that covers it, as it is not
    in a delivered file (``client_config_policy._writes_a_tightening``). It does
    not take effect either: the client's copy of the profile is resolved against
    the registered profile, and ``reporter_trust`` takes ``enabled`` from that,
    with a warning naming the client's value. Two
    shapes: an ``add`` or ``replace`` of ``/reporters/<name>/enabled`` with
    ``false``, and an ``add`` of ``/reporters/<name>`` whose value holds only
    ``enabled: false`` where ``config`` has no section for that reporter, which
    is how ``json_patch_between`` writes a section the base lacks. Anything else
    (``remove``, ``true``, a section with other keys) is checked as before.

    False without ``config``: the exemption holds because the caller drops the
    op, and each caller that does passes the config it drops it from. A caller
    with none would apply what this accepted.
    """
    from automated_security_helper.config.reporter_trust import (
        REPORTER_ENABLED_DEFAULTS,
        _sections_of,
        turns_a_reporter_off,
    )

    if config is None:
        return False
    if op.get("op") not in {"add", "replace"} or "value" not in op:
        return False
    segments = _path_segments(op.get("path", ""))
    if len(segments) not in (2, 3) or segments[0] != "reporters":
        return False
    names = plugin_key_lookup_names(segments[1])
    reporter = next(
        (r for r in REPORTER_ENABLED_DEFAULTS if reduced_plugin_name(r) in names),
        None,
    )
    if reporter is None:
        return False
    value = op["value"]
    if len(segments) == 3:
        return segments[2] == "enabled" and turns_a_reporter_off(value)
    return (
        op.get("op") == "add"
        and not _sections_of(config, reporter)
        and isinstance(value, dict)
        and list(value) == ["enabled"]
        and turns_a_reporter_off(value["enabled"])
    )


def _without_turn_offs(
    patch_ops: List[Dict[str, Any]], config: AshConfig | None, warn: bool = True
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """``patch_ops`` split into the ops to apply and the turn-offs dropped.

    Each dropped op is named in a warning, unless ``warn`` is False (for a
    caller that has already split the same ops once).
    """
    kept: List[Dict[str, Any]] = []
    dropped: List[Dict[str, Any]] = []
    for op in patch_ops:
        if not _turns_an_off_host_reporter_off(op, config):
            kept.append(op)
            continue
        dropped.append(op)
        if warn:
            ASH_LOGGER.warning(
                f"Ignoring '{op.get('path', '')}' from the MCP client: that reporter "
                "sends findings off the host, so only the operator's configuration "
                "turns it on or off; the session keeps the operator's setting.",
                extra=NO_MARKUP,
            )
    return kept, dropped


def _check_off_host_reporter(op: Dict[str, Any]) -> None:
    section = _off_host_reporter_section(op)
    if section is None:
        return
    raise RuntimePatchDeniedError(
        op,
        f"path {op.get('path', '')!r} reaches the {section!r} reporters section: a "
        f"reporter that is not one of ASH's built-in reporters can send the "
        f"findings off the host, to wherever its section says, so only the "
        f"operator's own configuration sets that section, whatever allowed_paths "
        f"permits",
    )


def check_runtime_ops(
    patch_ops: List[Dict[str, Any]],
    *,
    allowlist: RuntimeOverridesConfig,
    config: AshConfig | None,
) -> None:
    """Enforce the runtime allowlist on JSON-Patch ops without applying them.

    The rules ``apply_runtime_patch`` applies before it patches anything, for a
    caller that needs the verdict on each op whatever the op would change, such
    as ``cli/mcp/workspace._gate_client_overrides``. Raises
    ``RuntimePatchDeniedError`` on the first op a rule refuses. ``config`` is the
    config the ops would apply to, when there is one: its plugin sections and
    plugin modules add to the plugin keys a glob denial is matched over
    (``known_plugin_keys``), an op that only turns an off-host reporter off is
    accepted (``_turns_an_off_host_reporter_off``), and the caller does not
    apply it. A refusal names a policy entry the config's files read from the
    environment as ``<value>`` (``_PolicyNames``). ``config`` has no default: a
    caller with none passes ``None`` deliberately, and every policy entry, key
    and regex is then named ``<value>`` in refusals. In both modes a
    ``denied_paths`` entry equal to one of the shipped defaults, whose text is
    public, is named as written. A config whose files write a key as a
    reference where it has built-in keys refuses every op, first
    (``_refuse_a_profile_whose_key_can_name_a_built_in``).
    """
    if config is not None:
        _refuse_a_profile_whose_key_can_name_a_built_in(config)
    _refuse_a_malformed_op(patch_ops)
    if not allowlist.enabled:
        raise RuntimePatchDeniedError(
            None, "runtime overrides disabled (allowlist.enabled is False)"
        )

    # Defense-in-depth size cap. The PRIMARY limit on patch size must be
    # enforced upstream at HTTP-body-parse time (the transport should refuse
    # oversized bodies before they ever reach this function). This check
    # exists so a misconfigured transport, an in-process caller, or a future
    # alternate transport can never bypass the bound.
    serialized = json.dumps(patch_ops).encode("utf-8")
    if len(serialized) > _MAX_PATCH_BYTES:
        raise RuntimePatchDeniedError(
            None,
            f"patch size {len(serialized)} bytes exceeds 64 KiB limit",
        )

    plugin_keys = known_plugin_keys(config)
    # The policy's entries as a refusal names them (``config``'s copy of it).
    names = _PolicyNames(allowlist, config)
    for op in patch_ops:
        op_name = op.get("op")
        if op_name in _FORBIDDEN_OPS:
            raise RuntimePatchDeniedError(
                op, f"op type {op_name!r} is forbidden (move/copy)"
            )
        # An op at the root pointer addresses the whole document: `replace`
        # and `add` set every denied field at once, `remove` clears them, and
        # `test` turns the whole config into an equality oracle. No per-field
        # rule constrains any of those. The allowlist does not keep the root
        # out on its own either: `**` matches zero segments, so the
        # conventional `/**` entry matches the empty root path, and only an
        # entry naming the root literally counts as asking for it. A missing
        # `path` key resolves here too -- `path` is mandatory on every op this
        # module accepts, so a malformed op is refused rather than treated as
        # an empty path.
        if op.get("path", "") == "" and "" not in allowlist.allowed_paths:
            raise RuntimePatchDeniedError(
                op,
                "path '' is the root pointer: an op on the whole config is "
                "refused unless allowed_paths names '' explicitly",
            )
        _check_op_paths(
            op,
            allowlist=allowlist,
            plugin_keys=plugin_keys,
            config=config,
            names=names,
        )
        _check_value_pattern(
            op, allowlist=allowlist, plugin_keys=plugin_keys, names=names
        )
        # A client's enabled: false of an AWS reporter asks for nothing beyond
        # the profile and takes no effect (_turns_an_off_host_reporter_off), so
        # this rule leaves it alone, as denied_paths does.
        if not _turns_an_off_host_reporter_off(op, config):
            _check_off_host_reporter(op)


def apply_runtime_patch(
    base: AshConfig,
    patch_ops: List[Dict[str, Any]],
    *,
    allowlist: RuntimeOverridesConfig,
) -> AshConfig:
    """Apply a JSON-Patch to a config, enforcing the runtime allowlist.

    Returns a new `AshConfig`. The base instance is never mutated. Any rule
    violation raises `RuntimePatchDeniedError` and aborts the entire patch. An op
    that only turns an off-host reporter off is not applied, with a warning
    (``_turns_an_off_host_reporter_off``).
    """
    # First: every other rule names the op's path, and an override's ops name
    # the profile's own keys.
    _refuse_a_profile_whose_key_can_name_a_built_in(base)
    _refuse_a_malformed_op(patch_ops)
    _refuse_a_key_read_from_the_environment(base, patch_ops)
    check_runtime_ops(patch_ops, allowlist=allowlist, config=base)
    patch_ops, _ = _without_turn_offs(patch_ops, base)

    # One op at a time, in order, as jsonpatch applies a patch, so a refusal can
    # name its op. The base is never touched: each op applies to a copy.
    from automated_security_helper.config.config_validator import (
        environment_record_of_references,
    )

    patched: Any = base.model_dump(mode="python", by_alias=False)
    references = _ReferencesThroughPatch(base, patched)
    # The references the configuration keeps for its views and its session
    # copies, followed through the same ops (they are not the rewrites above).
    environment_references = tuple(getattr(base, "_environment_references", ()) or ())
    followed = _ReferencesThroughPatch(
        base,
        patched,
        items=environment_record_of_references(environment_references)[1],
        strict=False,
    )
    for op in patch_ops:
        if _goes_into_text(op.get("path", ""), patched):
            # jsonpointer indexes a string like a list, so a test op there
            # compares one character: the refusal is the same whatever the op's
            # value, and no op is applied.
            raise RuntimePatchDeniedError(op, INTO_TEXT_REFUSAL)
        references.refuse_a_write_over(op)
        references.follow(op, patched)
        followed.follow(op, patched)
        failure = None
        try:
            if op.get("op") == "test":
                # Against the configuration as written: a setting read from the
                # environment holds the reference its file wrote, so a test op
                # answers whether the client wrote that reference, never
                # whether it guessed the value. And as JSON, the form the op's
                # own value has: the dump is a Python one, where a date or a
                # path an operator's file set is an object no JSON value equals.
                jsonpatch.apply_patch(
                    to_jsonable_python(_as_written(base, references.rewrites, patched)),
                    [op],
                    in_place=False,
                )
            else:
                patched = jsonpatch.apply_patch(patched, [op], in_place=False)
        except (
            jsonpatch.JsonPatchException,
            jsonpatch.JsonPointerException,
            TypeError,
            ValueError,
        ) as exc:
            failure = type(exc).__name__
        if failure is not None:
            # The class only, and raised here, not in the except block, so the
            # refusal carries no error as its context: jsonpatch's text quotes
            # the configuration (a failed test's current value, the whole
            # mapping a missing member was looked for in), which can hold values
            # its files read from the environment, and the MCP tools return
            # this message to the client.
            raise RuntimePatchDeniedError(op, f"patch apply failed: {failure}")
        # After each op, so the next test op compares with the references
        # still standing: one an op wrote over is the client's text.
        references.track(op)
        references.settle()
        followed.track(op)
        followed.settle()

    try:
        rebuilt = AshConfig.model_validate(patched)
    except ValidationError as exc:
        # error_text: each entry of errors() holds the refused input, and the
        # MCP tool returns this message to the client.
        raise RuntimePatchDeniedError(
            None, f"patched config failed validation: {error_text(exc)}"
        ) from exc
    # The base with the client's ops, so it keeps what the base's load recorded:
    # the values its files read from the environment and the reference each was
    # written as (AshConfig's private attributes), as apply_config_overrides
    # does. A value the ops changed no longer equals the one read, and is
    # recorded as the client wrote it.
    rebuilt.__pydantic_private__ = copy.deepcopy(base.__pydantic_private__)
    if references.rewrites is not None:
        rebuilt._written_references = references.rewrites
    if environment_references:
        rebuilt._environment_references = followed.references_in(
            environment_references, patched
        )
        rebuilt._references_followed = True
    return rebuilt


#: The refusal of an op that is not a JSON-Patch op: not a mapping, an ``op``
#: that is none of RFC 6902's six, or a ``path`` member that is not a string.
#: The class jsonpatch gives such an op, so every malformed op is refused alike,
#: whichever member is wrong.
MALFORMED_OP_REFUSAL = "patch apply failed: InvalidJsonPatch"

#: RFC 6902's ops, as it spells them.
_JSON_PATCH_OPS = frozenset({"add", "remove", "replace", "move", "copy", "test"})


def _refuse_a_malformed_op(patch_ops: List[Dict[str, Any]]) -> None:
    """Refuse a patch with an op that is not a mapping, whose ``op`` is none of
    RFC 6902's six (another case, another name, or none), or whose ``path``
    member is there and is not a string.

    Every rule reads those members as strings: a path that is a number, a list
    or a mapping raised TypeError, AttributeError or KeyError out of the first
    rule that split it, and a null path read as the root. An op name jsonpatch
    does not take (``ADD``, ``merge``) would go through every rule before
    jsonpatch refused it. Checked before any rule reads an op. A missing
    ``path`` is the root, which its own rule refuses (check_runtime_ops).
    """
    for op in patch_ops:
        if (
            not isinstance(op, dict)
            # A string first: a list or a mapping cannot be looked up in a set.
            or not isinstance(op.get("op"), str)
            or op["op"] not in _JSON_PATCH_OPS
            or ("path" in op and not isinstance(op["path"], str))
        ):
            raise RuntimePatchDeniedError(op, MALFORMED_OP_REFUSAL)


#: The refusal of an op whose path goes into a text setting's characters.
INTO_TEXT_REFUSAL = (
    "the path goes into the characters of a text setting; a patch op names "
    "whole settings"
)

#: A JSON-Pointer list index: ASCII digits. str.isdigit is true for "²" too,
#: which int() then refuses.
_LIST_INDEX = re.compile(r"[0-9]+")


def _goes_into_text(path: str, document: Any) -> bool:
    """Whether ``path``, a JSON-Pointer into ``document``, takes a step from a
    string: past a text setting, into its characters. A path that ends at a
    string names the whole setting and is not."""
    node = document
    for segment in _path_segments(path):
        if isinstance(node, str):
            return True
        if isinstance(node, dict):
            if segment not in node:
                return False
            node = node[segment]
        elif isinstance(node, list):
            if not _LIST_INDEX.fullmatch(segment) or int(segment) >= len(node):
                return False
            node = node[int(segment)]
        else:
            return False
    return False


def _as_written(base: AshConfig, rewrites: Any, document: Any) -> Any:
    """``document`` with each value and key the base read from the environment
    as its file wrote it (record_of_config), at the locations ``rewrites``, the
    base's references as the ops so far moved them, name."""
    from automated_security_helper.config.config_validator import record_of_config

    if not rewrites:
        return document
    shim = base.model_copy()
    shim._written_references = list(rewrites)
    return record_of_config(shim, document)


class _ReferencesThroughPatch:
    """The base's references (``_written_references``) as the ops move them.

    A rewrite names a list entry by its index. An op that adds an entry at an
    index, or removes one, moves every entry after it, and the rewrite has to
    follow its entry: left at the old index, it named another entry, and the
    one the profile read from the environment was written into the session
    config as its value (config_writer). A rewrite whose entry is removed is
    dropped. Ops are followed in order, each against the document before it
    applies, as jsonpatch applies them. An append (``-``) moves nothing.

    Where each value goes is also tracked on its own (track, settle): a copy of
    the dump holds a token in place of each string a rewrite locates, and the
    same ops apply to it, so where a token is after the ops is where its value
    is. A rewrite whose token an op wrote over is dropped: that location holds
    the client's text, written and shown as the client wrote it whether or not
    it equals the value, so neither tells a right guess from a wrong one. A
    key's rewrite is dropped likewise when an op replaced the mapping holding
    the key. A token found anywhere but where its rewrite was followed to
    refuses the patch, rather than write the value there as text. Nothing else
    is compared: a default, or any other string equal to a value, is not one of
    the profile's values.

    ``items`` are the rewrites to follow where they are not the base's own
    (``references_in`` follows the configuration's references this way), and
    ``strict`` False drops a value that moved where its reference did not follow
    instead of refusing the patch: the other rewrites already refuse it.
    """

    def __init__(
        self,
        base: AshConfig,
        dumped: Any,
        items: Optional[List[Any]] = None,
        strict: bool = True,
    ) -> None:
        from automated_security_helper.config.config_validator import dumped_path

        rewrites = list(
            items
            if items is not None
            else getattr(base, "_written_references", None) or []
        )
        self._strict = strict
        #: None when the base has no references to follow.
        self.rewrites: List[Any] | None = rewrites or None
        # Each rewrite's path in the dump's keys, which an op's pointer names.
        self._where = [dumped_path(base, dumped, rewrite.path) for rewrite in rewrites]
        # Each rewrite's position in the base's list, kept as rewrites drop.
        self._ids = list(range(len(rewrites)))
        self._shadow: Any = copy.deepcopy(dumped) if rewrites else None
        self._tokens: Dict[str, int] = {}
        self._holders: Dict[int, Any] = {}
        #: The dump paths of the values read from the environment that a model
        #: typed (a number, a true/false value): no string token can stand in
        #: for one, so an op that writes over one is refused instead
        #: (refuse_a_write_over).
        self._typed: List[Tuple[str, ...]] = []
        self._lost = False
        for ident, (rewrite, at) in enumerate(zip(rewrites, self._where)):
            if at is None:
                continue
            if rewrite.kind == "value" and at:
                container = _node_at(self._shadow, at[:-1])
                if _holds_text(container, at[-1]):
                    # Unique to this patch, so no client string is one.
                    token = f"ash-reference-{secrets.token_hex(16)}"
                    container[at[-1]] = token
                    self._tokens[token] = ident
                elif _holds_a_typed_value(container, at[-1]):
                    self._typed.append(tuple(str(part) for part in at))
            elif rewrite.kind == "key":
                holder = _node_at(self._shadow, at)
                if isinstance(holder, dict):
                    self._holders[ident] = holder

    def refuse_a_write_over(self, op: Dict[str, Any]) -> None:
        """Refuse ``op`` when it writes over a value the base read from the
        environment that a model typed (a number, a true/false value), or
        removes or replaces what holds one.

        Such a value carries no token: the tokens are strings, and a number is
        not one. Followed through the patch, its rewrite was kept whatever an
        op wrote at its place, so the session copy wrote the profile's reference
        where the client's own number stood, and a test op against the written
        form answered for the client's value. An op whose path is the leaf, or
        a place above it (a mapping or list entry that holds it, replaced or
        removed whole), is refused outright; a move's source is such a path too.
        Only the strict tracker refuses: the lenient one follows the
        configuration's own references, which the strict one already guards.
        """
        if not self._strict or not self._typed:
            return
        if op.get("op") not in ("add", "replace", "remove", "move", "copy"):
            return
        pointers = [op.get("path", "")]
        if op.get("op") == "move":
            pointers.append(op.get("from", ""))
        for pointer in pointers:
            if not isinstance(pointer, str):
                continue
            segments = _path_segments(pointer)
            for at in self._typed:
                if list(at[: len(segments)]) == segments:
                    raise RuntimePatchDeniedError(
                        op, TYPED_VALUE_READ_FROM_THE_ENVIRONMENT_REFUSAL
                    )

    def track(self, op: Dict[str, Any]) -> None:
        """Apply ``op``, which applied to the configuration, to the copy with
        the tokens. A test op changes nothing."""
        if self._shadow is None or op.get("op") == "test":
            return
        try:
            self._shadow = jsonpatch.apply_patch(
                self._shadow, [copy.deepcopy(op)], in_place=True
            )
        except (
            jsonpatch.JsonPatchException,
            jsonpatch.JsonPointerException,
            IndexError,
            KeyError,
            TypeError,
            ValueError,
        ):
            # Where the configuration took the op and the copy did not, the
            # values can no longer be located: settle refuses the patch.
            self._lost = True

    def settle(self) -> None:
        """Keep the rewrites whose value or key is where they were followed to,
        drop those an op wrote over, and refuse the patch when a value is
        anywhere else."""
        if self._shadow is None or self.rewrites is None:
            return
        landed: Dict[int, Tuple[Any, ...]] = {}
        held: Dict[int, Tuple[Any, ...]] = {}
        holder_ids = {id(holder): ident for ident, holder in self._holders.items()}

        def walk(node: Any, path: Tuple[Any, ...]) -> None:
            if isinstance(node, str):
                if node in self._tokens:
                    landed[self._tokens[node]] = path
            elif isinstance(node, dict):
                if id(node) in holder_ids:
                    held[holder_ids[id(node)]] = path
                for key, value in node.items():
                    walk(value, (*path, key))
            elif isinstance(node, list):
                for index, value in enumerate(node):
                    walk(value, (*path, index))

        walk(self._shadow, ())
        valued = set(self._tokens.values())
        moved = self._lost
        rewrites, where, ids = [], [], []
        for rewrite, at, ident in zip(self.rewrites, self._where, self._ids):
            tracked = landed if ident in valued else held
            if ident in valued or ident in self._holders:
                if ident not in tracked:
                    continue
                if tracked[ident] != at:
                    moved = True
                    continue
            rewrites.append(rewrite)
            where.append(at)
            ids.append(ident)
        # A value whose rewrite was dropped with its entry, still in the
        # configuration.
        if any(ident not in ids for ident in landed):
            moved = True
        if moved and self._strict:
            raise RuntimePatchDeniedError(None, MOVED_WITHOUT_ITS_REFERENCE)
        self.rewrites, self._where, self._ids = rewrites, where, ids

    def references_in(self, references: Sequence[Any], dumped: Any) -> Tuple[Any, ...]:
        """``references``, the base's, as the ops left them: each one whose value
        or key was not written over, at the place it was followed to, and with the
        length of the list it stands in as ``dumped`` now has it.

        What a session copy is written from, so that a client's string equal to a
        value, at the entry a reference stood at or anywhere else, is written as
        the client wrote it, and the reference is written at its own entry.
        """
        if self.rewrites is None:
            return ()
        followed = []
        for ident, rewrite, at in zip(self._ids, self.rewrites, self._where):
            reference = references[ident]
            length = reference.length
            if length is not None and reference.index_at is not None and at:
                holder = _node_at(dumped, at[: reference.index_at])
                if isinstance(holder, list):
                    length = len(holder)
            followed.append(replace(reference, path=rewrite.path, length=length))
        return tuple(followed)

    def follow(self, op: Dict[str, Any], document: Any) -> None:
        if self.rewrites is None or op.get("op") not in ("add", "remove"):
            return
        segments = _path_segments(op.get("path", ""))
        if not segments or not _LIST_INDEX.fullmatch(segments[-1]):
            return
        depth = len(segments) - 1
        parent: Any = document
        for segment in segments[:-1]:
            if isinstance(parent, dict) and segment in parent:
                parent = parent[segment]
            elif (
                isinstance(parent, list)
                and _LIST_INDEX.fullmatch(segment)
                and int(segment) < len(parent)
            ):
                parent = parent[int(segment)]
            else:
                return
        if not isinstance(parent, list):
            return
        index = int(segments[-1])
        rewrites, where, ids = [], [], []
        for rewrite, at, ident in zip(self.rewrites, self._where, self._ids):
            if (
                at is None
                or len(at) <= depth
                or [str(part) for part in at[:depth]] != segments[:depth]
                or not isinstance(at[depth], int)
            ):
                rewrites.append(rewrite)
                where.append(at)
                ids.append(ident)
                continue
            entry = at[depth]
            if op["op"] == "remove" and entry == index:
                continue
            if op["op"] == "add" and entry >= index:
                entry += 1
            elif op["op"] == "remove" and entry > index:
                entry -= 1
            rewrites.append(
                rewrite._replace(
                    path=rewrite.path[:depth] + (entry,) + rewrite.path[depth + 1 :]
                )
            )
            where.append(at[:depth] + (entry,) + at[depth + 1 :])
            ids.append(ident)
        self.rewrites, self._where, self._ids = rewrites, where, ids


#: The refusal of an op through a key of a mapping whose keys the profile read
#: from the environment. One text, naming neither the op nor the mapping: an
#: override's ops name the profile's own keys.
KEY_READ_FROM_THE_ENVIRONMENT_REFUSAL = (
    "the path goes through a key of a mapping that holds a key the profile read "
    "from the environment; only a key the profile writes as text can be patched "
    "there"
)

#: The refusal of an op that writes over a value the profile read from the
#: environment and a model typed (a number, a true/false value), or replaces or
#: removes what holds one. It names no value or location.
TYPED_VALUE_READ_FROM_THE_ENVIRONMENT_REFUSAL = (
    "the path writes over a value the profile read from the environment that is "
    "not text, or replaces what holds it; such a value cannot be followed "
    "through a patch, so nothing at or above it can be patched"
)

#: The refusal of an op that adds or removes a list entry above a mapping that
#: holds a key the profile read from the environment, which would move the
#: mapping to another index. It names no value or location.
LIST_SHIFT_ABOVE_A_KEY_READ_FROM_THE_ENVIRONMENT_REFUSAL = (
    "the path adds or removes an entry of a list that holds a mapping with a "
    "key the profile read from the environment, which would move that mapping "
    "to another index; such a list cannot be patched at an index"
)

#: The refusal of every op on a profile that reads a key from the environment
#: where the configuration has built-in keys. One text, naming no key or value:
#: the profile's keys are answered the same whatever the variable holds.
PROFILE_KEY_CAN_NAME_A_BUILT_IN_REFUSAL = (
    "the profile reads a key from the environment in a mapping that has "
    "built-in keys, which the key can name; a patch, an override or a test op "
    "on that profile is refused"
)


#: A mapping of a profile that holds a key its file writes as a reference: its
#: path in the dump's keys (None where it has no place), the keys the files
#: write there as text, and the part of the configuration there.
_KeyedMapping = Tuple[Optional[Tuple[str, ...]], FrozenSet[str], Any]


def _mappings_holding_a_key_read_from_the_environment(
    base: AshConfig,
) -> Tuple[Any, List[_KeyedMapping]]:
    """``base``'s dump, and each of its mappings where its files write a key as
    a reference, whether or not the variable is set and whatever it holds.

    From the files as written (``_written_key_mappings``), not from what was
    read: an unset variable's key is its default, and a key that resolves to one
    the file writes as text merges with it, so neither is a key the record
    (``_written_references``) holds, and a rule reading the record would answer
    by the variable's value. Each key the record holds counts as well, for a
    configuration not loaded through load_config_file_for_run. No dump and no
    mapping where the profile writes no such key.
    """
    from automated_security_helper.config.config_validator import dumped_place

    written = list(getattr(base, "_written_key_mappings", None) or ())
    written += [
        (rewrite.path, frozenset())
        for rewrite in getattr(base, "_written_references", None) or []
        if rewrite.kind == "key"
    ]
    if not written:
        return None, []
    dumped = base.model_dump(mode="python", by_alias=False)
    found: List[_KeyedMapping] = []
    for path, text_keys in written:
        placed = None if path is None else dumped_place(base, dumped, tuple(path))
        if placed is None:
            found.append((None, frozenset(text_keys), None))
            continue
        where, part = placed
        found.append(
            (tuple(str(segment) for segment in where), frozenset(text_keys), part)
        )
    return dumped, found


def _has_built_in_keys(mapping: Optional[Tuple[str, ...]], part: Any) -> bool:
    """Whether the configuration has keys of its own at ``mapping``, which a key
    read from the environment there can name: a model's fields (a plugin
    section, a list entry such as a suppression), or a default with keys. Only
    a plain mapping with no default keys, an option of a plugin ASH does not
    ship, has none; a mapping with no place counts as having them."""
    # A model (a pydantic BaseModel) is not a dict.
    if mapping is None or not isinstance(part, dict):
        return True
    default = _node_at(AshConfig().model_dump(mode="python", by_alias=False), mapping)
    return isinstance(default, dict) and bool(default)


def _refuse_a_profile_whose_key_can_name_a_built_in(base: AshConfig) -> None:
    """Refuse every op on a profile whose file writes a key as a reference
    (``${VAR}`` or ``${VAR:default}``) in a mapping where the configuration has
    built-in keys: a ``reporters``, ``scanners`` or ``converters`` section, a
    built-in plugin's options, or a list entry such as a suppression.

    Where the variable names a built-in (``markdown``), the profile's section
    merges with the built-in's, and the profile as written has no section under
    the built-in's name; another value leaves the built-in's default section in
    place. An override that keeps the reference, one that adds the built-in's
    section, and a test op there would be answered by those two shapes, and so
    tell whether the variable names a built-in, and in a suppression entry
    which of its fields the key is. Decided from the file as written,
    never from what it read, so every value, and an unset variable, is answered
    with the one text. A mapping with no built-in keys (an option of a plugin
    ASH does not ship) is left to ``_refuse_a_key_read_from_the_environment``.
    """
    _, mappings = _mappings_holding_a_key_read_from_the_environment(base)
    for mapping, _, part in mappings:
        if _has_built_in_keys(mapping, part):
            raise RuntimePatchDeniedError(None, PROFILE_KEY_CAN_NAME_A_BUILT_IN_REFUSAL)


def _refuse_a_key_read_from_the_environment(
    base: AshConfig, patch_ops: List[Dict[str, Any]]
) -> None:
    """Refuse an op whose path goes through a key of a mapping where the
    profile's file writes a key as a reference (an option of a plugin ASH does
    not ship named ``${VAR}``, say), unless the profile writes that key as text,
    and a ``test`` op at, above or through such a mapping.

    Such an op applied only when the key existed (``replace
    /scanners/<plugin>/options/<name>``), so its outcome, and which later rule
    refused it, depended on the variable's value. The keys it may name are the
    ones whose presence does not: the mapping's keys in the configuration's dump
    that the profile writes as text. An op cannot add another, since adding one
    is an op through the mapping too. Where the variable names a key the
    profile writes as text, the two merge, so a ``test`` op of the mapping, of
    what holds it or of that key's value would tell which. An op that replaces or
    removes the mapping itself, or what holds it, makes the mapping the
    client's, and ends the rule for it. Decided from the file as written and
    the ops' paths alone, before any other rule, so the answer does not depend
    on the value, nor on whether the variable is set. A mapping with built-in
    keys never gets here: ``_refuse_a_profile_whose_key_can_name_a_built_in``
    refuses the whole profile first.
    """
    dumped, mappings = _mappings_holding_a_key_read_from_the_environment(base)
    if not mappings:
        return
    # Each mapping that holds a key written as a reference, by its path in the
    # dump's keys, with the keys an op may name in it.
    known: Dict[Tuple[str, ...], set] = {}
    for mapping, text_keys, _ in mappings:
        if mapping is None:
            continue
        held = _node_at(dumped, mapping)
        # A key any file of the chain writes there as text.
        named = set(held) & text_keys if isinstance(held, dict) else set()
        known[mapping] = known.get(mapping, set()) | named
    for op in patch_ops:
        segments = _path_segments(op.get("path", ""))
        # An add or remove at an index of a list that holds such a mapping
        # moves the mapping to another index, and every later op's path is
        # then matched against the index the mapping no longer has: refused
        # outright, whatever the index, rather than tracked (a move's source
        # is a remove). An append (the "-" index) moves nothing.
        shifting = [segments] if op.get("op") in ("add", "remove", "copy") else []
        if op.get("op") == "move":
            source = op.get("from", "")
            shifting = [segments] + (
                [_path_segments(source)] if isinstance(source, str) else []
            )
        for shifted in shifting:
            if not shifted or not _LIST_INDEX.fullmatch(shifted[-1]):
                continue
            depth = len(shifted) - 1
            for mapping in known:
                if (
                    depth < len(mapping)
                    and _LIST_INDEX.fullmatch(mapping[depth])
                    and tuple(shifted[:depth]) == mapping[:depth]
                ):
                    raise RuntimePatchDeniedError(
                        None, LIST_SHIFT_ABOVE_A_KEY_READ_FROM_THE_ENVIRONMENT_REFUSAL
                    )
        for mapping in list(known):
            depth = len(mapping)
            if len(segments) <= depth:
                if tuple(segments) != mapping[: len(segments)]:
                    continue
                if op.get("op") == "test":
                    raise RuntimePatchDeniedError(
                        None, KEY_READ_FROM_THE_ENVIRONMENT_REFUSAL
                    )
                if op.get("op") in ("add", "replace", "remove"):
                    # The mapping itself, or what holds it, is replaced: its
                    # keys are now the client's.
                    del known[mapping]
                continue
            if tuple(segments[:depth]) != mapping:
                continue
            if op.get("op") == "test" or segments[depth] not in known[mapping]:
                raise RuntimePatchDeniedError(
                    None, KEY_READ_FROM_THE_ENVIRONMENT_REFUSAL
                )


#: The refusal of a patch that would move a value the profile read from the
#: environment where its reference does not follow it. It names no value or
#: location: a location can hold a key read from the environment.
MOVED_WITHOUT_ITS_REFERENCE = (
    "the patch moves a value the profile read from the environment where its "
    "reference does not follow"
)


def _node_at(document: Any, path: Tuple[Any, ...]) -> Any:
    """The part of ``document`` at ``path`` (dump keys and list indices), or
    None."""
    node = document
    for segment in path:
        if isinstance(node, dict) and segment in node:
            node = node[segment]
        elif isinstance(node, list) and isinstance(segment, int):
            if not 0 <= segment < len(node):
                return None
            node = node[segment]
        else:
            return None
    return node


def _holds_a_typed_value(container: Any, segment: Any) -> bool:
    """Whether ``container[segment]`` is a value a model typed from text: a
    number or a true/false value (never a string, None or a container)."""
    if isinstance(container, dict):
        held = container.get(segment)
    elif isinstance(container, list) and isinstance(segment, int):
        held = container[segment] if 0 <= segment < len(container) else None
    else:
        return False
    return isinstance(held, (bool, int, float)) and not isinstance(held, str)


def _holds_text(container: Any, segment: Any) -> bool:
    """Whether ``container[segment]`` is a string."""
    if isinstance(container, dict):
        return isinstance(container.get(segment), str)
    if isinstance(container, list) and isinstance(segment, int):
        return 0 <= segment < len(container) and isinstance(container[segment], str)
    return False


def _escape_pointer_segment(key: str) -> str:
    """Escape a mapping key as an RFC 6901 JSON-Pointer segment (`~` first)."""
    return key.replace("~", "~0").replace("/", "~1")


def _same_json_value(before: Any, after: Any) -> bool:
    """Compare two JSON values as JSON, not as Python.

    Python's `==` says `True == 1` and `1 == 1.0`, so a change between them
    would produce no op and never reach the gate. Serializing both sides keeps
    them apart.
    """
    return json.dumps(before, sort_keys=True) == json.dumps(after, sort_keys=True)


def json_patch_between(before: Any, after: Any, path: str = "") -> List[Dict[str, Any]]:
    """Return add/remove/replace ops that turn the JSON value `before` into `after`.

    Mappings are walked key by key, so a change deep in the document becomes an
    op at the deepest pointer that differs; that is the pointer an operator's
    `allowed_paths` names. Lists and scalars are compared whole and replaced
    whole. An element-wise list diff would emit index pointers (`/x/0`) that an
    allowlist written for the list itself or for appends (`/x/-`) does not name,
    and the denylist covers a list's elements either way.

    No `move` or `copy` ops are produced, because `apply_runtime_patch` refuses
    them.
    """
    if isinstance(before, dict) and isinstance(after, dict):
        ops: List[Dict[str, Any]] = []
        for key in before:
            if key not in after:
                ops.append(
                    {"op": "remove", "path": f"{path}/{_escape_pointer_segment(key)}"}
                )
        for key, value in after.items():
            child = f"{path}/{_escape_pointer_segment(key)}"
            if key not in before:
                ops.append({"op": "add", "path": child, "value": value})
            else:
                ops.extend(json_patch_between(before[key], value, child))
        return ops
    if _same_json_value(before, after):
        return []
    return [{"op": "replace", "path": path, "value": after}]


def apply_runtime_override(
    base: AshConfig,
    override: AshConfig,
    *,
    allowlist: RuntimeOverridesConfig,
) -> AshConfig:
    """Gate a whole-document override with the rules `apply_runtime_patch` enforces.

    The override replaces `base` wholesale, so a field it leaves out reverts to
    its default. Diffing the two documents, rather than reading only the fields
    the override names, is what catches that: an override that omits `sandbox`
    from a profile that sets `sandbox.mode: bwrap` is a `replace` at
    `/sandbox/mode`, and is refused like one.

    Returns the config the gated patch produces, not `override` itself, so what
    the caller binds is exactly what the gate checked. If that config differs
    from the override, part of the override was not expressed as an op and so
    was never checked; that is refused rather than bound either way. The ops
    ``apply_runtime_patch`` drops, which only turn an off-host reporter off, are
    the one allowed difference: the config with them applied has to be the
    override.

    Both sides are compared as written (record_of_config): where the profile
    read a key or a value from the environment, the base holds the reference
    its file wrote, as a test op compares. The override's text at that place
    is therefore an op whatever it is, unless it is the reference itself, so
    an override holding the value is answered as one holding any other text.
    """
    from automated_security_helper.config.config_validator import record_of_config

    base_doc = record_of_config(base, base.model_dump(mode="json", by_alias=False))
    override_doc = override.model_dump(mode="json", by_alias=False)
    patch_ops = json_patch_between(base_doc, override_doc)
    patched = apply_runtime_patch(base, patch_ops, allowlist=allowlist)
    _, dropped = _without_turn_offs(patch_ops, base, warn=False)
    patched_doc = record_of_config(
        patched, patched.model_dump(mode="json", by_alias=False)
    )
    if dropped:
        patched_doc = jsonpatch.apply_patch(patched_doc, dropped, in_place=False)
    if not _same_json_value(patched_doc, override_doc):
        raise RuntimePatchDeniedError(
            None,
            "the patch computed from the override does not reproduce the "
            "override, so part of it could not be checked",
        )
    return patched
