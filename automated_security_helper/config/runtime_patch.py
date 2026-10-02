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
5. Each op's `path` must NOT overlap any entry in `denied_paths` (denied wins).
   Both sides denote subtrees, so an entry fires for three shapes of write:
   the pointer it names, anything below that pointer (`/-`, `/0`, a nested
   key), and any ancestor, because a write at an ancestor supplies or deletes
   the denied descendant along with everything else in that subtree.
6. For `add` / `replace` ops, the value must not match any regex in
   `denied_value_patterns` whose key overlaps the op's path under the same
   subtree reading as (5).
7. The result, after applying the patch, must validate as a full `AshConfig`.

A single failing op aborts the entire patch. The base config is never mutated.
"""

from __future__ import annotations

import fnmatch
import json
import re
from typing import Any, Dict, List, Pattern

import jsonpatch
from pydantic import ValidationError

from automated_security_helper.config.ash_config import (
    AshConfig,
    RuntimeOverridesConfig,
)


_MAX_PATCH_BYTES = 64 * 1024
_FORBIDDEN_OPS = {"move", "copy"}


class RuntimePatchDeniedError(Exception):
    """Raised when a runtime patch is rejected by the allowlist."""

    def __init__(self, op: Dict[str, Any] | None, rule: str) -> None:
        self.op = op
        self.rule = rule
        super().__init__(f"Patch op {op!r} denied by rule: {rule}")


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
    # Standard glob match with `**` support, implemented as a small DP.
    # Use a recursive matcher with memoization on (i, j) indices.
    cache: Dict[tuple, bool] = {}

    def helper(i: int, j: int) -> bool:
        if (i, j) in cache:
            return cache[(i, j)]
        if i == len(pattern_segs):
            result = j == len(path_segs)
        elif pattern_segs[i] == "**":
            # zero or more segments
            if helper(i + 1, j):
                result = True
            elif j < len(path_segs) and helper(i, j + 1):
                result = True
            else:
                result = False
        elif j == len(path_segs):
            result = False
        elif pattern_segs[i] == "*":
            result = helper(i + 1, j + 1)
        else:
            # Use fnmatch to support partial-segment globs like `aws_*`.
            if fnmatch.fnmatchcase(path_segs[j], pattern_segs[i]):
                result = helper(i + 1, j + 1)
            else:
                result = False
        cache[(i, j)] = result
        return result

    return helper(0, 0)


def _pattern_reaches_into(pattern_segs: List[str], subtree_segs: List[str]) -> bool:
    """Test whether a pattern matches any location at or below a concrete path.

    `_match_segments` answers the narrower question "does this pattern match
    exactly this path", which is why a denylist built on it was not
    subtree-closed: the pattern still had segments left when the path ran out,
    so an entry naming a descendant never fired for a write at an ancestor.

    `subtree_segs` is a concrete path, not a pattern; only `pattern_segs` is
    globbed. The two base cases are the whole difference from
    `_match_segments`.
    """
    cache: Dict[tuple, bool] = {}

    def helper(i: int, j: int) -> bool:
        if j == len(subtree_segs):
            # The pattern consumed every segment of the concrete path, so it
            # names this location or one beneath it. Either way it names a
            # location the write at `subtree_segs` reaches.
            return True
        if (i, j) in cache:
            return cache[(i, j)]
        if i == len(pattern_segs):
            # Pattern exhausted while the path continues: the pattern names a
            # strict ancestor of the path, which is outside the path's subtree.
            result = False
        elif pattern_segs[i] == "**":
            # zero or more segments
            result = helper(i + 1, j) or helper(i, j + 1)
        elif pattern_segs[i] == "*":
            result = helper(i + 1, j + 1)
        else:
            # Use fnmatch to support partial-segment globs like `aws_*`.
            if fnmatch.fnmatchcase(subtree_segs[j], pattern_segs[i]):
                result = helper(i + 1, j + 1)
            else:
                result = False
        cache[(i, j)] = result
        return result

    return helper(0, 0)


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


def _denied_path_reason(denied: str, path: str) -> str | None:
    """Explain how a `denied_paths` entry blocks a write at `path`, or None.

    The refusal has to name the entry that caused it: subtree closure rejects
    writes that used to succeed, and an operator who set `/global_settings`
    wholesale cannot act on a message that does not say which descendant of it
    is off limits.
    """
    if not _policy_covers_op_path(denied, path):
        return None
    if _path_matches(denied, path):
        return f"path {path!r} matches denied_paths entry {denied!r}"
    if _match_segments(_subtree_pattern(denied), _path_segments(path)):
        return f"path {path!r} is inside denied_paths entry {denied!r}"
    return f"path {path!r} writes a subtree that contains denied_paths entry {denied!r}"


def _check_op_paths(
    op: Dict[str, Any],
    *,
    allowlist: RuntimeOverridesConfig,
) -> None:
    path = op.get("path", "")
    if not any(_path_matches(p, path) for p in allowlist.allowed_paths):
        raise RuntimePatchDeniedError(op, f"path {path!r} not in allowed_paths")
    for denied in allowlist.denied_paths:
        reason = _denied_path_reason(denied, path)
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
) -> None:
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
    for pattern_path, pattern in allowlist.denied_value_patterns.items():
        if not _policy_covers_op_path(pattern_path, path):
            continue
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            raise RuntimePatchDeniedError(
                op,
                f"denied_value_patterns regex for {pattern_path!r} is invalid: {exc}",
            ) from exc
        if _walk_string_leaves(value, compiled):
            raise RuntimePatchDeniedError(
                op,
                f"value at {path!r} matches denied_value_patterns regex "
                f"{pattern!r} bound to {pattern_path!r}",
            )


def apply_runtime_patch(
    base: AshConfig,
    patch_ops: List[Dict[str, Any]],
    *,
    allowlist: RuntimeOverridesConfig,
) -> AshConfig:
    """Apply a JSON-Patch to a config, enforcing the runtime allowlist.

    Returns a new `AshConfig`. The base instance is never mutated. Any rule
    violation raises `RuntimePatchDeniedError` and aborts the entire patch.
    """
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
        _check_op_paths(op, allowlist=allowlist)
        _check_value_pattern(op, allowlist=allowlist)

    base_dict = base.model_dump(mode="python", by_alias=False)
    try:
        patched = jsonpatch.apply_patch(base_dict, patch_ops, in_place=False)
    except jsonpatch.JsonPatchException as exc:
        raise RuntimePatchDeniedError(None, f"patch apply failed: {exc}") from exc
    except jsonpatch.JsonPointerException as exc:
        raise RuntimePatchDeniedError(None, f"patch pointer failed: {exc}") from exc

    try:
        return AshConfig.model_validate(patched)
    except ValidationError as exc:
        raise RuntimePatchDeniedError(
            None, f"patched config failed validation: {exc.errors()}"
        ) from exc
