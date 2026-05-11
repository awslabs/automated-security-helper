"""Runtime JSON-Patch overrides with allowlist enforcement.

This module is the security boundary for runtime config mutation issued through
the MCP streamable-HTTP transport. Callers pass a list of RFC 6902 JSON-Patch
ops; this module decides — based on `RuntimeOverridesConfig` — whether the
patch is permitted, and (if so) returns a freshly validated `AshConfig`.

Defense-in-depth checks (in order):

1. Allowlist must be `enabled` (default is False).
2. Patch document, serialized as JSON, must be <= 64 KiB.
3. `move` and `copy` ops are rejected outright (they let an attacker exfiltrate
   one part of the config into another, sidestepping path checks).
4. Each op's `path` must match at least one entry in `allowed_paths`.
5. Each op's `path` must NOT match any entry in `denied_paths` (denied wins).
6. For `add` / `replace` ops, the value must not match the regex bound to that
   path in `denied_value_patterns`.
7. The result, after applying the patch, must validate as a full `AshConfig`.

A single failing op aborts the entire patch. The base config is never mutated.
"""

from __future__ import annotations

import fnmatch
import json
import re
from typing import Any, Dict, List

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


def _path_segments(path: str) -> List[str]:
    """Split a JSON-Pointer path into segments. Empty string means root."""
    if not path:
        return []
    if path[0] != "/":
        # JSON-Pointer paths must start with '/' (or be empty for root).
        return [path]
    return path[1:].split("/")


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


def _path_matches(pattern: str, path: str) -> bool:
    """Test whether `path` matches a glob `pattern` under JSON-Pointer rules."""
    if pattern == path:
        return True
    # Treat the trailing "/-" array-append marker as equivalent to a concrete
    # index for matching purposes (so an allowed_paths entry of
    # "/external_reports_to_include/-" matches a patch op against "/.../-").
    return _match_segments(_path_segments(pattern), _path_segments(path))


def _check_op_paths(
    op: Dict[str, Any],
    *,
    allowlist: RuntimeOverridesConfig,
) -> None:
    path = op.get("path", "")
    if not any(_path_matches(p, path) for p in allowlist.allowed_paths):
        raise RuntimePatchDeniedError(
            op, f"path {path!r} not in allowed_paths"
        )
    for denied in allowlist.denied_paths:
        if _path_matches(denied, path):
            raise RuntimePatchDeniedError(
                op,
                f"path {path!r} matches denied_paths entry {denied!r}",
            )


def _check_value_pattern(
    op: Dict[str, Any],
    *,
    allowlist: RuntimeOverridesConfig,
) -> None:
    if op.get("op") not in {"add", "replace", "test"}:
        return
    path = op.get("path", "")
    pattern = allowlist.denied_value_patterns.get(path)
    if pattern is None:
        return
    value = op.get("value")
    if value is None:
        return
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        raise RuntimePatchDeniedError(
            op, f"denied_value_patterns regex for {path!r} is invalid: {exc}"
        ) from exc
    serialized = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
    if compiled.search(serialized):
        raise RuntimePatchDeniedError(
            op,
            f"value at {path!r} matches denied_value_patterns regex {pattern!r}",
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
