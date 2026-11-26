# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Both self-scan configs pin the mcp B104 suppression to the log helper.

Why this exists
---------------
``automated_security_helper/cli/mcp/__init__.py`` holds one bandit B104 false
positive: the startup log helper that reproduces uvicorn's "running on" line
computes ``host = "0.0.0.0" if config.host is None`` for DISPLAY, for a socket
that is already bound. ``.ash.yaml`` and ``.ash/.ash_alpha_plugins.yaml`` both
suppress it. A file-wide entry would also hide a real ``0.0.0.0`` bind added
anywhere else in that file, which is exactly the finding the suppression's own
reason says must still report, so each entry is pinned to the helper by
``symbol``. The two files run different self-scan legs, so they must carry the
same pin: a narrowing applied to one file alone leaves the other leg blind.

What this checks
----------------
* Each config carries exactly one B104 entry for the mcp module, pinned by
  ``symbol`` (no file-wide entry, no line pin that drifts when the file moves).
* The two entries name the same symbol.
* The symbol still resolves in the file (read literally, with ``ast``) and the
  suppressed ``0.0.0.0`` display expression still sits inside its span, so the
  pin excuses the line it was written for and nothing else.
"""

import ast
from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml

from automated_security_helper.utils.suppression_matcher import file_path_matches

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[4]
CONFIGS = (".ash.yaml", ".ash/.ash_alpha_plugins.yaml")
MCP_PATH = "automated_security_helper/cli/mcp/__init__.py"
SYMBOL = "_log_where_the_server_listens"
FLAGGED_TEXT = '"0.0.0.0" if config.host is None'


def _select_b104(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Every B104 entry whose path REACHES the mcp module, read by the real
    matcher: string equality would let a glob or a bare directory (which
    matches its whole subtree) hide a real ``0.0.0.0`` bind."""
    return [
        e
        for e in entries
        if e.get("rule_id") == "B104"
        and file_path_matches(MCP_PATH, str(e.get("path") or ""))
    ]


def _b104_entries(config: str) -> List[Dict[str, Any]]:
    doc = yaml.safe_load((REPO_ROOT / config).read_text(encoding="utf-8")) or {}
    return _select_b104((doc.get("global_settings") or {}).get("suppressions") or [])


def _symbol_span(source: str, name: str) -> "tuple[int, int]":
    """``(first line, last line)`` of the module-level definition *name*."""
    for node in ast.parse(source).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == name:
                return node.lineno, node.end_lineno
    raise AssertionError(f"{MCP_PATH} no longer defines {name}")


@pytest.mark.parametrize("config", CONFIGS)
def test_each_config_pins_the_mcp_b104_entry_to_the_symbol(config):
    entries = _b104_entries(config)
    assert len(entries) == 1, (
        f"{config} must carry exactly one B104 entry for {MCP_PATH}; a second "
        f"(or a file-wide) entry would hide a real bind: {entries}"
    )
    entry = entries[0]
    assert entry.get("symbol") == SYMBOL, (
        f"{config}'s B104 entry for {MCP_PATH} must be pinned to {SYMBOL}; "
        "a file-wide entry hides a bind added anywhere in the file"
    )
    assert entry.get("line_start") is None and entry.get("line_end") is None, (
        f"{config}: the symbol pin replaces the line pin; a stacked line pin "
        "drifts when the file changes above it"
    )


def test_the_two_configs_carry_the_same_pin():
    (default,) = _b104_entries(CONFIGS[0])
    (alpha,) = _b104_entries(CONFIGS[1])
    assert default.get("symbol") == alpha.get("symbol"), (
        "the default and alpha self-scan configs must pin the mcp B104 entry "
        "to the same symbol (kept in step)"
    )


def test_the_selector_sees_every_path_spelling_that_reaches_the_module():
    """Control: each spelling that covers the mcp module is selected, so a
    planted entry in any of them would break the exactly-one assertion."""
    spellings = [
        MCP_PATH,
        "automated_security_helper/cli/mcp/**",
        "automated_security_helper/cli/mcp/*.py",
        "automated_security_helper/cli/mcp",
    ]
    planted = [{"rule_id": "B104", "path": spelling} for spelling in spellings]
    assert _select_b104(planted) == planted
    # And ones that do not reach it stay unselected: another rule, another
    # subtree, a pathless entry, and a ./-prefixed path, which the product
    # matcher itself reads as matching nothing, so it suppresses nothing.
    assert (
        _select_b104(
            [
                {"rule_id": "B105", "path": MCP_PATH},
                {"rule_id": "B104", "path": "automated_security_helper/cli/report/**"},
                {"rule_id": "B104"},
                {"rule_id": "B104", "path": f"./{MCP_PATH}"},
            ]
        )
        == []
    )


def test_the_flagged_expression_still_sits_inside_the_pinned_symbol():
    source = (REPO_ROOT / MCP_PATH).read_text(encoding="utf-8")
    start, end = _symbol_span(source, SYMBOL)
    lines = source.splitlines()
    flagged = [
        number for number, line in enumerate(lines, start=1) if FLAGGED_TEXT in line
    ]
    assert flagged, (
        f"{MCP_PATH} no longer holds {FLAGGED_TEXT!r}; the B104 entries in "
        f"{CONFIGS} suppress nothing and should be removed"
    )
    outside = [number for number in flagged if not start <= number <= end]
    assert not outside, (
        f"{FLAGGED_TEXT!r} moved outside {SYMBOL} (lines {start}-{end}) to "
        f"{outside}; re-pin the B104 entries in {CONFIGS}"
    )
