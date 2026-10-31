# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two readings of utils/symbol_spans.py.

A TypeScript ``namespace A.B {}`` or a string-named ``module "x" {}`` used to
contribute no qualified-name segment, so its members were indexed under the
enclosing scope and a suppression for a top-level name also covered them. A
dotted name now contributes its segments, and a name no symbol can spell keeps
its members out of every spellable scope.

SymbolResolver turned every backslash of a finding's file path into "/", so on
POSIX, where a backslash is a character of a file name, a suppression was checked
against a file other than the finding's.

The grammars are the optional ``symbols`` extra. Without it the parse tests skip,
unless ``ASH_REQUIRE_SYMBOLS_EXTRA`` is set, as CI sets it, in which case a
missing extra is a failure rather than a skip.
"""

from __future__ import annotations

import os
import sys

import pytest

from automated_security_helper.utils.symbol_spans import (
    GRAMMARS_BY_EXTENSION,
    SymbolResolver,
    index_symbols,
)

pytestmark = pytest.mark.unit


def _require_symbols_extra() -> None:
    try:
        import tree_sitter  # noqa: F401
        import tree_sitter_typescript  # noqa: F401
    except ImportError as exc:
        if os.environ.get("ASH_REQUIRE_SYMBOLS_EXTRA"):
            raise AssertionError(f"the symbols extra is required here: {exc}") from exc
        pytest.skip(f"the symbols extra is not installed: {exc}")


TYPESCRIPT = """\
export function handler() {
  return eval("1"); // MARK top-level handler
}

namespace Outer.Inner {
  export function handler() {
    return eval("2"); // MARK namespaced handler
  }
}

declare module "quoted" {
  export function handler(): void; // MARK string-named module handler
}
"""


def _line(marker: str) -> int:
    for number, text in enumerate(TYPESCRIPT.splitlines(), start=1):
        if marker in text:
            return number
    raise AssertionError(marker)


def test_a_dotted_namespace_contributes_its_segments():
    _require_symbols_extra()

    spans = index_symbols(TYPESCRIPT.encode("utf-8"), GRAMMARS_BY_EXTENSION[".ts"])

    inside_namespace = _line("MARK namespaced handler")
    assert any(
        first <= inside_namespace <= last for first, last in spans["Outer.Inner"]
    )
    assert any(
        first <= inside_namespace <= last
        for first, last in spans["Outer.Inner.handler"]
    )
    # The top-level name covers only its own definition, not the namespace's.
    top_level = spans["handler"]
    assert len(top_level) == 1
    assert not any(first <= inside_namespace <= last for first, last in top_level)


def test_a_string_named_module_keeps_its_members_out_of_spellable_scopes():
    _require_symbols_extra()

    spans = index_symbols(TYPESCRIPT.encode("utf-8"), GRAMMARS_BY_EXTENSION[".ts"])

    inside_module = _line("MARK string-named module handler")
    for name, ranges in spans.items():
        if any(first <= inside_module <= last for first, last in ranges):
            # Only a name no suppression can spell reaches into the module.
            assert chr(0) in name, name


@pytest.mark.skipif(sys.platform == "win32", reason="a backslash is a separator")
def test_a_posix_file_name_holding_a_backslash_is_the_findings_file(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "b.py").write_text("x = 1\n", encoding="utf-8")
    with_backslash = tmp_path / ("a" + chr(0x5C) + "b.py")
    with_backslash.write_text("y = 2\n", encoding="utf-8")
    resolver = SymbolResolver(tmp_path)

    assert resolver._resolve("a" + chr(0x5C) + "b.py") == with_backslash.resolve()
    assert resolver._resolve("a/b.py") == (tmp_path / "a" / "b.py").resolve()
