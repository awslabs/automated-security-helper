# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Readings of utils/symbol_spans.py that need no grammar, and two that do.

is_valid_symbol matches the whole text, so a symbol with a trailing newline is
refused rather than accepted and then matching nothing. A tree-sitter binding
whose API is not the one called (TypeError) is a grammar that is not available,
and fails closed as a missing one does. SymbolResolver.contains returns False,
never raises, for a path with an embedded NUL, and for a region that ends
before it starts. The index cache keeps a result only when it is the file's
own: a missing grammar and a read failure are not cached, and a file whose stat
moved during the read is not cached under the stat read first.

With the symbols extra: a TypeScript type alias contributes a segment, and a
method's decorator line is inside the method's span.
"""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.utils import symbol_spans
from automated_security_helper.utils.symbol_spans import (
    GRAMMARS_BY_EXTENSION,
    SymbolGrammar,
    SymbolResolver,
    SymbolsUnavailableError,
    index_symbols,
    is_valid_symbol,
)

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("symbol", ["Outer.inner\n", "name\n", "a.b\r\n"])
def test_a_symbol_with_a_trailing_line_break_is_not_valid(symbol):
    assert not is_valid_symbol(symbol)
    assert is_valid_symbol(symbol.strip()), "the control: the text itself is valid"


def test_a_binding_whose_language_raises_type_error_is_an_unavailable_grammar(
    monkeypatch,
):
    grammar = SymbolGrammar(
        language="Fake",
        module="fake_grammar_for_this_test",
        loader="language",
        definitions=frozenset(),
    )

    class _Language:
        def __init__(self, pointer):
            raise TypeError("__init__() takes 1 positional argument but 2 were given")

    fake_tree_sitter = SimpleNamespace(Language=_Language)
    fake_grammar = SimpleNamespace(language=lambda: object())
    real_import = symbol_spans.importlib.import_module

    def import_module(name, *args, **kwargs):
        if name == "tree_sitter":
            return fake_tree_sitter
        if name == grammar.module:
            return fake_grammar
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(symbol_spans.importlib, "import_module", import_module)
    symbol_spans._language_cache.pop((grammar.module, grammar.loader), None)

    with pytest.raises(SymbolsUnavailableError):
        symbol_spans._load_language(grammar)


def test_a_path_with_an_embedded_nul_is_outside_every_symbol(tmp_path):
    resolver = SymbolResolver(tmp_path)
    assert resolver._resolve("src/a\x00b.py") is None
    assert resolver.contains("src/a\x00b.py", 1, 1, "f") is False


def test_a_region_that_ends_before_it_starts_is_outside_every_symbol(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        symbol_spans,
        "_index_file",
        lambda path: symbol_spans._Indexed({"f": ((1, 10),)}),
    )
    (tmp_path / "a.py").write_text("def f():\n    pass\n", encoding="utf-8")
    resolver = SymbolResolver(tmp_path)

    assert resolver.contains("a.py", 5, 5, "f") is True, "the control"
    assert resolver.contains("a.py", 8, 3, "f") is False


@pytest.fixture
def clean_cache():
    symbol_spans.clear_symbol_cache()
    yield
    symbol_spans.clear_symbol_cache()


def test_a_missing_grammar_is_answered_but_not_cached(
    tmp_path, monkeypatch, clean_cache
):
    source = tmp_path / "a.py"
    source.write_text("def f():\n    pass\n", encoding="utf-8")
    calls = []

    def index(source_bytes, grammar):
        calls.append(1)
        if len(calls) == 1:
            raise SymbolsUnavailableError("not installed yet")
        return {"f": [(1, 2)]}

    monkeypatch.setattr(symbol_spans, "index_symbols", index)

    first = symbol_spans._index_file(source)
    second = symbol_spans._index_file(source)

    assert isinstance(first, symbol_spans._Unresolvable)
    assert isinstance(second, symbol_spans._Indexed), second
    assert len(calls) == 2


def test_a_read_failure_is_answered_but_not_cached(tmp_path, monkeypatch, clean_cache):
    source = tmp_path / "a.py"
    source.write_text("def f():\n    pass\n", encoding="utf-8")
    real_read = Path.read_bytes
    failures = [PermissionError(13, "Permission denied")]

    def read_bytes(self):
        if failures:
            raise failures.pop()
        return real_read(self)

    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    monkeypatch.setattr(symbol_spans, "index_symbols", lambda s, g: {"f": [(1, 2)]})

    first = symbol_spans._index_file(source)
    second = symbol_spans._index_file(source)

    assert isinstance(first, symbol_spans._Unresolvable)
    assert "Permission denied" in first.reason
    assert isinstance(second, symbol_spans._Indexed), second


def test_a_file_that_changes_during_the_read_is_not_cached_under_the_old_stat(
    tmp_path, monkeypatch, clean_cache
):
    source = tmp_path / "a.py"
    source.write_text("def f():\n    pass\n", encoding="utf-8")
    stat = source.stat()
    calls = []

    def index(source_bytes, grammar):
        calls.append(1)
        if len(calls) == 1:
            # The file is rewritten while this parse runs: a longer file.
            source.write_text("def f():\n    pass\n\ndef g():\n    pass\n", "utf-8")
        return {"f": [(1, 2)]}

    monkeypatch.setattr(symbol_spans, "index_symbols", index)

    symbol_spans._index_file(source)
    key = (str(source), stat.st_mtime_ns, stat.st_size)

    assert key not in symbol_spans._INDEX_CACHE
    assert source.stat().st_size != stat.st_size, "the control: the file changed"


def _require_symbols_extra() -> None:
    try:
        import tree_sitter  # noqa: F401
        import tree_sitter_typescript  # noqa: F401
    except ImportError as exc:
        if os.environ.get("ASH_REQUIRE_SYMBOLS_EXTRA"):
            raise AssertionError(f"the symbols extra is required here: {exc}") from exc
        pytest.skip(f"the symbols extra is not installed: {exc}")


TYPESCRIPT = """\
type Shape = {
  area(): number; // MARK type literal member
};

class Widget {
  @log()
  render() { // MARK decorated method
    return eval("1");
  }
}
"""


def _line(marker: str) -> int:
    for number, text in enumerate(TYPESCRIPT.splitlines(), start=1):
        if marker in text:
            return number
    raise AssertionError(marker)


def test_a_type_alias_contributes_a_segment():
    _require_symbols_extra()

    spans = index_symbols(TYPESCRIPT.encode("utf-8"), GRAMMARS_BY_EXTENSION[".ts"])

    member = _line("MARK type literal member")
    assert any(a <= member <= b for a, b in spans["Shape.area"]), spans
    assert "area" not in spans, spans


def test_a_methods_decorator_line_is_inside_its_span():
    _require_symbols_extra()

    spans = index_symbols(TYPESCRIPT.encode("utf-8"), GRAMMARS_BY_EXTENSION[".ts"])

    decorator = _line("MARK decorated method") - 1
    assert TYPESCRIPT.splitlines()[decorator - 1].strip() == "@log()"
    assert any(a <= decorator <= b for a, b in spans["Widget.render"]), spans
