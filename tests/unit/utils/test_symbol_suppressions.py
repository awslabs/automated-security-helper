# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Symbol-scoped suppressions: ``symbol: MyClass.my_method``.

A line-number suppression rots as soon as code above it moves. A suppression
with ``symbol`` names a definition instead, and covers a finding when the
finding's lines lie inside that definition's span in the finding's file. Spans
come from real tree-sitter parses of the fixture sources below; nothing here
mocks the parser.

Every way of not knowing the span fails closed: the finding stays visible and a
warning says why.

The grammars are the optional ``symbols`` extra. Without it these tests skip,
unless ``ASH_REQUIRE_SYMBOLS_EXTRA`` is set, as CI sets it, in which case a
missing extra is a failure rather than a skip.
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import date, timedelta
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.config_linter import (
    ConfigLinter,
    LintCategory,
    LintResult,
    LintSeverity,
)
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.plugin_modules.ash_builtin.reporters.unused_suppressions_reporter import (
    UnusedSuppressionsReporter,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation2,
    Region,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils import symbol_spans
from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif
from automated_security_helper.utils.symbol_spans import (
    GRAMMARS_BY_EXTENSION,
    SymbolResolver,
    grammar_for_path,
    index_symbols,
)


def _require_symbols_extra() -> None:
    try:
        import tree_sitter  # noqa: F401
        import tree_sitter_java  # noqa: F401
        import tree_sitter_javascript  # noqa: F401
        import tree_sitter_python  # noqa: F401
        import tree_sitter_typescript  # noqa: F401
    except ImportError as exc:  # pragma: no cover - environment-dependent
        if os.environ.get("ASH_REQUIRE_SYMBOLS_EXTRA", "").strip().upper() in (
            "1",
            "YES",
            "TRUE",
        ):
            pytest.fail(
                "ASH_REQUIRE_SYMBOLS_EXTRA is set but the [symbols] extra is not "
                f"importable ({exc}). These tests must run in CI, not skip."
            )
        pytest.skip(f"[symbols] extra not installed ({exc})")


@pytest.fixture(autouse=True)
def _symbols_extra_and_fresh_cache():
    """Each test starts from an empty parse cache, so a parse count is its own."""
    _require_symbols_extra()
    symbol_spans.clear_symbol_cache()
    yield
    symbol_spans.clear_symbol_cache()


PYTHON_SOURCE = """\
import subprocess


def module_function():
    subprocess.call("ls", shell=True)  # MARK module_function body


@decorator_one  # MARK decorated first decorator
@decorator_two(
    arg=1,
)
def decorated():
    return 1  # MARK decorated body


class Outer:
    attr = 1  # MARK Outer attr

    def method(self):
        return 2  # MARK Outer.method body

    class Inner:
        def method(self):
            return 3  # MARK Outer.Inner.method body

        def sibling(self):
            return 4  # MARK Outer.Inner.sibling body

    @property
    def value(self):
        return 5  # MARK Outer.value getter

    @value.setter
    def value(self, new):
        self._v = new  # MARK Outer.value setter


def outer_function():
    def inner_function():
        return 6  # MARK inner_function body

    return inner_function


if True:

    def conditional():
        return 7  # MARK conditional body
"""


def _line(source: str, marker: str) -> int:
    """1-based line of the only line containing ``marker``."""
    hits = [i for i, text in enumerate(source.splitlines(), 1) if marker in text]
    assert len(hits) == 1, f"{marker!r} on lines {hits}"
    return hits[0]


def _def_line(source: str, header: str) -> int:
    return _line(source, header)


def _python_spans(source: str = PYTHON_SOURCE):
    return index_symbols(source.encode("utf-8"), GRAMMARS_BY_EXTENSION[".py"])


def _write(root: Path, rel: str, content: bytes | str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, str):
        path.write_bytes(content.encode("utf-8"))
    else:
        path.write_bytes(content)
    return path


def _finding(path: str, line_start: int | None, line_end: int | None = None, **kw):
    fields = {
        "id": "f",
        "title": "t",
        "description": "d",
        "severity": "HIGH",
        "scanner": "bandit",
        "scanner_type": "SAST",
        "rule_id": "B602",
        "file_path": path,
        "line_start": line_start,
        "line_end": line_end if line_end is not None else line_start,
    }
    fields.update(kw)
    return FlatVulnerability(**fields)


def _suppression(**overrides) -> AshSuppression:
    fields = {"rule_id": "B602", "path": "src/app.py", "reason": "r"}
    fields.update(overrides)
    return AshSuppression(**fields)


class TestPythonSpans:
    def test_first_and_last_line_of_a_function_are_inside_it(self, tmp_path):
        _write(tmp_path, "src/app.py", PYTHON_SOURCE)
        resolver = SymbolResolver(tmp_path)
        first = _def_line(PYTHON_SOURCE, "def module_function")
        last = _line(PYTHON_SOURCE, "MARK module_function body")
        assert last == first + 1

        for line in (first, last):
            assert resolver.contains("src/app.py", line, line, "module_function")
        # One line either side is outside.
        for line in (first - 1, last + 1):
            assert not resolver.contains("src/app.py", line, line, "module_function")

    def test_decorators_are_part_of_the_span(self):
        spans = _python_spans()
        first_decorator = _line(PYTHON_SOURCE, "MARK decorated first decorator")
        body = _line(PYTHON_SOURCE, "MARK decorated body")
        assert spans["decorated"] == [(first_decorator, body)]

    def test_nested_names_are_qualified_from_the_top_of_the_file(self):
        spans = _python_spans()
        inner_method = _line(PYTHON_SOURCE, "MARK Outer.Inner.method body")
        for name in ("Outer.Inner.method", "Outer.Inner", "Outer"):
            assert any(a <= inner_method <= b for a, b in spans[name]), name
        # No suffix matching: the bare and partial names are not defined.
        assert "method" not in spans
        assert "Inner.method" not in spans
        assert "Inner" not in spans
        # A same-named method one level up is a different symbol.
        assert not any(a <= inner_method <= b for a, b in spans["Outer.method"])

    def test_nested_function_and_conditional_definition(self):
        spans = _python_spans()
        inner = _line(PYTHON_SOURCE, "MARK inner_function body")
        assert any(a <= inner <= b for a, b in spans["outer_function.inner_function"])
        conditional = _line(PYTHON_SOURCE, "MARK conditional body")
        assert any(a <= conditional <= b for a, b in spans["conditional"])

    def test_async_def_and_overload_stubs(self):
        source = (
            "from typing import overload\n"  # 1
            "@overload\n"  # 2
            "def coerce(x: int) -> int: ...\n"  # 3
            "@overload\n"  # 4
            "def coerce(x: str) -> str: ...\n"  # 5
            "def coerce(x):\n"  # 6
            "    return x\n"  # 7
            "class Client:\n"  # 8
            "    async def fetch(self):\n"  # 9
            "        await go()\n"  # 10
        )
        spans = index_symbols(source.encode(), GRAMMARS_BY_EXTENSION[".py"])
        assert spans["coerce"] == [(2, 3), (4, 5), (6, 7)]
        assert spans["Client.fetch"] == [(9, 10)]

    def test_duplicate_names_cover_every_definition(self):
        spans = _python_spans()
        getter = _line(PYTHON_SOURCE, "MARK Outer.value getter")
        setter = _line(PYTHON_SOURCE, "MARK Outer.value setter")
        assert len(spans["Outer.value"]) == 2
        for line in (getter, setter):
            assert any(a <= line <= b for a, b in spans["Outer.value"])
        attr = _line(PYTHON_SOURCE, "MARK Outer attr")
        assert not any(a <= attr <= b for a, b in spans["Outer.value"])

    @pytest.mark.parametrize("newline", ["\r\n", "\r"], ids=["crlf", "bare-cr"])
    def test_line_endings_do_not_move_spans(self, newline):
        converted = PYTHON_SOURCE.replace("\n", newline).encode("utf-8")
        assert index_symbols(converted, GRAMMARS_BY_EXTENSION[".py"]) == (
            _python_spans()
        )

    def test_crlf_file_resolves_through_the_resolver(self, tmp_path):
        _write(tmp_path, "src/app.py", PYTHON_SOURCE.replace("\n", "\r\n"))
        line = _line(PYTHON_SOURCE, "MARK Outer.Inner.method body")
        assert SymbolResolver(tmp_path).contains(
            "src/app.py", line, line, "Outer.Inner.method"
        )

    def test_utf8_bom_is_ignored(self):
        with_bom = b"\xef\xbb\xbf" + PYTHON_SOURCE.encode("utf-8")
        assert index_symbols(with_bom, GRAMMARS_BY_EXTENSION[".py"]) == (
            _python_spans()
        )

    def test_non_utf8_file_with_ascii_names_resolves(self, tmp_path):
        source = (
            "# -*- coding: latin-1 -*-\ndef greet():\n    return 'h\xe9llo'\n"
        ).encode("latin-1")
        with pytest.raises(UnicodeDecodeError):
            source.decode("utf-8")
        _write(tmp_path, "src/app.py", source)
        assert SymbolResolver(tmp_path).contains("src/app.py", 3, 3, "greet")

    def test_utf16_file_fails_closed(self, tmp_path, caplog):
        _write(tmp_path, "src/app.py", "def greet():\n    pass\n".encode("utf-16"))
        with caplog.at_level(logging.WARNING, logger="ash"):
            assert not SymbolResolver(tmp_path).contains("src/app.py", 2, 2, "greet")
        assert "does not parse cleanly" in caplog.text


class TestOtherGrammars:
    def test_extension_table_is_the_only_selector(self):
        assert grammar_for_path("a/b.PY").language == "Python"
        assert grammar_for_path("a\\b.tsx").language == "TSX"
        assert grammar_for_path("a/b.go") is None
        assert grammar_for_path("Makefile") is None

    def test_javascript(self):
        source = (
            "class Api {\n"  # 1
            "  handle() {\n"  # 2
            "    eval(x);\n"  # 3
            "  }\n"  # 4
            "  onClick = () => {\n"  # 5
            "    eval(y);\n"  # 6
            "  };\n"  # 7
            "}\n"  # 8
            "export function run() {\n"  # 9
            "  return 1;\n"  # 10
            "}\n"  # 11
            "const helper = () => {\n"  # 12
            "  return 2;\n"  # 13
            "};\n"  # 14
            "const config = { build() { return 3; } };\n"  # 15
        )
        spans = index_symbols(source.encode(), GRAMMARS_BY_EXTENSION[".js"])
        assert spans["Api"] == [(1, 8)]
        assert spans["Api.handle"] == [(2, 4)]
        assert spans["Api.onClick"] == [(5, 7)]
        assert spans["run"] == [(9, 11)]
        assert spans["helper"] == [(12, 14)]
        # A method in an object literal is not addressable: `config` is not a
        # function, and `build` is not a class member.
        assert "config" not in spans
        assert "build" not in spans
        assert "config.build" not in spans

    def test_typescript_overloads_and_decorators(self):
        source = (
            "@Component({\n"  # 1
            "  selector: 'x',\n"  # 2
            "})\n"  # 3
            "export class Widget {\n"  # 4
            "  render(): void {}\n"  # 5
            "}\n"  # 6
            "function parse(a: string): number;\n"  # 7
            "function parse(a: any): number {\n"  # 8
            "  return 1;\n"  # 9
            "}\n"  # 10
            "interface Shape { area(): number; }\n"  # 11
        )
        spans = index_symbols(source.encode(), GRAMMARS_BY_EXTENSION[".ts"])
        assert spans["Widget"] == [(1, 6)]
        assert spans["Widget.render"] == [(5, 5)]
        assert spans["parse"] == [(7, 7), (8, 10)]
        assert spans["Shape.area"] == [(11, 11)]

    def test_tsx(self):
        source = "export function View() {\n  return <div>{x}</div>;\n}\n"
        spans = index_symbols(source.encode(), GRAMMARS_BY_EXTENSION[".tsx"])
        assert spans["View"] == [(1, 3)]

    def test_java_overloads_annotations_and_nesting(self):
        source = (
            "@Service\n"  # 1
            "public class Handler {\n"  # 2
            "  @Override\n"  # 3
            "  public void run() {\n"  # 4
            "    exec();\n"  # 5
            "  }\n"  # 6
            "  void run(int n) {}\n"  # 7
            "  Handler() {}\n"  # 8
            "  static class Inner {\n"  # 9
            "    void go() {}\n"  # 10
            "  }\n"  # 11
            "}\n"  # 12
        )
        spans = index_symbols(source.encode(), GRAMMARS_BY_EXTENSION[".java"])
        assert spans["Handler"] == [(1, 12)]
        assert spans["Handler.run"] == [(3, 6), (7, 7)]
        assert spans["Handler.Handler"] == [(8, 8)]
        assert spans["Handler.Inner.go"] == [(10, 10)]


class TestMatching:
    @pytest.fixture
    def root(self, tmp_path):
        _write(tmp_path, "src/app.py", PYTHON_SOURCE)
        return tmp_path

    def test_inside_matches_and_sibling_stays_visible(self, root):
        resolver = SymbolResolver(root)
        supp = _suppression(symbol="Outer.Inner.method")
        inside = _line(PYTHON_SOURCE, "MARK Outer.Inner.method body")
        sibling = _line(PYTHON_SOURCE, "MARK Outer.Inner.sibling body")
        assert supp.matches(_finding("src/app.py", inside), resolver)
        assert not supp.matches(_finding("src/app.py", sibling), resolver)

    def test_enclosing_symbol_covers_nested_definitions(self, root):
        resolver = SymbolResolver(root)
        inside = _line(PYTHON_SOURCE, "MARK Outer.Inner.method body")
        assert _suppression(symbol="Outer").matches(
            _finding("src/app.py", inside), resolver
        )
        assert not _suppression(symbol="method").matches(
            _finding("src/app.py", inside), resolver
        )

    def test_finding_must_lie_wholly_inside(self, root):
        resolver = SymbolResolver(root)
        first = _def_line(PYTHON_SOURCE, "def module_function")
        last = _line(PYTHON_SOURCE, "MARK module_function body")
        supp = _suppression(symbol="module_function")
        assert supp.matches(_finding("src/app.py", first, last), resolver)
        assert not supp.matches(_finding("src/app.py", first, last + 3), resolver)
        assert not supp.matches(_finding("src/app.py", first - 2, last), resolver)

    def test_other_fields_still_narrow(self, root):
        resolver = SymbolResolver(root)
        inside = _line(PYTHON_SOURCE, "MARK module_function body")
        finding = _finding("src/app.py", inside)
        assert _suppression(symbol="module_function").matches(finding, resolver)
        assert not _suppression(symbol="module_function", rule_id="B101").matches(
            finding, resolver
        )
        assert not _suppression(symbol="module_function", path="lib/*.py").matches(
            finding, resolver
        )
        assert not _suppression(
            symbol="module_function", line_start=1, line_end=2
        ).matches(finding, resolver)
        assert not _suppression(
            symbol="module_function", package_name="requests"
        ).matches(finding, resolver)

    def test_path_glob_follows_a_moved_symbol(self, tmp_path):
        moved = "\n\n\n# padding\n" + PYTHON_SOURCE
        _write(tmp_path, "pkg/new_home.py", moved)
        resolver = SymbolResolver(tmp_path)
        line = _line(moved, "MARK module_function body")
        supp = _suppression(symbol="module_function", path="**/*.py")
        assert supp.matches(_finding("pkg/new_home.py", line), resolver)

    def test_expired_entry_never_matches(self, root):
        resolver = SymbolResolver(root)
        inside = _line(PYTHON_SOURCE, "MARK module_function body")
        yesterday = (date.today() - timedelta(days=1)).isoformat()
        tomorrow = (date.today() + timedelta(days=1)).isoformat()
        finding = _finding("src/app.py", inside)
        assert _suppression(symbol="module_function", expiration=tomorrow).matches(
            finding, resolver
        )
        assert not _suppression(symbol="module_function", expiration=yesterday).matches(
            finding, resolver
        )

    def test_without_a_resolver_a_symbol_entry_matches_nothing(self, root):
        inside = _line(PYTHON_SOURCE, "MARK module_function body")
        assert not _suppression(symbol="module_function").matches(
            _finding("src/app.py", inside)
        )

    def test_finding_without_a_line_never_matches(self, root):
        resolver = SymbolResolver(root)
        assert not _suppression(symbol="module_function").matches(
            _finding("src/app.py", None), resolver
        )

    def test_removed_symbol_never_matches(self, root):
        resolver = SymbolResolver(root)
        inside = _line(PYTHON_SOURCE, "MARK module_function body")
        assert not _suppression(symbol="deleted_function").matches(
            _finding("src/app.py", inside), resolver
        )


class TestFailClosed:
    def test_parse_error(self, tmp_path, caplog):
        _write(tmp_path, "src/app.py", "def broken(:\n    eval(x)\n")
        with caplog.at_level(logging.WARNING, logger="ash"):
            assert not SymbolResolver(tmp_path).contains("src/app.py", 2, 2, "broken")
        assert "does not parse cleanly" in caplog.text
        assert "line 1" in caplog.text

    def test_partial_tree_is_not_trusted(self, tmp_path):
        # The function parses; a later line does not. The whole file fails
        # closed rather than trusting the part that happened to parse.
        _write(tmp_path, "src/app.py", "def fine():\n    eval(x)\n\nclass (:\n")
        assert not SymbolResolver(tmp_path).contains("src/app.py", 2, 2, "fine")

    def test_unsupported_language(self, tmp_path, caplog):
        _write(tmp_path, "src/main.go", "package main\nfunc run() {}\n")
        with caplog.at_level(logging.WARNING, logger="ash"):
            assert not SymbolResolver(tmp_path).contains("src/main.go", 2, 2, "run")
        assert "no symbol grammar for extension '.go'" in caplog.text

    def test_missing_file(self, tmp_path, caplog):
        with caplog.at_level(logging.WARNING, logger="ash"):
            assert not SymbolResolver(tmp_path).contains("src/gone.py", 1, 1, "f")
        assert "cannot be read" in caplog.text

    def test_outside_the_scan_root(self, tmp_path, caplog):
        _write(tmp_path, "outside.py", "def f():\n    pass\n")
        root = tmp_path / "root"
        root.mkdir()
        with caplog.at_level(logging.WARNING, logger="ash"):
            assert not SymbolResolver(root).contains("../outside.py", 2, 2, "f")
        assert "outside the scan root" in caplog.text

    def test_missing_extra(self, tmp_path, caplog, monkeypatch):
        _write(tmp_path, "src/app.py", PYTHON_SOURCE)
        # A None entry in sys.modules makes `import tree_sitter` raise
        # ImportError, which is what an install without the extra does.
        monkeypatch.setitem(sys.modules, "tree_sitter", None)
        monkeypatch.setattr(symbol_spans, "_language_cache", {})
        inside = _line(PYTHON_SOURCE, "MARK module_function body")
        with caplog.at_level(logging.WARNING, logger="ash"):
            assert not _suppression(symbol="module_function").matches(
                _finding("src/app.py", inside), SymbolResolver(tmp_path)
            )
        assert "'symbols' extra" in caplog.text
        assert "automated-security-helper[symbols]" in caplog.text
        assert not symbol_spans.symbols_extra_available()

    def test_each_reason_warns_once_per_resolver(self, tmp_path, caplog):
        _write(tmp_path, "src/main.go", "package main\n")
        resolver = SymbolResolver(tmp_path)
        with caplog.at_level(logging.WARNING, logger="ash"):
            for line in range(1, 4):
                resolver.contains("src/main.go", line, line, "run")
        assert caplog.text.count("no symbol grammar") == 1


class TestIdentityAndValidation:
    def test_id_without_symbol_is_unchanged(self):
        assert _suppression(line_start=3).id == "src/app.py|B602|3|3"
        assert (
            _suppression(package_name="lodash").id == "src/app.py|B602|*|*|lodash@*@*"
        )

    def test_id_with_symbol_has_six_parts(self):
        assert (
            _suppression(symbol="Outer.method").id
            == "src/app.py|B602|*|*|*@*@*|Outer.method"
        )
        assert (
            _suppression(symbol="Outer.method", package_name="lodash").id
            == "src/app.py|B602|*|*|lodash@*@*|Outer.method"
        )
        assert _suppression(symbol="a").id != _suppression(symbol="b").id

    @pytest.mark.parametrize(
        "symbol",
        ["MyClass.my_method", "f", "_private", "Ünïcode.naïve", "$jq", "A.#priv"],
    )
    def test_valid_symbols(self, symbol):
        assert _suppression(symbol=symbol).symbol == symbol

    @pytest.mark.parametrize(
        "symbol",
        ["", "A..b", ".a", "a.", "a b", "A.*", "f()", "1abc", "A::b", "a/b"],
    )
    def test_invalid_symbols_are_rejected_by_the_model(self, symbol):
        with pytest.raises(ValueError, match="dotted qualified name"):
            _suppression(symbol=symbol)

    def test_config_with_invalid_symbol_fails_validation(self):
        with pytest.raises(ValueError, match="dotted qualified name"):
            AshConfig(
                project_name="p",
                global_settings={
                    "suppressions": [{"path": "a.py", "reason": "r", "symbol": "a b"}]
                },
            )


def _lint(suppressions) -> LintResult:
    result = LintResult(config_path=Path("x.yaml"))
    ConfigLinter._check_suppression_issues(
        {"global_settings": {"suppressions": suppressions}}, result
    )
    return result


def _symbol_issues(result: LintResult):
    return [i for i in result.issues if i.category == LintCategory.SUPPRESSION_SYMBOL]


class TestLint:
    def test_valid_symbol_has_no_issue(self):
        assert not _symbol_issues(
            _lint([{"path": "src/*.py", "reason": "r", "symbol": "A.b"}])
        )

    def test_invalid_symbol_is_an_error(self):
        issues = _symbol_issues(
            _lint([{"path": "src/a.py", "reason": "r", "symbol": "A.b()"}])
        )
        assert [i.severity for i in issues] == [LintSeverity.ERROR]
        assert issues[0].path == "global_settings.suppressions[0]"

    def test_unsupported_extension_is_a_warning(self):
        issues = _symbol_issues(
            _lint([{"path": "cmd/*.go", "reason": "r", "symbol": "run"}])
        )
        assert [i.severity for i in issues] == [LintSeverity.WARNING]
        assert "'.go'" in issues[0].message

    def test_missing_extra_is_reported_once(self, monkeypatch):
        monkeypatch.setattr(symbol_spans, "symbols_extra_available", lambda: False)
        issues = _symbol_issues(
            _lint(
                [
                    {"path": "a.py", "reason": "r", "symbol": "f"},
                    {"path": "b.py", "reason": "r", "symbol": "g"},
                ]
            )
        )
        assert len(issues) == 1
        assert "automated-security-helper[symbols]" in issues[0].message

    def test_linter_id_matches_model_id(self):
        raw = {"path": "a.py", "rule_id": "B602", "reason": "r", "symbol": "A.b"}
        assert ConfigLinter._make_suppression_id(raw) == AshSuppression(**raw).id


def _sarif(uri: str, lines) -> SarifReport:
    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="bandit", version="1")),
                results=[
                    Result(
                        ruleId="B602",
                        message=Message(text="subprocess with shell=True"),
                        locations=[
                            Location(
                                physicalLocation=PhysicalLocation2(
                                    artifactLocation=ArtifactLocation(uri=uri),
                                    region=Region(startLine=line, endLine=line),
                                )
                            )
                        ],
                    )
                    for line in lines
                ],
            )
        ],
    )


def _context(root: Path, out: Path, suppressions) -> PluginContext:
    config = AshConfig(
        project_name="p", global_settings={"suppressions": list(suppressions)}
    )
    return PluginContext(source_dir=root, output_dir=out, config=config)


class TestApplyToSarif:
    def test_suppresses_inside_and_leaves_sibling_visible(self, tmp_path):
        root = tmp_path / "src_root"
        _write(root, "src/app.py", PYTHON_SOURCE)
        inside = _line(PYTHON_SOURCE, "MARK Outer.Inner.method body")
        sibling = _line(PYTHON_SOURCE, "MARK Outer.Inner.sibling body")
        supp = _suppression(symbol="Outer.Inner.method")
        used: set = set()
        report = apply_suppressions_to_sarif(
            _sarif("src/app.py", [inside, sibling]),
            _context(root, tmp_path / "out", [supp]),
            used_suppressions=used,
        )
        results = report.runs[0].results
        assert results[0].suppressions and len(results[0].suppressions) == 1
        assert not results[1].suppressions
        assert used == {supp.id}

    def test_each_file_is_parsed_once_and_only_when_needed(self, tmp_path, monkeypatch):
        root = tmp_path / "src_root"
        _write(root, "src/app.py", PYTHON_SOURCE)
        _write(root, "other/untouched.py", PYTHON_SOURCE)
        parsed = []
        real = symbol_spans.index_symbols

        def counting(source, grammar):
            parsed.append(grammar.language)
            return real(source, grammar)

        monkeypatch.setattr(symbol_spans, "index_symbols", counting)
        lines = [
            _line(PYTHON_SOURCE, "MARK module_function body"),
            _line(PYTHON_SOURCE, "MARK Outer.Inner.method body"),
            _line(PYTHON_SOURCE, "MARK conditional body"),
        ]
        supp = _suppression(symbol="module_function")
        context = _context(root, tmp_path / "out", [supp])
        # Twice, as a scan does: once per scanner's SARIF, once for the aggregate.
        for _ in range(2):
            apply_suppressions_to_sarif(_sarif("src/app.py", lines), context)
            # Findings the entry's path does not match never cause a parse.
            apply_suppressions_to_sarif(_sarif("other/untouched.py", lines), context)
        assert parsed == ["Python"]

    def test_config_without_symbols_never_builds_a_resolver(
        self, tmp_path, monkeypatch
    ):
        root = tmp_path / "src_root"
        _write(root, "src/app.py", PYTHON_SOURCE)

        def explode(*args, **kwargs):
            raise AssertionError("SymbolResolver built for a config with no symbol")

        monkeypatch.setattr(
            "automated_security_helper.utils.sarif_utils.SymbolResolver", explode
        )
        report = apply_suppressions_to_sarif(
            _sarif("src/app.py", [5]),
            _context(root, tmp_path / "out", [_suppression(line_start=5, line_end=5)]),
        )
        assert report.runs[0].results[0].suppressions

    def test_removed_symbol_is_reported_unused(self, tmp_path):
        root = tmp_path / "src_root"
        _write(root, "src/app.py", PYTHON_SOURCE)
        live = _suppression(symbol="module_function")
        gone = _suppression(symbol="deleted_function")
        context = _context(root, tmp_path / "out", [live, gone])
        used: set = set()
        apply_suppressions_to_sarif(
            _sarif("src/app.py", [_line(PYTHON_SOURCE, "MARK module_function body")]),
            context,
            used_suppressions=used,
        )
        assert used == {live.id}

        reporter = UnusedSuppressionsReporter(context=context)

        class _Model:
            used_suppressions = used

        unused = [
            s
            for s in context.config.global_settings.suppressions
            if s.id not in _Model.used_suppressions
        ]
        assert [reporter._suppression_to_dict(s) for s in unused] == [
            {
                "path": "src/app.py",
                "rule_id": "B602",
                "line_start": None,
                "line_end": None,
                "reason": "r",
                "expiration": None,
                "symbol": "deleted_function",
            }
        ]
        # The linter rebuilds the same id from that report entry, so
        # `ash config lint --fix-unused` comments out the right entry.
        assert (
            ConfigLinter._make_suppression_id(reporter._suppression_to_dict(gone))
            == gone.id
        )
