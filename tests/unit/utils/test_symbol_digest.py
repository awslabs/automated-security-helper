# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The symbol digest: what a symbol-scoped ``.ash.lock`` scope is bound to.

Why this exists
---------------
A symbol suppression covers a finding whose lines lie inside one of its
symbol's spans, and a span is whole lines. A symbol-scoped lock entry stops
applying when the code it covers changes, so its digest has to cover every token
a finding inside the span could sit on, and nothing an edit elsewhere could
touch without changing what the definition means:

- every token on the span's lines (the line window), so in
  ``const a = () => 1, b = () => evil();`` an edit to ``b`` invalidates ``a``;
- every definition bearing the name (overloads, a redefinition);
- the headers of the definitions it sits in (bases, decorators, parameters);
- the file's prelude (byte order mark, encoding declaration, ``#!``,
  ``from __future__``, the directive prologue).

What it does not cover is pinned as unchanged (imports, constants, class
attributes, other definitions, callers, enclosing control flow), so widening
it is a visible decision. These tests parse with tree-sitter, the ``symbols``
extra.
"""

from __future__ import annotations

from typing import Optional

import pytest

from automated_security_helper.utils import symbol_spans
from tests.utils.optional_extras import require_symbols_extra

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _extra_and_fresh_cache():
    require_symbols_extra()
    symbol_spans.clear_symbol_cache()
    yield
    symbol_spans.clear_symbol_cache()


def _digest(source: bytes, symbol: str, name: str = "a.py") -> Optional[str]:
    return symbol_spans.analyze(source, name).symbol_digest(symbol)


def _same(first: bytes, second: bytes, symbol: str, name: str = "a.py") -> bool:
    one = _digest(first, symbol, name)
    other = _digest(second, symbol, name)
    assert one is not None and other is not None, (one, other)
    return one == other


class TestLineWindow:
    def test_an_edit_to_a_declaration_sharing_the_line_changes_the_symbol(self):
        assert not _same(
            b"const a = () => 1, b = () => 2;\n",
            b"const a = () => 1, b = () => evil();\n",
            "a",
            "a.js",
        )

    def test_an_edit_on_another_line_does_not(self):
        assert _same(
            b"const a = () => 1;\nconst b = () => 2;\n",
            b"const a = () => 1;\nconst b = () => evil();\n",
            "a",
            "a.js",
        )

    def test_a_class_field_alone_on_its_line_ignores_another_member(self):
        assert _same(
            b"class C {\n  h = () => {};\n  m() { return 1; }\n}\n",
            b"class C {\n  h = () => {};\n  m() { return 2; }\n}\n",
            "C.h",
            "a.js",
        )

    def test_on_a_one_line_class_a_sibling_member_changes_the_method(self):
        assert not _same(
            b"class A { m() {} n() {} }\n",
            b"class A { m() {} n() { evil(); } }\n",
            "A.m",
            "a.js",
        )

    def test_code_after_the_class_on_the_methods_line_changes_the_method(self):
        # No sibling of the method holds the call, so the window climbs out of
        # the class to the statement that shares the line.
        assert not _same(
            b"class A { m() { return 1; } } g();\n",
            b"class A { m() { return 1; } } evil();\n",
            "A.m",
            "a.js",
        )

    def test_a_java_member_shares_its_line_with_the_next_class(self):
        assert not _same(
            b"class A { void m() {} } class B { void n() {} }\n",
            b"class A { void m() {} } class B { void n() { evil(); } }\n",
            "A.m",
            "A.java",
        )

    def test_a_typescript_decorator_on_the_line_above_is_the_members(self):
        assert not _same(
            b"class W {\n  @log()\n  render() { return 1; }\n}\n",
            b"class W {\n  @trace()\n  render() { return 1; }\n}\n",
            "W.render",
            "a.ts",
        )


class TestOccurrences:
    def test_a_second_definition_of_the_name_changes_it(self):
        assert not _same(
            b"def risky():\n    return 1\n",
            b"def risky():\n    return 1\n\n\ndef risky():\n    return evil()\n",
            "risky",
        )

    def test_an_overload_signature_changes_the_implementation(self):
        assert not _same(
            b"function f(a: string): void;\nfunction f(a: any) { return a; }\n",
            b"function f(a: number): void;\nfunction f(a: any) { return a; }\n",
            "f",
            "a.ts",
        )


class TestHeaders:
    METHOD = b"class A(Base):\n    def m(self):\n        return 1\n\n    def other(self):\n        return 2\n"

    def test_a_class_base_changes_the_method(self):
        assert not _same(self.METHOD, self.METHOD.replace(b"(Base)", b"(Other)"), "A.m")

    def test_a_class_decorator_changes_the_method(self):
        assert not _same(self.METHOD, b"@frozen\n" + self.METHOD, "A.m")

    def test_a_sibling_methods_edit_does_not(self):
        assert _same(self.METHOD, self.METHOD.replace(b"return 2", b"return 3"), "A.m")

    def test_an_enclosing_methods_decorator_changes_what_it_holds(self):
        source = b"class A:\n    def m(self):\n        def inner():\n            return 1\n        return inner\n"
        decorated = source.replace(b"    def m", b"    @cached\n    def m")
        assert not _same(source, decorated, "A.m.inner")
        assert not _same(source, decorated, "A.m")

    def test_an_outer_functions_parameters_change_the_inner_one(self):
        source = (
            b"def outer(p):\n    def inner():\n        return 1\n    return inner\n"
        )
        assert not _same(source, source.replace(b"(p)", b"(p, q)"), "outer.inner")

    def test_an_arrow_functions_parameters_change_the_inner_one(self):
        source = b"const outer = (p) => {\n  function inner() { return 1; }\n  return inner;\n};\n"
        assert not _same(
            source, source.replace(b"(p)", b"(p, q)"), "outer.inner", "a.js"
        )

    def test_java_extends_and_a_record_component_change_the_member(self):
        klass = b"class A extends B {\n  void m() { }\n}\n"
        assert not _same(klass, klass.replace(b"B", b"C"), "A.m", "a.java")
        record = b"record R(int x) {\n  void m() { }\n}\n"
        assert not _same(record, record.replace(b"int x", b"long x"), "R.m", "a.java")


LIMITS = b"""\
import os

LIMIT = 3


class A:
    rate = 1

    def m(self):
        return os.getcwd()

    def other(self):
        return self.m()


if True:

    def g():
        return 1
"""


class TestWhatItDoesNotCover:
    @pytest.mark.parametrize(
        "old, new, symbol",
        [
            (b"import os", b"import os, sys", "A.m"),
            (b"LIMIT = 3", b"LIMIT = 4", "A.m"),
            (b"rate = 1", b"rate = 2", "A.m"),
            (b"return self.m()", b"return self.m() + 1", "A.m"),
            (b"if True:", b"if False:", "g"),
        ],
    )
    def test_an_edit_outside_the_definition_leaves_it_unchanged(self, old, new, symbol):
        assert old in LIMITS
        assert _same(LIMITS, LIMITS.replace(old, new), symbol)

    @pytest.mark.parametrize(
        "old, new, symbol",
        [
            (b"return os.getcwd()", b"return os.getcwd() + 1", "A.m"),
            (b"return 1", b"return 2", "g"),
        ],
    )
    def test_an_edit_inside_it_is_seen(self, old, new, symbol):
        assert not _same(LIMITS, LIMITS.replace(old, new), symbol)

    def test_a_directive_in_an_enclosing_body_is_not_covered(self):
        source = b'function outer() {\n  "use strict";\n  function inner() { return 1; }\n}\n'
        assert _same(
            source,
            source.replace(b'"use strict";', b'"use asm";'),
            "outer.inner",
            "a.js",
        )


class TestPrelude:
    SOURCE = b"x = 1\n\n\ndef f():\n    return 1\n"

    @pytest.mark.parametrize(
        "changed",
        [
            b"# -*- coding: latin-1 -*-\n" + SOURCE,
            b"#!/usr/bin/env python3\n" + SOURCE,
            b"from __future__ import annotations\n" + SOURCE,
            b"\xef\xbb\xbf" + SOURCE,
        ],
    )
    def test_a_python_prelude_change_changes_the_symbol(self, changed):
        assert not _same(self.SOURCE, changed, "f")

    def test_a_leading_license_comment_does_not(self):
        assert _same(self.SOURCE, b"# Copyright someone\n" + self.SOURCE, "f")

    def test_a_directive_prologue_changes_the_symbol(self):
        source = b"function f() { return 1; }\n"
        assert not _same(source, b'"use strict";\n' + source, "f", "a.js")
        tsx = b"export const A = () => <b>x</b>;\n"
        assert not _same(tsx, b"/** @jsxImportSource y */\n" + tsx, "A", "a.tsx")


class TestComments:
    SOURCE = b"def f():\n    return 1\n"

    def test_a_comment_inside_the_definition_changes_it(self):
        assert not _same(self.SOURCE, b"def f():\n    # why\n    return 1\n", "f")

    def test_a_comment_on_the_line_above_does_not(self):
        assert _same(self.SOURCE, b"# about f\n" + self.SOURCE, "f")

    def test_a_whitespace_edit_inside_does_not(self):
        assert _same(self.SOURCE, b"def f( ):\n\treturn  1\n", "f")


class TestNesting:
    SOURCE = b"class Outer:\n    class Inner:\n        def m(self):\n            return 1\n\n    def other(self):\n        return 2\n"

    def test_an_edit_to_a_nested_definition_changes_the_outer_one(self):
        assert not _same(
            self.SOURCE, self.SOURCE.replace(b"return 1", b"return 9"), "Outer"
        )

    def test_an_edit_to_a_sibling_leaves_the_nested_one(self):
        assert _same(
            self.SOURCE, self.SOURCE.replace(b"return 2", b"return 9"), "Outer.Inner.m"
        )


class TestNames:
    def test_an_undefined_name_has_no_digest(self):
        source = b"def f():\n    return 1\n"
        assert _digest(source, "g") is None
        assert _digest(source, "f") is not None

    def test_a_name_no_symbol_can_spell_is_never_digested(self):
        source = b"class A:\n    pass\n"
        assert _digest(source, "\x00A") is None
        assert _digest(source, "A") is not None
