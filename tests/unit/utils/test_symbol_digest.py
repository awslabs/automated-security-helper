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
- the headers of the definitions it sits in (bases, decorators, parameters,
  and the directive prologue at the top of an enclosing function's body);
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


# A member's decorator, a comment line, then the member. tree-sitter-typescript
# puts a member's decorator beside it in the class body, so there the comment is
# a sibling between the two; plain JavaScript makes the decorator the method's own.
COMMENTED_MEMBER = b"class W {\n  @log()\n  // a note\n  render() { return 1; }\n}\n"


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

    @pytest.mark.parametrize("name", ["a.ts", "a.tsx"])
    @pytest.mark.parametrize(
        "old, new",
        [(b"@log()", b"@trace()"), (b"  @log()\n", b"")],
        ids=["swapped", "removed"],
    )
    def test_a_comment_after_the_decorator_keeps_it_the_members(self, name, old, new):
        assert old in COMMENTED_MEMBER
        changed = COMMENTED_MEMBER.replace(old, new)
        assert not _same(COMMENTED_MEMBER, changed, "W.render", name)

    @pytest.mark.parametrize(
        "source, old, new, symbol, name",
        [
            pytest.param(
                b"class A:\n    @cached\n    # a note\n    def m(self): return 1\n",
                b"@cached",
                b"@other",
                "A.m",
                "a.py",
                id="python",
            ),
            pytest.param(
                COMMENTED_MEMBER,
                b"@log()",
                b"@trace()",
                "W.render",
                "a.js",
                id="javascript",
            ),
        ],
    )
    def test_python_and_javascript_keep_a_decorator_behind_a_comment(
        self, source, old, new, symbol, name
    ):
        assert not _same(source, source.replace(old, new), symbol, name)


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

    @pytest.mark.parametrize("name", ["a.ts", "a.tsx"])
    def test_a_comment_after_an_enclosing_members_decorator_keeps_it(self, name):
        source = (
            b"class W {\n  @log()\n  // a note\n  render() {\n"
            b"    function inner() { return 1; }\n    return inner;\n  }\n}\n"
        )
        changed = source.replace(b"@log()", b"@trace()")
        assert not _same(source, changed, "W.render.inner", name)

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

    def test_a_directive_in_an_enclosing_body_changes_the_nested_symbol(self):
        source = b'function outer() {\n  "use strict";\n  function inner() { return 1; }\n}\n'
        assert not _same(
            source,
            source.replace(b'"use strict";', b'"use asm";'),
            "outer.inner",
            "a.js",
        )

    @pytest.mark.parametrize(
        "source, symbol",
        [
            pytest.param(
                b'const outer = () => {\n  "use strict";\n  function inner() { return 1; }\n  return inner;\n};\n',
                "outer.inner",
                id="arrow-function",
            ),
            pytest.param(
                b'class C {\n  m() {\n    "use strict";\n    function inner() { return 1; }\n    return inner;\n  }\n}\n',
                "C.m.inner",
                id="method",
            ),
            pytest.param(
                b'function outer() {\n  // a note\n  "use strict";\n  function inner() { return 1; }\n}\n',
                "outer.inner",
                id="after-a-comment",
            ),
        ],
    )
    def test_the_directive_prologue_of_an_enclosing_body_changes_the_nested_symbol(
        self, source, symbol
    ):
        changed = source.replace(b'"use strict";', b'"use asm";')
        assert changed != source
        assert not _same(source, changed, symbol, "a.js")

    def test_a_comment_in_an_enclosing_body_does_not_change_the_nested_symbol(self):
        source = (
            b"function outer() {\n  // a note\n  function inner() { return 1; }\n}\n"
        )
        changed = source.replace(b"// a note", b"// another note")
        assert _same(source, changed, "outer.inner", "a.js")

    def test_a_python_docstring_in_an_enclosing_body_does_not_change_it(self):
        source = b'def outer():\n    "doc"\n    def inner():\n        return 1\n    return inner\n'
        changed = source.replace(b'"doc"', b'"another doc"')
        assert _same(source, changed, "outer.inner")


# Functions that hold a symbol without being definitions: an immediately invoked
# function, a callback (a function and an arrow), the value of
# ``module.exports``, a method of an object literal and a generator function
# expression. None of them is a definition, so none is among the symbol's
# enclosing definitions, but each one's directive prologue governs the code
# inside it as much as a named function's does.
UNNAMED_FUNCTIONS = [
    pytest.param(
        b'(function () {\n  "use strict";\n  function inner() { return 1; }\n})();\n',
        id="iife",
    ),
    pytest.param(
        b'describe("x", function () {\n  "use strict";\n'
        b"  function inner() { return 1; }\n});\n",
        id="callback",
    ),
    pytest.param(
        b'run(() => {\n  "use strict";\n  function inner() { return 1; }\n});\n',
        id="arrow-callback",
    ),
    pytest.param(
        b'module.exports = function () {\n  "use strict";\n'
        b"  function inner() { return 1; }\n  return inner;\n};\n",
        id="module-exports",
    ),
    pytest.param(
        b'const o = {\n  m() {\n    "use strict";\n'
        b"    function inner() { return 1; }\n    return inner;\n  },\n};\n",
        id="object-literal-method",
    ),
    pytest.param(
        b'(function* () {\n  "use strict";\n  function inner() { return 1; }\n})();\n',
        id="generator-iife",
    ),
]


class TestEnclosingFunctions:
    @pytest.mark.parametrize("name", ["a.js", "a.ts", "a.tsx"])
    @pytest.mark.parametrize("source", UNNAMED_FUNCTIONS)
    def test_the_directive_prologue_of_any_function_it_sits_in_changes_it(
        self, source, name
    ):
        changed = source.replace(b'"use strict";', b'"use asm";')
        assert changed != source
        assert not _same(source, changed, "inner", name)

    def test_a_directive_of_a_function_between_two_definitions_changes_it(self):
        # outer is a definition and its own body opens with a call, so only the
        # callback between outer and inner holds the directive.
        source = (
            b'function outer() {\n  run(function () {\n    "use strict";\n'
            b"    function inner() { return 1; }\n  });\n}\n"
        )
        changed = source.replace(b'"use strict";', b'"use asm";')
        assert not _same(source, changed, "outer.inner", "a.js")

    @pytest.mark.parametrize("name", ["a.js", "a.ts"])
    def test_a_directive_after_code_in_such_a_function_does_not_change_it(self, name):
        # A string statement after the first other statement is not a directive.
        source = (
            b'(function () {\n  init();\n  "use strict";\n'
            b"  function inner() { return 1; }\n})();\n"
        )
        changed = source.replace(b'"use strict";', b'"use asm";')
        assert _same(source, changed, "inner", name)

    @pytest.mark.parametrize("name", ["a.js", "a.ts"])
    def test_a_directive_in_a_function_it_is_not_in_does_not_change_it(self, name):
        source = (
            b"(function () {\n  function inner() { return 1; }\n})();\n"
            b'(function () {\n  "use strict";\n})();\n'
        )
        changed = source.replace(b'"use strict";', b'"use asm";')
        assert _same(source, changed, "inner", name)

    def test_a_comment_in_such_a_function_does_not_change_it(self):
        source = (
            b"(function () {\n  // a note\n  function inner() { return 1; }\n})();\n"
        )
        changed = source.replace(b"// a note", b"// another note")
        assert _same(source, changed, "inner", "a.js")


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

    # Spaces in JSX text are text the element renders, not layout between tokens.
    @pytest.mark.parametrize(
        "first, second",
        [
            pytest.param(
                b"export const A = () => <div>hi {x}</div>;\n",
                b"export const A = () => <div>hi{x}</div>;\n",
                id="a-space-before-an-expression",
            ),
            pytest.param(
                b"export const A = () => <p>a  b</p>;\n",
                b"export const A = () => <p>a b</p>;\n",
                id="two-spaces-in-the-text",
            ),
        ],
    )
    def test_whitespace_in_jsx_text_changes_it(self, first, second):
        assert not _same(first, second, "A", "a.tsx")


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
        # Definitions whose names fail SYMBOL_PATTERN, at the top of a file and
        # under the spellable A: a name holding a middle dot (U+00B7), which
        # JavaScript and Python identifiers allow and the pattern's word class
        # does not, and class methods named by a string and by a number. chr()
        # builds the dot, which keeps this file ASCII.
        dotted = ("a" + chr(0xB7) + "b").encode("utf-8")
        javascript = (
            b"class A {\n  'x-y'() { return 1; }\n  1() { return 2; }\n}\nfunction "
            + dotted
            + b"() { return 3; }\n"
        )
        python = (
            b"class A:\n    def "
            + dotted
            + b"(self):\n        return 1\n\n\ndef "
            + dotted
            + b"():\n    return 2\n"
        )
        unspellable = symbol_spans._UNSPELLABLE
        found = []
        for source, name in ((javascript, "a.js"), (python, "a.py")):
            analysis = symbol_spans.analyze(source, name)
            assert analysis.spans is not None, (name, analysis.reason)
            # The control, a name that can be spelled. This first symbol_digest
            # call also fills the analysis's occurrence table.
            assert analysis.symbol_digest("A") is not None, name
            # The occurrence table is private, with no accessor, and it is what
            # symbol_digest looks a name up in: a name read from it is a
            # definition, so a None for it comes from the guard, not "not found".
            found += [
                (analysis, qualified)
                for qualified in analysis._occurrences or {}
                if unspellable in qualified
            ]
        names = [qualified for _, qualified in found]
        assert any(n.startswith(unspellable) for n in names), names
        assert any(not n.startswith(unspellable) for n in names), names
        digested = [q for a, q in found if a.symbol_digest(q) is not None]
        assert digested == []
