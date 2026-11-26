# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The canonical syntax-tree digest ``.ash.lock`` records (utils/ast_digest.py).

Why this exists
---------------
A lock entry used to be the SHA-256 of the file's raw bytes, so a re-indent or a
checkout that rewrote line endings made every symbol suppression of the file
inert. The digest hashes the tree instead: what changes code changes the digest,
and layout between tokens does not. Each rule below is pinned with a twin that
must give the opposite verdict:

- layout (spaces, tabs, line feeds between tokens, line endings) is ignored in
  every grammar, and one token edit is not;
- every token counts, named or anonymous, and so does the tree's structure;
- string-like literals are hashed as their exact text, comments are tokens, and a
  byte between nodes that is not layout is hashed whole;
- Python's backslash continuation is layout; in JavaScript and TypeScript a line
  break before a token counts;
- the prelude (a byte order mark, an encoding declaration, ``#!``,
  ``from __future__``, a directive prologue) is part of the digest;
- a file digest never equals a symbol digest, and grammars are kept apart;
- the grammar's tables are fingerprinted and the digest tables are validated
  against the running grammar and pinned to the algorithm id.

Every test that parses needs the ``symbols`` extra; the stub-node tests do not.
"""

from __future__ import annotations

import dataclasses
import random
from types import SimpleNamespace
from typing import Any, List, Optional

import pytest

from automated_security_helper.utils import ast_digest, symbol_spans
from automated_security_helper.utils.ast_digest import (
    ALGORITHM,
    LAYOUT,
    POLICY_SHA256,
    DigestUnavailable,
)
from tests.utils.optional_extras import require_symbols_extra

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _fresh_cache():
    symbol_spans.clear_symbol_cache()
    yield
    symbol_spans.clear_symbol_cache()


def _digest(source: bytes, name: str = "a.py") -> str:
    require_symbols_extra()
    return symbol_spans.analyze(source, name).file_digest()


def _symbol(source: bytes, symbol: str, name: str = "a.py") -> Optional[str]:
    require_symbols_extra()
    return symbol_spans.analyze(source, name).symbol_digest(symbol)


# One source per grammar, its layout twin (same tokens on the same lines in
# JS/TS, so the line-feed bit agrees), and a twin with one token edited.
LAYOUT_TWINS = {
    "a.py": (
        b"def f(a, b):\n    return a + b\n",
        b"def f(a,\n      b):   \n\n\treturn a+b\n\n\n",
        b"def f(a, b):\n    return a - b\n",
    ),
    "a.js": (
        b"function f(a, b) {\n  return a + b;\n}\n",
        b"function f( a , b )   {\n\n\t\treturn   a+b;   \n}\n\n",
        b"function f(a, b) {\n  return a - b;\n}\n",
    ),
    "a.ts": (
        b"function f(a: number, b: number): number {\n  return a + b;\n}\n",
        b"function f(a:number,b:number):number {\n\treturn a+b;\n}\n",
        b"function f(a: number, b: number): number {\n  return a * b;\n}\n",
    ),
    "a.tsx": (
        b"const f = (a: number) => {\n  return a + 1;\n};\n",
        b"const f = ( a:number )=>{\n    return a+1;\n};\n",
        b"const f = (a: number) => {\n  return a + 2;\n};\n",
    ),
    "a.java": (
        b"class A { int f(int a) { return a + 1; } }\n",
        b"class A {\n  int f(int a)\n  {\n    return a+1;\n  }\n}\n",
        b"class A { int f(int a) { return a - 1; } }\n",
    ),
}


class TestLayout:
    @pytest.mark.parametrize("name", sorted(LAYOUT_TWINS))
    def test_layout_between_tokens_is_ignored(self, name):
        source, layout, _ = LAYOUT_TWINS[name]
        assert _digest(source, name) == _digest(layout, name)

    @pytest.mark.parametrize("name", sorted(LAYOUT_TWINS))
    def test_one_token_edit_is_not(self, name):
        source, _, edited = LAYOUT_TWINS[name]
        assert _digest(source, name) != _digest(edited, name)

    @pytest.mark.parametrize("name", sorted(LAYOUT_TWINS))
    def test_line_endings_are_ignored(self, name):
        source = LAYOUT_TWINS[name][0]
        crlf = source.replace(b"\n", b"\r\n")
        lone_cr = source.replace(b"\n", b"\r")
        assert _digest(source, name) == _digest(crlf, name) == _digest(lone_cr, name)


class TestTokensAndStructure:
    @pytest.mark.parametrize(
        "first, second",
        [
            (b"a + b\n", b"a - b\n"),
            (b"x is y\n", b"x is not y\n"),
            (b"x in y\n", b"x not in y\n"),
            (b"if a:\n    pass\n", b"while a:\n    pass\n"),
        ],
    )
    def test_every_token_counts_named_or_anonymous(self, first, second):
        assert _digest(first) != _digest(second)

    def test_python_block_structure_counts(self):
        assert _digest(b"if a:\n    b\n    c\n") != _digest(b"if a:\n    b\nc\n")

    def test_javascript_return_before_a_line_break_counts(self):
        assert _digest(b"function f() { return\nx }\n", "a.js") != _digest(
            b"function f() { return x }\n", "a.js"
        )


class TestLiterals:
    @pytest.mark.parametrize(
        "first, second",
        [
            (b'x = "a\\n b"\n', b'x = "a\\nb"\n'),
            (b'x = "\\n \\n"\n', b'x = "\\n\\n"\n'),
            (b'x = f"{y = }"\n', b'x = f"{y=}"\n'),
            (b"x = 'a'\n", b'x = "a"\n'),
        ],
    )
    def test_python_strings_are_their_exact_text(self, first, second):
        assert _digest(first) != _digest(second)

    def test_a_reindented_java_text_block_counts(self):
        first = b'class A { String s = """\n    hi\n    """; }\n'
        second = b'class A { String s = """\n  hi\n  """; }\n'
        assert _digest(first, "a.java") != _digest(second, "a.java")

    def test_template_literal_spacing_counts(self):
        assert _digest(b"let x = `a  b`;\n", "a.js") != _digest(
            b"let x = `a b`;\n", "a.js"
        )
        assert _digest(b"type T = `a ${string}`;\n", "a.ts") != _digest(
            b"type T = `a${string}`;\n", "a.ts"
        )


# Stub nodes: what a digest does with bytes a grammar leaves between its nodes.


class _StubNode:
    def __init__(self, node_type, start, end, children=(), named=True):
        self.type = node_type
        self.start_byte = start
        self.end_byte = end
        self.children = list(children)
        self.child_count = len(self.children)
        self.is_named = named
        self.parent = None
        for child in self.children:
            child.parent = self

    def field_name_for_child(self, index):
        return None

    def walk(self):
        return _StubCursor(self)


class _StubCursor:
    def __init__(self, node):
        self._path: List[Any] = [(node, 0)]

    @property
    def node(self):
        return self._path[-1][0]

    @property
    def field_name(self):
        return None

    def goto_first_child(self):
        node = self.node
        if not node.children:
            return False
        self._path.append((node.children[0], 0))
        return True

    def goto_next_sibling(self):
        if len(self._path) < 2:
            return False
        node, index = self._path[-1]
        parent = self._path[-2][0]
        if index + 1 >= len(parent.children):
            return False
        self._path[-1] = (parent.children[index + 1], index + 1)
        return True

    def goto_parent(self):
        if len(self._path) < 2:
            return False
        self._path.pop()
        return True


_STUB_POLICY = SimpleNamespace(
    verbatim=frozenset(),
    skip=frozenset(),
    line_breaks=False,
    lock_id="stub",
    prologue="",
)


def _stub_digest(source: bytes, gap_start: int, gap_end: int) -> str:
    """A parent over ``source`` with one leaf before and one after the gap."""
    left = _StubNode("leaf", 0, gap_start)
    right = _StubNode("leaf", gap_end, len(source))
    parent = _StubNode("parent", 0, len(source), [left, right])
    walker = ast_digest._Walker(source, _STUB_POLICY)
    walker.walk(parent, "")
    return walker.hexdigest()


class TestGaps:
    def test_a_layout_gap_is_the_gap_free_tree(self):
        assert _stub_digest(b"a  \n b", 1, 5) == _stub_digest(b"ab", 1, 1)

    @pytest.mark.parametrize("gap", [b" x ", b"\x0c", b"\x0b", b"\xc2\xa0"])
    def test_a_gap_holding_a_byte_outside_layout_counts(self, gap):
        source = b"a" + gap + b"b"
        assert _stub_digest(source, 1, 1 + len(gap)) != _stub_digest(b"ab", 1, 1)

    def test_layout_is_space_tab_and_line_feed_only(self):
        assert set(LAYOUT) == {0x20, 0x09, 0x0A}

    def test_a_form_feed_before_the_first_token_counts(self):
        assert _digest(b"\x0c\nx = 1\n") != _digest(b"\nx = 1\n")


class TestComments:
    def test_a_comment_edit_counts(self):
        base = _digest(b"x = 1  # note\n")
        assert base != _digest(b"x = 1  # other\n")
        assert base != _digest(b"x = 1\n")
        assert _digest(b"x = 1\n") != _digest(b"# added\nx = 1\n")

    def test_whitespace_beside_a_comment_does_not(self):
        assert _digest(b"x = 1  # note\n") == _digest(b"x = 1      # note\n")


class TestLineBreaks:
    def test_a_python_backslash_continuation_is_layout(self):
        assert _digest(b"x = 1 + \\\n    2\n") == _digest(b"x = 1 + 2\n")
        assert _digest(b"x = 1 + \\\n    2\n") != _digest(b"x = 1 + 3\n")

    def test_a_typescript_modifier_before_a_line_break_counts(self):
        assert _digest(b"abstract class A {}\n", "a.ts") != _digest(
            b"abstract\nclass A {}\n", "a.ts"
        )

    def test_a_javascript_call_across_a_line_break_counts(self):
        assert _digest(b"a = b\n(c)\n", "a.js") != _digest(b"a = b(c)\n", "a.js")

    def test_a_javascript_reindent_that_moves_no_token_does_not(self):
        assert _digest(b"if (a) {\n  b();\n}\n", "a.js") == _digest(
            b"if (a) {\n\t\t\tb();\n}\n", "a.js"
        )

    def test_python_rewraps_inside_brackets_do_not(self):
        assert _digest(b"f(a, b)\n") == _digest(b"f(\n    a,\n    b)\n")


class TestPrelude:
    @pytest.mark.parametrize("name", sorted(LAYOUT_TWINS))
    def test_a_byte_order_mark_counts(self, name):
        source = LAYOUT_TWINS[name][0]
        assert _digest(source, name) != _digest(b"\xef\xbb\xbf" + source, name)

    @pytest.mark.parametrize(
        "first, second, name",
        [
            (
                b"# -*- coding: latin-1 -*-\nx = 1\n",
                b"# -*- coding: utf-8 -*-\nx = 1\n",
                "a.py",
            ),
            (b"#!/usr/bin/python3\nx = 1\n", b"#!/usr/bin/python2\nx = 1\n", "a.py"),
            (b"from __future__ import annotations\nx = 1\n", b"x = 1\n", "a.py"),
            (b'"use strict";\nlet x = 1;\n', b"let x = 1;\n", "a.js"),
        ],
    )
    def test_the_prelude_counts(self, first, second, name):
        assert _digest(first, name) != _digest(second, name)

    def test_an_unreadable_encoding_declaration_is_not_digested(self):
        require_symbols_extra()
        with_latin = b"\xef\xbb\xbf# -*- coding: latin-1 -*-\nx = 1\n"
        with pytest.raises(DigestUnavailable, match="encoding declaration"):
            symbol_spans.analyze(with_latin, "a.py").file_digest()
        with_utf8 = b"\xef\xbb\xbf# -*- coding: utf-8 -*-\nx = 1\n"
        assert len(symbol_spans.analyze(with_utf8, "a.py").file_digest()) == 64


class TestDomains:
    def test_a_file_digest_is_never_a_symbol_digest(self):
        source = b"def f():\n    return 1\n"
        assert _digest(source) != _symbol(source, "f")

    def test_the_same_text_in_two_grammars_digests_apart(self):
        assert _digest(b"let x = 1;\n", "a.js") != _digest(b"let x = 1;\n", "a.ts")


class TestErrors:
    def test_a_parse_error_names_its_line(self):
        require_symbols_extra()
        broken = b"x = 1\ny = (\n"
        with pytest.raises(DigestUnavailable, match="syntax error at line"):
            symbol_spans.analyze(broken, "a.py").file_digest()
        with pytest.raises(symbol_spans.SymbolParseError, match="line"):
            symbol_spans.index_symbols(
                broken, symbol_spans.GRAMMARS_BY_EXTENSION[".py"]
            )
        assert len(_digest(b"x = 1\ny = ()\n")) == 64

    def test_a_file_with_no_grammar_says_which_extension(self):
        analysis = symbol_spans.analyze(b"x: 1\n", "a.yaml")
        with pytest.raises(DigestUnavailable) as caught:
            analysis.file_digest()
        assert str(caught.value) == symbol_spans._unsupported_reason("a.yaml")


class _StubLanguage:
    def __init__(self, kinds, fields=("name",)):
        self._kinds = list(kinds)
        self._fields = list(fields)
        self.abi_version = 14
        self.parse_state_count = 7

    @property
    def node_kind_count(self):
        return len(self._kinds)

    def node_kind_for_id(self, kind):
        return self._kinds[kind]

    def node_kind_is_named(self, kind):
        return True

    def node_kind_is_visible(self, kind):
        return True

    @property
    def field_count(self):
        return len(self._fields)

    def field_name_for_id(self, field):
        return self._fields[field - 1]


class TestFingerprint:
    def test_it_is_stable_and_tells_the_grammars_apart(self):
        require_symbols_extra()
        grammars = symbol_spans.digest_grammars()
        prints = {
            g.lock_id: ast_digest.language_fingerprint(symbol_spans._load_language(g))
            for g in grammars
        }
        assert len(set(prints.values())) == len(grammars) == 5
        again = symbol_spans.grammar_identity(grammars[0]).fingerprint
        assert again == prints[grammars[0].lock_id]

    def test_the_binding_exposes_what_the_digest_reads(self):
        require_symbols_extra()
        language = symbol_spans._load_language(
            symbol_spans.GRAMMARS_BY_EXTENSION[".py"]
        )
        for attribute in (
            "abi_version",
            "parse_state_count",
            "node_kind_count",
            "node_kind_for_id",
            "node_kind_is_named",
            "node_kind_is_visible",
            "field_count",
            "field_name_for_id",
            "id_for_node_kind",
        ):
            assert hasattr(language, attribute), attribute
        tree = symbol_spans._parse(
            b"x = 1\n", symbol_spans.GRAMMARS_BY_EXTENSION[".py"]
        )
        cursor = tree.root_node.walk()
        assert cursor.goto_first_child() and hasattr(cursor, "field_name")

    def test_a_renamed_kind_is_another_fingerprint(self):
        first = ast_digest.language_fingerprint(_StubLanguage(["end", "a", "b"]))
        renamed = ast_digest.language_fingerprint(_StubLanguage(["end", "a", "c"]))
        assert first != renamed
        assert first == ast_digest.language_fingerprint(
            _StubLanguage(["end", "a", "b"])
        )


class TestPolicy:
    def test_every_table_type_is_a_named_kind_of_its_pinned_grammar(self):
        require_symbols_extra()
        for grammar in symbol_spans.digest_grammars():
            language = symbol_spans._load_language(grammar)
            ast_digest.validate_policy(language, grammar)
        named = {
            ".ts": "template_literal_type",
            ".py": "future_import_statement",
            ".js": "hash_bang_line",
        }
        for extension, node_type in named.items():
            grammar = symbol_spans.GRAMMARS_BY_EXTENSION[extension]
            assert node_type in ast_digest.policy_node_types(grammar)
        assert "line_continuation" in symbol_spans.GRAMMARS_BY_EXTENSION[".py"].skip

    def test_a_table_naming_a_type_the_grammar_lacks_makes_it_undigestible(self):
        require_symbols_extra()
        java = symbol_spans.GRAMMARS_BY_EXTENSION[".java"]
        broken = dataclasses.replace(java, verbatim=java.verbatim | {"comment"})
        with pytest.raises(DigestUnavailable, match="comment"):
            ast_digest.validate_policy(symbol_spans._load_language(java), broken)

    def test_the_tables_are_the_ones_the_algorithm_id_names(self):
        grammars = symbol_spans.digest_grammars()
        assert ALGORITHM == "ash-ast-1"
        assert ast_digest.policy_sha256(grammars) == POLICY_SHA256
        ast_digest.check_policy_pin(grammars)
        edited = [
            dataclasses.replace(g, verbatim=g.verbatim | {"comment"})
            if g.lock_id == "python"
            else g
            for g in grammars
        ]
        with pytest.raises(DigestUnavailable, match=ALGORITHM):
            ast_digest.check_policy_pin(edited)


class TestDepth:
    def test_a_deeply_nested_file_digests(self):
        source = b"x = " + b"(" * 3000 + b"1" + b")" * 3000 + b"\n"
        assert len(_digest(source)) == 64


#: Pinned so a change to the record format, a domain tag or the tables shows: a
#: digest that moves means existing locks read every changed file as changed, and
#: needs a new ``ALGORITHM``. The fingerprints pin the grammar builds uv.lock pins.
GOLDEN_FINGERPRINTS = {
    "java": "a253b3379f9038f58b43406e9932c6a4c4ddf65d78b3b66b6a761412e512484b",
    "javascript": "1b5660a725a0fab6e5999b0b428e90c796f59f870e237e2dfc09c8ee8b8da6ef",
    "python": "c7db63356729a56e790e54ed5202e975f81ff7c194866457bbd64e3c40b2b72d",
    "tsx": "67750497583e0f879e37f73a1967e53e71a1a7ac92c17f86bebe632e3946b441",
    "typescript": "5dfcdf75016f1e69da4ffb84cd33256753198b496dc8f6dfbe56b1112c92edee",
}

GOLDEN = [
    (
        "a.py",
        b"x = 1\n",
        "4329e521586652095b039b986c9a4da9dee96af57289b4a69fcbb2cba1912021",
    ),
    (
        "a.py",
        b"def f(a, b):\n    return a + b\n",
        "c564b487b979b14fbf53f4c89957f87c8125137dfe637cd6b110479cf709d154",
    ),
    (
        "a.py",
        b"class A(B):\n    @d\n    def m(self):\n        pass\n",
        "9266f58289fc89c91d292458daab80c4b6d69912b56fe4bf6d93c407c3f8c3f9",
    ),
    (
        "a.py",
        b'x = f"{y!r:>4}"  # c\n',
        "752a785f844afcab836d9ed4c25a327f02612640449ea926f9d070c7465380bd",
    ),
    (
        "a.py",
        b"\xef\xbb\xbf# coding: utf-8\nfrom __future__ import annotations\n",
        "8d411cfdf96e0e199520bf2a1dd2b3cc315743fefdc811d9e3ccaa56c0af5952",
    ),
    (
        "a.js",
        b"let x = 1;\n",
        "8e7d3682198a25ca34efbc405b36b9b6f71e78702e0b75e5990a946069f2ce72",
    ),
    (
        "a.js",
        b"#!/usr/bin/env node\n'use strict';\nfunction f() { return `${a}`; }\n",
        "d44a887e716e4e3316dd1b874442d64cea682e5c56111fd4bc98862bf9674771",
    ),
    (
        "a.js",
        b"const r = /a+/g;\nexport default class A extends B {}\n",
        "0370c57e07e82e3f5520014f1218bd725be812c94a5eb794ba3e4b4cfbdcd3b3",
    ),
    (
        "a.js",
        b"a\n++b\n",
        "d836fb563e3096195c0ec16fc576342d8f84836ac2b0379b5a7b618ab166f175",
    ),
    (
        "a.ts",
        b"let x: number = 1;\n",
        "f988216a695b9fde3b1821a5554d01a50e94befb03dc0898e7d50ded2791c99c",
    ),
    (
        "a.ts",
        b"abstract class A { abstract m(): void; }\n",
        "2c46a2721533e9a79357ce19784848ab8947da25d6963d60cbd25b3850014df3",
    ),
    (
        "a.ts",
        b"type T = `a${string}`;\ninterface I { x?: T }\n",
        "0aac200d8aae4593c62701a6dc6ec811c747c1c4f54ac5183293928f9957cdeb",
    ),
    (
        "a.ts",
        b"@d class A { @e m() {} }\n",
        "1595483e6233aef31aa62ce2fc5dcb2d1ca0036508f1e773b1ae8426198b3038",
    ),
    (
        "a.tsx",
        b"const A = () => <div>hi {x}</div>;\n",
        "00e4ab5e26742bb041f76bad922669eece0c05d9ee55850bbb923a9610b20699",
    ),
    (
        "a.tsx",
        b'/** @jsxImportSource x */\nexport const B = <a b="c" />;\n',
        "6ae5f10bfedd917fc3c559723ae670fe7c6d579f91d11a2400157d3dcf3fc9a1",
    ),
    (
        "a.java",
        b"class A {}\n",
        "70267cfa63e256afa4e5f58b8f7ce1f6843f3e5bcaf3ebf275c021a770a46f19",
    ),
    (
        "a.java",
        b"class A { void m() { int x = 'a'; } }\n",
        "d63783dab8de4cb07070a927fa9d5d9013d90f5706848469a28eee5caa6a6446",
    ),
    (
        "a.java",
        b'record R(int x) { String s = """\n  t\n  """; }\n',
        "a4ca15889addb74d9c375f2de8839e00afccf71032381f45f566ede30667a749",
    ),
    (
        "a.java",
        b"@interface N {}\n// c\n/* d */\nenum E { X }\n",
        "f070969e289fe358976b22b4abab949b9552d8a423febb069e15cea63c23c1eb",
    ),
    (
        "a.py",
        b"x = 1 + \\\n    2\n",
        "2334ae7de783590135e3d3d897eed9f733b01c1c2bd013b7fd9be580ec8aaea6",
    ),
]


class TestGolden:
    def test_the_grammar_fingerprints_are_the_pinned_builds(self):
        require_symbols_extra()
        found = {
            g.lock_id: symbol_spans.grammar_identity(g).fingerprint
            for g in symbol_spans.digest_grammars()
        }
        assert found == GOLDEN_FINGERPRINTS

    @pytest.mark.parametrize("name, source, expected", GOLDEN)
    def test_the_file_digest_is_the_pinned_one(self, name, source, expected):
        assert _digest(source, name) == expected


# The property: a byte that is not layout, replaced, changes the digest whenever
# the file still parses cleanly; layout inserted between two tokens on one line
# never does.

PROPERTY_SAMPLES = {
    "a.py": [
        b"import os\n\n\ndef run(cmd, *, shell=False):\n    if shell:\n        return os.system(cmd)\n    return [c for c in cmd.split() if c]\n",
        b"class Handler(Base):\n    rate = 3\n\n    def handle(self, x):\n        # scale it\n        return x * self.rate - 1\n",
        b'NAME = "value"\nTOTAL = {"a": 1, "b": 2}\nprint(NAME, TOTAL["a"] + 7)\n',
        b"def gen(n):\n    while n > 0:\n        yield n % 2\n        n //= 2\n",
    ],
    "a.js": [
        b"function run(cmd, shell) {\n  if (shell) {\n    return exec(cmd);\n  }\n  return cmd.split(' ');\n}\n",
        b"class Handler extends Base {\n  handle(x) {\n    // scale it\n    return x * this.rate - 1;\n  }\n}\n",
        b"const total = { a: 1, b: 2 };\nconsole.log(total.a + 7, 'value');\n",
        b"let n = 10;\nwhile (n > 0) {\n  n = n - 3;\n}\n",
    ],
    "a.ts": [
        b"function run(cmd: string, shell: boolean): string[] {\n  if (shell) {\n    return [cmd];\n  }\n  return cmd.split(' ');\n}\n",
        b"class Handler {\n  private rate = 3;\n  handle(x: number): number {\n    return x * this.rate - 1;\n  }\n}\n",
        b"interface Item { name: string; count: number }\nconst item: Item = { name: 'v', count: 7 };\n",
        b"let n: number = 10;\nwhile (n > 0) {\n  n = n - 3;\n}\n",
    ],
    "a.tsx": [
        b"function run(cmd: string, shell: boolean): string[] {\n  if (shell) {\n    return [cmd];\n  }\n  return cmd.split(' ');\n}\n",
        b"const total = { a: 1, b: 2 };\nexport const f = (x: number) => x * total.a + 7;\n",
        b"let n: number = 10;\nwhile (n > 0) {\n  n = n - 3;\n}\n",
        b"export function g(items: number[]): number {\n  return items.reduce((a, b) => a + b, 0);\n}\n",
    ],
    "a.java": [
        b"class Runner {\n  int run(int cmd, boolean shell) {\n    if (shell) {\n      return cmd * 2;\n    }\n    return cmd - 1;\n  }\n}\n",
        b"class Handler extends Base {\n  int rate = 3;\n  // scale it\n  int handle(int x) { return x * rate - 1; }\n}\n",
        b'class Names {\n  static final String NAME = "value";\n  int total() { return NAME.length() + 7; }\n}\n',
        b"class Gen {\n  void loop(int n) {\n    while (n > 0) {\n      n = n / 2;\n    }\n  }\n}\n",
    ],
}

_REPLACEMENTS = b"abcxyzABQ019_+-*/<>=!&|^~%.,;:()[]{}'\"#@$?"


def _parses_cleanly(source: bytes, name: str) -> bool:
    analysis = symbol_spans.analyze(source, name)
    return analysis.spans is not None


def _token_ends_inside_a_line(source: bytes, name: str) -> List[int]:
    """Offsets where a token ends and another starts later on the same line,
    with no verbatim node or JSX text around: inserting a space there is layout."""
    grammar = symbol_spans.grammar_for_path(name)
    assert grammar is not None
    tree = symbol_spans._parse(symbol_spans._normalize_source(source), grammar)
    ends = []
    stack = [tree.root_node]
    leaves = []
    while stack:
        node = stack.pop()
        if node.child_count == 0 or (node.is_named and node.type in grammar.verbatim):
            leaves.append(node)
            continue
        stack.extend(reversed(node.children))
    leaves.sort(key=lambda n: n.start_byte)
    for left, right in zip(leaves, leaves[1:]):
        if "jsx" in left.type or "jsx" in right.type:
            continue
        if b"\n" in source[left.end_byte : right.start_byte]:
            continue
        ends.append(left.end_byte)
    return ends


class TestProperty:
    @pytest.mark.parametrize("name", sorted(PROPERTY_SAMPLES))
    def test_a_replaced_byte_that_still_parses_changes_the_digest(self, name):
        require_symbols_extra()
        rng = random.Random(f"ash-ast-1:{name}")
        checked = 0
        for sample in PROPERTY_SAMPLES[name]:
            base = _digest(sample, name)
            positions = [i for i, byte in enumerate(sample) if byte not in LAYOUT]
            attempts = 0
            while (
                checked < 60 * (PROPERTY_SAMPLES[name].index(sample) + 1)
                and attempts < 4000
            ):
                attempts += 1
                position = rng.choice(positions)
                replacement = rng.choice(_REPLACEMENTS)
                if replacement == sample[position]:
                    continue
                mutated = (
                    sample[:position] + bytes([replacement]) + sample[position + 1 :]
                )
                if not _parses_cleanly(mutated, name):
                    continue
                assert _digest(mutated, name) != base, (position, chr(replacement))
                checked += 1
        assert checked >= 200, checked

    @pytest.mark.parametrize("name", sorted(PROPERTY_SAMPLES))
    def test_layout_inserted_between_tokens_never_changes_the_digest(self, name):
        require_symbols_extra()
        inserted = 0
        for sample in PROPERTY_SAMPLES[name]:
            base = _digest(sample, name)
            for position in _token_ends_inside_a_line(sample, name):
                for layout in (b" ", b"\t"):
                    mutated = sample[:position] + layout + sample[position:]
                    if not _parses_cleanly(mutated, name):
                        continue
                    assert _digest(mutated, name) == base, (position, layout)
                    inserted += 1
        assert inserted >= 40, inserted
