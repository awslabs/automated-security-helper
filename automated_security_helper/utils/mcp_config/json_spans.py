# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A position-aware JSON reader for MCP config files.

``json.loads`` gives values and no positions, and an ``object_pairs_hook`` cannot recover
them. This module is a small recursive-descent parser that returns the same Python value
``json.loads`` would, plus a table from JSON pointer to the source span of that value and
of the member key that holds it.

It accepts what editors write in these files: ``//`` and ``/* */`` comments (VS Code's
``mcp.json`` is JSONC) and trailing commas. Nothing else is relaxed: a bare word, a
single-quoted string or a raw control character in a string is a parse error.

A document that is not valid is refused with :class:`JsonSpanError`, which carries the
1-based line and column of the problem and a fixed reason. It never quotes the document:
these files can hold tokens.

When an object repeats a key the last value wins, as in ``json.loads``, and the span table
holds the last occurrence too.
"""

import bisect
import json
import re
from typing import Any, Dict, List, Tuple

from automated_security_helper.utils.mcp_config.model import (
    Span,
    pointer_join,
)

MAX_DEPTH = 100

_WS = " \t\r\n"
_BOM = chr(0xFEFF)
_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_LITERALS = {"true": True, "false": False, "null": None}


class JsonSpanError(ValueError):
    """The document is not readable JSON. Carries a position, never document text."""

    def __init__(self, reason: str, line: int, col: int):
        super().__init__(f"{reason} at line {line}, column {col}")
        self.reason = reason
        self.line = line
        self.col = col


class JsonSpans:
    """The parsed value and its span tables."""

    def __init__(
        self,
        value: Any,
        spans: Dict[str, Span],
        key_spans: Dict[str, Span],
    ):
        self.value = value
        self.spans = spans
        self.key_spans = key_spans


class _Parser:
    def __init__(self, text: str):
        self.text = text
        self.n = len(text)
        self.i = 0
        self.spans: Dict[str, Span] = {}
        self.key_spans: Dict[str, Span] = {}
        self._line_starts: List[int] = [0]
        for m in re.finditer("\n", text):
            self._line_starts.append(m.end())

    def pos(self, offset: int) -> Tuple[int, int]:
        line_index = bisect.bisect_right(self._line_starts, offset) - 1
        return line_index + 1, offset - self._line_starts[line_index] + 1

    def span(self, start: int, end: int) -> Span:
        line, col = self.pos(start)
        end_line, end_col = self.pos(end)
        return Span(line=line, col=col, end_line=end_line, end_col=end_col)

    def fail(self, reason: str, offset: int | None = None) -> "JsonSpanError":
        line, col = self.pos(self.i if offset is None else offset)
        return JsonSpanError(reason, line, col)

    def skip(self) -> None:
        text, n = self.text, self.n
        while self.i < n:
            ch = text[self.i]
            if ch in _WS:
                self.i += 1
            elif text.startswith("//", self.i):
                nl = text.find("\n", self.i)
                self.i = n if nl < 0 else nl + 1
            elif text.startswith("/*", self.i):
                close = text.find("*/", self.i + 2)
                if close < 0:
                    raise self.fail("unterminated comment")
                self.i = close + 2
            else:
                break

    def parse_document(self) -> Any:
        if self.text.startswith(_BOM):
            self.i = 1
        self.skip()
        value = self.parse_value("", 0)
        self.skip()
        if self.i != self.n:
            raise self.fail("unexpected content after the document")
        return value

    def parse_value(self, pointer: str, depth: int) -> Any:
        if depth > MAX_DEPTH:
            raise self.fail("nesting too deep")
        if self.i >= self.n:
            raise self.fail("unexpected end of document")
        start = self.i
        ch = self.text[self.i]
        value: Any
        if ch == "{":
            value = self.parse_object(pointer, depth)
        elif ch == "[":
            value = self.parse_array(pointer, depth)
        elif ch == '"':
            value, _ = self.parse_string()
        else:
            value = self.parse_scalar()
        self.spans[pointer] = self.span(start, self.i)
        return value

    def parse_string(self) -> Tuple[str, int]:
        text = self.text
        start = self.i
        j = start + 1
        while True:
            if j >= self.n:
                raise self.fail("unterminated string", start)
            ch = text[j]
            if ch == "\\":
                j += 2
                continue
            if ch == '"':
                break
            j += 1
        raw = text[start : j + 1]
        try:
            value = json.loads(raw)
        except ValueError:
            raise self.fail("invalid string", start) from None
        self.i = j + 1
        return value, start

    def parse_scalar(self) -> Any:
        text = self.text
        for word, value in _LITERALS.items():
            if text.startswith(word, self.i):
                self.i += len(word)
                return value
        m = _NUMBER.match(text, self.i)
        if m is None:
            raise self.fail("unexpected character")
        self.i = m.end()
        return json.loads(m.group())

    def parse_array(self, pointer: str, depth: int) -> List[Any]:
        self.i += 1
        items: List[Any] = []
        while True:
            self.skip()
            if self.i >= self.n:
                raise self.fail("unterminated array")
            if self.text[self.i] == "]":
                self.i += 1
                return items
            items.append(
                self.parse_value(pointer_join(pointer, str(len(items))), depth + 1)
            )
            self.skip()
            if self.i >= self.n:
                raise self.fail("unterminated array")
            ch = self.text[self.i]
            if ch == ",":
                self.i += 1
            elif ch != "]":
                raise self.fail("expected ',' or ']'")

    def parse_object(self, pointer: str, depth: int) -> Dict[str, Any]:
        self.i += 1
        members: Dict[str, Any] = {}
        while True:
            self.skip()
            if self.i >= self.n:
                raise self.fail("unterminated object")
            ch = self.text[self.i]
            if ch == "}":
                self.i += 1
                return members
            if ch != '"':
                raise self.fail("expected a string key")
            key, key_start = self.parse_string()
            key_end = self.i
            self.skip()
            if self.i >= self.n or self.text[self.i] != ":":
                raise self.fail("expected ':'")
            self.i += 1
            self.skip()
            child = pointer_join(pointer, key)
            members[key] = self.parse_value(child, depth + 1)
            self.key_spans[child] = self.span(key_start, key_end)
            self.skip()
            if self.i >= self.n:
                raise self.fail("unterminated object")
            ch = self.text[self.i]
            if ch == ",":
                self.i += 1
            elif ch != "}":
                raise self.fail("expected ',' or '}'")


def parse_json_with_spans(text: str) -> JsonSpans:
    """Parse ``text`` and return the value with its pointer-to-span tables."""
    parser = _Parser(text)
    value = parser.parse_document()
    return JsonSpans(value, parser.spans, parser.key_spans)
