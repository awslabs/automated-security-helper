# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A line-scan span table for TOML MCP config (``.codex/config.toml``).

``tomllib`` returns values and no positions. The values here come from ``tomllib``; the
spans come from a scan of the text that follows table headers and ``key = value`` lines.

Limits, all by design:

* A span covers the first line of its key only. The start is the key (or the ``[`` of a
  table header); the end is the end of the value text on that line, a trailing comment
  excluded. A multi-line array or string is not extended to its last line.
* A pointer that has no line of its own (an element of an array, a key inside an inline
  table, a key of a dotted-key table that only appears as part of a longer key) has no
  entry; ``McpServerEntry.span`` falls back to the nearest parent that has one.
* ``[[array.tables]]`` headers set the current table but get no span of their own.
"""

import bisect
import json
import re
import tomllib
from typing import Any, Dict, List, Optional, Tuple

from automated_security_helper.utils.mcp_config.json_spans import JsonSpanError
from automated_security_helper.utils.mcp_config.model import Span, pointer_join

_BARE = re.compile(r"[A-Za-z0-9_-]+")
_ERROR_POSITION = re.compile(r"line (\d+), column (\d+)")


def _pointer(parts: List[str]) -> str:
    pointer = ""
    for part in parts:
        pointer = pointer_join(pointer, part)
    return pointer


class _Scanner:
    def __init__(self, text: str):
        self.text = text
        self.n = len(text)
        self._line_starts: List[int] = [0]
        for m in re.finditer("\n", text):
            self._line_starts.append(m.end())
        self.spans: Dict[str, Span] = {}
        self.key_spans: Dict[str, Span] = {}

    def pos(self, offset: int) -> Tuple[int, int]:
        line_index = bisect.bisect_right(self._line_starts, offset) - 1
        return line_index + 1, offset - self._line_starts[line_index] + 1

    def one_line(self, start: int, end: int) -> Span:
        line, col = self.pos(start)
        _, end_col = self.pos(end)
        return Span(line=line, col=col, end_line=line, end_col=end_col)

    def key_path(self, i: int) -> Tuple[List[str], int]:
        """Read a dotted key starting at ``i``; return its parts and the next offset."""
        parts: List[str] = []
        text = self.text
        while True:
            while i < self.n and text[i] in " \t":
                i += 1
            if i >= self.n:
                return parts, i
            ch = text[i]
            if ch == '"':
                j = i + 1
                while j < self.n and text[j] != '"' and text[j] != "\n":
                    j += 2 if text[j] == "\\" else 1
                raw = text[i : j + 1]
                try:
                    parts.append(json.loads(raw))
                except ValueError:
                    parts.append(raw[1:-1])
                i = j + 1
            elif ch == "'":
                j = text.find("'", i + 1)
                if j < 0 or text.find("\n", i, j) >= 0:
                    return parts, i
                parts.append(text[i + 1 : j])
                i = j + 1
            else:
                m = _BARE.match(text, i)
                if m is None:
                    return parts, i
                parts.append(m.group())
                i = m.end()
            while i < self.n and text[i] in " \t":
                i += 1
            if i < self.n and text[i] == ".":
                i += 1
                continue
            return parts, i

    def scan_value(self, i: int) -> Tuple[int, int]:
        """Scan one value from ``i``.

        Returns ``(end of the first line's value text, offset of the newline that
        ends the whole value)``.
        """
        text, n = self.text, self.n
        depth = 0
        first_end = i
        first_done = False
        while i < n:
            ch = text[i]
            if ch == "\n":
                first_done = True
                if depth <= 0:
                    return first_end, i
                i += 1
                continue
            if ch == "#":
                nl = text.find("\n", i)
                first_done = True
                i = n if nl < 0 else nl
                continue
            if ch in "\"'":
                triple = text.startswith(ch * 3, i)
                if triple:
                    j = i + 3
                    while j < n:
                        if ch == '"' and text[j] == "\\":
                            j += 2
                            continue
                        if text.startswith(ch * 3, j):
                            j += 3
                            while j < n and text[j] == ch:
                                j += 1
                            break
                        j += 1
                    else:
                        j = n
                else:
                    j = i + 1
                    while j < n and text[j] != ch and text[j] != "\n":
                        j += 2 if (ch == '"' and text[j] == "\\") else 1
                    j = min(j + 1, n) if j < n and text[j] == ch else j
                if not first_done:
                    inner_nl = text.find("\n", i, j)
                    if inner_nl < 0:
                        first_end = j
                    else:
                        first_end = (
                            inner_nl - 1 if text[inner_nl - 1] == "\r" else inner_nl
                        )
                        first_done = True
                i = j
                continue
            if ch in "[{":
                depth += 1
            elif ch in "]}":
                depth -= 1
            if not first_done and ch not in " \t\r":
                first_end = i + 1
            i += 1
        return first_end, n

    def run(self) -> None:
        text, n = self.text, self.n
        table: List[str] = []
        i = 0
        while i < n:
            nl = text.find("\n", i)
            line_end = n if nl < 0 else nl
            j = i
            while j < line_end and text[j] in " \t":
                j += 1
            if j >= line_end or text[j] == "#":
                i = line_end + 1
                continue
            if text[j] == "[":
                is_array = text.startswith("[[", j)
                parts, k = self.key_path(j + (2 if is_array else 1))
                close = "]]" if is_array else "]"
                if parts and text.startswith(close, k):
                    end = k + len(close)
                    table = parts
                    if not is_array:
                        span = self.one_line(j, end)
                        self.spans[_pointer(parts)] = span
                        self.key_spans[_pointer(parts)] = span
                        for depth in range(1, len(parts)):
                            prefix = _pointer(parts[:depth])
                            self.spans.setdefault(prefix, span)
                            self.key_spans.setdefault(prefix, span)
                i = line_end + 1
                continue
            parts, k = self.key_path(j)
            if parts and k < line_end and text[k] == "=":
                value_start = k + 1
                while value_start < n and text[value_start] in " \t":
                    value_start += 1
                first_end, value_end = self.scan_value(value_start)
                pointer = _pointer(table + parts)
                self.spans[pointer] = self.one_line(j, max(first_end, k + 1))
                key_end = k
                while text[key_end - 1] in " \t":
                    key_end -= 1
                self.key_spans[pointer] = self.one_line(j, key_end)
                i = value_end + 1
                continue
            i = line_end + 1


class TomlSpans:
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


def parse_toml_with_spans(text: str) -> TomlSpans:
    """Parse ``text`` with ``tomllib`` and scan it for first-line spans."""
    try:
        value = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        found: Optional[re.Match[str]] = _ERROR_POSITION.search(str(exc))
        line = int(found.group(1)) if found else 1
        col = int(found.group(2)) if found else 1
        raise JsonSpanError("invalid TOML", line, col) from None
    scanner = _Scanner(text)
    scanner.run()
    return TomlSpans(value, scanner.spans, scanner.key_spans)
