# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The position-aware JSON reader: values match ``json.loads``, spans are exact."""

import json
from pathlib import Path

import pytest

from automated_security_helper.utils.mcp_config.json_spans import (
    MAX_DEPTH,
    JsonSpanError,
    parse_json_with_spans,
)
from automated_security_helper.utils.mcp_config.model import Span

pytestmark = pytest.mark.unit

FIXTURES = Path(__file__).resolve().parents[3] / "test_data" / "mcp_config"
STRICT_JSON_FIXTURES = sorted(
    p for p in FIXTURES.rglob("*.json") if "vscode" not in p.relative_to(FIXTURES).parts
)


def _span(line, col, end_line, end_col):
    return Span(line=line, col=col, end_line=end_line, end_col=end_col)


def test_there_are_strict_json_fixtures_to_compare():
    assert len(STRICT_JSON_FIXTURES) == 16


@pytest.mark.parametrize(
    "path", STRICT_JSON_FIXTURES, ids=lambda p: str(p.relative_to(FIXTURES))
)
def test_value_matches_json_loads(path):
    text = path.read_text(encoding="utf-8")
    assert parse_json_with_spans(text).value == json.loads(text)


def test_scalar_spans_are_one_based_and_end_exclusive():
    parsed = parse_json_with_spans('{"a": "xy", "b": 12, "c": true, "d": null}')
    assert parsed.spans["/a"] == _span(1, 7, 1, 11)
    assert parsed.spans["/b"] == _span(1, 18, 1, 20)
    assert parsed.spans["/c"] == _span(1, 27, 1, 31)
    assert parsed.spans["/d"] == _span(1, 38, 1, 42)
    assert parsed.spans[""] == _span(1, 1, 1, 43)


def test_key_spans_cover_the_quoted_key():
    parsed = parse_json_with_spans('{"abc": 1}')
    assert parsed.key_spans["/abc"] == _span(1, 2, 1, 7)
    assert parsed.spans["/abc"] == _span(1, 9, 1, 10)


def test_object_and_array_spans_run_open_to_close_across_lines():
    text = '{\n  "xs": [\n    1,\n    2\n  ]\n}\n'
    parsed = parse_json_with_spans(text)
    assert parsed.spans["/xs"] == _span(2, 9, 5, 4)
    assert parsed.spans["/xs/0"] == _span(3, 5, 3, 6)
    assert parsed.spans["/xs/1"] == _span(4, 5, 4, 6)
    assert parsed.spans[""] == _span(1, 1, 6, 2)


def test_pointer_tokens_are_escaped():
    parsed = parse_json_with_spans('{"a/b": {"c~d": 1}}')
    assert "/a~1b/c~0d" in parsed.spans
    assert parsed.key_spans["/a~1b"] == _span(1, 2, 1, 7)


def test_columns_count_characters_not_bytes_or_utf16_units():
    # The e-acute is two bytes in UTF-8 and the emoji is two UTF-16 units; both are
    # one character here.
    parsed = parse_json_with_spans('{"é😀": "x"}')
    assert parsed.key_spans["/é😀"] == _span(1, 2, 1, 6)
    assert parsed.spans["/é😀"] == _span(1, 8, 1, 11)


def test_crlf_line_endings_count_one_line_each():
    parsed = parse_json_with_spans('{\r\n  "a": 1\r\n}\r\n')
    assert parsed.spans["/a"] == _span(2, 8, 2, 9)


def test_string_escapes_decode_like_json_loads():
    text = r'{"a": "q\"uote é \n tab\t \\ \/ 😀"}'
    parsed = parse_json_with_spans(text)
    assert parsed.value == json.loads(text)
    # The span covers the escaped source, quotes included.
    assert parsed.spans["/a"].end_col == len(text)


def test_line_and_block_comments_and_trailing_commas_are_accepted():
    text = (
        "{\n"
        "  // a line comment\n"
        '  "a": [1, 2,], /* block\n'
        "  comment */\n"
        '  "b": {"c": 3,},\n'
        "}\n"
    )
    parsed = parse_json_with_spans(text)
    assert parsed.value == {"a": [1, 2], "b": {"c": 3}}
    assert parsed.spans["/a/1"] == _span(3, 12, 3, 13)
    assert parsed.spans["/b/c"] == _span(5, 14, 5, 15)


def test_a_comment_marker_inside_a_string_is_text():
    parsed = parse_json_with_spans('{"u": "http://example.com/a"}')
    assert parsed.value == {"u": "http://example.com/a"}


def test_a_leading_byte_order_mark_is_skipped():
    parsed = parse_json_with_spans(chr(0xFEFF) + '{"a": 1}')
    assert parsed.value == {"a": 1}


def test_a_repeated_key_keeps_the_last_value_and_its_span():
    parsed = parse_json_with_spans('{"a": 1, "a": 22}')
    assert parsed.value == {"a": 22}
    assert parsed.spans["/a"] == _span(1, 15, 1, 17)


def test_numbers_match_json_loads():
    text = "[0, -1, 1.5, 2e3, -0.25E-2]"
    assert parse_json_with_spans(text).value == json.loads(text)


@pytest.mark.parametrize(
    "text, reason, line, col",
    [
        ("", "unexpected end of document", 1, 1),
        ("{", "unterminated object", 1, 2),
        ("[1, 2", "unterminated array", 1, 6),
        ('{"a" 1}', "expected ':'", 1, 6),
        ("{a: 1}", "expected a string key", 1, 2),
        ("[1 2]", "expected ',' or ']'", 1, 4),
        ('{"a": 1 "b": 2}', "expected ',' or '}'", 1, 9),
        ('{"a": "x', "unterminated string", 1, 7),
        ("{'a': 1}", "expected a string key", 1, 2),
        ("[tru]", "unexpected character", 1, 2),
        ("{} x", "unexpected content after the document", 1, 4),
        ("/* open", "unterminated comment", 1, 1),
        ('{"a": "tab\there"}', "invalid string", 1, 7),
        ("\n\n  [1,\n  ?]", "unexpected character", 4, 3),
    ],
)
def test_invalid_documents_are_refused_with_a_position(text, reason, line, col):
    with pytest.raises(JsonSpanError) as raised:
        parse_json_with_spans(text)
    assert raised.value.reason == reason
    assert (raised.value.line, raised.value.col) == (line, col)


def test_an_error_never_quotes_the_document():
    secret = "ghp_notARealTokenValue123"
    with pytest.raises(JsonSpanError) as raised:
        parse_json_with_spans('{"token": "%s" "x": 1}' % secret)
    assert secret not in str(raised.value)


def test_nesting_past_the_limit_is_refused():
    deep = "[" * (MAX_DEPTH + 5) + "]" * (MAX_DEPTH + 5)
    with pytest.raises(JsonSpanError) as raised:
        parse_json_with_spans(deep)
    assert raised.value.reason == "nesting too deep"
    ok = "[" * MAX_DEPTH + "]" * MAX_DEPTH
    assert parse_json_with_spans(ok).value is not None
