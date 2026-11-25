# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The TOML line scan: values from tomllib, first-line spans from the scan."""

import tomllib

import pytest

from automated_security_helper.utils.mcp_config.json_spans import JsonSpanError
from automated_security_helper.utils.mcp_config.model import Span
from automated_security_helper.utils.mcp_config.toml_spans import (
    parse_toml_with_spans,
)

pytestmark = pytest.mark.unit


def _span(line, col, end_col, end_line=None):
    return Span(line=line, col=col, end_line=end_line or line, end_col=end_col)


def test_value_is_what_tomllib_returns():
    text = 'a = 1\n[t]\nb = "x"\n'
    assert parse_toml_with_spans(text).value == tomllib.loads(text)


def test_table_headers_and_key_lines_get_first_line_spans():
    text = '[mcp_servers.x]\ncommand = "sudo"\nargs = ["a", "b"]\n'
    parsed = parse_toml_with_spans(text)
    assert parsed.spans["/mcp_servers/x"] == _span(1, 1, 16)
    assert parsed.spans["/mcp_servers/x/command"] == _span(2, 1, 17)
    assert parsed.key_spans["/mcp_servers/x/command"] == _span(2, 1, 8)
    assert parsed.spans["/mcp_servers/x/args"] == _span(3, 1, 18)


def test_a_trailing_comment_is_not_part_of_the_span():
    parsed = parse_toml_with_spans('k = "v"  # note\n')
    assert parsed.spans["/k"] == _span(1, 1, 8)


def test_a_hash_inside_a_string_is_not_a_comment():
    parsed = parse_toml_with_spans('k = "a # b"  # note\n')
    assert parsed.spans["/k"] == _span(1, 1, 12)


def test_a_multi_line_array_is_spanned_on_its_first_line_only():
    text = "xs = [\n  1,\n  2,\n]\nafter = 1\n"
    parsed = parse_toml_with_spans(text)
    assert parsed.spans["/xs"] == _span(1, 1, 7)
    assert parsed.spans["/after"] == _span(5, 1, 10)


def test_lines_inside_a_multi_line_string_are_not_read_as_keys():
    text = 'doc = """\nfake = 1\n"""\nreal = 2\n'
    parsed = parse_toml_with_spans(text)
    assert "/fake" not in parsed.spans
    assert parsed.spans["/doc"] == _span(1, 1, 10)
    assert parsed.spans["/real"] == _span(4, 1, 9)


def test_a_multi_line_literal_string_is_skipped_too():
    text = "doc = '''\nfake = 1\n'''\nreal = 2\n"
    parsed = parse_toml_with_spans(text)
    assert "/fake" not in parsed.spans
    assert parsed.spans["/real"] == _span(4, 1, 9)


def test_quoted_and_dotted_keys_become_pointer_tokens():
    text = '["a.b"."c/d"]\ne = 1\nf.g = 2\n'
    parsed = parse_toml_with_spans(text)
    assert parsed.spans["/a.b/c~1d"] == _span(1, 1, 14)
    assert parsed.spans["/a.b/c~1d/e"] == _span(2, 1, 6)
    assert parsed.spans["/a.b/c~1d/f/g"] == _span(3, 1, 8)


def test_a_sub_table_gives_its_missing_parents_a_span_but_not_over_a_real_one():
    text = "[a.b.c]\nk = 1\n[a.b]\nm = 2\n"
    parsed = parse_toml_with_spans(text)
    assert parsed.spans["/a"] == _span(1, 1, 8)
    assert parsed.spans["/a/b"] == _span(3, 1, 6)
    assert parsed.spans["/a/b/c/k"] == _span(2, 1, 6)


def test_array_of_tables_headers_set_the_table_without_a_span():
    parsed = parse_toml_with_spans("[[items]]\nname = 1\n")
    assert "/items" not in parsed.spans
    assert parsed.spans["/items/name"] == _span(2, 1, 9)


def test_an_inline_table_has_one_span_for_the_whole_key_line():
    parsed = parse_toml_with_spans("env = { A = 1, B = 2 }\n")
    assert parsed.spans["/env"] == _span(1, 1, 23)
    assert "/env/A" not in parsed.spans


def test_crlf_line_endings_do_not_widen_a_span():
    parsed = parse_toml_with_spans('k = "v"\r\nm = [\r\n1\r\n]\r\n')
    assert parsed.spans["/k"] == _span(1, 1, 8)
    assert parsed.spans["/m"] == _span(2, 1, 6)


def test_invalid_toml_is_refused_without_quoting_it():
    secret = "ghp_notARealTokenValue123"
    with pytest.raises(JsonSpanError) as raised:
        parse_toml_with_spans('token = "%s"\nbroken = \n' % secret)
    assert raised.value.reason == "invalid TOML"
    assert raised.value.line >= 1
    assert secret not in str(raised.value)
