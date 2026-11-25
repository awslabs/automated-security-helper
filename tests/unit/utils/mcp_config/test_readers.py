# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Per-format parse rows: entry fields and span positions for each fixture pair."""

import json
from pathlib import Path

import pytest

from automated_security_helper.utils.mcp_config import (
    FORMATS,
    McpConfigParseError,
    McpServerEntry,
    Span,
    detect_format,
    format_by_id,
    parse_mcp_config_file,
    parse_mcp_config_text,
)

pytestmark = pytest.mark.unit

FIXTURES = Path(__file__).resolve().parents[3] / "test_data" / "mcp_config"

REL_PATHS = {
    "claude_code": ".mcp.json",
    "cursor": ".cursor/mcp.json",
    "vscode": ".vscode/mcp.json",
    "gemini": ".gemini/settings.json",
    "claude_desktop": "config/claude_desktop_config.json",
    "amazonq": ".amazonq/mcp.json",
    "roo": ".roo/mcp.json",
    "kiro": ".kiro/settings/mcp.json",
    "devin": ".devin/mcp_config.json",
    "codex": ".codex/config.toml",
}

CMD = "/usr/local/bin/mcp-files"
ARGS = ["--root", "/srv/data"]
DOCS = "https://mcp.example.com/docs"
BAD_DOCS = "http://mcp.example.com/docs"


def _span(line, col, end_line, end_col):
    return Span(line=line, col=col, end_line=end_line, end_col=end_col)


# (server_name, kind, command, args, url, transport, auto_approve)
def _files(transport=None, auto=None):
    return ("files", "stdio", CMD, ARGS, None, transport, auto or {})


def _remote(url, transport, name="docs"):
    return (name, "remote", None, [], url, transport, {})


def _elevated(transport=None, auto=None):
    return ("elevated", "stdio", "sudo", [CMD, *ARGS], None, transport, auto or {})


def _runner(transport=None):
    return ("runner", "stdio", "npx", ["-y", "some-mcp-server"], None, transport, {})


EXPECTED = {
    # The JSON fixtures are in the pre-commit JSON hook's own format (keys sorted,
    # arrays expanded), so entries come out in alphabetical order.
    ("claude_code", "benign"): [_remote(DOCS, "http"), _files()],
    ("claude_code", "violating"): [
        _elevated(),
        _remote(BAD_DOCS, "http", "remote"),
        _runner(),
    ],
    ("vscode", "benign"): [_files("stdio"), _remote(DOCS, "http")],
    ("vscode", "violating"): [
        _elevated("stdio"),
        _runner("stdio"),
        _remote(BAD_DOCS, "http", "remote"),
    ],
    ("gemini", "benign"): [
        _remote("https://mcp.example.com/sse", "sse", "events"),
        _files(auto={"trust": False}),
        _remote("https://mcp.example.com/stream", "http", "stream"),
    ],
    ("gemini", "violating"): [
        _elevated(auto={"trust": True}),
        _remote("http://mcp.example.com/sse", "sse", "events"),
        _runner(),
        _remote("http://mcp.example.com/stream", "http", "stream"),
    ],
    ("roo", "benign"): [
        _remote(DOCS, "streamable-http"),
        _files(auto={"alwaysAllow": []}),
    ],
    ("roo", "violating"): [
        _elevated(auto={"alwaysAllow": ["read_file", "write_file"]}),
        _remote(BAD_DOCS, "streamable-http", "remote"),
        _runner(),
    ],
    ("kiro", "benign"): [_remote(DOCS, None), _files(auto={"autoApprove": []})],
    ("kiro", "violating"): [
        _elevated(auto={"autoApprove": ["*"]}),
        _remote(BAD_DOCS, None, "remote"),
        _runner(),
    ],
    ("devin", "benign"): [_remote(DOCS, None), _files()],
    ("devin", "violating"): [
        _elevated(),
        _remote(BAD_DOCS, None, "remote"),
        _runner(),
    ],
    ("codex", "benign"): [_files(), _remote(DOCS, None)],
    ("codex", "violating"): [
        _elevated(auto={"approval_mode": "full-auto"}),
        _runner(),
        _remote(BAD_DOCS, None, "remote"),
    ],
}
for _same in ("cursor", "amazonq", "claude_desktop"):
    EXPECTED[(_same, "benign")] = EXPECTED[("claude_code", "benign")]
    EXPECTED[(_same, "violating")] = EXPECTED[("claude_code", "violating")]


def _load(format_id, variant):
    rel = REL_PATHS[format_id]
    return parse_mcp_config_file(FIXTURES / format_id / variant / rel, rel)


def _row(entry: McpServerEntry):
    return (
        entry.server_name,
        entry.kind,
        entry.command,
        entry.args,
        entry.url,
        entry.transport,
        entry.auto_approve,
    )


def test_the_fixture_matrix_covers_every_format_in_both_variants():
    assert {fmt.format_id for fmt in FORMATS} == set(REL_PATHS)
    assert set(EXPECTED) == {(f, v) for f in REL_PATHS for v in ("benign", "violating")}
    for format_id, rel in REL_PATHS.items():
        for variant in ("benign", "violating"):
            assert (FIXTURES / format_id / variant / rel).is_file()


@pytest.mark.parametrize("format_id, variant", sorted(EXPECTED))
def test_entry_fields_per_format(format_id, variant):
    entries = _load(format_id, variant)
    assert [_row(e) for e in entries] == EXPECTED[(format_id, variant)]
    for entry in entries:
        assert entry.format_id == format_id
        assert entry.source_file == REL_PATHS[format_id]
        assert entry.pointer.endswith("/" + entry.server_name)


@pytest.mark.parametrize("format_id", sorted(REL_PATHS))
def test_every_entry_has_a_span_for_itself_and_its_command_or_url(format_id):
    for variant in ("benign", "violating"):
        for entry in _load(format_id, variant):
            assert entry.span() is not None
            assert entry.key_span() is not None
            if entry.kind == "stdio":
                assert entry.span("/command") is not None
            else:
                assert entry.url_pointer is not None
                assert entry.url_pointer.startswith(entry.pointer + "/")
                assert entry.span(entry.url_pointer[len(entry.pointer) :]) is not None


def test_env_and_headers_are_read_as_string_maps():
    docs, files = _load("claude_code", "benign")
    assert files.env == {"LOG_LEVEL": "info"}
    assert docs.headers == {"X-Client": "ash-fixture"}
    codex = _load("codex", "benign")
    assert codex[0].env == {"LOG_LEVEL": "info"}
    inline = _load("codex", "violating")[1]
    assert inline.env == {"API_TOKEN": "literal-not-a-reference"}


@pytest.mark.parametrize(
    "format_id", ["claude_code", "cursor", "amazonq", "claude_desktop"]
)
def test_spans_in_the_mcp_servers_json_shape_benign(format_id):
    docs, files = _load(format_id, "benign")
    assert files.pointer == "/mcpServers/files"
    assert files.span() == _span(10, 14, 19, 6)
    assert files.key_span() == _span(10, 5, 10, 12)
    assert files.span("/command") == _span(15, 18, 15, 44)
    assert files.span("/args") == _span(11, 15, 14, 8)
    assert files.span("/args/0") == _span(12, 9, 12, 17)
    assert files.span("/args/1") == _span(13, 9, 13, 20)
    assert files.span("/env/LOG_LEVEL") == _span(17, 22, 17, 28)
    assert files.key_span("/env/LOG_LEVEL") == _span(17, 9, 17, 20)
    assert docs.pointer == "/mcpServers/docs"
    assert docs.span() == _span(3, 13, 9, 6)
    assert docs.url_pointer == "/mcpServers/docs/url"
    assert docs.span("/type") == _span(7, 15, 7, 21)
    assert docs.span("/url") == _span(8, 14, 8, 44)


@pytest.mark.parametrize(
    "format_id", ["claude_code", "cursor", "amazonq", "claude_desktop"]
)
def test_spans_in_the_mcp_servers_json_shape_violating(format_id):
    elevated, remote, runner = _load(format_id, "violating")
    assert elevated.span("/command") == _span(9, 18, 9, 24)
    assert elevated.span("/args/0") == _span(5, 9, 5, 35)
    assert runner.span("/command") == _span(20, 18, 20, 23)
    assert runner.span("/args/0") == _span(17, 9, 17, 13)
    assert runner.span("/args/1") == _span(18, 9, 18, 26)
    assert remote.url_pointer == "/mcpServers/remote/url"
    assert remote.span("/url") == _span(13, 14, 13, 43)


def test_a_span_lookup_falls_back_to_the_nearest_parent():
    files = _load("claude_code", "benign")[1]
    assert files.span("/args/9") == files.span("/args")
    assert files.span("/nothing/at/all") == files.span()


def test_vscode_reads_the_servers_key_and_tolerates_comments_and_trailing_commas():
    elevated, runner, remote = _load("vscode", "violating")
    assert elevated.pointer == "/servers/elevated"
    assert elevated.span("/command") == _span(7, 18, 7, 24)
    assert runner.span("/command") == _span(12, 18, 12, 23)
    assert remote.span("/url") == _span(17, 14, 17, 43)


def test_vscode_ignores_the_inputs_key():
    entries = parse_mcp_config_text(
        '{"inputs": [{"id": "x"}], "servers": {"a": {"command": "c"}}}',
        ".vscode/mcp.json",
    )
    assert [e.server_name for e in entries] == ["a"]


def test_gemini_distinguishes_sse_url_from_streamable_http_url():
    elevated, events, _runner_entry, stream = _load("gemini", "violating")
    assert elevated.span("/trust") == _span(10, 16, 10, 20)
    assert elevated.key_span("/trust") == _span(10, 7, 10, 14)
    assert stream.url_pointer == "/mcpServers/stream/httpUrl"
    assert stream.span("/httpUrl") == _span(23, 18, 23, 49)
    assert events.url_pointer == "/mcpServers/events/url"
    benign = _load("gemini", "benign")
    assert benign[1].span("/trust") == _span(15, 16, 15, 21)


def test_a_gemini_entry_with_both_url_fields_prefers_http_url():
    entries = parse_mcp_config_text(
        '{"mcpServers": {"a": {"url": "https://a/sse", "httpUrl": "https://a/http"}}}',
        ".gemini/settings.json",
    )
    assert entries[0].url == "https://a/http"
    assert entries[0].transport == "http"


def test_an_entry_with_both_a_command_and_a_url_keeps_both_fields():
    """The url decides the classed kind; the declared command is kept with it, so
    the policy checks and the converter (which gate on the fields, not the kind)
    see the command a decoy url would otherwise hide."""
    entries = parse_mcp_config_text(
        json.dumps(
            {
                "mcpServers": {
                    "both": {
                        "type": "stdio",
                        "command": "sudo",
                        "args": ["/usr/local/bin/mcp-files"],
                        "url": "http://127.0.0.1:1/",
                    }
                }
            }
        ),
        ".mcp.json",
    )
    (entry,) = entries
    assert entry.kind == "remote"
    assert entry.command == "sudo"
    assert entry.args == ["/usr/local/bin/mcp-files"]
    assert entry.url == "http://127.0.0.1:1/"
    assert entry.transport == "stdio"


def test_roo_and_kiro_auto_approve_lists_are_kept_raw_with_spans():
    roo = _load("roo", "violating")[0]
    assert roo.auto_approve == {"alwaysAllow": ["read_file", "write_file"]}
    assert roo.span("/alwaysAllow") is not None
    kiro = _load("kiro", "violating")[0]
    assert kiro.span("/autoApprove") == _span(9, 22, 11, 8)
    assert kiro.span("/autoApprove/0") == _span(10, 9, 10, 12)


def test_devin_remote_url_comes_from_server_url():
    remote = _load("devin", "violating")[1]
    assert remote.url_pointer == "/mcpServers/remote/serverUrl"
    assert remote.span("/serverUrl") == _span(12, 20, 12, 49)


def test_codex_spans_are_first_line_of_the_key_only():
    elevated, runner, remote = _load("codex", "violating")
    assert elevated.pointer == "/mcp_servers/elevated"
    assert elevated.span() == _span(3, 1, 3, 23)
    assert elevated.span("/command") == _span(4, 1, 4, 17)
    assert elevated.span("/args").line == 5
    assert elevated.span("/args/1") == elevated.span("/args")
    assert elevated.span("/approval_mode").line == 6
    assert runner.span("/env") == _span(11, 1, 11, 48)
    assert runner.span("/env/API_TOKEN") == runner.span("/env")
    assert remote.span() == _span(13, 1, 13, 21)
    assert remote.span("/url") == _span(14, 1, 14, 36)


def test_codex_sub_table_keys_have_their_own_line():
    files = _load("codex", "benign")[0]
    assert files.span("/env") == _span(7, 1, 7, 24)
    assert files.span("/env/LOG_LEVEL") == _span(8, 1, 8, 19)


@pytest.mark.parametrize(
    "rel_path, format_id",
    [
        (".mcp.json", "claude_code"),
        ("./.mcp.json", "claude_code"),
        (".cursor/mcp.json", "cursor"),
        (".vscode/mcp.json", "vscode"),
        (".gemini/settings.json", "gemini"),
        ("claude_desktop_config.json", "claude_desktop"),
        ("deep/er/claude_desktop_config.json", "claude_desktop"),
        (".amazonq/mcp.json", "amazonq"),
        (".roo/mcp.json", "roo"),
        (".kiro/settings/mcp.json", "kiro"),
        (".devin/mcp_config.json", "devin"),
        (".codex/config.toml", "codex"),
    ],
)
def test_detection_matches_the_exact_paths(rel_path, format_id):
    found = detect_format(rel_path)
    assert found is not None and found.format_id == format_id
    assert format_by_id(format_id) is found


@pytest.mark.parametrize(
    "rel_path",
    [
        "sub/.mcp.json",
        "sub/.cursor/mcp.json",
        ".cursor/mcp.jsonc",
        "mcp.json",
        ".claude/settings.json",
        ".zed/settings.json",
        ".codex/config.yaml",
        "x/.codex/config.toml",
        "claude_desktop_config.json.bak",
        "",
    ],
)
def test_other_paths_are_not_targets_and_read_as_empty(rel_path):
    assert detect_format(rel_path) is None
    assert (
        parse_mcp_config_text('{"mcpServers": {"a": {"command": "c"}}}', rel_path) == []
    )


def test_a_document_without_the_servers_key_or_with_a_wrong_shape_reads_empty():
    for text in ("{}", "[]", '{"mcpServers": []}', '{"mcpServers": {"a": 1}}'):
        assert parse_mcp_config_text(text, ".mcp.json") == []


def test_an_entry_with_neither_command_nor_url_is_a_stdio_entry_without_a_command():
    entry = parse_mcp_config_text('{"mcpServers": {"a": {}}}', ".mcp.json")[0]
    assert (entry.kind, entry.command, entry.url, entry.args) == (
        "stdio",
        None,
        None,
        [],
    )


def test_wrongly_typed_fields_are_dropped_not_guessed():
    text = (
        '{"mcpServers": {"a": {"command": 5, "args": "x", "env": [1],'
        ' "url": 7, "headers": "h"}}}'
    )
    entry = parse_mcp_config_text(text, ".mcp.json")[0]
    assert entry.command is None and entry.args == [] and entry.env == {}
    assert entry.kind == "stdio" and entry.url is None and entry.headers == {}


def test_scalar_args_and_env_values_are_stringified():
    text = '{"mcpServers": {"a": {"command": "c", "args": [1, true, "x", null], "env": {"N": 2, "B": false, "Z": null}}}}'
    entry = parse_mcp_config_text(text, ".mcp.json")[0]
    assert entry.args == ["1", "true", "x"]
    assert entry.env == {"N": "2", "B": "false"}


def test_server_names_with_slashes_get_escaped_pointers():
    entry = parse_mcp_config_text(
        '{"mcpServers": {"a/b": {"command": "c"}}}', ".mcp.json"
    )[0]
    assert entry.server_name == "a/b"
    assert entry.pointer == "/mcpServers/a~1b"
    assert entry.span("/command") is not None


def test_the_span_table_holds_only_this_entrys_pointers():
    files, docs = _load("claude_code", "benign")
    assert all(k.startswith(files.pointer) for k in files.spans)
    assert all(k.startswith(docs.pointer) for k in docs.spans)
    assert files.pointer in files.spans and docs.pointer in docs.spans


@pytest.mark.parametrize("rel_path", [".mcp.json", ".codex/config.toml"])
def test_invalid_syntax_raises_a_parse_error_that_does_not_quote_the_file(rel_path):
    secret = "ghp_notARealTokenValue123"
    text = '{"mcpServers": {"a": {"env": {"T": "%s"}}' % secret
    if rel_path.endswith(".toml"):
        text = 'x = "%s"\n[mcp_servers.a\n' % secret
    with pytest.raises(McpConfigParseError) as raised:
        parse_mcp_config_text(text, rel_path)
    assert raised.value.source_file == rel_path
    assert raised.value.line >= 1
    assert secret not in str(raised.value)


def test_file_read_refusals(tmp_path):
    big = tmp_path / ".mcp.json"
    big.write_bytes(b" " * (1024 * 1024 + 1))
    with pytest.raises(McpConfigParseError, match="too large"):
        parse_mcp_config_file(big, ".mcp.json")
    bad = tmp_path / "bad.json"
    bad.write_bytes(b'{"mcpServers": {"a": "\xff"}}')
    with pytest.raises(McpConfigParseError, match="not UTF-8"):
        parse_mcp_config_file(bad, ".mcp.json")
    with pytest.raises(McpConfigParseError, match="could not be read"):
        parse_mcp_config_file(tmp_path / "missing.json", ".mcp.json")
    assert parse_mcp_config_file(tmp_path / "missing.json", "other.json") == []


def test_entries_are_json_serializable():
    entry = _load("claude_code", "benign")[0]
    again = McpServerEntry.model_validate_json(entry.model_dump_json())
    assert again == entry
