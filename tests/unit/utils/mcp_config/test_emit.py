# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The shell text one command-declaring MCP server entry is rendered as.

The rows pin three things: one config token stays one script token (the shlex
round trip, with the ANSI-C words a newline needs decoded first), the script is
three lines whose every line has a span row, and a name read from a config never
chooses a path outside the directory the script is written under.
"""

import json
import shlex

import pytest

from automated_security_helper.utils.mcp_config import McpServerEntry, Span
from automated_security_helper.utils.mcp_config.emit import (
    command_line,
    emit_script,
    posix_quote,
    sidecar_text,
    slug,
    source_slug,
    span_comment,
)

pytestmark = pytest.mark.unit

#: Private-use characters that stand in for the ANSI-C words while shlex reads the line.
_PLACEHOLDER_BASE = 0xF000

#: Written as code points: a literal separator in this file would end a source line.
NEL = chr(0x85)
LINE_SEP = chr(0x2028)
PARA_SEP = chr(0x2029)


def decode_ansi_c(body: str) -> str:
    """The text of the inside of one ``$'...'`` word this module writes."""
    raw = bytearray()
    index = 0
    while index < len(body):
        assert body[index] == "\\", body
        kind = body[index + 1]
        if kind == "n":
            raw.append(10)
            index += 2
        elif kind == "r":
            raw.append(13)
            index += 2
        else:
            assert kind == "x", body
            raw.append(int(body[index + 2 : index + 4], 16))
            index += 4
    return raw.decode("utf-8", "surrogatepass")


def tokens_of(line: str) -> list:
    """Split ``line`` like a POSIX shell would, reading each ``$'...'`` word too."""
    decoded = []
    out = []
    index = 0
    in_single = False
    while index < len(line):
        character = line[index]
        if in_single:
            out.append(character)
            in_single = character != "'"
            index += 1
        elif line.startswith("$'", index):
            end = line.index("'", index + 2)
            decoded.append(decode_ansi_c(line[index + 2 : end]))
            out.append(chr(_PLACEHOLDER_BASE + len(decoded) - 1))
            index = end + 1
        else:
            out.append(character)
            in_single = character == "'"
            index += 1
    words = shlex.split("".join(out), posix=True)
    result = []
    for word in words:
        for number, text in enumerate(decoded):
            word = word.replace(chr(_PLACEHOLDER_BASE + number), text)
        result.append(word)
    return result


def make_entry(**kwargs) -> McpServerEntry:
    base = {
        "source_file": ".mcp.json",
        "format_id": "claude_code",
        "server_name": "demo",
        "pointer": "/mcpServers/demo",
        "kind": "stdio",
        "command": "npx",
        "spans": {
            "/mcpServers/demo": Span(line=3, col=5, end_line=9, end_col=6),
        },
    }
    base.update(kwargs)
    return McpServerEntry(**base)


AWKWARD_VALUES = [
    "plain",
    "with space",
    "",
    "it's",
    "'",
    "''",
    "a'b'c",
    'say "hi"',
    "back\\slash",
    "$HOME and `id` and $(id)",
    "semi; colon && pipe | redirect > file",
    "glob * ? [a]",
    "tab\there",
    "line one\nline two",
    "trailing newline\n",
    "\n",
    "carriage\rreturn",
    "bell\x07and escape\x1b[0m",
    "del\x7fchar",
    "caf" + chr(0xE9) + " " + chr(0x4E2D) + chr(0x6587),
    "line sep " + LINE_SEP + " and para sep " + PARA_SEP + " and nel " + NEL,
    "-leading-dash",
    "lone surrogate " + chr(0xD800) + " here",
]


@pytest.mark.parametrize("value", AWKWARD_VALUES)
def test_one_config_value_stays_one_script_word(value):
    assert tokens_of(posix_quote(value)) == [value]


def test_every_awkward_value_is_one_token_in_one_line():
    entry = make_entry(
        command="run it",
        args=AWKWARD_VALUES,
        env={"KEEP": "x y", "NEWLINES": "a\nb"},
    )
    line = command_line(entry)

    assert "\n" not in line and "\r" not in line
    for separator in (LINE_SEP, PARA_SEP, NEL, "\x0b", "\x0c", "\x1c"):
        assert separator not in line
    assert tokens_of(line) == [
        "KEEP=x y",
        "NEWLINES=a\nb",
        "exec",
        "run it",
        *AWKWARD_VALUES,
    ]


def test_a_command_line_is_assignments_then_exec_then_every_word_quoted():
    entry = make_entry(
        command="npx", args=["-y", "pkg"], env={"A": "b c", "TOKEN": "${TOKEN}"}
    )

    assert command_line(entry) == "A='b c' TOKEN='${TOKEN}' exec 'npx' '-y' 'pkg'"


def test_a_command_that_starts_with_a_dash_follows_exec_dash_dash():
    assert command_line(make_entry(command="-x", args=["y"])) == "exec -- '-x' 'y'"


def test_an_env_name_a_shell_cannot_assign_is_handed_to_env_as_one_word():
    entry = make_entry(command="npx", env={"GOOD": "1", "bad-name": "2", "a b": "c"})

    line = command_line(entry)

    assert line == "GOOD='1' exec env 'bad-name=2' 'a b=c' 'npx'"
    assert tokens_of(line) == [
        "GOOD=1",
        "exec",
        "env",
        "bad-name=2",
        "a b=c",
        "npx",
    ]


def test_an_env_name_cannot_inject_a_word_into_the_line():
    entry = make_entry(command="npx", env={"X; rm -rf /; Y": "1"})

    assert tokens_of(command_line(entry)) == [
        "exec",
        "env",
        "X; rm -rf /; Y=1",
        "npx",
    ]


def test_an_entry_with_no_command_has_no_line_and_no_script():
    entry = make_entry(command=None)

    assert command_line(entry) is None
    assert emit_script(entry) is None


def test_a_url_only_remote_entry_emits_no_script():
    entry = make_entry(kind="remote", command=None, url="https://example.com/mcp")

    assert emit_script(entry) is None


def test_a_remote_classed_entry_with_a_command_still_emits_its_script():
    """A decoy url key classes the entry remote and must not hide the command."""
    entry = make_entry(
        kind="remote",
        command="sudo",
        args=["/usr/local/bin/mcp-files"],
        url="http://127.0.0.1:1/",
    )

    emitted = emit_script(entry)

    assert emitted is not None
    text, rows = emitted
    assert text.split("\n")[2] == "exec 'sudo' '/usr/local/bin/mcp-files'"
    assert [row["script_line"] for row in rows] == [1, 2, 3]


def test_the_script_is_three_lines_and_every_line_has_a_span_row():
    entry = make_entry(command="npx", args=["-y", "pkg"])

    text, rows = emit_script(entry)

    lines = text.split("\n")
    assert lines[-1] == "" and len(lines) == 4
    assert lines[0] == "#!/bin/sh"
    assert lines[2] == "exec 'npx' '-y' 'pkg'"
    assert [row["script_line"] for row in rows] == [1, 2, 3]
    for row in rows:
        assert row == {
            "script_line": row["script_line"],
            "source_file": ".mcp.json",
            "pointer": "/mcpServers/demo",
            "line": 3,
            "col": 5,
            "end_line": 9,
            "end_col": 6,
        }


def test_the_span_comment_is_json_on_one_line_whatever_the_name_holds():
    pointer = "/mcpServers/a\nb" + LINE_SEP + "c"
    entry = make_entry(
        server_name="a\nb" + LINE_SEP + "c",
        pointer=pointer,
        source_file="dir/with\nnewline/.mcp.json",
    )

    comment = span_comment(entry, Span(line=2, col=7, end_line=2, end_col=9))

    assert comment.startswith("# ash-mcp-span: ")
    assert len(comment.splitlines()) == 1
    assert comment.isascii()
    record = json.loads(comment[len("# ash-mcp-span: ") :])
    assert record == {
        "source": "dir/with\nnewline/.mcp.json",
        "pointer": pointer,
        "line": 2,
        "col": 7,
    }


def test_the_span_comment_key_order_is_source_pointer_line_col():
    entry = make_entry()

    comment = span_comment(entry, Span(line=3, col=5, end_line=9, end_col=6))

    assert comment == (
        '# ash-mcp-span: {"source":".mcp.json","pointer":"/mcpServers/demo",'
        '"line":3,"col":5}'
    )


def test_an_entry_with_no_span_maps_to_the_top_of_the_file():
    entry = make_entry(spans={})

    _, rows = emit_script(entry)

    assert {(r["line"], r["col"], r["end_line"], r["end_col"]) for r in rows} == {
        (1, 1, 1, 1)
    }


def test_the_sidecar_is_ascii_json_with_a_trailing_newline():
    _, rows = emit_script(make_entry(server_name="caf" + chr(0xE9)))

    sidecar = sidecar_text(rows)

    assert sidecar.endswith("}\n]\n") and sidecar.isascii()
    assert json.loads(sidecar) == rows
    assert sidecar == json.dumps(rows, indent=2, sort_keys=True) + "\n"


@pytest.mark.parametrize("name", ["demo", "my-server_2", "v1.2.3"])
def test_a_safe_name_is_kept(name):
    assert slug(name) == name


@pytest.mark.parametrize(
    "name",
    [
        "../escape",
        "a/b",
        ".hidden",
        "..",
        ".",
        "",
        "a b",
        "caf" + chr(0xE9),
        "x" * 200,
        "\n",
    ],
)
def test_an_unsafe_name_never_names_a_path_outside_its_directory(name):
    result = slug(name)

    assert result and "/" not in result and "\\" not in result
    assert not result.startswith(".")
    assert result.isascii() and len(result) < 100


def test_two_names_that_fold_to_the_same_text_get_two_files():
    taken = set()

    first = slug("a/b", taken)
    second = slug("a_b", taken)
    third = slug("a b", taken)

    assert len({first, second, third}) == 3
    assert second == "a_b"


def test_a_repeated_name_gets_a_second_file():
    taken = set()

    assert slug("demo", taken) == "demo"
    assert slug("demo", taken) != "demo"


def test_a_source_file_path_names_one_flat_directory():
    assert source_slug(".mcp.json") == "mcp.json"
    assert source_slug(".cursor/mcp.json") == "cursor__mcp.json"
    assert source_slug("config/claude_desktop_config.json") == (
        "config__claude_desktop_config.json"
    )
    assert source_slug(".kiro/settings/mcp.json") == "kiro__settings__mcp.json"
