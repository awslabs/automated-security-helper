# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config file that is not UTF-8 is refused as one that does not parse.

The file was read; its content is the problem, so every refusal of it uses the
parse wording, as for YAML or JSON that does not parse:

- the load's handler for a file ``ash scan --config`` cannot read or parse
  lists the decode error, so the refusal is the parse one, not a generic
  "Unexpected error";
- a workspace scan's ``--config`` check says the file could not be parsed, not
  "could not be read";
- ``ash config validate`` reports it under its "does not parse" header;
- a pyproject.toml that declares ``[tool.ash]`` is refused as unparsed, without
  the decoder's own message.

Each refusal says the file could not be parsed and never repeats the
decoder's message. The cells pin no error-type token and no byte value: the
formatter's wording for where the decoder stopped ("not UTF-8 at byte offset
N") is its own commit's to pin. The workspace check's verb comes from the
error, not the except tuple: read only for an OSError, parsed for any
ValueError, since every such ValueError comes from decoding or parsing the
content (JSON's integer-size limit is one).
"""

from __future__ import annotations

import os
import sys

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit

#: Valid YAML in Latin-1: "é" is the single byte 0xE9, which UTF-8 refuses. The
#: alias-like value is a canary: no refusal of this file may quote its text.
LATIN1 = "project_name: café\napi_key: *Abc123secretcanary\n".encode("latin-1")


@pytest.fixture
def latin1(tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    for name in ("ASH_SOURCE_DIR", "ASH_OUTPUT_DIR", "ASH_WORKSPACE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(tmp_path)
    config = tmp_path / "latin1.yaml"
    config.write_bytes(LATIN1)
    return config


@pytest.fixture
def logged():
    """Every message ASH's logger logs during the test, read from the records."""
    from automated_security_helper.utils.log import ASH_LOGGER

    messages: list = []

    def keep(record) -> bool:
        messages.append(record.getMessage())
        return True

    ASH_LOGGER.addFilter(keep)
    yield messages
    ASH_LOGGER.removeFilter(keep)


def test_scan_refuses_it_as_a_file_that_does_not_parse(tmp_path, latin1, logged):
    source = tmp_path / "src"
    source.mkdir()

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--source-dir",
            str(source),
            "--output-dir",
            str(tmp_path / "out"),
            "--no-progress",
            "--config",
            str(latin1),
        ],
    )

    assert result.exit_code == 3, result.output
    assert "could not be parsed" in result.output, result.output
    assert "not UTF-8 at byte offset" in result.output, result.output
    assert "can't decode" not in result.output, result.output
    assert "could not be resolved" not in result.output, result.output
    unexpected = [m for m in logged if m.startswith("Unexpected error in")]
    assert unexpected == [], unexpected


def test_a_workspace_scan_s_config_check_says_it_does_not_parse(tmp_path, latin1):
    import json

    (tmp_path / "api").mkdir()
    workspace = tmp_path / "dev.code-workspace"
    workspace.write_text(json.dumps({"folders": [{"path": "api"}]}), encoding="utf-8")

    result = CliRunner().invoke(
        app,
        ["scan", "--workspace", str(workspace), "--config", str(latin1), "--dry-run"],
    )

    assert result.exit_code == 3, result.output
    assert "could not be read" not in result.output, result.output
    assert "could not be parsed" in result.output, result.output
    assert "not UTF-8 at byte offset" in result.output, result.output
    assert "can't decode" not in result.output, result.output
    # The canary: no refusal of this file quotes its text.
    assert "Abc123secretcanary" not in result.output, result.output


def test_validate_s_line_matches_its_parse_header(latin1):
    result = CliRunner().invoke(app, ["config", "validate", "--config", str(latin1)])

    assert result.exit_code == 3, result.output
    assert "does not parse" in result.output, result.output
    assert "not UTF-8 at byte offset" in result.output, result.output
    assert "can't decode" not in result.output, result.output
    assert "could not read" not in result.output.lower(), result.output


def test_a_workspace_config_with_a_non_parser_value_error_says_parsed(
    tmp_path, monkeypatch
):
    """A ValueError that is not a parser's own type comes from parsing the
    content all the same (JSON's integer-size limit here), so the verb is
    parsed, not read."""
    import json

    for name in ("ASH_CONFIG", "ASH_SOURCE_DIR", "ASH_OUTPUT_DIR", "ASH_WORKSPACE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "api").mkdir()
    workspace = tmp_path / "dev.code-workspace"
    workspace.write_text(json.dumps({"folders": [{"path": "api"}]}), encoding="utf-8")
    config = tmp_path / "huge.json"
    config.write_text('{"x": %s}' % ("1" * 5000), encoding="utf-8")

    result = CliRunner().invoke(
        app,
        ["scan", "--workspace", str(workspace), "--config", str(config), "--dry-run"],
    )

    assert result.exit_code == 3, result.output
    assert "could not be parsed" in result.output, result.output
    assert "could not be read" not in result.output, result.output


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_a_workspace_config_the_process_cannot_read_says_read(tmp_path, monkeypatch):
    """The read verb stays for an OSError: the file could not be opened, so
    there is no syntax to send a reader to."""
    import json

    if os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0):
        pytest.skip("root (and Windows, with no mode bits) reads a mode-0 file")
    for name in ("ASH_CONFIG", "ASH_SOURCE_DIR", "ASH_OUTPUT_DIR", "ASH_WORKSPACE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "api").mkdir()
    workspace = tmp_path / "dev.code-workspace"
    workspace.write_text(json.dumps({"folders": [{"path": "api"}]}), encoding="utf-8")
    config = tmp_path / "unreadable.yaml"
    config.write_text("project_name: t\n", encoding="utf-8")
    config.chmod(0)
    try:
        result = CliRunner().invoke(
            app,
            [
                "scan",
                "--workspace",
                str(workspace),
                "--config",
                str(config),
                "--dry-run",
            ],
        )
    finally:
        config.chmod(0o644)

    assert result.exit_code == 3, result.output
    assert "could not be read" in result.output, result.output
    assert "could not be parsed" not in result.output, result.output


def test_a_pyproject_that_declares_ash_is_refused_without_the_decoder_s_words(
    tmp_path, monkeypatch
):
    """A pyproject.toml with a [tool.ash] table that is not UTF-8 is an error,
    not a skip, and the refusal gives the error's type, never the decoder's
    message, which repeats the undecodable byte."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(tmp_path)
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_bytes("[tool.ash]\nproject_name = 'café'\n".encode("latin-1"))

    result = CliRunner().invoke(app, ["config", "get"])

    assert result.exit_code == 3, result.output
    assert "declares an ASH configuration" in result.output, result.output
    assert "could not be parsed" in result.output, result.output
    assert "not UTF-8 at byte offset" in result.output, result.output
    assert "can't decode" not in result.output, result.output


@pytest.fixture
def latin1_toml(tmp_path, monkeypatch):
    """A TOML config in Latin-1: TOML requires UTF-8, so the read refuses."""
    for name in ("ASH_CONFIG", "ASH_SOURCE_DIR", "ASH_OUTPUT_DIR", "ASH_WORKSPACE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(tmp_path)
    config = tmp_path / "latin1.toml"
    config.write_bytes('project_name = "café"\n'.encode("latin-1"))
    return config


@pytest.mark.parametrize("command", ["validate", "get"])
def test_a_toml_config_that_is_not_utf8_is_refused_without_the_decoder(
    latin1_toml, command
):
    result = CliRunner().invoke(app, ["config", command, "--config", str(latin1_toml)])

    assert result.exit_code == 3, result.output
    assert "not UTF-8 at byte offset" in result.output, result.output
    assert "can't decode" not in result.output, result.output


def test_the_scan_refuses_a_toml_config_that_is_not_utf8_without_the_decoder(
    tmp_path, latin1_toml
):
    source = tmp_path / "src"
    source.mkdir()

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--source-dir",
            str(source),
            "--output-dir",
            str(tmp_path / "out"),
            "--no-progress",
            "--config",
            str(latin1_toml),
        ],
    )

    assert result.exit_code == 3, result.output
    assert "not UTF-8 at byte offset" in result.output, result.output
    assert "can't decode" not in result.output, result.output


def test_mcp_validate_types_a_toml_that_is_not_utf8_as_a_parse_error(latin1_toml):
    from automated_security_helper.cli.mcp_tools import mcp_validate_config

    result = mcp_validate_config(config_path=str(latin1_toml))

    assert result["valid"] is False, result
    types = [e.get("type") for e in result["errors"]]
    assert "toml_parse_error" in types, result["errors"]
    for error in result["errors"]:
        assert "can't decode" not in error.get("message", ""), error


def test_mcp_validate_types_a_yaml_that_is_not_utf8_as_a_parse_error_whatever_its_path(
    tmp_path, monkeypatch
):
    """The type comes from the validator's category prefix, never from words of
    the message or the path: a path containing "Unknown" is not an
    unknown_field."""
    from automated_security_helper.cli.mcp_tools import mcp_validate_config

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config = tmp_path / "Unknown.yaml"
    config.write_bytes(LATIN1)

    result = mcp_validate_config(config_path=str(config))

    assert result["valid"] is False, result
    types = [e.get("type") for e in result["errors"]]
    assert "yaml_parse_error" in types, result["errors"]
    assert "unknown_field" not in types, result["errors"]


@pytest.mark.parametrize(
    "name,content",
    [
        ("latin1.toml", 'project_name = "café"\n'.encode("latin-1")),
        (
            "pyproject.toml",
            "[tool.ash]\nproject_name = 'café'\n".encode("latin-1"),
        ),
        ("twice.toml", b"[a]\nx = 1\n[a]\ny = 2\n"),
    ],
    ids=["not-utf8-toml", "not-utf8-pyproject", "duplicate-table"],
)
def test_lint_shows_a_toml_parse_refusal_without_a_prefix(
    tmp_path, monkeypatch, name, content
):
    """The linter framed every TOML refusal with "Failed to parse config
    file:", restating a reason that already names the file and says it did not
    parse."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(tmp_path)
    config = tmp_path / name
    config.write_bytes(content)

    result = CliRunner().invoke(app, ["config", "lint", "--config", str(config)])

    assert result.exit_code == 3, result.output
    assert "could not be parsed" in result.output, result.output
    assert "Failed to parse config file" not in result.output, result.output


def test_validate_s_verdict_for_a_toml_that_does_not_parse_matches_yaml(
    tmp_path, monkeypatch
):
    """Parity: since the shared formatter, every format's parse
    refusal is one ASHConfigUnparsedError through one sentence, so validate's
    verdict for a broken TOML says the file does not parse, as its YAML and
    JSON twins do."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(tmp_path)
    config = tmp_path / "twice.toml"
    config.write_bytes(b"[a]\nx = 1\n[a]\ny = 2\n")

    result = CliRunner().invoke(app, ["config", "validate", "--config", str(config)])

    assert result.exit_code == 3, result.output
    assert "could not be parsed" in result.output, result.output
    assert "it does not parse, so none of its settings apply" in result.output, (
        result.output
    )


def test_lint_s_verdict_for_a_constructor_value_error_matches_validate(
    tmp_path, monkeypatch
):
    """A YAML constructor's ValueError (!!int) is a parse refusal; lint's
    own issue line and config validate say the file does not parse, so lint's
    verdict says it too instead of the generic one."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(tmp_path)
    config = tmp_path / "ctor.yaml"
    config.write_text("project_name: t\napi_key: !!int notanint\n", encoding="utf-8")

    result = CliRunner().invoke(app, ["config", "lint", "--config", str(config)])

    assert result.exit_code == 3, result.output
    assert "could not be parsed" in result.output, result.output
    assert "it does not parse, so none of its settings apply" in result.output, (
        result.output
    )


def test_lint_s_verdict_for_a_toml_that_does_not_parse_matches_yaml(
    tmp_path, monkeypatch
):
    """The linter's ignored tuple named the YAML, JSON and decode errors but
    not the TOML parse refusal, so a broken TOML drew the generic verdict where
    its YAML twin says the file does not parse."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(tmp_path)
    config = tmp_path / "twice.toml"
    config.write_bytes(b"[a]\nx = 1\n[a]\ny = 2\n")

    result = CliRunner().invoke(app, ["config", "lint", "--config", str(config)])

    assert result.exit_code == 3, result.output
    assert "it does not parse, so none of its settings apply" in result.output, (
        result.output
    )


@pytest.mark.parametrize("command", ["lint", "validate"])
@pytest.mark.parametrize(
    "content,fragment",
    [
        ('[tool.other]\nname = "t"\n', "no [tool.ash] table"),
        ("[tool]\nash = 3\n", "must be a table"),
    ],
    ids=["no-table", "not-a-table"],
)
def test_a_non_parse_pyproject_s_verdict_is_not_the_parse_one(
    tmp_path, monkeypatch, content, fragment, command
):
    """Lint's ignored tuple takes the parse-refusal marker type alone,
    and validate sets ignored_by_scan only in its ASHConfigUnparsedError arm,
    so a pyproject refusal that is not a parse failure keeps the generic
    verdict at both commands; a config problem is not mislabeled as syntax.
    Red when either side widens to the whole ASHConfigSourceError subtree."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(tmp_path)
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(content, encoding="utf-8")

    result = CliRunner().invoke(app, ["config", command, "--config", str(pyproject)])

    assert result.exit_code == 3, result.output
    assert fragment in result.output, result.output
    assert "it does not parse, so none of its settings apply" not in result.output, (
        result.output
    )


def test_a_toml_profile_that_does_not_parse_names_its_file_once(tmp_path):
    """The registry's load-failure frame names the path, and a parse refusal
    names it again."""
    from automated_security_helper.cli.mcp.profile_registry import (
        ProfileRegistryError,
        register_profiles,
    )

    profile = tmp_path / "p.toml"
    profile.write_bytes('project_name = "café"\n'.encode("latin-1"))

    with pytest.raises(ProfileRegistryError) as info:
        register_profiles([f"p={profile}"])

    text = str(info.value)
    assert "could not be parsed" in text, text
    assert "failed to load" not in text, text
    assert text.count(profile.name) == 1, text


def test_a_pyproject_without_ash_is_not_typed_by_words_of_its_path(tmp_path):
    """The classifier keys on the category prefix, so a path that spells
    the parse refusal's own words ("could not be parsed (") inside a non-parse
    TOML refusal must not become a toml_parse_error."""
    from automated_security_helper.cli.mcp_tools import mcp_validate_config

    config_dir = tmp_path / "could not be parsed (x"
    config_dir.mkdir()
    pyproject = config_dir / "pyproject.toml"
    pyproject.write_text('[tool.other]\nname = "t"\n', encoding="utf-8")

    result = mcp_validate_config(config_path=str(pyproject))

    assert result["valid"] is False, result
    types = [e.get("type") for e in result["errors"]]
    assert "toml_parse_error" not in types, result["errors"]


def test_pyproject_discovery_marks_its_parse_refusals(tmp_path):
    """pyproject_has_ash_table's two refusals of a declaring file that
    does not parse carry the marker type (the message is the complete refusal),
    so a printer that frames other source errors shows them as they are. Not
    observable at lint, validate or get today, which read the file through
    read_config_text instead: the type is the contract."""
    from automated_security_helper.config.config_sources import pyproject_has_ash_table
    from automated_security_helper.core.exceptions import ASHConfigUnparsedError

    declared_not_utf8 = tmp_path / "a" / "pyproject.toml"
    declared_not_utf8.parent.mkdir()
    declared_not_utf8.write_bytes(
        "[tool.ash]\nproject_name = 'café'\n".encode("latin-1")
    )
    declared_unparsed = tmp_path / "b" / "pyproject.toml"
    declared_unparsed.parent.mkdir()
    declared_unparsed.write_text("[tool.ash]\nx = \n", encoding="utf-8")

    for pyproject in (declared_not_utf8, declared_unparsed):
        with pytest.raises(ASHConfigUnparsedError) as info:
            pyproject_has_ash_table(pyproject)
        assert "could not be parsed" in str(info.value), str(info.value)


def test_config_get_names_a_broken_toml_file_once(tmp_path, monkeypatch):
    """The YAML blocks lost their restating header; a broken TOML still
    had "Invalid configuration in <file>:" over a reason that names the file,
    so the path was printed twice."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(tmp_path)
    config = tmp_path / "broken.toml"
    config.write_text("project_name = \n", encoding="utf-8")

    result = CliRunner().invoke(app, ["config", "get", "--config", str(config)])

    assert result.exit_code == 3, result.output
    assert "could not be parsed" in result.output, result.output
    assert result.output.count(config.name) == 1, result.output


def test_the_workspace_policy_refuses_a_file_that_is_not_utf8(tmp_path):
    """The policy reader's decode arm gives the error's type and place, never the
    decoder's message, which prints the undecodable byte's value."""
    from automated_security_helper.workspace.policy import load_workspace_policy

    policy = tmp_path / "policy.yaml"
    policy.write_bytes(LATIN1)

    with pytest.raises(Exception) as info:
        load_workspace_policy(policy)

    text = str(info.value)
    assert "could not be parsed" in text, text
    assert "not UTF-8 at byte offset" in text, text
    assert "can't decode" not in text, text
    assert "Abc123secretcanary" not in text, text


def test_the_workspace_file_is_refused_without_the_decoder_when_not_utf8(tmp_path):
    """The workspace-file reader's decode arm gives the error's type and place,
    never the decoder's message, which prints the undecodable byte's value."""
    from automated_security_helper.workspace.workspace_file import load_workspace_file

    workspace = tmp_path / "dev.code-workspace"
    workspace.write_bytes('{"folders": [{"path": "café"}]}'.encode("latin-1"))

    with pytest.raises(Exception) as info:
        load_workspace_file(workspace)

    text = str(info.value)
    assert "could not be parsed" in text, text
    assert "not UTF-8 at byte offset" in text, text
    assert "can't decode" not in text, text


@pytest.mark.parametrize(
    "name,content",
    [
        ("s.yaml", LATIN1),
        (
            "s.json",
            '{"project_name": "café", "note": "*Abc123secretcanary"}\n'.encode(
                "latin-1"
            ),
        ),
    ],
    ids=["yaml", "json"],
)
def test_the_suppression_save_refuses_a_file_that_is_not_utf8(tmp_path, name, content):
    """The suppression saves read their file inside the parse guard, so a file
    that is not UTF-8 is refused with its type and place, never the decoder's
    message (the YAML path through read_text, the JSON path through json.load on
    the open file)."""
    from automated_security_helper.config.ash_config import add_suppression_to_config
    from automated_security_helper.models.core import AshSuppression

    config = tmp_path / name
    config.write_bytes(content)

    with pytest.raises(ValueError) as info:
        add_suppression_to_config(
            config, AshSuppression(rule_id="B101", path="x.py", reason="r")
        )

    text = str(info.value)
    assert "could not be parsed" in text, text
    assert "not UTF-8 at byte offset" in text, text
    assert "can't decode" not in text, text
    assert "Abc123secretcanary" not in text, text


def test_the_suppression_save_refuses_a_malformed_json_without_its_text(tmp_path):
    """The JSON suppression guard's JSONDecodeError arm, pinned: a
    malformed (valid UTF-8) .json is refused with the type and place only,
    nothing of the file's text."""

    from automated_security_helper.config.ash_config import add_suppression_to_config
    from automated_security_helper.models.core import AshSuppression

    content = '{"project_name": "Abc123secretcanary",,}\n'
    config = tmp_path / "s.json"
    config.write_text(content, encoding="utf-8")
    import json as json_module

    with pytest.raises(json_module.JSONDecodeError) as parse:
        json_module.loads(content)
    # The exact parenthetical, built from the error's own fields: json's
    # messages are fixed templates that hold no document text, so the refusal
    # carries the parser's reason with the place and NOTHING between them that
    # a formatter could add; the canary pins that nothing of the file
    # rides in.
    expected = (
        f"(JSONDecodeError: {parse.value.msg} at line {parse.value.lineno}, "
        f"column {parse.value.colno})"
    )

    with pytest.raises(ValueError) as info:
        add_suppression_to_config(
            config, AshSuppression(rule_id="B101", path="x.py", reason="r")
        )

    text = str(info.value)
    assert "could not be parsed" in text, text
    assert expected in text, (expected, text)
    assert "Abc123secretcanary" not in text, text


@pytest.mark.parametrize("debug", [False, True], ids=["default", "debug"])
@pytest.mark.parametrize(
    "name,content",
    [
        (".ash.yaml", "project_name: [unclosed\n"),
        ("broken.yaml", "project_name: [unclosed\n"),
        ("broken.json", '{"project_name": ,}\n'),
        ("broken.toml", "[tool.ash\nproject_name = 1\n"),
    ],
    ids=["discovered-yaml", "config-yaml", "config-json", "config-toml"],
)
def test_a_scan_prints_a_parse_refusal_once(
    tmp_path, monkeypatch, name, content, debug
):
    """A scan shows a config's parse refusal once at every verbosity, whatever
    the format: the refusal the load raises is the scan's to print, with no
    log record saying the same thing beside it."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    (src / ".ash").mkdir(parents=True)
    discovered = name.startswith(".")
    where = (src / ".ash" / name) if discovered else (tmp_path / name)
    where.write_text(content, encoding="utf-8")
    out = tmp_path / "out"
    args = ["scan", "--source-dir", str(src), "--output-dir", str(out)]
    if not discovered:
        args += ["--config", str(where)]
    if debug:
        args.append("--debug")

    result = CliRunner().invoke(app, args)

    assert result.exit_code == 3, result.output
    assert result.output.count("could not be parsed") == 1, result.output


@pytest.mark.parametrize(
    "name,content",
    [
        ("broken.yaml", "project_name: [unclosed\n"),
        ("broken.json", '{"project_name": ,}\n'),
        ("broken.toml", "[tool.ash\nproject_name = 1\n"),
    ],
    ids=["yaml", "json", "toml"],
)
def test_config_get_prints_a_parse_refusal_once_at_debug(
    tmp_path, monkeypatch, name, content
):
    """config get shows a parse refusal once under --debug too, whatever the
    format: the caller prints the raised refusal in its own words, and the
    load keeps no record that a debug console would show beside it."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(tmp_path)
    config = tmp_path / name
    config.write_text(content, encoding="utf-8")

    result = CliRunner().invoke(
        app, ["config", "get", "--config", str(config), "--debug"]
    )

    assert result.exit_code == 3, result.output
    assert result.output.count("could not be parsed") == 1, result.output


@pytest.mark.parametrize("fallback", [True, False], ids=["scan", "caller-words"])
def test_the_load_logs_no_parse_refusal_record(tmp_path, fallback):
    """The load logs no record for a parse refusal, at any level and with the
    fallback on or off: every caller prints the raised refusal in its own
    words, so a record here showed the same thing beside it at some verbosity
    — and only for YAML and JSON, never TOML, whose refusal arrives already
    raised."""
    import logging

    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigValidationError
    from automated_security_helper.utils.log import ASH_LOGGER

    records: list = []

    class Keep(logging.Filter):
        def filter(self, record):
            records.append((record.levelno, record.getMessage()))
            return True

    keep = Keep()
    old_level = ASH_LOGGER.level
    ASH_LOGGER.addFilter(keep)
    ASH_LOGGER.setLevel(logging.DEBUG)
    config = tmp_path / "unparsed.yaml"
    config.write_text("project_name: [unclosed\n", encoding="utf-8")
    try:
        with pytest.raises(ASHConfigValidationError):
            resolve_config(
                config_path=config, source_dir=tmp_path, fallback_to_default=fallback
            )
    finally:
        ASH_LOGGER.removeFilter(keep)
        ASH_LOGGER.setLevel(old_level)

    parse_logs = [(lvl, m) for lvl, m in records if "could not be parsed" in m]
    assert parse_logs == [], parse_logs


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
@pytest.mark.parametrize(
    "name", ["unreadable.yaml", "un\\readable.yaml"], ids=["plain", "backslash"]
)
def test_the_default_config_refuses_a_file_it_cannot_read_as_its_own(
    tmp_path, monkeypatch, name
):
    """A raw OSError escaped get_default_config, so each caller
    classified an unreadable ASH_CONFIG file its own way (the MCP workspace
    tools disagreed on the exit code). Wrapped at the source as the ASH_CONFIG
    file's own refusal (ash_config_file set), every caller refuses it as a
    config, exit 3, with the read verb: the file's syntax was never seen.

    The refusal names the file once, as given, by the wrap; the OSError's own
    copy of the name is left out (os_error_without_named_file). The backslash
    name is the as-given proof: a repr quote would double its backslash, so
    the as-given name would not appear at all."""
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    if os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0):
        pytest.skip("root (and Windows, with no mode bits) reads a mode-0 file")
    config = tmp_path / name
    config.write_text("project_name: t\n", encoding="utf-8")
    config.chmod(0)
    monkeypatch.setenv("ASH_CONFIG", str(config))

    try:
        with pytest.raises(ASHConfigValidationError) as info:
            get_default_config()
    finally:
        config.chmod(0o644)

    text = str(info.value)
    # The wording resolve_config's read wrap already uses for a config the
    # process could not read.
    assert "could not read" in text, text
    assert "could not be parsed" not in text, text
    assert text.count(str(config)) == 1, text
    assert info.value.ash_config_file == config


def test_the_default_config_s_parse_refusal_is_the_reason_alone(tmp_path, monkeypatch):
    """get_default_config's refusal of an ASH_CONFIG file that does not parse
    is the formatted reason, with no "Configuration validation failed:" in
    front of it: nothing was validated, and the reason says what failed."""
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    config = tmp_path / "unparsed.yaml"
    config.write_text("project_name: [unclosed\n", encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(config))

    with pytest.raises(ASHConfigValidationError) as info:
        get_default_config()

    assert "could not be parsed" in str(info.value), str(info.value)
    assert "Configuration validation failed" not in str(info.value), str(info.value)
