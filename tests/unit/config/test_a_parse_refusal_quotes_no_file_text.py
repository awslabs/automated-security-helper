# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config parse refusal carries no text from the config file, anywhere.

Why this exists
---------------
A config file inside a scanned tree can hold a secret on the malformed line,
and the refusal of a file that does not parse is shown to consoles, ash.log and
MCP clients. PyYAML's message quotes the file two ways:

- a load from a *str* quotes a snippet of the offending line. Every config
  parse goes through a stream (the open file, or config_sources._NamedText),
  whose marks give PyYAML no buffer to print a snippet from;
- the message's own words quote a token of the line whatever the source:
  "found undefined alias '<name>'" (``api_key: *Abc123``) and "could not
  determine a constructor for the tag '<tag>'" (``token: !s3cr3t``), and
  tomllib's "Cannot declare '<table>' twice" does the same.

So no refusal repeats the parser's words at all. Each one says where the
parser stopped and nothing from the file (config_sources.unparsed_config_reason):

    <path> could not be parsed (ComposerError at line 1, column 15)

These cells pin that for every way a config file is read: a canary on the
malformed line, in shapes covering every leaking error kind, reaches no
refusal text and no reply, and the refusal carries the error's type and place,
so a cell that never reached the parser cannot pass. The controls pin the
hazard itself, so the pin cannot pass vacuously: the same text loaded as a str
does put the canary in PyYAML's message, and a valid value does reach the
output.
"""

from __future__ import annotations

import json
import logging
import re
import secrets
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Union
from unittest.mock import patch

import pytest
import yaml
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

pytestmark = pytest.mark.unit

#: shape name -> (text template, the parser error's type name). The canary sits
#: on the line the parser's mark points at. undefined-alias and unknown-tag are
#: the shapes whose parser message quotes the canary token itself; the others
#: leak only through a str load's snippet.
SHAPES = {
    "flow-sequence": ("project_name: [{canary} unclosed\n", "ParserError"),
    "mapping-value": (
        "project_name: probe\nglobal_settings: {canary}: x\n",
        "ScannerError",
    ),
    "quoted-scalar": ('project_name: "{canary}\n', "ScannerError"),
    "undefined-alias": ("project_name: *{canary}\n", "ComposerError"),
    "unknown-tag": ("project_name: !{canary} x\n", "ConstructorError"),
}

SCAN = "automated_security_helper.core.orchestrator.ASHScanOrchestrator.execute_scan"


def _canary() -> str:
    return "CANARY" + secrets.token_hex(8)


def _squeezed(text: str) -> str:
    """``text`` with whitespace and Rich's box-drawing characters removed, so a
    canary or a marker a panel wrapped or framed still compares."""
    return "".join(
        ch for ch in text if not ch.isspace() and not 0x2500 <= ord(ch) <= 0x257F
    )


def _sans_paths(text: str, *paths: Path) -> str:
    """``text`` squeezed and lowercased with each of ``paths`` removed, so an
    absence assert reads the message and not the random temporary directory
    names the message embeds."""
    out = _squeezed(text).lower()
    for path in paths:
        for form in {str(path), str(path.resolve())}:
            out = out.replace(_squeezed(form).lower(), "")
    return out


@dataclass
class _Reply:
    refused: bool
    text: str


class _World:
    def __init__(self, root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.root = root
        self.monkeypatch = monkeypatch
        self.project = root / "p1"
        (self.project / ".ash").mkdir(parents=True)
        (self.project / "a.py").write_text("x = 1\n", encoding="utf-8")
        self.output = root / "out"

    @property
    def discovered(self) -> Path:
        return self.project / ".ash" / ".ash.yaml"

    @property
    def named(self) -> Path:
        return self.root / "defaults.yaml"

    @property
    def root_config(self) -> Path:
        return self.root / ".ash" / ".ash.yaml"

    @property
    def workspace_file(self) -> Path:
        path = self.root / "dev.code-workspace"
        if not path.exists():
            path.write_text(json.dumps({"folders": [{"path": "p1"}]}), encoding="utf-8")
        return path

    def write(self, where: Path, text: Union[str, bytes]) -> Path:
        where.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, bytes):
            where.write_bytes(text)
        else:
            where.write_text(text, encoding="utf-8")
        return where


@pytest.fixture
def world(tmp_path, monkeypatch) -> _World:
    monkeypatch.chdir(tmp_path)
    for name in (
        "ASH_CONFIG",
        "ASH_MCP_ALLOWED_ROOTS",
        "ASH_MCP_ALLOWED_CONFIG_ROOTS",
        "ASH_MCP_WORKSPACE_ROOT",
    ):
        monkeypatch.delenv(name, raising=False)
    return _World(tmp_path, monkeypatch)


@pytest.fixture
def ash_log():
    """Every message ASH's logger would log during the cell, DEBUG included.

    A handler on the "ash" logger, so records from its children arrive too, and
    the logger forced to DEBUG for the cell: a leak into a DEBUG record is still
    a leak, since an operator debugging a scan reads those lines.
    """
    from automated_security_helper.utils.log import ASH_LOGGER

    messages: list = []

    class _Keep(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            messages.append(record.getMessage())

    handler = _Keep(level=logging.DEBUG)
    level_before = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield messages
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level_before)


def _no_scan():
    """The orchestrator and git lookups a refusal must never reach."""
    return (
        patch(SCAN, side_effect=AssertionError("a scan started")),
        patch(
            "automated_security_helper.workspace.execution.git_repository_root",
            return_value=None,
        ),
        patch(
            "automated_security_helper.utils.get_scan_set._rev_parse_toplevel",
            return_value=(None, "not a git repository"),
        ),
    )


def _invoke(args) -> _Reply:
    scan, git_root, toplevel = _no_scan()
    with scan, git_root, toplevel:
        result = CliRunner().invoke(app, args)
    return _Reply(result.exit_code == 3, result.output)


def _scan_args(world: _World, *more: str) -> list:
    return [
        "scan",
        "--no-progress",
        "--source-dir",
        str(world.project),
        "--output-dir",
        str(world.output),
        *more,
    ]


def _cli_scan_discovered(world: _World, text: str) -> _Reply:
    world.write(world.discovered, text)
    return _invoke(_scan_args(world))


def _cli_scan_named(world: _World, text: str) -> _Reply:
    world.write(world.named, text)
    return _invoke(_scan_args(world, "--config", str(world.named)))


def _cli_scan_ash_config(world: _World, text: str) -> _Reply:
    world.write(world.named, text)
    world.monkeypatch.setenv("ASH_CONFIG", str(world.named))
    return _invoke(_scan_args(world))


def _ws_args(world: _World, *more: str) -> list:
    return [
        "scan",
        "--no-progress",
        "--workspace",
        str(world.workspace_file),
        "--output-dir",
        str(world.output),
        *more,
    ]


def _cli_workspace(world: _World, text: str) -> _Reply:
    world.write(world.discovered, text)
    return _invoke(_ws_args(world))


def _cli_workspace_dry_run(world: _World, text: str) -> _Reply:
    world.write(world.discovered, text)
    return _invoke(_ws_args(world, "--dry-run"))


def _cli_workspace_named(world: _World, text: str) -> _Reply:
    world.write(world.named, text)
    return _invoke(_ws_args(world, "--config", str(world.named)))


def _cli_workspace_root(world: _World, text: str) -> _Reply:
    world.write(world.discovered, "project_name: p1\n")
    world.write(world.root_config, text)
    return _invoke(_ws_args(world))


def _run_ash_scan(world: _World, text: str) -> _Reply:
    from automated_security_helper.core.enums import RunMode
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    world.write(world.discovered, text)
    scan, git_root, toplevel = _no_scan()
    with scan, git_root, toplevel, pytest.raises(SystemExit) as exited:
        run_ash_scan(
            source_dir=str(world.project),
            output_dir=str(world.output),
            mode=RunMode.local,
            progress=False,
            show_summary=False,
        )
    return _Reply(
        exited.value.code == 3, str(getattr(exited.value, "message", exited.value))
    )


def _cli_dependencies_install(world: _World, text: str) -> _Reply:
    world.write(world.discovered, text)
    world.monkeypatch.chdir(world.project)
    return _invoke(["dependencies", "install"])


def _cli_plugin_list(world: _World, text: str) -> _Reply:
    world.write(world.discovered, text)
    world.monkeypatch.chdir(world.project)
    return _invoke(["plugin", "list"])


def _cli_report_config(world: _World, text: str) -> _Reply:
    world.write(world.named, text)
    return _invoke(
        ["report", "--config", str(world.named), "--output-dir", str(world.output)]
    )


def _cli_scan_use_existing(world: _World, text: str) -> _Reply:
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    world.write(world.discovered, text)
    world.output.mkdir()
    existing = world.output / "ash_aggregated_results.json"
    existing.write_text(AshAggregatedResults().model_dump_json(), encoding="utf-8")
    return _invoke(_scan_args(world, "--use-existing"))


def _cli_config_validate(world: _World, text: str) -> _Reply:
    world.write(world.discovered, text)
    return _invoke(
        [
            "config",
            "validate",
            "--config",
            str(world.discovered),
            "--source-dir",
            str(world.project),
        ]
    )


def _cli_config_lint(world: _World, text: str) -> _Reply:
    world.write(world.discovered, text)
    result = CliRunner().invoke(
        app, ["config", "lint", "--config", str(world.discovered)]
    )
    return _Reply(result.exit_code != 0, result.output)


def _cli_config_get(world: _World, text: str) -> _Reply:
    world.write(world.discovered, text)
    return _invoke(["config", "get", "--config", str(world.discovered)])


def _mcp_response(world: _World, response) -> _Reply:
    return _Reply(
        response.get("success") is False and response.get("exit_code") == 3,
        repr(response),
    )


def _mcp_scan_directory(world: _World, text: str) -> _Reply:
    import asyncio
    from unittest.mock import AsyncMock

    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.cli.mcp.scan_target import ASH_MCP_ALLOWED_ROOTS_ENV

    world.write(world.discovered, text)
    world.monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(world.root))
    world.monkeypatch.setattr(mcp_tools, "_run_scan_async", AsyncMock())
    response = asyncio.run(
        mcp_tools.mcp_scan_directory(directory_path=str(world.project))
    )
    return _mcp_response(world, response)


def _mcp_resolve_workspace(world: _World, text: str) -> _Reply:
    import asyncio

    from automated_security_helper.cli.mcp.scan_target import ASH_MCP_ALLOWED_ROOTS_ENV
    from automated_security_helper.cli.mcp.workspace import mcp_resolve_workspace

    world.write(world.discovered, "project_name: p1\n")
    world.write(world.root_config, text)
    world.monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(world.root))
    response = asyncio.run(
        mcp_resolve_workspace(workspace_file=str(world.workspace_file))
    )
    return _mcp_response(world, response)


def _mcp_get_config(world: _World, text: str) -> _Reply:
    from automated_security_helper.cli import mcp_tools

    world.write(world.discovered, text)
    return _mcp_response(world, mcp_tools.mcp_get_config(search_dir=str(world.project)))


def _mcp_get_config_raw(world: _World, text: str) -> _Reply:
    from automated_security_helper.cli import mcp_tools

    world.write(world.discovered, text)
    return _mcp_response(
        world, mcp_tools.mcp_get_config(config_path=str(world.discovered), raw=True)
    )


def _mcp_validate_config(world: _World, text: str) -> _Reply:
    from automated_security_helper.cli import mcp_tools

    world.write(world.discovered, text)
    response = mcp_tools.mcp_validate_config(config_path=str(world.discovered))
    return _Reply(response.get("valid") is False, repr(response))


#: Every way a run reads a config file. Each one must refuse the file and say
#: only where the parser stopped.
FORMS: Dict[str, Callable[[_World, str], _Reply]] = {
    "cli-scan-discovered": _cli_scan_discovered,
    "cli-scan-named": _cli_scan_named,
    "cli-scan-ash-config": _cli_scan_ash_config,
    "cli-workspace": _cli_workspace,
    "cli-workspace-dry-run": _cli_workspace_dry_run,
    "cli-workspace-named": _cli_workspace_named,
    "cli-workspace-root": _cli_workspace_root,
    "run-ash-scan": _run_ash_scan,
    "cli-dependencies-install": _cli_dependencies_install,
    "cli-plugin-list": _cli_plugin_list,
    "cli-report-config": _cli_report_config,
    "cli-scan-use-existing": _cli_scan_use_existing,
    "cli-config-validate": _cli_config_validate,
    "cli-config-lint": _cli_config_lint,
    "cli-config-get": _cli_config_get,
    "mcp-scan-directory": _mcp_scan_directory,
    "mcp-resolve-workspace": _mcp_resolve_workspace,
    "mcp-get-config": _mcp_get_config,
    "mcp-get-config-raw": _mcp_get_config_raw,
    "mcp-validate-config": _mcp_validate_config,
}


@pytest.mark.parametrize("shape", sorted(SHAPES))
@pytest.mark.parametrize("form", sorted(FORMS))
def test_a_refusal_quotes_no_file_text(world, ash_log, form, shape):
    canary = _canary()
    template, kind = SHAPES[shape]

    reply = FORMS[form](world, template.format(canary=canary))

    squeezed = _squeezed(reply.text)
    assert reply.refused, reply.text[-3000:]
    # Where the parser stopped: the cell reached the parser, with this file.
    assert _squeezed(f"could not be parsed ({kind} at line") in squeezed, reply.text[
        -3000:
    ]
    assert canary not in squeezed, reply.text[-3000:]
    # A log record is an output too, at any level: an operator debugging a
    # scan reads DEBUG lines.
    logged = _squeezed("\n".join(ash_log))
    assert canary not in logged, [m for m in ash_log if canary in _squeezed(m)]


#: A YAML config that is not UTF-8; the parser never gets text to quote, and
#: the refusal says the byte's offset, never its value.
NOT_UTF8 = b"project_name: \xff\n"


@pytest.mark.parametrize("form", sorted(FORMS))
def test_a_file_that_is_not_utf8_is_refused_without_its_bytes(world, ash_log, form):
    reply = FORMS[form](world, NOT_UTF8)

    squeezed = _squeezed(reply.text)
    assert reply.refused, reply.text[-3000:]
    # The offset says where to look, in the words the merge and validator
    # surfaces use; the decoder's own message would give the byte's value
    # ("can't decode byte 0xff").
    assert _squeezed("could not be parsed (not UTF-8 at byte offset 14)") in (
        squeezed
    ), reply.text[-3000:]
    assert "xff" not in _sans_paths(reply.text, world.root), reply.text[-3000:]
    assert "xff" not in _sans_paths("\n".join(ash_log), world.root), [
        m for m in ash_log if "xff" in m.lower()
    ]


#: A TOML config whose parser message quotes the duplicated table's name.
TOML_SHAPE = "[tool.{canary}]\n[tool.{canary}]\n"


def _toml_named_forms(world: _World) -> Dict[str, Callable[[], _Reply]]:
    """The named-config forms, pointed at a ``.toml`` file."""
    from automated_security_helper.cli import mcp_tools

    named = world.root / "defaults.toml"

    def _validate_config() -> _Reply:
        response = mcp_tools.mcp_validate_config(config_path=str(named))
        return _Reply(response.get("valid") is False, repr(response))

    return {
        "cli-scan-named": lambda: _invoke(_scan_args(world, "--config", str(named))),
        "cli-config-get": lambda: _invoke(["config", "get", "--config", str(named)]),
        "cli-config-validate": lambda: _invoke(
            [
                "config",
                "validate",
                "--config",
                str(named),
                "--source-dir",
                str(world.project),
            ]
        ),
        "mcp-get-config-raw": lambda: _mcp_response(
            world, mcp_tools.mcp_get_config(config_path=str(named), raw=True)
        ),
        "mcp-validate-config": _validate_config,
    }


@pytest.mark.parametrize(
    "form",
    [
        "cli-scan-named",
        "cli-config-get",
        "cli-config-validate",
        "mcp-get-config-raw",
        "mcp-validate-config",
    ],
)
def test_a_toml_refusal_quotes_no_file_text(world, ash_log, form):
    canary = _canary()
    world.write(world.root / "defaults.toml", TOML_SHAPE.format(canary=canary))

    reply = _toml_named_forms(world)[form]()

    squeezed = _squeezed(reply.text)
    assert reply.refused, reply.text[-3000:]
    # The place for this shape on every interpreter: tomllib sets lineno on
    # Python 3.14 and later only, and elsewhere the refusal reads the fixed
    # "(at line N, column M)" suffix of the parser's message, digits only. An
    # error raised at the end of the document ends "(at end of document)"
    # instead, so such a refusal carries no place before 3.14; this cell's
    # duplicated table is refused mid-document.
    assert _squeezed("could not be parsed (TOMLDecodeError at line") in squeezed, (
        reply.text[-3000:]
    )
    assert canary not in squeezed, reply.text[-3000:]
    assert canary not in _squeezed("\n".join(ash_log)), [
        m for m in ash_log if canary in _squeezed(m)
    ]


def test_control_a_toml_str_load_does_quote_the_file_text():
    """The hazard: tomllib's message names the duplicated table."""
    canary = _canary()

    with pytest.raises(tomllib.TOMLDecodeError) as from_str:
        tomllib.loads(TOML_SHAPE.format(canary=canary))

    assert canary in str(from_str.value)


def test_a_toml_refusal_names_its_place_mid_document():
    """tomllib sets lineno and colno on Python 3.14 and later only, and a
    message for an error mid-document ends with the fixed "(at line N, column
    M)" suffix, so the refusal reads the place from the suffix where the
    attributes are missing: digits only, never the message's naming of the
    duplicated table."""
    from automated_security_helper.config.config_sources import parse_error_kind

    canary = _canary()
    with pytest.raises(tomllib.TOMLDecodeError) as refused:
        tomllib.loads(TOML_SHAPE.format(canary=canary))

    kind = parse_error_kind(refused.value)
    assert re.fullmatch(r"\(TOMLDecodeError at line \d+, column \d+\)", kind), kind
    assert canary not in kind, kind


def test_a_toml_refusal_at_the_end_of_the_document_names_a_place_only_if_known():
    """An error at the end of the document ends its message "(at end of
    document)", with no place to read. Where tomllib sets no lineno (before
    Python 3.14) the refusal names the kind alone, inventing no place and
    taking none of the message's words; where it does, the place is named."""
    from automated_security_helper.config.config_sources import parse_error_kind

    with pytest.raises(tomllib.TOMLDecodeError) as refused:
        tomllib.loads('a = "unterminated')

    kind = parse_error_kind(refused.value)
    if getattr(refused.value, "lineno", None) is None:
        assert kind == "(TOMLDecodeError)", kind
    else:
        assert re.fullmatch(r"\(TOMLDecodeError at line \d+, column \d+\)", kind), kind


@pytest.mark.parametrize(
    "document,reason",
    [
        ('{"a": 1 "b": 2}', "Expecting ',' delimiter"),
        ('{"a" 1}', "Expecting ':' delimiter"),
    ],
    ids=["comma", "colon"],
)
def test_a_json_delimiter_refusal_keeps_its_fixed_reason(document, reason):
    """The two delimiter templates are the messages that hold a quote
    character and are still kept: the quoted character is the template's own
    punctuation, not the document's, so the reason is said whole, with its
    place."""
    from automated_security_helper.config.config_sources import parse_error_kind

    with pytest.raises(json.JSONDecodeError) as refused:
        json.loads(document)

    error = refused.value
    assert error.msg == reason, error.msg
    assert parse_error_kind(error) == (
        f"(JSONDecodeError: {reason} at line {error.lineno}, column {error.colno})"
    )


def test_a_json_refusal_carries_the_parsers_fixed_reason():
    """The C scanner's templates hold no document text, and this one (a
    trailing comma) is fixed under both scanners, so the refusal carries the
    parser's reason with the place."""
    from automated_security_helper.config.config_sources import parse_error_kind

    canary = _canary()
    with pytest.raises(json.JSONDecodeError) as refused:
        json.loads(f'{{"{canary}": 1,}}')

    error = refused.value
    kind = parse_error_kind(error)
    assert kind == (
        f"(JSONDecodeError: {error.msg} at line {error.lineno}, column {error.colno})"
    ), kind
    assert canary not in kind, kind


@pytest.mark.parametrize(
    "form",
    [
        "cli-scan-named",
        "cli-config-get",
        "cli-config-validate",
        "mcp-get-config-raw",
        "mcp-validate-config",
    ],
)
def test_a_toml_file_that_is_not_utf8_is_refused_without_its_bytes(
    world, ash_log, form
):
    """TOML requires UTF-8, and the refusal of a file that is not says where
    the bad byte sits, never its value: the decoder's own message gives the
    byte ("can't decode byte 0xff"), in the words the YAML refusal already
    keeps out."""
    world.write(world.root / "defaults.toml", NOT_UTF8)

    reply = _toml_named_forms(world)[form]()

    squeezed = _squeezed(reply.text)
    assert reply.refused, reply.text[-3000:]
    assert _squeezed("not UTF-8 at byte offset 14") in squeezed, reply.text[-3000:]
    assert "xff" not in _sans_paths(reply.text, world.root), reply.text[-3000:]
    assert "xff" not in _sans_paths("\n".join(ash_log), world.root), [
        m for m in ash_log if "xff" in m.lower()
    ]


def test_reading_a_toml_file_that_is_not_utf8_names_no_byte():
    """The reader behind both TOML views refuses a non-UTF-8 file with the
    offset alone, with nothing of the decoder's message reachable: it names
    the byte's value, and a reader of the chain would reach it."""
    import tempfile

    from automated_security_helper.config.config_sources import read_config_text
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    with tempfile.TemporaryDirectory() as scratch:
        bad = Path(scratch) / "defaults.toml"
        bad.write_bytes(NOT_UTF8)

        with pytest.raises(ASHConfigSourceError) as refused:
            read_config_text(bad)

    assert "not UTF-8 at byte offset 14" in str(refused.value), refused.value
    assert "xff" not in _sans_paths(str(refused.value), Path(scratch)), refused.value
    assert refused.value.__cause__ is None, repr(refused.value.__cause__)
    assert refused.value.__context__ is None, repr(refused.value.__context__)


def test_a_refusal_whose_marks_differ_names_both_places():
    """An unclosed flow sequence stops the parser at the end of the stream, a
    place not in the editor, while the construct's own ``[`` is. When the
    parser's problem and context marks differ, the refusal gives both, digits
    alone: where it stopped, and where what it was reading started."""
    from automated_security_helper.config.config_sources import parse_error_kind

    canary = _canary()
    with pytest.raises(yaml.error.MarkedYAMLError) as refused:
        yaml.safe_load(f"{canary}: [stop\n")

    kind = parse_error_kind(refused.value)
    assert kind == (
        "(ParserError at line 2, column 1; "
        f"started at line 1, column {len(canary) + 3})"
    ), kind
    assert canary not in kind, kind


def test_a_refusal_whose_marks_agree_names_one_place():
    """Equal marks say the place once: no "; started at" of the same spot."""
    from automated_security_helper.config.config_sources import parse_error_kind

    mark = yaml.error.Mark("probe", 0, 4, 2, None, None)
    same = yaml.error.MarkedYAMLError(
        context="while probing", context_mark=mark, problem="agreed", problem_mark=mark
    )

    assert parse_error_kind(same) == "(MarkedYAMLError at line 5, column 3)"


def test_a_refusal_with_no_context_mark_names_one_place():
    """A problem mark alone, an undefined alias, keeps the single place."""
    from automated_security_helper.config.config_sources import parse_error_kind

    with pytest.raises(yaml.error.MarkedYAMLError) as refused:
        yaml.safe_load("api_key: *missing\n")
    assert refused.value.context_mark is None

    assert parse_error_kind(refused.value) == "(ComposerError at line 1, column 10)"


def test_a_json_reason_that_quotes_a_character_keeps_it_out():
    """json's pure-Python scanner formats the refused character into two of
    its templates (an invalid control character, an invalid escape), where the
    C scanner's are fixed. A quoted character is document text, so such a
    refusal gives the type and place alone."""
    from automated_security_helper.config.config_sources import parse_error_kind

    quoted = json.JSONDecodeError("Invalid control character '\\x00' at", "{}", 0)

    assert parse_error_kind(quoted) == "(JSONDecodeError at line 1, column 1)"


def test_a_json_reason_ending_in_at_meets_the_place_once():
    """ "Unterminated string starting at" joins " at line" without saying at
    twice."""
    from automated_security_helper.config.config_sources import parse_error_kind

    unterminated = json.JSONDecodeError("Unterminated string starting at", '"x', 1)

    kind = parse_error_kind(unterminated)
    assert "at at" not in kind, kind
    assert kind == (
        "(JSONDecodeError: Unterminated string starting at line 1, column 2)"
    ), kind


@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_saving_a_suppression_quotes_no_file_text(world, shape):
    """add_suppression_to_config edits the file as text, so it is the one load
    outside the stream readers; its refusal says no more than the others."""
    from automated_security_helper.config.ash_config import add_suppression_to_config
    from automated_security_helper.models.core import AshSuppression

    canary = _canary()
    template, kind = SHAPES[shape]
    world.write(world.discovered, template.format(canary=canary))

    with pytest.raises(ValueError) as refused:
        add_suppression_to_config(
            world.discovered,
            AshSuppression(rule_id="RULE-1", path="a.py", reason="pinned"),
        )

    assert canary not in str(refused.value)
    assert f"could not be parsed ({kind} at line" in str(refused.value)


def test_saving_a_suppression_keeps_an_env_reference(world, monkeypatch):
    """A config whose value carries the documented ``!ENV`` tag is valid, and
    the entry is inserted as text: the reference stays as written, and the
    parse that finds the insertion point reads nothing from the environment."""
    from automated_security_helper.config.ash_config import add_suppression_to_config
    from automated_security_helper.models.core import AshSuppression

    canary = _canary()
    monkeypatch.setenv("ASH_SUPPRESSION_TEST_VALUE", canary)
    world.write(
        world.discovered,
        "project_name: !ENV ${ASH_SUPPRESSION_TEST_VALUE}\n"
        "global_settings:\n"
        "  suppressions: []\n",
    )

    written = add_suppression_to_config(
        world.discovered,
        AshSuppression(rule_id="RULE-1", path="a.py", reason="pinned"),
    )

    text = world.discovered.read_text(encoding="utf-8")
    assert written is True
    assert "RULE-1" in text
    assert "!ENV ${ASH_SUPPRESSION_TEST_VALUE}" in text
    assert canary not in text
    # The saved file still parses and holds the entry, through the same
    # environment-free loader the writer reads with.
    from automated_security_helper.config.ash_config import _KeepsEnvReferences

    data = yaml.load(text, Loader=_KeepsEnvReferences)  # nosec B506 - a SafeLoader
    entries = (data.get("global_settings") or {}).get("suppressions") or []
    assert any(e.get("rule_id") == "RULE-1" for e in entries), text


def test_saving_a_suppression_does_not_rewrite_an_env_reference_whole(
    world, monkeypatch
):
    """The shape that can only be saved by a full rewrite is refused when the
    file reads the environment: this writer reads with _KeepsEnvReferences, so
    its rewrite would drop the !ENV tags. The file is left as it was."""
    from automated_security_helper.config.ash_config import add_suppression_to_config
    from automated_security_helper.models.core import AshSuppression

    canary = _canary()
    monkeypatch.setenv("ASH_SUPPRESSION_TEST_VALUE", canary)
    before = (
        "project_name: !ENV ${ASH_SUPPRESSION_TEST_VALUE}\n"
        "global_settings: {fail_on_findings: true}\n"
    )
    world.write(world.discovered, before)

    with pytest.raises(ValueError) as refused:
        add_suppression_to_config(
            world.discovered,
            AshSuppression(rule_id="RULE-1", path="a.py", reason="pinned"),
        )

    assert "environment references" in str(refused.value)
    assert canary not in str(refused.value)
    assert world.discovered.read_text(encoding="utf-8") == before


@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_control_a_str_load_does_quote_the_file_text(shape):
    """The hazard the cells above guard against: PyYAML's message for a load
    from a str quotes the malformed line's text, as a snippet (flow, mapping,
    quoted) or in its own words (alias, tag)."""
    canary = _canary()
    text = SHAPES[shape][0].format(canary=canary)

    with pytest.raises(yaml.YAMLError) as from_str:
        yaml.safe_load(text)

    assert canary in str(from_str.value)


def test_linting_a_toml_file_that_does_not_parse_says_it_once(world):
    """The TOML reader's refusal names the file and says it did not parse, so
    the lint issue is that refusal alone: a "Failed to parse config file"
    prefix before it would say the same thing twice."""
    from automated_security_helper.config.config_linter import ConfigLinter

    canary = _canary()
    bad = world.write(world.root / "defaults.toml", TOML_SHAPE.format(canary=canary))

    result = ConfigLinter().lint(bad)

    [issue] = [i for i in result.issues if "could not be parsed" in i.message]
    assert "Failed to parse" not in issue.message, issue.message
    assert issue.message.count("could not be parsed") == 1, issue.message
    assert canary not in issue.message, issue.message


def test_an_extends_base_that_does_not_parse_is_refused_without_its_text(
    world, ash_log
):
    """The extends-base refusal is built on its own (config_sources), and it
    says where the base's parser stopped in the formatter's words, with
    nothing of the base's text."""
    canary = _canary()
    world.write(
        world.discovered.parent / "base.yaml",
        SHAPES["undefined-alias"][0].format(canary=canary),
    )

    reply = FORMS["cli-config-get"](world, "project_name: t\nextends: base.yaml\n")

    squeezed = _squeezed(reply.text)
    assert reply.refused, reply.text[-3000:]
    assert _squeezed("could not be parsed (ComposerError at line") in squeezed, (
        reply.text[-3000:]
    )
    assert canary not in squeezed, reply.text[-3000:]
    assert canary not in _squeezed("\n".join(ash_log)), [
        m for m in ash_log if canary in _squeezed(m)
    ]


def test_a_merge_config_that_does_not_parse_is_refused_without_its_text(world, ash_log):
    """ash merge reads --config through the same loader, and refuses it in the
    formatter's words."""
    canary = _canary()
    results = world.write(world.root / "results.json", "{}")
    bad = world.write(
        world.root / "bad.yaml", SHAPES["undefined-alias"][0].format(canary=canary)
    )

    reply = _invoke(
        [
            "merge",
            "--results",
            str(results),
            "--output-dir",
            str(world.root / "out"),
            "--config",
            str(bad),
        ]
    )

    squeezed = _squeezed(reply.text)
    assert reply.refused, reply.text[-3000:]
    assert _squeezed("could not be parsed (ComposerError at line") in squeezed, (
        reply.text[-3000:]
    )
    assert canary not in squeezed, reply.text[-3000:]
    assert canary not in _squeezed("\n".join(ash_log)), [
        m for m in ash_log if canary in _squeezed(m)
    ]


def test_config_update_refuses_a_config_that_does_not_parse_without_its_text(
    world, ash_log
):
    """config update checks the file before rewriting it (_describe_load_error,
    which config wizard shares), and the refusal gives the formatter's words."""
    canary = _canary()
    bad = world.write(
        world.root / "bad.yaml", SHAPES["undefined-alias"][0].format(canary=canary)
    )

    reply = _invoke(["config", "update", "--config", str(bad)])

    squeezed = _squeezed(reply.text)
    assert reply.refused, reply.text[-3000:]
    assert _squeezed("could not be parsed (ComposerError at line") in squeezed, (
        reply.text[-3000:]
    )
    assert canary not in squeezed, reply.text[-3000:]
    assert canary not in _squeezed("\n".join(ash_log)), [
        m for m in ash_log if canary in _squeezed(m)
    ]


def test_a_profile_that_does_not_parse_is_refused_without_its_text(world):
    """A --profile file that does not parse is refused in the formatter's
    words, with nothing of the file's text."""
    from automated_security_helper.cli.mcp.profile_registry import (
        ProfileRegistryError,
        clear_profile_registry,
        register_profiles,
    )

    canary = _canary()
    bad = world.write(
        world.root / "p.yaml", SHAPES["undefined-alias"][0].format(canary=canary)
    )

    clear_profile_registry()
    try:
        with pytest.raises(ProfileRegistryError) as refused:
            register_profiles([f"p1={bad}"])
    finally:
        clear_profile_registry()

    assert "could not be parsed (ComposerError at line" in str(refused.value), (
        refused.value
    )
    assert canary not in str(refused.value), refused.value


def test_an_mcp_refusal_names_the_config_file_once(world):
    """mcp_get_config's refusal of a config that does not parse names the file
    once: the frame names it, and the reason inside says "it could not be
    parsed" rather than naming the file again."""
    from automated_security_helper.cli import mcp_tools

    canary = _canary()
    world.write(world.discovered, SHAPES["flow-sequence"][0].format(canary=canary))

    response = mcp_tools.mcp_get_config(config_path=str(world.discovered), raw=True)

    assert response.get("success") is False, repr(response)
    message = str(response.get("error"))
    assert message.count(world.discovered.as_posix()) == 1, message
    assert "could not be parsed (" in message, message
    assert canary not in message, message


def test_an_mcp_toml_refusal_names_the_config_file_once(world):
    """The TOML reader's refusal names the file itself, so the frame does not
    name it again."""
    from automated_security_helper.cli import mcp_tools

    canary = _canary()
    named = world.write(world.root / "defaults.toml", TOML_SHAPE.format(canary=canary))

    response = mcp_tools.mcp_get_config(config_path=str(named), raw=True)

    assert response.get("success") is False, repr(response)
    message = str(response.get("error"))
    assert message.count(named.as_posix()) == 1, message
    assert "could not be parsed (TOMLDecodeError at line" in message, message
    assert canary not in message, message


def _a_yaml_parse_error() -> Exception:
    """A real parser refusal, for driving the frame directly."""
    try:
        yaml.safe_load("a: [1,")
    except yaml.YAMLError as error:
        return error
    raise AssertionError("the shape parsed")


def test_the_mcp_frames_file_name_is_the_form_its_duplicate_check_compares():
    """The frame names the file as describe_config_path spells it, which is
    what its duplicate-check compares. On Windows ``str(path)`` writes
    backslashes while the check reads the POSIX form, so the frame named the
    file in a form the check could never match, and the once-named pins above
    counted 0 on that leg. PureWindowsPath carries the divergence on any host."""
    from pathlib import PureWindowsPath

    from automated_security_helper.cli.mcp_tools import _config_load_failure

    windows_form = PureWindowsPath("C:/scan/.ash.yaml")

    response = _config_load_failure(_a_yaml_parse_error(), windows_form)

    message = str(response.get("error"))
    assert message.count("C:/scan/.ash.yaml") == 1, message
    assert "\\" not in message, message
    assert "could not be parsed (" in message, message


def test_a_reason_naming_the_file_keeps_the_frames_own_name_out_in_any_form():
    """The no-second-name arm reads the same form the frame prints: a reason
    that starts with the file's described name leaves the frame's name out,
    for a Windows-form path too."""
    from pathlib import PureWindowsPath

    from automated_security_helper.cli.mcp_tools import _config_load_failure

    windows_form = PureWindowsPath("C:/scan/.ash.yaml")
    reason = OSError("C:/scan/.ash.yaml could not be read")

    response = _config_load_failure(reason, windows_form)

    message = str(response.get("error"))
    assert message.count("C:/scan/.ash.yaml") == 1, message
    assert message.startswith("Configuration file cannot be loaded: "), message


def test_a_posix_paths_frame_is_what_it_always_was():
    """The control: for a POSIX path the two forms agree, and the frame's text
    is unchanged."""
    from automated_security_helper.cli.mcp_tools import _config_load_failure

    response = _config_load_failure(_a_yaml_parse_error(), Path("/scan/.ash.yaml"))

    message = str(response.get("error"))
    assert message.startswith(
        "Configuration file /scan/.ash.yaml cannot be loaded: "
    ), message
    assert message.count("/scan/.ash.yaml") == 1, message


def test_a_pyproject_frame_names_the_table_as_every_other_line_does(tmp_path):
    """describe_config_path names a pyproject source with its table, and the
    frame prints that same form: the refusal reads
    ``pyproject.toml [tool.ash] (line N)``, as the read-failure line already
    does, not the bare path the duplicate-check would never match."""
    from automated_security_helper.cli.mcp_tools import _config_load_failure
    from automated_security_helper.config.config_sources import describe_config_path

    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[tool.ash]\nproject_name = "x"\n', encoding="utf-8")

    response = _config_load_failure(_a_yaml_parse_error(), pyproject)

    message = str(response.get("error"))
    described = describe_config_path(pyproject)
    assert "[tool.ash]" in described, described
    assert message.count(described) == 1, (described, message)


def test_control_the_log_capture_sees_a_load_record(world, ash_log):
    """The log capture sees the logger's records at all: get_logger takes only
    ASH's own handlers off the logger (remove_ash_handlers) and sets its level
    to TRACE, so the fixture's handler stays attached through a command, and
    the load's own record reaches it. (The load keeps no record for the parse
    refusal itself; the caller prints it.) Without this control, every
    "canary not in the log" assertion would hold with nothing captured."""
    reply = FORMS["cli-config-get"](
        world, SHAPES["flow-sequence"][0].format(canary=_canary())
    )

    assert reply.refused, reply.text[-3000:]
    assert any("Loading configuration from" in m for m in ash_log), ash_log[:50]


def test_control_the_outputs_can_show_a_canary(world):
    """The capture path sees a canary at all: a valid value is printed."""
    canary = _canary()
    world.write(world.discovered, f"project_name: {canary}\n")

    result = CliRunner().invoke(
        app, ["config", "get", "--config", str(world.discovered)]
    )

    assert result.exit_code == 0, result.output[-2000:]
    assert canary in result.output
