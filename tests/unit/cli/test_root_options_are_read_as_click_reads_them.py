# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The root group reads its argv as click does, and the guide command writes what it says.

A refusal names the spelling the operator typed, never a value token or the
wrong flag of a cluster; a help token that is another option's value is not
help; a root option reaches the subcommand's option spelled the same; the
scan's environment variables are not parsed for a subcommand; get-genai-guide
quotes --branch into the URL, refuses a ref that is not one, reports a write
error in its own words, counts the file's bytes, and reports a path the
console cannot encode without exiting 1; running the module as a script does
not import it twice.
"""

from __future__ import annotations

import io
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import typer

# Typer 0.27 vendors click as ``typer._click`` and has no ``Option`` class there:
# its options are ``typer.core.TyperOption``, a ``Parameter`` subclass of the
# vendored copy, so the parser under test sees the type it is given at runtime.
from typer.core import TyperOption
from typer.testing import CliRunner

from automated_security_helper.cli import entrypoint
from automated_security_helper.cli import main as cli_main
from automated_security_helper.cli.main import (
    _asks_for_help,
    _echo_encodable,
    _run_as_main,
    _typed_spelling,
    app,
)
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR

pytestmark = pytest.mark.unit

ORCHESTRATOR_CREATE = (
    "automated_security_helper.core.orchestrator.ASHScanOrchestrator.create"
)


@pytest.fixture
def params():
    return [
        TyperOption(param_decls=["--format", "-f"], multiple=True),
        TyperOption(param_decls=["--verbose", "-v"], is_flag=True),
        TyperOption(param_decls=["--output-dir", "-o"]),
    ]


def _param(params, name):
    return next(p for p in params if name in p.opts)


# --- the spelling a refusal names ---


def test_a_value_token_is_not_read_as_a_spelling(params):
    """`--output-dir -f scan`: "-f" is --output-dir's value; the refusal named it."""
    fmt = _param(params, "--format")

    assert _typed_spelling(fmt, ["--output-dir", "-f", "scan"], params) == "--format"


def test_a_short_flag_inside_a_cluster_is_found(params):
    """`-vf sarif`: the cluster does not start with -f, so the long spelling
    was named for a flag the operator typed short."""
    fmt = _param(params, "--format")

    assert _typed_spelling(fmt, ["-vf", "sarif"], params) == "-f"


def test_the_equals_form_names_the_long_spelling():
    """`--format=sarif` names --format.

    This option declares its short spelling first, so the fallback to the first
    spelling (``param.opts[0]``, what a reading that misses the equals form
    returns) is "-f" here and cannot pass the assertion: with the shared
    fixture's order both readings answered "--format".
    """
    fmt = TyperOption(param_decls=["-f", "--format"], multiple=True)
    params = [fmt, TyperOption(param_decls=["--verbose", "-v"], is_flag=True)]
    assert fmt.opts[0] == "-f"

    assert _typed_spelling(fmt, ["--format=sarif"], params) == "--format"


def test_a_short_options_value_in_the_same_token_is_not_a_spelling(params):
    """`-ofoo`: foo is -o's value, not the flags f, o, o."""
    fmt = _param(params, "--format")

    assert _typed_spelling(fmt, ["-ofoo"], params) == "--format"


# --- help ---


def _report_command():
    root = typer.main.get_command(app)
    ctx = root.make_context("ash", ["report"], resilient_parsing=True)
    return root.get_command(ctx, "report"), ctx


@pytest.mark.parametrize(
    "args, expected",
    [
        (["--help"], True),
        (["--format", "text", "--help"], True),
        (["--config", "--help"], False),
        (["--", "--help"], False),
        (["--output-dir=--help"], False),
    ],
)
def test_help_is_asked_only_where_click_reads_an_option(args, expected):
    """Any token equal to a help spelling, as another option's value included,
    made the root drop the options given before the subcommand."""
    command, ctx = _report_command()

    assert _asks_for_help(command, ctx, args) is expected


# --- the environment and a subcommand ---


def test_the_scans_environment_variables_are_not_parsed_for_a_subcommand(
    monkeypatch, tmp_path
):
    """ASH_MODE=bogus failed `ash config ...` and `ash report` with a usage
    error for an option they do not take."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ASH_MODE", "bogus")

    result = CliRunner().invoke(app, ["get-genai-guide", "--help"])

    assert result.exit_code == 0, result.output
    assert "Usage:" in result.output


def test_the_control_a_bare_scan_still_reads_them(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ASH_MODE", "bogus")

    with patch(ORCHESTRATOR_CREATE):
        result = CliRunner().invoke(app, ["--source-dir", str(tmp_path)])

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    # The usage error is the environment value's: click refuses "bogus" as a
    # choice for --mode and names it. A usage error from anything else would
    # have passed the exit-code check alone.
    assert "bogus" in result.output, result.output


# --- get-genai-guide ---

GUIDE = "# GenAI guide\n\nUse ash_aggregated_results.json. Café.\n"


@pytest.fixture
def installed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "install"
    main_py = root / "automated_security_helper" / "cli" / "main.py"
    main_py.parent.mkdir(parents=True)
    guide = root / "docs" / "content" / "docs" / "genai-steering-guide.md"
    guide.parent.mkdir(parents=True)
    guide.write_text(GUIDE, encoding="utf-8")
    monkeypatch.setattr(cli_main, "__file__", str(main_py))
    return root


def test_the_branch_is_quoted_into_the_url(tmp_path):
    response = MagicMock()
    response.text = GUIDE
    response.raise_for_status = MagicMock()

    with patch("requests.get", return_value=response) as get:
        result = CliRunner().invoke(
            app,
            [
                "get-genai-guide",
                "--output",
                str(tmp_path / "guide.md"),
                "--from-github",
                "--branch",
                "release/v#1 2%",
            ],
        )

    assert result.exit_code == 0, result.output
    url = get.call_args.args[0]
    assert "/release/v%231%202%25/docs/" in url, url


@pytest.mark.parametrize("branch", ["..", "a/../b", "", "a//b"])
def test_a_branch_that_is_not_a_ref_name_is_refused(tmp_path, branch):
    with patch("requests.get") as get:
        result = CliRunner().invoke(
            app,
            [
                "get-genai-guide",
                "--output",
                str(tmp_path / "guide.md"),
                "--from-github",
                "--branch",
                branch,
            ],
        )

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert not get.called
    assert "not a git ref name" in result.output


def test_a_write_that_fails_is_the_commands_own_error(tmp_path, installed, monkeypatch):
    def full(*args, **kwargs):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(
        "automated_security_helper.utils.sandbox.fs_guard.replace_without_following",
        full,
    )

    result = CliRunner().invoke(
        app, ["get-genai-guide", "--output", str(tmp_path / "guide.md")]
    )

    assert result.exit_code == 1, result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "cannot write the guide" in result.output, result.output


def test_the_file_size_is_the_files_bytes(tmp_path, installed):
    result = CliRunner().invoke(
        app, ["get-genai-guide", "--output", str(tmp_path / "guide.md")]
    )

    assert result.exit_code == 0, result.output
    # GUIDE is 54 characters and 55 bytes: the é of "Café" is two bytes in
    # UTF-8. Pinned as literals, so the test does not repeat the command's own
    # arithmetic.
    assert "File size: 55 bytes" in result.output
    assert "File size: 54 bytes" not in result.output


def test_a_path_the_console_cannot_encode_is_still_reported(monkeypatch):
    said: list = []

    def ascii_echo(text, **kwargs):
        text.encode("ascii")
        said.append(text)

    monkeypatch.setattr(cli_main, "echo", ascii_echo)
    monkeypatch.setattr(sys, "stdout", io.StringIO())

    _echo_encodable("saved to: /out/café/guide.md")

    assert said == ["saved to: /out/caf\\xe9/guide.md"]


def test_a_console_with_a_codec_of_its_own_escapes_in_that_codec(monkeypatch):
    """The fallback encodes with the console's codec, not ASCII: under latin-1,
    "é" is written as itself and only the euro sign becomes an escape. The
    test above exercises the default taken when the console names no codec."""
    said: list = []

    def latin1_echo(text, **kwargs):
        text.encode("latin-1")
        said.append(text)

    monkeypatch.setattr(cli_main, "echo", latin1_echo)
    monkeypatch.setattr(
        sys, "stdout", io.TextIOWrapper(io.BytesIO(), encoding="latin-1")
    )

    _echo_encodable("saved to: /out/café €/guide.md")

    assert said == ["saved to: /out/café \\u20ac/guide.md"]


# --- running the module as a script ---


def test_running_the_module_as_main_registers_it_once(monkeypatch):
    """entrypoint.main imports automated_security_helper.cli.main; run as
    __main__, that import executed this file a second time."""
    calls: list = []
    monkeypatch.setattr(entrypoint, "main", lambda: calls.append("ran"))
    monkeypatch.delitem(sys.modules, "automated_security_helper.cli.main")
    as_main = types.ModuleType("__main__")

    _run_as_main(as_main)

    assert calls == ["ran"]
    assert sys.modules["automated_security_helper.cli.main"] is as_main
