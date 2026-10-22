# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A usage error names the value it refuses once: as typed, shown by its sink.

click and typer name a refused value by its repr in several messages: a choice
("'x' is not one of ..."), a number, a path, an unknown command. A repr writes a
control as the text of its escape (ESC as "\\x1b", U+202E as "\\u202e"). The
usage error's sink, terminal_text's shown_not_obeyed, gets the value as typed:
shown twice, the backslash doubles, and a real U+202E prints as "\\\\u202e", which the
escape rule reads as the text "\\u202e", the same as the six characters typed
literally. With real ``ash``, the doubled form of --mode
given U+202E has 2 backslashes before u202e, the literal text 4, and ESC 2.
"""

from __future__ import annotations

import json
import subprocess  # nosec B404 - ash runs as a child process, as an operator runs it
import sys
import warnings
from pathlib import Path

import pytest

from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from automated_security_helper.utils.terminal_text import shown_not_obeyed
from tests.utils.helpers import module_from_this_checkout

#: A right-to-left override, the text that only looks like one, and an ESC.
_RLO = "x\U0000202ey"
_RLO_AS_TEXT = "x\\u202ey"
_ESC = "x\x1b[31my"


def _ash(tmp_path: Path, *args: str) -> subprocess.CompletedProcess:
    """Run ``ash`` as an operator does, wide enough that no line of it wraps."""
    import os

    return subprocess.run(  # nosec B603 - fixed interpreter and arguments
        [
            sys.executable,
            "-I",
            "-c",
            module_from_this_checkout("automated_security_helper.cli.main"),
            *args,
        ],
        cwd=tmp_path,
        env={**os.environ, "TERMINAL_WIDTH": "400", "COLUMNS": "400"},
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def _assert_shown_once(output: str, value: str) -> None:
    once = str(shown_not_obeyed(value))
    # str() first: shown_not_obeyed returns text it was given shown already as it is.
    twice = str(shown_not_obeyed(once))
    assert once in output, (once, output)
    assert twice not in output, (twice, output)
    assert "\x1b" not in output and "\U0000202e" not in output, ascii(output)


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(_RLO, id="right-to-left-override"),
        pytest.param(_RLO_AS_TEXT, id="the-text-of-its-escape"),
        pytest.param(_ESC, id="esc"),
    ],
)
@pytest.mark.parametrize(
    "option",
    [
        pytest.param(["scan", "--mode"], id="choice-mode"),
        pytest.param(["scan", "--log-level"], id="choice-log-level"),
        pytest.param(["scan", "--shard-index"], id="integer-shard-index"),
    ],
)
def test_a_refused_option_value_is_shown_once(tmp_path, option, value):
    result = _ash(tmp_path, *option, value)

    assert result.returncode == ASH_EXIT_USAGE_ERROR, result.stdout + result.stderr
    _assert_shown_once(result.stdout + result.stderr, value)


def test_a_real_override_and_the_text_of_its_escape_stay_distinct(tmp_path):
    """Shown once each, the two read differently: one escape, then an escaped
    backslash and the text. Shown twice, the override read as the text."""
    real = _ash(tmp_path, "scan", "--mode", _RLO)
    text = _ash(tmp_path, "scan", "--mode", _RLO_AS_TEXT)

    assert "'x\\u202ey'" in real.stderr + real.stdout
    assert "'x\\\\u202ey'" in text.stderr + text.stdout
    assert "'x\\\\u202ey'" not in real.stderr + real.stdout


@pytest.mark.parametrize(
    "value",
    [pytest.param(_RLO, id="right-to-left-override"), pytest.param(_ESC, id="esc")],
)
def test_an_unknown_command_is_shown_once(tmp_path, value):
    result = _ash(tmp_path, value)

    assert result.returncode == ASH_EXIT_USAGE_ERROR, result.stdout + result.stderr
    assert "No such command" in result.stdout + result.stderr
    _assert_shown_once(result.stdout + result.stderr, value)


@pytest.mark.parametrize(
    "document, needle",
    [
        pytest.param({"mode": _ESC}, "is not one of", id="a-refused-value"),
        pytest.param({"mo\x1b[31mde": "local"}, "unknown key", id="an-unknown-key"),
    ],
)
def test_a_cli_json_input_refusal_is_shown_once(tmp_path, document, needle):
    """The JSON input names its keys, and the refused value's own message, by repr."""
    source = tmp_path / "input.json"
    source.write_text(json.dumps(document), encoding="utf-8")

    result = _ash(tmp_path, "scan", "--cli-json-input", str(source))

    output = result.stdout + result.stderr
    assert result.returncode == ASH_EXIT_USAGE_ERROR, output
    assert needle in output, output
    _assert_shown_once(output, _ESC if "mode" in document else "mo\x1b[31mde")


def test_a_duplicated_cli_json_input_key_is_shown_once(tmp_path):
    source = tmp_path / "input.json"
    source.write_text('{"x\\u001b[31my": 1, "x\\u001b[31my": 2}', encoding="utf-8")

    result = _ash(tmp_path, "scan", "--cli-json-input", str(source))

    output = result.stdout + result.stderr
    assert result.returncode == ASH_EXIT_USAGE_ERROR, output
    assert "more than once" in output, output
    _assert_shown_once(output, _ESC)


#: A value that, put back as typed with its newlines, wrote a line of its own into
#: the error panel: one that reads as ASH's.
_ERROR_LINE_LOOKALIKE = "N\n Error: --mode was accepted\nN"


def _lookalike_line(output: str) -> bool:
    # The panel's left and right border, a vertical box-drawing line.
    border = " " + chr(0x2502)
    return any(
        line.strip(border).startswith("Error: --mode was accepted")
        for line in output.splitlines()
    )


def test_a_value_with_a_newline_stays_on_one_line(tmp_path):
    """The repr kept it on one line ("\\n"); put back as typed, its newlines laid
    the panel out, so the panel held a line the value wrote."""
    result = _ash(tmp_path, "scan", "--mode", _ERROR_LINE_LOOKALIKE)

    output = result.stdout + result.stderr
    assert result.returncode == ASH_EXIT_USAGE_ERROR, output
    assert not _lookalike_line(output), output
    assert "N\\x0a Error: --mode was accepted\\x0aN" in output, output


@pytest.mark.parametrize(
    "document",
    [
        pytest.param({"mode": _ERROR_LINE_LOOKALIKE}, id="a-refused-value"),
        pytest.param({"mo\n Error: --mode was accepted\nde": "local"}, id="a-key"),
    ],
)
def test_a_cli_json_input_value_or_key_with_a_newline_stays_on_one_line(
    tmp_path, document
):
    source = tmp_path / "input.json"
    source.write_text(json.dumps(document), encoding="utf-8")

    result = _ash(tmp_path, "scan", "--cli-json-input", str(source))

    output = result.stdout + result.stderr
    assert result.returncode == ASH_EXIT_USAGE_ERROR, output
    assert not _lookalike_line(output), output


def test_a_value_holding_a_quote_keeps_the_quotes_its_repr_chose(tmp_path):
    """repr quotes a'b with double quotes; put back between single ones, it read
    as 'a' followed by b'."""
    result = _ash(tmp_path, "scan", "--mode", "a'b")

    output = result.stdout + result.stderr
    assert result.returncode == ASH_EXIT_USAGE_ERROR, output
    assert '"a\'b" is not one of' in output, output


def test_an_unknown_option_was_shown_once_already(tmp_path):
    """The control: click names an unknown option as typed, so it was shown once."""
    result = _ash(tmp_path, "scan", "--nope" + "\x1b[31m")

    assert result.returncode == ASH_EXIT_USAGE_ERROR, result.stdout + result.stderr
    _assert_shown_once(result.stdout + result.stderr, "--nope\x1b[31m")


def test_a_path_typer_names_by_repr_is_given_as_typed():
    """No ash option makes typer check a path's existence today, so its message is
    checked where the usage error's text is made."""
    import typer
    from typer.models import TyperPath

    from automated_security_helper.cli.json_input import _typed_text

    class _Param:
        type = TyperPath(exists=True)

        def get_error_hint(self, ctx):
            return "'--config'"

    param = _Param()
    with pytest.raises(typer.BadParameter) as caught:
        param.type.convert("no" + _ESC, param, None)

    assert "'no" + _ESC + "'" in _typed_text(caught.value), ascii(
        _typed_text(caught.value)
    )


def test_text_that_only_looks_like_a_repr_is_left_as_it_is():
    """Only a literal that is its value's own repr is put back: a quoted Windows
    path holding "\\x64" is no repr ("\\x64" would be "d"), and stays as it was,
    with ("\\L") or without an escape Python does not know."""
    import typer
    from typer._click.types import IntParamType

    from automated_security_helper.cli.json_input import _typed_text

    class _Param:
        type = IntParamType()

        def get_error_hint(self, ctx):
            return "'--n'"

    error = typer.BadParameter(
        "'C:\\x64\\Lib', 'C:\\x64' and 'x\\x1by' are named", param=_Param()
    )

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        text = _typed_text(error)

    # Reading "\\L" warns nowhere the operator sees it.
    assert not caught, [str(w.message) for w in caught]
    assert "'C:\\x64\\Lib'" in text, text
    assert "'C:\\x64' and" in text, text
    assert "'x\x1by'" in text, ascii(text)


@pytest.mark.parametrize(
    "command",
    [
        pytest.param(["scan"], id="scan"),
        pytest.param(["report"], id="report"),
        pytest.param(["config", "get"], id="config-get"),
        pytest.param(["dependencies", "install"], id="dependencies-install"),
    ],
)
def test_an_unknown_option_holding_a_newline_stays_on_one_line(tmp_path, command):
    """click writes an unknown option's token into its message as typed, so a
    newline in it laid out a line of the error panel that the token set, in
    every command."""
    proc = _ash(tmp_path, *command, "--" + _ERROR_LINE_LOOKALIKE)

    output = proc.stdout + "\n" + proc.stderr
    assert proc.returncode == ASH_EXIT_USAGE_ERROR, output
    assert not _lookalike_line(output), output
    assert "\\x0a Error: --mode was accepted\\x0a" in output, output


def test_an_extra_argument_holding_a_newline_stays_on_one_line(tmp_path):
    """The same for the extra-arguments message, the other message that embeds
    argv as typed."""
    proc = _ash(tmp_path, "scan", _ERROR_LINE_LOOKALIKE, "extra")

    output = proc.stdout + "\n" + proc.stderr
    assert proc.returncode == ASH_EXIT_USAGE_ERROR, output
    assert not _lookalike_line(output), output
    assert "\\x0a Error: --mode was accepted\\x0a" in output, output


@pytest.mark.parametrize(
    "command",
    [pytest.param(["scan"], id="scan"), pytest.param(["merge"], id="merge")],
)
def test_a_refused_output_format_stays_on_one_line(tmp_path, command):
    """The format refusals build their own message around the value as typed."""
    if command == ["merge"]:
        results = tmp_path / "results.json"
        results.write_text("{}", encoding="utf-8")
        command = [
            "merge",
            "--results",
            str(results),
            "--output-dir",
            str(tmp_path / "out"),
        ]

    proc = _ash(tmp_path, *command, "--output-formats", _ERROR_LINE_LOOKALIKE)

    output = proc.stdout + "\n" + proc.stderr
    assert proc.returncode == ASH_EXIT_USAGE_ERROR, output
    assert "is not a valid format" in output, output
    assert not _lookalike_line(output), output
    # The whole value was shown, its newlines as escapes: a refusal that cut
    # the value at the first newline would also write no such line.
    assert "\\x0a Error: --mode was accepted\\x0a" in output, output


def test_two_config_files_are_named_on_one_line(tmp_path):
    """config get's two-files refusal embeds both paths as typed."""
    proc = _ash(
        tmp_path,
        "config",
        "get",
        _ERROR_LINE_LOOKALIKE + ".yaml",
        "--config",
        "other.yaml",
    )

    output = proc.stdout + "\n" + proc.stderr
    assert proc.returncode == ASH_EXIT_USAGE_ERROR, output
    assert "names two config files" in output, output
    assert not _lookalike_line(output), output
    # Both names were shown whole, the multi-line one with its newlines as escapes.
    assert "\\x0a Error: --mode was accepted\\x0a" in output, output
    assert "other.yaml" in output, output


def test_a_missing_parameter_with_a_multi_line_message_prints_on_one_line(
    capfd, monkeypatch
):
    """The error's type says nothing about where its text came from: a
    MissingParameter raised with its own message carries whatever that code
    put there, and a newline in it would otherwise start a new output line.
    Only click's own Choice layout is flattened; a message some code built
    itself keeps every whitespace character as the text of its escape, like
    every other error's, so different texts stay distinct and the message's
    only output line is ASH's own "Error: " line."""
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("TERMINAL_WIDTH", "400")
    from typer._click.exceptions import MissingParameter

    from automated_security_helper.cli.main import _shown_usage_error

    error = MissingParameter(
        message=_ERROR_LINE_LOOKALIKE, ctx=None, param_type="option"
    )
    # The control: the message really is multi-line.
    assert "\n" in error.format_message(), ascii(error.format_message())

    raised = _shown_usage_error(error)

    output = capfd.readouterr().err
    assert getattr(raised, "exit_code", None) == ASH_EXIT_USAGE_ERROR
    assert not _lookalike_line(output), output
    assert "\\x0a Error: --mode was accepted\\x0a" in output, output


def test_a_newline_in_the_message_gives_the_output_no_fold_point_at_width_80(
    capfd, monkeypatch
):
    """The message sets its own length. At a typical CI width, a newline
    collapsed to a plain space gave the panel a fold point, and 14 pad
    lengths put that fold exactly before the embedded sentence, which then
    started a bordered line. With every usage error on ASH's own unwrapped
    line there is no fold at any pad length - for the multi-line
    MissingParameter and for the plain control alike - so both pad sets are
    EMPTY, asserted directly: the earlier ==-comparison form passed whenever
    both regressed identically."""
    monkeypatch.setenv("COLUMNS", "80")
    monkeypatch.setenv("TERMINAL_WIDTH", "80")
    from typer._click.exceptions import MissingParameter, UsageError

    from automated_security_helper.cli.main import _shown_usage_error

    sentence = "Error: --mode was accepted, full access granted"
    newline_pads = []
    plain_pads = []
    for pad in range(40, 120):
        multi_line = MissingParameter(
            message="A" * pad + "\n" + sentence, ctx=None, param_type="option"
        )
        _shown_usage_error(multi_line)
        if _lookalike_line(capfd.readouterr().err):
            newline_pads.append(pad)
        # The control: one plain token of the same shown length, the embedded
        # sentence at the same offset ("zzzz" stands where the escape's four
        # characters sit), through the same printer.
        plain = UsageError("A" * pad + "zzzz" + sentence)
        _shown_usage_error(plain)
        if _lookalike_line(capfd.readouterr().err):
            plain_pads.append(pad)

    assert newline_pads == [], newline_pads
    assert plain_pads == [], plain_pads


def test_a_token_wider_than_the_panel_prints_whole_without_a_panel(capfd, monkeypatch):
    """A message holding a token wider than the panel's usable line (its width
    minus two border and two padding columns; tokens of 77 break at width 80,
    76 does not, measured) cannot render in the panel without a mid-token
    break, and the break's position follows the text before the token - so
    the text at the start of a bordered row depended on the whole message.
    Such a message takes the one-line unwrapped form every usage error takes:
    the token prints whole, and there is no bordered row."""
    monkeypatch.setenv("COLUMNS", "80")
    monkeypatch.setenv("TERMINAL_WIDTH", "80")
    from typer._click.exceptions import UsageError

    from automated_security_helper.cli.main import _shown_usage_error

    token = "A" * 50 + "Error:-row-start-marker" + "B" * 4  # 77 characters
    assert len(token) == 77

    _shown_usage_error(UsageError(f"the option value {token} was refused"))

    output = capfd.readouterr().err
    # Whole, on one line, and with no panel whose rows a pad could lay out.
    assert token in output, output
    assert chr(0x2502) not in output, output
    # The structure itself: the message's only line is ASH's own "Error: "
    # line, so no row starts inside the token at a position the text set.
    non_empty = [line for line in output.splitlines() if line.strip()]
    assert len(non_empty) == 1, output
    assert non_empty[0].startswith("Error: "), output


def test_a_spaced_message_also_prints_on_one_line(capfd, monkeypatch):
    """The panel folds at every space in the message, so a spaced message can
    start a bordered row at any word: pad words position the fold, and the
    next word opens the row. Every usage error prints in the one-line
    unwrapped form, and the panel is not used for them at all - the
    message's only line is ASH's own "Error: " line."""
    monkeypatch.setenv("COLUMNS", "80")
    monkeypatch.setenv("TERMINAL_WIDTH", "80")
    from typer._click.exceptions import UsageError

    from automated_security_helper.cli.main import _shown_usage_error

    # Every token fits the old panel; the spaces are the fold points.
    marker = "Error:-row-start-marker"
    message = ("pad " * 18) + marker + " tail"

    _shown_usage_error(UsageError(message))

    output = capfd.readouterr().err
    assert marker in output, output
    assert chr(0x2502) not in output, output
    # Were it folded at the width, even without a border, the pads would put
    # the marker at the start of a line; it must not be.
    assert not any(line.lstrip().startswith(marker) for line in output.splitlines()), (
        output
    )
    # The structure itself: one "Error: " line, so no fold at any pad length.
    non_empty = [line for line in output.splitlines() if line.strip()]
    assert len(non_empty) == 1, output
    assert non_empty[0].startswith("Error: "), output


def test_a_wide_character_token_prints_whole_without_a_panel(capfd, monkeypatch):
    """Rich wraps by cells, not by characters: a token of 45 characters and 90
    cells is wider than the console, so a panel had to break it mid-run at a
    position the text before it sets, while the length check read 45 and
    kept the panel. One-line unwrapped, the token prints whole."""
    monkeypatch.setenv("COLUMNS", "80")
    monkeypatch.setenv("TERMINAL_WIDTH", "80")
    from typer._click.exceptions import UsageError

    from automated_security_helper.cli.main import _shown_usage_error

    token = "ＥＲＲ" * 15  # fullwidth ERR: len 45, 90 cells
    assert len(token) == 45

    _shown_usage_error(UsageError(f"the option value {token} was refused"))

    output = capfd.readouterr().err
    assert token in output, output
    assert chr(0x2502) not in output, output
    # The structure itself: one "Error: " line, so no break mid-run at a
    # position the text before the token set.
    non_empty = [line for line in output.splitlines() if line.strip()]
    assert len(non_empty) == 1, output
    assert non_empty[0].startswith("Error: "), output


def test_choose_from_in_a_message_without_a_choice_parameter_stays_escaped():
    """Only a missing Choice parameter's own layout is flattened. The phrase
    says nothing about where the text came from: a MissingParameter raised
    with its own message and no Choice parameter carries whatever that code
    put there, so its separators are whitespace in the text, shown as escapes
    like any other error's, before and after "Choose from" alike. Flattened,
    a message written with the separators and one written with plain spaces
    printed the same."""
    from typer._click.exceptions import MissingParameter

    from automated_security_helper.cli.json_input import usage_error_text

    text = usage_error_text(
        MissingParameter(
            message="text:\n\tgranted. Choose from:\n\tlocal,\n\tcontainer",
            ctx=None,
            param_type="option",
        )
    )

    shown = str(text)
    assert "text:\\x0a\\x09granted." in shown, shown
    assert "Choose from:\\x0a\\x09local,\\x0a\\x09container" in shown, shown
    assert "Choose from: local, container" not in shown, shown


def test_a_missing_choice_parameter_stays_on_one_line(capfd, monkeypatch):
    """click's text for a missing choice lists the choices a line each, the one
    message of its type that holds newlines. Built the way click builds it (a
    required Choice option processed with no value raises through its
    command's context), the message's whitespace is collapsed, so it reads
    "Choose from: local, container" on one line rather than an escape per
    choice: this message is click's own layout, never an argv token, and a
    newline in it is layout to flatten, not a value to keep. The width is
    pinned wide, so folding cannot stand in for the layout."""
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("TERMINAL_WIDTH", "400")
    from typer._click.core import Context
    from typer._click.exceptions import MissingParameter
    from typer._types import TyperChoice
    from typer.core import TyperCommand, TyperOption

    from automated_security_helper.cli.main import _shown_usage_error

    option = TyperOption(
        param_decls=["--mode"], type=TyperChoice(["local", "container"]), required=True
    )
    command = TyperCommand(name="scan", params=[option])
    with pytest.raises(MissingParameter) as excinfo:
        with Context(command) as ctx:
            command.parse_args(ctx, [])
    error = excinfo.value
    # The control: the message really is multi-line, so the assertions below
    # distinguish escaped layout from kept layout.
    assert "\n" in error.format_message(), ascii(error.format_message())

    raised = _shown_usage_error(error)

    output = capfd.readouterr().err
    assert getattr(raised, "exit_code", None) == ASH_EXIT_USAGE_ERROR
    assert "Choose from" in output, output
    assert "\\x0a" not in output, output
    # One line, readable, in exactly the promised words: a regression that
    # collapsed only the newlines would leave the tabs to be escaped, and
    # "Choose from: \\x09local, \\x09container" would still satisfy weaker
    # checks.
    assert "Choose from: local, container" in output, output
    assert "\\x09" not in output, output


def test_a_missing_choice_message_from_a_translated_builder_still_flattens(
    capfd, monkeypatch
):
    """The layout to flatten is the one the Choice parameter's own message
    builder wrote, not an English phrase: matched against the builder's text,
    a missing choice reads one per line collapsed to one readable line in any
    language. The vendored builder (typer._types.TyperChoice
    .get_missing_message) writes its text literally rather than through a
    translation catalog, so no catalog can translate it in a test; the builder
    itself is patched to the shape a translation would give, which changes the
    message the same way."""
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("TERMINAL_WIDTH", "400")
    from typer._click.core import Context
    from typer._click.exceptions import MissingParameter
    from typer._types import TyperChoice
    from typer.core import TyperCommand, TyperOption

    from automated_security_helper.cli.main import _shown_usage_error

    def _translated(self, param, ctx):
        choices = ",\n\t".join(self._normalized_mapping(ctx=ctx).values())
        return f"Choisissez parmi:\n\t{choices}"

    monkeypatch.setattr(TyperChoice, "get_missing_message", _translated)
    option = TyperOption(
        param_decls=["--mode"], type=TyperChoice(["local", "container"]), required=True
    )
    command = TyperCommand(name="scan", params=[option])
    with pytest.raises(MissingParameter) as excinfo:
        with Context(command) as ctx:
            command.parse_args(ctx, [])
    error = excinfo.value
    # The control: the message really is multi-line, and no English phrase
    # is left for a phrase match to find.
    assert "\n" in error.format_message(), ascii(error.format_message())
    assert "Choose from" not in error.format_message(), error.format_message()

    raised = _shown_usage_error(error)

    output = capfd.readouterr().err
    assert getattr(raised, "exit_code", None) == ASH_EXIT_USAGE_ERROR
    assert "Choisissez parmi: local, container" in output, output
    assert "\\x0a" not in output and "\\x09" not in output, output
