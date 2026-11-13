# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A template-based scanner's recorded command line hides values read from the environment.

``ScannerPluginBase._inject_invocation`` records the command a scanner ran in
``runs[0].invocations[0]`` (``commandLine`` and ``arguments``) and in the
scanner details attached to the tool driver. An option written ``${VAR}`` in
the configuration file is part of the configuration's redaction set and shows
as ``<value>`` in both. An option written out literally is operator text and is
recorded whole.
"""

import json
import shlex
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    _arguments_in_joined_redactions,
    redacted_command_record,
)
from automated_security_helper.config import resolve_config as resolve_config_module
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.config_validator import REDACTED
from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
    SemgrepScanner,
)
from automated_security_helper.utils.error_text import text_without_values
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()
AshConfig.model_rebuild()

RULESET_FROM_ENVIRONMENT = "marker-secret-ruleset-value"
RULESET_WRITTEN_OUT = "marker-literal-ruleset-value"
# A value that holds a single quote: shlex.join writes it as several quoted
# segments, so the joined text no longer holds the value as one piece.
RULESET_WITH_QUOTE = "marker-quote'carrier-value"

EMPTY_SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "semgrep", "version": "1.0.0", "rules": []}},
            "results": [],
        }
    ],
}


def _scan(
    tmp_path,
    monkeypatch,
    config_line,
    environment_value=RULESET_FROM_ENVIRONMENT,
    values_hook=None,
):
    """Scan with a fake semgrep, the ``config`` option written as ``config_line``.

    ``values_hook`` replaces the scanner's ``_values_to_redact`` for the scan.
    """
    monkeypatch.setenv("ASH_TEST_SEMGREP_RULESET", environment_value)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    config_file = tmp_path / "operator" / ".ash.yaml"
    config_file.parent.mkdir()
    config_file.write_text(
        "project_name: command-record-project\n"
        "scanners:\n"
        "  semgrep:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      config: {config_line}\n",
        encoding="utf-8",
    )
    _, config = resolve_config_module.load_config_file_for_run(config_file)
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n")
    output = tmp_path / "out"
    output.mkdir()
    scanner = SemgrepScanner(
        context=PluginContext(source_dir=source, output_dir=output, config=config),
        config=config.get_plugin_config(plugin_type="scanner", plugin_name="semgrep"),
    )
    scanner.dependencies_satisfied = True
    argv = []

    def fake_run(*, command, results_dir, **kwargs):
        argv[:] = [str(a) for a in command]
        Path(results_dir, "results_sarif.sarif").write_text(json.dumps(EMPTY_SARIF))
        return {"stdout": "", "stderr": "", "returncode": 0}

    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        # The version probe would start the tool; no tool starts in this cell.
        patch.object(scanner, "resolve_deferred_tool_version"),
        patch.object(scanner, "_run_subprocess", side_effect=fake_run),
        patch.object(SemgrepScanner, "_values_to_redact", values_hook)
        if values_hook is not None
        else nullcontext(),
    ):
        report = scanner.scan(target=source, target_type="source")
    return report, argv


def _recorded_invocations(report):
    """The two places the template records the command: the run's invocation and
    the tool driver's scanner details."""
    invocation = report.runs[0].invocations[0]
    details = report.runs[0].tool.driver.properties.scanner_details["tool_invocation"]
    return invocation, details


def test_an_option_read_from_the_environment_is_hidden_in_the_recorded_command(
    tmp_path, monkeypatch
):
    report, argv = _scan(tmp_path, monkeypatch, "!ENV ${ASH_TEST_SEMGREP_RULESET}")

    assert RULESET_FROM_ENVIRONMENT in argv, argv
    invocation, details = _recorded_invocations(report)
    assert RULESET_FROM_ENVIRONMENT not in invocation.commandLine
    assert not any(RULESET_FROM_ENVIRONMENT in a for a in invocation.arguments)
    assert RULESET_FROM_ENVIRONMENT not in details["command_line"]
    assert not any(RULESET_FROM_ENVIRONMENT in a for a in details["arguments"])
    assert RULESET_FROM_ENVIRONMENT not in report.model_dump_json()
    assert "--config" in invocation.arguments


def test_an_option_written_out_is_recorded_whole(tmp_path, monkeypatch):
    report, argv = _scan(tmp_path, monkeypatch, RULESET_WRITTEN_OUT)

    assert RULESET_WRITTEN_OUT in argv, argv
    invocation, details = _recorded_invocations(report)
    assert RULESET_WRITTEN_OUT in invocation.commandLine
    assert RULESET_WRITTEN_OUT in invocation.arguments
    assert RULESET_WRITTEN_OUT in details["command_line"]
    assert RULESET_WRITTEN_OUT in details["arguments"]


def test_an_environment_value_holding_a_quote_is_hidden_in_the_recorded_command(
    tmp_path, monkeypatch
):
    report, argv = _scan(
        tmp_path,
        monkeypatch,
        "!ENV ${ASH_TEST_SEMGREP_RULESET}",
        environment_value=RULESET_WITH_QUOTE,
    )

    assert RULESET_WITH_QUOTE in argv, argv
    invocation, details = _recorded_invocations(report)
    for recorded in (invocation.commandLine, details["command_line"]):
        assert "marker-quote" not in recorded, recorded
        assert "carrier-value" not in recorded, recorded
    assert RULESET_WITH_QUOTE not in report.model_dump_json()
    assert "--config" in invocation.arguments


def test_a_written_out_value_holding_a_quote_is_recorded_in_its_quoted_form(
    tmp_path, monkeypatch
):
    report, argv = _scan(tmp_path, monkeypatch, f'"{RULESET_WITH_QUOTE}"')

    assert RULESET_WITH_QUOTE in argv, argv
    invocation, details = _recorded_invocations(report)
    assert shlex.quote(RULESET_WITH_QUOTE) in invocation.commandLine
    assert shlex.quote(RULESET_WITH_QUOTE) in details["command_line"]
    assert RULESET_WITH_QUOTE in invocation.arguments


def _raising_hook(_self):
    raise RuntimeError("the values hook broke")


def _none_hook(_self):
    return None


def _number_hook(_self):
    return 7


def _assert_records_carry_only_the_command(report, argv):
    """The scan finished with a report, and its two records name the command
    and nothing else: none of the arguments the tool was given."""
    assert hasattr(report, "runs"), type(report)
    invocation, details = _recorded_invocations(report)
    command = argv[0]
    assert invocation.commandLine == command, invocation.commandLine
    assert invocation.arguments == []
    assert details["command_line"] == command, details["command_line"]
    assert details["arguments"] == []
    assert "--config" in argv
    assert RULESET_WRITTEN_OUT not in report.model_dump_json()


def test_a_raising_values_hook_does_not_fail_the_scan_and_the_records_hold_only_the_command(
    tmp_path, monkeypatch
):
    report, argv = _scan(
        tmp_path, monkeypatch, RULESET_WRITTEN_OUT, values_hook=_raising_hook
    )

    assert RULESET_WRITTEN_OUT in argv, argv
    _assert_records_carry_only_the_command(report, argv)


@pytest.mark.parametrize(
    "hook", [_none_hook, _number_hook], ids=["none", "not-a-value-set"]
)
def test_an_unusable_values_answer_leaves_the_records_holding_only_the_command(
    tmp_path, monkeypatch, hook
):
    report, argv = _scan(tmp_path, monkeypatch, RULESET_WRITTEN_OUT, values_hook=hook)

    assert RULESET_WRITTEN_OUT in argv, argv
    _assert_records_carry_only_the_command(report, argv)


def test_a_values_answer_that_hides_the_value_keeps_the_redacted_command_line(
    tmp_path, monkeypatch
):
    report, argv = _scan(
        tmp_path,
        monkeypatch,
        f'"{RULESET_WITH_QUOTE}"',
        values_hook=lambda _self: (RULESET_WITH_QUOTE,),
    )

    assert RULESET_WITH_QUOTE in argv, argv
    invocation, details = _recorded_invocations(report)
    expected = f"--config {shlex.quote('<value>')}"
    assert expected in invocation.commandLine, invocation.commandLine
    assert expected in details["command_line"], details["command_line"]
    assert "carrier-value" not in invocation.commandLine


def test_an_empty_values_answer_records_the_whole_command_line(tmp_path, monkeypatch):
    report, argv = _scan(
        tmp_path, monkeypatch, RULESET_WRITTEN_OUT, values_hook=lambda _self: ()
    )

    invocation, details = _recorded_invocations(report)
    assert invocation.commandLine == shlex.join(argv), invocation.commandLine
    assert details["command_line"] == shlex.join(argv)
    assert RULESET_WRITTEN_OUT in invocation.arguments


# A value whose text spans two argv entries ("--config" and the ruleset): no
# single argument holds it, so only the joined command line does.
SPLIT_ACROSS_ARGUMENTS = f"--config {RULESET_WRITTEN_OUT}"


def test_a_value_split_across_two_arguments_is_hidden_in_the_recorded_command_line(
    tmp_path, monkeypatch
):
    report, argv = _scan(
        tmp_path,
        monkeypatch,
        RULESET_WRITTEN_OUT,
        values_hook=lambda _self: (SPLIT_ACROSS_ARGUMENTS,),
    )

    # The scanner passes "--config" more than once; the written-out ruleset is
    # the argument the values answer spans.
    position = argv.index(RULESET_WRITTEN_OUT)
    assert argv[position - 1] == "--config", argv
    invocation, details = _recorded_invocations(report)
    for recorded in (invocation.commandLine, details["command_line"]):
        assert RULESET_WRITTEN_OUT not in recorded, recorded
        assert SPLIT_ACROSS_ARGUMENTS not in recorded, recorded
        assert "<value>" in recorded, recorded


def test_an_unrelated_values_answer_leaves_the_split_arguments_in_the_command_line(
    tmp_path, monkeypatch
):
    report, argv = _scan(
        tmp_path,
        monkeypatch,
        RULESET_WRITTEN_OUT,
        values_hook=lambda _self: ("marker-unrelated-secret-value",),
    )

    invocation, details = _recorded_invocations(report)
    assert invocation.commandLine == shlex.join(argv), invocation.commandLine
    assert details["command_line"] == shlex.join(argv)
    # A non-secret argv is recorded untouched in both argument fields.
    assert invocation.arguments == argv[1:], invocation.arguments
    assert details["arguments"] == argv[1:], details["arguments"]


def test_a_value_split_across_two_arguments_leaves_no_bare_half_in_either_argument_field(
    tmp_path, monkeypatch
):
    report, argv = _scan(
        tmp_path,
        monkeypatch,
        RULESET_WRITTEN_OUT,
        values_hook=lambda _self: (SPLIT_ACROSS_ARGUMENTS,),
    )

    position = argv.index(RULESET_WRITTEN_OUT)
    assert argv[position - 1] == "--config", argv
    invocation, details = _recorded_invocations(report)
    for recorded in (invocation.arguments, details["arguments"]):
        assert RULESET_WRITTEN_OUT not in recorded, recorded
        assert not any(RULESET_WRITTEN_OUT in a for a in recorded), recorded
        # Both halves of the span are hidden; the built-in "--config" before it
        # and every other entry are recorded as they were.
        assert len(recorded) == len(argv) - 1
        hidden = [i for i, a in enumerate(recorded) if a == REDACTED]
        assert hidden == [position - 2, position - 1], recorded
        for index, entry in enumerate(recorded):
            if index not in hidden:
                assert entry == argv[index + 1], (index, recorded)


# A value that spans two argv entries where the second piece holds a single
# quote: shlex.join respells that piece as several quoted segments, so the
# joined line holds the value only in that respelled spelling.
SPLIT_WITH_A_QUOTE_HOLDING_PIECE = f"--config {RULESET_WITH_QUOTE}"


def test_a_split_value_with_a_quote_holding_piece_is_hidden_in_the_joined_records(
    tmp_path, monkeypatch
):
    report, argv = _scan(
        tmp_path,
        monkeypatch,
        f'"{RULESET_WITH_QUOTE}"',
        values_hook=lambda _self: (SPLIT_WITH_A_QUOTE_HOLDING_PIECE,),
    )

    # The quote-holding ruleset stands as its own argument after a "--config":
    # no single argument holds the value, and the joined line spells the
    # ruleset piece the way shlex.join quotes it.
    position = argv.index(RULESET_WITH_QUOTE)
    assert argv[position - 1] == "--config", argv
    invocation, details = _recorded_invocations(report)
    for recorded in (invocation.commandLine, details["command_line"]):
        assert "marker-quote" not in recorded, recorded
        assert "carrier-value" not in recorded, recorded
        assert shlex.quote(RULESET_WITH_QUOTE) not in recorded, recorded
        assert REDACTED in recorded, recorded
    for recorded in (invocation.arguments, details["arguments"]):
        assert RULESET_WITH_QUOTE not in recorded, recorded
        assert not any("marker-quote" in a for a in recorded), recorded


def test_a_split_value_with_plain_pieces_keeps_its_masking(tmp_path, monkeypatch):
    report, argv = _scan(
        tmp_path,
        monkeypatch,
        RULESET_WRITTEN_OUT,
        values_hook=lambda _self: (SPLIT_ACROSS_ARGUMENTS,),
    )

    # No piece needs quoting, so the joined line holds the value as it is;
    # the masking of the line and of the two spanned entries stays as it was.
    position = argv.index(RULESET_WRITTEN_OUT)
    assert argv[position - 1] == "--config", argv
    invocation, details = _recorded_invocations(report)
    for recorded in (invocation.commandLine, details["command_line"]):
        assert RULESET_WRITTEN_OUT not in recorded, recorded
        assert REDACTED in recorded, recorded
    for recorded in (invocation.arguments, details["arguments"]):
        hidden = [i for i, a in enumerate(recorded) if a == REDACTED]
        assert hidden == [position - 2, position - 1], recorded
        for index, entry in enumerate(recorded):
            if index not in hidden:
                assert entry == argv[index + 1], (index, recorded)


def test_a_value_held_whole_by_one_argument_keeps_its_per_argument_record(
    tmp_path, monkeypatch
):
    report, argv = _scan(
        tmp_path,
        monkeypatch,
        RULESET_WRITTEN_OUT,
        values_hook=lambda _self: (RULESET_WRITTEN_OUT,),
    )

    expected = [REDACTED if a == RULESET_WRITTEN_OUT else a for a in argv[1:]]
    assert expected.count(REDACTED) == 1, expected
    invocation, details = _recorded_invocations(report)
    assert invocation.arguments == expected, invocation.arguments
    assert details["arguments"] == expected, details["arguments"]


def _values_hook_lines(warning):
    """The warnings that say the command record was cut back because the
    values hook gave no usable answer."""
    return [
        call.args[0]
        for call in warning.call_args_list
        if call.args and "holds only the command name" in str(call.args[0])
    ]


@pytest.mark.parametrize(
    ("hook", "wording"),
    [
        (_raising_hook, "raised RuntimeError"),
        (_none_hook, "returned an unusable answer"),
        (_number_hook, "returned an unusable answer"),
    ],
    ids=["raises", "none", "not-a-value-set"],
)
def test_a_failed_values_hook_is_logged_once_without_naming_an_argument(
    tmp_path, monkeypatch, hook, wording
):
    with patch.object(ASH_LOGGER, "warning") as warning:
        report, argv = _scan(
            tmp_path, monkeypatch, RULESET_WRITTEN_OUT, values_hook=hook
        )

    lines = _values_hook_lines(warning)
    assert len(lines) == 1, warning.call_args_list
    assert wording in lines[0], lines[0]
    assert "SemgrepScanner" in lines[0], lines[0]
    assert RULESET_WRITTEN_OUT not in lines[0]
    assert "--config" not in lines[0]
    _assert_records_carry_only_the_command(report, argv)


@pytest.mark.parametrize(
    "hook",
    [lambda _self: (), lambda _self: (RULESET_WRITTEN_OUT,)],
    ids=["no-values", "values-hide-the-argument"],
)
def test_a_working_values_hook_logs_no_values_hook_line(tmp_path, monkeypatch, hook):
    with patch.object(ASH_LOGGER, "warning") as warning:
        _scan(tmp_path, monkeypatch, RULESET_WRITTEN_OUT, values_hook=hook)

    assert _values_hook_lines(warning) == [], warning.call_args_list


# Shapes where values redact in the joined text: spans that abut, overlap,
# chain, or repeat, and one row whose per-argument pass already hides
# everything, so the joined pass changes nothing. Each row is (arguments
# after the command, values, the exact entries expected to take part, in
# argument order). The trailing "--verbose" takes part in no redaction, so
# every mask holds at least one False and an all-hide answer fails the row.
SPAN_SHAPES = {
    "adjacent-entries-each-a-whole-value": (
        ["alpha-secret-one", "beta-secret-two", "--verbose"],
        ("alpha-secret-one", "beta-secret-two"),
        [False, False, False],
    ),
    "one-value-spanning-two-entries": (
        ["--tok", "alpha-secret-one", "--verbose"],
        ("--tok alpha-secret-one",),
        [True, True, False],
    ),
    "two-values-overlapping-on-the-middle-entry": (
        ["--tok", "alpha-secret-one", "other-secret-two", "--verbose"],
        ("--tok alpha-secret-one", "alpha-secret-one other-secret-two"),
        [True, True, True, False],
    ),
    "a-spanning-value-and-a-whole-value-apart": (
        ["--tok", "alpha-secret-one", "beta-secret-two", "--verbose"],
        ("--tok alpha-secret-one", "beta-secret-two"),
        [True, True, False, False],
    ),
    "chain-of-three-overlapping-values": (
        ["a1-secret", "b1-secret", "c1-secret", "d1-secret", "--verbose"],
        ("a1-secret b1-secret", "b1-secret c1-secret", "c1-secret d1-secret"),
        [True, True, True, True, False],
    ),
    "one-value-appearing-twice-with-a-gap": (
        [
            "beta-secret",
            "gamma-secret",
            "gap-word",
            "beta-secret",
            "gamma-secret",
            "--verbose",
        ],
        ("beta-secret gamma-secret",),
        [True, True, False, True, True, False],
    ),
    "one-value-spanning-three-entries": (
        ["alpha-secret", "beta-secret", "gamma-secret", "tail", "--verbose"],
        ("alpha-secret beta-secret gamma-secret",),
        [True, True, True, False, False],
    ),
    "one-value-repeating-over-overlapping-occurrences": (
        ["rep-secret", "rep-secret", "rep-secret", "--verbose"],
        ("rep-secret rep-secret",),
        [True, True, True, False],
    ),
}


@pytest.mark.parametrize("shape", sorted(SPAN_SHAPES))
def test_every_argument_taking_part_in_a_joined_redaction_is_hidden(shape):
    arguments, values, expected = SPAN_SHAPES[shape]
    per_argument = [text_without_values(a, values) for a in ["scanner", *arguments]]
    taking_part = _arguments_in_joined_redactions(per_argument, values)
    # Copies redacted_command_record's comprehension (scanner_plugin.py), so
    # drift between the recorded arguments and this probe is visible here.
    recorded = [
        REDACTED if hidden else text
        for text, hidden in zip(per_argument[1:], taking_part[1:])
    ]

    assert taking_part[1:] == expected, taking_part
    pieces = {piece for value in values for piece in value.split()}
    bare = [entry for entry in recorded if entry in pieces]
    assert bare == [], (recorded, bare)
    assert len(recorded) == len(arguments)


# Full argument vectors (command first) with the entries the joined text hides,
# the arguments recorded after the command, and the recorded command line.
RECORD_SHAPES = {
    "one-value-appearing-twice-with-a-gap": (
        [
            "scanner",
            "beta-secret",
            "gamma-secret",
            "gap-word",
            "beta-secret",
            "gamma-secret",
        ],
        ("beta-secret gamma-secret",),
        [False, True, True, False, True, True],
        [REDACTED, REDACTED, "gap-word", REDACTED, REDACTED],
        f"scanner {REDACTED} gap-word {REDACTED}",
    ),
    "one-value-spanning-three-entries": (
        ["scanner", "alpha-secret", "beta-secret", "gamma-secret", "tail"],
        ("alpha-secret beta-secret gamma-secret",),
        [False, True, True, True, False],
        [REDACTED, REDACTED, REDACTED, "tail"],
        f"scanner {REDACTED} tail",
    ),
    "one-value-repeating-over-overlapping-occurrences": (
        ["scanner", "rep-secret", "rep-secret", "rep-secret"],
        ("rep-secret rep-secret",),
        [False, True, True, True],
        [REDACTED, REDACTED, REDACTED],
        f"scanner {REDACTED}",
    ),
    "value-spanning-the-command-and-the-first-argument": (
        ["scan-head-secret", "--tok", "tail"],
        ("scan-head-secret --tok",),
        [True, True, False],
        [REDACTED, "tail"],
        f"{REDACTED} tail",
    ),
}


@pytest.mark.parametrize("shape", sorted(RECORD_SHAPES))
def test_the_record_hides_exactly_the_entries_inside_a_joined_redaction(shape):
    argv, values, expected_crossing, expected_arguments, expected_line = RECORD_SHAPES[
        shape
    ]
    per_argument = [text_without_values(a, values) for a in argv]
    command_line = text_without_values(shlex.join(per_argument), values)
    crossing = _arguments_in_joined_redactions(
        per_argument, values, redacted=command_line
    )
    recorded = [
        REDACTED if hidden else text
        for text, hidden in zip(per_argument[1:], crossing[1:])
    ]

    assert crossing == expected_crossing, crossing
    assert recorded == expected_arguments, recorded
    assert command_line == expected_line, command_line


@pytest.mark.parametrize("shape", sorted(RECORD_SHAPES))
def test_the_shared_record_helper_returns_the_same_line_and_arguments(shape):
    argv, values, _, expected_arguments, expected_line = RECORD_SHAPES[shape]

    command_line, arguments = redacted_command_record(argv, values)

    assert command_line == expected_line, command_line
    assert arguments == expected_arguments, arguments
