# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner's own failure records carry no value the config read from the environment.

A config option can come from the environment (``${VAR}``), and
``AshConfig._environment_values`` keeps what it read. Three records a scanner
makes of its own failure interpolate text that can carry such a value:

- the timeout record (``_record_timeout``) prints the ``scan_timeout`` limit,
  which can itself be ``${VAR}``-sourced;
- the template ``scan()`` raises a ScannerError naming the same limit;
- a failure while reading a run's result is logged with the exception's text
  and the raw stack trace, and stored as the response's error, which the
  executor and the results file keep.

A short number redacts only where the message quotes it whole
(``config_validator.MIN_REDACTED_LENGTH``), so the limit has to be printed as
its own quoted token: ``timed out after '60' s``, never ``after 60s``.
"""

import contextlib
import itertools
import logging
import os
import signal as signal_module
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.utils.log import ASH_LOGGER
from tests.unit.base.test_scanner_plugin_coverage import (
    _execute_writing,
    _populated_target,
    _scanner,
)

pytestmark = pytest.mark.unit

#: Long enough that redaction replaces it anywhere, so these cells measure the
#: sink, not the band a short value falls in.
SETTINGS_CANARY = "/nonexistent/ENVCANARY-77aa/settings.yaml"

#: A negative exit code is a signal death only on POSIX: elsewhere
#: subprocess_utils.signal_death answers None, and -9 is an ordinary code.
_POSIX_SIGNAL = pytest.mark.skipif(
    os.name != "posix", reason="a signal death is POSIX's case"
)


def _context(tmp_path, environment_values):
    source_dir = tmp_path / "source"
    source_dir.mkdir(exist_ok=True)
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    work_dir = output_dir / ASH_WORK_DIR_NAME
    work_dir.mkdir(exist_ok=True)
    context = PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=work_dir,
        config=AshConfig(project_name="test"),
    )
    context.config._environment_values = list(environment_values)
    return context


@pytest.fixture
def logged():
    lines = []

    class _Collect(logging.Handler):
        def emit(self, record):
            lines.append(logging.Formatter("%(message)s").format(record))

    handler = _Collect(level=logging.DEBUG)
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(logging.DEBUG)
    ASH_LOGGER.addHandler(handler)
    try:
        yield lines
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)


def _config_dumps(lines):
    """The pre-scan's two config dumps among the logged lines.

    The plugin log writes each message after a tab, and wraps it in an empty
    ``[none][/none]`` pair that keeps the console from reading the text as markup.
    The pair is not part of what a dump says, so it is taken out before the dump's
    own opening words are compared.
    """

    def body(line):
        return line.split("\t", 1)[-1].replace("[none][/none]", "")

    return [
        line for line in lines if body(line).startswith(("self.config: ", "config: "))
    ]


def test_timeout_record_carries_no_environment_value(tmp_path, logged):
    """The limit is a short number, so it has to be its own quoted token."""
    scanner = _scanner(_context(tmp_path, ["67"]))

    scanner._record_timeout({"timed_out": True}, 67)

    line = next(line for line in scanner.errors if "timed out after" in line)
    assert "scan_timeout" in line, line
    assert "67" not in line, line
    text = "\n".join(logged)
    assert "timed out after" in text, text
    assert "67" not in text, text


def test_template_timeout_error_carries_no_environment_value(tmp_path):
    """The ScannerError the template scan() raises names the limit too."""
    scanner = _scanner(_context(tmp_path, ["67"]), execute_scan=_execute_writing(None))
    scanner.config.options.scan_timeout = 67
    target = _populated_target(tmp_path)

    with (
        patch.object(
            type(scanner), "_run_subprocess", return_value={"timed_out": True}
        ),
        pytest.raises(ScannerError) as excinfo,
    ):
        scanner.scan(target=target, target_type="source")

    message = str(excinfo.value)
    assert "timed out after" in message, message
    assert "scanners.stub.options.scan_timeout" in message, message
    # The clause from "No stderr captured" on names the checked log's path,
    # which sits under pytest's own tmp directory; its run counter can hold
    # any digits, so the leak assert reads only the text before it.
    said = message.split("No stderr captured")[0]
    assert "67" not in said, message


@pytest.mark.parametrize("where", ["elsewhere", "under HOME"])
def test_post_run_handling_failure_carries_no_environment_value(
    tmp_path, logged, where
):
    """An exception while reading a run's result can name a configured value.

    It reaches three sinks: the full-details DEBUG line (whose raw stack trace
    repeats the message), the response's recorded error, and the ERROR line
    the post-run recorder logs. Under HOME too: a value there no longer
    matches once a line writes it with ~.
    """
    from pathlib import Path

    value = (
        SETTINGS_CANARY
        if where == "elsewhere"
        else (Path.home() / "ENVCANARY-77aa" / "settings.yaml").as_posix()
    )
    context = _context(tmp_path, [value])
    scanner = _scanner(context)
    scanner.use_uv_tool = False

    def _raise(_response):
        raise RuntimeError(f"could not parse {value}")

    with (
        patch.object(type(scanner), "_process_command_response", side_effect=_raise),
        patch(
            "automated_security_helper.utils.subprocess_utils"
            ".run_command_with_output_handling",
            return_value={"returncode": 0, "stdout": "", "stderr": ""},
        ),
    ):
        response = scanner._run_subprocess(
            ["stub-tool"], results_dir=context.output_dir
        )

    assert response.get("post_run_error") is True, response
    assert "could not parse" in response["error"], response["error"]
    assert "ENVCANARY-77aa" not in response["error"], response["error"]
    stored = scanner.scan_post_run_error
    assert "could not parse" in stored, stored
    assert "ENVCANARY-77aa" not in stored, stored
    text = "\n".join(logged)
    assert "Full error details" in text, text
    assert "could not record" in text, text
    assert "ENVCANARY-77aa" not in text, text


# A whole limit prints whole in the quoted token, '1000000', never '1e+06';
# a fraction as Python writes it. scan_timeout has no upper bound.

LIMITS = [
    pytest.param(1000000, "'1000000' s", id="large"),
    pytest.param(1000000.0, "'1000000' s", id="large-float"),
    pytest.param(7.5, "'7.5' s", id="fraction"),
]


@pytest.mark.parametrize("limit,token", LIMITS)
def test_the_timeout_record_prints_a_limit_whole(tmp_path, logged, limit, token):
    scanner = _scanner(_context(tmp_path, []))

    scanner._record_timeout({"timed_out": True}, limit)

    line = next(line for line in scanner.errors if "timed out after" in line)
    assert f"timed out after {token}" in line, line


# An environment value the model types to the limit ("067" loads as 67) would
# print in Python's spelling, which the redaction needle -- the text as the
# environment wrote it -- never matches. Every timeout message goes through
# the one shared limit token, which names the option there instead.
ENV_TYPED_LIMIT = "067"


def test_the_template_timeout_error_names_the_option_for_an_env_typed_limit(
    tmp_path,
):
    scanner = _scanner(
        _context(tmp_path, [ENV_TYPED_LIMIT]), execute_scan=_execute_writing(None)
    )
    scanner.config.options.scan_timeout = 67
    target = _populated_target(tmp_path)

    with (
        patch.object(
            type(scanner), "_run_subprocess", return_value={"timed_out": True}
        ),
        pytest.raises(ScannerError) as excinfo,
    ):
        scanner.scan(target=target, target_type="source")

    text = str(excinfo.value)
    assert "timed out after the configured scan_timeout" in text, text
    # As in the cell above: the clause from "No stderr captured" on names the
    # checked log's path under pytest's tmp directory, which can hold any digits.
    said = text.split("No stderr captured")[0]
    assert "67" not in said, text


def test_the_timeout_record_names_the_option_for_an_env_typed_limit(tmp_path, logged):
    scanner = _scanner(_context(tmp_path, [ENV_TYPED_LIMIT]))

    scanner._record_timeout({"timed_out": True}, 67)

    line = next(line for line in scanner.errors if "timed out after" in line)
    assert "timed out after the configured scan_timeout" in line, line
    assert "67" not in line, line


@pytest.mark.parametrize("limit,token", LIMITS)
def test_the_template_timeout_error_prints_a_limit_whole(tmp_path, limit, token):
    scanner = _scanner(_context(tmp_path, []), execute_scan=_execute_writing(None))
    scanner.config.options.scan_timeout = limit
    target = _populated_target(tmp_path)

    with (
        patch.object(
            type(scanner), "_run_subprocess", return_value={"timed_out": True}
        ),
        pytest.raises(ScannerError) as excinfo,
    ):
        scanner.scan(target=target, target_type="source")

    assert f"timed out after {token}" in str(excinfo.value), str(excinfo.value)


@pytest.mark.parametrize("limit,token", LIMITS)
def test_the_subprocess_timeout_text_prints_a_limit_whole(monkeypatch, limit, token):
    from automated_security_helper.utils import subprocess_utils

    monkeypatch.setattr(subprocess_utils, "_runner", lambda sandboxed: _times_out)

    result = subprocess_utils.run_command(["stub-tool", "--scan"], timeout=limit)

    assert f"Command timed out after {token}" in result.error, result.error


def test_the_subprocess_timeout_text_prints_the_shared_limit_token(monkeypatch):
    """The generic "Command timed out after" text prints its limit through the
    one formatter every timeout message uses (error_text.timeout_limit_token),
    so it cannot drift from the others: a stand-in token is what it shows. The
    cell above pins what that token prints."""
    from automated_security_helper.utils import error_text, subprocess_utils

    monkeypatch.setattr(
        error_text, "timeout_limit_token", lambda limit, values: "<the shared token>"
    )
    monkeypatch.setattr(subprocess_utils, "_runner", lambda sandboxed: _times_out)

    result = subprocess_utils.run_command(["stub-tool", "--scan"], timeout=67)

    assert "Command timed out after <the shared token>" in result.error, result.error


@pytest.mark.parametrize("limit,token", LIMITS)
def test_the_unfinished_run_reason_prints_a_limit_whole(limit, token):
    from automated_security_helper.core.phases.scanner_executor import (
        _unfinished_run_reason,
    )

    reason = _unfinished_run_reason(
        "stub", "source", ("timed_out", "the tool was stopped"), limit
    )

    assert f"timed out after {token}" in reason, reason


# What the handler appends to a response's error after it redacted it - a
# recorder that raised under guard, a stderr log it could not read - is
# redacted too.


def test_a_recorder_that_raises_adds_no_environment_value(tmp_path):
    context = _context(tmp_path, [SETTINGS_CANARY])
    scanner = _scanner(context)
    scanner.use_uv_tool = False

    def _raise(_response):
        raise RuntimeError("the response could not be read")

    def _recorder_raises(self, _response):
        raise RuntimeError(f"the recorder could not write {SETTINGS_CANARY}")

    with (
        patch.object(type(scanner), "_process_command_response", side_effect=_raise),
        patch.object(type(scanner), "_record_post_run_error", _recorder_raises),
        patch(
            "automated_security_helper.utils.subprocess_utils"
            ".run_command_with_output_handling",
            return_value={"returncode": 0, "stdout": "", "stderr": ""},
        ),
    ):
        response = scanner._run_subprocess(
            ["stub-tool"], results_dir=context.output_dir
        )

    # The control: the recorder's error was added to the response's.
    assert "the recorder could not write" in response["error"], response["error"]
    assert "ENVCANARY-77aa" not in response["error"], response["error"]


def test_an_unreadable_stderr_log_adds_no_environment_value(tmp_path):
    from automated_security_helper.utils.sandbox import fs_guard

    context = _context(tmp_path, [SETTINGS_CANARY])
    scanner = _scanner(context)
    post_run = {"error": "the response could not be read"}

    with patch.object(
        fs_guard,
        "read_bytes_at_most",
        side_effect=OSError(f"permission denied: {SETTINGS_CANARY}"),
    ):
        scanner._carry_stderr_log(
            post_run, tmp_path / "Tool.stderr.log", (SETTINGS_CANARY,)
        )

    # The control: the read's error was added.
    assert "its stderr log could not be read" in post_run["error"], post_run
    assert "ENVCANARY-77aa" not in post_run["error"], post_run


def test_the_read_bound_cannot_split_a_value_at_the_carried_texts_end(tmp_path):
    """The bounded read of the stderr log can land its cut inside a quoted
    env-read value, and the sinks that redact the carried text match whole
    spellings, so the split tail would survive them. The cut shrinks instead:
    a trailing piece that is a prefix of a value's spelling goes with the
    rest of the cut text. The value here straddles the read bound so the raw
    cut would keep its first six characters."""
    from automated_security_helper.base.plugin_base import _STDERR_LOG_READ_LIMIT

    value = "EDGESECRET-9912"
    context = _context(tmp_path, [value])
    scanner = _scanner(context)
    log = tmp_path / "Tool.stderr.log"
    log.write_text(
        "x" * (_STDERR_LOG_READ_LIMIT - 6) + value + " trailing text",
        encoding="utf-8",
    )
    post_run = {"error": "the response could not be read"}

    scanner._carry_stderr_log(post_run, log, (value,))

    carried = post_run["stderr"]
    assert carried.endswith(" ...[truncated]"), carried[-40:]
    kept = carried[: -len(" ...[truncated]")]
    assert not kept.endswith("EDGESE"), carried[-40:]
    assert "EDGESECRET" not in carried, carried[-60:]


def test_a_value_with_a_space_is_still_trimmed_at_the_read_bound(tmp_path):
    """The trim's forms are uv's printable spellings, which strip spaces, so
    a value WITH a space never matched the tail the cut left of it and its
    fragment survived the read bound. The raw value joins the forms: the
    prefix test sees the value as the log holds it."""
    from automated_security_helper.base.plugin_base import _STDERR_LOG_READ_LIMIT

    value = "EDGE SECRET-9912"
    context = _context(tmp_path, [value])
    scanner = _scanner(context)
    log = tmp_path / "Tool.stderr.log"
    log.write_text(
        "x" * (_STDERR_LOG_READ_LIMIT - 7) + value + " trailing text",
        encoding="utf-8",
    )
    post_run = {"error": "the response could not be read"}

    scanner._carry_stderr_log(post_run, log, (value,))

    carried = post_run["stderr"]
    assert carried.endswith(" ...[truncated]"), carried[-40:]
    # No 4-character piece either: without the raw form the trim still
    # dropped one character (the last "E" matched a form's first), so a cell
    # rejecting only the exact "EDGE SE" passed at that parent. The whole
    # fragment has to be gone.
    assert "EDGE" not in carried[-40:], carried[-40:]


def test_a_color_code_inside_the_fragment_does_not_defeat_the_trim(tmp_path):
    """A tool can wrap part of a value in a color code, and a raw prefix test
    never matches a fragment the code splits ("EDG<code>ESECR"). The sinks
    strip the codes before matching, so the split halves would print around
    the code. The tail is matched with codes removed, and the raw span is
    trimmed."""
    from automated_security_helper.base.plugin_base import _STDERR_LOG_READ_LIMIT

    value = "EDGESECRET-4417"
    context = _context(tmp_path, [value])
    scanner = _scanner(context)
    log = tmp_path / "Tool.stderr.log"
    # 3 + 4 + 5 characters put the read bound right after "ESECR", so the
    # kept tail is "EDG\x1b[1mESECR": plain "EDGESECR", a proper prefix of
    # the value, with the code inside it.
    log.write_text(
        "x" * (_STDERR_LOG_READ_LIMIT - 12) + "EDG\x1b[1mESECR" + "ET-4417 trailing",
        encoding="utf-8",
    )
    post_run = {"error": "the response could not be read"}

    scanner._carry_stderr_log(post_run, log, (value,))

    carried = post_run["stderr"]
    assert carried.endswith(" ...[truncated]"), carried[-40:]
    assert "ESECR" not in carried[-60:], repr(carried[-60:])
    assert "EDG" not in carried[-40:], repr(carried[-40:])


def test_a_trailing_non_color_escape_does_not_defeat_the_trim(tmp_path):
    """The read bound can land right after a complete NON-color code such as
    erase-line ("\\x1b[K"), which neither the color strip nor the sinks
    remove. The trailing strip takes any complete or cut-off escape, so the
    value fragment behind it is still seen and trimmed."""
    from automated_security_helper.base.plugin_base import _STDERR_LOG_READ_LIMIT

    value = "EDGESECRET-4417"
    context = _context(tmp_path, [value])
    scanner = _scanner(context)
    log = tmp_path / "Tool.stderr.log"
    log.write_text(
        "x" * (_STDERR_LOG_READ_LIMIT - 10) + "EDGESEC\x1b[K" + "RET-4417 trailing",
        encoding="utf-8",
    )
    post_run = {"error": "the response could not be read"}

    scanner._carry_stderr_log(post_run, log, (value,))

    carried = post_run["stderr"]
    assert carried.endswith(" ...[truncated]"), carried[-40:]
    assert "EDGESEC" not in carried[-60:], repr(carried[-60:])


def test_a_private_mode_code_inside_the_fragment_does_not_defeat_the_trim(tmp_path):
    """The trim and the sinks must read the SAME escape set. The sinks strip
    private-mode CSI codes ("\\x1b[?25l"), so a fragment split around one
    prints re-joined unless the trim's walk skips it too: with the cut right
    after "EDGE<code>SE", a walk blind to "?" finds only "E" as a prefix and
    leaves "EDGE<code>S", which the sink shows as "EDGES"."""
    from automated_security_helper.base.plugin_base import _STDERR_LOG_READ_LIMIT

    value = "EDGESECRET-4417"
    context = _context(tmp_path, [value])
    scanner = _scanner(context)
    log = tmp_path / "Tool.stderr.log"
    log.write_text(
        "x" * (_STDERR_LOG_READ_LIMIT - 12) + "EDGE\x1b[?25lSE" + "CRET-4417 more",
        encoding="utf-8",
    )
    post_run = {"error": "the response could not be read"}

    scanner._carry_stderr_log(post_run, log, (value,))

    carried = post_run["stderr"]
    assert carried.endswith(" ...[truncated]"), carried[-40:]
    assert "EDGE" not in carried[-40:], repr(carried[-40:])


def test_a_trailing_private_mode_code_does_not_defeat_the_trim(tmp_path):
    """The read bound can land right after a private-mode code the sinks
    strip ("\\x1b[?25l"). A trailing strip blind to "?" neither takes the
    code nor sees the value fragment behind it, so the fragment prints whole
    once the sink removes the code."""
    from automated_security_helper.base.plugin_base import _STDERR_LOG_READ_LIMIT

    value = "EDGESECRET-4417"
    context = _context(tmp_path, [value])
    scanner = _scanner(context)
    log = tmp_path / "Tool.stderr.log"
    log.write_text(
        "x" * (_STDERR_LOG_READ_LIMIT - 12) + "EDGESE\x1b[?25l" + "CRET-4417 more",
        encoding="utf-8",
    )
    post_run = {"error": "the response could not be read"}

    scanner._carry_stderr_log(post_run, log, (value,))

    carried = post_run["stderr"]
    assert carried.endswith(" ...[truncated]"), carried[-40:]
    assert "EDGESE" not in carried[-60:], repr(carried[-60:])


def test_a_colon_form_color_code_inside_a_value_is_still_hidden():
    """CSI parameter bytes are 0x30-0x3F per ECMA-48, colon included: a
    colon-form SGR ("\\x1b[38:5:196m") inside a value splits the match on a
    strip that only reads digits, semicolons and "?", and the value prints
    around the code."""
    from automated_security_helper.utils.error_text import shown_tool_stderr

    value = "EDGESECRET-9912"
    shown = shown_tool_stderr(
        "npm saw EDGE\x1b[38:5:196mSECRET-9912 in its config", (value,)
    )

    assert value not in shown, shown
    assert "EDGE" not in shown, shown
    assert "\x1b" not in shown, shown


@pytest.mark.parametrize(
    ("value", "printed", "cut_at"),
    [
        # The sinks match in any case: a validator upper-cases its message.
        ("edgesecret-4417", "EDGESECRET-4417", 6),
        # A value with a backslash is written JSON-escaped in a tool's JSON
        # stderr: the backslash doubles, and the cut lands inside that form.
        ("Zq7Kx9Lm\\Pw4Nv", "Zq7Kx9Lm\\\\Pw4Nv", 11),
        # A value with ":" prints percent-encoded in a URL a library formats
        # into its error ("%3A").
        ("Zq7Kx9Lm:Pw4Nv", "Zq7Kx9Lm%3APw4Nv", 11),
    ],
    ids=["printed-upper-case", "printed-json-escaped", "printed-url-escaped"],
)
def test_a_cut_inside_a_printed_spelling_is_trimmed(tmp_path, value, printed, cut_at):
    """The sinks match every PRINTED spelling of a value (repr body, JSON,
    URL-quoted; config_validator.printed_forms) in any case; a trim that
    tested only the as-written and uv-respelled forms left a piece of a
    printed spelling at the cut, which the sinks cannot match."""
    from automated_security_helper.base.plugin_base import _STDERR_LOG_READ_LIMIT

    context = _context(tmp_path, [value])
    scanner = _scanner(context)
    log = tmp_path / "Tool.stderr.log"
    head = printed[:cut_at]
    log.write_text(
        "x" * (_STDERR_LOG_READ_LIMIT - len(head)) + head + printed[cut_at:],
        encoding="utf-8",
    )
    post_run = {"error": "the response could not be read"}

    scanner._carry_stderr_log(post_run, log, (value,))

    carried = post_run["stderr"]
    assert carried.endswith(" ...[truncated]"), carried[-40:]
    assert head[:6] not in carried[-60:], repr(carried[-60:])


def test_a_cut_inside_a_respelled_form_is_trimmed(tmp_path):
    """The trim's forms include each uv respelling of a value
    (_spelled_forms): an env-read "9.9.9-RC777" prints as "9.9.9rc777", and
    a cut inside THAT form leaves a piece neither the as-written match nor
    the sinks can hide."""
    from automated_security_helper.base.plugin_base import _STDERR_LOG_READ_LIMIT

    value = "9.9.9-RC777"
    context = _context(tmp_path, [value])
    scanner = _scanner(context)
    log = tmp_path / "Tool.stderr.log"
    head = "resolver pinned 9.9.9rc7"
    log.write_text(
        "x" * (_STDERR_LOG_READ_LIMIT - len(head)) + head + "77 and failed",
        encoding="utf-8",
    )
    post_run = {"error": "the response could not be read"}

    scanner._carry_stderr_log(post_run, log, (value,))

    carried = post_run["stderr"]
    assert carried.endswith(" ...[truncated]"), carried[-40:]
    assert "9.9.9" not in carried[-60:], repr(carried[-60:])


def test_a_color_code_before_each_character_stays_inside_the_window(tmp_path):
    """The plain-tail window is counted in PLAIN characters: with a 24-bit
    color code before every character (rainbow-style output), a raw-counted
    window started inside the codes and the fragment's start sat out of
    reach, so the tail never ended in a form prefix."""
    from automated_security_helper.base.plugin_base import _STDERR_LOG_READ_LIMIT

    value = "Zq7Kx9Lm2Pw4Nv"
    colored = "".join(f"\x1b[38;2;255;100;0m{ch}" for ch in value[:12])
    context = _context(tmp_path, [value])
    scanner = _scanner(context)
    log = tmp_path / "Tool.stderr.log"
    log.write_text(
        "x" * (_STDERR_LOG_READ_LIMIT - len(colored)) + colored + value[12:],
        encoding="utf-8",
    )
    post_run = {"error": "the response could not be read"}

    scanner._carry_stderr_log(post_run, log, (value,))

    carried = post_run["stderr"]
    assert carried.endswith(" ...[truncated]"), carried[-40:]
    # The carried text keeps the codes, so the fragment's characters are
    # never contiguous THERE: the leak shows once a sink strips the codes
    # and re-joins them. Assert on what the sink prints.
    from automated_security_helper.utils.error_text import shown_tool_stderr

    shown = shown_tool_stderr(carried, (value,))
    assert "Zq7K" not in shown[-400:], repr(shown[-120:])


def test_a_cut_after_a_glued_extras_value_is_trimmed_with_the_inputs(tmp_path):
    """For a uv run the shower hides the run's plugin-built inputs WHOLE, so
    a cut just after a glued extra's value leaves "bandit[sarifqz4b": the
    value is whole (not a split piece), the 4-character band leaves it glued
    to letters, and the input arm cannot match the cut input. The trim takes
    the run's inputs and drops a tail that is a proper prefix of an input's
    spelling."""
    from automated_security_helper.base.plugin_base import trimmed_at_read_edge

    text = "x" * 200 + "you require bandit[sarifqz4b"
    trimmed = trimmed_at_read_edge(text, ("qz4b",), inputs=("bandit[sarifqz4b]==1.0",))

    assert "sarifqz4b" not in trimmed, trimmed[-60:]
    assert "you require " in trimmed, trimmed[-60:]


def test_report_lines_hide_a_value_split_by_a_code_for_a_non_uv_tool(tmp_path):
    """The NEUTRAL report-line branch strips escape codes before matching
    (shown_tool_stderr): an SGR code inside a value otherwise splits the
    match and both halves print re-joined once a sink or terminal drops the
    code. This cell pins the neutral branch itself -- the uv branch has its
    own cells."""
    value = "EDGESECRET-7781"
    context = _context(tmp_path, [value])
    scanner = _scanner(context)
    assert not getattr(scanner, "use_uv_tool", False)

    scanner._process_command_response(
        {"stderr": "tool saw EDGE\x1b[1mSECRET-7781 here", "returncode": 1}
    )

    joined = " ".join(scanner.errors)
    assert "tool saw" in joined, scanner.errors
    assert "EDGE" not in joined, scanner.errors


def test_output_lines_hide_a_value_spanning_lines(tmp_path):
    """Tool stdout is recorded line by line (self.output), and the results
    keep those lines redacted one by one (ScannerExecutor's _tool_lines). A
    split BEFORE any redaction cuts a value that holds a line break, so
    neither recorded line matches it and both halves print in raw_results
    "output". The record redacts the whole text first, then splits."""
    value = "EDGESECRET-77aa\nTAILSECRET-77bb"
    context = _context(tmp_path, [value])
    scanner = _scanner(context)
    scanner.use_uv_tool = False

    scanner._process_command_response(
        {"stdout": f"tool saw {value} in its config\nand went on", "returncode": 0}
    )

    from automated_security_helper.core.phases.scanner_executor import _tool_lines
    from automated_security_helper.utils.error_text import config_environment_values

    recorded = _tool_lines(scanner.output, config_environment_values(context.config))
    for lines in (scanner.output, recorded):
        joined = " ".join(str(line) for line in lines)
        # The control: the tool's own words stay.
        assert "tool saw" in joined, lines
        assert "and went on" in joined, lines
        assert "EDGESECRET-77aa" not in joined, lines
        assert "TAILSECRET-77bb" not in joined, lines


def test_output_lines_hide_a_single_line_value_as_the_results_keep_them(tmp_path):
    """The control for the spanning cell, on the surface the results keep:
    a value on one line is hidden from raw_results "output" whether the
    record or the results layer hides it."""
    value = "EDGESECRET-77aa"
    context = _context(tmp_path, [value])
    scanner = _scanner(context)
    scanner.use_uv_tool = False

    scanner._process_command_response(
        {"stdout": f"tool saw {value} in its config", "returncode": 0}
    )

    from automated_security_helper.core.phases.scanner_executor import _tool_lines
    from automated_security_helper.utils.error_text import config_environment_values

    recorded = _tool_lines(scanner.output, config_environment_values(context.config))
    joined = " ".join(str(line) for line in recorded)
    assert "tool saw" in joined, recorded
    assert value not in joined, recorded


def test_a_raising_values_hook_loses_the_output_lines_not_the_run(
    tmp_path, monkeypatch
):
    """stdout is recorded redacted, so it needs the same guarded hook read as
    the report lines: without the values nothing can be redacted, and a
    raising hook loses the stdout lines (a value-free note takes their place)
    rather than recording them raw or failing the run."""
    context = _context(tmp_path, ["EDGESECRET-7781"])
    scanner = _scanner(context)

    def _raises(self):
        raise TypeError("hook drift")

    monkeypatch.setattr(type(scanner), "_values_to_redact", _raises)
    scanner._process_command_response(
        {"stdout": "tool saw EDGESECRET-7781 here", "returncode": 3}
    )

    joined = " ".join(scanner.output)
    assert "EDGESECRET-7781" not in joined, scanner.output
    assert "stdout not shown" in joined, scanner.output
    assert scanner.exit_code == 3


def test_a_raising_values_hook_loses_the_report_lines_not_the_run(
    tmp_path, monkeypatch
):
    """_values_to_redact is an overridable hook: without the values the
    report lines cannot be redacted, so a raise loses the lines (a
    value-free note takes their place) and never turns the response's own
    outcome into a post-run error."""
    context = _context(tmp_path, ["EDGESECRET-7781"])
    scanner = _scanner(context)

    def _raises(self):
        raise TypeError("hook drift")

    monkeypatch.setattr(type(scanner), "_values_to_redact", _raises)
    scanner._process_command_response(
        {"stderr": "tool saw EDGESECRET-7781 here", "returncode": 3}
    )

    joined = " ".join(scanner.errors)
    assert "EDGESECRET-7781" not in joined, scanner.errors
    assert "stderr not shown" in joined, scanner.errors
    assert scanner.exit_code == 3


def test_a_values_hook_answering_an_empty_set_keeps_the_lines(tmp_path, monkeypatch):
    """An empty iterable from the hook IS an answer: no values to hide, so the
    lines are recorded as the tool wrote them."""
    context = _context(tmp_path, [])
    scanner = _scanner(context)

    monkeypatch.setattr(type(scanner), "_values_to_redact", lambda self: [])
    scanner._process_command_response(
        {"stdout": "tool line one", "stderr": "tool err one", "returncode": 0}
    )

    out = " ".join(str(line) for line in scanner.output)
    err = " ".join(str(line) for line in scanner.errors)
    assert "tool line one" in out, scanner.output
    assert "tool err one" in err, scanner.errors
    assert "not shown" not in out + err, (scanner.output, scanner.errors)


def _mid_iteration_drift():
    """An iterable whose draining raises the one error the normalizer's own
    tuple() arm would swallow into an empty value set."""

    def entries():
        yield "EDGESECRET-7781"
        raise TypeError("hook drift mid-iteration")

    return entries()


@pytest.mark.parametrize(
    "answer",
    [
        pytest.param(lambda: None, id="none"),
        pytest.param(lambda: 67, id="non-iterable"),
        pytest.param(_mid_iteration_drift, id="raising-iterable"),
    ],
)
def test_a_values_hook_answering_no_set_withholds_the_lines(
    tmp_path, monkeypatch, answer
):
    """None, a non-iterable, or an iterable that raises mid-drain is the same
    broken answer as a raise: the normalizer reads each as an EMPTY value set,
    which here would be the license to record the lines in clear, so the
    guarded read takes the hook-raised arm and the value-free notes stand in
    for both streams."""
    context = _context(tmp_path, ["EDGESECRET-7781"])
    scanner = _scanner(context)

    monkeypatch.setattr(type(scanner), "_values_to_redact", lambda self: answer())
    scanner._process_command_response(
        {
            "stdout": "tool saw EDGESECRET-7781 here",
            "stderr": "err saw EDGESECRET-7781 too",
            "returncode": 3,
        }
    )

    out = " ".join(str(line) for line in scanner.output)
    err = " ".join(str(line) for line in scanner.errors)
    assert "EDGESECRET-7781" not in out + err, (scanner.output, scanner.errors)
    assert "stdout not shown" in out, scanner.output
    assert "stderr not shown" in err, scanner.errors
    assert scanner.exit_code == 3


def test_a_values_hook_returning_a_bare_string_hides_that_whole_value(
    tmp_path, monkeypatch
):
    """A bare str from the hook is ONE value, never its characters
    (environment_strings' rule): tuple() of it is its characters, each below
    the shortest band the redaction replaces, so the whole value printed in
    the recorded lines."""
    value = "EDGESECRET-7781"
    context = _context(tmp_path, [value])
    scanner = _scanner(context)

    monkeypatch.setattr(type(scanner), "_values_to_redact", lambda self: value)
    scanner._process_command_response(
        {
            "stdout": f"tool saw {value} here",
            "stderr": f"err saw {value} too",
            "returncode": 0,
        }
    )

    out = " ".join(str(line) for line in scanner.output)
    err = " ".join(str(line) for line in scanner.errors)
    assert "tool saw" in out, scanner.output
    assert "err saw" in err, scanner.errors
    assert value not in out, scanner.output
    assert value not in err, scanner.errors


def test_a_complete_code_longer_than_the_junk_window_is_still_stripped(tmp_path):
    """The junk loop searches a 128-character window at the end, so a single
    complete code longer than the window straddles it and the windowed
    search never sees the code's start: the code stays, and the value
    fragment behind it sits out of the walk's reach. The rfind fallback
    strips it, and the fragment with it."""
    from automated_security_helper.base.plugin_base import _STDERR_LOG_READ_LIMIT

    value = "EDGESECRET-4417"
    long_code = "\x1b[" + "0;" * 100 + "0m"
    context = _context(tmp_path, [value])
    scanner = _scanner(context)
    log = tmp_path / "Tool.stderr.log"
    kept = 6 + len(long_code)
    log.write_text(
        "x" * (_STDERR_LOG_READ_LIMIT - kept) + "EDGESE" + long_code + "CRET-4417",
        encoding="utf-8",
    )
    post_run = {"error": "the response could not be read"}

    scanner._carry_stderr_log(post_run, log, (value,))

    carried = post_run["stderr"]
    assert carried.endswith(" ...[truncated]"), carried[-40:]
    assert "EDGESE" not in carried[-60:], repr(carried[-60:])
    assert "\x1b" not in carried[-(len(long_code) + 60) :], repr(carried[-60:])


def test_a_cut_inside_a_code_longer_than_the_junk_window_is_still_stripped(
    tmp_path,
):
    """The read bound can land INSIDE a code longer than the junk window.
    The windowed search sees only parameter bytes with no ESC, so nothing
    matched and the fragment behind the cut-off code survived the trim."""
    from automated_security_helper.base.plugin_base import _STDERR_LOG_READ_LIMIT

    value = "EDGESECRET-4417"
    cut_code = "\x1b[" + "0;" * 100  # cut before any final byte
    context = _context(tmp_path, [value])
    scanner = _scanner(context)
    log = tmp_path / "Tool.stderr.log"
    kept = 6 + len(cut_code)
    log.write_text(
        "x" * (_STDERR_LOG_READ_LIMIT - kept) + "EDGESE" + cut_code + "0mCRET-4417",
        encoding="utf-8",
    )
    post_run = {"error": "the response could not be read"}

    scanner._carry_stderr_log(post_run, log, (value,))

    carried = post_run["stderr"]
    assert carried.endswith(" ...[truncated]"), carried[-40:]
    # The window is wider than the cut code: a fragment the trim left
    # BEHIND an unstripped code must not read as absent only because the
    # assertion's window ends before it.
    tail = carried[-(len(cut_code) + 80) :]
    assert "EDGESE" not in tail, repr(tail[:80])


def test_a_cut_inside_a_truecolor_code_is_inside_the_junk_window(tmp_path):
    """A 24-bit color code ("\\x1b[38;2;255;100;0m") is 19 characters, and
    the read bound can land anywhere inside it: the cut code and the
    fragment behind it must go. The anchored rfind fallback catches a code
    the window cannot hold, so a window shrunk below 19 characters is
    closed there rather than by this cell: it pins the behavior for the
    longest common code, not the window constant itself."""
    from automated_security_helper.base.plugin_base import _STDERR_LOG_READ_LIMIT

    value = "EDGESECRET-4417"
    cut_code = "\x1b[38;2;255;100;0"  # cut before the final "m"
    context = _context(tmp_path, [value])
    scanner = _scanner(context)
    log = tmp_path / "Tool.stderr.log"
    kept = 6 + len(cut_code)
    log.write_text(
        "x" * (_STDERR_LOG_READ_LIMIT - kept) + "EDGESE" + cut_code + "mCRET-4417",
        encoding="utf-8",
    )
    post_run = {"error": "the response could not be read"}

    scanner._carry_stderr_log(post_run, log, (value,))

    carried = post_run["stderr"]
    assert carried.endswith(" ...[truncated]"), carried[-40:]
    assert "EDGESE" not in carried[-60:], repr(carried[-60:])


def test_a_cut_osc_hyperlink_at_the_read_edge_does_not_defeat_the_trim(tmp_path):
    """A terminal hyperlink is OSC ("\\x1b]8;;https://host\\x1b\\\\"), not
    CSI, and the read bound can land inside one: a trim whose incomplete
    branch reads only cut CSI neither takes the cut-off OSC nor sees the
    value fragment behind it."""
    from automated_security_helper.base.plugin_base import _STDERR_LOG_READ_LIMIT

    value = "EDGESECRET-4417"
    cut_osc = "\x1b]8;;https://exa"  # cut before the terminator
    context = _context(tmp_path, [value])
    scanner = _scanner(context)
    log = tmp_path / "Tool.stderr.log"
    kept = 6 + len(cut_osc)
    log.write_text(
        "x" * (_STDERR_LOG_READ_LIMIT - kept)
        + "EDGESE"
        + cut_osc
        + "mple\x1b\\CRET-4417",
        encoding="utf-8",
    )
    post_run = {"error": "the response could not be read"}

    scanner._carry_stderr_log(post_run, log, (value,))

    carried = post_run["stderr"]
    assert carried.endswith(" ...[truncated]"), carried[-40:]
    assert "EDGESE" not in carried[-60:], repr(carried[-60:])


def test_an_osc_hyperlink_inside_a_value_is_still_hidden():
    """OSC is not CSI: a strip that reads only the CSI set leaves a
    hyperlink inside a value, splitting the contiguous match, and a sink or
    terminal that drops or obeys the code shows the value whole."""
    from automated_security_helper.utils.error_text import shown_tool_stderr

    value = "EDGESECRET-9912"
    shown = shown_tool_stderr(
        "npm saw EDGE\x1b]8;;https://example.com\x1b\\SECRET-9912 in its config",
        (value,),
    )

    assert value not in shown, shown
    assert "EDGE" not in shown, shown
    assert "\x1b" not in shown, shown


def test_report_lines_hide_a_pinning_spec_without_a_carried_attribute(
    tmp_path, monkeypatch
):
    """The report lines compute the uv run's inputs from the plugin's own
    hooks when use_uv_tool is set: a direct _process_command_response call,
    with no dispatch wrapper around it, still hides a spec that pins a short
    env-read value. State carried on the instance and set around the call
    let two concurrent responses erase each other's inputs mid-call;
    computed inputs cannot."""
    pin = "1.8"
    context = _context(tmp_path, [pin])
    scanner = _scanner(context)
    scanner.use_uv_tool = True
    monkeypatch.setattr(
        type(scanner), "_uv_from_spec", lambda self: f"bandit=={pin}", raising=False
    )

    scanner._process_command_response(
        {"stderr": f"error: you require bandit=={pin}", "returncode": 1}
    )

    joined = " ".join(scanner.errors)
    assert "you require" in joined, scanner.errors
    assert f"bandit=={pin}" not in joined, scanner.errors


def test_report_lines_hide_with_dependencies_built_by_the_real_hooks(
    tmp_path, monkeypatch
):
    """The run's input set comes from _uv_run_inputs reading the plugin's
    OWN hooks -- the --with entries included. This cell sets the hooks and
    lets the real builder assemble the set (no stub of
    _uv_run_inputs_for_records), so dropping the --with half of the builder
    turns it red: uv's resolver quotes a --with entry back, pinned
    ("bandit==1.8") or glued ("tomlqz4b==1.0"), and both are hidden on the
    report lines while the resolver's own words stay."""
    context = _context(tmp_path, ["1.8", "qz4b"])
    scanner = _scanner(context)
    scanner.use_uv_tool = True
    monkeypatch.setattr(
        type(scanner),
        "_get_tool_version_constraint",
        lambda self: "==2.0",
        raising=False,
    )
    monkeypatch.setattr(
        type(scanner), "_get_tool_package_extras", lambda self: None, raising=False
    )
    monkeypatch.setattr(
        type(scanner),
        "_get_tool_with_dependencies",
        lambda self: ["bandit==1.8", "tomlqz4b==1.0"],
        raising=False,
    )

    scanner._process_command_response(
        {
            "stderr": (
                "error: because bandit==1.8 conflicts with tomlqz4b==1.0, "
                "resolution failed"
            ),
            "returncode": 1,
        }
    )

    joined = " ".join(scanner.errors)
    assert "resolution failed" in joined, scanner.errors
    assert "bandit==1.8" not in joined, scanner.errors
    assert "tomlqz4b" not in joined, scanner.errors
    assert "qz4b" not in joined, scanner.errors


def test_a_lone_trailing_escape_does_not_defeat_the_trim(tmp_path):
    """The read bound can land right after a bare ESC the tool was about to
    turn into a color code. The trailing strip takes the lone ESC too, so the
    value fragment behind it is still seen and trimmed."""
    from automated_security_helper.base.plugin_base import _STDERR_LOG_READ_LIMIT

    value = "EDGESECRET-4417"
    context = _context(tmp_path, [value])
    scanner = _scanner(context)
    log = tmp_path / "Tool.stderr.log"
    log.write_text(
        "x" * (_STDERR_LOG_READ_LIMIT - 8) + "EDGESEC\x1b" + "RET-4417 trailing",
        encoding="utf-8",
    )
    post_run = {"error": "the response could not be read"}

    scanner._carry_stderr_log(post_run, log, (value,))

    carried = post_run["stderr"]
    assert carried.endswith(" ...[truncated]"), carried[-40:]
    assert "EDGESEC" not in carried[-60:], repr(carried[-60:])


def test_a_cut_inside_a_multibyte_character_still_hides_the_value_prefix(tmp_path):
    """errors="replace" turns a cut-split multibyte character into a
    replacement character at the carried text's very end, and a prefix test
    that reads the raw tail never sees the value fragment sitting right
    behind it. The replacement characters (and a split color code) are
    stripped from the tail before the prefix test, so the fragment still
    goes with the cut. The value here holds a two-byte character placed so
    the read bound splits it right after the fragment."""
    from automated_security_helper.base.plugin_base import _STDERR_LOG_READ_LIMIT

    value = "EDGESE" + "é" + "CRET-9912"
    context = _context(tmp_path, [value])
    scanner = _scanner(context)
    log = tmp_path / "Tool.stderr.log"
    # The value's first six ascii characters end at byte LIMIT-1; the two-byte
    # character that follows is split by the bound, decoding to one
    # replacement character at the tail.
    log.write_bytes(
        b"x" * (_STDERR_LOG_READ_LIMIT - 7) + value.encode("utf-8") + b" trailing text"
    )
    post_run = {"error": "the response could not be read"}

    scanner._carry_stderr_log(post_run, log, (value,))

    carried = post_run["stderr"]
    assert carried.endswith(" ...[truncated]"), carried[-40:]
    kept = carried[: -len(" ...[truncated]")]
    assert not kept.endswith("EDGESE"), carried[-40:]
    assert "EDGESE" not in carried[-60:], carried[-60:]


@pytest.mark.parametrize("where", ["elsewhere", "under HOME", "windows path"])
def test_empty_results_warning_carries_no_environment_value(tmp_path, logged, where):
    """The empty-results WARNING repeats the tool's stderr, which can name one.

    The windows-path value holds backslashes, the spelling repr() doubles.

    A failure message carries what the run logged, so the outcome can be read
    from it: the warning was never logged (the run ended before it), it was
    logged without the tool's stderr, or the planted value is in a logged line
    (any line of the run, not only the warning). The empty results file is then
    refused as nothing to grade (ScannerError), and the refusal's own text
    carries no value either."""
    from pathlib import Path

    if where == "elsewhere":
        value = SETTINGS_CANARY
    elif where == "under HOME":
        value = (Path.home() / "ENVCANARY-under-home" / "settings.yaml").as_posix()
    else:
        value = "C:\\Users\\ENVCANARY-winpath\\settings.yaml"
    scanner = _scanner(_context(tmp_path, [value]), execute_scan=_execute_writing(""))
    target = _populated_target(tmp_path)
    scanner.errors = [f"cannot read {value}"]

    with (
        patch.object(type(scanner), "_run_subprocess", return_value={}),
        pytest.raises(ScannerError, match="nothing to grade") as refused,
    ):
        scanner.scan(target=target, target_type="source")

    warning_lines = [line for line in logged if "results file is empty" in line]
    record = f"logged_lines={len(logged)} warning_lines={warning_lines!r}"
    assert warning_lines, f"the warning was never logged; {record}"
    # The control: the tool's stderr is in the line.
    assert "cannot read" in warning_lines[0], record
    leaked = [line for line in logged if "ENVCANARY-" in line]
    assert not leaked, f"{record}; leaked lines: {leaked!r}"
    assert "results file is empty" in str(refused.value), str(refused.value)


# ---------------------------------------------------------------------------
# A number read from the environment, as a plugin's model types it
# ---------------------------------------------------------------------------
#
# A builtin scanner's section refuses a number read from the environment at
# load (its model is strict), so such a number reaches a line through a plugin
# module's section, which the plugin's own model types later, laxly: "067",
# "+67" and "67.0" all load as 67, and the timeout record prints '67'. The
# config records the number's canonical spelling beside the variable's text.

SPELLINGS = ["067", "+67", "67.0"]


def _loaded_with_limit(
    tmp_path, monkeypatch, spelling, section="plugin-tool"
) -> AshConfig:
    """A run's config whose plugin-module section reads its limit from the environment."""
    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )

    monkeypatch.setenv("ASH_SPELLED_LIMIT", spelling)
    profile = tmp_path / "spelled-limit.ash.yaml"
    profile.write_text(
        "project_name: spelled-limit\n"
        "scanners:\n"
        f"  {section}:\n"
        "    enabled: true\n"
        "    options:\n"
        "      scan_timeout: ${ASH_SPELLED_LIMIT}\n",
        encoding="utf-8",
    )
    return load_config_file_for_run(profile)[1]


@pytest.mark.parametrize("spelling", SPELLINGS)
def test_a_numbers_bare_spelling_is_not_recorded_as_a_needle(
    tmp_path, monkeypatch, spelling
):
    """The variable's own text is recorded; the bare number its typed form
    prints is not: a bare number identifies nothing, and hiding it anywhere
    corrupts text that contains it. The records that print the typed limit
    print it as written or as a quoted token, which the cells below pin, so
    the number needs no needle of its own."""
    from automated_security_helper.utils.error_text import config_environment_values

    recorded = config_environment_values(
        _loaded_with_limit(tmp_path, monkeypatch, spelling)
    )

    # The control: the variable's text, as the load recorded it before.
    assert spelling in recorded, recorded
    assert "67" not in recorded, recorded


@pytest.mark.parametrize(
    "text,spelling",
    [
        pytest.param("Infinity", "inf", id="infinity"),
        pytest.param("-Infinity", "-inf", id="minus-infinity"),
        pytest.param("+nan", "nan", id="plus-nan"),
        pytest.param("1e999", "inf", id="past-the-largest-float"),
    ],
)
def test_a_non_finite_number_is_recorded_as_a_float_prints_it(text, spelling):
    """A float option types a non-finite text as inf, -inf or nan, the form a
    line prints it in, which the variable's text no longer matches."""
    from automated_security_helper.config.config_validator import _typed_spellings

    assert spelling in _typed_spellings(text)


def test_a_non_finite_value_s_printed_spelling_is_redacted():
    """The printed spelling is redacted as any value is: a three-character one
    (inf, nan) where a line quotes it, as every value shorter than
    MIN_REDACTED_LENGTH is. "-inf" is four characters with a non-word
    character, the shape ordinarily replaced anywhere, but a float's word
    identifies nothing inside another word, so it is matched as a whole word
    (_NON_FINITE_FORMS): standing alone or quoted it is hidden, while
    "--info" and "non-inference" keep their text (the cut-or-cased cells pin
    that side; a finite value like "-0.0" takes the number bound instead,
    hidden inside words and left inside a longer number). Words that only
    hold a shorter spelling (info, inference, nanosecond) are left."""
    from automated_security_helper.config.config_validator import (
        _typed_spellings,
        redact_values,
    )

    infinity = ["Infinity", *_typed_spellings("Infinity")]
    negative = ["-Infinity", *_typed_spellings("-Infinity")]
    not_a_number = ["+nan", *_typed_spellings("+nan")]

    shown = redact_values("limit 'inf' reached", infinity)
    # The control: the line keeps its other words.
    assert "limit" in shown and "reached" in shown, shown
    assert "'inf'" not in shown, shown
    assert "-inf" not in redact_values("limit -inf reached", negative)
    assert "'nan'" not in redact_values("limit 'nan' reached", not_a_number)
    # Must not flag: words that only hold a spelling.
    for values in (infinity, not_a_number):
        line = "info: inference nanosecond"
        assert redact_values(line, values) == line, values


@pytest.mark.parametrize(
    "written, printed",
    [
        ("-1.50", "-1.5"),
        ("1e20", "1e+20"),
        ("0.00001", "1e-05"),
        ("1e308", "1e+308"),
        ("-067", "-67.0"),
        ("12345678901234567890123", "1.2345678901234568e+22"),
    ],
    ids=[
        "trailing-zero",
        "exponent",
        "small-exponent",
        "huge-exponent",
        "padded",
        "long-exponent-print",
    ],
)
def test_a_short_float_print_of_a_hidden_value_is_hidden_in_a_plugins_words(
    tmp_path, monkeypatch, written, printed
):
    """A float-typed option read from ``${X}`` can be named by the plugin's own
    exception, which prints the float's text, not the variable's. That text
    goes through error_text with the config's environment values, so the
    needles must hold the float print of every value the config hides: these
    values are MIN_REDACTED_LENGTH characters or longer and are themselves
    redacted unquoted, and a line that hides "1e20" while printing "1e+20"
    hides nothing. A bare unsigned number ("67.0") still joins nothing, and a
    value under MIN_REDACTED_LENGTH keeps the drop its own weak band gives
    it. A long exponent print ("1.2345678901234568e+22") is not an integer
    rendering, so it joins through this same hidden-value arm, not by
    length."""
    from automated_security_helper.utils.error_text import error_text

    config = _loaded_with_limit(tmp_path, monkeypatch, written)
    from automated_security_helper.utils.error_text import config_environment_values

    values = config_environment_values(config)
    # The control: the value as written is hidden.
    assert written in values, values

    line = error_text(
        ValueError(f"plugin-tool refused scan_timeout {printed}: out of range"),
        values,
    )
    assert printed not in line, (line, values)
    # The rest of the plugin's words survive.
    assert "out of range" in line, line


@pytest.mark.parametrize("spelling", SPELLINGS)
def test_a_typed_limit_is_redacted_from_the_timeout_record(
    tmp_path, monkeypatch, logged, spelling
):
    from tests.unit.base.test_scanner_plugin_coverage import StubConfig

    config = _loaded_with_limit(tmp_path, monkeypatch, spelling)
    context = _context(tmp_path, [])
    context.config = config
    scanner = _scanner(context)
    # The section as the plugin's own model types it.
    section = dict(config.scanners.model_extra["plugin-tool"])
    scanner.config = StubConfig.model_validate({**section, "name": "stub"})
    limit = scanner.config.options.scan_timeout
    # The control: the plugin's model read the spelling as the number.
    assert limit == 67, limit

    scanner._record_timeout({"timed_out": True}, limit)

    line = next(line for line in scanner.errors if "timed out after" in line)
    assert "scan_timeout" in line, line
    assert "67" not in line, line
    text = "\n".join(logged)
    assert "timed out after" in text, text
    assert "67" not in text, text


# ---------------------------------------------------------------------------
# The subprocess layer's own timeout text
# ---------------------------------------------------------------------------
#
# subprocess_utils words its own timeout (the result's error, a timed-out
# run's stderr), and that text reaches the plugin's errors and the row's
# reason, which are redacted with the config's values. A short limit is
# replaced only where it is quoted whole, so the limit is printed as the same
# quoted token the scanners print: "Command timed out after '67' s".


def _times_out(args, **kwargs):
    import subprocess

    raise subprocess.TimeoutExpired(args, kwargs.get("timeout"))


@pytest.mark.parametrize("limit", [67, 67.0])
def test_run_command_quotes_its_limit(monkeypatch, limit):
    from automated_security_helper.utils import subprocess_utils
    from automated_security_helper.utils.error_text import text_without_values

    monkeypatch.setattr(subprocess_utils, "_runner", lambda sandboxed: _times_out)

    result = subprocess_utils.run_command(["stub-tool", "--scan"], timeout=limit)

    assert getattr(result, "timed_out", False) is True, result
    for text in (result.error, result.stderr):
        assert "Command timed out after '67' s" in text, text
        assert "67" not in text_without_values(text, ["67"]), text


@pytest.mark.parametrize("limit", [67, 67.0])
def test_run_command_with_output_handling_quotes_its_limit(
    tmp_path, monkeypatch, limit
):
    from automated_security_helper.utils import subprocess_utils
    from automated_security_helper.utils.error_text import text_without_values

    monkeypatch.setattr(subprocess_utils, "_runner", lambda sandboxed: _times_out)

    response = subprocess_utils.run_command_with_output_handling(
        ["stub-tool", "--scan"], results_dir=tmp_path, class_name="Tool", timeout=limit
    )

    assert response.get("timed_out") is True, response
    assert "Command timed out after '67' s: stub-tool --scan" in response["error"]
    assert "67" not in text_without_values(response["error"], ["67"])


def test_a_scanners_timed_out_run_records_no_limit(tmp_path, monkeypatch):
    """Through the scanner: the limit its config read from the environment."""
    from automated_security_helper.utils import subprocess_utils

    monkeypatch.setattr(subprocess_utils, "_runner", lambda sandboxed: _times_out)
    context = _context(tmp_path, ["67"])
    scanner = _scanner(context)
    scanner.use_uv_tool = False

    # The limit as the template scan() passes its scan_timeout.
    response = scanner._run_subprocess(
        ["stub-tool", "--scan"], results_dir=context.output_dir, timeout=67
    )

    assert response.get("timed_out") is True, response
    # The errors as the results keep them (ScannerExecutor's _tool_lines).
    from automated_security_helper.core.phases.scanner_executor import _tool_lines
    from automated_security_helper.utils.error_text import config_environment_values

    recorded = "\n".join(
        _tool_lines(scanner.errors, config_environment_values(context.config))
    )
    # The control: the subprocess layer's text reached the errors.
    assert "Command timed out after" in recorded, recorded
    assert "67" not in recorded, recorded


# The subprocess layer logs its own timeout line (ERROR), beside the plugin's.
# No log handler redacts, so the runner is handed the scan config's values and
# prints the limit through the shared token with them: a value that types to
# the limit, "067" read as 67, names the option there, and the line is redacted
# with them. The errors the results keep are the same text.


def _timeout_lines(lines, tmp_path):
    """The lines that say a run timed out, with pytest's tmp directory taken out.

    Only these: other lines name the run's scratch directories, whose digits
    are their own, and these are the lines that print the limit."""
    return [
        line.replace(tmp_path.as_posix(), "<tmp>").replace(str(tmp_path), "<tmp>")
        for text in lines
        for line in text.splitlines()
        if "timed out" in line
    ]


def _assert_no_limit(logged, errors, config, tmp_path):
    from automated_security_helper.core.phases.scanner_executor import _tool_lines
    from automated_security_helper.utils.error_text import config_environment_values

    for lines in (
        _timeout_lines(logged, tmp_path),
        # The errors as the results keep them (ScannerExecutor's _tool_lines).
        _timeout_lines(
            _tool_lines(errors, config_environment_values(config)), tmp_path
        ),
    ):
        # The control: the subprocess layer's own text is among them.
        assert any("Command timed out after" in line for line in lines), (lines, logged)
        for line in lines:
            assert "67" not in line, line


@pytest.mark.parametrize("spelling", ["67", "067"])
def test_a_scanners_timed_out_run_logs_no_limit(
    tmp_path, monkeypatch, logged, spelling
):
    from automated_security_helper.utils import subprocess_utils

    monkeypatch.setattr(subprocess_utils, "_runner", lambda sandboxed: _times_out)
    monkeypatch.setattr(subprocess_utils, "find_executable", lambda name: None)
    context = _context(tmp_path, [spelling])
    scanner = _scanner(context)
    scanner.use_uv_tool = False

    response = scanner._run_subprocess(
        ["stub-tool", "--scan"], results_dir=context.output_dir, timeout=67
    )

    assert response.get("timed_out") is True, response
    _assert_no_limit(logged, scanner.errors, context.config, tmp_path)


@pytest.mark.parametrize("handled", [True, False], ids=["with-output", "plain"])
def test_a_timed_out_run_logs_no_value_its_command_carries(
    tmp_path, monkeypatch, logged, handled
):
    """The runner's timeout line names the command, which can carry a value the
    config read from the environment (an option's path, say): the line is
    redacted with the values the caller hands it, in both runners. A scanner's
    run hands them to run_command_with_output_handling; run_command is a
    public helper a plugin can call with its own."""
    from automated_security_helper.utils import subprocess_utils

    monkeypatch.setattr(subprocess_utils, "_runner", lambda sandboxed: _times_out)
    monkeypatch.setattr(subprocess_utils, "find_executable", lambda name: None)
    command = ["stub-tool", "--config", SETTINGS_CANARY]

    if handled:
        subprocess_utils.run_command_with_output_handling(
            command, results_dir=tmp_path, timeout=67, values=[SETTINGS_CANARY]
        )
    else:
        subprocess_utils.run_command(command, timeout=67, values=[SETTINGS_CANARY])

    lines = _timeout_lines(logged, tmp_path)
    # The control: the timeout line names the command.
    assert any(
        "Command timed out after" in line and "--config" in line for line in lines
    ), lines
    # Every line the run logged, not only the timeout line: the line that
    # names the command before it runs ("Running command:", "Running:") holds
    # it too.
    assert any("Running" in line and "--config" in line for line in logged), logged
    for line in logged:
        assert "ENVCANARY-77aa" not in line, line


@pytest.mark.parametrize("handled", [True, False], ids=["with-output", "plain"])
def test_the_runner_s_own_timeout_line_names_the_option_for_an_env_typed_limit(
    tmp_path, monkeypatch, logged, handled
):
    """Each runner's own ERROR line and the error it returns, handed a value
    that types to the limit ("067" loads as 67): both name the option and
    print no number, as the uv runner's text does."""
    from automated_security_helper.utils import subprocess_utils

    monkeypatch.setattr(subprocess_utils, "_runner", lambda sandboxed: _times_out)
    monkeypatch.setattr(subprocess_utils, "find_executable", lambda name: None)

    if handled:
        response = subprocess_utils.run_command_with_output_handling(
            ["stub-tool", "--scan"],
            results_dir=tmp_path,
            timeout=67,
            values=[ENV_TYPED_LIMIT],
        )
        timed_out, error = response.get("timed_out"), response.get("error")
    else:
        result = subprocess_utils.run_command(
            ["stub-tool", "--scan"], timeout=67, values=[ENV_TYPED_LIMIT]
        )
        timed_out, error = result.timed_out, result.error

    lines = _timeout_lines(logged, tmp_path)
    assert any(
        "Command timed out after the configured scan_timeout" in line for line in lines
    ), lines
    for line in lines:
        assert "67" not in line, line
    assert timed_out is True, timed_out
    assert "the configured scan_timeout" in str(error), error
    assert "67" not in str(error), error


def test_run_command_s_timed_out_stderr_names_the_option_for_an_env_typed_limit(
    monkeypatch,
):
    """A child that wrote nothing before the timeout leaves run_command's own
    text as the result's stderr, and that text prints the limit as the error
    does: the option, for a value that types to it, never the number."""
    from automated_security_helper.utils import subprocess_utils

    monkeypatch.setattr(subprocess_utils, "_runner", lambda sandboxed: _times_out)
    monkeypatch.setattr(subprocess_utils, "find_executable", lambda name: None)

    result = subprocess_utils.run_command(
        ["stub-tool", "--scan"], timeout=67, values=[ENV_TYPED_LIMIT]
    )

    assert result.stderr == ("Command timed out after the configured scan_timeout"), (
        result.stderr
    )


def test_run_tool_hands_its_values_to_the_runner_with_a_results_dir(
    tmp_path, monkeypatch
):
    """run_tool with a results directory, the branch every scanner takes, hands
    run_command_with_output_handling the values it was given, as a tuple. The
    other branch prints the limit itself (the env-typed cell above for it)."""
    from automated_security_helper.utils import subprocess_utils

    seen = []

    def _recording(*args, **kwargs):
        seen.append(kwargs.get("values"))
        return {"returncode": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(
        subprocess_utils, "run_command_with_output_handling", _recording
    )

    _uv_runner().run_tool(
        "stub-tool",
        args=["--scan"],
        results_dir=tmp_path,
        values=[SETTINGS_CANARY, ENV_TYPED_LIMIT],
    )

    assert seen == [(SETTINGS_CANARY, ENV_TYPED_LIMIT)], seen


def _failing_runner(mode):
    """A runner whose child ends ``mode``'s way, its stderr quoting the value."""
    import subprocess

    def run(args, **kwargs):
        if mode == "never-starts":
            raise OSError(2, "No such file or directory")
        if mode == "check-raises":
            raise subprocess.CalledProcessError(
                2, args, output="", stderr=f"cannot read {SETTINGS_CANARY}"
            )
        return subprocess.CompletedProcess(
            args,
            {"nonzero": 2, "signal": -9, "post-run": 0}[mode],
            stdout="",
            stderr=f"cannot read {SETTINGS_CANARY}",
        )

    return run


@pytest.mark.parametrize(
    "mode,expected",
    [
        pytest.param("nonzero", "Command stderr:", id="nonzero"),
        pytest.param(
            "check-raises",
            "Command failed with return code 2: stub-tool",
            id="check-raises",
        ),
        pytest.param(
            "signal", "a signal ASH did not send", id="signal", marks=_POSIX_SIGNAL
        ),
        pytest.param(
            "post-run", "ASH could not record the output of stub-tool", id="post-run"
        ),
        pytest.param("never-starts", "Could not start stub-tool", id="never-starts"),
    ],
)
@pytest.mark.parametrize("given", ["list", "generator"])
def test_run_command_s_own_lines_carry_no_value_its_caller_hands_it(
    monkeypatch, mode, expected, given
):
    """run_command is a public helper a plugin can import and call with values
    of its own. Every line it logs itself, at any level, is redacted with them:
    the command it is about to run, the failed exit, the signal that ended the
    child, ASH's own failure after the run, the command that never started,
    and the child's stderr at DEBUG. What it returns stays as it is. The
    values can come as any iterable, a generator included, which every line
    is redacted with, not only the first."""
    import subprocess

    from automated_security_helper.utils import subprocess_utils

    monkeypatch.setattr(
        subprocess_utils, "_runner", lambda sandboxed: _failing_runner(mode)
    )
    monkeypatch.setattr(subprocess_utils, "find_executable", lambda name: None)
    if mode == "post-run":
        # ASH fails once after the tool exited, while reading the result.
        real = subprocess_utils.signal_death
        failed = []

        def _fails_once(*args, **kwargs):
            if not failed:
                failed.append(True)
                raise RuntimeError("ASH failed after the run")
            return real(*args, **kwargs)

        monkeypatch.setattr(subprocess_utils, "signal_death", _fails_once)
    records = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    handler = _Collect(level=1)
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(1)
    ASH_LOGGER.addHandler(handler)
    values = (
        [SETTINGS_CANARY] if given == "list" else (value for value in [SETTINGS_CANARY])
    )
    try:
        command = ["stub-tool", "--config", SETTINGS_CANARY]
        if mode == "check-raises":
            # check=True re-raises once the lines are logged.
            with pytest.raises(subprocess.CalledProcessError):
                subprocess_utils.run_command(command, check=True, values=values)
        else:
            subprocess_utils.run_command(command, values=values)
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)

    # The controls: the runner logged the line this way of failing gives, as
    # well as the command it ran.
    assert any(expected in record for record in records), records
    assert any("--config" in record for record in records), records
    for record in records:
        assert "ENVCANARY-77aa" not in record, record


@pytest.mark.parametrize(
    "mode",
    [
        pytest.param("nonzero", id="scanner-nonzero"),
        pytest.param("signal", id="scanner-signal", marks=_POSIX_SIGNAL),
        pytest.param("post-run", id="scanner-post-run"),
        pytest.param("never-starts", id="scanner-never-starts"),
    ],
)
def test_a_run_s_own_lines_carry_no_value_its_command_or_stderr_carries(
    tmp_path, monkeypatch, mode
):
    """Every line the runner logs itself, at any level: the command it is
    about to run (VERBOSE), the signal that ended the child, ASH's own failure
    after the run, and the command that never started. Each can carry a value
    the config read from the environment (an option's path, in the command and
    in what the tool said about it), so each is redacted with the values a
    scanner's _run_subprocess hands run_command_with_output_handling."""
    from automated_security_helper.utils import subprocess_utils

    monkeypatch.setattr(
        subprocess_utils, "_runner", lambda sandboxed: _failing_runner(mode)
    )
    monkeypatch.setattr(subprocess_utils, "find_executable", lambda name: None)
    if mode == "post-run":
        # ASH fails once after the tool exited, while writing the stream logs.
        # Once, so the handler that reports it reads the result as it would.
        real = subprocess_utils._write_stream_log
        failed = []

        def _fails_once(*args, **kwargs):
            if not failed:
                failed.append(True)
                raise RuntimeError("ASH failed after the run")
            return real(*args, **kwargs)

        monkeypatch.setattr(subprocess_utils, "_write_stream_log", _fails_once)
    records = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    handler = _Collect(level=1)
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(1)
    ASH_LOGGER.addHandler(handler)
    try:
        command = ["stub-tool", "--config", SETTINGS_CANARY]
        context = _context(tmp_path, [SETTINGS_CANARY])
        scanner = _scanner(context)
        scanner.use_uv_tool = False
        scanner._run_subprocess(command, results_dir=context.output_dir)
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)

    # The controls: the runner logged the line this way of failing gives, as
    # well as the command it ran.
    expected = {
        "nonzero": "Running:",
        "signal": "a signal ASH did not send",
        "post-run": "ASH could not record the output of stub-tool",
        "never-starts": "Could not start stub-tool",
    }[mode]
    assert any(expected in record for record in records), records
    assert any("--config" in record for record in records), records
    for record in records:
        assert "ENVCANARY-77aa" not in record, record


class _ExitedChild:
    """A child that had already ended on SIGKILL when ASH's wait on it failed."""

    pid = 2**22 + 17
    returncode = -9
    stdout = None
    stderr = None

    def poll(self):
        return self.returncode


def _wait_fails_on_an_exited_child(args, **kwargs):
    """A runner that records its child, as every runner does right after Popen
    returns, and whose wait on it then raises."""
    from automated_security_helper.utils import subprocess_utils

    subprocess_utils._note_start(_ExitedChild())
    raise RuntimeError("reading its output failed")


@_POSIX_SIGNAL
@pytest.mark.parametrize(
    "shape",
    [
        pytest.param("log-write", id="a-signaled-run-whose-stream-log-write-fails"),
        pytest.param("wait", id="a-failed-wait-on-a-child-that-ended-on-a-signal"),
    ],
)
def test_the_post_run_error_line_carries_no_value_its_command_carries(
    tmp_path, monkeypatch, shape
):
    """A tool that died on a signal before ASH's own failure: the error starts
    with "<command> ended on SIGKILL", and the command can carry a value the
    config read from the environment. The plugin's "ran, but ASH could not
    record its tool's output" line is redacted as its could-not-start line is.
    """
    from automated_security_helper.utils import subprocess_utils

    if shape == "log-write":
        monkeypatch.setattr(
            subprocess_utils, "_runner", lambda sandboxed: _failing_runner("signal")
        )

        def _fails(*args, **kwargs):
            raise RuntimeError("ASH failed after the run")

        monkeypatch.setattr(subprocess_utils, "_write_stream_log", _fails)
    else:
        monkeypatch.setattr(
            subprocess_utils,
            "_runner",
            lambda sandboxed: _wait_fails_on_an_exited_child,
        )
    monkeypatch.setattr(subprocess_utils, "find_executable", lambda name: None)
    context = _context(tmp_path, [SETTINGS_CANARY])
    scanner = _scanner(context)
    scanner.use_uv_tool = False
    records = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    handler = _Collect(level=1)
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(1)
    ASH_LOGGER.addHandler(handler)
    try:
        response = scanner._run_subprocess(
            ["stub-tool", "--config", SETTINGS_CANARY],
            results_dir=context.output_dir,
        )
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)

    # The controls: a post-run failure of a run that ended on SIGKILL, whose
    # error quotes the command, and the plugin's own line for it.
    assert response.get("post_run_error") is True, response
    assert "SIGKILL" in response["error"], response
    assert SETTINGS_CANARY in response["error"], response
    assert any(
        "ran, but ASH could not record its tool's output" in record
        for record in records
    ), records
    for record in records:
        assert "ENVCANARY-77aa" not in record, record


@_POSIX_SIGNAL
@pytest.mark.parametrize("runner", ["run_command", "run_command_with_output_handling"])
def test_a_failed_wait_on_a_started_child_is_a_post_run_error_at_each_runner(
    tmp_path, monkeypatch, runner
):
    """Both runners' handler for a wait that failed after the runner recorded
    its child: the child's own ending is kept (-9, signaled), the response is a
    post-run error, and each runner's line naming it is redacted with the
    values its caller hands it. What the response keeps stays as the runner
    gave it."""
    from automated_security_helper.utils import subprocess_utils

    monkeypatch.setattr(
        subprocess_utils, "_runner", lambda sandboxed: _wait_fails_on_an_exited_child
    )
    monkeypatch.setattr(subprocess_utils, "find_executable", lambda name: None)
    command = ["stub-tool", "--config", SETTINGS_CANARY]
    records = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    handler = _Collect(level=1)
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(1)
    ASH_LOGGER.addHandler(handler)
    try:
        if runner == "run_command":
            result = subprocess_utils.run_command(command, values=[SETTINGS_CANARY])
            returncode = result.returncode
            post_run = getattr(result, "post_run_error", False)
            signaled = getattr(result, "signaled", False)
            error = getattr(result, "error", "")
        else:
            response = subprocess_utils.run_command_with_output_handling(
                command, results_dir=tmp_path, values=[SETTINGS_CANARY]
            )
            returncode = response.get("returncode")
            post_run = response.get("post_run_error")
            signaled = response.get("signaled")
            error = response.get("error", "")
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)

    assert returncode == -9, (runner, returncode)
    assert post_run is True, runner
    assert signaled is True, runner
    assert "reading its output failed" in error, error
    lines = [r for r in records if "ASH could not record the output of" in r]
    assert lines, records
    for record in records:
        assert "ENVCANARY-77aa" not in record, record


def _hook_raises(self):
    raise RuntimeError("the plugin's values could not be read")


@pytest.mark.parametrize(
    "hook",
    [
        pytest.param(lambda self: (), id="returns-none"),
        pytest.param(_hook_raises, id="raises"),
    ],
)
@pytest.mark.parametrize(
    "mode,expected",
    [
        pytest.param("nonzero", "Running:", id="running"),
        pytest.param("never-starts", "Could not start stub-tool", id="never-starts"),
        pytest.param(
            "wait",
            "ran, but ASH could not record its tool's output",
            id="post-run",
            marks=_POSIX_SIGNAL,
        ),
    ],
)
def test_a_plugin_whose_own_values_drop_the_config_s_still_redacts_them(
    tmp_path, monkeypatch, mode, expected, hook
):
    """A plugin may override ``_environment_values()``, and one that returns
    fewer values than the config read, or raises, still redacts the config's:
    the runner's own lines and the plugin's could-not-start and post-run lines
    take the config's values and the plugin's together. The post-run line
    quotes the command through the signal that ended the child."""
    from automated_security_helper.utils import subprocess_utils

    runner = _wait_fails_on_an_exited_child if mode == "wait" else _failing_runner(mode)
    monkeypatch.setattr(subprocess_utils, "_runner", lambda sandboxed: runner)
    monkeypatch.setattr(subprocess_utils, "find_executable", lambda name: None)
    context = _context(tmp_path, [SETTINGS_CANARY])
    scanner = _scanner(context)
    scanner.use_uv_tool = False
    monkeypatch.setattr(type(scanner), "_environment_values", hook)
    records = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    handler = _Collect(level=1)
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(1)
    ASH_LOGGER.addHandler(handler)
    try:
        response = scanner._run_subprocess(
            ["stub-tool", "--config", SETTINGS_CANARY],
            results_dir=context.output_dir,
        )
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)

    # The controls: the line this way of failing gives, and the command; for
    # the post-run line, the error it prints quotes the value.
    assert any(expected in record for record in records), records
    assert any("--config" in record for record in records), records
    if mode == "wait":
        assert response.get("post_run_error") is True, response
        assert SETTINGS_CANARY in response["error"], response
    for record in records:
        assert "ENVCANARY-77aa" not in record, record


@pytest.mark.parametrize("spelling", ["67", "067"])
def test_a_scanners_timed_out_uv_run_logs_no_limit(
    tmp_path, monkeypatch, logged, spelling
):
    """The same run through uv: the mixin hands run_tool the values too."""
    from automated_security_helper.utils import subprocess_utils, uv_tool_runner

    monkeypatch.setattr(subprocess_utils, "_runner", lambda sandboxed: _times_out)
    # uv shown as "uv", not resolved to a path whose digits are its own.
    monkeypatch.setattr(subprocess_utils, "find_executable", lambda name: None)
    runner = uv_tool_runner.UVToolRunner(uv_executable="uv")
    runner._uv_available_cache = True
    monkeypatch.setattr(uv_tool_runner, "get_uv_tool_runner", lambda: runner)
    context = _context(tmp_path, [spelling])
    scanner = _scanner(context)
    scanner.use_uv_tool = True

    response = scanner._run_subprocess(
        ["stub-tool", "--scan"], results_dir=context.output_dir, timeout=67
    )

    assert response.get("timed_out") is True, response
    # The control: the run went through uv.
    assert any("tool run" in line for line in _timeout_lines(logged, tmp_path)), logged
    _assert_no_limit(logged, scanner.errors, context.config, tmp_path)


# ---------------------------------------------------------------------------
# The uv runner's own timeout texts
# ---------------------------------------------------------------------------
#
# run_tool without a results directory, and a tool install, word their own
# timeout. They print the limit through the same shared token, so a whole
# limit prints whole there too: '1000000', never the '1e+06' that :g writes.

UV_LIMITS = [
    *LIMITS,
    pytest.param(1e21, "'1000000000000000000000' s", id="huge-float"),
]


def _uv_runner():
    from automated_security_helper.utils.uv_tool_runner import UVToolRunner

    runner = UVToolRunner(uv_executable="uv")
    runner._uv_available_cache = True
    return runner


def _uv_run_times_out(monkeypatch, limit):
    import subprocess

    from automated_security_helper.utils import uv_tool_runner

    def _spawn_run(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs.get("timeout"))

    monkeypatch.setattr(uv_tool_runner, "spawn_run", _spawn_run)
    return _uv_runner().run_tool("stub-tool", args=["--scan"], timeout=limit)


def _uv_install_times_out(monkeypatch, limit):
    import subprocess

    from automated_security_helper.utils import uv_tool_runner
    from automated_security_helper.utils.uv_tool_runner import UVToolRunnerError

    def _spawn_run(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs.get("timeout"))

    runner = _uv_runner()
    monkeypatch.setattr(runner, "is_tool_installed", lambda *a, **k: False)
    monkeypatch.setattr(uv_tool_runner, "spawn_run", _spawn_run)
    monkeypatch.setattr(
        "automated_security_helper.core.constants.is_offline_mode", lambda: False
    )
    with pytest.raises(UVToolRunnerError) as excinfo:
        runner.install_tool_with_version("stub-tool", timeout=limit)
    return str(excinfo.value)


@pytest.mark.parametrize("limit,token", UV_LIMITS)
def test_the_uv_runs_timeout_text_prints_a_limit_whole(monkeypatch, limit, token):
    result = _uv_run_times_out(monkeypatch, limit)

    assert getattr(result, "timed_out", False) is True, result
    assert f"Command timed out after {token}" in result.error, result.error
    assert f"Command timed out after {token}" in result.stderr, result.stderr


@pytest.mark.parametrize("limit,token", UV_LIMITS)
def test_the_uv_install_timeout_text_prints_a_limit_whole(monkeypatch, limit, token):
    message = _uv_install_times_out(monkeypatch, limit)

    assert f"timed out after {token}" in message, message


def test_the_uv_install_timeout_text_prints_its_limit_once(monkeypatch):
    """The error says it timed out once: the TimeoutExpired's own text repeats
    the limit in its spelling, "timed out after 67 seconds", outside the token."""
    message = _uv_install_times_out(monkeypatch, 67)

    assert message.count("timed out after") == 1, message
    assert "seconds" not in message, message


def test_the_uv_timeout_texts_print_the_shared_limit_token(monkeypatch):
    """Both print their limit through error_text.timeout_limit_token, the one
    formatter every timeout message uses, so they cannot drift from the others."""
    from automated_security_helper.utils import error_text

    monkeypatch.setattr(
        error_text, "timeout_limit_token", lambda limit, values: "<the shared token>"
    )

    result = _uv_run_times_out(monkeypatch, 67)
    message = _uv_install_times_out(monkeypatch, 67)

    assert "Command timed out after <the shared token>" in result.error, result.error
    assert "timed out after <the shared token>" in message, message


def test_the_uv_runs_timeout_text_names_the_option_for_an_env_typed_limit(
    monkeypatch,
):
    """run_tool without a results directory, handed the scan config's values."""
    import subprocess

    from automated_security_helper.utils import uv_tool_runner

    def _spawn_run(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs.get("timeout"))

    monkeypatch.setattr(uv_tool_runner, "spawn_run", _spawn_run)

    result = _uv_runner().run_tool(
        "stub-tool", args=["--scan"], timeout=67, values=[ENV_TYPED_LIMIT]
    )

    for text in (result.error, result.stderr):
        assert "Command timed out after the configured scan_timeout" in text, text
        assert "67" not in text, text


# ---------------------------------------------------------------------------
# Limits a config file cannot read from the environment
# ---------------------------------------------------------------------------
#
# Callers that print these limits through the shared token with no values (the
# cdk-nag worker's scan_timeout, a builtin scanner's install_timeout, the
# workspace's project_timeout) rely on this: a config file is validated
# strictly, so a number written as a reference to the environment is refused
# at load, in every form a reference takes. Only a plugin module's own section,
# which its model types later and laxly, takes one (the SPELLINGS cells above).

_STRICT_LIMIT_TABLE = [
    # The limit as a YAML file writes it, as a TOML file does, and the JSON
    # pointer a patch operation names it by.
    (
        "workspace-project_timeout",
        "workspace:\n  project_timeout: {ref}\n",
        '[workspace]\nproject_timeout = "{ref}"\n',
        "/workspace/project_timeout",
    ),
    (
        "cdk-nag-scan_timeout",
        "scanners:\n  cdk-nag:\n    options:\n      scan_timeout: {ref}\n",
        '[scanners.cdk-nag.options]\nscan_timeout = "{ref}"\n',
        "/scanners/cdk-nag/options/scan_timeout",
    ),
    (
        "bandit-install_timeout",
        "scanners:\n  bandit:\n    options:\n      install_timeout: {ref}\n",
        '[scanners.bandit.options]\ninstall_timeout = "{ref}"\n',
        "/scanners/bandit/options/install_timeout",
    ),
]

STRICT_LIMITS = [
    pytest.param(block, id=name) for name, block, _, _ in _STRICT_LIMIT_TABLE
]

STRICT_LIMIT_ROUTES = [
    pytest.param(block, table, pointer, id=name)
    for name, block, table, pointer in _STRICT_LIMIT_TABLE
]

# Each of these but the quoted one resolves, to ASH_STRICT_LIMIT's "67" or to its
# default with ASH_STRICT_LIMIT_UNSET unset, so a load that typed the text laxly
# would take a number from the environment: it is the strict model that refuses
# them. A quoted reference is never resolved (YAML resolves only a plain
# scalar), so its cell is refused for the text "${ASH_STRICT_LIMIT}" itself, as
# it would be however laxly the file loaded.
REFERENCE_FORMS = [
    pytest.param("${ASH_STRICT_LIMIT}", id="plain"),
    pytest.param("!ENV ${ASH_STRICT_LIMIT}", id="tagged"),
    pytest.param("${ASH_STRICT_LIMIT:60}", id="default-set"),
    pytest.param("${ASH_STRICT_LIMIT_UNSET:60}", id="default-unset"),
    pytest.param("${ASH_STRICT_LIMIT}0", id="run-into-text"),
    pytest.param("'${ASH_STRICT_LIMIT}'", id="quoted-never-resolved"),
]


def _refused_at_load(profile):
    from automated_security_helper.config.resolve_config import (
        ConfigFileRefused,
        load_config_file_for_run,
    )

    with pytest.raises(ConfigFileRefused) as excinfo:
        load_config_file_for_run(profile)

    # Refused for the reference's type: a number, or a whole number, was due.
    assert "Input should be a valid" in str(excinfo.value), str(excinfo.value)


@pytest.mark.parametrize("ref", REFERENCE_FORMS)
@pytest.mark.parametrize("block", STRICT_LIMITS)
def test_a_builtin_limit_read_from_the_environment_is_refused_at_load(
    tmp_path, monkeypatch, block, ref
):
    monkeypatch.setenv("ASH_STRICT_LIMIT", "67")
    monkeypatch.delenv("ASH_STRICT_LIMIT_UNSET", raising=False)
    profile = tmp_path / "strict-limit.ash.yaml"
    profile.write_text(
        "project_name: strict-limit\n" + block.format(ref=ref), encoding="utf-8"
    )

    _refused_at_load(profile)


@pytest.mark.parametrize("route", ["toml", "extends", "patch"])
@pytest.mark.parametrize(("block", "table", "pointer"), STRICT_LIMIT_ROUTES)
def test_a_builtin_limit_read_from_the_environment_another_way_is_refused_at_load(
    tmp_path, monkeypatch, block, table, pointer, route
):
    """The reference written by a TOML file, by the base a file extends, or as a
    patch operation's value, which lands on the limit after the file is read."""
    monkeypatch.setenv("ASH_STRICT_LIMIT", "67")
    ref = "${ASH_STRICT_LIMIT}"
    if route == "toml":
        profile = tmp_path / "strict-limit.ashrc.toml"
        profile.write_text(
            'project_name = "strict-limit"\n' + table.format(ref=ref),
            encoding="utf-8",
        )
    elif route == "extends":
        (tmp_path / "base.yaml").write_text(
            "project_name: strict-limit\n" + block.format(ref=ref), encoding="utf-8"
        )
        profile = tmp_path / "strict-limit.ash.yaml"
        profile.write_text(
            "extends: base.yaml\nproject_name: strict-limit\n", encoding="utf-8"
        )
    else:
        profile = tmp_path / "strict-limit.ash.yaml"
        profile.write_text(
            "project_name: strict-limit\n"
            + block.format(ref="1")
            + f"patch:\n  - op: replace\n    path: {pointer}\n    value: {ref}\n",
            encoding="utf-8",
        )

    _refused_at_load(profile)


@pytest.mark.parametrize("block", STRICT_LIMITS)
def test_a_builtin_limit_written_as_a_number_loads(tmp_path, block):
    """The control: the refusals above are the reference's, not the limit's."""
    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )

    profile = tmp_path / "strict-limit.ash.yaml"
    profile.write_text(
        "project_name: strict-limit\n" + block.format(ref="67"), encoding="utf-8"
    )

    load_config_file_for_run(profile)


@pytest.mark.parametrize("spelling", ["67", "067"])
def test_pre_scan_dumps_show_a_value_from_the_environment_as_written(
    tmp_path, monkeypatch, logged, spelling
):
    """_pre_scan's two DEBUG dumps print the scanner's config whole.

    A short number in them is printed bare (``scan_timeout=67``), which
    redaction leaves, so each value the scan config read from the environment
    is dumped as the reference its file wrote, typed by the plugin's model or
    not.
    """
    import re

    from tests.unit.base.test_scanner_plugin_coverage import StubConfig

    config = _loaded_with_limit(tmp_path, monkeypatch, spelling, section="stub")
    context = _context(tmp_path, [])
    context.config = config
    scanner = _scanner(context)
    section = dict(config.scanners.model_extra["stub"])
    scanner.config = StubConfig.model_validate({**section, "name": "stub"})
    # The control: the plugin's model read the spelling as the number.
    assert scanner.config.options.scan_timeout == 67
    target = _populated_target(tmp_path)
    logged.clear()

    assert scanner._pre_scan(target=target, target_type="source", config=scanner.config)

    dumps = _config_dumps(logged)
    assert len(dumps) == 2, logged
    for line in dumps:
        assert "${ASH_SPELLED_LIMIT}" in line, line
        assert not re.search(r"scan_timeout\W+0?67\b", line), line


@pytest.mark.parametrize(
    "answer",
    [
        pytest.param(lambda: None, id="none"),
        pytest.param(lambda: 67, id="a-non-iterable"),
        pytest.param(_mid_iteration_drift, id="a-raising-iterable"),
    ],
)
def test_a_hook_answering_no_set_skips_the_dumps_instead_of_printing_clear(
    tmp_path, logged, answer
):
    """The dumps' guarded hook read degrades on a raise, and an override that
    answers None, any non-iterable, or an iterable that raises mid-drain is
    the same broken answer: it is never read as an EMPTY value set, which
    would print what the values would have hidden. The dumps are skipped
    whole, the arm the raise already takes, and the scan itself goes on. The
    record read takes the same conservative arm (the value-free notes); only
    a true value set, the empty one included, is an answer."""
    scanner = _scanner(_context(tmp_path, []))
    target = _populated_target(tmp_path)
    logged.clear()

    with patch.object(type(scanner), "_values_to_redact", return_value=answer()):
        assert scanner._pre_scan(
            target=target, target_type="source", config=scanner.config
        )

    dumps = _config_dumps(logged)
    assert dumps == [], dumps


_BIG = "12345678901234567891"


@pytest.mark.parametrize(
    "current,text,typed",
    [
        pytest.param(int(_BIG), _BIG, True, id="an-int-above-2**53"),
        pytest.param(float(_BIG), _BIG, True, id="a-float-above-2**53"),
        pytest.param(67, "067", True, id="an-int-with-a-leading-zero"),
        pytest.param(67, "67.0", True, id="an-int-from-a-float-text"),
        pytest.param(67.5, "67.5", True, id="a-float"),
        pytest.param(67, "68", False, id="another-number"),
        pytest.param(True, "1", False, id="a-bool"),
        pytest.param(
            2**53 + 1,
            str(2**53 + 1) + ".0",
            True,
            id="an-int-above-2**53-written-with-decimal-zeros",
        ),
        pytest.param(
            -(2**53) - 1,
            str(-(2**53) - 1) + ".0",
            True,
            id="a-negative-int-below-minus-2**53-written-with-decimal-zeros",
        ),
        pytest.param(
            int(_BIG), _BIG + ".0", True, id="a-big-int-written-with-decimal-zeros"
        ),
        pytest.param(float("nan"), "nan", True, id="a-float-nan"),
        pytest.param(1000, "1e3", False, id="an-int-from-an-exponent-text"),
        pytest.param(67, "67.", False, id="an-int-from-a-text-ending-in-a-point"),
    ],
)
def test_the_typed_number_check_reads_the_text_as_the_model_typed_it(
    current, text, typed
):
    """Whether *current* is the number a lax model typed from *text*, typed
    the way the field that holds it types the text. An int field holds the
    text's exact value, digits past 2**53 included, whether or not the text
    carries decimal zeros, and refuses an exponent text or one ending in a
    point ("1e3", "67."); a float field holds
    the nearest float. A NaN typed from "nan" is typed from it, though it
    equals nothing."""
    from automated_security_helper.config.config_validator import typed_from

    assert typed_from(current, text) is typed


@pytest.mark.parametrize(
    "current,text",
    [
        pytest.param(2**53, str(2**53 + 1), id="2**53-from-2**53+1"),
        pytest.param(-(2**53), str(-(2**53) - 1), id="minus-2**53-from-minus-2**53-1"),
        pytest.param(int(float(_BIG)), _BIG, id="the-nearest-float-of-a-big-int"),
        pytest.param(2**60, str(2**60 + 1), id="2**60-from-2**60+1"),
        pytest.param(
            2**53,
            str(2**53 + 1) + ".0",
            id="2**53-from-2**53+1-written-with-decimal-zeros",
        ),
        pytest.param(
            int(float(_BIG)),
            _BIG + ".0",
            id="the-nearest-float-of-a-big-int-written-with-decimal-zeros",
        ),
    ],
)
def test_an_int_the_text_only_rounds_to_is_not_typed_from_it(current, text):
    """An int field types a whole-number text exactly, so an int that only the
    text's nearest float equals is not the number the field typed from it:
    the dump would write the reference for a value the variable did not
    give."""
    from pydantic import TypeAdapter

    from automated_security_helper.config.config_validator import typed_from

    # The controls: the text's nearest float is this int, and an int field
    # types the text as another int.
    assert float(text) == current
    assert TypeAdapter(int).validate_python(text) != current
    assert typed_from(current, text) is False


_BIG_SPELLINGS = [
    pytest.param(_BIG, id="digits"),
    pytest.param(_BIG + ".0", id="digits-with-decimal-zeros"),
]


@pytest.mark.parametrize("spelling", _BIG_SPELLINGS)
def test_pre_scan_dumps_show_a_large_whole_value_as_written(
    tmp_path, monkeypatch, logged, spelling
):
    """The same for a whole number above 2**53, whose digits a float compare
    loses, with or without decimal zeros: the typed-number check reads the
    text as the int the model typed, so the dump shows the reference and not
    the number."""
    from tests.unit.base.test_scanner_plugin_coverage import StubConfig

    config = _loaded_with_limit(tmp_path, monkeypatch, spelling, section="stub")
    context = _context(tmp_path, [])
    context.config = config
    scanner = _scanner(context)
    section = dict(config.scanners.model_extra["stub"])
    scanner.config = StubConfig.model_validate({**section, "name": "stub"})
    # The controls: the model typed the text with every digit, which the
    # nearest float does not keep.
    assert scanner.config.options.scan_timeout == int(_BIG)
    assert float(_BIG) != int(_BIG)
    target = _populated_target(tmp_path)
    logged.clear()

    assert scanner._pre_scan(target=target, target_type="source", config=scanner.config)

    dumps = _config_dumps(logged)
    assert len(dumps) == 2, logged
    for line in dumps:
        assert "${ASH_SPELLED_LIMIT}" in line, line
        assert _BIG not in line, line


@pytest.mark.parametrize("spelling", _BIG_SPELLINGS)
def test_a_large_whole_number_is_recorded_as_its_own_text(
    tmp_path, monkeypatch, spelling
):
    """A plugin's int option types a whole number above 2**53 exactly, decimal
    zeros or not. The config records the variable's own text; a bare-digit
    spelling of it is no needle, and the nearest float's digits never appear
    anywhere."""
    from automated_security_helper.utils.error_text import config_environment_values

    recorded = config_environment_values(
        _loaded_with_limit(tmp_path, monkeypatch, spelling)
    )

    # The control: the variable's text, as the load recorded it.
    assert spelling in recorded, recorded
    # Neither bare-digit form joins: not the typed value's, and not the
    # nearest float's lossy digits.
    assert str(int(float(_BIG))) not in recorded, recorded


@pytest.mark.parametrize("spelling", _BIG_SPELLINGS)
def test_a_large_typed_limit_is_redacted_from_the_timeout_record(
    tmp_path, monkeypatch, logged, spelling
):
    """The timeout record of a plugin whose int limit is a whole number above
    2**53, decimal zeros or not, carries no digit of it."""
    from tests.unit.base.test_scanner_plugin_coverage import StubConfig

    config = _loaded_with_limit(tmp_path, monkeypatch, spelling)
    context = _context(tmp_path, [])
    context.config = config
    scanner = _scanner(context)
    section = dict(config.scanners.model_extra["plugin-tool"])
    scanner.config = StubConfig.model_validate({**section, "name": "stub"})
    limit = scanner.config.options.scan_timeout
    # The control: the plugin's model typed every digit.
    assert limit == int(_BIG), limit

    scanner._record_timeout({"timed_out": True}, limit)

    line = next(line for line in scanner.errors if "timed out after" in line)
    assert "scan_timeout" in line, line
    assert _BIG not in line, line
    text = "\n".join(logged)
    assert "timed out after" in text, text
    assert _BIG not in text, text


def test_the_neutral_layer_strips_a_non_color_escape_inside_a_value():
    """shown_tool_stderr stripped only color codes, so a non-color escape
    inside a value ("EDGE\\x1b[KSECRET") split the match on every report
    line built with the neutral layer, and a sink or terminal that drops or
    obeys the escape then showed the value whole. The helper strips every
    complete escape code before matching, so the npm and yarn sites no
    longer carry their own pre-strip."""
    from automated_security_helper.utils.error_text import shown_tool_stderr

    value = "EDGESECRET-9912"
    shown = shown_tool_stderr("npm saw EDGE\x1b[KSECRET-9912 in its config", (value,))

    assert value not in shown, shown
    assert "EDGE" not in shown, shown
    assert "\x1b" not in shown, shown


@pytest.mark.skipif(
    not hasattr(signal_module, "SIGALRM"),
    reason="SIGALRM does not exist on Windows; the deadline guard needs it",
)
def test_the_read_edge_trim_stays_fast_on_junk_runs():
    """Pin the trim's cost on the inputs that hung or crawled earlier
    versions, at the LARGEST bound a caller uses (_carry_stderr_log's
    1 MiB): a read filled with replacement characters (a tool writing
    binary or a non-UTF-8 code page to stderr) and one filled with color
    codes. The one-regex version backtracked combinatorially; the
    per-token loop that sliced the string on every pass copied up to
    O(tokens x n) bytes, tens of seconds at this size. The end-index loop
    slices once. The alarm turns a reintroduced slow shape into a clean
    failure instead of a hung suite."""
    from automated_security_helper.base.plugin_base import (
        _STDERR_LOG_READ_LIMIT,
        trimmed_at_read_edge,
    )

    def _bail(*_args):
        raise TimeoutError("the read-edge trim did not finish in 30 s")

    previous = signal_module.signal(signal_module.SIGALRM, _bail)
    signal_module.alarm(30)
    try:
        value = "JUNKSECRET-776611"
        # A read-sized run of replacement characters, as the whole tail and
        # mid-text (mid-text junk is never walked; only the tail is).
        fffd = chr(0xFFFD) * (_STDERR_LOG_READ_LIMIT - 1000)
        assert trimmed_at_read_edge("a" * 1000 + fffd, [value]) == "a" * 1000
        assert trimmed_at_read_edge("a" * 500 + fffd + "b", [value]).endswith("b")
        # A read filled with color codes, as the tail and before a fragment.
        codes = "\x1b[31m" * ((_STDERR_LOG_READ_LIMIT - 1000) // 5)
        assert trimmed_at_read_edge("a" * 1000 + codes, [value]) == "a" * 1000
        kept = trimmed_at_read_edge("a" * 1000 + codes + "JUNKSE", [value])
        assert not kept.endswith("JUNKSE"), kept[-20:]
    finally:
        signal_module.alarm(0)
        signal_module.signal(signal_module.SIGALRM, previous)


#: A hyperlink OSC far longer than the junk loop's 128-character window,
#: ended by ST ("\\x1b\\\\"): the terminator holds the LAST ESC in the text,
#: which is where a single rfind lands.
_LONG_OSC_ST = "\x1b]8;;https://docs.example.com/" + "p" * 190 + "\x1b\\"


def test_a_long_st_terminated_osc_at_the_carried_bound_does_not_defeat_the_trim(
    tmp_path,
):
    """The junk loop's over-length fallback rfinds the last ESC. For a long
    OSC ended by ST that ESC is the terminator's own, the anchored search
    from it matches nothing, and the loop breaks with the code in place; the
    walk's window then opens inside the OSC, reads its body as plain text,
    and never reaches the value fragment in front of it. The sinks strip the
    whole OSC and print the fragment."""
    from automated_security_helper.base.plugin_base import _STDERR_LOG_READ_LIMIT

    value = "EDGESECRET-4417"
    context = _context(tmp_path, [value])
    scanner = _scanner(context)
    log = tmp_path / "Tool.stderr.log"
    kept = 6 + len(_LONG_OSC_ST)
    log.write_text(
        "x" * (_STDERR_LOG_READ_LIMIT - kept) + "EDGESE" + _LONG_OSC_ST + "CRET-4417",
        encoding="utf-8",
    )
    post_run = {"error": "the response could not be read"}

    scanner._carry_stderr_log(post_run, log, (value,))

    carried = post_run["stderr"]
    assert carried.endswith(" ...[truncated]"), carried[-40:]
    tail = carried[-(len(_LONG_OSC_ST) + 80) :]
    assert "EDGESE" not in tail, repr(tail[:80])
    assert "\x1b" not in tail, repr(tail[:80])


def test_a_long_st_terminated_osc_at_the_trims_edge_is_still_stripped():
    """The same shape at the trim's own edge, as the excerpt path cuts it:
    the fragment and the whole ST-terminated OSC behind it go together."""
    from automated_security_helper.base.plugin_base import trimmed_at_read_edge

    trimmed = trimmed_at_read_edge(
        "scanner wrote EDGESE" + _LONG_OSC_ST, ["EDGESECRET-4417"]
    )
    assert "EDGESE" not in trimmed, repr(trimmed[-80:])
    assert "\x1b" not in trimmed, repr(trimmed[-80:])


def test_a_bel_terminated_long_osc_is_still_stripped():
    """Control for the ST shape: the same over-length OSC ended by BEL keeps
    no ESC but its opener, so the fallback's single rfind already lands
    right, and the fix for the ST shape must not disturb it."""
    from automated_security_helper.base.plugin_base import trimmed_at_read_edge

    osc_bel = "\x1b]8;;https://docs.example.com/" + "p" * 190 + "\x07"
    trimmed = trimmed_at_read_edge(
        "scanner wrote EDGESE" + osc_bel, ["EDGESECRET-4417"]
    )
    assert "EDGESE" not in trimmed, repr(trimmed[-80:])
    assert "\x1b" not in trimmed, repr(trimmed[-80:])


def test_a_short_st_terminated_osc_is_still_stripped():
    """Control: an ST-terminated OSC that fits the junk window whole is seen
    by the windowed search and never reaches the fallback."""
    from automated_security_helper.base.plugin_base import trimmed_at_read_edge

    osc_short = "\x1b]8;;x\x1b\\"
    trimmed = trimmed_at_read_edge(
        "scanner wrote EDGESE" + osc_short, ["EDGESECRET-4417"]
    )
    assert "EDGESE" not in trimmed, repr(trimmed[-60:])
    assert "\x1b" not in trimmed, repr(trimmed[-60:])


def test_a_long_code_between_the_fragments_halves_stays_inside_the_walk(tmp_path):
    """The walk's window is sized in plain characters by widening a raw
    slice, and the slice's START can land inside a code longer than the
    window: the walk then reads the code's body as plain text, the body's
    characters sit where the value's would be matched, and the fragment in
    front of the code survives. The window must open at the code's ESC, which
    the walk skips whole."""
    from automated_security_helper.base.plugin_base import _STDERR_LOG_READ_LIMIT

    value = "EDGESECRET-4417"
    long_code = "\x1b[" + "0;" * 100 + "0m"
    context = _context(tmp_path, [value])
    scanner = _scanner(context)
    log = tmp_path / "Tool.stderr.log"
    kept = 6 + len(long_code)
    log.write_text(
        "x" * (_STDERR_LOG_READ_LIMIT - kept) + "EDGE" + long_code + "SE" + "CRET-4417",
        encoding="utf-8",
    )
    post_run = {"error": "the response could not be read"}

    scanner._carry_stderr_log(post_run, log, (value,))

    carried = post_run["stderr"]
    assert carried.endswith(" ...[truncated]"), carried[-40:]
    tail = carried[-(len(long_code) + 80) :]
    assert "EDGE" not in tail, repr(tail[:80])
    assert "SE ...[truncated]" not in carried, carried[-40:]


def test_the_carried_log_trims_a_cut_inside_a_glued_input(tmp_path):
    """The carried stderr's bounded read trimmed only against the values: a
    uv run's inputs were not passed on the carry path, while the excerpt and
    the explainer already pass them, so a cut just after a glued extra's
    value kept a fragment the sinks cannot match whole
    ("bandit[sarifqz4b ...[truncated]")."""
    from automated_security_helper.base.plugin_base import _STDERR_LOG_READ_LIMIT

    value = "qz4b"
    context = _context(tmp_path, [value])
    scanner = _scanner(context)
    scanner.use_uv_tool = True
    scanner._uv_run_inputs_for_records = lambda: ("bandit[sarifqz4b]==1.0",)
    log = tmp_path / "Tool.stderr.log"
    head = "bandit[sarifqz4b"
    log.write_text(
        "x" * (_STDERR_LOG_READ_LIMIT - len(head)) + head + "]==1.0 and more",
        encoding="utf-8",
    )
    post_run = {"error": "the response could not be read"}

    scanner._carry_stderr_log(post_run, log, (value,))

    carried = post_run["stderr"]
    assert carried.endswith(" ...[truncated]"), carried[-40:]
    assert "sarifqz4b" not in carried[-60:], repr(carried[-60:])
    assert "qz4b" not in carried[-60:], repr(carried[-60:])


def test_the_carried_log_trims_a_cut_inside_an_inputs_wheel_spelling(tmp_path):
    """The trim matches every spelling uv can print for an input, not the
    spec as written: ``pkg.aqz4bb==1.0`` can appear as the wheel name
    ``pkg_aqz4bb``, so a cut inside THAT spelling leaves a fragment
    ("pkg_aqz4b") the as-written form alone cannot match."""
    from automated_security_helper.base.plugin_base import _STDERR_LOG_READ_LIMIT

    value = "unrelated-value-qq1"
    context = _context(tmp_path, [value])
    scanner = _scanner(context)
    scanner.command = "checkov"
    scanner.use_uv_tool = True
    scanner._uv_run_inputs_for_records = lambda: ("pkg.aqz4bb==1.0",)
    log = tmp_path / "Tool.stderr.log"
    head = "pkg_aqz4b"
    log.write_text(
        "x" * (_STDERR_LOG_READ_LIMIT - len(head)) + head + "b-1.0 and more",
        encoding="utf-8",
    )
    post_run = {"error": "the response could not be read"}

    scanner._carry_stderr_log(post_run, log, (value,))

    carried = post_run["stderr"]
    assert carried.endswith(" ...[truncated]"), carried[-40:]
    assert "pkg_aqz4b" not in carried[-60:], repr(carried[-60:])
    assert "aqz4b" not in carried[-60:], repr(carried[-60:])


class _IdentityRecordingPattern:
    """The junk pattern with the OBJECT each ``search`` reads recorded."""

    def __init__(self, pattern) -> None:
        self._pattern = pattern
        self.seen_ids: list = []

    def search(self, text, *args):
        self.seen_ids.append(id(text))
        return self._pattern.search(text, *args)


def test_the_junk_loop_searches_the_original_text_every_pass():
    """The junk loop tracks an END INDEX and slices once at the bottom: a
    version that sliced the string per pass passed a NEW object to each
    search (the O(tokens x text) copying the cost cell bounds in time) --
    a call count alone cannot tell the two apart, the object identity
    can."""
    from automated_security_helper.base import plugin_base

    original_pattern = plugin_base._TRAILING_JUNK
    recorder = _IdentityRecordingPattern(original_pattern)
    text = "a" * 1000 + "\x1b[31m" * 5000
    try:
        plugin_base._TRAILING_JUNK = recorder
        trimmed = plugin_base.trimmed_at_read_edge(text, ["JUNKSECRET-776611"])
    finally:
        plugin_base._TRAILING_JUNK = original_pattern
    assert trimmed == "a" * 1000
    assert len(recorder.seen_ids) >= 5000, len(recorder.seen_ids)
    assert set(recorder.seen_ids) == {id(text)}, (
        "a junk-loop search read a sliced copy, not the original text"
    )


class _CountingPattern:
    """The escape pattern with its ``match`` calls counted. With a ``limit``
    the first call past it raises, so a runaway shape fails at once instead
    of at an alarm."""

    def __init__(self, pattern, limit=None) -> None:
        self._pattern = pattern
        self.limit = limit
        self.calls = 0

    def match(self, *args, **kwargs):
        self.calls += 1
        if self.limit is not None and self.calls > self.limit:
            raise AssertionError(
                f"{self.calls} escape-pattern match calls against a budget "
                f"of {self.limit}"
            )
        return self._pattern.match(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._pattern, name)


@pytest.mark.parametrize("value_count", [1, 5])
def test_the_trim_walks_the_tail_once_for_all_forms(monkeypatch, value_count):
    """The code-skipping walk reads up to the whole text, and the forms are
    values x spellings x printed forms: a walk run per form multiplies that
    read by dozens, seconds per cut log read. One walk serves every form,
    and only a cut that has come within one form's length of the walked
    window's start, with unwalked text in front of it, buys a wider one.
    Pinned by a budget on the escape pattern's match calls, three walks'
    worth, which a per-form walk exceeds whatever the host."""
    from automated_security_helper.base import plugin_base

    counting = _CountingPattern(plugin_base._ESCAPE_CODES)
    monkeypatch.setattr(plugin_base, "_ESCAPE_CODES", counting)
    code_count = 20_000
    # Plain text AFTER the codes, so the junk loop cannot trim them away and
    # the walk has to widen through the whole code mass to find its plain
    # window. Nothing matches any form, so nothing is trimmed.
    text = "a" * 1000 + "\x1b[31m" * code_count + "zz"
    values = [f"BUDGETSECRET-{index}{index}7" for index in range(value_count)]

    trimmed = plugin_base.trimmed_at_read_edge(text, values)

    assert trimmed == text
    # One walk costs about one match call per code, twice over for the
    # window's doubling passes; three walks' worth leaves room without
    # admitting a per-form rerun.
    budget = 3 * (2 * code_count + 2000)
    assert counting.calls <= budget, (
        f"{counting.calls} escape-pattern match calls against a budget of "
        f"{budget}: the walk is running per form again"
    )


@contextlib.contextmanager
def _finishing_within(seconds):
    """Fail with a TimeoutError once *seconds* pass, so a reintroduced slow
    shape ends as a clean failure and not a hung suite (SIGALRM, POSIX)."""

    def _bail(*_args):
        raise TimeoutError(f"the read-edge trim did not finish in {seconds} s")

    previous = signal_module.signal(signal_module.SIGALRM, _bail)
    signal_module.alarm(seconds)
    try:
        yield
    finally:
        signal_module.alarm(0)
        signal_module.signal(signal_module.SIGALRM, previous)


@pytest.mark.skipif(
    not hasattr(signal_module, "SIGALRM"),
    reason="SIGALRM does not exist on Windows; the deadline guard needs it",
)
def test_a_read_that_is_a_run_of_a_values_first_character_loses_one_character(
    monkeypatch,
):
    """A tail that is nothing but a value's first character (a separator
    row, a progress bar, a hexdump's padding) matches that value's
    one-character prefix at every position. A trim that repeats whenever the
    new end matches a prefix again takes one character per pass and re-walks
    the window on each: about a million passes at _carry_stderr_log's 1 MiB
    bound, a quadratic scan, and a result of "" that loses every carried
    diagnostic. The cut here is ONE character, found once. Pinned three
    ways: on what is KEPT (all but the last character, so an empty or a
    shortened result fails), on the WORK (a budget on the escape pattern's
    match calls, which raises at the first call past it so a slow shape
    fails at once, not at the alarm), and on the clock. DISARMED: the value
    is fake and built in-test; nothing reads the environment."""
    from automated_security_helper.base import plugin_base

    value = "x" + "FAKESECRET" + "x"
    text = "x" * plugin_base._STDERR_LOG_READ_LIMIT
    # One walk reads twice the longest form plus 128 plain characters. The
    # cut needs that one walk, so four walks' worth is a wide margin that a
    # pass per character (a walk each) exceeds on its second or third pass.
    budget = 4 * (2 * len(value) + 128)
    counting = _CountingPattern(plugin_base._ESCAPE_CODES, limit=budget)
    monkeypatch.setattr(plugin_base, "_ESCAPE_CODES", counting)

    with _finishing_within(30):
        trimmed = plugin_base.trimmed_at_read_edge(text, [value])

    kept = len(text) - 1
    assert (len(trimmed), trimmed.count("x")) == (kept, kept)
    assert counting.calls <= budget, counting.calls


@pytest.mark.skipif(
    not hasattr(signal_module, "SIGALRM"),
    reason="SIGALRM does not exist on Windows; the deadline guard needs it",
)
def test_a_chain_of_overlapping_spellings_is_walked_in_a_few_reads(monkeypatch):
    """After the pass over the forms the cut goes back to the start of the run
    of overlapping occurrences it falls inside. Here "aZ" trims the last "a"
    of a long run, and "aaa" (complete at the end, so left alone by the pass)
    starts an occurrence at every position of the run, so the run of
    occurrences is the whole run of "a": every "a" goes and the 10 "p" in
    front of it stay. The window is widened by doubling when the run reaches
    its front, so the walks sum to under three reads of the text: a budget
    of four reads, raising at the first match call past it. A re-walk per
    step (about 130 matches each) exceeds that after about six hundred
    steps. Pinned on what is KEPT too: exactly the 10 "p", so an empty
    result fails. DISARMED: the values are fake and built in-test; nothing
    reads the environment."""
    from automated_security_helper.base import plugin_base

    text = "p" * 10 + "a" * 20_000
    budget = 4 * len(text)
    counting = _CountingPattern(plugin_base._ESCAPE_CODES, limit=budget)
    monkeypatch.setattr(plugin_base, "_ESCAPE_CODES", counting)

    with _finishing_within(30):
        trimmed = plugin_base.trimmed_at_read_edge(text, ["aaa", "aZ"])

    assert trimmed == "p" * 10, (len(trimmed), trimmed[:20])
    assert counting.calls <= budget, counting.calls


class _CountingOccurrences:
    """The forms pattern with its scans, the positions they cover and the
    occurrences they yield counted. ``finditer`` is the one call the cut's
    pass makes on it."""

    def __init__(self, pattern, tally) -> None:
        self._pattern = pattern
        self._tally = tally

    def finditer(self, text, pos, endpos):
        self._tally["scans"] += 1
        self._tally["covered"] += endpos - pos
        for match in self._pattern.finditer(text, pos, endpos):
            self._tally["occurrences"] += 1
            yield match


@pytest.mark.skipif(
    not hasattr(signal_module, "SIGALRM"),
    reason="SIGALRM does not exist on Windows; the deadline guard needs it",
)
def test_a_self_overlapping_run_at_the_read_limit_is_cut_in_linear_work(monkeypatch):
    """The chain above at the read limit: 1 MiB, a run of "a" that a spelling
    repeating itself ("aaa") covers at every position. The pass this
    replaced stepped back two characters at a time, a find per form at each
    step, about half a million steps here; the occurrences are now found in
    one pass over each walked window. Pinned on the WORK by construction, not
    on the clock: the scans (one per walked window, and the windows double,
    so a count of the order of log2 of the text), the positions the scans
    cover (each looks only at the part of its window in front of the cut,
    which the earlier windows did not cover, so together they cover the text
    once and a form's overlap per window; a rescan of the whole window each
    time covers about twice that), and the occurrences they yield (at most
    one per covered position). Also on what is KEPT: exactly the 10 "p" in
    front of the run, so the whole run goes, as trimmed_at_read_edge's
    docstring says it does when a spelling overlaps itself. The deadline only
    keeps a regression from hanging the suite. DISARMED: the values are fake
    and built in-test; nothing reads the environment."""
    from automated_security_helper.base import plugin_base

    text = "p" * 10 + "a" * (plugin_base._STDERR_LOG_READ_LIMIT - 10)
    assert len(text) == plugin_base._STDERR_LOG_READ_LIMIT
    tally = {"scans": 0, "covered": 0, "occurrences": 0}
    real_run_start = plugin_base._overlap_run_start

    def _counting_run_start(pattern, plain_folded, kept, stop):
        return real_run_start(
            _CountingOccurrences(pattern, tally), plain_folded, kept, stop
        )

    monkeypatch.setattr(plugin_base, "_overlap_run_start", _counting_run_start)
    walk_budget = 4 * len(text)
    counting = _CountingPattern(plugin_base._ESCAPE_CODES, limit=walk_budget)
    monkeypatch.setattr(plugin_base, "_ESCAPE_CODES", counting)

    with _finishing_within(120):
        trimmed = plugin_base.trimmed_at_read_edge(text, ["aaa", "aZ"])

    assert trimmed == "p" * 10, (len(trimmed), trimmed[:20])
    assert counting.calls <= walk_budget, counting.calls
    assert 1 <= tally["scans"] <= 2 * len(text).bit_length(), tally
    assert tally["covered"] <= len(text) + len(text) // 4, tally
    assert tally["occurrences"] <= tally["covered"], tally


def _stepping_cut(plain, ordered_forms, kept):
    """Where the pass that _overlap_run_start replaced stopped: the cut moves
    to the lowest start of the first form (longest first) that has an
    occurrence running through it, again until none has."""
    while True:
        for form in ordered_forms:
            size = len(form)
            spanning = plain.find(
                form, max(kept - size + 1, 0), min(kept + size - 1, len(plain))
            )
            if spanning != -1:
                kept = spanning
                break
        else:
            return kept


@pytest.mark.parametrize(
    "forms",
    [
        pytest.param(("a",), id="one-character"),
        pytest.param(("aa",), id="repeats-itself-by-one"),
        pytest.param(("aaa",), id="repeats-itself-by-two"),
        pytest.param(("aba",), id="repeats-itself-at-a-distance"),
        pytest.param(("ab",), id="touching-occurrences"),
        pytest.param(("abab", "ba"), id="one-inside-the-overlap-of-the-other"),
        pytest.param(("aab", "ab", "b"), id="each-the-end-of-the-last"),
        pytest.param(("aaa", "aab", "abab"), id="three-forms-overlapping"),
        pytest.param(("abba", "bb"), id="a-form-inside-a-form"),
    ],
)
def test_the_overlap_run_start_is_where_the_stepping_pass_stopped(forms):
    """The cut the single pass reaches is the cut the stepping pass it
    replaced reached, on every text of up to nine characters over two
    letters, at every cut position: the stepping pass could only stop at a
    position no occurrence runs through, and every position inside a run of
    overlapping occurrences is run through, so both end at the run's start.
    The comparison is the cut itself, not how it was found. DISARMED: the
    forms are fake and built in-test; nothing reads the environment."""
    from automated_security_helper.base import plugin_base

    ordered = sorted(set(forms), key=lambda form: (-len(form), form))
    pattern = plugin_base._spellings_pattern(ordered)
    longest = len(ordered[0])
    compared = 0
    for length in range(10):
        for letters in itertools.product("ab", repeat=length):
            plain = "".join(letters)
            for kept in range(len(plain) + 1):
                stop = min(kept + longest - 1, len(plain))
                found = plugin_base._overlap_run_start(pattern, plain, kept, stop)
                assert found == _stepping_cut(plain, ordered, kept), (
                    plain,
                    kept,
                    ordered,
                )
                compared += 1
    # 2**length texts of each length, length + 1 cut positions each.
    assert compared == sum(2**length * (length + 1) for length in range(10))


def test_the_carry_cannot_be_called_without_the_handlers_values():
    """``environment_values`` has no default: a caller that forgets it would
    otherwise trim with NO values and carry a fragment the sinks cannot
    match, silently. Forgetting must be a TypeError, not an empty value
    set."""
    import inspect

    from automated_security_helper.base.plugin_base import PluginBase

    parameter = inspect.signature(PluginBase._carry_stderr_log).parameters[
        "environment_values"
    ]

    assert parameter.default is inspect.Parameter.empty, parameter


def test_a_cut_landing_exactly_after_a_value_keeps_the_whole_spelling():
    """A value whose first character equals its last, with the cut landing
    right after the whole value: the tail holds the COMPLETE spelling, and
    the sinks redact whole spellings, so nothing needs trimming. A trim that
    only knows proper prefixes matches the value's first character against
    the value's own last character and cuts it, leaving a tail no sink can
    match (11 of 12 characters in clear). The trim must leave a complete
    trailing spelling alone; a proper partial at the end is the leak this
    function exists to prevent. The assertion is the EXACT text, not "no
    proper prefix ends it": an empty result, or one that also dropped
    "tool echoed ", passes the second and fails the first. DISARMED: the
    value is fake and built in-test; nothing reads the environment."""
    from automated_security_helper.base.plugin_base import trimmed_at_read_edge

    value = "x" + "FAKESECRET" + "x"
    assert value[0] == value[-1]
    text = "tool echoed " + value  # the bounded read cut exactly after it

    trimmed = trimmed_at_read_edge(text, (value,))

    assert trimmed == text, repr(trimmed)


def test_a_shorter_value_cannot_expose_a_prefix_of_a_longer_one():
    """Two values where the shorter's first character equals the longer's
    last: the text ends with the longer value complete, the shorter's
    one-character prefix matches that end, and a trim that only cuts that
    character leaves the carried text ending with a proper prefix of the
    longer value, which no sink can match. The cut must go back to the start
    of the longer value, which the walked tail holds whole and the one-
    character cut ran through, and nothing before it may go: the short
    value's own complete spelling and the text around it stay. The
    assertion is the EXACT text, so an empty result, or one that also
    dropped " then " or the short value, fails it. DISARMED: both values
    are fake and built in-test; nothing reads the environment."""
    from automated_security_helper.base.plugin_base import trimmed_at_read_edge

    long_value = "tok_" + "FAKE" + "1"
    short_value = "1" + "FAKEZ"
    assert long_value[-1] == short_value[0]
    text = "uv printed " + short_value + " then " + long_value

    trimmed = trimmed_at_read_edge(text, (long_value, short_value))

    assert trimmed == "uv printed " + short_value + " then ", repr(trimmed)
