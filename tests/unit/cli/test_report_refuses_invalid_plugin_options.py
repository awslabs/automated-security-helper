# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash report`` refuses an invalid option of a loaded plugin the way ``ash scan`` does.

Why this exists
---------------
A built-in plugin's options are checked when the config loads, so a bad one is an
invalid configuration: one line naming the option, exit 3, for ``ash scan`` and
``ash report`` alike. A plugin loaded from ``ash_plugin_modules`` (the AWS
reporters, say) is checked only once the plugins are loaded, and only the scan
engine made that check (``config/plugin_option_check.py``). ``ash report``
checks a loaded plugin's options before it builds the reporter, so
``reporters.aws-security-hub.options.max_retries: three`` is refused as an
invalid configuration, exit 3, with no pydantic text.

What the tests check
--------------------
With such a config and saved results, ``ash report`` exits 3, says the
configuration is invalid in one message naming the option's location, prints no
pydantic text and nothing on stdout, and never builds a boto3 session. A control
reports with the same plugin module loaded and a valid option, and gets past the
check. AWS is unreachable throughout: fake credentials, no metadata service, no
config files, and ``boto3.Session`` replaced by a stub that fails the test.

An off-host reporter's destination and retry options are the operator's
(``config/reporter_trust.py``): ``ash report`` takes them from the defaults and
``--config-overrides`` and ignores a config file's, since stored results do not
say which tree was scanned. So a wrong-typed retry option is given through
``--config-overrides`` here, which is where the check reads it; an unknown key is
no such option and is read from the file.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit

AWS_PLUGINS = "automated_security_helper.plugin_modules.ash_aws_plugins"


@pytest.fixture(autouse=True)
def _no_route_to_aws(monkeypatch, tmp_path):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "no-aws-config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "no-aws-creds"))
    monkeypatch.delenv("ASH_CONFIG", raising=False)


@pytest.fixture(autouse=True)
def _reporters_resolved_afresh(monkeypatch):
    """Each test resolves the reporters itself, whatever ran before it.

    ``plugin_modules()`` memoises the classes it resolves on the process-wide
    ``ash_plugin_manager``, and registering a plugin later does not clear that.
    So when an earlier ``ash report`` in the same worker (tests/unit/cli/test_report.py,
    say) had resolved the reporters before ``ash_aws_plugins`` was registered,
    these tests loaded the module, got the memoised list without it, and
    exited 5 with "Reporter plugin 'aws-security-hub' not found". Measured with
    ``-n 0 -p no:randomly`` and either of those modules first: 4 of these 5 failed.

    The memo is emptied for the test and the previous one put back afterwards.
    The registrations are left alone: Python imports ``ash_aws_plugins`` once, so
    a registration removed here would never be made again for a later test
    (tests/snapshot/conftest.py merges such registrations back for that reason).
    """
    from automated_security_helper.plugins import ash_plugin_manager

    monkeypatch.setattr(ash_plugin_manager, "_resolved_plugins", {})


def _project(tmp_path: Path, options: str) -> Path:
    output = tmp_path / "out"
    output.mkdir()
    (output / "ash_aggregated_results.json").write_text(
        AshAggregatedResults().model_dump_json(by_alias=True), encoding="utf-8"
    )
    (tmp_path / "ash.yaml").write_text(
        "project_name: report-option-check\n"
        "ash_plugin_modules:\n"
        f"  - {AWS_PLUGINS}\n"
        "reporters:\n"
        "  aws-security-hub:\n"
        "    enabled: true\n"
        "    options:\n"
        "      aws_region: us-east-1\n"
        f"{options}",
        encoding="utf-8",
    )
    return output


def _report(tmp_path: Path, output: Path, fmt: str, *overrides: str):
    session = MagicMock(side_effect=AssertionError("AWS was contacted"))
    arguments = [
        "report",
        "--format",
        fmt,
        "--output-dir",
        str(output),
        "--config",
        str(tmp_path / "ash.yaml"),
        "--no-color",
    ]
    for override in overrides:
        arguments += ["--config-overrides", override]
    with patch(f"{AWS_PLUGINS}.security_hub_reporter.boto3.Session", session):
        result = CliRunner().invoke(app, arguments, env={"COLUMNS": "300"})
    session.assert_not_called()
    return result


@pytest.mark.parametrize(
    "file_options, overrides, named",
    [
        # The retry options of an off-host reporter are the operator's
        # (config/reporter_trust.py REPORTER_DESTINATION_OPTIONS): ash report
        # ignores a config file's value for them, so a wrong type is given the
        # operator's way, through --config-overrides, where the check sees it.
        (
            "",
            ("reporters.aws-security-hub.options.max_retries=three",),
            "max_retries",
        ),
        # An unknown key is not an operator's option, so the file's own is read.
        ("      max_retires: 3\n", (), "max_retires"),
    ],
    ids=["wrong-type", "unknown-key"],
)
def test_an_invalid_option_of_a_loaded_plugin_is_an_invalid_configuration(
    tmp_path, file_options, overrides, named
):
    output = _project(tmp_path, file_options)

    result = _report(tmp_path, output, "aws-security-hub", *overrides)

    assert result.exit_code == 3, result.output
    assert result.stdout == "", result.stdout
    assert "Invalid configuration" in result.stderr, result.stderr
    # The plugin's options section and the option itself: a wrong value is located
    # at the option, an unknown key at the section with the key in the message.
    assert "reporters.aws-security-hub.options" in result.stderr, result.stderr
    assert named in result.stderr, result.stderr
    assert "validation errors for" not in result.stderr, result.stderr
    assert "ReporterPluginConfigBase" not in result.stderr, result.stderr
    assert "Traceback" not in result.output, result.output


def test_an_unknown_key_holding_markup_is_named_as_given(tmp_path):
    """The refusal prints the configuration's key as text, not as markup.

    Printed as markup, "[/x]" in it raised, and "[red]...[/red]" tags around the
    message would have shown under --no-color only if it went back to print().
    """
    output = _project(tmp_path, "      max[/x]_retries: 3\n")

    result = _report(tmp_path, output, "aws-security-hub")

    assert result.exit_code == 3, result.output
    assert "max[/x]_retries" in result.stderr, result.stderr
    assert "[red]" not in result.stderr, result.stderr
    assert "Traceback" not in result.output, result.output


def test_the_check_is_made_whatever_format_is_asked_for(tmp_path):
    """A scan refuses the config whichever reporters it runs, so report does too.

    The wrong-typed retry option is given through ``--config-overrides``, where
    ``ash report`` reads an off-host reporter's retry options (a config file's
    value for them is ignored, as the module docstring says), and the format
    asked for is one whose reporter has no such option.
    """
    output = _project(tmp_path, "")

    result = _report(
        tmp_path,
        output,
        "markdown",
        "reporters.aws-security-hub.options.max_retries=three",
    )

    assert result.exit_code == 3, result.output
    assert "reporters.aws-security-hub.options.max_retries" in result.stderr


def test_the_refusal_is_shown_as_text_on_a_terminal(tmp_path, monkeypatch):
    """The refusal goes through _print_error, as report's other errors do.

    It is printed through _print_error, so stderr holds the message without
    rich's tags, and the option's key, which the scanned repository's config
    chooses, is shown with its controls as escapes.
    """
    import io
    import re

    from automated_security_helper.cli import report

    class _Terminal(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.delenv("NO_COLOR", raising=False)
    terminal = _Terminal()
    # report.py builds each console through utils/console.py's factory.
    real_console = report.ash_console

    def console(*args, **kwargs):
        if kwargs.pop("stderr", False):
            kwargs["file"] = terminal
        return real_console(*args, **kwargs)

    monkeypatch.setattr(report, "ash_console", console)
    # YAML escapes: \e is ESC, \a is BEL, \x9b a C1 CSI. The OSC has no
    # terminator (the BEL comes first): a complete one is removed from an
    # error's text in every print, and this cell is about controls shown as text.
    output = _project(tmp_path, '      "max[/x]\\a\\e]52;c;cGF5bG9hZA==\\x9b": 3\n')

    result = _report(tmp_path, output, "aws-security-hub")

    shown = re.sub(r"\x1b\[[0-9;]*m", "", terminal.getvalue())
    assert result.exit_code == 3, result.output
    assert "[red]" not in result.stderr + terminal.getvalue()
    assert "Invalid configuration" in shown, (shown, result.stderr)
    assert "max[/x]" in shown and "52;c;cGF5bG9hZA==" in shown
    assert [c for c in ("\x1b", "\x07", "\x9b") if c in shown] == []


_SECRET_HEAD = "canary-Zq7Kx9Lm"
_SECRET_TAIL = "Pw4Nv2Rt-canary"


@pytest.mark.parametrize("carried", [True, False], ids=["value-carried", "control"])
def test_the_refusal_hides_a_carried_value_a_complete_code_splits(tmp_path, carried):
    """The refusal prints an error's text with a carried value hidden, even where
    a complete color code splits it.

    The check refuses with a key that spells the value with a code in the middle;
    no contiguous match finds it until the code is gone, so only a redaction that
    looks past the code hides it. The control carries no value, so the same text
    prints its pieces: the absence in the first case is the redaction's.
    """
    from automated_security_helper.cli import report
    from automated_security_helper.core.exceptions import ASHConfigValidationError
    from automated_security_helper.utils.error_text import carry_environment_values

    error = ASHConfigValidationError(
        f"Unknown key '{_SECRET_HEAD}\x1b[1m{_SECRET_TAIL}' in these plugin options."
    )
    if carried:
        carry_environment_values(error, [_SECRET_HEAD + _SECRET_TAIL])
    output = _project(tmp_path, "      max_retries: 3\n")

    with patch.object(report, "refuse_unknown_plugin_options", side_effect=error):
        result = _report(tmp_path, output, "aws-security-hub")

    shown = result.stdout + result.stderr
    # The pieces are named in a failure's text, which is the only way to read it.
    seen = repr(shown.replace(_SECRET_HEAD, "<head>").replace(_SECRET_TAIL, "<tail>"))
    assert result.exit_code == 3, seen
    assert "Unknown key" in shown, seen
    if carried:
        assert _SECRET_HEAD not in shown and _SECRET_TAIL not in shown, seen
    else:
        assert _SECRET_HEAD in shown, seen


@pytest.mark.parametrize("holds_value", [True, False], ids=["value-read", "control"])
def test_the_refusal_hides_a_value_a_complete_code_splits(
    tmp_path, monkeypatch, holds_value
):
    """The refusal prints a key a complete color code splits around an environment value.

    The config reads the value from the environment (``project_name``) and also
    holds an unknown option key that spells the value with a code in the middle.
    No contiguous match finds that key's value until the code is gone, so only a
    redaction that looks past the code hides it. The control reads no value, so
    the same key prints its pieces: the absence is the redaction's.
    """
    if holds_value:
        monkeypatch.setenv("ASH_SPLIT_VALUE", _SECRET_HEAD + _SECRET_TAIL)
        name = "${ASH_SPLIT_VALUE}"
    else:
        name = "plain"
    output = _project(
        tmp_path,
        f'      "{_SECRET_HEAD}\\e[1m{_SECRET_TAIL}": 3\n',
    )
    config = tmp_path / "ash.yaml"
    config.write_text(
        config.read_text(encoding="utf-8").replace("report-option-check", name),
        encoding="utf-8",
    )

    result = _report(tmp_path, output, "aws-security-hub")

    assert result.exit_code == 3, result.output
    assert "Invalid configuration" in result.stderr, result.stderr
    shown = result.stdout + result.stderr
    # The pieces are named in a failure's text, which is the only way to read it.
    seen = repr(shown.replace(_SECRET_HEAD, "<head>").replace(_SECRET_TAIL, "<tail>"))
    if holds_value:
        assert _SECRET_HEAD not in shown, seen
        assert _SECRET_TAIL not in shown, seen
    else:
        assert _SECRET_HEAD in shown, seen


def test_control_a_valid_option_passes_the_check(tmp_path):
    output = _project(tmp_path, "      max_retries: 3\n")

    result = _report(tmp_path, output, "markdown")

    assert result.exit_code == 0, result.output
    assert "Invalid configuration" not in result.stderr, result.stderr
