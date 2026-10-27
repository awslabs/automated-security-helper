# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash mcp`` accepts exactly the options ``mcp_command`` declares.

Why this file exists
--------------------
``ash mcp`` is registered in ``cli/main.py`` as ``_mcp_wrapper``, a lazy wrapper
that imports ``cli/mcp`` (and with it the MCP SDK, about 0.6 s) only when the
command runs. The wrapper redeclares every option of ``mcp_command`` and forwards
each one, so the two lists have to match:

- ``--profile`` is on both, or ``ash mcp --profile x=y`` fails with "No such
  option" and no profile can be registered: every ``list_profiles`` call on a
  real server returns an empty list and every ``select_profile`` fails.
- ``-v`` and ``-d`` are on both.
- ``--log-level`` is a choice on both; a free string on the wrapper would accept
  ``--log-level bogus`` and silently treat it as INFO.
- ``--quiet`` has one default on both, or the documented default depends on which
  of the two a reader looks at.

A check of one flag each in the ``--help`` text (as in ``test_mcp_streamable_http.py``
and ``test_mcp_stateless_http.py``) lets a whole option go missing with the suite
green. Here the click
parameters of the two commands are compared field by field, and a CLI invocation
checks that every parameter is forwarded, so an option added to one side only
fails this file.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

import pytest
import typer
import typer.main
from typer.testing import CliRunner

from automated_security_helper.cli.main import app as ash_app
from automated_security_helper.cli.mcp import mcp_command
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text: str) -> str:
    """Strip Rich's styling and collapse whitespace, so wrapped text reads as one line."""
    return " ".join(_ANSI.sub("", text).split())


def _describe(command) -> Dict[str, Dict[str, Any]]:
    """Every click parameter of ``command``, as the fields a user can observe."""
    described: Dict[str, Dict[str, Any]] = {}
    for param in command.params:
        param_type = param.type
        described[param.name] = {
            "kind": type(param).__name__,
            "opts": sorted(param.opts),
            "secondary_opts": sorted(param.secondary_opts),
            "default": param.default,
            "multiple": param.multiple,
            "is_flag": getattr(param, "is_flag", None),
            "required": param.required,
            "type": type(param_type).__name__,
            "choices": tuple(getattr(param_type, "choices", ()) or ()),
            "case_sensitive": getattr(param_type, "case_sensitive", None),
            "help": getattr(param, "help", None),
            "envvar": getattr(param, "envvar", None),
        }
    return described


def _wrapper_command():
    return typer.main.get_command(ash_app).commands["mcp"]


def _inner_command():
    inner_app = typer.Typer(add_completion=False)
    inner_app.command(name="mcp")(mcp_command)
    return typer.main.get_command(inner_app)


class TestTheWrapperMirrorsMcpCommand:
    def test_every_option_is_declared_identically(self):
        """Names, flags, defaults, types, choices and help, for every option."""
        wrapper = _describe(_wrapper_command())
        inner = _describe(_inner_command())

        missing = sorted(set(inner) - set(wrapper))
        extra = sorted(set(wrapper) - set(inner))
        assert not missing and not extra, (
            f"`ash mcp` and mcp_command declare different options. Only on "
            f"mcp_command (unreachable from the CLI): {missing}. Only on the "
            f"wrapper: {extra}."
        )
        differing = {
            name: {"wrapper": wrapper[name], "mcp_command": inner[name]}
            for name in inner
            if wrapper[name] != inner[name]
        }
        assert not differing, (
            "`ash mcp` declares these options differently from mcp_command, so the "
            f"CLI's flags or defaults are not the ones documented: {differing}"
        )

    def test_the_comparison_can_fail(self):
        """Control: a real difference in one field is reported.

        Without this, a ``_describe`` that dropped every field would make the
        parity assertion above pass for any pair of commands.
        """
        inner = _describe(_inner_command())
        tampered = {name: dict(fields) for name, fields in inner.items()}
        tampered["quiet"]["default"] = not tampered["quiet"]["default"]
        assert tampered != inner


def _non_default_arguments(tmp_path: Path):
    """CLI arguments that set every mcp_command option away from its default."""
    profile = tmp_path / "dev.yaml"
    profile.write_text("project_name: dev\n", encoding="utf-8")
    value_file = tmp_path / "token"
    value_file.write_text("secret-value\n", encoding="utf-8")
    argv = [
        "mcp",
        "--log-level",
        "DEBUG",
        "-v",
        "-d",
        "--no-color",
        "--no-quiet",
        "--transport",
        "streamable-http",
        "--host",
        "127.0.0.2",
        "--port",
        "8123",
        "--mount-path",
        "/other",
        "--auth-header-name",
        "X-Token",
        "--auth-header-value",
        "secret-value",
        "--auth-header-value-file",
        str(value_file),
        "--auth-header-value-fd",
        "3",
        "--stateless-http",
        "--trust-upstream-session-id",
        "--allowed-host",
        "a.example",
        "--allowed-host",
        "b.example",
        "--session-workspace-ttl",
        "3600",
        "--trust-upstream-host-check",
        "--profile",
        f"dev={profile}",
    ]
    # Values that contradict each other on a real run (three sources of the auth
    # value; --allowed-host with --trust-upstream-host-check) are refused by
    # mcp_command, which this test replaces: here only the parse and the
    # forwarding are measured.
    expected = {
        "log_level": "DEBUG",
        "verbose": True,
        "debug": True,
        "color": False,
        "quiet": False,
        "transport": "streamable-http",
        "host": "127.0.0.2",
        "port": 8123,
        "mount_path": "/other",
        "auth_header_name": "X-Token",
        "auth_header_value": "secret-value",
        "auth_header_value_file": value_file,
        "auth_header_value_fd": 3,
        "stateless_http": True,
        "trust_upstream_session_id": True,
        "allowed_host": ["a.example", "b.example"],
        "session_workspace_ttl": 3600,
        "trust_upstream_host_check": True,
        "profile": [f"dev={profile}"],
    }
    return argv, expected


class TestEveryOptionReachesMcpCommand:
    def test_every_parsed_value_is_forwarded(self, tmp_path):
        """The wrapper hands mcp_command every option, with the value parsed."""
        import inspect

        argv, expected = _non_default_arguments(tmp_path)
        received: Dict[str, Any] = {}

        def _record(**kwargs):
            received.update(kwargs)

        with patch("automated_security_helper.cli.mcp.mcp_command", _record):
            result = CliRunner().invoke(ash_app, argv)

        assert result.exit_code == 0, _plain(result.output)
        received.pop("ctx", None)
        declared = set(inspect.signature(mcp_command).parameters) - {"ctx"}
        assert set(received) == declared, (
            f"The wrapper forwards {sorted(received)} but mcp_command declares "
            f"{sorted(declared)}"
        )
        # The enum arrives as its member; compare by value so the expectation
        # stays readable.
        normalized = {
            key: getattr(value, "value", value) for key, value in received.items()
        }
        normalized = {
            key: list(value) if isinstance(value, tuple) else value
            for key, value in normalized.items()
        }
        assert normalized == expected
        assert set(expected) == declared, "the expectation must cover every option"


@pytest.fixture
def _restore_mcp_process_state(monkeypatch):
    """mcp_command sets ASH_LOG_TO_STDERR and may fill the profile registry."""
    from automated_security_helper.cli.mcp import profile_registry

    monkeypatch.setenv("ASH_LOG_TO_STDERR", "1")
    profile_registry.clear_profile_registry()
    yield
    profile_registry.clear_profile_registry()


@pytest.mark.usefixtures("_restore_mcp_process_state")
class TestTheRealCommandLine:
    """Through ``ash``'s own app, as a user types it. Nothing binds a port."""

    def test_profile_is_accepted_and_registered(self, tmp_path):
        from automated_security_helper.cli.mcp import profile_registry

        profile = tmp_path / "dev.yaml"
        profile.write_text("project_name: dev\n", encoding="utf-8")
        with patch("automated_security_helper.cli.mcp_server.run_mcp_server") as run:
            result = CliRunner().invoke(ash_app, ["mcp", "--profile", f"dev={profile}"])

        output = _plain(result.output)
        assert "No such option" not in output, output
        assert result.exit_code == 0, output
        run.assert_called_once()
        assert set(profile_registry.get_profile_registry()) == {"dev"}

    def test_a_bad_profile_fails_startup_with_exit_3(self, tmp_path):
        missing = tmp_path / "absent.yaml"
        with patch("automated_security_helper.cli.mcp_server.run_mcp_server") as run:
            # Wide enough that Rich does not wrap the message inside the path.
            result = CliRunner().invoke(
                ash_app, ["mcp", "--profile", f"dev={missing}"], env={"COLUMNS": "300"}
            )

        output = _plain(result.output)
        assert result.exit_code == 3, output
        assert "absent.yaml" in output, output
        run.assert_not_called()

    @pytest.mark.parametrize("flag", ["-v", "-d", "--verbose", "--debug"])
    def test_verbose_and_debug_work_without_no_quiet(self, flag):
        """The default is not quiet, so -v and -d need no extra flag.

        ``--transport bogus`` stops the command at validation, after the
        verbose/quiet check, so the message proves which check ran.
        """
        result = CliRunner().invoke(ash_app, ["mcp", flag, "--transport", "bogus"])

        output = _plain(result.output)
        # An unknown --transport is a usage error.
        assert result.exit_code == ASH_EXIT_USAGE_ERROR, output
        assert "--transport must be one of" in output, output
        assert "Cannot use --quiet" not in output, output

    def test_the_negative_forms_parse(self):
        """``--no-verbose`` and ``--no-debug`` are accepted."""
        result = CliRunner().invoke(
            ash_app,
            ["mcp", "--no-verbose", "--no-debug", "--transport", "bogus"],
        )

        output = _plain(result.output)
        assert result.exit_code == ASH_EXIT_USAGE_ERROR, output
        assert "--transport must be one of" in output, output

    @pytest.mark.parametrize("spelling", ["debug", "Debug", "DEBUG"])
    def test_the_log_level_takes_any_case(self, spelling):
        """As `ash scan --log-level` does: `ash mcp --log-level debug` was refused."""
        from automated_security_helper.core.enums import AshLogLevel

        received: Dict[str, Any] = {}

        def _record(**kwargs):
            received.update(kwargs)

        with patch("automated_security_helper.cli.mcp.mcp_command", _record):
            result = CliRunner().invoke(ash_app, ["mcp", "--log-level", spelling])

        assert result.exit_code == 0, _plain(result.output)
        assert received["log_level"] is AshLogLevel.DEBUG

    def test_an_unknown_log_level_is_refused(self):
        result = CliRunner().invoke(
            ash_app, ["mcp", "--log-level", "bogus", "--transport", "bogus"]
        )

        output = _plain(result.output)
        # click's refusal of a value, which ASH exits with its usage-error code.
        assert result.exit_code == ASH_EXIT_USAGE_ERROR, output
        assert "Invalid value" in output and "bogus" in output, output

    def test_help_lists_every_option(self):
        """What the CDK entrypoint and a reader see: ``ash mcp --help``."""
        # Wide, as the CDK entrypoint runs it (COLUMNS=200), so Rich does not
        # split a long flag such as --no-stateless-http across two lines.
        result = CliRunner().invoke(ash_app, ["mcp", "--help"], env={"COLUMNS": "200"})

        assert result.exit_code == 0, result.output
        flat = _plain(result.output)
        for flag in (
            "--profile",
            "-v",
            "-d",
            "--log-level",
            "--stateless-http",
            "--no-stateless-http",
            "--allowed-host",
        ):
            assert flag in flat, f"Missing {flag} in `ash mcp --help`:\n{flat}"
