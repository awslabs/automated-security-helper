# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Debug and verbose output has to reach the console in CI (#628).

Two defects, each enough on its own to leave a CI log empty:

* ``ASH_DEBUG``/``ASH_VERBOSE`` were read only by the execution engine, for the
  Rich live panel. ``_resolve_log_level`` read CLI flags alone, so the env var
  left the console at INFO.
* ``_setup_logger`` and the orchestrator decided separately whether the live
  panel would run. The panel owns console output when it runs, so the console
  handler is left off; but the orchestrator also refused the panel under ``CI``
  and for VERBOSE/DEBUG and ``_setup_logger`` did not. Where they disagreed
  there was no sink at all.
"""

import logging

import pytest
from rich.logging import RichHandler
from typer.testing import CliRunner

from automated_security_helper.core.enums import AshLogLevel
from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    _apply_log_level_env,
    _live_progress_enabled,
    _resolve_log_level,
    _setup_logger,
)
from automated_security_helper.utils.log import ASH_LOGGER

_ENV = ("ASH_DEBUG", "ASH_VERBOSE", "CI", "ASH_IN_CONTAINER")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in _ENV:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def restore_ash_logger():
    handlers = list(ASH_LOGGER.handlers)
    yield
    for handler in ASH_LOGGER.handlers:
        if handler not in handlers:
            handler.close()
    ASH_LOGGER.handlers = handlers


def _opts(tmp_path, **kwargs):
    return ScanOptions(source_dir=tmp_path, output_dir=tmp_path / "out", **kwargs)


class TestPrecedence:
    @pytest.mark.parametrize(
        "env,expected",
        [
            ({}, AshLogLevel.INFO),
            ({"ASH_DEBUG": "true"}, AshLogLevel.DEBUG),
            ({"ASH_DEBUG": "YES"}, AshLogLevel.DEBUG),
            ({"ASH_DEBUG": "on"}, AshLogLevel.DEBUG),
            ({"ASH_VERBOSE": "1"}, AshLogLevel.VERBOSE),
            ({"ASH_DEBUG": "NO"}, AshLogLevel.INFO),
            ({"ASH_DEBUG": "maybe"}, AshLogLevel.INFO),
            # Both set: the more detailed one.
            ({"ASH_DEBUG": "true", "ASH_VERBOSE": "true"}, AshLogLevel.DEBUG),
        ],
    )
    def test_env_applies_when_no_flag_is_given(
        self, tmp_path, monkeypatch, env, expected
    ):
        for name, value in env.items():
            monkeypatch.setenv(name, value)

        assert _resolve_log_level(_opts(tmp_path)) == expected

    @pytest.mark.parametrize(
        "flags,expected",
        [
            ({"quiet": True}, AshLogLevel.ERROR),
            ({"simple": True}, AshLogLevel.ERROR),
            ({"verbose": True}, AshLogLevel.VERBOSE),
            ({"log_level": AshLogLevel.ERROR}, AshLogLevel.ERROR),
            ({"log_level": AshLogLevel.TRACE}, AshLogLevel.TRACE),
        ],
    )
    def test_a_cli_flag_beats_the_env(self, tmp_path, monkeypatch, flags, expected):
        monkeypatch.setenv("ASH_DEBUG", "true")

        assert _resolve_log_level(_opts(tmp_path, **flags)) == expected

    def test_the_env_level_is_recorded_as_the_flag(self, tmp_path, monkeypatch):
        """Container and nix mode forward opts.debug, not the console level."""
        monkeypatch.setenv("ASH_DEBUG", "true")
        opts = _opts(tmp_path)

        _apply_log_level_env(opts)

        assert opts.debug is True and opts.verbose is False

    def test_a_cli_flag_is_left_alone(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ASH_DEBUG", "true")
        opts = _opts(tmp_path, quiet=True)

        _apply_log_level_env(opts)

        assert opts.debug is False


class TestTheConsoleHasASink:
    @pytest.mark.parametrize(
        "env,flags",
        [
            ({"CI": "true"}, {}),
            ({"CI": "true"}, {"verbose": True}),
            ({"ASH_IN_CONTAINER": "YES"}, {"debug": True}),
            ({}, {"debug": True}),
            ({}, {"verbose": True}),
            ({}, {"quiet": True}),
        ],
    )
    def test_no_live_panel_means_a_console_handler(
        self, tmp_path, monkeypatch, restore_ash_logger, env, flags
    ):
        for name, value in env.items():
            monkeypatch.setenv(name, value)
        opts = _opts(tmp_path, progress=True, **flags)

        assert _live_progress_enabled(opts) is False
        logger = _setup_logger(opts)

        assert any(isinstance(h, RichHandler) for h in logger.handlers), (
            "no live panel and no console handler: every log line is dropped"
        )

    def test_the_live_panel_replaces_the_console_handler(
        self, tmp_path, restore_ash_logger
    ):
        opts = _opts(tmp_path, progress=True)

        assert _live_progress_enabled(opts) is True
        logger = _setup_logger(opts)

        assert not any(isinstance(h, RichHandler) for h in logger.handlers)

    def test_ash_debug_in_the_container_reaches_the_console_at_debug(
        self, tmp_path, monkeypatch, restore_ash_logger
    ):
        """The reported setup: ASH image, env var, no CLI flag."""
        monkeypatch.setenv("ASH_IN_CONTAINER", "YES")
        monkeypatch.setenv("ASH_DEBUG", "true")
        opts = _opts(tmp_path, progress=True)
        _apply_log_level_env(opts)

        logger = _setup_logger(opts)

        (console,) = [h for h in logger.handlers if isinstance(h, RichHandler)]
        assert console.level == logging.DEBUG


class TestCli:
    """envvar= on --debug/--verbose must not let the env outrank a CLI flag."""

    def _invoke(self, monkeypatch, args, env):
        from automated_security_helper.cli import scan as scan_cli
        from automated_security_helper.cli.main import app

        seen = {}

        def fake_run_ash_scan(**kwargs):
            seen.update(kwargs)

        monkeypatch.setattr(scan_cli, "run_ash_scan", fake_run_ash_scan)
        result = CliRunner().invoke(app, ["scan", *args], env=env)
        assert result.exit_code == 0, result.output
        return seen

    def test_env_debug_is_left_to_run_ash_scan(self, monkeypatch, tmp_path):
        seen = self._invoke(
            monkeypatch, ["--source-dir", str(tmp_path)], {"ASH_DEBUG": "true"}
        )

        # Dropped at the CLI so run_ash_scan applies it below the flags; it
        # still resolves to DEBUG there.
        assert seen["debug"] is False
        opts = ScanOptions(
            source_dir=tmp_path, output_dir=tmp_path / "o", log_level=seen["log_level"]
        )
        monkeypatch.setenv("ASH_DEBUG", "true")
        assert _resolve_log_level(opts) == AshLogLevel.DEBUG

    def test_env_debug_does_not_beat_quiet(self, monkeypatch, tmp_path):
        seen = self._invoke(
            monkeypatch,
            ["--source-dir", str(tmp_path), "--quiet"],
            {"ASH_DEBUG": "true"},
        )
        monkeypatch.setenv("ASH_DEBUG", "true")

        opts = ScanOptions(
            source_dir=tmp_path,
            output_dir=tmp_path / "o",
            debug=seen["debug"],
            quiet=seen["quiet"],
        )
        assert _resolve_log_level(opts) == AshLogLevel.ERROR

    def test_the_flag_itself_still_works(self, monkeypatch, tmp_path):
        seen = self._invoke(monkeypatch, ["--source-dir", str(tmp_path), "--debug"], {})

        assert seen["debug"] is True

    def test_help_documents_both_variables(self):
        from automated_security_helper.cli.main import app

        result = CliRunner().invoke(app, ["scan", "--help"], env={"COLUMNS": "250"})

        assert "ASH_DEBUG" in result.output
        assert "ASH_VERBOSE" in result.output
