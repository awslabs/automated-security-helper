# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the four console-script names ASH installs.

``ashx`` is the name. ``ash`` was the v3 name and is a deprecated alias: Alpine,
BusyBox and MSYS2 ship the Almquist shell as ``ash``, so a bare ``ash`` on PATH
is often not ASH. ``ashv3`` is deprecated because it pins a version number in the
command itself. ``automated-security-helper`` is kept indefinitely and
deliberately silent: it is the escape hatch for environments where a short name
resolves to something else.
"""

import sys
from importlib.metadata import entry_points
from unittest import mock

import pytest

from automated_security_helper.cli import entrypoint
from automated_security_helper.cli import main as cli_main
from automated_security_helper.cli.deprecations import (
    CANONICAL_CLI_NAME,
    deprecated_command_message,
    warn_deprecated_command_alias,
)


@pytest.fixture
def console_scripts():
    """The console scripts as actually installed, keyed by command name.

    Read from installed metadata rather than parsed out of pyproject.toml. It is
    the stronger assertion -- it covers what a user's PATH ends up with rather
    than what the manifest declares -- and it avoids needing a TOML parser.
    ``tomllib`` is stdlib only from 3.11 and this repo supports 3.10, where
    ``import tomllib`` at module scope would fail every test here; the fallback
    the other test modules use, ``tomli``, is not a declared dependency.
    """
    scripts = {ep.name: ep.value for ep in entry_points(group="console_scripts")}
    missing = {"ashx", "ash", "ashv3", "automated-security-helper"} - scripts.keys()
    assert not missing, (
        f"ASH's console scripts are not installed ({sorted(missing)} missing), so "
        "these assertions would pass or fail on the state of the environment "
        "rather than on the manifest. Install the package before running."
    )
    return scripts


class TestConsoleScriptTargets:
    """Every name resolves through ``cli.entrypoint``, not the bare Typer app.

    These assertions named ``cli.main:app`` until ``cli.entrypoint`` landed. pip's
    generated stub imports the target and calls it, so a target of ``app`` put the
    whole CLI import ahead of any ASH code -- and on a console-less host, where
    ``sys.stderr`` is ``None``, a failure in it exits 1 with both streams empty.
    See ``cli/entrypoint.py`` and ``test_startup_failure_diagnosability.py``, which
    resolves ``ashx`` out of the manifest for exactly that reason. So the target
    has to be a module that is cheap to import and repairs the streams first.
    """

    def test_ashx_is_the_canonical_entry_point(self, console_scripts):
        assert (
            console_scripts["ashx"] == "automated_security_helper.cli.entrypoint:main"
        )

    def test_ash_points_at_the_deprecation_wrapper(self, console_scripts):
        """``ash`` must not share ``ashx``'s target, or it could not warn."""
        assert (
            console_scripts["ash"]
            == "automated_security_helper.cli.entrypoint:main_ash"
        )

    def test_ashv3_points_at_the_warning_wrapper(self, console_scripts):
        """``ashv3`` must not share ``ashx``'s target.

        The deprecation has to fire once per invocation. Routing it through a
        dedicated entry point makes that structural: there is exactly one call
        site and it is the process entry, so it cannot fire per subcommand.

        ``main_ashv3`` is that entry point. It reaches ``cli.main:run_ashv3``, and
        the stream repair runs first so the notice itself has somewhere to go.
        """
        assert (
            console_scripts["ashv3"]
            == "automated_security_helper.cli.entrypoint:main_ashv3"
        )

    def test_long_form_is_kept_and_silent(self, console_scripts):
        """The long form shares ``main`` with ``ashx``, so it never warns."""
        assert (
            console_scripts["automated-security-helper"]
            == "automated_security_helper.cli.entrypoint:main"
        )


class TestAshv3DeprecationWarning:
    def test_it_goes_to_stderr_not_stdout(self, capsys):
        warn_deprecated_command_alias("ashv3")
        captured = capsys.readouterr()
        assert "ashv3" in captured.err
        assert captured.out == ""

    def test_it_names_ashx_as_the_replacement(self, capsys):
        warn_deprecated_command_alias("ashv3")
        err = capsys.readouterr().err
        assert "'ashx'" in err, "the warning must name the command that replaces it"

    def test_it_says_the_alias_is_going_away(self, capsys):
        warn_deprecated_command_alias("ashv3")
        assert "removal" in capsys.readouterr().err

    def test_it_fires_exactly_once_per_invocation(self, capsys):
        with mock.patch.object(cli_main, "app") as fake_app:
            cli_main.run_ashv3()
        fake_app.assert_called_once()
        err = capsys.readouterr().err
        assert err.count("ashv3") == 1, f"expected one warning, got: {err!r}"

    def test_it_still_runs_the_app(self):
        with mock.patch.object(cli_main, "app") as fake_app:
            cli_main.run_ashv3()
        fake_app.assert_called_once_with()


class TestAshAliasDeprecation:
    """``ash`` keeps working through v4: one stderr line, then the same app."""

    def test_canonical_name_is_ashx(self):
        assert CANONICAL_CLI_NAME == "ashx"

    def test_the_message_names_the_alias_and_its_replacement(self):
        message = deprecated_command_message("ash")
        assert "'ash'" in message
        assert "'ashx'" in message
        assert "removal" in message
        assert "\n" not in message, "the notice must be a single line"

    def test_it_prints_exactly_one_line_to_stderr(self, capsys):
        with mock.patch.object(cli_main, "app"):
            cli_main.run_ash_alias()
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err.splitlines() == [deprecated_command_message("ash")]

    def test_it_runs_the_app_once_with_no_arguments_changed(self):
        with mock.patch.object(cli_main, "app") as fake_app:
            cli_main.run_ash_alias()
        fake_app.assert_called_once_with()

    @pytest.mark.parametrize("code", [0, 1, 2, 3, 4])
    def test_exit_codes_pass_through_unchanged(self, capsys, code):
        """Through the real console-script target, ``main_ash``.

        0 is a clean scan, 1 an actionable failure (findings or an incomplete
        scan), 2 a usage error, 3 an invalid configuration and 4 a workspace
        definition, policy or confinement error. The alias must not map, swallow
        or add to any of them, and the notice must still be one line whatever
        the outcome.
        """
        with mock.patch.object(cli_main, "app", side_effect=SystemExit(code)):
            with pytest.raises(SystemExit) as raised:
                entrypoint.main_ash()
        assert raised.value.code == code
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err.splitlines() == [deprecated_command_message("ash")]

    @pytest.mark.parametrize("code", [0, 1, 2, 3, 4])
    def test_ashx_passes_the_same_codes_with_no_notice(self, capsys, code):
        """Negative control: the canonical name exits the same way, silently."""
        with mock.patch.object(cli_main, "app", side_effect=SystemExit(code)):
            with pytest.raises(SystemExit) as raised:
                entrypoint.main()
        assert raised.value.code == code
        assert capsys.readouterr().err == ""


class TestOtherEntryPointsDoNotWarn:
    """Negative controls. Without these, a warning wired into the Typer app
    itself -- firing for ``ashx`` too, and once per subcommand -- would pass every
    test above."""

    def test_invoking_the_app_directly_emits_no_deprecation(self, capsys):
        from typer.testing import CliRunner

        result = CliRunner().invoke(cli_main.app, ["--help"])
        assert result.exit_code == 0
        assert "deprecated" not in result.output
        assert "deprecated" not in capsys.readouterr().err

    def test_a_subcommand_emits_no_deprecation(self, capsys):
        from typer.testing import CliRunner

        result = CliRunner().invoke(cli_main.app, ["report", "--help"])
        assert result.exit_code == 0
        assert "deprecated" not in result.output
        assert "deprecated" not in capsys.readouterr().err

    def test_the_warning_is_not_registered_as_an_app_callback(self):
        """The alias wrappers must be plain functions, not Typer commands.

        If the deprecation were added as a Typer callback it would fire on the
        ``ashx`` name as well, and on group callbacks it can fire more than once.
        """
        for wrapper in (cli_main.run_ashv3, cli_main.run_ash_alias):
            assert callable(wrapper)
            assert not hasattr(wrapper, "__click_params__")


class TestDeprecatedRevisionSpellingWarns:
    """``--ash-revision`` and ``-rev`` are accepted, but they announce the name
    that replaces them rather than merely calling themselves deprecated."""

    @pytest.mark.parametrize("spelling", ["--ash-revision", "-rev"])
    def test_the_warning_names_the_replacement(self, capsys, spelling):
        from automated_security_helper.cli.deprecations import (
            warn_deprecated_option_spellings,
        )

        with mock.patch.object(sys, "argv", ["ashx", spelling, "v3.1.0"]):
            warn_deprecated_option_spellings()
        err = capsys.readouterr().err
        assert spelling in err
        assert "--ash-revision-to-install" in err

    def test_the_canonical_spelling_is_silent(self, capsys):
        from automated_security_helper.cli.deprecations import (
            warn_deprecated_option_spellings,
        )

        with mock.patch.object(
            sys, "argv", ["ashx", "--ash-revision-to-install", "v3.1.0"]
        ):
            warn_deprecated_option_spellings()
        assert capsys.readouterr().err == ""

    def test_it_goes_to_stderr(self, capsys):
        from automated_security_helper.cli.deprecations import (
            warn_deprecated_option_spellings,
        )

        with mock.patch.object(sys, "argv", ["ashx", "--ash-revision", "v3.1.0"]):
            warn_deprecated_option_spellings()
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "--ash-revision" in captured.err
