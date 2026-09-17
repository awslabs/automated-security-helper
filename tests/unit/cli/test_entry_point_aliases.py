# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the three console-script names ASH installs.

``ash`` is the name. ``ashv3`` is deprecated because it pins a version number in
the command itself, so it reads wrong the moment v4 exists.
``automated-security-helper`` is kept indefinitely and deliberately silent: it is
the escape hatch for environments where a bare ``ash`` resolves to something
else. That collision is real rather than hypothetical -- MSYS2 ships the Almquist
shell as ``ash`` and it has already shadowed ASH's entry point.
"""

import sys
from importlib.metadata import entry_points
from unittest import mock

import pytest

from automated_security_helper.cli import main as cli_main


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
    missing = {"ash", "ashv3", "automated-security-helper"} - scripts.keys()
    assert not missing, (
        f"ASH's console scripts are not installed ({sorted(missing)} missing), so "
        "these assertions would pass or fail on the state of the environment "
        "rather than on the manifest. Install the package before running."
    )
    return scripts


class TestConsoleScriptTargets:
    def test_ash_points_at_the_app(self, console_scripts):
        assert console_scripts["ash"] == "automated_security_helper.cli.main:app"

    def test_ashv3_points_at_the_warning_wrapper(self, console_scripts):
        """``ashv3`` must not share ``ash``'s target.

        The deprecation has to fire once per invocation. Routing it through a
        dedicated entry point makes that structural: there is exactly one call
        site and it is the process entry, so it cannot fire per subcommand.
        """
        assert (
            console_scripts["ashv3"] == "automated_security_helper.cli.main:run_ashv3"
        )

    def test_long_form_is_kept_and_silent(self, console_scripts):
        assert (
            console_scripts["automated-security-helper"]
            == "automated_security_helper.cli.main:app"
        )


class TestAshv3DeprecationWarning:
    def test_it_goes_to_stderr_not_stdout(self, capsys):
        cli_main._warn_ashv3_deprecation()
        captured = capsys.readouterr()
        assert "ashv3" in captured.err
        assert captured.out == ""

    def test_it_names_ash_as_the_replacement(self, capsys):
        cli_main._warn_ashv3_deprecation()
        err = capsys.readouterr().err
        assert "'ash'" in err, "the warning must name the command that replaces it"

    def test_it_says_the_alias_is_going_away(self, capsys):
        cli_main._warn_ashv3_deprecation()
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


class TestOtherEntryPointsDoNotWarn:
    """Negative controls. Without these, a warning wired into the Typer app
    itself -- firing for ``ash`` too, and once per subcommand -- would pass every
    test above."""

    def test_invoking_the_app_directly_emits_no_deprecation(self, capsys):
        from typer.testing import CliRunner

        result = CliRunner().invoke(cli_main.app, ["--help"])
        assert result.exit_code == 0
        assert "ashv3" not in result.output
        assert "ashv3" not in capsys.readouterr().err

    def test_a_subcommand_emits_no_deprecation(self, capsys):
        from typer.testing import CliRunner

        result = CliRunner().invoke(cli_main.app, ["report", "--help"])
        assert result.exit_code == 0
        assert "ashv3" not in result.output
        assert "ashv3" not in capsys.readouterr().err

    def test_the_warning_is_not_registered_as_an_app_callback(self):
        """``run_ashv3`` must be a plain function, not a Typer command.

        If the deprecation were added as a Typer callback it would fire on the
        ``ash`` name as well, and on group callbacks it can fire more than once.
        """
        assert callable(cli_main.run_ashv3)
        assert not hasattr(cli_main.run_ashv3, "__click_params__")


class TestDeprecatedRevisionSpellingWarns:
    """``--ash-revision`` and ``-rev`` are accepted, but they announce the name
    that replaces them rather than merely calling themselves deprecated."""

    @pytest.mark.parametrize("spelling", ["--ash-revision", "-rev"])
    def test_the_warning_names_the_replacement(self, capsys, spelling):
        from automated_security_helper.cli.deprecations import (
            warn_deprecated_option_spellings,
        )

        with mock.patch.object(sys, "argv", ["ash", spelling, "v3.1.0"]):
            warn_deprecated_option_spellings()
        err = capsys.readouterr().err
        assert spelling in err
        assert "--ash-revision-to-install" in err

    def test_the_canonical_spelling_is_silent(self, capsys):
        from automated_security_helper.cli.deprecations import (
            warn_deprecated_option_spellings,
        )

        with mock.patch.object(
            sys, "argv", ["ash", "--ash-revision-to-install", "v3.1.0"]
        ):
            warn_deprecated_option_spellings()
        assert capsys.readouterr().err == ""

    def test_it_goes_to_stderr(self, capsys):
        from automated_security_helper.cli.deprecations import (
            warn_deprecated_option_spellings,
        )

        with mock.patch.object(sys, "argv", ["ash", "--ash-revision", "v3.1.0"]):
            warn_deprecated_option_spellings()
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "--ash-revision" in captured.err
