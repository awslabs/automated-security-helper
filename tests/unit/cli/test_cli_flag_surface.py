# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Flag-surface regression tests for the consolidated ``ash`` CLI.

The root ``ash`` bash script used to own a parallel flag surface and was deleted
when the Python CLI absorbed it. These tests pin the v2-era spellings that had
no Python equivalent, and they pin the two behaviors most easily lost again:
``scan`` must reject an unknown flag, and ``build-image`` must still forward one.

Two measurement traps are handled explicitly rather than assumed away.

Parsing is exercised through ``make_context`` instead of ``CliRunner``. A bogus
flag that the parser *accepts* would otherwise invoke the command and run a real
scan, so a regression here would show up as a slow test rather than a failing
one. ``make_context`` parses and binds parameters without invoking anything.

No test appends ``--help`` to probe whether some other flag is accepted.
``--help`` is eager in click and short-circuits before validation, so a
deliberately bogus flag "passes" that way and the check measures nothing.
"""

import click
import pytest
import typer.main

from automated_security_helper.cli.main import app


def _usage_error_types():
    """Every exception class that means "the parser refused this argv".

    typer vendors its own copy of click under ``typer._click``. Commands built
    by ``typer.main.get_command`` therefore raise
    ``typer._click.exceptions.UsageError``, which is NOT a subclass of the
    standalone ``click.UsageError``. Catching only the standalone class makes
    every rejection look like an unexpected crash and every one of these tests
    pass for the wrong reason.
    """
    types = [click.UsageError]
    try:
        from typer._click import exceptions as vendored

        types.append(vendored.UsageError)
    except ImportError:  # pragma: no cover - older typer without the vendor
        pass
    return tuple(types)


USAGE_ERRORS = _usage_error_types()

ROOT = ()
SCAN = ("scan",)
REPORT = ("report",)
BUILD_IMAGE = ("build-image",)


def _resolve(path):
    """Walk from the root group to the command named by ``path``."""
    root = typer.main.get_command(app)
    cmd = root
    ctx = click.Context(root, info_name="ash")
    for name in path:
        cmd = cmd.get_command(ctx, name)
        assert cmd is not None, f"no such command: {name}"
        ctx = click.Context(cmd, parent=ctx, info_name=name)
    return root, cmd


def _parse(path, argv):
    """Parse ``argv`` against a command and return the bound parameters.

    Raises the parser's usage error if the argv is rejected.
    """
    root, cmd = _resolve(path)
    parent = click.Context(root, info_name="ash") if path else None
    ctx = cmd.make_context(
        path[-1] if path else "ash",
        list(argv),
        parent=parent,
        resilient_parsing=False,
    )
    return ctx.params


def _rejects(path, argv):
    """True when the parser refuses ``argv``."""
    try:
        _parse(path, argv)
    except USAGE_ERRORS:
        return True
    return False


def _spellings(path):
    """Every option spelling declared on a command.

    Reads ``opts``/``secondary_opts`` rather than filtering on
    ``isinstance(p, click.Option)``: the params are typer's vendored
    ``TyperOption``, so an isinstance check against standalone click matches
    none of them and the set comes back empty.
    """
    _, cmd = _resolve(path)
    found = set()
    for param in cmd.params:
        found.update(getattr(param, "opts", []) or [])
        found.update(getattr(param, "secondary_opts", []) or [])
    return found


class TestProbeIntegrity:
    """Controls. If these fail, nothing else in the module means anything."""

    def test_a_valid_flag_is_accepted(self):
        assert _parse(ROOT, ["--quiet"])["quiet"] is True

    def test_a_bogus_flag_is_rejected_somewhere(self):
        # `report` rejected unknown flags before this change and must still do
        # so. If this fails, _rejects() cannot detect a rejection at all.
        assert _rejects(REPORT, ["--zzz-not-an-option"])

    def test_introspection_sees_options(self):
        assert len(_spellings(SCAN)) > 20


class TestV2RevisionAliases:
    """``--ash-revision`` and ``-rev`` came from the deleted bash script."""

    @pytest.mark.parametrize("path", [ROOT, SCAN, BUILD_IMAGE])
    @pytest.mark.parametrize(
        "spelling", ["--ash-revision-to-install", "--ash-revision", "-rev"]
    )
    def test_every_spelling_binds_to_ash_revision_to_install(self, path, spelling):
        params = _parse(path, [spelling, "v3.1.0"])
        assert params["ash_revision_to_install"] == "v3.1.0"

    @pytest.mark.parametrize("path", [ROOT, SCAN, BUILD_IMAGE])
    def test_dash_rev_is_one_token_not_three_short_flags(self, path):
        """``-rev`` must not be parsed as ``-r -e -v``.

        Single-dash multi-character options are unusual, and click's short-option
        matcher splits an unrecognized ``-rev`` into characters. ``-r`` exists on
        these commands, so a split would silently set the wrong parameter (or
        fail on ``-e``) instead of setting the revision. Asserting only that
        ``-rev`` is accepted would not catch that; this asserts ``verbose`` is
        untouched, which a ``-r -e -v`` split could not leave alone.
        """
        params = _parse(path, ["-rev", "v3.1.0"])
        assert params["ash_revision_to_install"] == "v3.1.0"
        assert params["verbose"] is False


class TestQuietShortForm:
    def test_q_binds_to_quiet(self):
        assert _parse(ROOT, ["-q"])["quiet"] is True

    def test_build_image_q_binds_to_quiet(self):
        assert _parse(BUILD_IMAGE, ["-q"])["quiet"] is True

    def test_long_form_still_works(self):
        assert _parse(ROOT, ["--quiet"])["quiet"] is True

    def test_negation_was_not_dropped(self):
        """``--quiet`` was an implicit ``--quiet/--no-quiet`` pair.

        Naming the flag explicitly to attach ``-q`` would drop ``--no-quiet``
        unless the pair is spelled out, which is a silent breaking change for
        anyone who passes it.
        """
        assert _parse(ROOT, ["--no-quiet"])["quiet"] is False
        assert "--no-quiet" in _spellings(ROOT)


class TestVersionShortForm:
    """``-V``, not ``-v``: ``-v`` is ``--verbose`` and must stay that way."""

    def test_capital_V_binds_to_version(self):
        assert _parse(ROOT, ["-V"])["version"] is True

    def test_lowercase_v_still_binds_to_verbose(self):
        params = _parse(ROOT, ["-v"])
        assert params["verbose"] is True
        assert params["version"] is False

    def test_capital_V_prints_a_version_and_exits(self):
        from typer.testing import CliRunner

        result = CliRunner().invoke(app, ["-V"])
        assert result.exit_code == 0, result.output
        assert "automated-security-helper v" in result.output

    def test_capital_V_matches_long_form_output(self):
        from typer.testing import CliRunner

        runner = CliRunner()
        assert (
            runner.invoke(app, ["-V"]).output
            == runner.invoke(app, ["--version"]).output
        )


class TestHelpShortForm:
    """click injects ``--help`` only; ``-h`` needs ``help_option_names``."""

    @pytest.mark.parametrize("path", [[], ["scan"], ["build-image"], ["report"]])
    def test_dash_h_shows_help(self, path):
        from typer.testing import CliRunner

        result = CliRunner().invoke(app, list(path) + ["-h"])
        assert result.exit_code == 0, result.output
        assert "Usage:" in result.output

    def test_dash_h_matches_long_form(self):
        from typer.testing import CliRunner

        runner = CliRunner()
        assert (
            runner.invoke(app, ["-h"]).output == runner.invoke(app, ["--help"]).output
        )


class TestUnknownFlagsAreRejected:
    """``scan`` used to swallow unknown flags and run a full scan anyway."""

    def test_scan_rejects_an_unknown_flag(self):
        assert _rejects(SCAN, ["--totally-bogus-flag"])

    def test_bare_ash_rejects_an_unknown_flag(self):
        """The root callback shares ``scan``'s function but not its settings.

        Removing the pass-through from the ``scan`` command would not touch this
        path, so it is pinned separately.
        """
        assert _rejects(ROOT, ["--totally-bogus-flag"])

    def test_report_still_rejects_an_unknown_flag(self):
        assert _rejects(REPORT, ["--totally-bogus-flag"])

    def test_scan_still_accepts_its_real_flags(self):
        """Guard against fixing the rejection by breaking the parser."""
        params = _parse(SCAN, ["--quiet", "--verbose", "-rev", "v3.1.0"])
        assert params["quiet"] is True
        assert params["verbose"] is True
        assert params["ash_revision_to_install"] == "v3.1.0"


class TestBuildImageStillForwardsExtraArgs:
    """The one command whose pass-through is deliberate.

    ``build-image``'s help text promises that additional arguments are forwarded
    to ASH inside the container, so tightening it along with ``scan`` would break
    a documented contract.
    """

    def test_build_image_accepts_an_unknown_flag(self):
        assert not _rejects(BUILD_IMAGE, ["--totally-bogus-flag"])

    def test_build_image_context_settings_still_allow_extra_args(self):
        _, cmd = _resolve(BUILD_IMAGE)
        assert cmd.context_settings.get("allow_extra_args") is True
        assert cmd.context_settings.get("ignore_unknown_options") is True
