# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the installer's verdict, its counters, and --tool selection.

The test this file exists for is
``test_every_command_list_empty_does_not_report_success``. Before this change the
installer printed "All dependencies installed successfully!" in exactly that
situation, and grype, syft and trivy were all in it -- so the happiest output the
command could produce was also its report for having installed nothing. That is
the same defect class as a scanner that never runs and still exits 0.

The second thing under test is that the verdict reaches the *process*. A Typer
command's return value is discarded, so the previous implementation could print
"Some dependencies failed to install (exit code: 1)" and exit 0. A verdict its
caller cannot observe is not a verdict.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import typer
from typer.testing import CliRunner

from automated_security_helper.cli.dependencies import (
    EXIT_BAD_SELECTION,
    EXIT_INSTALL_FAILED,
    EXIT_OK,
    PluginInstallOutcome,
    _report_and_exit,
    dependencies_app,
)

runner = CliRunner()


def _outcome(**kwargs) -> PluginInstallOutcome:
    base = {"name": "tool", "plugin_type": "scanner", "command": "tool"}
    base.update(kwargs)
    return PluginInstallOutcome(**base)


class TestVerdictIsDerivedFromCounts:
    def test_every_command_list_empty_does_not_report_success(self):
        """The named requirement: nothing installed must not read as success.

        Three scanners with no install path, each reporting zero commands. The old
        code's exit code stayed 0 through exactly this and printed the success
        panel.
        """
        outcomes = [
            _outcome(name="grype", command="grype"),
            _outcome(name="syft", command="syft"),
            _outcome(name="trivy-repo", command="trivy"),
        ]
        with pytest.raises(typer.Exit) as exc:
            _report_and_exit(outcomes, requested_tools=[])
        assert exc.value.exit_code == EXIT_INSTALL_FAILED

    def test_a_successful_install_reports_success(self):
        """Positive control for the test above.

        Without it, the failure assertion could pass because _report_and_exit
        refuses every input rather than because nothing was installed.
        """
        outcomes = [
            _outcome(
                name="grype",
                commands_attempted=1,
                commands_succeeded=1,
                executable="/bin/grype",
            )
        ]
        assert _report_and_exit(outcomes, requested_tools=[]) == EXIT_OK

    def test_a_failed_command_fails_the_run(self):
        outcomes = [
            _outcome(
                name="cfn-nag",
                command="cfn_nag_scan",
                commands_attempted=1,
                commands_failed=1,
            )
        ]
        with pytest.raises(typer.Exit) as exc:
            _report_and_exit(outcomes, requested_tools=[])
        assert exc.value.exit_code == EXIT_INSTALL_FAILED

    def test_a_plugin_error_fails_the_run(self):
        outcomes = [
            _outcome(
                name="grype",
                commands_attempted=1,
                commands_succeeded=1,
                executable="/bin/grype",
                errors=["boom"],
            )
        ]
        with pytest.raises(typer.Exit) as exc:
            _report_and_exit(outcomes, requested_tools=[])
        assert exc.value.exit_code == EXIT_INSTALL_FAILED

    def test_an_unsatisfied_explicit_request_fails_the_run(self):
        """Asking for a tool by name and not getting it is a failure.

        The command ran and exited 0, but the tool the caller named is not on PATH
        -- which is the silent success in miniature.
        """
        outcomes = [
            _outcome(
                name="grype",
                commands_attempted=1,
                commands_succeeded=1,
                executable=None,
            )
        ]
        with pytest.raises(typer.Exit) as exc:
            _report_and_exit(outcomes, requested_tools=["grype"])
        assert exc.value.exit_code == EXIT_INSTALL_FAILED

    def test_requesting_a_python_only_plugin_succeeds(self):
        """`--tool sarif` must not fail for lacking a binary.

        `executable` is only ever populated for plugins that have a command, so a
        request check that only tested `not o.executable` failed for every reporter
        and for the archive converter -- plugins that were never going to have one.
        """
        outcomes = [_outcome(name="sarif", plugin_type="reporter", command=None)]
        assert _report_and_exit(outcomes, requested_tools=["sarif"]) == EXIT_OK

    def test_requesting_an_unprovisionable_tool_that_is_present_succeeds(self):
        """`--tool npm-audit` on a machine with node is a no-op, not a failure.

        ASH installed nothing, and it also had nothing to install: npm-audit needs a
        Node runtime ASH does not provide. Exiting non-zero when the desired end
        state already holds is a false alarm, and the docstring of the verdict
        function commits to treating this as a constraint rather than a malfunction.
        """
        outcomes = [_outcome(name="npm-audit", command="npm", executable="/usr/bin/npm")]
        assert _report_and_exit(outcomes, requested_tools=["npm-audit"]) == EXIT_OK

    def test_requesting_an_unprovisionable_tool_that_is_absent_fails(self):
        """The other half: asked for it, cannot install it, do not have it.

        This is the counterpart that keeps the test above from being a licence to
        exit 0 whenever nothing was attempted -- which is the original bug.
        """
        outcomes = [_outcome(name="grype", command="grype", executable=None)]
        with pytest.raises(typer.Exit) as exc:
            _report_and_exit(outcomes, requested_tools=["grype"])
        assert exc.value.exit_code == EXIT_INSTALL_FAILED

    def test_nothing_attempted_but_everything_present_is_not_a_failure(self):
        """A whole run that had nothing to do is a no-op, not a failure.

        Distinguished from the original bug by whether anything is still absent: the
        scanners that were silently missing were both unprovisionable *and* not on
        PATH.
        """
        outcomes = [
            _outcome(name="npm-audit", command="npm", executable="/usr/bin/npm"),
            _outcome(
                name="detect-secrets",
                command="detect-secrets",
                executable="/usr/bin/detect-secrets",
            ),
        ]
        assert _report_and_exit(outcomes, requested_tools=[]) == EXIT_OK

    def test_python_only_plugins_do_not_fail_a_run(self):
        """Reporters and converters have no external binary to find.

        A sweep that demanded an executable for every plugin would report failures
        for plugins that were never going to have one.
        """
        outcomes = [
            _outcome(name="sarif", plugin_type="reporter", command=None),
            _outcome(
                name="grype",
                commands_attempted=1,
                commands_succeeded=1,
                executable="/bin/grype",
            ),
        ]
        assert _report_and_exit(outcomes, requested_tools=[]) == EXIT_OK

    def test_a_tool_with_no_install_path_is_named_not_hidden(self, capsys):
        """npm-audit needs a Node runtime ASH does not install.

        That is a constraint rather than a malfunction, so it does not fail the run
        on its own -- but it must appear in the output. Reporting it only when the
        tool is also absent would hide it on every machine that happens to have
        node, which is every machine ASH's own CI runs on.
        """
        outcomes = [
            _outcome(name="npm-audit", command="npm", executable="/usr/bin/npm"),
            _outcome(
                name="grype",
                commands_attempted=1,
                commands_succeeded=1,
                executable="/bin/grype",
            ),
        ]
        assert _report_and_exit(outcomes, requested_tools=[]) == EXIT_OK
        assert "npm-audit" in capsys.readouterr().out


class TestOutcomeStatus:
    def test_no_install_path_when_a_tool_is_needed_and_absent(self):
        assert _outcome(name="grype").status == "NO INSTALL PATH"

    def test_already_present_when_found_without_installing(self):
        assert _outcome(name="npm-audit", executable="/usr/bin/npm").status == (
            "ALREADY PRESENT"
        )

    def test_installed_but_not_on_path_is_distinguished_from_installed(self):
        installed = _outcome(
            name="grype", commands_attempted=1, commands_succeeded=1, executable="/x"
        )
        stranded = _outcome(
            name="grype", commands_attempted=1, commands_succeeded=1, executable=None
        )
        assert installed.status == "INSTALLED"
        assert stranded.status == "INSTALLED (not on PATH)"

    def test_failed_outranks_everything_else(self):
        assert (
            _outcome(
                name="grype",
                commands_attempted=1,
                commands_failed=1,
                executable="/x",
            ).status
            == "FAILED"
        )

    def test_a_plugin_that_raised_is_not_reported_as_having_no_install_path(self):
        """A crash is an unknown install path, not an absent one.

        Reporting a plugin that blew up under "no install path on this platform"
        gives the wrong diagnosis in the function whose whole job is honest
        reporting -- it reads as a documented constraint rather than a bug.
        """
        crashed = _outcome(name="grype", errors=["boom"])
        assert crashed.declared_no_commands is False
        assert _outcome(name="grype").declared_no_commands is True


class TestEmptyArgvIsSkipped:
    """Drives the install loop, because the counters are what the verdict reads.

    The previous version of this test asserted `declared_no_commands is True` on an
    outcome constructed with `commands_skipped_empty=3` -- but that property reads
    `commands_attempted`, which defaults to 0, so the assertion was `0 == 0` and the
    3 was inert. It passed with the skip branch deleted. These drive the real loop.
    """

    def _run(self, tmp_path, monkeypatch, commands):
        monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
        fake = MagicMock()
        fake.config = SimpleNamespace(name="fake-scanner")
        fake.command = "fake-scanner"
        fake.get_installation_commands.return_value = commands

        monkeypatch.setattr(
            "automated_security_helper.cli.dependencies.load_plugins",
            lambda *_a, **_k: {},
        )
        monkeypatch.setattr(
            "automated_security_helper.cli.dependencies.ash_plugin_manager",
            SimpleNamespace(
                plugin_modules=lambda kind: [lambda **_kw: fake]
                if kind == "scanner"
                else []
            ),
        )
        ran = []
        monkeypatch.setattr(
            "automated_security_helper.cli.dependencies.run_command",
            lambda cmd, shell=False: ran.append(cmd) or 0,
        )
        result = runner.invoke(
            dependencies_app,
            ["--plugin-type", "scanner", "--bin-path", str(tmp_path / "bin")],
        )
        return result, ran

    def test_an_empty_argv_is_not_executed(self, tmp_path, monkeypatch):
        result, ran = self._run(tmp_path, monkeypatch, [[], ["echo", "real"]])
        assert ran == [["echo", "real"]], "an empty argv was handed to run_command"
        assert "Skipping an empty install command" in result.output

    def test_only_empty_argv_counts_as_nothing_attempted(self, tmp_path, monkeypatch):
        """A plugin declaring only empty entries has attempted nothing.

        Before the skip existed these reached run_command, failed, and pushed the
        exit code to 1 -- which then went nowhere, because the returned code was
        discarded. Either way the run must not read as a success.
        """
        result, ran = self._run(tmp_path, monkeypatch, [[], []])
        assert ran == []
        assert result.exit_code == EXIT_INSTALL_FAILED
        assert "no install commands were run" in result.output


class TestToolSelectionScopesFailures:
    """A --tool run must not fail for an unrelated plugin that would not construct.

    The discovery loop records a failure for every plugin whose constructor raises,
    and that happens before the --tool filter. Folding those into the verdict
    unconditionally meant
    `ash dependencies install --config .ash/.ash_community_plugins.yaml --tool
    trivy-repo` -- the command this change adds to CI -- exited 1 whenever any other
    community plugin failed to import, and named that other plugin in the panel.
    """

    def _invoke(self, tmp_path, monkeypatch, args):
        monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
        good = MagicMock()
        good.config = SimpleNamespace(name="good-scanner")
        good.command = "good-scanner"
        good.get_installation_commands.return_value = [["echo", "install"]]

        class Broken:
            def __init__(self, **_kwargs):
                raise RuntimeError("this plugin will not construct")

        monkeypatch.setattr(
            "automated_security_helper.cli.dependencies.load_plugins",
            lambda *_a, **_k: {},
        )
        monkeypatch.setattr(
            "automated_security_helper.cli.dependencies.ash_plugin_manager",
            SimpleNamespace(
                plugin_modules=lambda kind: [lambda **_kw: good, Broken]
                if kind == "scanner"
                else []
            ),
        )
        monkeypatch.setattr(
            "automated_security_helper.cli.dependencies.run_command",
            lambda cmd, shell=False: 0,
        )
        monkeypatch.setattr(
            "automated_security_helper.cli.dependencies.find_executable",
            lambda cmd: f"/usr/bin/{cmd}",
        )
        return runner.invoke(
            dependencies_app,
            ["--plugin-type", "scanner", "--bin-path", str(tmp_path / "bin"), *args],
        )

    def test_a_targeted_run_ignores_an_unrelated_broken_plugin(
        self, tmp_path, monkeypatch
    ):
        result = self._invoke(tmp_path, monkeypatch, ["--tool", "good-scanner"])
        assert result.exit_code == EXIT_OK, result.output
        # The load problem is still surfaced -- suppressing it would hide a plugin
        # that cannot run -- but it is not this run's verdict.
        assert "Installation Incomplete" not in result.output
        assert "could not be loaded" in result.output

    def test_an_unnarrowed_run_still_fails_on_a_broken_plugin(
        self, tmp_path, monkeypatch
    ):
        """The other half: without --tool, the run answers for every plugin.

        Without this, scoping the failure set could have been implemented by dropping
        construction failures altogether, which would hide a plugin that cannot load.
        """
        result = self._invoke(tmp_path, monkeypatch, [])
        assert result.exit_code == EXIT_INSTALL_FAILED
        assert "Broken" in result.output

    def test_an_unknown_tool_says_some_plugins_failed_to_load(
        self, tmp_path, monkeypatch
    ):
        """A name missing because its plugin would not load is not a typo.

        The declared name of a plugin that never constructed is unknowable, so this
        does not claim a match -- it says plugins failed to load and names their
        classes, so the reader is not sent hunting for a spelling mistake.
        """
        result = self._invoke(tmp_path, monkeypatch, ["--tool", "not-a-real-tool"])
        assert result.exit_code == EXIT_BAD_SELECTION
        assert "failed to load" in result.output
        assert "Broken" in result.output


class TestToolSelection:
    """Invoked through the CLI, isolated so it cannot leak into other tests.

    `install_dependencies` sets os.environ["ASH_BIN_PATH"], and CliRunner runs
    in-process -- so without monkeypatch.setenv these tests would leave that
    variable set for every later test sharing the xdist worker, changing where
    find_executable looks.
    """

    @pytest.fixture(autouse=True)
    def _isolate(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
        self.bin_args = ["--bin-path", str(tmp_path / "bin")]

    def test_unknown_tool_exits_two_and_lists_what_exists(self):
        result = runner.invoke(
            dependencies_app, ["--tool", "nonexistent", *self.bin_args]
        )
        assert result.exit_code == EXIT_BAD_SELECTION
        assert "Unknown tool" in result.output
        # The available list is what makes the error actionable rather than a wall.
        assert "grype" in result.output

    def test_unknown_tool_installs_nothing(self):
        """A bad selection must be refused before any command runs.

        Checked by asserting the failure panel says nothing was installed; the
        alternative -- installing everything and then complaining -- would be worse
        than the typo.
        """
        result = runner.invoke(
            dependencies_app, ["--tool", "nonexistent", *self.bin_args]
        )
        assert "Nothing installed" in result.output
        assert "Running command" not in result.output
