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

from typer.testing import CliRunner
import pytest
import typer

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

    def test_declared_no_commands_counts_attempts_not_declarations(self):
        """An empty argv is not an attempt.

        Empty command lists reached run_command before this change and failed; they
        are now skipped and counted separately, so a plugin that declared only
        empty entries still reports as having attempted nothing.
        """
        outcome = _outcome(name="syft", commands_skipped_empty=3)
        assert outcome.declared_no_commands is True


class TestToolSelection:
    def test_unknown_tool_exits_two_and_lists_what_exists(self):
        result = runner.invoke(dependencies_app, ["--tool", "nonexistent"])
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
        result = runner.invoke(dependencies_app, ["--tool", "nonexistent"])
        assert "Nothing installed" in result.output
        assert "Running command" not in result.output
