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

import io
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar, List, Optional
from unittest.mock import MagicMock

import pytest
import typer
from rich.console import Console
from typer.testing import CliRunner

from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.cli import dependencies as dependencies_module
from automated_security_helper.utils.uv_tool_runner import is_checking_only
from tests.utils.helpers import checkout_env
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


@pytest.mark.unit
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
        outcomes = [
            _outcome(name="npm-audit", command="npm", executable="/usr/bin/npm")
        ]
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


@pytest.mark.unit
class TestOutcomeStatus:
    def test_no_install_path_when_a_tool_is_needed_and_absent(self):
        assert _outcome(name="grype").status == "NO INSTALL PATH"

    def test_already_present_when_found_without_installing(self):
        assert _outcome(name="npm-audit", executable="/usr/bin/npm").status == (
            "ALREADY PRESENT"
        )

    def test_verified_but_off_path_names_the_scans_resolution(self):
        """The verified-present branch mirrors the installed one: a pinned
        binary already on disk, off PATH, whose check says a scan can run it is
        not reported beside a summary that says the same thing another way."""
        runnable = _outcome(
            name="grype", commands_satisfied=1, executable=None, runnable_by_scan=True
        )
        stranded = _outcome(name="grype", commands_satisfied=1, executable=None)
        assert runnable.status == "VERIFIED (a scan can run it)"
        assert stranded.status == "VERIFIED (not on PATH)"

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


@pytest.mark.unit
class TestEmptyArgvIsSkipped:
    """Drives the install loop, because the counters are what the verdict reads.

    The previous version of this test asserted `declared_no_commands is True` on an
    outcome constructed with `commands_skipped_empty=3` -- but that property reads
    `commands_attempted`, which defaults to 0, so the assertion was `0 == 0` and the
    3 was inert. It passed with the skip branch deleted. These drive the real loop.
    """

    def _run(self, tmp_path, monkeypatch, commands):
        monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
        # The command reads the working directory's .ash/.ash.yaml.
        monkeypatch.chdir(tmp_path)
        fake = MagicMock()
        fake.config = SimpleNamespace(name="fake-scanner")
        fake.command = "fake-scanner"
        fake.get_installation_commands.return_value = commands
        # The sweep never asks this fake: it only asks a plugin whose
        # resolves_tool_off_path is True, and a MagicMock attribute is a Mock,
        # not True (_declares_off_path_resolution). The explicit False stays so
        # the stub answers like an absent tool if that gate ever widens.
        fake.validate_plugin_dependencies.return_value = False

        monkeypatch.setattr(
            "automated_security_helper.cli.dependencies.load_plugins",
            lambda *_a, **_k: {},
        )
        monkeypatch.setattr(
            "automated_security_helper.cli.dependencies.ash_plugin_manager",
            SimpleNamespace(
                plugin_modules=lambda kind: (
                    [lambda **_kw: fake] if kind == "scanner" else []
                )
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


@pytest.mark.unit
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
        # The command reads the working directory's .ash/.ash.yaml.
        monkeypatch.chdir(tmp_path)
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
                plugin_modules=lambda kind: (
                    [lambda **_kw: good, Broken] if kind == "scanner" else []
                )
            ),
        )
        monkeypatch.setattr(
            "automated_security_helper.cli.dependencies.run_command",
            lambda cmd, shell=False: 0,
        )
        monkeypatch.setattr(
            "automated_security_helper.cli.dependencies.find_executable_for_scan",
            lambda cmd, root: f"/usr/bin/{cmd}",
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

    WHY THESE ASSERTIONS DO NOT READ ``result.output``

    CliRunner captures by swapping ``sys.stdout``, and pytest's logging plugin
    suspends and resumes global capture around log records -- on resume
    ``sys.stdout`` is pytest's capture object rather than the runner's. ASH emits
    its first log records while loading plugins, which happens once per process,
    so everything the command prints after that point misses the runner's buffer
    on the first invocation in a worker and reaches it on every later one.

    Measured rather than reasoned: this test failed run first and passed run
    second, passes under ``-p no:logging``, passes under ``-s``, and the missing
    "Nothing installed" panel accounts for the entire 451-byte difference between
    a first and a second invocation's captured length.

    The product is not affected. A real ``ash dependencies install --tool
    nonexistent`` prints the panel and exits 2;
    ``test_unknown_tool_reaches_a_real_stdout`` asserts that out of process, which
    is the only place it can honestly be asserted.

    So the installer's console is pinned to a buffer these tests own. That also
    repairs a negative assertion that had been passing vacuously: on a truncated
    capture, ``"Running command" not in result.output`` holds whether or not the
    text was printed, because the text it looks for was cut off rather than never
    written.
    """

    @pytest.fixture(autouse=True)
    def _isolate(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
        # The command reads the working directory's .ash/.ash.yaml.
        monkeypatch.chdir(tmp_path)
        self.bin_args = ["--bin-path", str(tmp_path / "bin")]
        # width, so Rich does not wrap a string an assertion looks for across two
        # lines; no_color, so it does not interleave ANSI inside one.
        self.panels = io.StringIO()
        monkeypatch.setattr(
            dependencies_module,
            "console",
            Console(file=self.panels, width=200, no_color=True),
        )

    @pytest.mark.unit
    def test_unknown_tool_exits_two_and_lists_what_exists(self):
        result = runner.invoke(
            dependencies_app, ["--tool", "nonexistent", *self.bin_args]
        )
        assert result.exit_code == EXIT_BAD_SELECTION
        printed = self.panels.getvalue()
        assert "Unknown tool" in printed
        # The available list is what makes the error actionable rather than a wall.
        assert "grype" in printed

    @pytest.mark.unit
    def test_unknown_tool_installs_nothing(self):
        """A bad selection must be refused before any command runs.

        Checked by asserting the failure panel says nothing was installed; the
        alternative -- installing everything and then complaining -- would be worse
        than the typo.
        """
        result = runner.invoke(
            dependencies_app, ["--tool", "nonexistent", *self.bin_args]
        )
        assert result.exit_code == EXIT_BAD_SELECTION
        printed = self.panels.getvalue()
        assert "Nothing installed" in printed
        assert "Running command" not in printed

    @pytest.mark.integration
    def test_unknown_tool_reaches_a_real_stdout(self, tmp_path, monkeypatch):
        """The rejection has to be visible to a person, not only to a test double.

        Every other assertion in this class reads a console this test pinned, which
        proves what the code printed but not where it went. Running the installed
        entry point in its own process is what shows an operator who typed a tool
        name wrong gets told so, and gets a non-zero status to act on.
        """
        ash = shutil.which("ash")
        if ash is None:
            pytest.skip("the `ash` console script is not on PATH in this environment")
        # `ash dependencies install` writes install receipts under its HOME, which a
        # child inherits; tests/conftest.py refuses to start one with the developer's.
        monkeypatch.setenv("HOME", str(tmp_path / "home"))
        monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
        # encoding and errors are load-bearing, and not for tidiness.
        #
        # `text=True` on its own decodes the pipe with
        # locale.getpreferredencoding(False), which is cp1252 on a Windows runner. The
        # child writes UTF-8: utils/log.py::configure_windows_safe_logging reconfigures
        # ash's own stdout to UTF-8 whenever a CI indicator is in the environment. Rich
        # then draws this panel with box-drawing glyphs, and on Windows it draws them
        # with box.SQUARE rather than box.ROUNDED, because rich.box.Box.substitute
        # swaps ROUNDED out when options.legacy_windows is set and a piped stdout
        # reports no VT support. SQUARE's top-right corner is U+2510, which is e2 94 90
        # in UTF-8, and 0x90 is unassigned in cp1252. Rounded corners would have
        # decoded into mojibake without complaint, which is why this went unnoticed.
        #
        # The decode error does not reach this frame. On Windows, Popen._communicate
        # reads each pipe on a daemon thread whose body is `buffer.append(fh.read())`,
        # so a raising read appends nothing, and the function ends with
        # `stdout = stdout[0] if stdout else None`. An empty buffer is falsy, so
        # subprocess.run returns a CompletedProcess whose stdout is None having raised
        # nothing at all -- the returncode assertion above still passes. That is what
        # failed all five Windows legs: first as `TypeError: argument of type
        # 'NoneType' is not iterable`, then, after this assertion was rewritten to read
        # both streams, as `TypeError: unsupported operand type(s) for +: 'NoneType'
        # and 'str'`. Neither shape was a console-width problem.
        #
        # errors="replace" is the part that closes the class rather than this instance:
        # no byte can make the reader thread raise, so a captured stream cannot come
        # back None again. tests/unit/utils/test_windows_console_encoding.py pins the
        # mechanism on every platform.
        proc = subprocess.run(
            [ash, "dependencies", "install", "--tool", "nonexistent", *self.bin_args],
            env=checkout_env(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=900,
        )
        assert proc.returncode == EXIT_BAD_SELECTION

        # Rich wraps the panel to its default width for a pipe, which can put a newline
        # and border padding inside the phrase being searched for, and which stream
        # carries the panel is not fixed either -- see configure_windows_safe_logging
        # above. Blanking the whole box-drawing block and collapsing whitespace rejoins
        # a wrapped phrase; searching both streams removes the second question. An
        # enumerated glyph list was tried first and was one glyph short, so the range is
        # deliberate. This still fails if the message is absent or renamed, which is
        # what the test is for.
        rendered = " ".join(
            (proc.stdout + "\n" + proc.stderr)
            .translate(dict.fromkeys(range(0x2500, 0x2580), " "))
            .replace("|", " ")
            .split()
        )
        assert "Unknown tool" in rendered, (
            f"the rejection did not reach the operator. returncode={proc.returncode}. "
            f"Rendered output: {rendered[:400]}"
        )
        assert "Nothing installed" in rendered


def _install_one_fake_scanner(
    tmp_path,
    monkeypatch,
    *,
    scan_can_run,
    commands=(("echo", "install"),),
    requested=True,
    on_path=None,
    configure=None,
    command_rc=0,
    extra_args=(),
):
    """``ash dependencies install`` over one fake scanner, through the CLI.

    Its install commands exit ``command_rc``. ``find_executable`` answers ``on_path`` for
    every name (None: the tool's shim is in a directory off PATH), and the
    plugin's own dependency check -- the one a scan runs -- answers
    ``scan_can_run``. The fake declares ``resolves_tool_off_path``, the opt-in
    for a check that can start its tool off PATH, which is the only kind the
    sweep consults. ``requested`` names it with ``--tool``; otherwise the run is
    a full one over this single plugin. ``configure`` is called with the fake
    before the run, to give it a context or a check of its own.
    """
    fake = _fake_scanner(scan_can_run=scan_can_run, commands=commands)
    if configure is not None:
        configure(fake)
    result = _install_fake_scanners(
        tmp_path,
        monkeypatch,
        [fake],
        tools=("fake-scanner",) if requested else (),
        command_rc=command_rc,
        on_path=on_path,
        extra_args=extra_args,
    )
    return result, fake


def _fake_scanner(
    name="fake-scanner",
    command="fake-scanner",
    *,
    scan_can_run,
    commands=(("echo", "install"),),
    declared=True,
):
    """A stand-in scanner: its check answers ``scan_can_run``, and ``declared``
    is its ``resolves_tool_off_path``."""
    fake = MagicMock()
    fake.config = SimpleNamespace(name=name)
    fake.command = command
    fake.resolves_tool_off_path = declared
    fake.get_installation_commands.return_value = [list(cmd) for cmd in commands]
    fake.validate_plugin_dependencies.return_value = scan_can_run
    return fake


def _builds(fake):
    return lambda **_kw: fake


#: A value a configuration reads from the environment, quoted by a reason.
DEPVERDICT_CANARY = "ENVCANARY-depverdict-0123456789"


def _refused_line(label: str) -> str:
    """The failure line for an absent tool whose own check was asked and said
    no, for ``label`` (the tool's name, with its missing programs)."""
    return (
        f"{label}: not on PATH, and its own dependency check (asked in "
        "check-only mode) did not find a tool to start"
    )


def _config_reading_the_environment(tmp_path):
    """A configuration file that reads ``ASH_DEPVERDICT_LIBRARY`` from the
    environment, so the run's config carries that value to redact."""
    config = tmp_path / "depverdict.yaml"
    config.write_text("project_name: ${ASH_DEPVERDICT_LIBRARY}\n", encoding="utf-8")
    return config


class _RefusingPluginConfig(ScannerPluginConfigBase):
    name: str = "refusing-plugin"


class _RefusingPlugin(ScannerPluginBase[_RefusingPluginConfig]):
    """A scanner whose own check refuses, with a reason quoting the canary.

    Its hook records whether it was asked in check-only mode, in
    ``asked_checking_only``: the reason is plugin code, asked in the scope the
    check runs in."""

    resolves_tool_off_path: ClassVar[bool] = True
    asked_checking_only: ClassVar[List[bool]] = []

    def model_post_init(self, context):
        if self.config is None:
            self.config = _RefusingPluginConfig()
        self.command = "refusing-plugin"
        super().model_post_init(context)

    def get_installation_commands(self, platform, arch):
        return [["echo", "install"]]

    def validate_plugin_dependencies(self) -> bool:
        return False

    def missing_dependency_reason(self):
        type(self).asked_checking_only.append(is_checking_only())
        return f"needs a library under /opt/{DEPVERDICT_CANARY}/lib"

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError  # pragma: no cover

    def scan(self, target, target_type, global_ignore_paths=None, config=None):
        raise NotImplementedError  # pragma: no cover


#: A value only the plugin itself knows to redact: none of the run's config.
OWN_CANARY = "ENVCANARY-own-9876543210"


class _PluginWithItsOwnValues(_RefusingPlugin):
    """A plugin whose ``_environment_values()`` adds a value of its own to the
    run's, and whose reason quotes that one."""

    def _environment_values(self):
        return (*super()._environment_values(), OWN_CANARY)

    def missing_dependency_reason(self):
        return f"needs a key file under /etc/{OWN_CANARY}/keys"


class _BaseHookPluginConfig(ScannerPluginConfigBase):
    name: str = "base-hook-plugin"


class _BaseHookPlugin(ScannerPluginBase[_BaseHookPluginConfig]):
    """A scanner that keeps the base ``missing_dependency_reason()`` and whose
    check refuses without recording a reason, the shape most shipped plugins
    have. Its command is on no PATH, so the base hook's answer is its
    "not found on PATH ... install it with `ash dependencies install`" one.
    ``recorded`` is the reason its check records, when a cell gives one."""

    resolves_tool_off_path: ClassVar[bool] = True
    recorded: ClassVar[Optional[str]] = None

    def model_post_init(self, context):
        if self.config is None:
            self.config = _BaseHookPluginConfig()
        self.command = "ash-depverdict-base-hook-tool"
        super().model_post_init(context)

    def get_installation_commands(self, platform, arch):
        return [["echo", "install"]]

    def validate_plugin_dependencies(self) -> bool:
        if type(self).recorded is not None:
            self.dependency_unavailable_reason = type(self).recorded
        return False

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError  # pragma: no cover

    def scan(self, target, target_type, global_ignore_paths=None, config=None):
        raise NotImplementedError  # pragma: no cover


class _FallingBackPlugin(_BaseHookPlugin):
    """A scanner whose own ``missing_dependency_reason()`` names one case and
    falls back to the base hook otherwise, the common shape of an override.
    ``special`` says whether the case holds."""

    special: ClassVar[bool] = False

    def missing_dependency_reason(self):
        if type(self).special:
            return "needs its rules bundle unpacked first"
        return super().missing_dependency_reason()


def _install_one_plugin_class(tmp_path, monkeypatch, plugin_class, tool):
    """``ash dependencies install --tool <tool>`` over one plugin class the
    command constructs, with a configuration that reads ASH_DEPVERDICT_LIBRARY."""
    monkeypatch.setenv("ASH_DEPVERDICT_LIBRARY", DEPVERDICT_CANARY)
    config = _config_reading_the_environment(tmp_path)
    return _install_fake_scanners(
        tmp_path,
        monkeypatch,
        [plugin_class],
        tools=(tool,),
        extra_args=("--config", str(config)),
        build=lambda cls: cls,
    )


def _install_fake_scanners(
    tmp_path,
    monkeypatch,
    fakes,
    *,
    tools=(),
    command_rc=0,
    on_path=None,
    extra_args=(),
    build=_builds,
):
    """``ash dependencies install`` over ``fakes``, in order, through the CLI.

    ``build`` turns each into what the plugin manager lists: by default a
    factory that ignores its arguments and returns the stand-in; a plugin class
    is listed as itself, so the command constructs it.

    Run from ``tmp_path``: from any other working directory the command reads
    that directory's ``.ash/.ash.yaml``, so a cell's verdict would depend on
    where pytest was started. The installer's console is pinned to a buffer this
    helper owns, folded into the returned ``output``: CliRunner's capture can
    lose what the command prints after a worker's first log record (see
    TestToolSelection's docstring), so a panel assertion against it could pass
    or fail by worker history. Width 240, so no asserted string wraps; no_color,
    so none is split by color codes.
    """
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    monkeypatch.chdir(tmp_path)
    panels = io.StringIO()
    monkeypatch.setattr(
        dependencies_module,
        "console",
        Console(file=panels, width=240, no_color=True),
    )
    monkeypatch.setattr(
        "automated_security_helper.cli.dependencies.load_plugins",
        lambda *_a, **_k: {},
    )
    monkeypatch.setattr(
        "automated_security_helper.cli.dependencies.ash_plugin_manager",
        SimpleNamespace(
            plugin_modules=lambda kind: (
                [build(fake) for fake in fakes] if kind == "scanner" else []
            )
        ),
    )
    monkeypatch.setattr(
        "automated_security_helper.cli.dependencies.run_command",
        lambda cmd, shell=False: command_rc,
    )
    monkeypatch.setattr(
        "automated_security_helper.cli.dependencies.find_executable_for_scan",
        lambda cmd, root: on_path,
    )
    args = ["--plugin-type", "scanner", "--bin-path", str(tmp_path / "bin")]
    args += list(extra_args)
    for tool in tools:
        args += ["--tool", tool]
    result = runner.invoke(dependencies_app, args)
    return SimpleNamespace(
        exit_code=result.exit_code,
        output=result.output + panels.getvalue(),
        exception=result.exception,
    )


@pytest.mark.unit
class TestAPluginLoadRefusalIsRedacted:
    """The catch-all invalid-configuration arm redacts the run's values.

    ``load_plugins`` can refuse with any ASHConfigValidationError, and that
    text can carry a value the configuration read from the environment. The
    install failure arms below print through ``error_text`` with the run's
    values; this arm printed ``error_text(e)`` alone, so the value reached
    the console - the anticipated-by-nobody arm is exactly where an
    unredacted value is likeliest.
    """

    def test_a_load_refusal_quoting_an_env_value_prints_it_redacted(
        self, tmp_path, monkeypatch
    ):
        from automated_security_helper.cli.dependencies import EXIT_INVALID_CONFIG
        from automated_security_helper.core.exceptions import (
            ASHConfigValidationError,
        )

        monkeypatch.setenv("ASH_DEPVERDICT_LIBRARY", DEPVERDICT_CANARY)
        config = _config_reading_the_environment(tmp_path)
        monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
        monkeypatch.chdir(tmp_path)
        panels = io.StringIO()
        monkeypatch.setattr(
            dependencies_module,
            "console",
            Console(file=panels, width=240, no_color=True),
        )

        def refuses(*_a, **_k):
            raise ASHConfigValidationError(
                f"a plugin requirement under /opt/{DEPVERDICT_CANARY}/lib is refused"
            )

        monkeypatch.setattr(
            "automated_security_helper.cli.dependencies.load_plugins", refuses
        )

        result = runner.invoke(
            dependencies_app,
            [
                "--plugin-type",
                "scanner",
                "--bin-path",
                str(tmp_path / "bin"),
                "--config",
                str(config),
            ],
        )

        output = result.output + panels.getvalue()
        assert result.exit_code == EXIT_INVALID_CONFIG, output
        assert "Invalid configuration" in output, output
        assert DEPVERDICT_CANARY not in output, output
        # The PLANTED refusal must be the one shown (its canary redacted).
        # Without this, a run that refuses earlier for another reason - the
        # same exit 3 and the same "Invalid configuration" - passes with the
        # canary never printed: measured, a mismatched probe variable (setenv
        # on one name, the config template reading another) left the whole
        # file green with this cell proving nothing.
        assert "a plugin requirement under /opt/<value>/lib is refused" in output, (
            output
        )


@pytest.mark.unit
class TestScanResolutionSatisfiesARequest:
    """A requested tool a scan can start is an install success, PATH or not.

    A scan decides whether a scanner's tool is there with the plugin's own
    ``validate_plugin_dependencies``, which can start a tool that is not on PATH
    (a third-party plugin's own lookup). The verdict judged a requested tool by
    the PATH lookup alone, so a tool every scan starts was reported "still not
    on PATH" with exit 1. For a plugin not run through uv, the post-install sweep
    asks that check when the PATH lookup does not find the tool, and a tool the
    check can start is present, with the PATH note informational. A tool run
    through ``uv tool run`` is judged by uv's listing, as before.
    """

    def test_a_requested_tool_the_scan_can_run_succeeds(self, tmp_path, monkeypatch):
        result, _ = _install_one_fake_scanner(tmp_path, monkeypatch, scan_can_run=True)
        assert result.exit_code == EXIT_OK, result.output
        assert "Installation Complete" in result.output
        # The PATH note is informational: the tool is named as reachable through
        # the resolution a scan uses, not as a failure.
        assert "Not on PATH; a scan can run them: fake-scanner" in result.output
        # One story, not three: the row says what resolution the tool has, the
        # "Resolved to" column names it, and the not-found warning does not list
        # a tool the run just said a scan can run.
        assert "INSTALLED (a scan can run it)" in result.output
        assert "its own dependency check" in result.output
        assert "Install ran but tool not found on PATH" not in result.output

    def test_the_consult_is_shown(self, tmp_path, monkeypatch):
        """The sweep says when it asks a plugin's own check, the way each
        install command is shown with "Running command:": the check is this
        verdict's only evidence for the tool, and it is the plugin's code."""
        result, _ = _install_one_fake_scanner(tmp_path, monkeypatch, scan_can_run=True)
        assert (
            "Asking fake-scanner's own dependency check whether a scan can run "
            "its tool" in result.output
        ), result.output

    def test_a_requested_tool_nothing_can_run_fails(self, tmp_path, monkeypatch):
        """The counterpart that keeps the check from being a licence to pass:
        the same run with the scan's resolution answering False keeps the exit-1
        verdict, on one line that says both things the sweep found. The tool is
        not on PATH, and putting it there would make the sweep find it. Its own
        check, asked in check-only mode (its install step skipped), did not
        find a tool to start: a scan, which installs, can still answer
        differently."""
        result, _ = _install_one_fake_scanner(tmp_path, monkeypatch, scan_can_run=False)
        assert result.exit_code == EXIT_INSTALL_FAILED, result.output
        assert _refused_line("fake-scanner") in result.output, result.output
        assert "still not on PATH: fake-scanner" not in result.output, result.output

    def test_a_refused_tool_s_missing_programs_are_named_on_its_line(
        self, tmp_path, monkeypatch
    ):
        """The refused line names the tool the way the other absent-tool lines
        do, with the programs it needs besides its command that the sweep did
        not find (cdk-nag's node), not only in the summary."""

        def configure(fake):
            fake.external_executables = ("node",)

        result, _ = _install_one_fake_scanner(
            tmp_path, monkeypatch, scan_can_run=False, configure=configure
        )
        assert result.exit_code == EXIT_INSTALL_FAILED, result.output
        assert _refused_line("fake-scanner (node)") in result.output, result.output

    def test_a_check_that_says_no_gives_its_reason_redacted(
        self, tmp_path, monkeypatch
    ):
        """The reason the scan's MISSING row will show is said here too, with
        values read from the environment redacted. The row reads the plugin's
        ``missing_dependency_reason()``, so that is what this one gives.

        The value is one the run's configuration read, and the stand-in has no
        values of its own to give: the scan's row redacts with the
        configuration's values, so this line must too, whatever the plugin
        object answers."""
        monkeypatch.setenv("ASH_DEPVERDICT_LIBRARY", DEPVERDICT_CANARY)
        config = _config_reading_the_environment(tmp_path)

        def configure(fake):
            fake.missing_dependency_reason.return_value = (
                f"needs a library under /opt/{DEPVERDICT_CANARY}/lib"
            )

        result, _ = _install_one_fake_scanner(
            tmp_path,
            monkeypatch,
            scan_can_run=False,
            configure=configure,
            extra_args=("--config", str(config)),
        )
        assert result.exit_code == EXIT_INSTALL_FAILED, result.output
        assert "did not find a tool to start" in result.output, result.output
        assert "needs a library under /opt/<value>/lib" in result.output, result.output
        assert DEPVERDICT_CANARY not in result.output, result.output

    def test_a_built_plugin_s_reason_is_redacted_with_the_run_s_values(
        self, tmp_path, monkeypatch
    ):
        """The same through a plugin the command builds itself: a
        ScannerPluginBase subclass, constructed with the run's plugin context,
        whose check refuses with a reason that quotes a value the configuration
        read from the environment."""
        result = _install_one_plugin_class(
            tmp_path, monkeypatch, _RefusingPlugin, "refusing-plugin"
        )
        assert result.exit_code == EXIT_INSTALL_FAILED, result.output
        assert (
            _refused_line("refusing-plugin")
            + ": needs a library under /opt/<value>/lib"
            in result.output
        ), result.output
        assert DEPVERDICT_CANARY not in result.output, result.output

    def test_a_reason_is_redacted_with_the_plugin_s_own_values_too(
        self, tmp_path, monkeypatch
    ):
        """A plugin whose ``_environment_values()`` names a value beyond the
        run's configuration has that one redacted too: the run's values and the
        plugin's own, never fewer than either gives."""
        result = _install_one_plugin_class(
            tmp_path, monkeypatch, _PluginWithItsOwnValues, "refusing-plugin"
        )
        assert result.exit_code == EXIT_INSTALL_FAILED, result.output
        assert "needs a key file under /etc/<value>/keys" in result.output, (
            result.output
        )
        assert OWN_CANARY not in result.output, result.output

    def test_the_reason_is_asked_in_check_only_mode(self, tmp_path, monkeypatch):
        """``missing_dependency_reason()`` is plugin code, like the check: it is
        asked in the scope the check ran in (check-only, and the probe's
        sandbox scope), so an override that probes installs nothing and
        downloads nothing at install time either."""
        monkeypatch.setattr(_RefusingPlugin, "asked_checking_only", [])

        result = _install_one_plugin_class(
            tmp_path, monkeypatch, _RefusingPlugin, "refusing-plugin"
        )
        assert "did not find a tool to start: needs a library" in result.output, (
            result.output
        )
        assert _RefusingPlugin.asked_checking_only == [True], (
            _RefusingPlugin.asked_checking_only
        )

    def test_the_base_hook_s_install_advice_is_not_quoted_at_install(
        self, tmp_path, monkeypatch
    ):
        """A shipped plugin that keeps the base ``missing_dependency_reason()``
        and records no reason gets the base hook's answer at scan time: its
        tool not found on PATH, and "install it with `ash dependencies
        install`". Quoted in this command's own failure panel, that advice
        sends the user back to the command they just ran, and blames PATH for
        a check that refused. So the install line says the check refused, and
        quotes nothing."""
        monkeypatch.setattr(_BaseHookPlugin, "recorded", None)

        result = _install_one_plugin_class(
            tmp_path, monkeypatch, _BaseHookPlugin, "base-hook-plugin"
        )
        assert result.exit_code == EXIT_INSTALL_FAILED, result.output
        assert _refused_line("base-hook-plugin") in result.output, result.output
        assert "did not find a tool to start:" not in result.output, result.output
        assert "ash dependencies install`" not in result.output, result.output
        assert "was not found on PATH" not in result.output, result.output

    def test_an_override_s_fallback_to_the_base_hook_is_not_quoted_at_install(
        self, tmp_path, monkeypatch
    ):
        """An override that falls back to ``super().missing_dependency_reason()``
        when its own case does not hold gives the base hook's generic answer
        then: the same install advice the cell above keeps out of this panel.
        The class defining its own hook does not make that text its own."""
        monkeypatch.setattr(_BaseHookPlugin, "recorded", None)
        monkeypatch.setattr(_FallingBackPlugin, "special", False)

        result = _install_one_plugin_class(
            tmp_path, monkeypatch, _FallingBackPlugin, "base-hook-plugin"
        )
        assert result.exit_code == EXIT_INSTALL_FAILED, result.output
        assert _refused_line("base-hook-plugin") in result.output, result.output
        assert "did not find a tool to start:" not in result.output, result.output
        assert "ash dependencies install`" not in result.output, result.output
        assert "was not found on PATH" not in result.output, result.output

    def _hook_lookup_finds_the_command(self, tmp_path, monkeypatch):
        """The base hook's OTHER generic answer needs its own lookup to find
        the command while the sweep's does not: patch the lookup the hook
        reads (base.scanner_plugin's find_executable), so the hook says the
        check failed and points at ash.log instead of blaming PATH.

        Returns the commands the patched lookup was asked for. A cell that
        only checks the check-failed words are absent cannot tell this patch
        from a broken one: with the lookup missed (a moved module, a renamed
        function), the hook blames PATH instead, and that answer is just as
        absent from the panel. Seeing the hook's command in this list is the
        proof the hook answered through the patch."""
        from automated_security_helper.base import scanner_plugin as base_module

        looked_up = []

        def finds_the_hook_tool(command):
            looked_up.append(command)
            if command == "ash-depverdict-base-hook-tool":
                return str(tmp_path / "elsewhere" / command)
            return None

        monkeypatch.setattr(base_module, "find_executable", finds_the_hook_tool)
        return looked_up

    def test_the_base_hook_s_check_failed_answer_is_not_quoted_at_install(
        self, tmp_path, monkeypatch
    ):
        """The base hook's second generic answer -- its command found, so "its
        dependency check failed (...); ash.log has the scanner's own message"
        -- names nothing the plugin knows, like the install advice, so the
        install line quotes it no more than the first answer."""
        monkeypatch.setattr(_BaseHookPlugin, "recorded", None)
        looked_up = self._hook_lookup_finds_the_command(tmp_path, monkeypatch)

        result = _install_one_plugin_class(
            tmp_path, monkeypatch, _BaseHookPlugin, "base-hook-plugin"
        )
        assert result.exit_code == EXIT_INSTALL_FAILED, result.output
        assert "ash-depverdict-base-hook-tool" in looked_up, looked_up
        assert _refused_line("base-hook-plugin") in result.output, result.output
        assert "ash.log" not in result.output, result.output
        assert "validate_plugin_dependencies() returned False" not in result.output, (
            result.output
        )

    def test_an_override_s_fallback_to_the_check_failed_answer_is_not_quoted(
        self, tmp_path, monkeypatch
    ):
        """The same through an override that falls back to the base hook: the
        second generic answer is the base hook's whichever class gave it."""
        monkeypatch.setattr(_BaseHookPlugin, "recorded", None)
        monkeypatch.setattr(_FallingBackPlugin, "special", False)
        looked_up = self._hook_lookup_finds_the_command(tmp_path, monkeypatch)

        result = _install_one_plugin_class(
            tmp_path, monkeypatch, _FallingBackPlugin, "base-hook-plugin"
        )
        assert result.exit_code == EXIT_INSTALL_FAILED, result.output
        assert "ash-depverdict-base-hook-tool" in looked_up, looked_up
        assert _refused_line("base-hook-plugin") in result.output, result.output
        assert "ash.log" not in result.output, result.output
        assert "validate_plugin_dependencies() returned False" not in result.output, (
            result.output
        )

    def test_an_override_s_own_case_is_quoted_at_install(self, tmp_path, monkeypatch):
        """The counterpart: when the override's own case holds, its words are
        quoted."""
        monkeypatch.setattr(_BaseHookPlugin, "recorded", None)
        monkeypatch.setattr(_FallingBackPlugin, "special", True)

        result = _install_one_plugin_class(
            tmp_path, monkeypatch, _FallingBackPlugin, "base-hook-plugin"
        )
        assert result.exit_code == EXIT_INSTALL_FAILED, result.output
        assert (
            _refused_line("base-hook-plugin")
            + ": needs its rules bundle unpacked first"
            in result.output
        ), result.output

    def test_a_reason_the_plugin_recorded_is_quoted_at_install(
        self, tmp_path, monkeypatch
    ):
        """The counterpart: the same base hook, for a check that recorded its
        reason (``dependency_unavailable_reason``, the field a sandbox refusal
        also fills), quotes it, redacted. That text is the plugin's own."""
        monkeypatch.setattr(
            _BaseHookPlugin,
            "recorded",
            f"needs a sidecar under /srv/{DEPVERDICT_CANARY}",
        )

        result = _install_one_plugin_class(
            tmp_path, monkeypatch, _BaseHookPlugin, "base-hook-plugin"
        )
        assert result.exit_code == EXIT_INSTALL_FAILED, result.output
        assert (
            _refused_line("base-hook-plugin") + ": needs a sidecar under /srv/<value>"
            in result.output
        ), result.output
        assert DEPVERDICT_CANARY not in result.output, result.output

    @pytest.mark.parametrize(
        "hook",
        [
            pytest.param({"return_value": None}, id="returns-none"),
            pytest.param({"return_value": ""}, id="returns-empty"),
            pytest.param({"side_effect": RuntimeError("hook broke")}, id="raises"),
            pytest.param({}, id="a-mock"),
        ],
    )
    def test_a_hook_that_gives_no_reason_adds_none_at_install(
        self, tmp_path, monkeypatch, hook
    ):
        """When the plugin's missing_dependency_reason() gives no text, the
        install line says only that the check refused. The scan's MISSING row
        adds a generic reason in that case; repeated here it would only restate
        the refusal, so the install line quotes nothing."""

        def configure(fake):
            fake.dependency_unavailable_reason = None
            for name, value in hook.items():
                setattr(fake.missing_dependency_reason, name, value)

        result, _ = _install_one_fake_scanner(
            tmp_path, monkeypatch, scan_can_run=False, configure=configure
        )
        assert result.exit_code == EXIT_INSTALL_FAILED, result.output
        assert _refused_line("fake-scanner") in result.output, result.output
        assert "did not find a tool to start:" not in result.output, result.output
        assert "ash.log has the scanner's own message" not in result.output, (
            result.output
        )
        assert "hook broke" not in result.output, result.output

    def test_a_reason_that_cannot_be_read_keeps_the_check_s_no(
        self, tmp_path, monkeypatch
    ):
        """Reading the reason is plugin code too: the hook gives text, and the
        recorded dependency_unavailable_reason that decides whether the text is
        the plugin's own raises when read. That does not turn the check's
        definite no into "the check failed": the tool is on the check-refused
        line with no reason, and no line says the check failed."""
        from unittest.mock import PropertyMock

        def configure(fake):
            fake.missing_dependency_reason.return_value = "needs its rules bundle"
            type(fake).dependency_unavailable_reason = PropertyMock(
                side_effect=RuntimeError("the reason could not be read")
            )

        result, fake = _install_one_fake_scanner(
            tmp_path, monkeypatch, scan_can_run=False, configure=configure
        )
        # The control: the check itself was asked, and said no.
        fake.validate_plugin_dependencies.assert_called()
        assert result.exit_code == EXIT_INSTALL_FAILED, result.output
        assert _refused_line("fake-scanner") in result.output, result.output
        assert "own dependency check failed" not in result.output, result.output
        assert "the reason could not be read" not in result.output, result.output

    def test_a_reason_given_only_by_the_method_is_said_as_the_scan_says_it(
        self, tmp_path, monkeypatch
    ):
        """A plugin that explains itself only through ``missing_dependency_reason()``
        -- the hook the MISSING row reads, overridden the way cdk-nag does -- and
        records no ``dependency_unavailable_reason`` gets that reason here too,
        with the home directory written as ``~`` the way the row records it.
        Only the home prefix is rewritten (``home_as_tilde``); the rest of the
        path keeps the separators the reason was written with, so the expected
        text is built with this host's, which on Windows are backslashes."""
        home = Path.home()
        library = home / "depverdict-tools" / "lib"
        under_tilde = str(Path("~") / "depverdict-tools" / "lib")

        def configure(fake):
            fake.dependency_unavailable_reason = None
            fake.missing_dependency_reason.return_value = (
                f"needs node and the CDK packages under {library}"
            )

        result, _ = _install_one_fake_scanner(
            tmp_path, monkeypatch, scan_can_run=False, configure=configure
        )
        assert result.exit_code == EXIT_INSTALL_FAILED, result.output
        assert (
            _refused_line("fake-scanner")
            + f": needs node and the CDK packages under {under_tilde}"
            in result.output
        ), result.output
        assert str(library) not in result.output, result.output

    def test_an_unprovisionable_absent_tool_the_scan_can_run_succeeds(
        self, tmp_path, monkeypatch
    ):
        """The still-absent rule admits the same resolution: a tool with no
        install path here that a scan starts anyway is present in every sense a
        run cares about."""
        result, _ = _install_one_fake_scanner(
            tmp_path, monkeypatch, scan_can_run=True, commands=(), requested=False
        )
        assert result.exit_code == EXIT_OK, result.output
        # Its row says so too, rather than "NO INSTALL PATH" beside the summary's
        # "a scan can run them".
        assert "RUNNABLE BY SCAN" in result.output


@pytest.mark.unit
class TestSweepConsultsTheScansResolution:
    """The post-install sweep asks the plugin's check only when the tool is not
    found otherwise."""

    def test_a_tool_off_path_is_asked_about_once(self, tmp_path, monkeypatch):
        _, fake = _install_one_fake_scanner(tmp_path, monkeypatch, scan_can_run=True)
        fake.validate_plugin_dependencies.assert_called_once()

    def test_a_tool_on_path_is_not_asked_about(self, tmp_path, monkeypatch):
        """The control: the PATH lookup found it, so nothing else is asked."""
        result, fake = _install_one_fake_scanner(
            tmp_path,
            monkeypatch,
            scan_can_run=False,
            on_path=str(tmp_path / "bin" / "fake-scanner"),
        )
        assert result.exit_code == EXIT_OK, result.output
        fake.validate_plugin_dependencies.assert_not_called()

    def test_an_undeclared_plugins_check_is_not_asked(self, tmp_path, monkeypatch):
        """A plugin that does not declare its check can start the tool off PATH
        is judged by the lookups alone. Most checks are the same PATH lookup the
        sweep just made, so asking one can only answer True for a tool nothing
        here can start -- and a requested tool that is absent everywhere must
        keep exit 1, whatever such a check answers."""

        def configure(fake):
            fake.resolves_tool_off_path = False

        result, fake = _install_one_fake_scanner(
            tmp_path, monkeypatch, scan_can_run=True, configure=configure
        )
        assert result.exit_code == EXIT_INSTALL_FAILED, result.output
        assert "requested tool(s) still not on PATH" in result.output
        fake.validate_plugin_dependencies.assert_not_called()

    def test_a_plugin_without_the_attribute_is_undeclared(self, tmp_path, monkeypatch):
        """A plugin that never heard of the declaration -- one not built on
        ScannerPluginBase -- is undeclared, not opted in by default."""

        def configure(fake):
            del fake.resolves_tool_off_path

        result, fake = _install_one_fake_scanner(
            tmp_path, monkeypatch, scan_can_run=True, configure=configure
        )
        assert result.exit_code == EXIT_INSTALL_FAILED, result.output
        fake.validate_plugin_dependencies.assert_not_called()

    def test_only_true_declares_it(self, tmp_path, monkeypatch):
        """The declaration is ``True`` itself: a truthy value of another kind
        (a string a plugin set by mistake) does not opt a plugin in."""

        def configure(fake):
            fake.resolves_tool_off_path = "yes"

        result, fake = _install_one_fake_scanner(
            tmp_path, monkeypatch, scan_can_run=True, configure=configure
        )
        assert result.exit_code == EXIT_INSTALL_FAILED, result.output
        fake.validate_plugin_dependencies.assert_not_called()


@pytest.mark.unit
class TestARaisingCheckGivesNoAnswer:
    """A dependency check that raises gives no answer (``_scan_can_run`` returns
    None, not False), and the crash is shown.

    An installer cannot treat a crash as a tool, and the exception's message can
    carry whatever the check read -- a path, a config value -- so the verdict
    keeps the message out of the output and the log. What is shown is that the
    check itself failed: a line naming the plugin and the exception's type, so
    "still not on PATH" is not the only word on a check that blew up, and the
    same type at DEBUG.
    """

    def _run(self, tmp_path, monkeypatch, canary, error_type=RuntimeError):
        from automated_security_helper.utils.log import ASH_LOGGER

        def raising():
            raise error_type(f"could not read {canary}")

        def configure(fake):
            fake.validate_plugin_dependencies.side_effect = raising

        records = []

        def keep(record):
            records.append(record)
            return True

        # A filter, not a handler: the command's get_logger replaces the
        # logger's handlers, and ASH_LOGGER does not propagate to root.
        ASH_LOGGER.addFilter(keep)
        try:
            result, _ = _install_one_fake_scanner(
                tmp_path,
                monkeypatch,
                scan_can_run=True,
                configure=configure,
                extra_args=("--debug",),
            )
        finally:
            ASH_LOGGER.removeFilter(keep)
        return result, records

    def test_a_raising_check_gives_no_answer_and_shows_nothing(
        self, tmp_path, monkeypatch
    ):
        canary = str(tmp_path / "canary-dir" / "canary-value.yaml")
        result, records = self._run(tmp_path, monkeypatch, canary)
        logged = [record.getMessage() for record in records]
        assert result.exit_code == EXIT_INSTALL_FAILED, result.output
        assert "requested tool(s) still not on PATH" in result.output
        assert canary not in result.output
        # The crash's own record first: with no records captured (a filter
        # that never attached, a record that never fired), the sweep below
        # is true of an empty list and measures nothing.
        assert any("dependency check raised" in message for message in logged), logged
        assert all(canary not in message for message in logged), logged

    def test_the_debug_log_names_the_exceptions_type(self, tmp_path, monkeypatch):
        import logging

        canary = str(tmp_path / "canary-dir" / "canary-value.yaml")
        _, records = self._run(tmp_path, monkeypatch, canary)
        named = [r for r in records if "RuntimeError" in r.getMessage()]
        assert named, [r.getMessage() for r in records]
        assert all(r.levelno == logging.DEBUG for r in named)
        assert all(canary not in r.getMessage() for r in named)

    def test_the_debug_log_names_the_plugin(self, tmp_path, monkeypatch):
        """A log a reader greps by plugin: 'which check raised' needs the name.

        The console line already names the plugin; the DEBUG record said only
        "a plugin's dependency check", so with two flagged plugins the record
        could not say whose check blew up.
        """
        canary = str(tmp_path / "canary-dir" / "canary-value.yaml")
        _, records = self._run(tmp_path, monkeypatch, canary)
        named = [r for r in records if "RuntimeError" in r.getMessage()]
        assert named, [r.getMessage() for r in records]
        assert any(
            "fake-scanner's dependency check raised RuntimeError" in r.getMessage()
            for r in named
        ), [r.getMessage() for r in named]

    def test_the_crash_is_shown_without_its_message(self, tmp_path, monkeypatch):
        """The operator sees that the check failed, not only the verdict it
        produced -- and still none of what the exception carried."""
        canary = str(tmp_path / "canary-dir" / "canary-value.yaml")
        result, _ = self._run(tmp_path, monkeypatch, canary)
        assert (
            "fake-scanner's own dependency check failed (RuntimeError); the "
            "verdict counts the tool as not found" in result.output
        ), result.output
        assert canary not in result.output

    @pytest.mark.parametrize(
        "class_name,shown",
        [
            pytest.param("Bad[/yellow]Err", "Bad[/yellow]Err", id="a-closing-tag"),
            pytest.param("Bad[bold]Err", "Bad[bold]Err", id="an-opening-tag"),
            pytest.param("Bad\x1b[31mErr", "Bad\\x1b[31mErr", id="a-terminal-control"),
        ],
    )
    def test_an_exception_type_s_name_is_shown_as_written(
        self, tmp_path, monkeypatch, class_name, shown
    ):
        """The type's name is the exception's own text, data to Rich: a name
        holding a closing tag made the crash line raise inside its own except,
        so the command ended with no verdict, and an opening tag vanished from
        the line. A terminal control in it is shown as its escape, never sent
        to the terminal. Such a name is reachable only through type() or a
        __name__ assignment."""
        canary = str(tmp_path / "canary-dir" / "canary-value.yaml")
        error_type = type(class_name, (RuntimeError,), {})
        result, records = self._run(tmp_path, monkeypatch, canary, error_type)
        assert result.exit_code == EXIT_INSTALL_FAILED, result.output
        assert "requested tool(s) still not on PATH" in result.output, result.output
        assert (
            f"fake-scanner's own dependency check failed ({shown}); the "
            "verdict counts the tool as not found" in result.output
        ), result.output
        assert "\x1b" not in result.output, result.output
        # The log path too: the DEBUG record reaches ash.log and, with
        # --debug, any console handler, and CliRunner's capture can lose
        # command output after a worker's first record (_install_fake_scanners
        # docstring), so result.output alone does not cover it. The record
        # has to exist first: over an empty capture the sweep is vacuous.
        assert any("dependency check raised" in r.getMessage() for r in records), [
            r.getMessage() for r in records
        ]
        assert all("\x1b" not in r.getMessage() for r in records), [
            r.getMessage() for r in records if "\x1b" in r.getMessage()
        ]
        assert canary not in result.output

    def test_the_check_s_answer_is_none_when_it_raises(self):
        """The answer itself, not only the wording it leads to: a check that
        raises gives None, which the verdict reads as no answer, never False,
        which it reads as a refusal."""
        from automated_security_helper.cli.dependencies import _scan_can_run

        raising = _fake_scanner(scan_can_run=True)
        raising.validate_plugin_dependencies.side_effect = RuntimeError("broke")
        # The control: the same stand-in whose check answers gives that answer.
        assert _scan_can_run(_fake_scanner(scan_can_run=True), "fake-scanner") is True
        assert _scan_can_run(raising, "fake-scanner") is None


@pytest.mark.unit
class TestAFailedInstallIsNotAskedAgain:
    """An outcome with a failed command keeps its exit-1 verdict unasked.

    The verdict line means "a scan can run them now", and a failed install
    already decided it: the run exits 1 whatever the check answers. Asking
    anyway re-runs the plugin's own resolution -- for a scanner with an install
    path, up to its full install timeout -- after the answer stopped mattering.
    """

    def test_the_sweep_skips_the_check_after_a_failed_command(
        self, tmp_path, monkeypatch
    ):
        result, fake = _install_one_fake_scanner(
            tmp_path, monkeypatch, scan_can_run=True, command_rc=1
        )
        assert result.exit_code == EXIT_INSTALL_FAILED, result.output
        fake.validate_plugin_dependencies.assert_not_called()

    def test_the_sweep_skips_the_check_after_a_plugin_error(
        self, tmp_path, monkeypatch
    ):
        """The other half of the rule: a plugin that raised while giving its
        install commands has an error, which decides the verdict too."""

        def configure(fake):
            fake.get_installation_commands.side_effect = RuntimeError("no commands")

        result, fake = _install_one_fake_scanner(
            tmp_path, monkeypatch, scan_can_run=True, configure=configure
        )
        assert result.exit_code == EXIT_INSTALL_FAILED, result.output
        fake.validate_plugin_dependencies.assert_not_called()


@pytest.mark.unit
class TestEachOutcomeIsJudgedByItsOwnPlugin:
    """Two plugins that answer to one name are each judged by their own check.

    Names are not unique: two plugin modules can ship a scanner of the same
    name. The sweep's answer for an outcome must come from the plugin that
    produced it, whatever order the plugins were loaded in: an undeclared
    plugin's absent tool keeps exit 1 even beside a declared namesake whose
    check can start its own.
    """

    @pytest.mark.parametrize(
        "declared_first", [False, True], ids=["undeclared-first", "declared-first"]
    )
    def test_each_plugin_is_asked_with_its_own_check(
        self, tmp_path, monkeypatch, declared_first
    ):
        undeclared = _fake_scanner("dup", "dup-a", scan_can_run=True, declared=False)
        declared = _fake_scanner("dup", "dup-b", scan_can_run=True)
        fakes = [declared, undeclared] if declared_first else [undeclared, declared]

        result = _install_fake_scanners(tmp_path, monkeypatch, fakes, tools=("dup",))

        assert result.exit_code == EXIT_INSTALL_FAILED, result.output
        undeclared.validate_plugin_dependencies.assert_not_called()
        declared.validate_plugin_dependencies.assert_called_once()


@pytest.mark.unit
class TestADeclarationThatRaises:
    """A plugin whose declaration raises is undeclared, and the run goes on.

    The attribute is read for every plugin the sweep counts; one plugin's
    property that raises must not abort the sweep and the verdict for all of
    them.
    """

    def test_the_sweep_finishes_and_the_tool_counts_as_undeclared(
        self, tmp_path, monkeypatch
    ):
        from unittest.mock import PropertyMock

        def configure(fake):
            type(fake).resolves_tool_off_path = PropertyMock(
                side_effect=RuntimeError("declaration raised")
            )

        result, fake = _install_one_fake_scanner(
            tmp_path, monkeypatch, scan_can_run=True, configure=configure
        )

        assert not isinstance(result.exception, RuntimeError), repr(result.exception)
        assert result.exit_code == EXIT_INSTALL_FAILED, result.output
        assert "requested tool(s) still not on PATH" in result.output
        fake.validate_plugin_dependencies.assert_not_called()


@pytest.mark.unit
class TestTheDeclarationIsPartOfThePluginContract:
    """The class attribute the sweep reads, declared where an author finds it."""

    def test_the_scanner_base_declares_it_false(self):
        from automated_security_helper.base.scanner_plugin import ScannerPluginBase

        assert ScannerPluginBase.resolves_tool_off_path is False

    def test_detect_secrets_declares_it(self):
        """detect-secrets' check runs the library in-process and never looks
        for its console script, so the sweep has to ask it."""
        from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
            DetectSecretsScanner,
        )

        assert DetectSecretsScanner.resolves_tool_off_path is True


@pytest.mark.unit
class TestTheCellsRunFromTheirOwnDirectory:
    """A cell's verdict does not depend on the directory pytest was started in."""

    def test_a_config_in_the_callers_directory_is_not_read(self, tmp_path, monkeypatch):
        elsewhere = tmp_path / "elsewhere"
        (elsewhere / ".ash").mkdir(parents=True)
        # A configuration file that does not parse refuses any run that reads it.
        (elsewhere / ".ash" / ".ash.yaml").write_text(
            "project_name: [unclosed\n", encoding="utf-8"
        )
        monkeypatch.chdir(elsewhere)
        run_dir = tmp_path / "run"
        run_dir.mkdir()

        result, _ = _install_one_fake_scanner(run_dir, monkeypatch, scan_can_run=True)

        assert result.exit_code == EXIT_OK, result.output


class TestTheCheckRunsInTheScansProbeScope:
    """The sweep asks the plugin's check in the sandbox scope a scan asks it in.

    ScanPhase runs ``validate_plugin_dependencies`` inside ``plugin_probe_scope``.
    Under a sandbox the host cannot provide, that scope refuses every probe the
    check starts, so the scan does not run the scanner (a backend named
    explicitly records an ERROR naming the backend; ``auto`` with no working
    backend records MISSING). Asked outside it, the same check started its probe
    unsandboxed and answered True, and ``--tool`` exited 0 for a tool no scan
    here can run. This covers the tools the sweep consults the check for -- the
    off-PATH ones; a tool the PATH lookup finds is reported by that lookup and
    its own scanner answers for itself at scan time.
    """

    def _run(self, tmp_path, monkeypatch, mode, reason_probes=False):
        from automated_security_helper.base.plugin_context import PluginContext
        from automated_security_helper.config.ash_config import (
            AshConfig,
            SandboxConfig,
        )
        from automated_security_helper.utils.sandbox import scope
        from automated_security_helper.utils.sandbox.policy import SandboxUnavailable
        from automated_security_helper.utils.subprocess_utils import spawn_run

        def no_backend(_mode):
            # A sandbox this host cannot provide, whatever the host is.
            raise SandboxUnavailable("no backend for this mode on this host")

        monkeypatch.setattr(scope, "resolve_backend", no_backend)
        probes = []

        def probe():
            # A probe started as a plugin's check starts one, through ASH's
            # spawner, which a refusing scope stops before anything starts. The
            # command is the test's own interpreter doing nothing. The scope,
            # not one exception type, is what this measures: a refusal may
            # surface as SandboxUnavailable, as CalledProcessError, or as the
            # spawn helpers' failure exit (127 with spawn_failed), so any
            # non-zero outcome of a command that cannot fail counts as refused.
            try:
                completed = spawn_run([sys.executable, "-I", "-c", "pass"], check=False)
            except (SandboxUnavailable, subprocess.CalledProcessError):
                probes.append("refused")
                return False
            if completed.returncode != 0:
                probes.append("refused")
                return False
            probes.append("ran")
            return True

        def reason():
            # The hook probes as the check does: whether the reason is asked
            # in the same scope is measured by what happens to its probe.
            probe()
            return "needs a library the probe could not start"

        def configure(fake):
            fake.context = PluginContext(
                source_dir=tmp_path,
                output_dir=tmp_path / "out",
                config=AshConfig(sandbox=SandboxConfig(mode=mode)),
            )
            fake.validate_plugin_dependencies.side_effect = probe
            if reason_probes:
                fake.missing_dependency_reason.side_effect = reason

        result, _ = _install_one_fake_scanner(
            tmp_path, monkeypatch, scan_can_run=True, configure=configure
        )
        return result, probes

    @pytest.mark.integration
    def test_with_the_sandbox_off_the_probe_runs_and_answers(
        self, tmp_path, monkeypatch
    ):
        """The control: no scope applies, so the scan and the installer agree."""
        result, probes = self._run(tmp_path, monkeypatch, "off")
        assert probes == ["ran"]
        assert result.exit_code == EXIT_OK, result.output

    @pytest.mark.unit
    def test_a_sandbox_the_host_cannot_provide_refuses_the_probe(
        self, tmp_path, monkeypatch
    ):
        result, probes = self._run(tmp_path, monkeypatch, "bwrap")
        assert probes == ["refused"], "the check's probe ran outside the scan's scope"
        assert result.exit_code == EXIT_INSTALL_FAILED, result.output

    @pytest.mark.unit
    @pytest.mark.parametrize("mode", ["bwrap", "auto"])
    def test_the_reason_is_asked_in_the_probe_scope_too(
        self, tmp_path, monkeypatch, mode
    ):
        """``missing_dependency_reason()`` is plugin code like the check, so
        whatever the hook starts is refused as the check's probe is: under a
        sandbox the host cannot provide, both probes record "refused". The
        probe measures the behavior itself -- a wrong scope active where the
        reason is asked would let its probe run, where a check that only reads
        ``active_scope() is not None`` reads any scope as the right one."""
        result, probes = self._run(tmp_path, monkeypatch, mode, reason_probes=True)
        assert probes == ["refused", "refused"], probes
        assert result.exit_code == EXIT_INSTALL_FAILED, result.output

    @pytest.mark.integration
    def test_with_the_sandbox_off_the_reason_hook_is_not_reached(
        self, tmp_path, monkeypatch
    ):
        """The negative control for the pair above: with no scope to refuse,
        the check's probe runs and answers True, so the install succeeds and
        the reason is never asked -- one "ran", nothing refused. The refusals
        in the sandbox cells are the scope's doing, not this harness's."""
        result, probes = self._run(tmp_path, monkeypatch, "off", reason_probes=True)
        assert probes == ["ran"], probes
        assert result.exit_code == EXIT_OK, result.output
