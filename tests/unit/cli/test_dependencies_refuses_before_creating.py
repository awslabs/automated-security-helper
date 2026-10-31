# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`ash dependencies install` refuses before it creates, and judges what a scan judges.

--tool names match plugins as the scan matches them; a repeated --plugin-type
selects its kind once; the bin directory is made after every refusal and an
unmakable one is a refusal; a deleted working directory is a refusal; a malformed
install command list fails its plugin alone and a CustomCommand's shell flag is
honored; every install command has a timeout and a `python -m uv` command gets the
uv child's overrides; the sweep looks tools up as a scan does; the status and the
summary say what is so.
"""

from __future__ import annotations

import errno
import io
import os
import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import typer
from rich.console import Console
from typer.testing import CliRunner

from automated_security_helper.base.plugin_base import CustomCommand
from automated_security_helper.cli import dependencies
from automated_security_helper.cli.dependencies import (
    EXIT_BAD_SELECTION,
    EXIT_INVALID_CONFIG,
    INSTALL_COMMAND_TIMEOUT_SECONDS,
    PluginInstallOutcome,
    _canonical_tool_names,
    _report_and_exit,
    _resolve_tool_aliases,
    _section_disables,
    _uv_reads_project_config,
    _well_formed_commands,
    _with_path_imported,
    dependencies_app,
)
from automated_security_helper.utils import subprocess_utils, uv_tool_runner

pytestmark = pytest.mark.unit

# Wide, so rich does not fold a refusal's long temporary path across lines: off a
# terminal it wraps at 80 columns, and a 71-character path put "be" of "cannot be
# created" on the next line.
runner = CliRunner(env={"COLUMNS": "300"})


class _Calls(list):
    panels: io.StringIO


def _flat(output: str) -> str:
    """The output on one line, without the colors rich adds."""
    return " ".join(re.sub(r"\x1b\[[0-9;]*m", "", output).split())


@pytest.fixture
def quiet_machine(tmp_path, monkeypatch):
    """No uv probe starts, no install command runs, the panels are captured.

    The command exports ASH_BIN_PATH for the rest of the process (``set_environ``)
    before any refusal; ``delenv`` of a name that was not set records nothing to
    undo, so the value is removed here, as the other bin-path fixtures do."""
    calls = _Calls()

    def _spawn(argv, **_kwargs):
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 1, "", "stand-in uv")

    uv_tool_runner._reset_uv_tool_runner_caches()
    monkeypatch.setattr(uv_tool_runner, "spawn_run", _spawn)
    monkeypatch.setattr(
        uv_tool_runner.UVToolRunner, "is_uv_available", lambda self: True
    )
    monkeypatch.setattr(
        dependencies, "run_command", lambda cmd, shell=False: calls.append(cmd) or 0
    )
    monkeypatch.delenv("ASH_BIN_PATH", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    # With this set to "skip" an unknown --tool is skipped, not refused.
    monkeypatch.delenv(dependencies.UNKNOWN_TOOLS_SETTING, raising=False)
    monkeypatch.chdir(tmp_path)
    panels = io.StringIO()
    monkeypatch.setattr(
        dependencies, "console", Console(file=panels, width=300, no_color=True)
    )
    calls.panels = panels
    yield calls
    os.environ.pop("ASH_BIN_PATH", None)
    uv_tool_runner._reset_uv_tool_runner_caches()
    subprocess_utils.clear_find_executable_cache()


def _outcome(**kwargs) -> PluginInstallOutcome:
    base = {"name": "tool", "plugin_type": "scanner", "command": "tool"}
    base.update(kwargs)
    return PluginInstallOutcome(**base)


# --- --tool names ---


def test_tool_names_match_without_regard_to_case_or_blanks():
    """`ash scan --scanners Grype` runs grype; `--tool Grype` was refused as unknown,
    and under the unknown-tools setting skipped a tool the scan then ran."""
    resolution = _canonical_tool_names(
        _resolve_tool_aliases([" Grype ", "gryp"]), ["grype", "syft"]
    )

    assert resolution == {" Grype ": "grype", "gryp": "gryp"}


def test_a_differently_cased_tool_name_is_not_refused(quiet_machine, tmp_path):
    result = runner.invoke(
        dependencies_app, ["--bin-path", str(tmp_path / "bin"), "--tool", "Sarif"]
    )

    # Zero, as `--tool sarif` exits in the tests beside this one: "not the
    # selection code" also admitted a traceback's exit 1.
    assert result.exit_code == 0, result.output
    assert "Unknown tool(s)" not in quiet_machine.panels.getvalue()


def test_a_repeated_plugin_type_installs_each_plugin_once(quiet_machine, tmp_path):
    """The candidates loop appended every plugin of the kind once per repetition."""
    result = runner.invoke(
        dependencies_app,
        [
            "--bin-path",
            str(tmp_path / "bin"),
            "--plugin-type",
            "reporter",
            "--plugin-type",
            "reporter",
            "--tool",
            "sarif",
        ],
    )

    assert result.exit_code == 0, result.output
    assert result.output.count("reporter plugin: sarif") == 1, result.output


# --- the bin directory ---


def test_a_refused_run_does_not_create_the_bin_directory(quiet_machine, tmp_path):
    """The directory was made before the --tool check, so a run that said
    "Nothing installed" had still created it."""
    bin_dir = tmp_path / "new-bin"

    result = runner.invoke(
        dependencies_app, ["--bin-path", str(bin_dir), "--tool", "no-such-tool-zz"]
    )

    assert result.exit_code == EXIT_BAD_SELECTION, result.output
    assert not bin_dir.exists()


def test_a_bin_path_that_is_a_file_is_a_refusal_not_a_traceback(
    quiet_machine, tmp_path
):
    """mkdir on a regular file raised FileExistsError out of the command with exit
    1, the code for an install that ran and failed."""
    occupied = tmp_path / "occupied"
    occupied.write_text("a file\n", encoding="utf-8")

    result = runner.invoke(
        dependencies_app, ["--bin-path", str(occupied), "--tool", "sarif"]
    )

    assert result.exit_code == EXIT_INVALID_CONFIG, result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "cannot be created" in _flat(result.output), result.output


# A bin path under "~" with no usable home is refused: pinned, with both HOME and
# USERPROFILE emptied and a mkdir guard, in
# test_dependencies_bin_path_under_tilde_needs_a_usable_home.py.


class _Built(list):
    watch: list


@pytest.fixture
def building_scanner(quiet_machine, monkeypatch):
    """One scanner that declares no name, so a ``--tool`` run builds it to learn
    the name, as bandit and checkov are built before their version probe runs.
    ``built`` holds, for each build, whether the bin directory existed then."""
    built = _Built()
    built.watch = []

    class Building:
        def __init__(self, **_kwargs):
            built.append(any(path.exists() for path in built.watch))
            self.config = SimpleNamespace(name="builds-a-probe")
            self.command = "builds-a-probe"

        def get_installation_commands(self, platform_name, arch):
            return []

    monkeypatch.setattr(dependencies, "load_plugins", lambda *_a, **_k: {})
    monkeypatch.setattr(
        dependencies,
        "ash_plugin_manager",
        SimpleNamespace(
            plugin_modules=lambda kind: [Building] if kind == "scanner" else []
        ),
    )
    monkeypatch.setattr(dependencies, "_report_and_exit", lambda *_a, **_k: 0)
    return built


def test_an_unmakable_bin_path_is_refused_before_any_plugin_is_built(
    building_scanner, tmp_path
):
    """The bin directory was only tried at the mkdir after the plugins were
    built, so every build and version probe ran, and downloaded, before a path
    that could never be made was refused."""
    occupied = tmp_path / "occupied"
    occupied.write_text("a file\n", encoding="utf-8")

    result = runner.invoke(
        dependencies_app,
        ["--bin-path", str(occupied / "bin"), "--tool", "builds-a-probe"],
    )

    assert result.exit_code == EXIT_INVALID_CONFIG, result.output
    assert "cannot be created" in _flat(result.output), result.output
    assert building_scanner == [], building_scanner


def test_a_usable_bin_path_is_still_made_after_the_plugins_are_built(
    building_scanner, tmp_path
):
    """The control: the check reads the path and makes nothing, so the directory
    does not exist while the plugins are built and exists after."""
    bin_dir = tmp_path / "fresh" / "bin"
    building_scanner.watch.append(bin_dir)

    result = runner.invoke(
        dependencies_app, ["--bin-path", str(bin_dir), "--tool", "builds-a-probe"]
    )

    assert result.exit_code == 0, result.output
    assert building_scanner == [False], building_scanner
    assert bin_dir.is_dir()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX reads the backslash")
@pytest.mark.parametrize("bin_path", ["~\\tools", "~ash-no-such-user-xq9/tools"])
def test_a_tilde_user_bin_path_posix_cannot_expand_is_refused(
    quiet_machine, tmp_path, bin_path
):
    """On POSIX `~\\tools` is one path component, not `~` (PurePosixPath reads no
    backslash as a separator, the rule _is_under_tilde follows), so expanduser
    reads `\\tools` as a user name, as it reads `ash-no-such-user-xq9`; neither
    user exists and pathlib raises RuntimeError. Uncaught, that was a traceback,
    exit 1; it is a refusal, exit 3, that creates nothing. The old check accepted
    `~\\` as home on every platform; `~\\x` means home on Windows only now, where
    the backslash is a separator."""
    result = runner.invoke(
        dependencies_app, ["--bin-path", bin_path, "--tool", "sarif"]
    )

    assert result.exit_code == EXIT_INVALID_CONFIG, result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "cannot be expanded" in _flat(result.output), result.output
    assert not (tmp_path / bin_path).exists()
    assert not (tmp_path / "tools").exists()


def test_a_deleted_working_directory_is_the_usage_refusal(
    quiet_machine, tmp_path, monkeypatch
):
    """Path.cwd raises FileNotFoundError once the working directory is gone from
    under the process; the command reports it as a scan does. The directory is
    not removed for real: Windows refuses to remove a process's working directory
    (WinError 32), and the unit tier runs there too."""

    def gone(cls):
        raise FileNotFoundError(errno.ENOENT, "the working directory was removed")

    monkeypatch.setattr(Path, "cwd", classmethod(gone))

    result = runner.invoke(
        dependencies_app, ["--bin-path", str(tmp_path / "bin"), "--tool", "sarif"]
    )

    assert result.exit_code == 5, result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "deleted or unmounted" in _flat(result.output), result.output


@pytest.mark.parametrize("how", ["option", "environment"])
def test_a_relative_bin_path_under_a_deleted_working_directory_is_the_usage_refusal(
    quiet_machine, tmp_path, how
):
    """The bin path was made absolute before the working directory was checked,
    and os.path.abspath reads the working directory for a relative path: the
    command ended in a FileNotFoundError traceback, exit 1, where the same
    deleted directory with an absolute --bin-path is the usage refusal."""
    gone = tmp_path / "gone"
    gone.mkdir()
    before = os.getcwd()
    os.chdir(gone)
    try:
        gone.rmdir()
        if how == "option":
            result = runner.invoke(
                dependencies_app, ["--bin-path", "bin", "--tool", "sarif"]
            )
        else:
            result = runner.invoke(
                dependencies_app, ["--tool", "sarif"], env={"ASH_BIN_PATH": "bin"}
            )
    finally:
        os.chdir(before)

    assert result.exit_code == 5, (result.output, result.exception)
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "deleted or unmounted" in _flat(result.output), result.output


# --- install commands ---


def test_a_command_list_that_is_none_is_a_value_error_for_that_plugin():
    with pytest.raises(ValueError):
        _well_formed_commands(None)


# An argv element that is not text (a number) is a TypeError, and a Path is read
# as its text: pinned in test_dependencies_command_lines_hide_environment_values.py.


def test_a_command_iterable_that_raises_raises_inside_the_check():
    def commands():
        yield ["pip", "install", "x"]
        raise RuntimeError("the generator failed")

    with pytest.raises(RuntimeError):
        _well_formed_commands(commands())


def test_a_custom_command_keeps_its_shell_flag():
    """The flag was dropped before the installer saw the command."""
    commands = _well_formed_commands(
        [CustomCommand(args=["echo $HOME"], shell=True), ["pip", "install", "x"]]
    )

    assert commands == [(["echo $HOME"], True), (["pip", "install", "x"], False)]


def test_a_shell_command_reaches_the_runner_as_one_command_line(monkeypatch):
    """With the flag carried (the base returns the CustomCommand itself), the
    installer handed the runner the argv LIST with shell=True; on POSIX, Popen
    then runs `sh -c` on the first word alone and the rest become $0, $1, ...,
    so a list of words printed an empty line for `echo $HOME`. The one string a
    shell command is declared as reaches the shell as written, the line the
    "Running command" line shows."""
    seen = {}

    def fake_run(args, **kwargs):
        seen["args"] = args
        seen.update(kwargs)
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(subprocess_utils, "run_command", fake_run)
    monkeypatch.setattr(subprocess_utils, "run_succeeded", lambda result: True)

    code = dependencies.run_command(["echo $HOME"], shell=True)

    assert code == 0
    assert seen["args"] == "echo $HOME", seen["args"]
    assert seen["shell"] is True
    assert seen["timeout"] == INSTALL_COMMAND_TIMEOUT_SECONDS


def test_the_opengrep_fix_keeps_the_scripts_arguments():
    """The rewrite rebuilt the command from its first three elements, dropping
    sys.argv, and joined the import with ';', which broke a script that starts
    with a compound statement."""
    cmd = [sys.executable, "-c", "if True:\n    print('opengrep')", "--dest", "x"]

    fixed = _with_path_imported(cmd)

    assert fixed[:2] == [sys.executable, "-c"]
    assert fixed[2].startswith("from pathlib import Path\n")
    assert fixed[3:] == ["--dest", "x"]
    assert _with_path_imported(
        [sys.executable, "-c", "from __future__ import annotations; opengrep"]
    ) == [sys.executable, "-c", "from __future__ import annotations; opengrep"]


def test_uv_python_preference_is_read_as_a_value_option():
    """Missing from the list, its value read as the subcommand: `--python-preference
    managed tool run ...` was judged to read the project's uv config."""
    assert not _uv_reads_project_config(
        ["uv", "--python-preference", "managed", "tool", "run", "x"], False
    )
    assert _uv_reads_project_config(
        ["uv", "--python-preference", "managed", "pip", "install", "x"], False
    )


def test_install_commands_run_with_a_timeout_and_uv_overrides(monkeypatch):
    """No timeout: one stalled download hung the installer for ever. And a
    `python -m uv` command got UV_NO_CONFIG but not the UV_PYTHON / UV_NO_PROJECT
    overrides a plain `uv` command gets."""
    seen = {}

    def fake_run(args, **kwargs):
        seen["args"] = args
        seen.update(kwargs)
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(subprocess_utils, "run_command", fake_run)
    monkeypatch.setattr(subprocess_utils, "run_succeeded", lambda result: True)
    monkeypatch.delenv("UV_PYTHON", raising=False)
    monkeypatch.delenv("UV_SYSTEM_PYTHON", raising=False)

    code = dependencies.run_command([sys.executable, "-m", "uv", "pip", "install", "x"])

    assert code == 0
    assert seen["timeout"] == INSTALL_COMMAND_TIMEOUT_SECONDS
    assert seen["env"]["UV_NO_PROJECT"] == "1"
    assert seen["env"]["UV_PYTHON"] == sys.executable
    assert seen["env"]["UV_NO_CONFIG"] == "1"


# --- the sweep ---


def test_the_sweep_looks_tools_up_as_a_scan_of_the_source_tree_does(
    quiet_machine, tmp_path, monkeypatch
):
    """find_executable with no scanned-tree scope reported a tool found only inside
    the working directory installed, while a scan of that tree refuses it."""
    roots = []

    def scoped(command, root):
        roots.append((command, Path(root)))
        return None

    monkeypatch.setattr(dependencies, "find_executable_for_scan", scoped)

    runner.invoke(
        dependencies_app, ["--bin-path", str(tmp_path / "bin"), "--tool", "grype"]
    )

    assert ("grype", tmp_path) in roots, roots


def test_a_program_a_command_less_plugin_needs_counts_when_missing():
    outcome = _outcome(
        command=None, external_executables=("node",), missing_executables=["node"]
    )

    assert outcome.is_absent
    assert "node not found" in outcome.status


# --- status and summary ---


def test_a_requested_absent_tool_reports_its_own_state():
    """A tool named with --tool fails the run when absent, so its row read
    "DISABLED IN CONFIG" beside a failure for its absence."""
    outcome = _outcome(name="cfn-nag", disabled_by_config=True, requested=True)

    assert outcome.status == "NO INSTALL PATH"
    assert _outcome(name="cfn-nag", disabled_by_config=True).status == (
        "DISABLED IN CONFIG"
    )


def test_a_python_only_plugin_whose_install_succeeded_reads_installed():
    outcome = _outcome(
        name="archive",
        plugin_type="converter",
        command=None,
        commands_attempted=1,
        commands_succeeded=1,
    )

    assert outcome.status == "INSTALLED"


def test_a_requested_absent_tool_is_named_in_one_failure_clause(monkeypatch):
    panels = io.StringIO()
    monkeypatch.setattr(
        dependencies, "console", Console(file=panels, width=300, no_color=True)
    )

    with pytest.raises(typer.Exit):
        _report_and_exit([_outcome(name="grype")], requested_tools=["grype"])

    text = " ".join(panels.getvalue().split())
    assert "requested tool(s) still not on PATH: grype" in text, text
    assert "no install commands were run" not in text, text


def test_a_requested_construction_failure_counts_by_the_request_it_carries(
    monkeypatch,
):
    """The outcome is named by its class and the request by the declared name;
    the tally read the name only, so a disabled plugin's failure was listed as
    not counted and the run passed."""
    panels = io.StringIO()
    monkeypatch.setattr(
        dependencies, "console", Console(file=panels, width=300, no_color=True)
    )
    failure = _outcome(
        name="CfnNagScanner",
        command=None,
        disabled_by_config=True,
        errors=["cfn-nag stand-in cannot be built"],
        requested=True,
    )

    with pytest.raises(typer.Exit) as exit_info:
        _report_and_exit([failure], requested_tools=["cfn-nag"])

    assert exit_info.value.exit_code == 1
    text = " ".join(panels.getvalue().split())
    assert "plugin error(s): CfnNagScanner" in text, text
    assert "not counted" not in text, text


def test_a_tool_uv_alone_lists_is_not_counted_as_verified_on_path(monkeypatch):
    panels = io.StringIO()
    monkeypatch.setattr(
        dependencies, "console", Console(file=panels, width=300, no_color=True)
    )
    outcome = _outcome(
        name="bandit",
        commands_attempted=1,
        commands_succeeded=1,
        uv_managed=True,
        executable="uv tool bandit",
    )

    assert _report_and_exit([outcome], requested_tools=[]) == 0
    text = " ".join(panels.getvalue().split())
    assert "Tools verified on PATH: 0" in text, text
    assert "Tools uv manages, in its listing (not on PATH): 1 -- bandit" in text, text


def test_a_disabled_section_is_read_without_building_the_plugin():
    resolved = SimpleNamespace(get_plugin_config=lambda **_: {"enabled": False})
    enabled = SimpleNamespace(get_plugin_config=lambda **_: {"enabled": True})

    class Plugin:
        pass

    assert _section_disables(resolved, "scanner", Plugin)
    assert not _section_disables(enabled, "scanner", Plugin)


def test_no_color_reaches_the_panels_and_the_print_lines(
    quiet_machine, tmp_path, monkeypatch
):
    """--no-color reached the logger only. The panels are written through
    ``dependencies.console``, which the fixture replaces with a console that is
    already without color; it is set to color here, so the assertion reaches the
    command's own change and not the fixture's."""
    from automated_security_helper.utils.console import global_console

    shared = global_console()
    monkeypatch.setattr(shared, "no_color", False)
    monkeypatch.setattr(dependencies.err_console, "no_color", False)
    monkeypatch.setattr(dependencies.console, "no_color", False)

    runner.invoke(
        dependencies_app,
        ["--bin-path", str(tmp_path / "bin"), "--tool", "sarif", "--no-color"],
    )

    assert shared.no_color is True
    assert dependencies.err_console.no_color is True
    assert dependencies.console.no_color is True
