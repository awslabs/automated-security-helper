# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fixes in run_ash_container around the runner prefix, the run phase and --no-build.

* ``OCI_RUNNER_WRAPPER`` is split on space, tab and newline only, with no quote or
  backslash processing, as ``./ash`` and ``Invoke-ASH`` split it.
* An ``extends`` entry holding a NUL is refused as an unusable entry, not raised
  as ValueError out of the host's checks.
* A SIGTERM relayed as an exit while the runtime runs stops the runtime first.
* The pipe reader drains the child's output to its end after a failed console
  write, so the child never blocks on a full pipe.
* A runtime that cannot be started comes back as a run that never started.
* The --debug line for a failed run shows the command with each override value
  as its key, and the output kept on a result hides the run's carried values.
* ``--no-build`` neither refuses a revision derived from the install nor runs the
  stock image when ``--custom-containerfile`` names the custom one.
"""

from __future__ import annotations

import io
import os
import subprocess
from typing import List

import pytest

from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.interactions.run_ash_container import (
    run_cmd_direct as _real_run_cmd_direct,
)
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import create_completed_process

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# OCI_RUNNER_WRAPPER
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value, words",
    [
        pytest.param(
            r"sudo C:\tools\wrap.exe", ["sudo", r"C:\tools\wrap.exe"], id="backslashes"
        ),
        pytest.param("sudo it's", ["sudo", "it's"], id="unbalanced-quote"),
        pytest.param('sudo "a b"', ["sudo", '"a', 'b"'], id="quotes-are-text"),
        pytest.param("sudo\x0bwrap", ["sudo\x0bwrap"], id="vertical-tab-is-a-word"),
        pytest.param(" sudo\t-E \n", ["sudo", "-E"], id="ifs-only"),
    ],
)
def test_the_wrapper_is_split_as_the_shell_wrappers_split_it(monkeypatch, value, words):
    monkeypatch.setenv("OCI_RUNNER_WRAPPER", value)

    assert rac._get_oci_wrapper_prefix() == words


# ---------------------------------------------------------------------------
# An extends entry with a NUL
# ---------------------------------------------------------------------------


def test_an_extends_entry_holding_a_nul_is_refused_not_raised(tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    (tmp_path / "src").mkdir()
    config = tmp_path / "operator" / "ash.yaml"
    config.parent.mkdir()
    config.write_text('project_name: p\nextends: "base\\0.yaml"\n', encoding="utf-8")

    refusal = rac.container_input_refusal(
        str(tmp_path / "src"), str(tmp_path / "out"), str(config)
    )

    assert isinstance(refusal, str), refusal
    assert "NUL" in refusal, refusal
    assert "extends" in refusal, refusal


# ---------------------------------------------------------------------------
# The run phase
# ---------------------------------------------------------------------------


class _Pipe:
    def __init__(self, text: str = "") -> None:
        self._stream = io.StringIO(text)

    def readline(self) -> str:
        return self._stream.readline()


class _Runtime:
    """A runtime that runs until stopped; its second poll calls ``on_poll``."""

    def __init__(self, on_poll=None, stdout: str = "", stderr: str = "") -> None:
        self.stdout = _Pipe(stdout)
        self.stderr = _Pipe(stderr)
        self.returncode = None
        self.pid = os.getpid()
        self.polls = 0
        self.on_poll = on_poll
        self.killed = False

    def kill(self):
        self.killed = True

    def poll(self):
        self.polls += 1
        if self.polls > 300:
            raise RuntimeError("polled past the bound")
        if self.polls == 2 and self.on_poll is not None:
            self.on_poll()
        return self.returncode


def test_an_exit_raised_while_the_runtime_runs_stops_it_first(monkeypatch):
    """A SIGTERM relayed as SystemExit by the run step's wrapper: the runtime
    received nothing, so it is stopped as the cancel path stops it."""

    def relayed_exit():
        raise SystemExit(143)

    runtime = _Runtime(on_poll=relayed_exit)
    monkeypatch.setattr(
        subprocess_utils, "create_process_with_pipes", lambda **kw: runtime
    )
    stops = []

    def stop(process, **kwargs):
        stops.append(kwargs)
        process.returncode = -15

    monkeypatch.setattr(rac, "_stop_after_interrupt", stop)

    with pytest.raises(SystemExit) as exited:
        rac.run_cmd_direct(["runtime", "run", "scan"])

    assert exited.value.code == 143
    assert stops == [{"child_got_the_interrupt": False}]


@pytest.mark.parametrize(
    "first",
    [
        pytest.param(lambda: SystemExit(143), id="a-sigterm-then-a-sigterm"),
        pytest.param(KeyboardInterrupt, id="a-sigint-then-a-sigterm"),
    ],
)
def test_a_second_exit_inside_the_stop_still_kills_the_runtime(monkeypatch, first):
    """A CI cancel sends SIGTERM again (or SIGINT, then SIGTERM) while ASH waits
    out the runtime's grace. The second signal reaches the wait as a SystemExit,
    which the wait does not handle, so the exit unwound with the runtime still
    running after ASH had gone."""

    def first_signal():
        raise first()

    runtime = _Runtime(on_poll=first_signal)
    monkeypatch.setattr(
        subprocess_utils, "create_process_with_pipes", lambda **kw: runtime
    )

    def stop_cut_short(process, **kwargs):
        raise SystemExit(143)

    monkeypatch.setattr(rac, "_stop_after_interrupt", stop_cut_short)

    with pytest.raises(SystemExit) as exited:
        rac.run_cmd_direct(["runtime", "run", "scan"])

    assert exited.value.code == 143
    assert runtime.killed is True


def test_a_stop_that_ends_normally_does_not_kill_the_runtime(monkeypatch):
    """Control: a runtime that stopped in its grace is left as it is."""

    def relayed_exit():
        raise SystemExit(143)

    runtime = _Runtime(on_poll=relayed_exit)
    monkeypatch.setattr(
        subprocess_utils, "create_process_with_pipes", lambda **kw: runtime
    )
    monkeypatch.setattr(rac, "_stop_after_interrupt", lambda process, **kw: True)

    with pytest.raises(SystemExit):
        rac.run_cmd_direct(["runtime", "run", "scan"])

    assert runtime.killed is False


def test_the_reader_drains_the_pipe_after_a_failed_console_write(monkeypatch):
    class BrokenConsole:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def write(self, text):
            raise OSError("console gone")

    runtime = _Runtime(stdout="one\ntwo\nthree\n")
    runtime.returncode = 0
    monkeypatch.setattr(
        subprocess_utils, "create_process_with_pipes", lambda **kw: runtime
    )
    monkeypatch.setattr(rac, "CommandSafeStream", BrokenConsole)

    result = rac.run_cmd_direct(["runtime", "run", "scan"], check=False)

    assert result.stdout == "one\ntwo\nthree\n"


def _cannot_spawn(**kwargs):
    raise FileNotFoundError(2, "No such file or directory", "/nonexistent/docker")


def test_a_runtime_that_cannot_be_started_is_a_run_that_never_started(monkeypatch):
    """Through the real run_cmd_direct: the spawn is what fails."""
    monkeypatch.setattr(subprocess_utils, "create_process_with_pipes", _cannot_spawn)

    result = rac._execute_container(
        ["/nonexistent/docker", "run", "img", "ash"], debug=False
    )

    assert not rac.container_was_started(result)
    assert result.returncode == 1
    assert "could not be started" in result.stderr


def _fails_after_the_runtime_started(cmd, debug=False, env=None):
    raise BrokenPipeError(32, "Broken pipe")


def test_an_error_raised_while_the_runtime_ran_is_not_a_run_that_never_started(
    monkeypatch,
):
    """An OSError out of the wait (a signal to the runtime refused, a pipe closed
    under it) came after the runtime started; it was reported as one that could
    not be started."""
    monkeypatch.setattr(rac, "run_cmd_direct", _fails_after_the_runtime_started)

    result = rac._execute_container(
        ["/nonexistent/docker", "run", "img", "ash"], debug=False
    )

    assert rac.container_was_started(result)
    assert result.returncode == 1
    assert "failed while it ran" in result.stderr


def test_the_debug_line_for_a_failed_run_shows_overrides_by_key(monkeypatch, capfd):
    planted = "override-value-7f3a1c"
    cmd = [
        "docker",
        "run",
        "img",
        "ash",
        "--config-overrides",
        f"project_name={planted}",
    ]

    def fails(cmd_list, debug=False, env=None):
        raise subprocess.CalledProcessError(1, list(cmd_list))

    monkeypatch.setattr(rac, "run_cmd_direct", fails)

    result = rac._execute_container(cmd, debug=True)

    out, err = capfd.readouterr()
    assert isinstance(result, subprocess.CalledProcessError)
    assert planted not in out, out
    assert planted not in err, err
    assert "project_name" in out


def test_the_output_kept_on_a_result_hides_the_runs_carried_values(monkeypatch):
    carried = "carried-environment-value-4e9b"

    def completed(cmd_list, debug=False, env=None):
        return create_completed_process(
            args=list(cmd_list),
            returncode=125,
            stdout=f"scan log mentions {carried}\n",
            stderr=f"mount failed for {carried}\n",
        )

    monkeypatch.setattr(rac, "run_cmd_direct", completed)

    with subprocess_utils._spawn_values((carried,)):
        result = rac._execute_container(["docker", "run", "img", "ash"], debug=False)

    assert carried not in result.stdout, result.stdout
    assert carried not in result.stderr, result.stderr
    assert "mount failed" in result.stderr


# ---------------------------------------------------------------------------
# --no-build
# ---------------------------------------------------------------------------


@pytest.fixture
def commands(monkeypatch, tmp_path) -> List[List[str]]:
    seen: List[List[str]] = []

    def record(cmd_list, check=True, debug=False, shell=False, env=None):
        cmd = [str(item) for item in cmd_list if item is not None]
        seen.append(cmd)
        return create_completed_process(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 1000)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 1000)
    monkeypatch.setattr(rac, "_host_is_windows", lambda: False)
    monkeypatch.setattr(
        rac, "_find_runner", lambda _name: "/nonexistent/ash-test/docker"
    )
    monkeypatch.setattr(rac, "_runner_supports_buildx", lambda _runner: False)
    monkeypatch.setattr(rac, "run_cmd_direct", record)
    for name in ("CI", "ASH_IMAGE_NAME", "ASH_CONFIG", "OCI_RUNNER_WRAPPER"):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / "src").mkdir()
    monkeypatch.chdir(tmp_path)
    return seen


def _run_command(commands: List[List[str]]) -> List[str]:
    (run,) = [cmd for cmd in commands if cmd[1] == "run"]
    return run


def test_no_build_does_not_refuse_a_revision_derived_from_the_install(
    commands, monkeypatch
):
    """Nothing is installed into an image that is not built, so a revision the
    build could not take is no reason to refuse the run."""
    monkeypatch.setattr(rac, "get_ash_revision", lambda quiet=False: "odd;ref")

    result = rac.run_ash_container(source_dir="src", build=False, run=True)

    assert result.returncode == 0, result.stderr
    assert [cmd[1] for cmd in commands] == ["run"]


def test_a_build_still_refuses_a_revision_derived_from_the_install(
    commands, monkeypatch, tmp_path
):
    """Control."""
    monkeypatch.setattr(rac, "get_ash_revision", lambda quiet=False: "odd;ref")

    result = rac.run_ash_container(source_dir="src", build=True, run=True)

    assert result.returncode == 1
    assert "Invalid ASH revision" in result.stderr
    assert commands == []


def test_the_record_of_a_container_that_may_still_run_is_kept(commands, monkeypatch):
    """A failure raised while the runtime ran says nothing of its container, so
    the leftover record stays for the next sweep; run_ash_container dropped it
    with the record of one that never existed."""
    discarded = []
    monkeypatch.setattr(rac, "discard_record", discarded.append)
    monkeypatch.setattr(rac, "run_cmd_direct", _fails_after_the_runtime_started)

    result = rac.run_ash_container(source_dir="src", build=False, run=True)

    assert result.returncode == 1
    assert discarded == []


def test_the_record_of_a_container_that_never_started_is_dropped(commands, monkeypatch):
    """Control: no container existed, so its record goes."""
    discarded = []
    monkeypatch.setattr(rac, "discard_record", discarded.append)
    monkeypatch.setattr(rac, "run_cmd_direct", _real_run_cmd_direct)
    monkeypatch.setattr(subprocess_utils, "create_process_with_pipes", _cannot_spawn)

    result = rac.run_ash_container(source_dir="src", build=False, run=True)

    assert not rac.container_was_started(result)
    assert len(discarded) == 1


def test_no_build_with_a_custom_containerfile_runs_the_custom_image(commands, tmp_path):
    containerfile = tmp_path / "Containerfile.custom"
    containerfile.write_text("FROM scratch\n", encoding="utf-8")

    result = rac.run_ash_container(
        source_dir="src",
        build=False,
        run=True,
        custom_containerfile=str(containerfile),
    )

    assert result.returncode == 0, result.stderr
    run = _run_command(commands)
    assert run[run.index("ash") - 1] == "automated-security-helper:custom"


def test_no_build_without_a_custom_containerfile_runs_the_stock_image(commands):
    """Control: the stage's own image, non-root off Windows."""
    result = rac.run_ash_container(source_dir="src", build=False, run=True)

    assert result.returncode == 0, result.stderr
    run = _run_command(commands)
    assert run[run.index("ash") - 1] == "automated-security-helper:non-root"


def test_an_image_named_by_the_environment_wins_over_the_custom_default(
    commands, monkeypatch, tmp_path
):
    monkeypatch.setenv("ASH_IMAGE_NAME", "registry.example/ash:pinned")
    containerfile = tmp_path / "Containerfile.custom"
    containerfile.write_text("FROM scratch\n", encoding="utf-8")

    result = rac.run_ash_container(
        source_dir="src",
        build=False,
        run=True,
        custom_containerfile=str(containerfile),
    )

    assert result.returncode == 0, result.stderr
    run = _run_command(commands)
    assert run[run.index("ash") - 1] == "registry.example/ash:pinned"


# ---------------------------------------------------------------------------
# --min-severity reaches a workspace scan inside the container
# ---------------------------------------------------------------------------


def _assembled(tmp_path, **extra):
    from automated_security_helper.core.enums import ExecutionPhase, ExecutionStrategy

    (tmp_path / "src").mkdir(exist_ok=True)
    (tmp_path / "out").mkdir(exist_ok=True)
    kwargs = {
        "oci_command_prefix": [],
        "resolved_oci_runner": "docker",
        "image_name": "ash:test",
        "source_dir": (tmp_path / "src").resolve(),
        "output_dir": (tmp_path / "out").resolve(),
        "offline": False,
        "debug": False,
        "color": False,
        "quiet": True,
        "progress": False,
        "verbose": False,
        "simple": True,
        "python_based_plugins_only": False,
        "cleanup": False,
        "inspect": False,
        "fail_on_findings": None,
        "phases": [ExecutionPhase.SCAN],
        "scanners": [],
        "exclude_scanners": [],
        "output_formats": [],
        "config": None,
        "config_overrides": [],
        "existing_results": None,
        "ash_plugin_modules": [],
        "strategy": ExecutionStrategy.PARALLEL,
        "ctx": None,
    }
    kwargs.update(extra)
    return rac._assemble_run_command(**kwargs)


def test_a_workspace_scan_inside_the_container_is_given_the_minimum_severity(
    tmp_path, monkeypatch
):
    """The host returns a workspace scan's exit code as the container computed
    it, so a minimum the container never saw was applied nowhere."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)

    cmd = _assembled(
        tmp_path, workspace_relative_file="dev.code-workspace", min_severity="high"
    )

    assert cmd[cmd.index("--min-severity") + 1] == "high"


def test_a_one_directory_scan_inside_the_container_is_not(tmp_path, monkeypatch):
    """Control: the host recomputes a one-directory exit code and applies the
    minimum itself, so the container is not told."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)

    cmd = _assembled(tmp_path, min_severity="high")

    assert "--min-severity" not in cmd


def test_the_default_minimum_is_not_forwarded(tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)

    cmd = _assembled(
        tmp_path, workspace_relative_file="dev.code-workspace", min_severity="low"
    )

    assert "--min-severity" not in cmd
