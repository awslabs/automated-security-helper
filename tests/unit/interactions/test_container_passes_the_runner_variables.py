# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Container mode and ./ash pass the runner variables into the container.

Under GitHub Actions, Azure Pipelines and TeamCity (GITHUB_ACTIONS, TF_BUILD,
TEAMCITY_VERSION), ASH's console checks a terminal's lines for workflow commands
too, because a job that gives ASH a terminal still has every line read by the
runner (utils/console.py). Container mode adds -t to the container's run when its
own output is a terminal, so the scan inside writes to a terminal, and container
mode and ./ash pass each of those variables that is set in by name, so the scan
inside checks its lines for workflow commands too.

Through OCI_RUNNER_WRAPPER, which need not pass its environment on (sudo's default
env_reset does not), a variable passed by name reached the container empty. There
each of the three goes with its value, as one argument, because they are public
markers of the CI system. No other variable's value goes on the runner's command
line, and a marker holding a newline (or, in container mode, a NUL) is refused
with exit 3 rather than put there.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from tests.unit.interactions.test_run_ash_container_helpers_coverage import (
    _run_command,
)

RUNNERS = [
    pytest.param("GITHUB_ACTIONS", "true", id="github-actions"),
    pytest.param("TF_BUILD", "True", id="azure-pipelines"),
    pytest.param("TEAMCITY_VERSION", "2024.12", id="teamcity"),
]
RUNNER_NAMES = ("GITHUB_ACTIONS", "TF_BUILD", "TEAMCITY_VERSION")
REPO_ROOT = Path(__file__).resolve().parents[3]
ASH_SCRIPT = REPO_ROOT / "ash"
IMAGE = "automated-security-helper:non-root"


class _Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


def _passed_env(run_argv: list[str], image: str) -> list[str]:
    """What each -e before the image name passes."""
    before_image = run_argv[: run_argv.index(image)]
    return [before_image[i + 1] for i, arg in enumerate(before_image) if arg == "-e"]


@pytest.mark.parametrize("name, value", RUNNERS)
def test_a_terminal_run_under_a_runner_passes_its_variable_in(
    tmp_path, monkeypatch, name, value
):
    for other in RUNNER_NAMES:
        monkeypatch.delenv(other, raising=False)
    monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "stdout", _Tty())

    cmd = _run_command(tmp_path, tmp_path / "out", color=True)

    assert "-t" in cmd, cmd
    # By name, so the container gets the job's own value.
    assert name in _passed_env(cmd, "ash:test"), cmd


def test_without_a_runner_variable_none_is_passed(tmp_path, monkeypatch):
    for name in RUNNER_NAMES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(sys, "stdout", _Tty())

    cmd = _run_command(tmp_path, tmp_path / "out", color=True)

    passed = [env.split("=", 1)[0] for env in _passed_env(cmd, "ash:test")]
    assert not set(passed) & set(RUNNER_NAMES), cmd


#: As in test_ash_bash_entrypoint_subcommand_args.py: Windows runners' bash is the
#: WSL stub, and the installed-package layout has no ./ash.
needs_the_bash_entrypoint = pytest.mark.skipif(
    os.name == "nt" or shutil.which("bash") is None or not ASH_SCRIPT.is_file(),
    reason="needs bash and the repository's POSIX ./ash entrypoint",
)

RECORDING_RUNNER = """#!/bin/bash
echo "FAKE-RUNNER-INVOKED-WITH: $*"
exit 0
"""


def _ash_run_argv(tmp_path: Path, env: dict[str, str]) -> list[str]:
    """The argv ./ash hands a recording OCI runner's `run`."""
    runner = tmp_path / "fake-oci-runner"
    runner.write_text(RECORDING_RUNNER)
    runner.chmod(runner.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
    source_dir = tmp_path / "src"
    source_dir.mkdir(exist_ok=True)
    base = {k: v for k, v in os.environ.items() if k not in RUNNER_NAMES}
    result = subprocess.run(  # nosec B603 B607 - fixed script path, list args, no shell
        [
            "bash",
            str(ASH_SCRIPT),
            "--no-build",
            "--source-dir",
            str(source_dir),
            "--output-dir",
            str(tmp_path / "out"),
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        env={**base, "OCI_RUNNER": str(runner), **env},
        timeout=180,
        check=False,
    )
    lines = [
        line
        for line in result.stdout.splitlines()
        if line.startswith("FAKE-RUNNER-INVOKED-WITH: run ")
    ]
    assert len(lines) == 1, result.stdout + result.stderr
    return lines[0].split()


@needs_the_bash_entrypoint
@pytest.mark.parametrize("name, value", RUNNERS)
def test_the_bash_entrypoint_passes_the_runner_variable_in(tmp_path, name, value):
    run_argv = _ash_run_argv(tmp_path, {name: value})

    assert name in _passed_env(run_argv, IMAGE), run_argv


@needs_the_bash_entrypoint
def test_the_bash_entrypoint_passes_none_without_one(tmp_path):
    run_argv = _ash_run_argv(tmp_path, {})

    passed = [env.split("=", 1)[0] for env in _passed_env(run_argv, IMAGE)]
    assert not set(passed) & set(RUNNER_NAMES), run_argv


# Through OCI_RUNNER_WRAPPER. A runner stand-in records its argv and the variables of
# interest in its environment; the container's environment is what a runner makes of
# those (-e NAME takes the runner's own value, -e NAME=value the given one).

#: TeamCity's value holds spaces, which must reach the container as one value.
MARKERS = {
    "GITHUB_ACTIONS": "true",
    "TF_BUILD": "True",
    "TEAMCITY_VERSION": "2024.12 (build 1234)",
}
#: Values that must never reach the runner's command line: one an operator's config
#: reads, and one in an arbitrary CI_* variable.
CONFIG_CANARY = "ash-config-canary-5e1d-0123456789"
CI_CANARY = "ash-ci-canary-77b2-0123456789"
CANARIES = {"ASH_PROBE_VALUE": CONFIG_CANARY, "CI_PROBE_TOKEN": CI_CANARY}
NEWLINE_TAIL = "newline-tail-3f9c"
WITH_A_NEWLINE = {**MARKERS, "TEAMCITY_VERSION": f"2024.12\n{NEWLINE_TAIL}"}

RECORDING_RUNNER_FILES = """#!{python}
import json, os, sys
out = {out!r}
with open(os.path.join(out, "calls"), "a", encoding="utf-8") as calls:
    calls.write((sys.argv[1] if len(sys.argv) > 1 else "") + "\\n")
if sys.argv[1:2] == ["run"]:
    names = {names!r}
    with open(os.path.join(out, "run.json"), "w", encoding="utf-8") as record:
        json.dump(
            {{"argv": sys.argv[1:], "env": {{n: os.environ.get(n) for n in names}}}},
            record,
        )
"""
WRAPPERS = {
    "passes-its-environment": '#!/bin/sh\nexec "$@"\n',
    "resets-its-environment": '#!/bin/sh\nexec /usr/bin/env -i PATH=/usr/bin:/bin "$@"\n',
}

posix_runner_stand_ins = pytest.mark.skipif(
    os.name == "nt", reason="needs POSIX runner and wrapper stand-ins"
)


def _executable(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
    return path


def _recording_runner(directory: Path, out: Path) -> Path:
    text = RECORDING_RUNNER_FILES.format(
        python=sys.executable, out=str(out), names=[*MARKERS, *CANARIES]
    )
    return _executable(directory / "docker", text)


def _calls(out: Path) -> list[str]:
    """The first argument of every call the runner stand-in got."""
    calls = out / "calls"
    return calls.read_text(encoding="utf-8").splitlines() if calls.exists() else []


def _recorded(out: Path) -> tuple[list[str], dict[str, str]]:
    """The runner's `run` argv, and the environment the container gets from it."""
    record = json.loads((out / "run.json").read_text(encoding="utf-8"))
    argv, runner_env = record["argv"], record["env"]
    inside: dict[str, str] = {}
    for flag, value in zip(argv, argv[1:]):
        if flag == "-e":
            name, sep, given = value.partition("=")
            if sep:
                inside[name] = given
            elif runner_env.get(name) is not None:
                inside[name] = runner_env[name]
    return argv, inside


def _passed(argv: list[str]) -> list[str]:
    return [argv[i + 1] for i, arg in enumerate(argv[:-1]) if arg == "-e"]


def _given_values(argv: list[str]) -> set[str]:
    """The names passed as -e NAME=value."""
    return {value.partition("=")[0] for value in _passed(argv) if "=" in value}


def _container_mode(tmp_path, monkeypatch, env, wrapper, *, build=False):
    """Run `ash scan --mode container` against a recording runner."""
    from typer.testing import CliRunner

    from automated_security_helper.cli.main import app
    from automated_security_helper.interactions import run_ash_container as rac
    from automated_security_helper.utils import subprocess_utils

    out = tmp_path / "recorded"
    out.mkdir(parents=True)
    runner = _recording_runner(tmp_path, out)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 1000)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 1000)
    monkeypatch.setattr(rac, "_find_runner", lambda _name: str(runner))
    for name in (*RUNNER_NAMES, *CANARIES, "ASH_CONFIG", "ASH_IMAGE_NAME"):
        monkeypatch.delenv(name, raising=False)
    for name in ("OCI_RUNNER", "OCI_RUNNER_WRAPPER"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    if wrapper is not None:
        path = _executable(tmp_path / wrapper, WRAPPERS[wrapper])
        monkeypatch.setenv("OCI_RUNNER_WRAPPER", str(path))
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    # Inside the source directory, so the config rides the /src mount and the
    # run command carries no config mount of its own: these cells measure the
    # runner markers, not the config handover.
    operator = tmp_path / "src" / "ash-operator.yaml"
    operator.write_text("project_name: ${ASH_PROBE_VALUE}\n", encoding="utf-8")
    args = ["scan", "--mode", "container", "--no-progress"]
    args += [] if build else ["--no-build"]
    args += ["--source-dir", "src", "--output-dir", "out", "--config", str(operator)]
    result = CliRunner().invoke(app, args, env={"COLUMNS": "300"})
    return result, out


@posix_runner_stand_ins
@pytest.mark.parametrize("wrapper", [None, *WRAPPERS])
def test_container_mode_gives_the_markers_through_any_wrapper(
    tmp_path, monkeypatch, wrapper
):
    _result, out = _container_mode(
        tmp_path, monkeypatch, {**MARKERS, **CANARIES}, wrapper
    )

    argv, inside = _recorded(out)
    assert {name: inside.get(name) for name in MARKERS} == MARKERS, argv
    if wrapper is None:
        # By name, as before: the runner has this process's environment.
        assert set(MARKERS) <= set(_passed(argv)), argv
    else:
        # With its value, each as one argument, so TeamCity's spaces stay in it.
        given = {f"{name}={value}" for name, value in MARKERS.items()}
        assert given <= set(_passed(argv)), argv


@posix_runner_stand_ins
def test_through_a_wrapper_only_the_markers_go_on_argv_with_a_value(
    tmp_path, monkeypatch
):
    from automated_security_helper.interactions import run_ash_container as rac

    # Spelled out rather than taken from the runner list, so a name added there
    # later is passed by name, and its value never goes on the command line.
    assert rac.RUNNER_MARKERS_ON_ARGV == (
        "GITHUB_ACTIONS",
        "TF_BUILD",
        "TEAMCITY_VERSION",
    )
    monkeypatch.setattr(
        rac,
        "COMMAND_READING_RUNNERS",
        (*rac.COMMAND_READING_RUNNERS, "CI_PROBE_TOKEN"),
    )
    wrapper = "resets-its-environment"

    _baseline, baseline_out = _container_mode(
        tmp_path / "baseline", monkeypatch, CANARIES, wrapper
    )
    _marked, marked_out = _container_mode(
        tmp_path / "marked", monkeypatch, {**CANARIES, **MARKERS}, wrapper
    )

    baseline_argv, _ = _recorded(baseline_out)
    marked_argv, inside = _recorded(marked_out)
    # The markers are the only names the variables add as NAME=value; the rest are
    # ASH's own (its paths, the terminal size, the scan source label).
    assert _given_values(marked_argv) - _given_values(baseline_argv) == set(MARKERS)
    assert "CI_PROBE_TOKEN" in _passed(marked_argv), marked_argv
    for argv in (baseline_argv, marked_argv):
        assert not [arg for arg in argv if CONFIG_CANARY in arg or CI_CANARY in arg]
    assert {name: inside.get(name) for name in MARKERS} == MARKERS, marked_argv


@pytest.mark.parametrize(
    "value",
    [f"True\n{NEWLINE_TAIL}", f"True\0{NEWLINE_TAIL}"],
    ids=["newline", "nul"],
)
def test_the_argv_path_refuses_a_marker_holding_a_newline_or_nul(value):
    # A POSIX environment cannot hold a NUL, so this cell gives the mapping itself.
    from automated_security_helper.interactions import run_ash_container as rac

    with pytest.raises(rac.RunnerMarkerRefused) as refused:
        rac._runner_marker_args(["wrapper"], {"TF_BUILD": value})

    assert "TF_BUILD" in str(refused.value)
    assert NEWLINE_TAIL not in str(refused.value)
    # By name the value never goes on the command line, so it is not refused.
    assert rac._runner_marker_args([], {"TF_BUILD": value}) == ["-e", "TF_BUILD"]


@posix_runner_stand_ins
def test_container_mode_refuses_a_marker_holding_a_newline_before_building(
    tmp_path, monkeypatch
):
    result, out = _container_mode(
        tmp_path,
        monkeypatch,
        {**WITH_A_NEWLINE, **CANARIES},
        "passes-its-environment",
        build=True,
    )

    assert result.exit_code == 3, result.output
    assert "TEAMCITY_VERSION" in result.output, result.output
    assert NEWLINE_TAIL not in result.output, result.output
    assert not {"build", "run"} & set(_calls(out)), _calls(out)


@posix_runner_stand_ins
def test_without_a_wrapper_a_marker_holding_a_newline_still_goes_by_name(
    tmp_path, monkeypatch
):
    _result, out = _container_mode(
        tmp_path, monkeypatch, {**WITH_A_NEWLINE, **CANARIES}, None
    )

    argv, _inside = _recorded(out)
    assert "TEAMCITY_VERSION" in _passed(argv), argv
    assert not [arg for arg in argv if NEWLINE_TAIL in arg], argv


def _ash_through(
    tmp_path: Path,
    env: dict[str, str],
    wrapper: str | None,
    *,
    build=False,
    debug=False,
):
    """Run ./ash against a recording runner, through the wrapper stand-in named."""
    out = tmp_path / "recorded"
    out.mkdir()
    runner = _recording_runner(tmp_path, out)
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    dropped = {*RUNNER_NAMES, *CANARIES, "OCI_RUNNER_WRAPPER"}
    base = {k: v for k, v in os.environ.items() if k not in dropped}
    given = {"OCI_RUNNER": str(runner)}
    if wrapper is not None:
        path = _executable(tmp_path / wrapper, WRAPPERS[wrapper])
        given["OCI_RUNNER_WRAPPER"] = str(path)
    argv = ["bash", str(ASH_SCRIPT)] + ([] if build else ["--no-build"])
    argv += ["--debug"] if debug else []
    argv += ["--source-dir", str(source_dir), "--output-dir", str(tmp_path / "out")]
    result = subprocess.run(  # nosec B603 B607 - fixed script path, list args, no shell
        argv,
        capture_output=True,
        text=True,
        # Bytes that are not UTF-8 come back as surrogates, for a cell to find.
        errors="surrogateescape",
        cwd=str(REPO_ROOT),
        env={**base, **given, **env},
        timeout=180,
        check=False,
    )
    return result, out


@needs_the_bash_entrypoint
@pytest.mark.parametrize("wrapper", list(WRAPPERS))
def test_the_bash_entrypoint_gives_the_markers_through_a_wrapper(tmp_path, wrapper):
    result, out = _ash_through(tmp_path, {**MARKERS, **CANARIES}, wrapper)

    argv, inside = _recorded(out)
    assert {name: inside.get(name) for name in MARKERS} == MARKERS, argv
    # One argument each: TeamCity's spaces do not split it into words.
    given = {f"{name}={value}" for name, value in MARKERS.items()}
    assert given <= set(_passed(argv)), argv
    assert not [arg for arg in argv if CI_CANARY in arg], argv


@needs_the_bash_entrypoint
def test_the_bash_entrypoint_refuses_a_marker_holding_a_newline_before_building(
    tmp_path,
):
    result, out = _ash_through(
        tmp_path, WITH_A_NEWLINE, "passes-its-environment", build=True
    )

    assert result.returncode == 3, result.stdout + result.stderr
    assert "TEAMCITY_VERSION" in result.stderr, result.stderr
    assert NEWLINE_TAIL not in result.stdout + result.stderr
    assert not {"build", "run"} & set(_calls(out)), _calls(out)


#: A marker whose value holds characters a terminal acts on: ESC (a screen clear),
#: BEL and U+202E, which reverses the text after it (spelled with chr, so this file
#: holds no raw one).
RIGHT_TO_LEFT_OVERRIDE = chr(0x202E)
WITH_CONTROLS = {
    **MARKERS,
    "TEAMCITY_VERSION": f"2024.12\x1b[2J\x07{RIGHT_TO_LEFT_OVERRIDE}(build 1)",
}


@needs_the_bash_entrypoint
def test_the_bash_entrypoint_traces_the_markers_shown_under_debug(tmp_path):
    """./ash --debug traces its commands. Through a wrapper the run line carries the
    markers' values, so it is traced as shown: a control in a marker is written out,
    not sent to the terminal. The marker still reaches the container as it is."""
    result, out = _ash_through(
        tmp_path, WITH_CONTROLS, "passes-its-environment", debug=True
    )

    output = result.stdout + result.stderr
    for character in ("\x1b", "\x07", RIGHT_TO_LEFT_OVERRIDE):
        assert character not in output, ascii(output[-2000:])
    # Nor any part of one: a byte of U+202E traced alone is not UTF-8.
    assert not [c for c in output if "\udc80" <= c <= "\udcff"], ascii(output[-2000:])
    assert "TEAMCITY_VERSION=" in result.stderr, result.stderr[-2000:]
    _argv, inside = _recorded(out)
    assert inside.get("TEAMCITY_VERSION") == WITH_CONTROLS["TEAMCITY_VERSION"]


#: An OCI_RUNNER_WRAPPER of only whitespace is no wrapper on both surfaces: container
#: mode's prefix is the value's words, none, and ./ash's prefix line splits it into no
#: word. So the markers go by name there, and none goes on the command line.
ONLY_WHITESPACE = {"OCI_RUNNER_WRAPPER": " \t "}


@posix_runner_stand_ins
def test_container_mode_takes_a_wrapper_of_only_whitespace_as_none(
    tmp_path, monkeypatch
):
    # With CANARIES: the helper's config reads ${ASH_PROBE_VALUE}, and the
    # host resolves the config before the run, as a local scan would, so an
    # unset reference would refuse the run before this cell's wrapper
    # handling is reached.
    _result, out = _container_mode(
        tmp_path, monkeypatch, {**MARKERS, **CANARIES, **ONLY_WHITESPACE}, None
    )

    argv, _inside = _recorded(out)
    assert set(MARKERS) <= set(_passed(argv)), argv
    assert not _given_values(argv) & set(MARKERS), argv


@needs_the_bash_entrypoint
def test_the_bash_entrypoint_takes_a_wrapper_of_only_whitespace_as_none(tmp_path):
    _result, out = _ash_through(tmp_path, {**MARKERS, **ONLY_WHITESPACE}, None)

    argv, _inside = _recorded(out)
    assert set(MARKERS) <= set(_passed(argv)), argv
    assert not _given_values(argv) & set(MARKERS), argv


@needs_the_bash_entrypoint
def test_the_bash_entrypoint_takes_a_wrapper_of_other_whitespace_as_a_wrapper(
    tmp_path,
):
    """The prefix line splits on IFS, which is space, tab and newline only, so it
    runs a wrapper of only a vertical tab as a command of that name. The markers
    then go with their values, as through any wrapper. Here a wrapper stand-in that
    resets its environment has that name, first on PATH."""
    bin_dir = tmp_path / "wrapper-bin"
    bin_dir.mkdir()
    _executable(bin_dir / "\v", WRAPPERS["resets-its-environment"])
    path = f"{bin_dir}{os.pathsep}{os.environ['PATH']}"

    _result, out = _ash_through(
        tmp_path, {**MARKERS, "OCI_RUNNER_WRAPPER": "\v", "PATH": path}, None
    )

    argv, inside = _recorded(out)
    assert {name: inside.get(name) for name in MARKERS} == MARKERS, argv
    given = {f"{name}={value}" for name, value in MARKERS.items()}
    assert given <= set(_passed(argv)), argv


@posix_runner_stand_ins
def test_container_mode_takes_a_wrapper_of_other_whitespace_as_a_wrapper(
    tmp_path, monkeypatch
):
    """As in ./ash, a wrapper is split on space, tab and newline only, so a vertical
    tab is a word, the wrapper's name. Stripped of all whitespace it was no wrapper
    here, and the markers went by name while ./ash gave them with their values."""
    from automated_security_helper.interactions import run_ash_container as rac

    monkeypatch.setenv("OCI_RUNNER_WRAPPER", "\v")
    assert rac._get_oci_wrapper_prefix() == ["\v"]
    for value in (" \t\n ", ""):
        monkeypatch.setenv("OCI_RUNNER_WRAPPER", value)
        assert rac._get_oci_wrapper_prefix() == []
    monkeypatch.setenv("OCI_RUNNER_WRAPPER", " sudo -E \n")
    assert rac._get_oci_wrapper_prefix() == ["sudo", "-E"]
