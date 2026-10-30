# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``Invoke-ASH`` must start the container the way ``./ash`` and ``ash --mode container`` do.

The PowerShell wrapper had drifted from the other two entrypoints in ways a caller
could not see without reading the command it built:

* It read ``ASH_OCI_RUNNER``, a name nothing else in ASH uses, and ignored
  ``OCI_RUNNER``, which ``./ash`` and the CLI read. ``OCI_RUNNER=podman`` got docker.
* With no runner named it tried docker first; ``./ash`` and the CLI try finch, then
  docker, nerdctl, and podman.
* It always passed ``--fail-on-findings --no-progress --no-show-summary``, so a
  configuration's ``fail_on_findings: false`` was overridden and no summary was
  printed. ``./ash`` passes none of them unless asked, and ``ash --mode container``
  prints the summary on the host.
* CI called it with ``-ConfigFile``, which is not a parameter. PowerShell bound it to
  ``-AshArgs``, which forwarded ``-ConfigFile <path>`` to ash in the container
  ("No such option: -C", exit 2, the same code as findings).
* ``-AshArgs`` is read with PowerShell's own tokenizer and passed as an argument
  array, so quoted values stay whole and a ``;`` in them is text, never a command.
* It built the image for UID 500 unless told otherwise, where ``./ash`` and the CLI
  build it for the caller's UID and GID.
* With no runner it called ``exit 1``, which ends the caller's PowerShell session.
* It passed ``--source-dir /src --output-dir /out`` before the caller's arguments,
  so ``-AshArgs 'report'`` put options in front of a subcommand.
* Its default output directory was ``.ash/ash_output`` under the working directory,
  where ``./ash`` and ``ash scan`` default it inside the scanned directory, so
  ``-SourceDir sub`` from a checkout root wrote the reports beside the checkout.

The tests stand in a PowerShell function for each of finch, docker, nerdctl,
and podman. ``Get-Command`` finds a function before any program on PATH, so a stand-in
is what ``Invoke-ASH`` resolves on every platform, and it records the arguments the
wrapper passed. No test can reach a real runner: every runner name is a function,
the script refuses to start if one is not, and the first PATH entry holds programs
of the same names that fail the test. They run under ``pwsh``; skipped only on a
developer machine without it, failed in CI.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess  # nosec B404 - running pwsh against the wrapper is the point of this test
import sys
from pathlib import Path

import pytest
import yaml

from tests.utils.pwsh_env import inherited_env, scratch_home

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS = REPO_ROOT / "utils" / "ash_helpers.ps1"
RUN_SCAN_TEST = REPO_ROOT / ".github" / "actions" / "run-scan-test" / "action.yml"
PWSH = shutil.which("pwsh")

RUNNERS = ("finch", "docker", "nerdctl", "podman")
_GUARD_EXIT = 97
_GUARD_MESSAGE = "REAL-RUNNER-GUARD"

# Flags whose defaults belong to ash and its configuration, not to the wrapper.
_DEFAULTED_BY_ASH = {
    "--progress",
    "--no-progress",
    "--show-summary",
    "--no-show-summary",
    "--fail-on-findings",
    "--no-fail-on-findings",
}


@pytest.fixture(autouse=True)
def _require_pwsh(in_ci: bool):
    if PWSH is None:
        if in_ci:
            pytest.fail("pwsh is not on PATH; CI runners must run these tests")
        pytest.skip("pwsh is not on PATH (local run only; CI fails instead)")


def _stub_runners(build_exit: int = 0) -> str:
    """PowerShell defining a recording stand-in for every OCI runner name.

    The guard after the definitions stops the script before Invoke-ASH runs if any
    runner name would still resolve to something other than its stand-in. A stand-in
    sets $LASTEXITCODE to ``build_exit`` for a build and to 0 for anything else.
    """
    lines = []
    for name in RUNNERS:
        lines.append(
            f"function global:{name} {{ "
            f"Add-Content -LiteralPath $env:RUNNER_LOG -Value "
            f"(ConvertTo-Json -Compress -InputObject (@('{name}') + @($args | ForEach-Object {{ [string]$_ }}))); "
            f"$global:LASTEXITCODE = $(if ($args[0] -eq 'build') {{ {build_exit} }} else {{ 0 }}) }}"
        )
    names = ", ".join(f"'{name}'" for name in RUNNERS)
    lines.append(
        f"foreach ($n in @({names})) {{ "
        "if ((Get-Command $n).CommandType -ne 'Function') { "
        f'Write-Host "{_GUARD_MESSAGE}: $n is not the stand-in"; exit {_GUARD_EXIT} }} }}'
    )
    return "\n".join(lines) + "\n"


def _guard_dir(tmp_path: Path) -> Path:
    """Programs named like the runners that fail the test, for the front of PATH."""
    guard = tmp_path / "runner-guard"
    guard.mkdir(exist_ok=True)
    for name in RUNNERS:
        if os.name == "nt":
            (guard / f"{name}.cmd").write_text(
                f"@echo {_GUARD_MESSAGE}: {name} %* 1>&2\r\n@exit /b {_GUARD_EXIT}\r\n",
                encoding="utf-8",
            )
        else:
            program = guard / name
            program.write_text(
                # To stderr, which `$rc = Invoke-ASH ...` does not capture.
                f"#!/bin/sh\necho '{_GUARD_MESSAGE}: {name}' \"$@\" >&2\nexit {_GUARD_EXIT}\n",
                encoding="utf-8",
            )
            program.chmod(0o755)
    return guard


_RUNNER_VARIABLES = ("OCI_RUNNER", "ASH_OCI_RUNNER", "OCI_RUNNER_WRAPPER")


def _clean_env(tmp_path: Path, **overrides: str) -> dict[str, str]:
    env = inherited_env(*_RUNNER_VARIABLES, "ASH_CONFIG")
    guard = _guard_dir(tmp_path)
    env["PATH"] = os.pathsep.join([str(guard), env.get("PATH", "")])
    for name in RUNNERS:
        found = shutil.which(name, path=env["PATH"])
        if found is None or Path(found).parent != guard:
            pytest.fail(f"{name} on the test PATH resolves to {found}, not the guard")
    env["RUNNER_LOG"] = str(tmp_path / "runner.log")
    env.update(scratch_home(tmp_path))
    env.update(overrides)
    return env


def _ps_single_quoted(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _env_guard(env: dict[str, str]) -> str:
    """PowerShell that stops the script unless each runner variable is what the test
    passed in ``env``, or is unset when the test passed none."""
    lines = []
    for name in _RUNNER_VARIABLES:
        expected = env.get(name)
        if expected:
            wrong = f"$env:{name} -cne {_ps_single_quoted(expected)}"
        else:
            wrong = f"-not [string]::IsNullOrEmpty($env:{name})"
        lines.append(
            f"if ({wrong}) {{ Write-Host "
            f'"{_GUARD_MESSAGE}: {name} is not what the test set"; exit {_GUARD_EXIT} }}'
        )
    return "\n".join(lines) + "\n"


_SCRIPT_RUN = ("-NoProfile", "-NonInteractive", "-File")


def _pwsh(
    script: str,
    cwd: Path,
    env: dict[str, str],
    launch: tuple[str, ...] = _SCRIPT_RUN,
    stdin: str | None = None,
    interpreter: str | None = None,
) -> subprocess.CompletedProcess:
    """Run ``script`` with pwsh started as ``launch`` and then the script.

    The script goes in a file when ``launch`` ends with a -File spelling, and inline
    otherwise (after -Command). ``stdin`` is what a session started with -NoExit reads
    as its next commands. ``interpreter`` replaces pwsh (powershell.exe, say).
    """
    if launch[-1].lower().startswith(("-f", "/f")):
        script_file = cwd / "invoke.ps1"
        script_file.write_text(script, encoding="utf-8")
        target = str(script_file)
    else:
        target = script
    return _pwsh_argv([*launch, target], cwd, env, stdin=stdin, interpreter=interpreter)


def _pwsh_argv(
    arguments: list[str],
    cwd: Path,
    env: dict[str, str],
    stdin: str | None = None,
    interpreter: str | None = None,
) -> subprocess.CompletedProcess:
    program = interpreter or PWSH
    assert program is not None
    result = subprocess.run(  # nosec B603 - fixed interpreter, script built here
        [program, *arguments],
        cwd=cwd,
        env=env,
        input=stdin,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
        check=False,
    )
    if _GUARD_MESSAGE in result.stdout + result.stderr:
        pytest.fail(
            "a real OCI runner could have been run (the runner guard stopped it):\n"
            + result.stdout
            + result.stderr
        )
    return result


def _calls(tmp_path: Path) -> list[list[str]]:
    log = tmp_path / "runner.log"
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


def _run_script(
    tmp_path: Path,
    body: str,
    preamble: str = "",
    build_exit: int = 0,
    launch: tuple[str, ...] = _SCRIPT_RUN,
    stdin: str | None = None,
    env_preamble: str = "",
    interpreter: str | None = None,
    **env: str,
) -> tuple[subprocess.CompletedProcess, list[list[str]]]:
    """Run ``body`` after the stand-ins, ``preamble`` and the helpers.

    ``env_preamble`` runs before the check of the runner variables, as something that
    changed them before the script started would; only the guard's own test uses it.
    """
    (tmp_path / "src").mkdir(exist_ok=True)
    run_env = _clean_env(tmp_path, **env)
    script = (
        "$ErrorActionPreference = 'Stop'\n"
        + env_preamble
        + _env_guard(run_env)
        + _stub_runners(build_exit)
        + preamble
        + f". '{HELPERS.as_posix()}'\n"
        + body
    )
    result = _pwsh(
        script,
        tmp_path,
        run_env,
        launch=launch,
        stdin=stdin,
        interpreter=interpreter,
    )
    return result, _calls(tmp_path)


def _invoke(
    tmp_path: Path, invocation: str, preamble: str = "", **env: str
) -> tuple[subprocess.CompletedProcess, list[list[str]]]:
    return _run_script(
        tmp_path,
        f"$rc = {invocation}\nexit [int]$LASTEXITCODE\n",
        preamble=preamble,
        **env,
    )


def _run_call(result, calls) -> list[str]:
    runs = [call for call in calls if len(call) > 1 and call[1] == "run"]
    assert len(runs) == 1, (calls, result.stdout, result.stderr)
    return runs[0]


def _build_call(result, calls) -> list[str]:
    builds = [call for call in calls if len(call) > 1 and call[1] == "build"]
    assert len(builds) == 1, (calls, result.stdout, result.stderr)
    return builds[0]


def _inner_ash_args(run_call: list[str]) -> list[str]:
    """What follows the image name and ``ash``."""
    return run_call[run_call.index("ash") + 1 :]


#: What Invoke-ASH gives scan, and ash with no command named (which scans), right
#: after the command word or ahead of every word: the scan in the image never
#: sandboxes, the container is the boundary.
#: tests/unit/test_sandbox_refused_by_every_container_entrypoint.py covers why and
#: where it goes.
SANDBOX_OFF = ["--sandbox", "off"]


def _run_env(run_call: list[str]) -> dict[str, str]:
    """The ``-e NAME=value`` pairs before the image name."""
    before_image = run_call[: run_call.index("ash")]
    pairs = [
        before_image[i + 1]
        for i, arg in enumerate(before_image[:-1])
        if arg == "-e" and "=" in before_image[i + 1]
    ]
    return dict(pair.split("=", 1) for pair in pairs)


@pytest.mark.integration
def test_pwsh_runs_with_a_scratch_home_and_no_telemetry(tmp_path):
    # pwsh writes caches under HOME and the XDG directories, sends telemetry unless
    # opted out, and checks for updates; none of that belongs to a test.
    result, _ = _run_script(
        tmp_path,
        "Write-Output ($env:HOME, $env:XDG_CACHE_HOME, $env:XDG_DATA_HOME, "
        "$env:XDG_CONFIG_HOME, $env:POWERSHELL_TELEMETRY_OPTOUT, "
        "$env:POWERSHELL_UPDATECHECK -join '|')\n"
        "exit 0\n",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    home, cache, data, config, telemetry, update = (
        result.stdout.strip().splitlines()[-1].split("|")
    )
    for path in (home, cache, data, config):
        assert Path(path).is_relative_to(tmp_path), path
    assert (telemetry, update) == ("1", "Off")


# Choosing the runner.


@pytest.mark.integration
def test_oci_runner_selects_the_runner(tmp_path):
    result, calls = _invoke(
        tmp_path,
        "Invoke-ASH -NoBuild -SourceDir src -OutputDir out",
        OCI_RUNNER="podman",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert _run_call(result, calls)[0] == "podman"


_NATIVE_RUNNER = """#!/bin/sh
for arg in "$@"; do printf '%s\\n' "$arg"; done > "$NATIVE_RUNNER_LOG.$1"
exit 0
"""


def _native_runner(tmp_path: Path, name: str = "myrunner") -> Path:
    """A real program that records each argument on a line, outside PATH."""
    directory = tmp_path / "native-runner"
    directory.mkdir(exist_ok=True)
    program = directory / name
    program.write_text(_NATIVE_RUNNER, encoding="utf-8")
    program.chmod(0o755)
    return program


def _native_calls(tmp_path: Path, verb: str) -> list[str]:
    log = tmp_path / f"native.log.{verb}"
    return log.read_text(encoding="utf-8").splitlines() if log.exists() else []


@pytest.mark.integration
@pytest.mark.skipif(os.name == "nt", reason="the stand-in runner is a POSIX script")
def test_a_runner_named_by_path_is_the_one_that_runs(tmp_path):
    # Get-Command resolves the path, and its Name is just "myrunner": calling that ran
    # whatever PATH held under the name, or failed with "not recognized".
    runner = _native_runner(tmp_path)
    impostor_dir = tmp_path / "impostor"
    impostor_dir.mkdir()
    impostor = impostor_dir / runner.name
    impostor.write_text(
        f"#!/bin/sh\necho '{_GUARD_MESSAGE}: the same-named program on PATH ran' >&2\n"
        f"exit {_GUARD_EXIT}\n",
        encoding="utf-8",
    )
    impostor.chmod(0o755)
    env = _clean_env(tmp_path)
    result, calls = _invoke(
        tmp_path,
        "Invoke-ASH -NoBuild -SourceDir src -OutputDir out",
        OCI_RUNNER=str(runner),
        NATIVE_RUNNER_LOG=str(tmp_path / "native.log"),
        PATH=os.pathsep.join([str(impostor_dir), env["PATH"]]),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    run = _native_calls(tmp_path, "run")
    assert run[:2] == ["run", "--rm"], run
    assert calls == []


# Arguments a program would not get one for one. PowerShell before 7.3 has only the
# legacy quoting, and a batch file's arguments get it under every PowerShell and are
# then parsed again by cmd.exe. Assert-AshArgumentsPassWhole refuses what those would
# break; Invoke-ASH calls it with -LegacyQuoting on PowerShell before 7.3 and
# -BatchFile when the runner or the wrapper is one. Its rules are tested here on any
# host; which hosts set the flags is tested on Windows below.

_LEGACY = "-LegacyQuoting"
_BATCH = "-BatchFile 'C:\\tools\\runner.cmd'"


@pytest.mark.integration
@pytest.mark.parametrize(
    ("value", "flags", "refusal"),
    [
        pytest.param('a"b', _LEGACY, "holds a double quote", id="legacy-quote"),
        pytest.param("", _LEGACY, "is empty", id="legacy-empty"),
        pytest.param("a b\\", _LEGACY, "ends with a backslash", id="legacy-backslash"),
        pytest.param("a\tb\\", _LEGACY, "ends with a backslash", id="legacy-tab"),
        pytest.param("a\\", _LEGACY, None, id="legacy-backslash-no-space"),
        pytest.param("a b", _LEGACY, None, id="legacy-space"),
        pytest.param('a"b', _BATCH, "holds a double quote", id="batch-quote"),
        pytest.param("", _BATCH, "is empty", id="batch-empty"),
        pytest.param("a b\\", _BATCH, "ends with a backslash", id="batch-backslash"),
        *[
            pytest.param(f"a{c}b", _BATCH, "cmd.exe", id=f"batch-{name}")
            for c, name in [
                ("&", "ampersand"),
                ("|", "pipe"),
                ("<", "less"),
                (">", "greater"),
                ("^", "caret"),
                ("%", "percent"),
            ]
        ],
        pytest.param("a&b", _LEGACY, None, id="legacy-ampersand"),
        pytest.param('a"b& c\\', "", None, id="neither"),
        pytest.param("", "", None, id="neither-empty"),
    ],
)
def test_arguments_a_program_would_not_get_whole_are_refused(
    tmp_path, value, flags, refusal
):
    result, calls = _run_script(
        tmp_path,
        "try {\n"
        f"  Assert-AshArgumentsPassWhole -Arguments @('--x', {_ps_single_quoted(value)}) {flags}\n"
        "  Write-Host 'passed'\n"
        "} catch {\n"
        '  Write-Host "refused: $($_.Exception.Message)"\n'
        "}\n"
        "exit [int]$LASTEXITCODE\n",
    )
    detail = result.stdout + result.stderr
    if refusal is None:
        assert "passed" in result.stdout.splitlines(), detail
        assert result.returncode == 0, detail
    else:
        assert "refused: " in result.stdout, detail
        assert refusal in result.stdout, detail
        assert result.returncode == REFUSAL_EXIT, detail
    assert calls == []


@pytest.mark.integration
@pytest.mark.skipif(
    os.name != "nt", reason="Windows PowerShell 5.1 runs only on Windows"
)
@pytest.mark.parametrize(
    ("parameter", "refusal"),
    [
        ("-Scanners 'a\"b'", "holds a double quote"),
        ("-Scanners ''", "is empty"),
        ("-Config 'a b\\'", "ends with a backslash"),
    ],
)
def test_windows_powershell_refuses_what_its_quoting_would_break(
    tmp_path, parameter, refusal
):
    windows_powershell = shutil.which("powershell.exe")
    if windows_powershell is None:
        pytest.skip("powershell.exe is not on PATH")
    result, calls = _run_script(
        tmp_path,
        _wrapped(f"Invoke-ASH -NoBuild -SourceDir src -OutputDir out {parameter}"),
        interpreter=windows_powershell,
    )
    assert result.returncode == REFUSAL_EXIT, result.stdout + result.stderr
    assert _unwrapped(refusal) in _unwrapped(result.stderr), result.stderr
    assert calls == []


@pytest.mark.integration
@pytest.mark.skipif(
    os.name != "nt", reason="Windows PowerShell 5.1 runs only on Windows"
)
def test_windows_powershell_takes_the_default_output_directory(tmp_path):
    # The default was `Join-Path <cwd> '.ash' 'ash_output'`, and Join-Path takes a
    # third path only from PowerShell 6, so on 5.1 every call without -OutputDir
    # failed to bind. The default is inside -SourceDir now, built the same way.
    windows_powershell = shutil.which("powershell.exe")
    if windows_powershell is None:
        pytest.skip("powershell.exe is not on PATH")
    result, calls = _run_script(
        tmp_path,
        _wrapped("Invoke-ASH -NoBuild -SourceDir src"),
        interpreter=windows_powershell,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert (tmp_path / "src" / ".ash" / "ash_output").is_dir()
    assert _run_call(result, calls)


@pytest.mark.integration
def test_the_default_output_directory_is_inside_the_source_directory(tmp_path):
    """Without -OutputDir the reports land in ``.ash/ash_output`` inside -SourceDir.

    The default was ``.ash/ash_output`` under the working directory, where ``./ash``
    and ``ash scan`` default it inside the scanned directory
    (tests/unit/test_ash_bash_entrypoint_output_paths.py pins the launcher's rule).
    Run from a checkout root with ``-SourceDir sub``, the wrapper wrote its reports
    beside the working directory, and a ``.ash`` link the repository commits at that
    root took them wherever it pointed. The directory the container is given, the
    one it mounts at /out, and the one made on disk are all the source's own.
    """
    result, calls = _invoke(tmp_path, "Invoke-ASH -NoBuild -SourceDir src")
    assert result.returncode == 0, result.stdout + result.stderr
    run = _run_call(result, calls)
    expected = tmp_path / "src" / ".ash" / "ash_output"
    assert _run_env(run)["ASH_ACTUAL_OUTPUT_DIR"] == str(expected), run
    assert f"type=bind,source={expected},destination=/out" in run, run
    assert expected.is_dir()
    assert not (tmp_path / ".ash").exists()


@pytest.mark.integration
def test_every_join_path_names_one_child_path(tmp_path):
    # Windows PowerShell 5.1 has no -AdditionalChildPath, so a Join-Path with a third
    # path fails to bind there. Read with PowerShell's parser, so it runs on any host.
    result, _ = _run_script(
        tmp_path,
        f"$text = Get-Content -Raw -LiteralPath '{HELPERS.as_posix()}'\n"
        "$ast = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$null, [ref]$null)\n"
        "$joins = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] "
        "-and $n.GetCommandName() -eq 'Join-Path' }, $true))\n"
        "$wide = @($joins | Where-Object { @($_.CommandElements | Select-Object -Skip 1 | "
        "Where-Object { $_ -isnot [System.Management.Automation.Language.CommandParameterAst] }).Count -gt 2 "
        "-or $_.Extent.Text -match '-AdditionalChildPath' } | ForEach-Object { $_.Extent.Text })\n"
        "Write-Output (ConvertTo-Json -Compress -InputObject @{ joins = $joins.Count; wide = @($wide) })\n"
        "exit 0\n",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(result.stdout.strip().splitlines()[-1])
    assert report["joins"] > 0, report
    assert report["wide"] == [], report


@pytest.mark.integration
@pytest.mark.skipif(os.name != "nt", reason="cmd.exe runs batch files only on Windows")
def test_a_batch_file_runner_gets_no_value_cmd_exe_would_act_on(tmp_path):
    ran = tmp_path / "batch-runner-ran.log"
    runner = tmp_path / "runner.cmd"
    runner.write_text(f'@echo ran>> "{ran}"\r\n@exit /b 0\r\n', encoding="utf-8")
    result, _ = _run_script(
        tmp_path,
        _wrapped("Invoke-ASH -NoBuild -SourceDir src -OutputDir out -Scanners 'a&b'"),
        OCI_RUNNER=str(runner),
    )
    assert result.returncode == REFUSAL_EXIT, result.stdout + result.stderr
    assert "cmd.exe" in result.stderr, result.stderr
    assert not ran.exists(), "the batch file ran"


@pytest.mark.integration
@pytest.mark.skipif(os.name == "nt", reason="the stand-in runner is a POSIX script")
def test_values_stay_one_argument_under_legacy_native_argument_passing(tmp_path):
    # 'Legacy' wraps an argument holding a space in double quotes without escaping
    # the quotes inside it, so a value of `q" --privileged ` merged with the
    # arguments around it and left --privileged as an argument of its own: an option
    # for the runner, ahead of the image. One value of each kind the runner is
    # handed: the source and output directories' paths reach it in `-e NAME=value`
    # pairs (the source directory in the `--mount type=bind,source=...` value too),
    # and -Scanners as an argument of ash. (-OutputFormat does not reach the run
    # at all; see test_output_format_sets_no_variable_ash_does_not_read.) The
    # directories' paths hold the space and --privileged but no double quote: a
    # mounted path with one is refused before any runner is looked for, as ./ash
    # refuses it (a --mount value is read as CSV; test_a_refusal_exits_3_under_
    # error_action_stop[mount-path-double-quote]), so the quote rides in -Scanners,
    # an argument of ash and not a mount.
    runner = _native_runner(tmp_path)
    directory = "q --privileged "
    payload = 'q" --privileged '
    output_name = "out --privileged x"
    (tmp_path / directory).mkdir()
    result, calls = _invoke(
        tmp_path,
        f"Invoke-ASH -NoBuild -SourceDir {_ps_double_quoted(directory)} "
        f"-OutputDir {_ps_double_quoted(output_name)} "
        f"-Scanners {_ps_double_quoted(payload)}",
        preamble="$PSNativeCommandArgumentPassing = 'Legacy'\n",
        OCI_RUNNER=str(runner),
        NATIVE_RUNNER_LOG=str(tmp_path / "native.log"),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    run = _native_calls(tmp_path, "run")
    assert "--privileged" not in run, run
    assert f"ASH_ACTUAL_OUTPUT_DIR={tmp_path / output_name}" in run, run
    assert f"ASH_ACTUAL_SOURCE_DIR={tmp_path / directory}" in run, run
    assert payload in run, run


def _startup_files(tmp_path: Path, monkeypatch, body: str) -> Path:
    """Point BASH_ENV, ENV and ZDOTDIR at startup files that run ``body`` and log it."""
    canary = tmp_path / "startup-file-ran.log"
    text = f"echo ran >> '{canary}'\n{body}\n"
    startup = tmp_path / "startup.sh"
    startup.write_text(text, encoding="utf-8")
    zdotdir = tmp_path / "zdotdir"
    zdotdir.mkdir()
    (zdotdir / ".zshenv").write_text(text, encoding="utf-8")
    monkeypatch.setenv("BASH_ENV", str(startup))
    monkeypatch.setenv("ENV", str(startup))
    monkeypatch.setenv("ZDOTDIR", str(zdotdir))
    return canary


@pytest.mark.integration
def test_no_startup_file_of_the_developers_shell_runs(tmp_path, monkeypatch):
    # pwsh can be a bash script (nix installs it as one), and a non-interactive bash
    # runs $BASH_ENV first. One that exports OCI_RUNNER undid the test's removal of
    # it, and a full-path OCI_RUNNER is run by that path.
    canary = _startup_files(tmp_path, monkeypatch, "export OCI_RUNNER=/bin/false")
    result, calls = _invoke(
        tmp_path, "Invoke-ASH -NoBuild -SourceDir src -OutputDir out"
    )
    assert not canary.exists(), "a startup file of the developer's shell ran"
    assert result.returncode == 0, result.stdout + result.stderr
    assert _run_call(result, calls)[0] in RUNNERS


@pytest.mark.integration
@pytest.mark.parametrize("name", ["OCI_RUNNER", "ASH_OCI_RUNNER", "OCI_RUNNER_WRAPPER"])
def test_a_runner_variable_the_test_did_not_set_stops_the_script(tmp_path, name):
    # The guard behind the one above: whatever sets a runner variable between the
    # test and the script, the script stops before Invoke-ASH runs.
    with pytest.raises(pytest.fail.Exception, match=_GUARD_MESSAGE):
        _run_script(
            tmp_path,
            "Invoke-ASH -NoBuild -SourceDir src -OutputDir out\nexit 0\n",
            env_preamble=f"$env:{name} = '/bin/false'\n",
        )
    assert _calls(tmp_path) == []


@pytest.mark.integration
def test_pwsh_runs_with_a_home_of_the_tests_own(tmp_path):
    result, _ = _run_script(tmp_path, 'Write-Output "HOME=$HOME"\nexit 0\n')
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"HOME={tmp_path / 'pwsh-home'}" in result.stdout.splitlines(), result.stdout


@pytest.mark.integration
def test_oci_runner_wins_over_the_old_ash_oci_runner(tmp_path):
    result, calls = _invoke(
        tmp_path,
        "Invoke-ASH -NoBuild -SourceDir src -OutputDir out",
        OCI_RUNNER="podman",
        ASH_OCI_RUNNER="docker",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert _run_call(result, calls)[0] == "podman"


@pytest.mark.integration
def test_the_old_ash_oci_runner_still_works_and_says_it_is_deprecated(tmp_path):
    result, calls = _invoke(
        tmp_path,
        "Invoke-ASH -NoBuild -SourceDir src -OutputDir out",
        ASH_OCI_RUNNER="podman",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert _run_call(result, calls)[0] == "podman"
    assert "ASH_OCI_RUNNER is deprecated" in result.stdout + result.stderr


@pytest.mark.integration
def test_an_explicit_empty_oci_runner_is_refused_and_ash_oci_runner_is_not_used(
    tmp_path,
):
    # An -OCIRunner given an empty value is refused with exit 5, the usage-error code,
    # as ./ash refuses `--oci-runner ''` and the CLI refuses an option given no
    # argument; it does not ask for discovery. OCI_RUNNER applies only when the
    # caller named no runner at all, so it is not used here either. An -OCIRunner
    # left to default from an empty OCI_RUNNER discovers a runner
    # (test_every_invoke_ash_refusal_exits_with_its_code's accepted cell).
    result, calls = _run_script(
        tmp_path,
        _wrapped("Invoke-ASH -NoBuild -SourceDir src -OutputDir out -OCIRunner ''"),
        ASH_OCI_RUNNER="podman",
    )
    assert result.returncode == USAGE_ERROR_EXIT, result.stdout + result.stderr
    assert "-OCIRunnerneedsavalue" in _unwrapped(result.stderr), result.stderr
    assert "ASH_OCI_RUNNER" not in result.stdout + result.stderr
    assert calls == []


@pytest.mark.integration
def test_discovery_tries_finch_first_like_ash_and_the_cli(tmp_path):
    result, calls = _invoke(
        tmp_path, "Invoke-ASH -NoBuild -SourceDir src -OutputDir out"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert _run_call(result, calls)[0] == "finch"


@pytest.mark.integration
def test_no_runner_throws_to_the_caller(tmp_path):
    # `exit` inside a function would end the PowerShell session that dot-sourced it: a
    # caller's catch would never run and an interactive window would close, so
    # Invoke-ASH throws. 'Continue' is the interactive default; under 'Stop' a
    # Write-Error before an exit would throw first and hide it.
    result, calls = _run_script(
        tmp_path,
        "$ErrorActionPreference = 'Continue'\n"
        "try {\n"
        "  Invoke-ASH -NoBuild -NoRun -SourceDir src -OutputDir out -OCIRunner no-such-oci-runner\n"
        "} catch {\n"
        '  Write-Host "caught: $($_.Exception.Message)"\n'
        "}\n"
        "Write-Host 'the caller continues'\n"
        "exit 0\n",
    )
    assert "caught: Unable to resolve an OCI_RUNNER" in result.stdout, (
        result.stdout + result.stderr
    )
    assert "the caller continues" in result.stdout, result.stdout + result.stderr
    assert calls == []


_NO_RUNNER = "Invoke-ASH -NoBuild -NoRun -SourceDir src -OutputDir out -OCIRunner no-such-oci-runner"
_NO_RUNNER_MESSAGE = (
    "Unable to resolve an OCI_RUNNER: 'no-such-oci-runner' was not found"
)


@pytest.mark.integration
@pytest.mark.parametrize(
    "launch",
    [
        pytest.param(("-NoProfile", "-NoExit", "-File"), id="noexit-file"),
        pytest.param(("-NoProfile", "-NoExit", "-Command"), id="noexit-command"),
        pytest.param(("-NoProfile", "-NoE", "-Command"), id="abbreviated-noexit"),
    ],
)
def test_a_refusal_in_a_session_a_person_types_into_leaves_it_open(tmp_path, launch):
    # A refusal throws instead of calling `exit`, so a session started with -NoExit
    # (or a window someone dot-sourced the helpers into) stays open after it. The
    # commands after the script are what the session reads next, as if typed. With
    # -Command an `exit` would end the session; with -File PowerShell keeps a -NoExit
    # session open even after the script exits (measured with 7.6.6), so that case
    # pins only the session's $LASTEXITCODE.
    result, calls = _run_script(
        tmp_path,
        "$ErrorActionPreference = 'Continue'\n"
        "try {\n"
        f"  {_NO_RUNNER}\n"
        "} catch {\n"
        '  Write-Host "caught: $($_.Exception.Message)"\n'
        "}\n",
        launch=launch,
        stdin='Write-Output "session still open, LASTEXITCODE=$LASTEXITCODE"\nexit 0\n',
    )
    detail = result.stdout + result.stderr
    assert result.returncode == 0, detail
    assert _NO_RUNNER_MESSAGE in result.stdout, detail
    assert "session still open, LASTEXITCODE=3" in result.stdout, detail
    assert calls == []


def _unwrapped(text: str) -> str:
    """``text`` without color codes, whitespace, or the ``|`` PowerShell wraps with.

    PowerShell wraps an error's message to the console width, so a phrase can break
    across lines; compared this way it is found wherever the breaks fall.
    """
    return re.sub(r"[\s|]", "", re.sub(r"\x1b\[[0-9;]*m", "", text))


# Every refusal of the wrappers leaves exit code 3, the code ASH uses for input it
# refuses (./ash does the same).
REFUSAL_EXIT = 3

# A source or output directory that ASH cannot use is a usage error instead, exit 5,
# and ./ash, Invoke-ASH and ash itself give it the same text, such as "Source
# directory does not exist: <path>" (tests/unit/cli/test_directory_refusals_agree.py
# compares them).
USAGE_ERROR_EXIT = 5

# A refusal under the interactive default, 'Continue', with nothing to catch it.
# Each: the invocation, its environment, the exit code a build stand-in reports, the
# text found only in the message (not in the source line PowerShell quotes with it),
# and the $LASTEXITCODE the refusal leaves.
_FAILURES = {
    "no-runner": (
        (
            "Invoke-ASH -NoBuild -NoRun -SourceDir src -OutputDir out "
            "-OCIRunner no-such-oci-runner"
        ),
        {},
        0,
        "'no-such-oci-runner'wasnotfound",
        REFUSAL_EXIT,
    ),
    "ash-args": (
        "Invoke-ASH -NoBuild -NoRun -SourceDir src -OutputDir out -AshArgs '--x; y'",
        {},
        0,
        "-AshArgsholds';'",
        REFUSAL_EXIT,
    ),
    "tokenizer": (
        (
            "Invoke-ASH -NoBuild -NoRun -SourceDir src -OutputDir out "
            '-AshArgs "--x \'open"'
        ),
        {},
        0,
        "Thestringismissingtheterminator",
        REFUSAL_EXIT,
    ),
    "layout": (
        "Invoke-ASH -NoRun -SourceDir src -OutputDir out",
        {"ASH_BASE_OCI_LAYOUT": "bogus"},
        0,
        "ASH_BASE_OCI_LAYOUTis'bogus'",
        REFUSAL_EXIT,
    ),
    # Not a refusal: a failed build keeps the build's own exit code, here 7.
    "build": (
        "Invoke-ASH -SourceDir src -OutputDir out",
        {},
        7,
        "(exit7).Seethebuildoutput",
        7,
    ),
}


def _assert_only_the_failed_build_ran(failure: str, calls: list[list[str]]) -> None:
    """A refusal runs nothing; the failed build ran its one build and nothing else."""
    if failure == "build":
        assert [call[1:2] for call in calls] == [["build"]], calls
    else:
        assert calls == [], calls


@pytest.mark.integration
@pytest.mark.parametrize("failure", sorted(_FAILURES))
def test_a_refusal_ends_the_script_and_is_reported_once(tmp_path, failure):
    # The statement after Invoke-ASH must not run (a ThrowTerminatingError would let
    # it), and the error was printed twice: once by a Write-Error in the catch and
    # once more when the rethrow went uncaught. An uncaught error ends `pwsh -File`
    # with 1 whatever $LASTEXITCODE holds; PowerShell decides that, not Invoke-ASH.
    invocation, env, build_exit, text, _ = _FAILURES[failure]
    result, calls = _run_script(
        tmp_path,
        "$ErrorActionPreference = 'Continue'\n"
        f"{invocation}\n"
        "Write-Host 'the next statement ran'\n"
        "exit 0\n",
        build_exit=build_exit,
        **env,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert "the next statement ran" not in result.stdout, result.stdout
    assert _unwrapped(result.stderr).count(_unwrapped(text)) == 1, result.stderr
    _assert_only_the_failed_build_ran(failure, calls)


@pytest.mark.integration
@pytest.mark.parametrize("failure", sorted(_FAILURES))
def test_a_refusal_leaves_lastexitcode_set_for_a_script_that_continues(
    tmp_path, failure
):
    # `trap { continue }` resumes after the failed statement, so the script's exit
    # code is whatever $LASTEXITCODE holds: it was left at the stand-in's 0.
    invocation, env, build_exit, _, code = _FAILURES[failure]
    result, calls = _run_script(
        tmp_path,
        "$ErrorActionPreference = 'Continue'\n"
        "trap { continue }\n"
        "$global:LASTEXITCODE = 0\n"
        f"{invocation}\n"
        "exit $LASTEXITCODE\n",
        build_exit=build_exit,
        **env,
    )
    assert result.returncode == code, result.stdout + result.stderr
    _assert_only_the_failed_build_ran(failure, calls)


# The catch block the help gives a script that should end with Invoke-ASH's own exit
# code. It reports the error, which `catch { exit $LASTEXITCODE }` would swallow, and
# exits 1 when nothing set $LASTEXITCODE: PowerShell binds the parameters before
# Invoke-ASH runs, so a parameter left without its value, or a name it cannot place
# (an ambiguous -Con), throws with $LASTEXITCODE unset, and `exit $null` is `exit 0`.
# A -SourceDir that does not exist is Invoke-ASH's own refusal, with 3.
_WRAPPED_CATCH = (
    "Write-Error -ErrorRecord $_ -ErrorAction Continue",
    "exit $(if ($LASTEXITCODE) { $LASTEXITCODE } else { 1 })",
)


def _wrapped(invocation: str) -> str:
    return (
        f"try {{\n  {invocation}\n}} catch {{\n  "
        + "\n  ".join(_WRAPPED_CATCH)
        + "\n}\nWrite-Host 'the next statement ran'\nexit 0\n"
    )


def _statements(text: str) -> str:
    return " ".join(text.split())


@pytest.mark.integration
@pytest.mark.parametrize("preference", ["Stop", "Continue"])
@pytest.mark.parametrize("failure", sorted(_FAILURES))
def test_a_script_that_wraps_invoke_ash_as_the_help_shows_exits_with_its_code(
    tmp_path, failure, preference
):
    # Under `pwsh -File`: 3 for a refusal, the build's own code for a failed build.
    # 'Stop' is what GitHub's pwsh shell sets; 'Continue' is the default.
    invocation, env, build_exit, text, code = _FAILURES[failure]
    result, calls = _run_script(
        tmp_path,
        f"$ErrorActionPreference = '{preference}'\n" + _wrapped(invocation),
        build_exit=build_exit,
        **env,
    )
    assert result.returncode == code, result.stdout + result.stderr
    assert "the next statement ran" not in result.stdout, result.stdout
    assert _unwrapped(result.stderr).count(_unwrapped(text)) == 1, result.stderr
    _assert_only_the_failed_build_ran(failure, calls)


@pytest.mark.integration
@pytest.mark.parametrize(
    ("invocation", "text"),
    [
        # PowerShell's own binding errors, raised before Invoke-ASH runs. A -SourceDir
        # that does not exist is not one of them: Invoke-ASH checks it itself, and it
        # is a usage error (exit 5) in the per-site table below.
        pytest.param(
            "Invoke-ASH -NoBuild -NoRun -SourceDir src -OutputDir out -Con x",
            "Parametercannotbeprocessedbecausetheparametername'Con'isambiguous",
            id="ambiguous-parameter",
        ),
        pytest.param(
            "Invoke-ASH -NoBuild -NoRun -SourceDir src -OutputDir out -OCIRunner",
            "Missinganargumentforparameter'OCIRunner'",
            id="parameter-without-value",
        ),
    ],
)
def test_the_wrapped_form_does_not_exit_0_for_an_error_raised_before_invoke_ash_runs(
    tmp_path, invocation, text
):
    result, calls = _run_script(tmp_path, _wrapped(invocation))
    assert result.returncode == 1, result.stdout + result.stderr
    assert "the next statement ran" not in result.stdout, result.stdout
    assert _unwrapped(text) in _unwrapped(result.stderr), result.stderr
    assert calls == []


# Every refusal of Invoke-ASH, with the code it leaves. The rule: a usage error, the
# input `ash` itself refuses with 5, exits 5 with `ash`'s text (a -SourceDir that
# names no directory to scan, an -OutputDir that is a file or cannot be made, a path
# outside the file system, a parameter given an empty or blank value, an explicit
# --sandbox that is not off); every other refusal exits 3, the code ASH uses for input
# it refuses. Run as a script runs it, `pwsh -File`
# with the catch form the help gives, so the process exits with that code. Each cell:
# the call, what the test directory needs first, the environment, the code, and text
# found only in the message.
_INVOKE = "Invoke-ASH -NoBuild -NoRun -SourceDir src -OutputDir out"
_RUN = "Invoke-ASH -NoBuild -SourceDir src -OutputDir out"
_EMPTY_VALUE_PARAMETERS = (
    "Config",
    "OCIRunner",
    "AshImageName",
    "ContainerUID",
    "ContainerGID",
    "OutputFormat",
    "BuildTarget",
    "OfflineSemgrepRulesets",
)
_WORKSPACE_MESSAGE = "cannotrunaworkspacescan"

_INVOKE_ASH_SITES = {
    "ash-args-tokenizer": (
        f'{_INVOKE} -AshArgs "--x \'open"',
        {},
        {},
        REFUSAL_EXIT,
        "Thestringismissingtheterminator",
    ),
    "ash-args-not-an-argument": (
        f"{_INVOKE} -AshArgs '--x; y'",
        {},
        {},
        REFUSAL_EXIT,
        "-AshArgsholds';'",
    ),
    "ash-args-expandable": (
        f"{_INVOKE} -AshArgs '--x x$a'",
        {},
        {},
        REFUSAL_EXIT,
        "-AshArgsholds'x$a',whichPowerShellwouldexpand",
    ),
    "sandbox": (
        f"{_INVOKE} -AshArgs '--sandbox bwrap'",
        {},
        {},
        USAGE_ERROR_EXIT,
        "--sandboxbwrapcannotbeused",
    ),
    "image-name-dash": (
        f"{_INVOKE} -AshImageName '-x'",
        {},
        {},
        REFUSAL_EXIT,
        "Theimagename'-x'",
    ),
    "image-name-whitespace": (
        f"{_INVOKE} -AshImageName 'my image:tag'",
        {},
        {},
        REFUSAL_EXIT,
        "Theimagename'myimage:tag'",
    ),
    # The inputs ./ash's image-name cells use; a control character is shown as \xHH.
    "image-name-leading-space": (
        f"{_INVOKE} -AshImageName ' ash:ci'",
        {},
        {},
        REFUSAL_EXIT,
        "Theimagename'ash:ci'",
    ),
    "image-name-trailing-space": (
        f"{_INVOKE} -AshImageName 'ash:ci '",
        {},
        {},
        REFUSAL_EXIT,
        "Theimagename'ash:ci'",
    ),
    "image-name-tab": (
        f'{_INVOKE} -AshImageName "ash`t:ci"',
        {},
        {},
        REFUSAL_EXIT,
        "Theimagename'ash\\x09:ci'",
    ),
    "image-name-newline": (
        f'{_INVOKE} -AshImageName "ash:ci`nx"',
        {},
        {},
        REFUSAL_EXIT,
        "Theimagename'ash:ci\\x0Ax'",
    ),
    # .NET's $ also matches before a final newline; the check must not.
    "image-name-trailing-newline": (
        f'{_INVOKE} -AshImageName "ash:ci`n"',
        {},
        {},
        REFUSAL_EXIT,
        "Theimagename'ash:ci\\x0A'",
    ),
    "image-name-glob-character": (
        f"{_INVOKE} -AshImageName 'ash:c*'",
        {},
        {},
        REFUSAL_EXIT,
        "Theimagename'ash:c*'",
    ),
    "image-name-non-ascii-letter": (
        f'{_INVOKE} -AshImageName "caf`u{{e9}}:ci"',
        {},
        {},
        REFUSAL_EXIT,
        "Theimagename'caf\xe9:ci'",
    ),
    # Read when Invoke-ASH starts, with its other input, before anything is built.
    "base-image-override-space": (
        _INVOKE,
        {},
        {"ASH_BASE_IMAGE_OVERRIDE": "python:3.12 --network=host"},
        REFUSAL_EXIT,
        "ASH_BASE_IMAGE_OVERRIDE'python:3.12--network=host'",
    ),
    "base-image-override-dash": (
        _INVOKE,
        {},
        {"ASH_BASE_IMAGE_OVERRIDE": "-x"},
        REFUSAL_EXIT,
        "ASH_BASE_IMAGE_OVERRIDE'-x'",
    ),
    "output-dir-linked": (
        _INVOKE.replace("-OutputDir out", "-OutputDir linked"),
        {"links": [("linked", "elsewhere")]},
        {},
        REFUSAL_EXIT,
        "isreachedthroughalink",
    ),
    "output-dir-is-a-file": (
        _INVOKE.replace("-OutputDir out", "-OutputDir out-file"),
        {"files": ["out-file"]},
        {},
        USAGE_ERROR_EXIT,
        "Outputdirectoryisnotadirectory:out-file",
    ),
    "output-dir-under-a-file": (
        _INVOKE.replace("-OutputDir out", "-OutputDir blocker/out"),
        {"files": ["blocker"]},
        {},
        USAGE_ERROR_EXIT,
        "Outputdirectorycannotbecreated:blocker/out(Notadirectory)",
    ),
    "source-dir-missing": (
        _INVOKE.replace("-SourceDir src", "-SourceDir no-such-dir"),
        {},
        {},
        USAGE_ERROR_EXIT,
        "Sourcedirectorydoesnotexist:no-such-dir",
    ),
    "source-dir-is-a-file": (
        _INVOKE.replace("-SourceDir src", "-SourceDir a-file"),
        {"files": ["a-file"]},
        {},
        USAGE_ERROR_EXIT,
        "Sourcedirectoryisnotadirectory:a-file",
    ),
    # A container of another PowerShell provider is no directory to mount: Env: and
    # Function: passed the check, then Invoke-ASH failed with exit 1 reading FullName.
    "source-dir-env-provider": (
        _INVOKE.replace("-SourceDir src", "-SourceDir 'Env:'"),
        {},
        {},
        USAGE_ERROR_EXIT,
        "Sourcedirectoryisnotadirectory:Env:",
    ),
    "source-dir-function-provider": (
        _INVOKE.replace("-SourceDir src", "-SourceDir 'Function:'"),
        {},
        {},
        USAGE_ERROR_EXIT,
        "Sourcedirectoryisnotadirectory:Function:",
    ),
    # An -OutputDir on a drive that does not exist failed with exit 1, and one in
    # another provider was taken: 'Env:/x' created ./x.
    "output-dir-unknown-drive": (
        _INVOKE.replace("-OutputDir out", "-OutputDir 'nosuchdrive:/x'"),
        {},
        {},
        REFUSAL_EXIT,
        "-OutputDir'nosuchdrive:/x'isnotapathinthefilesystem",
    ),
    "output-dir-env-provider": (
        _INVOKE.replace("-OutputDir out", "-OutputDir 'Env:/x'"),
        {},
        {},
        REFUSAL_EXIT,
        "-OutputDir'Env:/x'isinPowerShell'sEnvironmentprovider,notinthefilesystem",
    ),
    # A parameter given an empty or blank value is a usage error, 5, as ./ash refuses
    # an option given no value and the CLI an option that requires an argument.
    "source-dir-empty": (
        _INVOKE.replace("-SourceDir src", "-SourceDir ''"),
        {},
        {},
        USAGE_ERROR_EXIT,
        "-SourceDirneedsavalue",
    ),
    # The same two -SourceDir refusals with -OutputDir left to its default. The
    # default was worked out while the parameters bound, from -SourceDir, and
    # Join-Path failed there on an empty -SourceDir ("Cannot bind argument to
    # parameter 'Path'"), ahead of the refusal: the call ended with 1 and the
    # binding error, not with 5 and "-SourceDir needs a value".
    "source-dir-empty-default-output": (
        _INVOKE.replace("-SourceDir src", "-SourceDir ''").replace(
            " -OutputDir out", ""
        ),
        {},
        {},
        USAGE_ERROR_EXIT,
        "-SourceDirneedsavalue",
    ),
    "source-dir-missing-default-output": (
        _INVOKE.replace("-SourceDir src", "-SourceDir not-there").replace(
            " -OutputDir out", ""
        ),
        {},
        {},
        USAGE_ERROR_EXIT,
        "Sourcedirectorydoesnotexist",
    ),
    "output-dir-blank": (
        _INVOKE.replace("-OutputDir out", "-OutputDir '  '"),
        {},
        {},
        USAGE_ERROR_EXIT,
        "-OutputDirneedsavalue",
    ),
    **{
        f"{name}-empty": (
            f"{_INVOKE} -{name} ''",
            {},
            {},
            USAGE_ERROR_EXIT,
            f"-{name}needsavalue",
        )
        for name in _EMPTY_VALUE_PARAMETERS
    },
    "OCIRunner-blank": (
        f"{_INVOKE} -OCIRunner '  '",
        {},
        {},
        USAGE_ERROR_EXIT,
        "-OCIRunnerneedsavalue",
    ),
    "Scanners-empty-element": (
        f"{_INVOKE} -Scanners ''",
        {},
        {},
        USAGE_ERROR_EXIT,
        "-Scannersneedsavalue",
    ),
    "ExcludeScanners-empty-element": (
        f"{_INVOKE} -ExcludeScanners bandit,''",
        {},
        {},
        USAGE_ERROR_EXIT,
        "-ExcludeScannersneedsavalue",
    ),
    "build-target-not-a-stage": (
        f"{_INVOKE} -BuildTarget bogus",
        {},
        {},
        REFUSAL_EXIT,
        "-BuildTarget'bogus'isnot",
    ),
    "workspace": (
        f"{_INVOKE} -AshArgs '--workspace w.code-workspace'",
        {},
        {},
        REFUSAL_EXIT,
        _WORKSPACE_MESSAGE,
    ),
    "workspace-attached": (
        f"{_INVOKE} -AshArgs '--workspace=auto'",
        {},
        {},
        REFUSAL_EXIT,
        _WORKSPACE_MESSAGE,
    ),
    "workspace-config": (
        f"{_INVOKE} -AshArgs '--workspace-config c.yaml'",
        {},
        {},
        REFUSAL_EXIT,
        _WORKSPACE_MESSAGE,
    ),
    "workspace-config-attached": (
        f"{_INVOKE} -AshArgs '--workspace-config=c.yaml'",
        {},
        {},
        REFUSAL_EXIT,
        _WORKSPACE_MESSAGE,
    ),
    "workspace-after-the-parameters": (
        f"{_INVOKE} scan --workspace w.code-workspace",
        {},
        {},
        REFUSAL_EXIT,
        _WORKSPACE_MESSAGE,
    ),
    "workspace-quoted": (
        f"{_INVOKE} -AshArgs \"scan '--workspace' auto\"",
        {},
        {},
        REFUSAL_EXIT,
        _WORKSPACE_MESSAGE,
    ),
    "no-runner": (_NO_RUNNER, {}, {}, REFUSAL_EXIT, _NO_RUNNER_MESSAGE),
    "base-oci-layout": (
        "Invoke-ASH -NoRun -SourceDir src -OutputDir out",
        {},
        {"ASH_BASE_OCI_LAYOUT": "bogus"},
        REFUSAL_EXIT,
        "ASH_BASE_OCI_LAYOUTis'bogus'",
    ),
    "argument-legacy-quoting": (
        "Assert-AshArgumentsPassWhole -Arguments @('a\"b') -LegacyQuoting",
        {},
        {},
        REFUSAL_EXIT,
        "holdsadoublequote",
    ),
    # Accepted, for contrast: an explicit --sandbox off; an -OCIRunner left to its
    # default from an empty OCI_RUNNER, which discovers a runner as ./ash does; and a
    # -SourceDir named with wildcard characters, which is that directory.
    # These run, so they leave -NoRun out.
    "sandbox-off": (f"{_RUN} -AshArgs '--sandbox off'", {}, {}, 0, None),
    "oci-runner-default-from-empty-variable": (_RUN, {}, {"OCI_RUNNER": ""}, 0, None),
    "source-dir-with-wildcard-characters": (
        _RUN.replace("-SourceDir src", "-SourceDir 's[r]c'"),
        {"dirs": ["s[r]c"]},
        {},
        0,
        None,
    ),
}


def _prepare(tmp_path: Path, needs: dict) -> None:
    for name in needs.get("dirs", []):
        (tmp_path / name).mkdir(parents=True)
    for name in needs.get("files", []):
        (tmp_path / name).write_text("not a directory\n", encoding="utf-8")
    for link, target in needs.get("links", []):
        (tmp_path / target).mkdir()
        _link_dir(tmp_path / link, tmp_path / target)


@pytest.mark.integration
@pytest.mark.parametrize("site", sorted(_INVOKE_ASH_SITES))
def test_every_invoke_ash_refusal_exits_with_its_code(tmp_path, site):
    invocation, needs, env, code, text = _INVOKE_ASH_SITES[site]
    _prepare(tmp_path, needs)
    result, calls = _run_script(tmp_path, _wrapped(invocation), **env)
    detail = result.stdout + result.stderr
    assert result.returncode == code, detail
    if code == 0:
        run = _run_call(result, calls)
        if "s[r]c" in invocation:
            assert _run_env(run)["ASH_ACTUAL_SOURCE_DIR"] == str(tmp_path / "s[r]c")
        return
    assert "the next statement ran" not in result.stdout, result.stdout
    assert _unwrapped(text) in _unwrapped(result.stderr), result.stderr
    assert calls == [], calls
    if "links" in needs:
        assert list((tmp_path / "elsewhere").iterdir()) == []
    if site == "output-dir-env-provider":
        assert not (tmp_path / "x").exists(), "a directory was made for Env:/x"


#: Image names, and what both wrappers do with each in every locale. Each takes only
#: A-Z, a-z, 0-9 and . _ : / @ -, not starting with '-', and refuses anything else
#: with 3: whitespace of any kind (U+00A0, U+0085 and U+2028, which bash's
#: [[:space:]] and .NET's \s can disagree on), a non-ASCII letter, and the Kelvin
#: sign, which a case-insensitive [A-Za-z] would take as K. Each cell: the name and
#: the code every run gives (0: the name was taken).
_IMAGE_NAMES = {
    "no-break-space": (f"ash{chr(0x00A0)}name:ci", REFUSAL_EXIT),
    "next-line": (f"ash{chr(0x0085)}name:ci", REFUSAL_EXIT),
    "line-separator": (f"ash{chr(0x2028)}name:ci", REFUSAL_EXIT),
    "space": ("ash name:ci", REFUSAL_EXIT),
    "tab": ("ash\tname:ci", REFUSAL_EXIT),
    "trailing-newline": ("ash:ci\n", REFUSAL_EXIT),
    "leading-dash": ("-ash:ci", REFUSAL_EXIT),
    "glob-character": ("ash:c*", REFUSAL_EXIT),
    "non-ascii-letter": (f"caf{chr(0x00E9)}:ci", REFUSAL_EXIT),
    "kelvin-sign": (f"as{chr(0x212A)}:ci", REFUSAL_EXIT),
    "default-name": ("automated-security-helper:non-root", 0),
    "registry-with-a-port": ("localhost:5000/team_x/ash.v2:1.0-rc", 0),
    "digest-reference": ("public.ecr.aws/ash/ash@sha256:" + "0" * 64, 0),
    # A documented limit: a registry named by a bracketed IPv6 literal is refused,
    # since [ and ] are glob characters; name the registry by a host name instead.
    "bracketed-ipv6-registry": ("[::1]:5000/team/ash:ci", REFUSAL_EXIT),
}

#: The same for ASH_BASE_IMAGE_OVERRIDE, a base image reference, which holds the same
#: characters as an image name.
_BASE_IMAGE_OVERRIDES = {
    "space": ("python:3.12 --network=host", REFUSAL_EXIT),
    "leading-dash": ("-python:3.12", REFUSAL_EXIT),
    "no-break-space": (f"python{chr(0x00A0)}:3.12", REFUSAL_EXIT),
    "non-ascii-letter": (f"pyth{chr(0x00F6)}n:3.12", REFUSAL_EXIT),
    # The two traps of a .NET match, pinned on this check too: a case-insensitive
    # [A-Za-z] takes the Kelvin sign as K, and $ matches before a final newline.
    "kelvin-sign": (f"python:3.12-{chr(0x212A)}", REFUSAL_EXIT),
    "trailing-newline": ("python:3.12\n", REFUSAL_EXIT),
    "digest-reference": ("docker.io/library/python@sha256:" + "b" * 64, 0),
}


def _utf8_locale() -> str | None:
    """A UTF-8 locale this host has."""
    try:
        listed = subprocess.run(  # nosec B603 B607 - fixed command, no input
            ["locale", "-a"], capture_output=True, text=True, timeout=30, check=False
        ).stdout.split()
    except (OSError, subprocess.SubprocessError):
        return None
    return next((name for name in ("C.UTF-8", "C.utf8") if name in listed), None)


def _both_wrappers_in_both_locales(
    tmp_path: Path, invocation: str, ash_flags: list[str], **env: str
) -> list[int]:
    """The exit codes of ./ash and of Invoke-ASH, each in the C and a UTF-8 locale.

    An ./ash run that exits 0 must have reached the runner, so 0 means the value was
    taken, not that the run stopped somewhere else.
    """
    utf8 = _utf8_locale()
    if utf8 is None:
        pytest.skip("no UTF-8 locale on this host")
    (tmp_path / "src").mkdir(exist_ok=True)
    runner = _native_runner(tmp_path)
    measured = []
    for locale_name in ("C", utf8):
        run_dir = tmp_path / f"ash-{locale_name}"
        run_dir.mkdir()
        proc = subprocess.run(  # nosec B603 - fixed interpreter and script, list args
            [
                shutil.which("bash") or "bash",
                str(REPO_ROOT / "ash"),
                *ash_flags,
                "--source-dir",
                str(tmp_path / "src"),
                "--output-dir",
                str(run_dir / "out"),
            ],
            cwd=run_dir,
            env=_clean_env(
                tmp_path,
                OCI_RUNNER=str(runner),
                NATIVE_RUNNER_LOG=str(run_dir / "native.log"),
                LC_ALL=locale_name,
                **env,
            ),
            capture_output=True,
            timeout=120,
            check=False,
        )
        ran = (run_dir / "native.log.run").exists()
        assert ran == (proc.returncode == 0), proc.stdout + proc.stderr
        measured.append(proc.returncode)
    for locale_name in ("C", utf8):
        run_dir = tmp_path / f"invoke-ash-{locale_name}"
        run_dir.mkdir()
        result, calls = _run_script(
            run_dir, _wrapped(invocation), LC_ALL=locale_name, **env
        )
        assert calls == [], calls
        measured.append(result.returncode)
    return measured


@pytest.mark.integration
@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="./ash's runs in this module are measured on Linux",
)
@pytest.mark.parametrize("name", sorted(_IMAGE_NAMES))
def test_the_wrappers_agree_on_an_image_name(tmp_path, name):
    image, code = _IMAGE_NAMES[name]
    measured = _both_wrappers_in_both_locales(
        tmp_path,
        f"{_INVOKE} -AshImageName $env:ASH_IMAGE_NAME",
        ["--no-build"],
        ASH_IMAGE_NAME=image,
        ASH_BASE_IMAGE_OVERRIDE="",
    )
    assert measured == [code] * 4, measured


@pytest.mark.integration
@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="./ash's runs in this module are measured on Linux",
)
@pytest.mark.parametrize("name", sorted(_BASE_IMAGE_OVERRIDES))
def test_the_wrappers_agree_on_a_base_image_override(tmp_path, name):
    # ./ash reads the override only when it builds without ASH_BASE_OCI_LAYOUT, so
    # its runs build; Invoke-ASH reads it when it starts.
    override, code = _BASE_IMAGE_OVERRIDES[name]
    measured = _both_wrappers_in_both_locales(
        tmp_path, _INVOKE, [], ASH_BASE_IMAGE_OVERRIDE=override
    )
    assert measured == [code] * 4, measured


#: Characters a refusal must not print as they are: each would move the cursor or
#: change colors (ESC), reverse the text after it (U+202E), hide in it (U+200B), or
#: break the line (U+2028). Each cell: the character and how Invoke-ASH writes it.
_HIDDEN_CHARACTERS = {
    "escape": (chr(0x1B), "\\x1B"),
    "right-to-left-override": (chr(0x202E), "\\u202E"),
    "zero-width-space": (chr(0x200B), "\\u200B"),
    "line-separator": (chr(0x2028), "\\u2028"),
}

#: Where each refused value is shown: the variable a test sets, and the text the
#: refusal puts before the value and after it, without whitespace, as _unwrapped
#: leaves it. Both wrappers give the same message.
_SHOWN_IN = {
    "image-name": (
        "ASH_IMAGE_NAME",
        "Theimagename'",
        (
            "'startswith'-',whichthecontainerruntimewouldreadasanoption,orholdsa"
            "characterotherthanA-Z,a-z,0-9and._:/@-,whichnoimagenamedoes.Namean"
            "imagewithonlythosecharacters,notstartingwith'-'."
        ),
    ),
    "base-image-override": (
        "ASH_BASE_IMAGE_OVERRIDE",
        "ASH_BASE_IMAGE_OVERRIDE'",
        (
            "'startswith'-'orholdsacharacterotherthanA-Z,a-z,0-9and._:/@-,whichno"
            "imagereferencedoes.Nameanimagereferencewithonlythosecharacters,or"
            "unsetittobuildfromtheDockerfile'sownbaseimagereference."
        ),
    ),
}


def _invoke_ash_refusal(tmp_path: Path, where: str, value: str):
    tmp_path.mkdir(parents=True, exist_ok=True)
    variable = _SHOWN_IN[where][0]
    invocation = _INVOKE
    if where == "image-name":
        invocation = f"{_INVOKE} -AshImageName $env:ASH_IMAGE_NAME"
    return _run_script(tmp_path, _wrapped(invocation), **{variable: value})


@pytest.mark.integration
@pytest.mark.parametrize("where", sorted(_SHOWN_IN))
@pytest.mark.parametrize("character", sorted(_HIDDEN_CHARACTERS))
def test_a_refused_value_is_shown_with_its_hidden_characters_escaped(
    tmp_path, where, character
):
    raw, escape = _HIDDEN_CHARACTERS[character]
    _, before, after = _SHOWN_IN[where]

    result, calls = _invoke_ash_refusal(tmp_path, where, f"image{raw}name")

    # The value as given, not ESC on its own: PowerShell colors its error view with
    # escape sequences of its own.
    assert result.returncode == REFUSAL_EXIT, result.stdout + result.stderr
    assert f"image{raw}name" not in result.stdout + result.stderr, repr(result.stderr)
    assert f"{before}image{escape}name{after}" in _unwrapped(result.stderr), repr(
        result.stderr
    )
    assert calls == [], calls


def _decode_ash_shown(shown: str) -> str:
    """The value ./ash's shown() wrote: as typed, or in bash's $'...' form."""
    if not (shown.startswith("$'") and shown.endswith("'")):
        return shown
    named = {"E": 0x1B, "a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13}
    named.update({"\\": 0x5C, "'": 0x27})
    body, decoded, at = shown[2:-1], bytearray(), 0
    while at < len(body):
        octal = re.match(r"\\([0-7]{3})", body[at:])
        if octal:
            decoded.append(int(octal.group(1), 8))
            at += 4
        elif body[at] == "\\" and body[at + 1 : at + 2] in named:
            decoded.append(named[body[at + 1]])
            at += 2
        else:
            decoded.extend(body[at].encode("utf-8"))
            at += 1
    return decoded.decode("utf-8")


def _decode_invoke_ash_shown(shown: str) -> str:
    """The value Invoke-ASH wrote: \\xHH, \\uXXXX and \\UXXXXXXXX read back.

    A run of backslashes before text that reads as an escape was doubled, so an odd
    run there ends in an escape and an even one is text; any other run is as typed.
    """

    def read(match: re.Match[str]) -> str:
        run, escape = match.group(1), match.group(2)
        if len(run) % 2 == 0:
            return "\\" * (len(run) // 2) + escape
        return "\\" * (len(run) // 2) + chr(int(escape[1:], 16))

    return re.sub(
        r"(\\+)(x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8})", read, shown
    )


#: Values whose shown form must read back to them, each different from the others:
#: a backslash before text that reads as an escape, before a character that is
#: written as one, and in a Windows path, where a backslash before anything else is
#: left as it is.
_BACKSLASH_LOOKALIKES = (
    "img\\x1Bname",
    f"img{chr(0x1B)}name",
    f"img\\{chr(0x1B)}name",
    "img\\\\x1Bname",
    "img\\u202Ename",
    f"img{chr(0x202E)}name",
    "img\\U000E0041name",
    f"img{chr(0xE0041)}name",
    "C:\\Python\\x64\\Lib",
    "C:\\src\\tools\\ash",
    "trailing\\",
)


@pytest.mark.integration
def test_the_shown_form_reads_back_to_the_value_one_to_one(tmp_path):
    """A literal backslash-x-1-B and a real ESC are shown differently.

    The display escapes what a terminal acts on and doubles a run of backslashes
    only where it would read as part of an escape, so a Windows path reads as typed
    and every value reads back from its shown form.
    """
    result, _ = _run_script(
        tmp_path,
        "$values = ConvertFrom-Json $env:ASH_PROBE_VALUES\n"
        "$shown = @($values | ForEach-Object { Format-AshShownValue $_ })\n"
        "Write-Output (ConvertTo-Json -Compress -InputObject $shown)\n"
        "exit 0\n",
        ASH_PROBE_VALUES=json.dumps(list(_BACKSLASH_LOOKALIKES)),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    shown = json.loads(result.stdout.strip().splitlines()[-1])

    assert [_decode_invoke_ash_shown(text) for text in shown] == list(
        _BACKSLASH_LOOKALIKES
    ), shown
    assert len(set(shown)) == len(shown), shown
    assert shown[_BACKSLASH_LOOKALIKES.index("C:\\src\\tools\\ash")] == (
        "C:\\src\\tools\\ash"
    ), shown
    assert not any(chr(0x1B) in text or chr(0x202E) in text for text in shown), shown


@pytest.mark.integration
def test_a_refused_literal_escape_and_a_real_one_are_shown_apart(tmp_path):
    shown = []
    for name, value in (("literal", "img\\x1Bname"), ("real", f"img{chr(0x1B)}name")):
        (tmp_path / name).mkdir()
        result, calls = _run_script(
            tmp_path / name,
            _wrapped(f"{_INVOKE} -AshImageName $env:ASH_IMAGE_NAME"),
            ASH_IMAGE_NAME=value,
        )
        assert result.returncode == REFUSAL_EXIT, result.stdout + result.stderr
        assert calls == [], calls
        shown.append(_shown_value(result.stderr, *_SHOWN_IN["image-name"][1:]))

    assert shown == ["img\\\\x1Bname", "img\\x1Bname"], shown


def _shown_value(output: str, before: str, after: str) -> str:
    """The value a refusal showed, between its text before and after it."""
    unwrapped = _unwrapped(output)
    assert before in unwrapped and after in unwrapped, repr(output)
    return unwrapped[unwrapped.index(before) + len(before) : unwrapped.index(after)]


@pytest.mark.integration
@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="./ash's runs in this module are measured on Linux",
)
@pytest.mark.parametrize("where", sorted(_SHOWN_IN))
@pytest.mark.parametrize("character", sorted(_HIDDEN_CHARACTERS))
def test_the_wrappers_show_a_refused_value_alike(tmp_path, where, character):
    """Both refusals print the same message and the same value, in two notations.

    Neither prints the character itself. ./ash writes the value as bash's printf
    %q quotes it, $'...', with a format or separator character as its UTF-8 bytes
    in octal (in every locale) and ESC as \\E; Invoke-ASH writes \\xHH for a control
    character and \\uXXXX for the others. Each reads back to the value given.
    """
    raw, _ = _HIDDEN_CHARACTERS[character]
    variable, before, after = _SHOWN_IN[where]
    value = f"image{raw}name"
    utf8 = _utf8_locale()
    if utf8 is None:
        pytest.skip("no UTF-8 locale on this host")
    (tmp_path / "src").mkdir()
    runner = _native_runner(tmp_path)

    for locale_name in ("C", utf8):
        run_dir = tmp_path / f"ash-{locale_name}"
        run_dir.mkdir()
        proc = subprocess.run(  # nosec B603 - fixed interpreter and script, list args
            [
                shutil.which("bash") or "bash",
                str(REPO_ROOT / "ash"),
                # ./ash reads the override only when it builds.
                *(["--no-build"] if where == "image-name" else []),
                "--source-dir",
                str(tmp_path / "src"),
                "--output-dir",
                str(run_dir / "out"),
            ],
            cwd=run_dir,
            env=_clean_env(
                tmp_path,
                OCI_RUNNER=str(runner),
                NATIVE_RUNNER_LOG=str(run_dir / "native.log"),
                LC_ALL=locale_name,
                **{variable: value},
            ),
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=120,
            check=False,
        )
        assert proc.returncode == REFUSAL_EXIT, proc.stdout + proc.stderr
        assert raw not in proc.stdout + proc.stderr, repr(proc.stderr)
        shown = _shown_value(proc.stderr, before, after)
        assert shown.startswith("$'"), shown
        assert _decode_ash_shown(shown) == value, shown

    result, calls = _invoke_ash_refusal(tmp_path / "invoke-ash", where, value)
    assert result.returncode == REFUSAL_EXIT, result.stdout + result.stderr
    # PowerShell colors its error view with escape sequences of its own.
    assert value not in result.stdout + result.stderr, repr(result.stderr)
    shown = _shown_value(result.stderr, before, after)
    assert _decode_invoke_ash_shown(shown) == value, shown
    assert calls == [], calls


#: --workspace and an explicit --sandbox other than off, together, in either order,
#: given as separate arguments or as one quoted argument. The sandbox is the usage
#: error ASH itself gives, so both wrappers refuse it with 5 whatever its place; the
#: workspace pass runs after it. Each cell: ./ash's arguments and Invoke-ASH's.
_WORKSPACE_AND_SANDBOX = {
    "separate-workspace-first": (
        ["--workspace", "w.code-workspace", "--sandbox", "bwrap"],
        f"{_INVOKE} --workspace w.code-workspace --sandbox bwrap",
    ),
    "separate-sandbox-first": (
        ["--sandbox", "bwrap", "--workspace", "w.code-workspace"],
        f"{_INVOKE} --sandbox bwrap --workspace w.code-workspace",
    ),
    "quoted-workspace-first": (
        ["--workspace w.code-workspace --sandbox bwrap"],
        f"{_INVOKE} -AshArgs '--workspace w.code-workspace --sandbox bwrap'",
    ),
    "quoted-sandbox-first": (
        ["--sandbox bwrap --workspace w.code-workspace"],
        f"{_INVOKE} -AshArgs '--sandbox bwrap --workspace w.code-workspace'",
    ),
}


@pytest.mark.integration
@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="./ash's runs in this module are measured on Linux",
)
@pytest.mark.parametrize("cell", sorted(_WORKSPACE_AND_SANDBOX))
def test_the_wrappers_refuse_a_sandbox_next_to_a_workspace_alike(tmp_path, cell):
    ash_args, invocation = _WORKSPACE_AND_SANDBOX[cell]
    (tmp_path / "src").mkdir()
    runner = _native_runner(tmp_path)
    proc = subprocess.run(  # nosec B603 - fixed interpreter and script, list args
        [
            shutil.which("bash") or "bash",
            str(REPO_ROOT / "ash"),
            "--no-build",
            "--source-dir",
            str(tmp_path / "src"),
            "--output-dir",
            str(tmp_path / "out"),
            *ash_args,
        ],
        cwd=tmp_path,
        env=_clean_env(
            tmp_path,
            OCI_RUNNER=str(runner),
            NATIVE_RUNNER_LOG=str(tmp_path / "native.log"),
        ),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    (tmp_path / "invoke-ash").mkdir()
    result, calls = _run_script(tmp_path / "invoke-ash", _wrapped(invocation))

    assert [proc.returncode, result.returncode] == [USAGE_ERROR_EXIT] * 2, (
        proc.stderr + result.stderr
    )
    assert "--sandbox bwrap cannot be used" in proc.stderr, proc.stderr
    assert "--sandboxbwrapcannotbeused" in _unwrapped(result.stderr), result.stderr
    assert not (tmp_path / "native.log.run").exists()
    assert calls == [], calls


@pytest.mark.integration
@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="./ash's runs in this module are measured on Linux",
)
def test_an_empty_ash_image_name_is_unset_in_both_wrappers(tmp_path):
    """An empty ASH_IMAGE_NAME names no image, so both wrappers use the default.

    ./ash reads it with ${ASH_IMAGE_NAME:-...}. pwsh off Windows keeps an empty
    variable as '' rather than $null, and Invoke-ASH tested $null, so -AshImageName
    defaulted to '' and was refused with 3. -AshImageName is left unbound here; the
    image-name tables bind it.
    """
    default = "automated-security-helper:non-root"
    (tmp_path / "src").mkdir()
    runner = _native_runner(tmp_path)
    proc = subprocess.run(  # nosec B603 - fixed interpreter and script, list args
        [
            shutil.which("bash") or "bash",
            str(REPO_ROOT / "ash"),
            "--no-build",
            "--source-dir",
            str(tmp_path / "src"),
            "--output-dir",
            str(tmp_path / "out"),
        ],
        cwd=tmp_path,
        env=_clean_env(
            tmp_path,
            OCI_RUNNER=str(runner),
            NATIVE_RUNNER_LOG=str(tmp_path / "native.log"),
            ASH_IMAGE_NAME="",
        ),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    (tmp_path / "invoke-ash").mkdir()
    result, calls = _run_script(
        tmp_path / "invoke-ash", _wrapped(_RUN), ASH_IMAGE_NAME=""
    )

    assert [proc.returncode, result.returncode] == [0, 0], proc.stderr + result.stderr
    assert default in _native_calls(tmp_path, "run"), _native_calls(tmp_path, "run")
    assert default in _run_call(result, calls), calls


@pytest.mark.integration
@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="./ash's runs in this module are measured on Linux",
)
@pytest.mark.parametrize("character", sorted(_HIDDEN_CHARACTERS))
def test_the_wrappers_show_ash_config_in_their_warning_alike(tmp_path, character):
    """The ASH_CONFIG warning shows the value as a refusal shows one.

    A scan carries the file ASH_CONFIG names into the container, and refuses a file
    that is not there. For another subcommand (``report`` here) both wrappers warn
    that they do not pass ASH_CONFIG into the container, naming it. Printed as it is,
    an ESC in it would change the terminal and U+202E would reverse the text after
    it, so ./ash writes it as bash's %q, Invoke-ASH with \\xHH and \\uXXXX; each
    reads back to the value given.
    """
    raw, _ = _HIDDEN_CHARACTERS[character]
    value = f"cfg{raw}x.yaml"
    before, after = "ASH_CONFIGisset(", "),but"
    (tmp_path / "src").mkdir()
    runner = _native_runner(tmp_path)
    proc = subprocess.run(  # nosec B603 - fixed interpreter and script, list args
        [
            shutil.which("bash") or "bash",
            str(REPO_ROOT / "ash"),
            "--no-build",
            "--source-dir",
            str(tmp_path / "src"),
            "--output-dir",
            str(tmp_path / "out"),
            "report",
        ],
        cwd=tmp_path,
        env=_clean_env(
            tmp_path,
            OCI_RUNNER=str(runner),
            NATIVE_RUNNER_LOG=str(tmp_path / "native.log"),
            ASH_CONFIG=value,
            LC_ALL=_utf8_locale() or "C",
        ),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
        check=False,
    )
    (tmp_path / "invoke-ash").mkdir()
    result, _ = _run_script(
        tmp_path / "invoke-ash",
        _wrapped(f"{_RUN} -AshArgs report"),
        ASH_CONFIG=value,
    )

    assert [proc.returncode, result.returncode] == [0, 0], proc.stderr + result.stderr
    ash_output = proc.stdout + proc.stderr
    assert raw not in ash_output, repr(ash_output)
    assert _decode_ash_shown(_shown_value(ash_output, before, after)) == value
    # PowerShell colors its own output with escape sequences, so it is the value
    # that must not appear, not a lone ESC.
    invoke_output = result.stdout + result.stderr
    assert value not in invoke_output, repr(invoke_output)
    shown = _shown_value(invoke_output, before, after)
    assert _decode_invoke_ash_shown(shown) == value, shown


#: A build target or a --sandbox mode with a control or format character after it.
#: PowerShell's -eq, -in and -notin compare with the culture, which ignores those
#: characters, so 'ci' + ESC was taken as ci and 'off' + U+200B as off, where ./ash
#: refuses both. Each cell: ./ash's arguments, the variable Invoke-ASH reads the value
#: from, the value, and the code both give (0: taken).
_TARGET_AND_MODE_LOOKALIKES = {
    **{
        f"build-target-{name}": ("--build-target", f"ci{chr(code)}", REFUSAL_EXIT)
        for name, code in (
            ("escape", 0x1B),
            ("bell", 0x07),
            ("right-to-left-override", 0x202E),
            ("zero-width-space", 0x200B),
            ("byte-order-mark", 0xFEFF),
            ("combining-grapheme-joiner", 0x034F),
        )
    },
    **{
        f"sandbox-{name}": ("--sandbox", f"off{chr(code)}", USAGE_ERROR_EXIT)
        for name, code in (
            ("escape", 0x1B),
            ("zero-width-space", 0x200B),
            ("right-to-left-override", 0x202E),
        )
    },
    # Controls: case is still ignored, as both wrappers ignore it.
    "build-target-upper-case": ("--build-target", "CI", 0),
    "sandbox-upper-case": ("--sandbox", "OFF", 0),
}


@pytest.mark.integration
@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="./ash's runs in this module are measured on Linux",
)
@pytest.mark.parametrize("cell", sorted(_TARGET_AND_MODE_LOOKALIKES))
def test_the_wrappers_agree_on_a_lookalike_target_or_mode(tmp_path, cell):
    option, value, code = _TARGET_AND_MODE_LOOKALIKES[cell]
    (tmp_path / "src").mkdir()
    runner = _native_runner(tmp_path)
    proc = subprocess.run(  # nosec B603 - fixed interpreter and script, list args
        [
            shutil.which("bash") or "bash",
            str(REPO_ROOT / "ash"),
            "--no-build",
            "--source-dir",
            str(tmp_path / "src"),
            "--output-dir",
            str(tmp_path / "out"),
            option,
            value,
        ],
        cwd=tmp_path,
        env=_clean_env(
            tmp_path,
            OCI_RUNNER=str(runner),
            NATIVE_RUNNER_LOG=str(tmp_path / "native.log"),
        ),
        capture_output=True,
        timeout=120,
        check=False,
    )
    if option == "--build-target":
        invocation = f"{_INVOKE} -BuildTarget $env:ASH_PROBE_VALUE"
    else:
        invocation = f"{_INVOKE} --sandbox $env:ASH_PROBE_VALUE"
    (tmp_path / "invoke-ash").mkdir()
    result, calls = _run_script(
        tmp_path / "invoke-ash", _wrapped(invocation), ASH_PROBE_VALUE=value
    )

    assert [proc.returncode, result.returncode] == [code, code], (
        proc.stderr,
        result.stderr,
    )
    assert calls == [], calls


#: Each refusal site that shows a value, given one holding U+202E through
#: ASH_PROBE_VALUE: the call, what the test directory needs, and how many times the
#: escape must appear (the link refusal shows the -OutputDir and the link). Each
#: exits with REFUSAL_EXIT except those in _HIDDEN_CHARACTER_USAGE_ERRORS.
_HIDDEN_CHARACTER_SITES = {
    "build-target": (f"{_INVOKE} -BuildTarget $env:ASH_PROBE_VALUE", "ci{c}x", {}, 1),
    "source-dir": (
        _INVOKE.replace("-SourceDir src", "-SourceDir $env:ASH_PROBE_VALUE"),
        "no{c}dir",
        {},
        1,
    ),
    "output-dir": (
        _INVOKE.replace("-OutputDir out", "-OutputDir $env:ASH_PROBE_VALUE"),
        "blocker/o{c}ut",
        {"files": ["blocker"]},
        1,
    ),
    # The reason is the system's text for the error, not the exception's message,
    # which names the path again, so the path is shown once.
    "output-dir-reason": (
        _INVOKE.replace("-OutputDir out", "-OutputDir $env:ASH_PROBE_VALUE"),
        "read-only/o{c}ut",
        {"read-only": ["read-only"]},
        1,
    ),
    "output-dir-link": (
        _INVOKE.replace("-OutputDir out", "-OutputDir $env:ASH_PROBE_VALUE"),
        "lin{c}k",
        {"links": [("lin{c}k", "elsewhere")]},
        2,
    ),
    "runner": (f"{_INVOKE} -OCIRunner $env:ASH_PROBE_VALUE", "no{c}runner", {}, 1),
    # A comment is not an argument; its text is shown.
    "ash-args-token": (f"{_INVOKE} -AshArgs $env:ASH_PROBE_VALUE", "--x #c{c}d", {}, 1),
    # A word PowerShell would expand; its text is shown.
    "ash-args-expandable": (
        f"{_INVOKE} -AshArgs $env:ASH_PROBE_VALUE",
        "--x $a{c}b",
        {},
        1,
    ),
    "pass-whole": (
        "Assert-AshArgumentsPassWhole -Arguments @($env:ASH_PROBE_VALUE) -LegacyQuoting",
        'a"b{c}',
        {},
        1,
    ),
}
#: A -SourceDir that does not exist and an -OutputDir that cannot be created are
#: usage errors, as they are from ./ash.
_HIDDEN_CHARACTER_USAGE_ERRORS = {"source-dir", "output-dir", "output-dir-reason"}


@pytest.mark.integration
@pytest.mark.parametrize("site", sorted(_HIDDEN_CHARACTER_SITES))
def test_every_refusal_that_shows_a_value_escapes_its_hidden_characters(tmp_path, site):
    invocation, template, needs, escapes = _HIDDEN_CHARACTER_SITES[site]
    raw = chr(0x202E)
    value = template.format(c=raw)
    if "read-only" in needs:
        if os.name == "nt" or os.geteuid() == 0:
            pytest.skip("a read-only directory stops only a user other than root")
        (tmp_path / "read-only").mkdir()
        (tmp_path / "read-only").chmod(0o555)
    for name in needs.get("files", []):
        (tmp_path / name).write_text("not a directory\n", encoding="utf-8")
    for link, target in needs.get("links", []):
        (tmp_path / target).mkdir()
        _link_dir(tmp_path / link.format(c=raw), tmp_path / target)
    try:
        result, calls = _run_script(
            tmp_path, _wrapped(invocation), ASH_PROBE_VALUE=value
        )
    finally:
        if "read-only" in needs:
            (tmp_path / "read-only").chmod(0o755)

    output = result.stdout + result.stderr
    if site in _HIDDEN_CHARACTER_USAGE_ERRORS:
        assert result.returncode == USAGE_ERROR_EXIT, output
    else:
        assert result.returncode == REFUSAL_EXIT, output
    assert raw not in output, repr(output)
    assert _unwrapped(output).count("\\u202E") >= escapes, output
    assert calls == [], calls


#: What a throw or a Write-* call in the helper may interpolate without
#: Format-AshShownValue: names and text the helper itself chose, never a value the
#: caller gave. $tried, $shownMode, $shownBuildCmd and $shownRunCmd are built from
#: values already shown, and so are $runnerRefusal and $mountRefusal, whole messages
#: thrown from a variable so that PowerShell's error view, which quotes the throw's
#: source line, prints each once. $createReason and $writeReason are the system's text for an
#: error, never the exception's message, which names the path. The
#: ASH_BASE_OCI_LAYOUT refusal is left as it is. ``$($id[0])`` is the word UID or GID
#: from the literal list the ContainerUID and ContainerGID check walks, and
#: ``$envConfigHeld`` is one of four phrases the helper picks for the character a
#: --mount cannot take in the ASH_CONFIG path. Both are allowed by the extent the walk
#: reaches on its way up from the variable, so ``$id`` on its own stays unlisted: the
#: value, ``$id[1]``, goes through Format-AshShownValue.
_INTERPOLATED_AS_IS = {
    "$createReason",
    "$writeReason",
    "$name",
    "$tokenType",
    "$reader",
    "$problem",
    "$instead",
    "$LASTEXITCODE",
    "$shownMode",
    "$shownBuildCmd",
    "$shownRunCmd",
    "$tried",
    "$subcommand",
    "$option",
    "$AshImageName",
    "$($sandboxModes -join ', ')",
    "$($outputProvider.Name)",
    "$($env:ASH_BASE_OCI_LAYOUT)",
    "$($id[0])",  # 'UID' or 'GID', the first word of each pair in the literal list
    "$envConfigHeld",  # a newline, a carriage return, a comma or a double quote
    "$runnerRefusal",  # the OCI_RUNNER refusal, built from $tried
    "$mountRefusal",  # the --mount refusal, built from shown paths and a held phrase
}


#: Messages in the runner and build block that is held for later work, left as they
#: are: the progress lines the ASH_BASE_OCI_LAYOUT and ASH_BASE_IMAGE_OVERRIDE
#: handling prints.
_HELD_MESSAGES = (
    'Write-Host "Base image expected in ',
    'Write-Host "Base image redirected to ',
)

#: Walks a helper with PowerShell's own parser: every throw and every Write-* call,
#: and each variable inside one that neither Format-AshShownValue nor an allowed
#: expression holds. Prints how many messages it read, then each finding as
#: line|variable|the message's first line, as JSON.
_UNSHOWN_VALUES = r"""
$ErrorActionPreference = 'Stop'
$allowed = @(ConvertFrom-Json $env:ASH_PROBE_ALLOWED)
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($env:ASH_PROBE_SOURCE, [ref]$tokens, [ref]$errors)
if (@($errors).Count -gt 0) { throw "the helper does not parse: $($errors[0].Message)" }
$messages = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.ThrowStatementAst] -or
    ($node -is [System.Management.Automation.Language.CommandAst] -and "$($node.GetCommandName())" -like 'Write-*')
}, $true))
$raw = @(foreach ($message in $messages) {
    foreach ($variable in @($message.FindAll({ param($node) $node -is [System.Management.Automation.Language.VariableExpressionAst] }, $true))) {
        $node = $variable
        $covered = $false
        while ($true) {
            if (($node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'Format-AshShownValue') -or ($allowed -ccontains $node.Extent.Text)) {
                $covered = $true
                break
            }
            if ([object]::ReferenceEquals($node, $message)) { break }
            $node = $node.Parent
        }
        if (-not $covered) {
            '{0}|{1}|{2}' -f $variable.Extent.StartLineNumber, $variable.Extent.Text, ($message.Extent.Text -split "`n")[0].Trim()
        }
    }
})
Write-Output ('COUNT ' + $messages.Count)
Write-Output (ConvertTo-Json -Compress -InputObject $raw)
exit 0
"""


def _unshown_values(tmp_path: Path, source: Path) -> tuple[int, list[str]]:
    """How many messages ``source`` has, and the values they show raw."""
    env = _clean_env(
        tmp_path,
        ASH_PROBE_SOURCE=str(source),
        ASH_PROBE_ALLOWED=json.dumps(sorted(_INTERPOLATED_AS_IS)),
    )
    result = _pwsh(_UNSHOWN_VALUES, tmp_path, env)
    assert result.returncode == 0, result.stdout + result.stderr
    lines = result.stdout.strip().splitlines()
    count = int(lines[-2].removeprefix("COUNT "))
    found = json.loads(lines[-1])
    return count, [
        finding
        for finding in found
        if not finding.split("|", 2)[2].startswith(_HELD_MESSAGES)
    ]


@pytest.mark.integration
def test_every_value_a_message_interpolates_is_shown(tmp_path):
    """A value in a throw or a Write-* call goes through Format-AshShownValue.

    The cells above reach the sites an input can reach. This reads the source with
    PowerShell's parser, so it holds a site no input reaches (the -AshArgs parse
    error) to the same rule, whatever form the message takes: a throw on one line
    with its if, a concatenation, a -f format, Write-Error, Write-Verbose or
    Write-Host, or a trailing comment. Reading lines that start with throw or
    Write-Warning missed all of those.
    """
    count, raw = _unshown_values(tmp_path, HELPERS)
    assert count >= 30, count
    assert raw == [], raw


#: A helper with two messages that show only allowed expressions and three that show
#: a variable raw: a bare ``$id``, ``$id[1]`` outside Format-AshShownValue, and a
#: value the helper did not choose next to ``$envConfigHeld``.
_ALLOWED_EXTENTS_PROBE = r"""
function Show-Probe {
    throw "Container $($id[0]) must be numeric: '$(Format-AshShownValue $id[1])'."
    throw "Container $id must be numeric."
    throw "Container $($id[1]) must be numeric."
    throw "ASH_CONFIG is a path with $envConfigHeld in it."
    throw "ASH_CONFIG $envConfigGiven is a path with $envConfigHeld in it."
}
"""


@pytest.mark.integration
def test_the_allowed_extents_do_not_cover_a_bare_variable(tmp_path):
    """Control for the walk above: ``$($id[0])`` and ``$envConfigHeld`` are allowed by
    their extents, so ``$id`` shown raw, ``$id[1]`` outside Format-AshShownValue and a
    value the helper did not choose are still found."""
    probe = tmp_path / "probe.ps1"
    probe.write_text(_ALLOWED_EXTENTS_PROBE, encoding="utf-8")

    count, raw = _unshown_values(tmp_path, probe)

    assert count == 5, count
    assert [finding.split("|", 2)[1] for finding in raw] == [
        "$id",
        "$id",
        "$envConfigGiven",
    ], raw


@pytest.mark.integration
def test_the_verbose_lines_show_paths_with_their_escapes(tmp_path):
    """-Verbose prints the source and output directories and the run command.

    Each path, and each word of the command, goes through Format-AshShownValue, as a
    refusal's value does, so U+202E in a directory's name is written out.
    """
    raw = chr(0x202E)
    (tmp_path / f"s{raw}rc").mkdir()
    result, calls = _run_script(
        tmp_path,
        "$rc = Invoke-ASH -NoBuild -SourceDir $env:ASH_PROBE_SOURCE"
        " -OutputDir $env:ASH_PROBE_OUTPUT -Verbose\n"
        "exit [int]$LASTEXITCODE\n",
        ASH_PROBE_SOURCE=f"s{raw}rc",
        ASH_PROBE_OUTPUT=f"o{raw}ut",
    )

    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert _run_call(result, calls)
    for label in ("Resolved SourceDir to:", "Creating OutputDir:", "Run command:"):
        assert _unwrapped(label) in _unwrapped(output), output
    assert raw not in output, repr(output)
    assert _unwrapped(output).count("\\" + "u202E") >= 3, output


@pytest.mark.integration
def test_tab_completion_offers_the_build_targets(tmp_path):
    # -BuildTarget is checked in the body, so a value outside the set exits 3 like
    # every refusal, not with PowerShell's binding error; the completer keeps the
    # values a ValidateSet would have offered.
    line = "Invoke-ASH -BuildTarget "
    result, _ = _run_script(
        tmp_path,
        f"$c = TabExpansion2 -inputScript '{line}' -cursorColumn {len(line)}\n"
        "Write-Output (ConvertTo-Json -Compress -InputObject "
        "@($c.CompletionMatches | ForEach-Object { $_.CompletionText }))\n"
        "exit 0\n",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout.strip().splitlines()[-1]) == ["ci", "non-root"]


@pytest.mark.unit
def test_the_help_gives_the_wrapped_form():
    help_text = HELPERS.read_text(encoding="utf-8").split("[CmdletBinding()]")[0]
    description = help_text.split(".DESCRIPTION")[1].split(".PARAMETER")[0]
    form = "try { Invoke-ASH ... } catch { " + "; ".join(_WRAPPED_CATCH) + " }"
    assert _unwrapped(form) in _unwrapped(description), description


@pytest.mark.integration
def test_oci_runner_wrapper_is_split_into_words(tmp_path):
    # OCI_RUNNER_WRAPPER prefixes the runner, and is split at whitespace as ./ash
    # splits it: "sudo -E" is a program and its option, not a program named "sudo -E".
    wrapper = (
        "function global:wrapme { Add-Content -LiteralPath $env:RUNNER_LOG -Value "
        "(ConvertTo-Json -Compress -InputObject (@('wrapme') + @($args | "
        "ForEach-Object { [string]$_ }))); $global:LASTEXITCODE = 0 }\n"
    )
    result, calls = _invoke(
        tmp_path,
        "Invoke-ASH -NoBuild -SourceDir src -OutputDir out",
        preamble=wrapper,
        OCI_RUNNER_WRAPPER="wrapme --keep-env",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    runs = [call for call in calls if call[3:4] == ["run"]]
    assert len(runs) == 1, calls
    assert runs[0][:4] == ["wrapme", "--keep-env", "finch", "run"], runs[0]


_RECORDING_ID_STUB = (
    'function global:id { Add-Content -LiteralPath $env:ID_LOG -Value "$args"; '
    "if ($args[0] -eq '-u') { '4242' } else { '4343' } }\n"
)


@pytest.mark.integration
def test_no_build_looks_up_no_ids(tmp_path):
    result, calls = _invoke(
        tmp_path,
        "Invoke-ASH -NoBuild -SourceDir src -OutputDir out",
        preamble=_RECORDING_ID_STUB,
        ID_LOG=str(tmp_path / "id.log"),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    # Invoke-ASH ran: an Invoke-ASH that did nothing would look up no IDs either.
    assert _run_call(result, calls)
    assert not (tmp_path / "id.log").exists()


@pytest.mark.integration
@pytest.mark.skipif(
    os.name == "nt", reason="the IDs are taken from id only off Windows"
)
def test_without_id_the_build_warns_and_keeps_the_images_default_ids(tmp_path):
    # A PATH with nothing but the runner guard, so there is no id to find.
    result, calls = _invoke(
        tmp_path,
        "Invoke-ASH -SourceDir src -OutputDir out",
        PATH=str(tmp_path / "runner-guard"),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "id is not on PATH" in result.stdout + result.stderr
    build = _build_call(result, calls)
    assert not [arg for arg in build if arg.startswith(("UID=", "GID="))], build


# Flags whose defaults belong to ash.


@pytest.mark.integration
def test_no_progress_summary_or_findings_flag_is_forced(tmp_path):
    result, calls = _invoke(
        tmp_path, "Invoke-ASH -NoBuild -SourceDir src -OutputDir out"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    forced = _DEFAULTED_BY_ASH.intersection(_inner_ash_args(_run_call(result, calls)))
    assert not forced, (
        f"Invoke-ASH passed {sorted(forced)} without being asked; ./ash leaves these "
        "to ash's defaults and configuration"
    )


@pytest.mark.integration
@pytest.mark.parametrize(
    ("switch", "expected"),
    [
        ("-Progress", "--progress"),
        ("-Progress:$false", "--no-progress"),
        ("-ShowSummary", "--show-summary"),
        ("-ShowSummary:$false", "--no-show-summary"),
        ("-NoFailOnFindings", "--no-fail-on-findings"),
        ("-NoFailOnFindings:$false", "--fail-on-findings"),
    ],
)
def test_a_requested_flag_is_passed_through(tmp_path, switch, expected):
    result, calls = _invoke(
        tmp_path, f"Invoke-ASH -NoBuild -SourceDir src -OutputDir out {switch}"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    inner = _inner_ash_args(_run_call(result, calls))
    assert _DEFAULTED_BY_ASH.intersection(inner) == {expected}, inner


@pytest.mark.integration
@pytest.mark.parametrize(
    ("switches", "expected", "ash_debug"),
    [
        ("-Verbose", ["--verbose"], "NO"),
        ("-Verbose:$false", [], "NO"),
        ("-Debug", ["--debug"], "YES"),
        ("-Debug:$false", [], "NO"),
    ],
)
def test_verbose_and_debug_follow_their_value_not_their_presence(
    tmp_path, switches, expected, ash_debug
):
    result, calls = _invoke(
        tmp_path, f"Invoke-ASH -NoBuild -SourceDir src -OutputDir out {switches}"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    run = _run_call(result, calls)
    inner = _inner_ash_args(run)
    assert [arg for arg in inner if arg in ("--verbose", "--debug")] == expected, inner
    assert _run_env(run).get("ASH_DEBUG") == ash_debug, run


@pytest.mark.integration
def test_config_is_passed_as_config(tmp_path):
    result, calls = _invoke(
        tmp_path, "Invoke-ASH -NoBuild -SourceDir src -OutputDir out -Config cfg.yaml"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    inner = _inner_ash_args(_run_call(result, calls))
    assert inner[inner.index("--config") + 1] == "cfg.yaml", inner


# The directories, and the arguments' position.


@pytest.mark.integration
def test_source_and_output_dirs_reach_ash_as_environment_variables(tmp_path):
    # Positional --source-dir/--output-dir came before the caller's words, so a
    # subcommand ended up after options it may not take. scan reads ASH_SOURCE_DIR and
    # ASH_OUTPUT_DIR; report and merge read ASH_OUTPUT_DIR.
    result, calls = _invoke(
        tmp_path, "Invoke-ASH -NoBuild -SourceDir src -OutputDir out -AshArgs 'report'"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    run = _run_call(result, calls)
    assert _inner_ash_args(run) == ["report"], run
    env = _run_env(run)
    assert env.get("ASH_SOURCE_DIR") == "/src", run
    assert env.get("ASH_OUTPUT_DIR") == "/out", run


@pytest.mark.integration
def test_output_format_sets_no_variable_ash_does_not_read(tmp_path):
    """-OutputFormat put ASH_OUTPUT_FORMAT into the container, and ASH reads no such
    variable: report formats are chosen with --output-formats. The parameter is
    still accepted, so a script that passes it keeps working."""
    result, calls = _invoke(
        tmp_path,
        "Invoke-ASH -NoBuild -SourceDir src -OutputDir out -OutputFormat sarif",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    run = _run_call(result, calls)
    assert "ASH_OUTPUT_FORMAT" not in _run_env(run), run
    assert not any("ASH_OUTPUT_FORMAT" in arg for arg in run), run


@pytest.mark.integration
@pytest.mark.parametrize(
    ("invocation", "source", "expected"),
    [
        # -SourceDir is position 0, so the first argument after the parameters binds
        # to it unless -SourceDir is given; the help and the CHANGELOG say so.
        ("Invoke-ASH -NoBuild -OutputDir out src report", "src", ["report"]),
        (
            "Invoke-ASH -NoBuild -OutputDir out -SourceDir src report --format text",
            "src",
            ["report", "--format", "text"],
        ),
    ],
)
def test_the_first_trailing_argument_is_the_source_directory_unless_given(
    tmp_path, invocation, source, expected
):
    result, calls = _invoke(tmp_path, invocation)
    assert result.returncode == 0, result.stdout + result.stderr
    run = _run_call(result, calls)
    assert _run_env(run)["ASH_ACTUAL_SOURCE_DIR"] == str(tmp_path / source), run
    assert _inner_ash_args(run) == expected, run


@pytest.mark.integration
@pytest.mark.parametrize(
    "report_dir", [True, False], ids=["report-exists", "no-report"]
)
def test_invoke_ash_report_takes_report_as_the_source_directory(tmp_path, report_dir):
    # As the help says: `Invoke-ASH report` scans a directory named report, and is
    # refused as a usage error, with exit 5, when there is none. It never runs
    # `ash report`.
    if report_dir:
        (tmp_path / "report").mkdir()
    result, calls = _run_script(
        tmp_path,
        _wrapped("Invoke-ASH -NoBuild -OutputDir out report"),
    )
    if report_dir:
        assert result.returncode == 0, result.stdout + result.stderr
        run = _run_call(result, calls)
        assert _run_env(run)["ASH_ACTUAL_SOURCE_DIR"] == str(tmp_path / "report"), run
        # A scan: only the sandbox the image's scan runs without.
        assert _inner_ash_args(run) == SANDBOX_OFF, run
    else:
        assert result.returncode == USAGE_ERROR_EXIT, result.stdout + result.stderr
        assert "Sourcedirectorydoesnotexist:report" in _unwrapped(result.stderr), (
            result.stderr
        )
        assert calls == []


# A subcommand in the arguments. ash takes an option given before a subcommand only
# when the subcommand declares it, and refuses it otherwise (`ash -q report` exits 5);
# on the base commit it dropped it silently. So the options Invoke-ASH adds go after
# the subcommand, and only to one that takes them.


@pytest.mark.integration
@pytest.mark.parametrize(
    ("invocation", "expected"),
    [
        pytest.param(
            "-Config c.yaml -Scanners bandit -AshArgs 'scan'",
            ["scan", *SANDBOX_OFF, "--config", "c.yaml", "--scanners", "bandit"],
            id="scan-takes-the-wrappers-options",
        ),
        pytest.param("-AshArgs '-q report'", ["report"], id="report-has-no-quiet"),
        pytest.param(
            "-AshArgs 'report --no-color'",
            ["report", "--no-color"],
            id="report-takes-no-color",
        ),
        pytest.param(
            "-Offline -AshArgs 'report'", ["report"], id="report-has-no-offline"
        ),
        pytest.param(
            "-Verbose -AshArgs 'report --format text'",
            ["report", "--verbose", "--format", "text"],
            id="report-takes-verbose",
        ),
        pytest.param(
            "-Verbose -Offline -AshArgs '-q -c config get'",
            ["config", "get"],
            id="a-group-takes-none",
        ),
        pytest.param(
            "-AshArgs '--log-level DEBUG report'",
            ["--log-level", "DEBUG", "report"],
            id="the-callers-own-words-stay-where-written",
        ),
        pytest.param(
            "-Offline -AshArgs '-q --scanners bandit'",
            [*SANDBOX_OFF, "--quiet", "--offline", "--scanners", "bandit"],
            id="no-subcommand-takes-all",
        ),
    ],
)
def test_the_wrappers_options_go_after_a_subcommand_that_takes_them(
    tmp_path, invocation, expected
):
    result, calls = _invoke(
        tmp_path, f"Invoke-ASH -NoBuild -SourceDir src -OutputDir out {invocation}"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert _inner_ash_args(_run_call(result, calls)) == expected


@pytest.mark.integration
@pytest.mark.parametrize(
    ("invocation", "expected"),
    [
        # With no subcommand ash scans, and the scan's `--sandbox off` comes first; a
        # scan named in the words gets it right after its name.
        pytest.param(
            "-NoFailOnFindings -Scanners bandit -AshArgs '--phases report'",
            [
                *SANDBOX_OFF,
                "--no-fail-on-findings",
                "--scanners",
                "bandit",
                "--phases",
                "report",
            ],
            id="a-value-names-report",
        ),
        pytest.param(
            "-Config cfg.yaml -AshArgs '--phases inspect'",
            [*SANDBOX_OFF, "--config", "cfg.yaml", "--phases", "inspect"],
            id="a-value-names-inspect",
        ),
        pytest.param(
            "-AshArgs '-q --source-dir report'",
            [*SANDBOX_OFF, "--quiet", "--source-dir", "report"],
            id="a-directory-named-report",
        ),
        pytest.param(
            "-AshArgs '-q --phases=report report'",
            ["--phases=report", "report"],
            id="an-attached-value-is-not-the-next-word",
        ),
        pytest.param(
            "-AshArgs '-q -f report scan'",
            ["-f", "report", "scan", *SANDBOX_OFF, "--quiet"],
            id="a-short-option-value",
        ),
        pytest.param(
            "-AshArgs '-q -Pf report scan'",
            ["-Pf", "report", "scan", *SANDBOX_OFF, "--quiet"],
            id="a-value-after-clustered-short-options",
        ),
        pytest.param(
            "-AshArgs '-q -Pfreport report'",
            ["-Pfreport", "report"],
            id="a-value-attached-to-clustered-short-options",
        ),
    ],
)
def test_an_option_value_is_not_the_subcommand(tmp_path, invocation, expected):
    # A root option's value can be a subcommand's name: --phases takes report and
    # inspect. Read as the subcommand, it dropped the wrapper's options with a warning
    # that report does not take them. ./ash skips such a value the same way.
    result, calls = _invoke(
        tmp_path, f"Invoke-ASH -NoBuild -SourceDir src -OutputDir out {invocation}"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert _inner_ash_args(_run_call(result, calls)) == expected
    assert "does not take" not in result.stdout + result.stderr


@pytest.mark.integration
def test_an_option_a_subcommand_does_not_take_is_named_in_a_warning(tmp_path):
    result, calls = _invoke(
        tmp_path,
        "Invoke-ASH -NoBuild -SourceDir src -OutputDir out -Offline -AshArgs 'report'",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "ash report does not take --offline" in result.stdout + result.stderr


@pytest.mark.integration
def test_quiet_and_no_color_are_dropped_without_a_warning(tmp_path):
    # As the help says: they have already quieted the build and kept the container off
    # a terminal, so a subcommand that does not take them loses nothing worth a warning.
    result, calls = _invoke(
        tmp_path,
        "Invoke-ASH -NoBuild -SourceDir src -OutputDir out -AshArgs '-q -c config get'",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert _inner_ash_args(_run_call(result, calls)) == ["config", "get"]
    assert "does not take" not in result.stdout + result.stderr


# The tables those tests rely on are checked against the real commands in
# test_powershell_wrapper_tables.py, which needs no pwsh.


# An output directory reached through a link. A repository that commits
# .ash/ash_output, or .ash, as a link would get the scan's output, and the
# in-container cleanup of the previous run's analysis, reports, scanners, and
# converted directories, sent wherever the link points. Since the image is built for
# the caller's IDs those writes succeed. The default output directory is inside
# -SourceDir, so the committed links below sit in the scanned directory, src.


def _refused(tmp_path, invocation: str):
    return _run_script(
        tmp_path,
        "try {\n"
        f"  {invocation}\n"
        "} catch {\n"
        '  Write-Host "refused: $($_.Exception.Message)"\n'
        "}\n"
        "exit [int]$LASTEXITCODE\n",
    )


def _link_dir(link: Path, target: Path) -> None:
    """Make ``link`` a link to the directory ``target``.

    A symlink, or on Windows a junction, which needs no privilege there; Get-Item
    reports both in LinkType. A target that does not exist is made and removed again
    around a junction, which would otherwise not be made, so the link dangles either way.
    """
    dangling = not target.exists()
    if dangling and os.name == "nt":
        target.mkdir()
    if os.name == "nt":
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    else:
        link.symlink_to(target, target_is_directory=True)
    if dangling and os.name == "nt":
        target.rmdir()


@pytest.mark.integration
@pytest.mark.parametrize(
    "linked",
    [".ash/ash_output", ".ash", ".ash/ash_output (dangling)", "src/out", "src/nested"],
)
def test_an_output_directory_reached_through_a_link_is_refused(tmp_path, linked):
    target = tmp_path / "elsewhere"
    target.mkdir()
    (tmp_path / "src").mkdir()
    output = ".ash/ash_output"
    if linked == ".ash/ash_output":
        (tmp_path / "src" / ".ash").mkdir()
        _link_dir(tmp_path / "src" / ".ash" / "ash_output", target)
        component = tmp_path / "src" / ".ash" / "ash_output"
    elif linked == ".ash":
        _link_dir(tmp_path / "src" / ".ash", target)
        component = tmp_path / "src" / ".ash"
    elif linked == ".ash/ash_output (dangling)":
        (tmp_path / "src" / ".ash").mkdir()
        _link_dir(tmp_path / "src" / ".ash" / "ash_output", target / "not-yet")
        component = tmp_path / "src" / ".ash" / "ash_output"
    elif linked == "src/out":
        _link_dir(tmp_path / "src" / "out", target)
        output = "src/out"
        component = tmp_path / "src" / "out"
    else:
        _link_dir(tmp_path / "src" / "nested", target)
        output = "src/nested/out"
        component = tmp_path / "src" / "nested"
    explicit = "" if output == ".ash/ash_output" else f" -OutputDir {output}"
    result, calls = _refused(tmp_path, f"Invoke-ASH -NoBuild -SourceDir src{explicit}")
    assert "refused: " in result.stdout, result.stdout + result.stderr
    assert "is reached through a link" in result.stdout, result.stdout
    # The refusal names the linked component, and says to pass the resolved path.
    assert _unwrapped(f"('{component}')") in _unwrapped(result.stdout), result.stdout
    assert "resolved path" in result.stdout, result.stdout
    # A refusal of the default output directory names -OutputDir as the way to
    # write elsewhere, as ./ash names --output-dir; one of a given -OutputDir does not.
    hinted = "pass -OutputDir to write elsewhere" in " ".join(result.stdout.split())
    assert hinted == (explicit == ""), result.stdout
    assert result.returncode == REFUSAL_EXIT, result.stdout + result.stderr
    assert calls == []
    assert list(target.iterdir()) == [], list(target.iterdir())


@pytest.mark.integration
def test_a_link_inside_the_source_directory_is_refused_from_another_working_directory(
    tmp_path,
):
    # Below the working directory and below -SourceDir are both checked. Here only
    # -SourceDir holds the link: dropping it from the roots passed every other test.
    (tmp_path / "cwd").mkdir()
    (tmp_path / "repo").mkdir()
    victim = tmp_path / "victim"
    victim.mkdir()
    _link_dir(tmp_path / "repo" / "nested", victim)
    output = tmp_path / "repo" / "nested" / "out"
    result, calls = _refused(
        tmp_path,
        f"Set-Location -LiteralPath '{(tmp_path / 'cwd').as_posix()}'; "
        f"Invoke-ASH -NoBuild -SourceDir '{(tmp_path / 'repo').as_posix()}' "
        f"-OutputDir '{output.as_posix()}'",
    )
    assert "is reached through a link" in result.stdout, result.stdout + result.stderr
    assert result.returncode == REFUSAL_EXIT, result.stdout + result.stderr
    assert calls == []
    assert list(victim.iterdir()) == [], list(victim.iterdir())


@pytest.mark.integration
def test_a_link_is_found_when_the_output_directory_is_typed_in_another_case(tmp_path):
    # macOS and Windows volumes usually ignore case, so the same directory can be typed
    # in another case. Compared case-sensitively, the typed path was not "below the
    # working directory", and the link in its parent was not looked for.
    swapped = Path(str(tmp_path).swapcase())
    if not swapped.exists():
        pytest.skip("this volume tells case apart, so no other spelling reaches it")
    (tmp_path / "src").mkdir()
    victim = tmp_path / "victim"
    victim.mkdir()
    _link_dir(tmp_path / "src" / "nested", victim)
    result, calls = _refused(
        tmp_path,
        f"Invoke-ASH -NoBuild -SourceDir src -OutputDir "
        f"'{(swapped / 'src' / 'nested' / 'out').as_posix()}'",
    )
    assert "is reached through a link" in result.stdout, result.stdout + result.stderr
    assert result.returncode == REFUSAL_EXIT, result.stdout + result.stderr
    assert calls == []
    assert list(victim.iterdir()) == [], list(victim.iterdir())


@pytest.mark.integration
def test_an_output_directory_without_links_is_created(tmp_path):
    result, calls = _invoke(tmp_path, "Invoke-ASH -NoBuild -SourceDir src")
    assert result.returncode == 0, result.stdout + result.stderr
    assert (tmp_path / "src" / ".ash" / "ash_output").is_dir()
    assert _run_call(result, calls)


# The container user.


_ID_STUB = (
    "function global:id { if ($args[0] -eq '-u') { '4242' } "
    "elseif ($args[0] -eq '-g') { '4343' } else { throw \"unexpected id $args\" } }\n"
)


def _uid_gid_args(build: list[str]) -> list[str]:
    return [
        build[i + 1]
        for i, arg in enumerate(build[:-1])
        if arg == "--build-arg" and build[i + 1].startswith(("UID=", "GID="))
    ]


@pytest.mark.integration
def test_the_image_is_built_for_the_callers_uid_and_gid(tmp_path):
    # ./ash and `ash --mode container` build for the caller, so the container can write
    # a host-owned output directory. The image's own default is 500:100.
    result, calls = _invoke(
        tmp_path, "Invoke-ASH -SourceDir src -OutputDir out", preamble=_ID_STUB
    )
    assert result.returncode == 0, result.stdout + result.stderr
    build = _build_call(result, calls)
    if os.name == "nt":
        assert _uid_gid_args(build) == [], build
    else:
        assert _uid_gid_args(build) == ["UID=4242", "GID=4343"], build


@pytest.mark.integration
def test_an_explicit_container_uid_and_gid_win(tmp_path):
    result, calls = _invoke(
        tmp_path,
        "Invoke-ASH -SourceDir src -OutputDir out -ContainerUID 7 -ContainerGID 8",
        preamble=_ID_STUB,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert _uid_gid_args(_build_call(result, calls)) == ["UID=7", "GID=8"]


_ROOT_ID_STUB = (
    "function global:id { if ($args[0] -in @('-u', '-g')) { '0' } "
    'else { throw "unexpected id $args" } }\n'
)


_CI_VARIABLES = ("CI", "IsCI", "ISCI", "CODEBUILD_BUILD_ID")


@pytest.mark.integration
@pytest.mark.skipif(
    os.name == "nt",
    reason="Windows always builds ci, and its variable names ignore case (ISCI is IsCI)",
)
@pytest.mark.parametrize(
    "variable",
    [
        *[pytest.param(name, id=name) for name in _CI_VARIABLES],
        pytest.param(None, id="none"),
    ],
)
def test_the_ci_variables_do_not_choose_the_stage(tmp_path, variable):
    # The four names CI systems set play no part in the stage, as for `ash --mode
    # container` and ./ash (run_ash_container.py, _resolve_build_target;
    # docs/content/docs/cli-reference.md): off Windows it is non-root unless
    # -BuildTarget names another. Names are case-sensitive here, so ISCI and IsCI are
    # two variables. The others are removed in the script, since the test's own
    # environment may be a CI runner's.
    others = [name for name in _CI_VARIABLES if name != variable]
    removals = "".join(
        f"Remove-Item -LiteralPath 'Env:{name}' -ErrorAction SilentlyContinue\n"
        for name in others
    )
    env = {variable: "1"} if variable else {}
    result, calls = _run_script(
        tmp_path,
        removals + "Invoke-ASH -NoRun -SourceDir src -OutputDir out\nexit 0\n",
        **env,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    build = _build_call(result, calls)
    assert build[build.index("--target") + 1] == "non-root", build


@pytest.mark.integration
@pytest.mark.skipif(
    os.name == "nt", reason="the IDs are taken from id only off Windows"
)
def test_a_root_caller_is_refused_the_non_root_stage(tmp_path):
    # ./ash and `ash --mode container` take a root caller's ids like any other's and
    # refuse UID 0 and GID 0 for the non-root stage before any build, naming the ci
    # stage (the `ash` script's "The non-root image stage creates a user with UID 0"
    # and run_ash_container.py's; docs/content/docs/cli-reference.md).
    result, calls = _run_script(
        tmp_path,
        _wrapped("Invoke-ASH -SourceDir src -OutputDir out -BuildTarget non-root"),
        preamble=_ROOT_ID_STUB,
    )
    assert result.returncode == REFUSAL_EXIT, result.stdout + result.stderr
    assert calls == [], calls
    message = " ".join(result.stderr.split())
    assert "Invoke-ASH is running as root" in message, message
    assert "Pass -BuildTarget ci" in message, message


@pytest.mark.integration
@pytest.mark.skipif(
    os.name == "nt", reason="the IDs are taken from id only off Windows"
)
def test_a_root_caller_builds_ci_with_its_own_ids(tmp_path):
    # The ci stage runs as root anyway, so a root caller's UID 0 and GID 0 are passed
    # as any caller's ids are, with nothing to warn about.
    result, calls = _invoke(
        tmp_path,
        "Invoke-ASH -SourceDir src -OutputDir out -BuildTarget ci",
        preamble=_ROOT_ID_STUB,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert _uid_gid_args(_build_call(result, calls)) == ["UID=0", "GID=0"]
    assert "Running as root" not in result.stdout + result.stderr


@pytest.mark.integration
def test_an_explicit_container_uid_of_0_is_passed_to_the_ci_stage(tmp_path):
    # An explicit choice is the caller's, and the ci stage takes it; the non-root
    # stage refuses 0 whether it came from id or from the caller.
    result, calls = _invoke(
        tmp_path,
        "Invoke-ASH -SourceDir src -OutputDir out -BuildTarget ci "
        "-ContainerUID 0 -ContainerGID 0",
        preamble=_ROOT_ID_STUB,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert _uid_gid_args(_build_call(result, calls)) == ["UID=0", "GID=0"]


@pytest.mark.integration
@pytest.mark.skipif(os.name == "nt", reason="id(1) and os.getuid are POSIX")
@pytest.mark.skipif(
    os.name != "nt" and os.getuid() == 0,
    reason="as root the non-root build is refused; see the root-caller tests",
)
def test_the_real_id_command_supplies_the_uid_and_gid(tmp_path):
    result, calls = _invoke(tmp_path, "Invoke-ASH -SourceDir src -OutputDir out")
    assert result.returncode == 0, result.stdout + result.stderr
    assert _uid_gid_args(_build_call(result, calls)) == [
        f"UID={os.getuid()}",
        f"GID={os.getgid()}",
    ]


# The CI step that calls Invoke-ASH.


def _ci_powershell_step_entry() -> dict:
    action = yaml.safe_load(RUN_SCAN_TEST.read_text(encoding="utf-8"))
    for step in action["runs"]["steps"]:
        if step.get("name") == "Validate ASH using PowerShell":
            assert step.get("shell", "").split(" ")[0] == "pwsh", step.get("shell")
            return step
    raise AssertionError(f"no 'Validate ASH using PowerShell' step in {RUN_SCAN_TEST}")


def _ci_powershell_step() -> str:
    return _ci_powershell_step_entry()["run"]


def _github_pwsh_arguments(shell: str, script: Path) -> list[str]:
    """The pwsh arguments GitHub's runner starts a ``run:`` block with.

    As in actions/runner's ScriptHandler: ``shell`` is split at its first space into
    the command and an argument format, ``pwsh`` alone takes the format
    ``-command ". '{0}'"``, and ``{0}`` is the script's path.
    """
    command, _, argument_format = shell.partition(" ")
    assert command == "pwsh", shell
    if not argument_format.strip():
        return ["-command", f". '{script}'"]
    return shlex.split(argument_format.replace("{0}", str(script)))


def _github_pwsh_contents(run: str) -> str:
    """``run`` with the two lines GitHub's runner puts around a pwsh script."""
    return (
        "$ErrorActionPreference = 'stop'\n"
        + run
        + "\nif ((Test-Path -LiteralPath variable:\\LASTEXITCODE)) { exit $LASTEXITCODE }\n"
    )


@pytest.mark.integration
def test_the_ci_powershell_step_names_only_declared_parameters(tmp_path):
    # An undeclared name such as -ConfigFile is not an error in PowerShell: it binds to
    # the arguments forwarded to ash. So the step's parameter names are checked against
    # Invoke-ASH's own, with PowerShell's parser and its prefix rule.
    step = tmp_path / "step.ps1"
    step.write_text(_ci_powershell_step(), encoding="utf-8")
    result, _ = _run_script(
        tmp_path,
        "$declared = @((Get-Command Invoke-ASH).Parameters.Values | "
        "ForEach-Object { $_.Name; $_.Aliases })\n"
        f"$text = Get-Content -Raw -LiteralPath '{step.as_posix()}'\n"
        "$ast = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$null, [ref]$null)\n"
        "$calls = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] "
        "-and $n.GetCommandName() -eq 'Invoke-ASH' }, $true))\n"
        "$used = @(foreach ($c in $calls) { $c.CommandElements | "
        "Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] } | "
        "ForEach-Object { $_.ParameterName } })\n"
        "$unknown = @($used | Where-Object { $name = $_; "
        '-not ($declared -contains $name) -and @($declared | Where-Object { $_ -like "$name*" }).Count -ne 1 })\n'
        "Write-Output (ConvertTo-Json -Compress -InputObject @{ calls = $calls.Count; used = $used; unknown = $unknown })\n"
        "exit 0\n",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(result.stdout.strip().splitlines()[-1])
    assert report["calls"] == 2, report
    assert "OCIRunner" in report["used"], report
    assert report["unknown"] == [], (
        f"the CI step passes Invoke-ASH parameters it does not declare: {report['unknown']}"
    )


@pytest.mark.integration
@pytest.mark.parametrize("config_file", ["default", "community"])
def test_the_ci_powershell_step_reaches_the_container_as_written(tmp_path, config_file):
    # The step dot-sources ./utils/ash_helpers.ps1 and scans $PWD, so it runs here in a
    # scratch directory holding a copy of the wrapper and a Dockerfile for it to name,
    # rather than in the checkout, where it would write .ash/ash_output.
    (tmp_path / "utils").mkdir()
    shutil.copy2(HELPERS, tmp_path / "utils" / "ash_helpers.ps1")
    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    env = _clean_env(
        tmp_path,
        OCI_RUNNER="docker",
        ASH_TEST_CONFIG_FILE=config_file,
        ASH_TEST_OS="test",
        ASH_TEST_PLATFORM="test",
    )
    # The way GitHub's pwsh shell runs a `run:` block.
    script = (
        "$ErrorActionPreference = 'stop'\n"
        + _env_guard(env)
        + _stub_runners()
        + _ci_powershell_step()
        + "\nif ((Test-Path -LiteralPath variable:\\LASTEXITCODE)) { exit $LASTEXITCODE }\n"
    )
    result = _pwsh(script, tmp_path, env)
    assert result.returncode == 0, result.stdout + result.stderr
    run = _run_call(result, _calls(tmp_path))
    assert run[0] == "docker", run
    inner = _inner_ash_args(run)
    if config_file == "community":
        assert inner[inner.index("--config") + 1] == ".ash/.ash_community_plugins.yaml"
    else:
        assert "--config" not in inner, inner


@pytest.mark.integration
def test_every_invoke_ash_call_in_the_ci_step_is_wrapped_as_the_help_shows(tmp_path):
    # Left uncaught, a refusal ends the step with PowerShell's 1, not ASH's 3.
    step = tmp_path / "step.ps1"
    step.write_text(_ci_powershell_step(), encoding="utf-8")
    result, _ = _run_script(
        tmp_path,
        f"$text = Get-Content -Raw -LiteralPath '{step.as_posix()}'\n"
        "$ast = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$null, [ref]$null)\n"
        "$calls = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] "
        "-and $n.GetCommandName() -eq 'Invoke-ASH' }, $true))\n"
        "$catches = @(foreach ($c in $calls) {\n"
        "  $p = $c.Parent\n"
        "  while ($p -and -not ($p -is [System.Management.Automation.Language.TryStatementAst] "
        "-and $p.Body.Extent.StartOffset -le $c.Extent.StartOffset "
        "-and $c.Extent.EndOffset -le $p.Body.Extent.EndOffset)) { $p = $p.Parent }\n"
        "  if (-not $p) { 'no try' } else {\n"
        "    (@(foreach ($cc in $p.CatchClauses) {\n"
        "      $kind = if ($cc.CatchTypes.Count) { 'typed: ' } else { '' }\n"
        "      $kind + ((@($cc.Body.Statements) | ForEach-Object { $_.Extent.Text }) -join ' ;; ')\n"
        "    }) -join ' -- ')\n"
        "  }\n"
        "})\n"
        "Write-Output (ConvertTo-Json -Compress -InputObject @{ calls = $calls.Count; catches = $catches })\n"
        "exit 0\n",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(result.stdout.strip().splitlines()[-1])
    assert report["calls"] == 2, report
    expected = _statements(" ;; ".join(_WRAPPED_CATCH))
    assert [_statements(catch) for catch in report["catches"]] == [expected] * 2, report


@pytest.mark.integration
def test_a_refusal_in_the_ci_step_fails_it_with_3(tmp_path):
    # The step is started the way GitHub's runner starts it, from its `shell:` value.
    # With the stock `shell: pwsh` that is `pwsh -command ". '<file>'"`, and pwsh then
    # reports any exit code a script sets, other than 0, as 1.
    (tmp_path / "utils").mkdir()
    shutil.copy2(HELPERS, tmp_path / "utils" / "ash_helpers.ps1")
    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    entry = _ci_powershell_step_entry()
    env = _clean_env(
        tmp_path,
        OCI_RUNNER="no-such-oci-runner",
        ASH_TEST_CONFIG_FILE="default",
        ASH_TEST_OS="test",
        ASH_TEST_PLATFORM="test",
    )
    step = tmp_path / "step.ps1"
    step.write_text(
        _github_pwsh_contents(_env_guard(env) + _stub_runners() + entry["run"]),
        encoding="utf-8",
    )
    result = _pwsh_argv(
        ["-NoProfile", *_github_pwsh_arguments(entry["shell"], step)], tmp_path, env
    )
    assert result.returncode == REFUSAL_EXIT, result.stdout + result.stderr
    assert _unwrapped(result.stderr).count(_unwrapped(_NO_RUNNER_MESSAGE)) == 1, (
        result.stderr
    )
    assert _calls(tmp_path) == []


# -AshArgs: Invoke-ASH handles --force, -q/--quiet, and -c/--no-color itself, as ./ash
# does, and forwards every other argument to ash in the container.


@pytest.mark.integration
def test_a_word_that_merely_contains_dash_c_is_not_no_color(tmp_path):
    # The words were matched as case-insensitive substrings, so --cleanup, --config,
    # --container-uid or a -ConfigFile typo each counted as -c and turned color off.
    result, calls = _invoke(
        tmp_path,
        "Invoke-ASH -NoBuild -SourceDir src -OutputDir out -AshArgs '--cleanup'",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    inner = _inner_ash_args(_run_call(result, calls))
    assert "--cleanup" in inner, inner
    assert "--no-color" not in inner, inner


@pytest.mark.integration
@pytest.mark.parametrize(
    ("word", "build_flag", "ash_flag"),
    [
        ("-q", "-q", "--quiet"),
        ("--quiet", "-q", "--quiet"),
        ("-c", None, "--no-color"),
        ("--no-color", None, "--no-color"),
        ("--force", "--no-cache", None),
    ],
)
def test_wrapper_flags_are_handled_like_ash(tmp_path, word, build_flag, ash_flag):
    # ash in the container has no -q and reads -c as --config, so the short forms
    # must not reach it; ./ash consumes all five words the same way.
    result, calls = _invoke(
        tmp_path, f"Invoke-ASH -SourceDir src -OutputDir out -AshArgs '{word}'"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    build, inner = _build_call(result, calls), _inner_ash_args(_run_call(result, calls))
    if build_flag is not None:
        assert build_flag in build, build
    if ash_flag is not None:
        assert inner.count(ash_flag) == 1, inner
    if word != ash_flag:
        assert word not in inner, inner


@pytest.mark.integration
def test_wrapper_flags_are_matched_case_sensitively(tmp_path):
    # ./ash compares exactly; -Q and --FORCE are not its flags and go to ash as given.
    result, calls = _invoke(
        tmp_path,
        "Invoke-ASH -SourceDir src -OutputDir out -AshArgs '-Q --FORCE -C --Quiet'",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    build, inner = _build_call(result, calls), _inner_ash_args(_run_call(result, calls))
    assert inner == [*SANDBOX_OFF, "-Q", "--FORCE", "-C", "--Quiet"], inner
    assert "--no-cache" not in build and "-q" not in build, build


@pytest.mark.integration
def test_other_words_are_forwarded_in_order(tmp_path):
    result, calls = _invoke(
        tmp_path,
        "Invoke-ASH -NoBuild -SourceDir src -OutputDir out "
        "-AshArgs '--scanners bandit --config-overrides \"reporters.text.enabled=false\"'",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    inner = _inner_ash_args(_run_call(result, calls))
    assert inner[-4:] == [
        "--scanners",
        "bandit",
        "--config-overrides",
        "reporters.text.enabled=false",
    ], inner


@pytest.mark.integration
@pytest.mark.parametrize(
    ("ash_args", "expected"),
    [
        # A quoted value holding -q and -c is one argument, not two wrapper flags.
        (
            '--config-overrides "scanners.bandit.options.additional_arguments=-q -c x"',
            [
                "--config-overrides",
                "scanners.bandit.options.additional_arguments=-q -c x",
            ],
        ),
        ('--config-overrides "a=x  y"', ["--config-overrides", "a=x  y"]),
        ('--config "my  dir/cfg.yaml"', ["--config", "my  dir/cfg.yaml"]),
        ("--config-overrides 'it''s=1'", ["--config-overrides", "it's=1"]),
    ],
)
def test_quoted_values_in_ash_args_are_kept_whole(tmp_path, ash_args, expected):
    quoted = ash_args.replace("'", "''")
    result, calls = _invoke(
        tmp_path,
        f"Invoke-ASH -NoBuild -SourceDir src -OutputDir out -AshArgs '{quoted}'",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert _inner_ash_args(_run_call(result, calls)) == [*SANDBOX_OFF, *expected]


@pytest.mark.integration
def test_arguments_after_the_parameters_are_forwarded_whole(tmp_path):
    result, calls = _invoke(
        tmp_path,
        "Invoke-ASH -NoBuild -SourceDir src -OutputDir out --config-overrides 'a=x  y' -q",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    inner = _inner_ash_args(_run_call(result, calls))
    assert inner == [*SANDBOX_OFF, "--quiet", "--config-overrides", "a=x  y"], inner


@pytest.mark.integration
def test_a_command_in_ash_args_is_refused_not_run(tmp_path):
    # The words are passed as arguments, not pasted into a string for
    # Invoke-Expression, which would run anything after a ; or a |.
    result, calls = _run_script(
        tmp_path,
        "try {\n"
        "  Invoke-ASH -NoBuild -SourceDir src -OutputDir out -AshArgs '--verbose; Write-Host INJECTED'\n"
        "} catch {\n"
        '  Write-Host "refused: $($_.Exception.Message)"\n'
        "}\n"
        "exit 0\n",
    )
    assert "INJECTED" not in result.stdout.replace("Write-Host INJECTED", ""), (
        result.stdout + result.stderr
    )
    assert "refused: -AshArgs holds ';'" in result.stdout, result.stdout + result.stderr
    assert calls == []


# Values reach the runner as given. No command is a string run through
# Invoke-Expression, which parses its input as PowerShell: a path or a value holding
# $(...), or a typographic quote that ends a single-quoted string, would run code.

# PowerShell reads each of these as a single quote, so a value quoted with ASCII
# quotes for Invoke-Expression could be closed early with one of them.
_UNICODE_SINGLE_QUOTES = ["‘", "’", "‚", "‛"]
# Prints a line that is exactly PWNED only if it runs; an error message quoting the
# text shows "Write-Host PWNED", never the bare word on a line of its own.
_PAYLOAD_OUTPUT = "PWNED"


def _payload(quote: str) -> str:
    return f"x{quote}; Write-Host {_PAYLOAD_OUTPUT}; {quote}"


def _ran_code(result) -> bool:
    return any(
        line.strip() == _PAYLOAD_OUTPUT
        for line in (result.stdout + result.stderr).splitlines()
    )


def _ps_double_quoted(value: str) -> str:
    """``value`` as a PowerShell double-quoted literal in the test script."""
    escaped = value.replace("`", "``").replace("$", "`$").replace('"', '`"')
    return f'"{escaped}"'


def _help_ash_args_example() -> str:
    text = HELPERS.read_text(encoding="utf-8")
    match = re.search(r"-AshArgs '([^']+)'`", text)
    assert match, "the help no longer shows an -AshArgs example"
    return match.group(1)


@pytest.mark.integration
def test_the_helps_own_ash_args_example_passes_its_comma_list_whole(tmp_path):
    example = _help_ash_args_example()
    result, calls = _invoke(
        tmp_path,
        f"Invoke-ASH -NoBuild -SourceDir src -OutputDir out -AshArgs '{example}'",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert _inner_ash_args(_run_call(result, calls)) == [
        *SANDBOX_OFF,
        *example.split(" "),
    ], example


@pytest.mark.integration
@pytest.mark.parametrize(
    ("ash_args", "expected"),
    [
        ("--output-formats sarif,html", ["--output-formats", "sarif,html"]),
        ("--config-overrides k=[a,b]", ["--config-overrides", "k=[a,b]"]),
        ('--x="a b"c', ["--x=a bc"]),
    ],
)
def test_adjacent_pieces_in_ash_args_are_one_argument(tmp_path, ash_args, expected):
    quoted = ash_args.replace("'", "''")
    result, calls = _invoke(
        tmp_path,
        f"Invoke-ASH -NoBuild -SourceDir src -OutputDir out -AshArgs '{quoted}'",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert _inner_ash_args(_run_call(result, calls)) == [*SANDBOX_OFF, *expected]


@pytest.mark.integration
def test_a_comma_list_after_the_parameters_stays_one_argument(tmp_path):
    # PowerShell reads `sarif,html` there as a two-element array before Invoke-ASH
    # sees it.
    result, calls = _invoke(
        tmp_path,
        "Invoke-ASH -NoBuild -SourceDir src -OutputDir out --output-formats sarif,html",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert _inner_ash_args(_run_call(result, calls)) == [
        *SANDBOX_OFF,
        "--output-formats",
        "sarif,html",
    ]


@pytest.mark.integration
def test_a_quoted_dash_c_after_the_parameters_is_no_color(tmp_path):
    # Bare, -c is an ambiguous prefix of -Config, -ContainerUID and -ContainerGID, so
    # PowerShell refuses it; quoted, it is an argument.
    result, calls = _invoke(
        tmp_path, "Invoke-ASH -NoBuild -SourceDir src -OutputDir out '-c'"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert _inner_ash_args(_run_call(result, calls)) == [*SANDBOX_OFF, "--no-color"]


@pytest.mark.integration
@pytest.mark.parametrize(
    "quote", _UNICODE_SINGLE_QUOTES, ids=lambda q: f"U+{ord(q):04X}"
)
@pytest.mark.parametrize("channel", ["Config", "Scanners", "after-parameters"])
def test_a_typographic_quote_in_a_value_never_runs_code(tmp_path, quote, channel):
    value = _payload(quote)
    literal = _ps_double_quoted(value)
    flag = {
        "Config": f"-Config {literal}",
        "Scanners": f"-Scanners {literal}",
        "after-parameters": literal,
    }[channel]
    result, calls = _invoke(
        tmp_path, f"Invoke-ASH -NoBuild -SourceDir src -OutputDir out {flag}"
    )
    assert not _ran_code(result), result.stdout + result.stderr
    assert result.returncode == 0, result.stdout + result.stderr
    assert value in _inner_ash_args(_run_call(result, calls))


@pytest.mark.integration
@pytest.mark.parametrize(
    "quote", _UNICODE_SINGLE_QUOTES, ids=lambda q: f"U+{ord(q):04X}"
)
def test_a_typographic_quote_in_ash_args_never_runs_code(tmp_path, quote):
    # Inside ASCII double quotes in -AshArgs the typographic quote is an ordinary
    # character, so the value has to arrive whole and nothing in it may run.
    value = _payload(quote)
    ash_args = _ps_double_quoted(f'--config-overrides "{value}"')
    result, calls = _invoke(
        tmp_path,
        f"Invoke-ASH -NoBuild -SourceDir src -OutputDir out -AshArgs {ash_args}",
    )
    assert not _ran_code(result), result.stdout + result.stderr
    assert result.returncode == 0, result.stdout + result.stderr
    assert _inner_ash_args(_run_call(result, calls)) == [
        *SANDBOX_OFF,
        "--config-overrides",
        value,
    ]


@pytest.mark.integration
def test_a_typographic_apostrophe_in_a_value_arrives_intact(tmp_path):
    name = "O’Neil"
    config = _ps_double_quoted(name + ".yaml")
    scanner = _ps_double_quoted(name)
    ash_args = _ps_double_quoted('--config-overrides "owner=' + name + '"')
    result, calls = _invoke(
        tmp_path,
        "Invoke-ASH -NoBuild -SourceDir src -OutputDir out "
        f"-Config {config} -Scanners {scanner} -AshArgs {ash_args} {scanner}",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert _inner_ash_args(_run_call(result, calls)) == [
        *SANDBOX_OFF,
        "--config",
        f"{name}.yaml",
        "--scanners",
        name,
        "--config-overrides",
        f"owner={name}",
        name,
    ]


@pytest.mark.integration
def test_an_unquoted_typographic_apostrophe_in_ash_args_is_refused_with_a_hint(
    tmp_path,
):
    # PowerShell reads it as an opening single quote, so the rest of -AshArgs is an
    # unterminated string.
    result, calls = _run_script(
        tmp_path,
        "try {\n"
        "  Invoke-ASH -NoBuild -SourceDir src -OutputDir out "
        f"-AshArgs {_ps_double_quoted('--config-overrides owner=O' + chr(0x2019) + 'Neil')}\n"
        "} catch {\n"
        '  Write-Host "refused: $($_.Exception.Message)"\n'
        "}\n"
        "exit 0\n",
    )
    assert "refused:" in result.stdout, result.stdout + result.stderr
    assert "double quotes" in result.stdout, result.stdout
    assert calls == []


@pytest.mark.integration
def test_a_refused_variable_is_named_with_its_dollar_sign(tmp_path):
    result, calls = _run_script(
        tmp_path,
        "try {\n"
        "  Invoke-ASH -NoBuild -SourceDir src -OutputDir out -AshArgs '--x $y'\n"
        "} catch {\n"
        '  Write-Host "refused: $($_.Exception.Message)"\n'
        "}\n"
        "exit 0\n",
    )
    assert "refused: -AshArgs holds '$y'" in result.stdout, (
        result.stdout + result.stderr
    )
    # Double quotes would not pass it as typed: PowerShell expands "$y" too.
    assert "Put it in single quotes" in result.stdout, result.stdout
    assert calls == []


#: -AshArgs elements that PowerShell's own parser reads as expandable strings, though
#: PSParser.Tokenize types each as a plain argument or a string: on a command line,
#: PowerShell would put a variable's value or a command's output there. They reach
#: ASH as the text typed, a different value from the one PowerShell would make of it.
_EXPANDABLE_ASH_ARGS = {
    "variable-after-text": "x$a",
    "subexpression-after-text": "a$(y)",
    "variable-before-a-dash": "$a-b",
    "variable-before-a-slash": "$a/b",
    "environment-variable-after-text": "x$env:HOME",
    "variable-before-a-format-character": "$a" + chr(0x202E) + "b",
    "subexpression-after-a-format-character": chr(0x202E) + "$(y)",
    "double-quoted-variable": '"dq$a"',
}


@pytest.mark.integration
@pytest.mark.parametrize("element", sorted(_EXPANDABLE_ASH_ARGS))
def test_an_ash_args_element_powershell_would_expand_is_refused(tmp_path, element):
    """Refused with 3, as a bare $variable is, and named with its escapes."""
    value = _EXPANDABLE_ASH_ARGS[element]
    result, calls = _run_script(
        tmp_path,
        _wrapped(f"{_RUN} -AshArgs $env:ASH_PROBE_VALUE"),
        ASH_PROBE_VALUE=f"--x {value}",
    )
    output = result.stdout + result.stderr
    assert result.returncode == REFUSAL_EXIT, output
    shown = value.replace(chr(0x202E), "\\" + "u202E")
    assert _unwrapped(f"-AshArgs holds '{shown}'") in _unwrapped(output), output
    assert _unwrapped("Put it in single quotes") in _unwrapped(output), output
    assert chr(0x202E) not in output, repr(output)
    assert calls == [], calls


#: The same text single-quoted, which PowerShell never expands, and what ASH gets:
#: exactly the characters typed. A dollar sign escaped with a backtick inside double
#: quotes is not expanded either.
_TYPED_ASH_ARGS = {
    **{
        name: (
            "--x '" + value.strip('"') + "'",
            ["--x", value.strip('"')],
        )
        for name, value in _EXPANDABLE_ASH_ARGS.items()
    },
    "config-override-single-quoted": (
        "--config-overrides 'a.b=$x'",
        ["--config-overrides", "a.b=$x"],
    ),
    "escaped-dollar-double-quoted": ('--x "a`$b"', ["--x", "a$b"]),
}


@pytest.mark.integration
@pytest.mark.parametrize("element", sorted(_TYPED_ASH_ARGS))
def test_a_single_quoted_dollar_sign_reaches_ash_as_typed(tmp_path, element):
    ash_args, expected = _TYPED_ASH_ARGS[element]
    result, calls = _run_script(
        tmp_path,
        f"$rc = {_RUN} -AshArgs $env:ASH_PROBE_VALUE\nexit [int]$LASTEXITCODE\n",
        ASH_PROBE_VALUE=ash_args,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert _inner_ash_args(_run_call(result, calls)) == [*SANDBOX_OFF, *expected]


@pytest.mark.integration
@pytest.mark.parametrize(
    "where", ["SourceDir", "OutputDir", "AshImageName", "ASH_IMAGE_NAME"]
)
def test_dollar_paren_in_a_path_or_the_image_name_never_runs(tmp_path, where):
    payload = f"s$(Write-Host {_PAYLOAD_OUTPUT})"
    env = {}
    source, output, extra = "src", "out", ""
    if where == "SourceDir":
        (tmp_path / payload).mkdir()
        source = _ps_double_quoted(payload)
    elif where == "OutputDir":
        output = _ps_double_quoted(payload)
    elif where == "AshImageName":
        extra = f"-AshImageName {_ps_double_quoted(payload + ':tag')}"
    else:
        env["ASH_IMAGE_NAME"] = payload + ":tag"
    result, calls = _invoke(
        tmp_path,
        f"Invoke-ASH -SourceDir {source} -OutputDir {output} {extra}",
        **env,
    )
    assert not _ran_code(result), result.stdout + result.stderr
    if where in ("AshImageName", "ASH_IMAGE_NAME"):
        # The payload holds a space, '$' and parentheses, none of which an image name
        # may hold, so it is refused before anything is built or run. Either way its
        # $(...) never runs.
        assert result.returncode == 1, result.stdout + result.stderr
        assert "orholdsacharacterotherthan" in _unwrapped(result.stderr), result.stderr
        assert calls == []
        return
    assert result.returncode == 0, result.stdout + result.stderr
    run = _run_call(result, calls)
    mounts = [run[i + 1] for i, arg in enumerate(run[:-1]) if arg == "--mount"]
    assert any(payload in mount for mount in mounts), mounts
