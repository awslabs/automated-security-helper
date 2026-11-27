"""The environment the tests start pwsh in, and the recording runner stand-ins.

Shared by the tests that run ``utils/ash_helpers.ps1``, so they cannot drift apart
on what they keep from the developer's environment, on how a runner is stood in for,
or on when a missing ``pwsh`` skips a test and when it fails one.

The stand-ins are PowerShell functions named for each OCI runner. ``Get-Command``
finds a function before any program on PATH, so a stand-in is what ``Invoke-ASH``
resolves on every platform, and it records the arguments the wrapper passed. No test
can reach a real runner: every runner name is a function, the script refuses to start
if one is not, and the first PATH entry holds programs of the same names that fail the
test.
"""

import json
import os
import shutil
import subprocess  # nosec B404 - running pwsh against the wrapper is the point of these tests
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS = REPO_ROOT / "utils" / "ash_helpers.ps1"
PWSH = shutil.which("pwsh")

RUNNERS = ("finch", "docker", "nerdctl", "podman")
GUARD_EXIT = 97
GUARD_MESSAGE = "REAL-RUNNER-GUARD"
RUNNER_VARIABLES = ("OCI_RUNNER", "ASH_OCI_RUNNER", "OCI_RUNNER_WRAPPER")
SCRIPT_RUN = ("-NoProfile", "-NonInteractive", "-File")


def require_pwsh(in_ci: bool) -> None:
    """Fail in CI, skip on a developer machine, when ``pwsh`` is not on PATH."""
    if PWSH is None:
        if in_ci:
            pytest.fail("pwsh is not on PATH; CI runners must run these tests")
        pytest.skip("pwsh is not on PATH (local run only; CI fails instead)")


#: Variables that make a shell read one of the developer's startup files. pwsh can
#: itself be a shell script (nix installs it as a bash wrapper), and a non-interactive
#: bash runs $BASH_ENV before anything else, so a startup file there could export
#: OCI_RUNNER again after a test removed it. ENV is read by sh and ksh, and zsh reads
#: $ZDOTDIR/.zshenv.
SHELL_STARTUP_VARIABLES = ("BASH_ENV", "ENV", "ZDOTDIR")

#: pwsh's telemetry and update check, both off.
QUIET_PWSH = {"POWERSHELL_TELEMETRY_OPTOUT": "1", "POWERSHELL_UPDATECHECK": "Off"}


def inherited_env(*drop: str) -> dict[str, str]:
    """``os.environ`` without the shell startup variables or the names in ``drop``."""
    excluded = {*SHELL_STARTUP_VARIABLES, *drop}
    return {name: value for name, value in os.environ.items() if name not in excluded}


def scratch_home(tmp_path: Path) -> dict[str, str]:
    """A HOME and XDG directories of the test's own, and ``QUIET_PWSH``.

    pwsh writes caches under them. Not for a test that runs a real OCI runner, which
    reads its configuration and (for podman) its image store from the same places.
    """
    home = tmp_path / "pwsh-home"
    for sub in ("", ".cache", ".local/share", ".config"):
        (home / sub).mkdir(parents=True, exist_ok=True)
    # pwsh on Windows derives $HOME from the user profile, not from HOME:
    # USERPROFILE first, with HOMEDRIVE+HOMEPATH as the older pair. All of
    # them point at the scratch home, so the tests' pwsh reads and writes the
    # same directory on every platform.
    drive, tail = os.path.splitdrive(str(home))
    return {
        "HOME": str(home),
        "USERPROFILE": str(home),
        "HOMEDRIVE": drive,
        "HOMEPATH": tail,
        "XDG_CACHE_HOME": str(home / ".cache"),
        "XDG_DATA_HOME": str(home / ".local" / "share"),
        "XDG_CONFIG_HOME": str(home / ".config"),
        **QUIET_PWSH,
    }


def stub_runners(build_exit: int = 0) -> str:
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
        f'Write-Host "{GUARD_MESSAGE}: $n is not the stand-in"; exit {GUARD_EXIT} }} }}'
    )
    return "\n".join(lines) + "\n"


def guard_dir(tmp_path: Path) -> Path:
    """Programs named like the runners that fail the test, for the front of PATH."""
    guard = tmp_path / "runner-guard"
    guard.mkdir(exist_ok=True)
    for name in RUNNERS:
        if os.name == "nt":
            (guard / f"{name}.cmd").write_text(
                f"@echo {GUARD_MESSAGE}: {name} %* 1>&2\r\n@exit /b {GUARD_EXIT}\r\n",
                encoding="utf-8",
            )
        else:
            program = guard / name
            program.write_text(
                # To stderr, which `$rc = Invoke-ASH ...` does not capture.
                f"#!/bin/sh\necho '{GUARD_MESSAGE}: {name}' \"$@\" >&2\nexit {GUARD_EXIT}\n",
                encoding="utf-8",
            )
            program.chmod(0o755)
    return guard


def clean_env(tmp_path: Path, **overrides: str) -> dict[str, str]:
    env = inherited_env(*RUNNER_VARIABLES, "ASH_CONFIG")
    guard = guard_dir(tmp_path)
    env["PATH"] = os.pathsep.join([str(guard), env.get("PATH", "")])
    for name in RUNNERS:
        found = shutil.which(name, path=env["PATH"])
        if found is None or Path(found).parent != guard:
            pytest.fail(f"{name} on the test PATH resolves to {found}, not the guard")
    env["RUNNER_LOG"] = str(tmp_path / "runner.log")
    env.update(scratch_home(tmp_path))
    env.update(overrides)
    return env


def ps_single_quoted(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def env_guard(env: dict[str, str]) -> str:
    """PowerShell that stops the script unless each runner variable is what the test
    passed in ``env``, or is unset when the test passed none."""
    lines = []
    for name in RUNNER_VARIABLES:
        expected = env.get(name)
        if expected:
            wrong = f"$env:{name} -cne {ps_single_quoted(expected)}"
        else:
            wrong = f"-not [string]::IsNullOrEmpty($env:{name})"
        lines.append(
            f"if ({wrong}) {{ Write-Host "
            f'"{GUARD_MESSAGE}: {name} is not what the test set"; exit {GUARD_EXIT} }}'
        )
    return "\n".join(lines) + "\n"


def pwsh(
    script: str,
    cwd: Path,
    env: dict[str, str],
    launch: tuple[str, ...] = SCRIPT_RUN,
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
    return pwsh_argv([*launch, target], cwd, env, stdin=stdin, interpreter=interpreter)


def pwsh_argv(
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
    if GUARD_MESSAGE in result.stdout + result.stderr:
        pytest.fail(
            "a real OCI runner could have been run (the runner guard stopped it):\n"
            + result.stdout
            + result.stderr
        )
    return result


def runner_calls(tmp_path: Path) -> list[list[str]]:
    log = tmp_path / "runner.log"
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


def run_script(
    tmp_path: Path,
    body: str,
    preamble: str = "",
    build_exit: int = 0,
    launch: tuple[str, ...] = SCRIPT_RUN,
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
    run_env = clean_env(tmp_path, **env)
    script = (
        "$ErrorActionPreference = 'Stop'\n"
        + env_preamble
        + env_guard(run_env)
        + stub_runners(build_exit)
        + preamble
        + f". '{HELPERS.as_posix()}'\n"
        + body
    )
    result = pwsh(
        script,
        tmp_path,
        run_env,
        launch=launch,
        stdin=stdin,
        interpreter=interpreter,
    )
    return result, runner_calls(tmp_path)


def invoke(
    tmp_path: Path, invocation: str, preamble: str = "", **env: str
) -> tuple[subprocess.CompletedProcess, list[list[str]]]:
    return run_script(
        tmp_path,
        f"$rc = {invocation}\nexit [int]$LASTEXITCODE\n",
        preamble=preamble,
        **env,
    )


def run_call(result, calls) -> list[str]:
    runs = [call for call in calls if len(call) > 1 and call[1] == "run"]
    assert len(runs) == 1, (calls, result.stdout, result.stderr)
    return runs[0]


def build_call(result, calls) -> list[str]:
    builds = [call for call in calls if len(call) > 1 and call[1] == "build"]
    assert len(builds) == 1, (calls, result.stdout, result.stderr)
    return builds[0]


def run_env(run_call_argv: list[str]) -> dict[str, str]:
    """The ``-e NAME=value`` pairs before the image name (``ashx``, the image's
    command, follows it)."""
    before_image = run_call_argv[: run_call_argv.index("ashx")]
    pairs = [
        before_image[i + 1]
        for i, arg in enumerate(before_image[:-1])
        if arg == "-e" and "=" in before_image[i + 1]
    ]
    return dict(pair.split("=", 1) for pair in pairs)
