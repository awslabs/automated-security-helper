# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``Invoke-ASH`` refuses a root build, a GID of 0 and a config chain it cannot mount.

utils/ash_helpers.ps1, matching ``ash --mode container`` and ``./ash``:

- Run as root (``id -u`` is 0) with the default ``-BuildTarget non-root`` and no
  ``-ContainerUID``, it refuses to build and names ``-BuildTarget ci``, the opt-in
  for the image that runs as root. ``-ContainerUID`` or ``-ContainerGID`` of 0 is
  refused the same way, and so is one that is not a number. An unprivileged caller
  builds as before.
- The file ``ASH_CONFIG`` names, when it is outside the source directory, is mounted
  on its own, without the files it extends, so one with an ``extends`` entry is
  refused, and so is one that names no file. ``-Config`` is passed to the scan as
  written and is not checked, so none of that applies to it.
- Every refusal sets ``$LASTEXITCODE`` to its code (3, or 1 without a runner) and
  throws, which test_powershell_wrapper_refusals_and_values.py checks in the source of
  each one; nothing in the helpers calls ``exit``. A script that dot-sources them can
  catch the error and carry on, and a session started with ``-NoExit`` stays open.
  A CI step that needs the code wraps the call in the one form the help and docs
  give (``CATCH`` below) and runs under ``shell: pwsh -File {0}``; uncaught,
  ``pwsh -File`` exits 1, as PowerShell does for any uncaught error. Any other error
  Invoke-ASH raises leaves ``$LASTEXITCODE`` non-zero too, so that wrapper cannot
  turn it into exit 0.

The text tests run everywhere. The ones that run the script need ``pwsh``: they
skip on a developer machine without it and fail in CI, as
test_powershell_default_runner_discovery.py does.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess  # nosec B404 - running pwsh against the wrapper is the point
from pathlib import Path
from typing import Optional

import pytest

from tests.utils.host_ids import fixed_id_dir
from tests.utils.pwsh_env import inherited_env, scratch_home

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS = REPO_ROOT / "utils" / "ash_helpers.ps1"
PWSH = shutil.which("pwsh")
_IN_CI = "true" in (os.environ.get("CI"), os.environ.get("GITHUB_ACTIONS"))


def _text() -> str:
    return HELPERS.read_text(encoding="utf-8")


def _code_lines() -> list:
    """The helpers' lines without comments and comment-based help."""
    lines, in_help = [], False
    for raw in _text().splitlines():
        line = raw.strip()
        if line.startswith("<#"):
            in_help = True
        if in_help:
            in_help = not line.endswith("#>")
            continue
        if line and not line.startswith("#"):
            lines.append(line)
    return lines


def test_nothing_in_the_helpers_exits():
    """``exit`` in a dot-sourced function ends the caller's whole script."""
    exits = [line for line in _code_lines() if re.search(r"(^|[;{]\s*)exit\b", line)]

    assert exits == []


#: The one catch block every mention of the CI form uses: it prints the error record
#: once, and exits with the refusal's code, or 1 for an error raised before
#: Invoke-ASH sets one.
CATCH = (
    "catch { Write-Error -ErrorRecord $_ -ErrorAction Continue; "
    "exit $(if ($LASTEXITCODE) { $LASTEXITCODE } else { 1 }) }"
)
#: Where the form is written for people: the help, the CLI reference, the CHANGELOG.
DOCUMENTED = (
    HELPERS,
    REPO_ROOT / "docs" / "content" / "docs" / "cli-reference.md",
    REPO_ROOT / "CHANGELOG.md",
)
SCAN_TEST_ACTION = REPO_ROOT / ".github" / "actions" / "run-scan-test" / "action.yml"


def _workflow_steps_calling_invoke_ash() -> list:
    """Every workflow and action step whose script calls Invoke-ASH."""
    import yaml

    found = []
    for path in sorted((REPO_ROOT / ".github").rglob("*.y*ml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            continue
        groups = [(data.get("runs") or {}).get("steps") or []]
        groups += [
            job.get("steps") or []
            for job in (data.get("jobs") or {}).values()
            if isinstance(job, dict)
        ]
        for steps in groups:
            for step in steps:
                run = str(step.get("run", ""))
                if any(
                    line.strip().startswith("Invoke-ASH ") for line in run.splitlines()
                ):
                    found.append((path, step))
    return found


def test_the_documented_catch_is_the_one_form():
    for path in DOCUMENTED:
        text = path.read_text(encoding="utf-8")
        assert CATCH in text, path
        assert "[Console]::Error.WriteLine($_.Exception.Message)" not in text, path


def test_every_step_calling_invoke_ash_wraps_it_under_pwsh_file():
    """``shell: pwsh`` runs ``pwsh -command ". '<script>'"``, which reports every
    non-zero ``exit`` as 1, so a refusal's 3 needs ``pwsh -File {0}``. That custom
    shell drops what the built-in one adds, so the step sets Stop itself and ends with
    the scan's own code."""
    steps = _workflow_steps_calling_invoke_ash()

    assert [path for path, _ in steps] == [SCAN_TEST_ACTION]
    for _, step in steps:
        lines = [line.strip() for line in step["run"].splitlines()]
        calls = [i for i, line in enumerate(lines) if line.startswith("Invoke-ASH ")]
        opened = lines.index("try {")
        caught = lines.index("} " + CATCH)

        assert step["shell"] == "pwsh -File {0}"
        assert lines[0] == "$ErrorActionPreference = 'Stop'"
        assert len(calls) == 2
        assert all(opened < i < caught for i in calls)
        assert lines[-1] == (
            "if ((Test-Path -LiteralPath variable:\\LASTEXITCODE)) { exit $LASTEXITCODE }"
        )


def test_the_session_detection_is_gone():
    """Exit or throw used to depend on the call stack and the command line."""
    text = _text()

    for name in ("Test-AshInteractiveSession", "Get-PSCallStack", "GetCommandLineArgs"):
        assert name not in text


def test_the_root_refusal_names_the_opt_in():
    text = _text()

    assert "id -u" in text
    assert re.search(r"Pass -BuildTarget ci to build the image that runs as root", text)


@pytest.fixture
def pwsh():
    if PWSH is None:
        if _IN_CI:
            pytest.fail("pwsh is not on PATH; CI runners must run this test")
        pytest.skip("pwsh is not on PATH (local run only; CI fails instead)")
    return PWSH


def _pwsh_script(
    pwsh,
    tmp_path: Path,
    body: str,
    *,
    file: bool = True,
    flags: tuple = ("-NonInteractive",),
    stdin: Optional[str] = None,
):
    """Run *body* with the helpers dot-sourced, as a script file or a -Command string.

    pwsh gets a HOME and XDG directories of its own under *tmp_path*
    (``scratch_home``): it writes its startup cache and its telemetry id under them,
    and the test's HOME must hold no tool's files when the test ends
    (tests/unit/conftest.py, ``_unit_tool_guard``)."""
    script = f". '{HELPERS.as_posix()}'\n{body}\n"
    if file:
        path = tmp_path / "caller.ps1"
        path.write_text(script, encoding="utf-8")
        command = [pwsh, "-NoProfile", *flags, "-File", str(path)]
    else:
        command = [pwsh, "-NoProfile", *flags, "-Command", script]
    env = inherited_env("ASH_CONFIG")
    env.update(scratch_home(tmp_path))
    env["NO_COLOR"] = "1"
    return subprocess.run(  # nosec B603 - fixed interpreter, script built here
        command,
        cwd=tmp_path,
        env=env,
        input=stdin,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
        check=False,
    )


#: A call Invoke-ASH refuses with exit 3 before it looks for a runner: --mount cannot
#: carry a comma.
REFUSED = (
    "Invoke-ASH -OCIRunner absent-runner-name -NoBuild -SourceDir src -OutputDir 'a,b'"
)
REFUSAL_TEXT = "cannot be handed to the container runner"


def _wrapped(call: str) -> str:
    """*call* in the form the help and docs/content/docs/cli-reference.md give a CI
    step that needs the code."""
    return f"try {{ {call} }} {CATCH}"


@pytest.fixture
def src(tmp_path) -> Path:
    path = tmp_path / "src"
    path.mkdir()
    return path


def test_a_dot_sourcing_script_catches_a_refusal_and_carries_on(pwsh, src, tmp_path):
    """The refusal throws, with $LASTEXITCODE set, and does not end the caller."""
    result = _pwsh_script(
        pwsh,
        tmp_path,
        "$ErrorActionPreference = 'Stop'\n"
        f'try {{ {REFUSED} }} catch {{ "caught $LASTEXITCODE" }}\n'
        "'carried on'\n"
        "exit 0",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.split() == ["caught", "3", "carried", "on"], result.stdout


def test_the_wrapped_call_exits_with_the_refusal_code(pwsh, src, tmp_path):
    """``pwsh -File`` with the documented wrapper, under ``Stop`` as on GitHub."""
    result = _pwsh_script(
        pwsh,
        tmp_path,
        "$ErrorActionPreference = 'Stop'\n" + _wrapped(REFUSED),
    )

    assert result.returncode == 3, result.stdout + result.stderr
    assert result.stderr.count(REFUSAL_TEXT) == 1, result.stderr


def test_an_uncaught_refusal_under_file_exits_1(pwsh, src, tmp_path):
    """PowerShell's exit code for any uncaught error; documented, not ASH's choice."""
    result = _pwsh_script(pwsh, tmp_path, f"{REFUSED}\n'after'")

    assert result.returncode == 1, result.stdout + result.stderr
    assert "after" not in result.stdout
    assert " ".join(result.stderr.split()).count(REFUSAL_TEXT) == 1, result.stderr


def test_a_no_exit_session_stays_open_after_a_refusal(pwsh, src, tmp_path):
    """The session reads the next commands from stdin after the refusal."""
    result = _pwsh_script(
        pwsh,
        tmp_path,
        REFUSED,
        file=False,
        flags=("-NoExit",),
        stdin='Write-Output "alive $LASTEXITCODE"\nexit 7\n',
    )

    assert result.returncode == 7, result.stdout + result.stderr
    assert "alive 3" in result.stdout


def test_another_error_leaves_the_code_non_zero(pwsh, src, tmp_path):
    """So ``catch { exit $LASTEXITCODE }`` cannot exit 0 after a failure that is not
    a refusal: here the output directory cannot be created under a file."""
    (tmp_path / "blocker").write_text("", encoding="utf-8")
    result = _pwsh_script(
        pwsh,
        tmp_path,
        "$ErrorActionPreference = 'Stop'\n"
        "$global:LASTEXITCODE = 0\n"
        "try { Invoke-ASH -OCIRunner absent-runner-name -NoBuild -SourceDir src "
        '-OutputDir blocker/out } catch { "code $LASTEXITCODE" }',
    )

    assert result.stdout.split() == ["code", "1"], result.stdout + result.stderr


@pytest.mark.skipif(
    os.name == "nt", reason="the stand-in runner is a POSIX shell script"
)
def test_another_error_in_the_run_leaves_the_code_non_zero(pwsh, src, tmp_path):
    """The same once the run has started: ``id -u`` leaves $LASTEXITCODE at 0, then a
    malformed ASH_BASE_OCI_LAYOUT stops the build before any runner command.

    Invoke-ASH keeps only the runner's name and runs it from PATH, so the stand-in
    goes first on PATH: no real runner is reached even if that ever changes."""
    runner = tmp_path / "bin" / "docker"
    runner.parent.mkdir()
    runner.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    runner.chmod(0o755)
    result = _pwsh_script(
        pwsh,
        tmp_path,
        "$ErrorActionPreference = 'Stop'\n"
        f"$env:PATH = '{runner.parent.as_posix()}' + "
        "[System.IO.Path]::PathSeparator + $env:PATH\n"
        "$env:ASH_BASE_OCI_LAYOUT = 'not-a-layout'\n"
        "try { Invoke-ASH -OCIRunner docker -BuildTarget ci "
        '-SourceDir src -OutputDir out } catch { "code $LASTEXITCODE" }',
    )

    # The build announces itself first.
    assert result.stdout.splitlines()[-1:] == ["code 1"], result.stdout + result.stderr


def test_a_refusal_is_printed_once(pwsh, src, tmp_path):
    """Uncaught, PowerShell prints the error; Invoke-ASH does not print it as well."""
    result = _pwsh_script(
        pwsh,
        tmp_path,
        "Invoke-ASH -OCIRunner absent-runner-name -NoBuild -SourceDir src -OutputDir out",
        file=False,
    )

    output = result.stdout + result.stderr
    assert result.returncode == 1, output
    assert output.count("Unable to resolve an OCI_RUNNER") == 1, output


@pytest.fixture
def host(tmp_path, pwsh):
    """A PATH with a recording docker and an ``id`` that reports a chosen UID."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "docker-args.txt"
    runner = bin_dir / "docker"
    runner.write_text(
        f"#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done >> '{log}'\n",
        encoding="utf-8",
    )
    runner.chmod(0o755)
    (tmp_path / "src").mkdir()

    def invoke(
        arguments: str,
        uid: Optional[str] = "1000",
        gid: Optional[str] = None,
        extra_env: Optional[dict] = None,
    ):
        if uid is not None:
            fixed_id_dir(bin_dir, uid, gid if gid is not None else uid)
        # As a CI step runs it: under Stop, wrapped so a refusal ends it with its code.
        call = f"Invoke-ASH -OCIRunner docker -SourceDir src -OutputDir out {arguments}"
        script = (
            f"$ErrorActionPreference = 'Stop'; . '{HELPERS.as_posix()}'; "
            f"{_wrapped(call)}; "
            "exit [int]$LASTEXITCODE"
        )
        env = inherited_env("PATH", "ASH_CONFIG")
        env["PATH"] = os.pathsep.join(
            [
                bin_dir.as_posix(),
                Path(pwsh).resolve().parent.as_posix(),
                "/usr/bin",
                "/bin",
            ]
        )
        # pwsh's own HOME and caches, as in _pwsh_script.
        env.update(scratch_home(tmp_path))
        env.update(extra_env or {})
        result = subprocess.run(  # nosec B603 - fixed interpreter, script built here
            [pwsh, "-NoProfile", "-NonInteractive", "-Command", script],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=120,
            check=False,
        )
        calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
        return result, calls

    return invoke


pytestmark_posix = pytest.mark.skipif(
    os.name == "nt", reason="the stand-in docker and id are POSIX shell scripts"
)


@pytestmark_posix
def test_a_root_caller_is_refused_with_the_opt_in_named(host):
    result, calls = host("-NoRun", uid="0")

    assert result.returncode == 3, result.stdout + result.stderr
    assert calls == []
    assert "-BuildTarget ci" in result.stderr


@pytestmark_posix
def test_a_root_caller_that_asks_for_ci_builds_it(host):
    result, calls = host("-NoRun -BuildTarget ci", uid="0")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "build" in calls and "ci" in calls


@pytestmark_posix
def test_an_unprivileged_caller_builds_non_root(host):
    """Control."""
    result, calls = host("-NoRun", uid="1000")

    assert result.returncode == 0, result.stdout + result.stderr
    assert calls[calls.index("--target") + 1] == "non-root"


@pytestmark_posix
def test_the_caller_ids_are_the_default_ids_of_the_non_root_user(host):
    """As ./ash and ash --mode container do: the user owns what the caller made."""
    result, calls = host("-NoRun", uid="1234", gid="1235")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "UID=1234" in calls and "GID=1235" in calls


@pytestmark_posix
def test_a_root_caller_with_another_uid_still_gets_gid_0_refused(host):
    """The GID comes from the caller too, so root's group 0 is refused, as ./ash
    and ash --mode container refuse it."""
    result, calls = host("-NoRun -ContainerUID 1000", uid="0", gid="0")

    assert result.returncode == 3, result.stdout + result.stderr
    assert calls == []
    assert "GID 0" in " ".join(result.stderr.split())


@pytestmark_posix
def test_explicit_ids_win_over_the_caller_ids(host):
    """Control."""
    result, calls = host(
        "-NoRun -ContainerUID 2000 -ContainerGID 2001", uid="0", gid="0"
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "UID=2000" in calls and "GID=2001" in calls


@pytestmark_posix
@pytest.mark.parametrize(
    ("arguments", "uid", "id_flag"),
    [
        pytest.param("-NoRun", "0", "-ContainerUID", id="uid-0"),
        pytest.param(
            "-NoRun -ContainerUID 1000 -ContainerGID 0",
            "1000",
            "-ContainerGID",
            id="gid-0",
        ),
    ],
)
def test_the_refusal_names_ci_first_and_other_ids_only_with_a_writable_output(
    arguments, uid, id_flag, host
):
    result, calls = host(arguments, uid=uid)

    assert result.returncode == 3 and calls == [], result.stdout + result.stderr
    message = " ".join(result.stderr.split())
    # The advice starts with ci; the cause before it may name the flag as given.
    advice = message[message.index("Pass -BuildTarget ci") :]
    assert id_flag in advice
    assert "output directory is writable" in advice[advice.index(id_flag) :]


@pytestmark_posix
@pytest.mark.parametrize("written", ["NON-ROOT", "Ci"])
def test_the_stage_is_built_by_its_lower_case_name(written, host):
    result, calls = host(f"-NoRun -BuildTarget {written}", uid="1000")

    assert result.returncode == 0, result.stdout + result.stderr
    assert calls[calls.index("--target") + 1] == written.lower()
    assert calls[calls.index("--tag") + 1] == (
        f"automated-security-helper:{written.lower()}"
    )


@pytestmark_posix
@pytest.mark.parametrize(
    "arguments",
    [
        "-NoRun -ContainerUID 1000 -ContainerGID 0",
        "-NoRun -ContainerUID 0",
        "-NoRun -ContainerUID 1x",
        # .NET's `$` matches before a final line feed; the ID check must not.
        '-NoRun -ContainerUID "1000`n"',
        '-NoRun -ContainerUID 1000 -ContainerGID "1000`n"',
    ],
    ids=[
        "gid-0",
        "uid-0",
        "uid-not-a-number",
        "uid-with-a-trailing-line-feed",
        "gid-with-a-trailing-line-feed",
    ],
)
def test_an_id_the_non_root_stage_cannot_use_is_refused(arguments, host):
    result, calls = host(arguments)

    assert result.returncode == 3, result.stdout + result.stderr
    assert calls == []


#: (file name, text): spellings ASH reads as an ``extends`` entry; see
#: test_container_wrappers_mount_containment.py for the precondition check.
EXTENDS_SPELLINGS = [
    pytest.param("ash.yaml", "extends: base.yaml\n", id="yaml"),
    pytest.param("ash.json", '{"extends": "base.json"}\n', id="json"),
    pytest.param("ash.toml", 'extends = "base.toml"\n', id="toml"),
    pytest.param(
        "ash.json", '{\n  "extends"\n  : "base.json"\n}\n', id="json-key-on-two-lines"
    ),
    pytest.param("ash.yaml", '"ext\\x65nds": base.yaml\n', id="yaml-escaped-key"),
    pytest.param("ash.yaml", "? extends\n: base.yaml\n", id="yaml-complex-key"),
]


@pytestmark_posix
@pytest.mark.parametrize(("name", "text"), EXTENDS_SPELLINGS)
def test_an_outside_config_with_extends_is_refused(name, text, host, tmp_path):
    (tmp_path / "base.yaml").write_text("project_name: p\n", encoding="utf-8")
    config = tmp_path / name
    config.write_text(text, encoding="utf-8")

    result, calls = host("-NoBuild", extra_env={"ASH_CONFIG": config.as_posix()})

    assert result.returncode == 3, result.stdout + result.stderr
    assert calls == []
    assert "extends" in result.stderr


@pytestmark_posix
@pytest.mark.parametrize(("name", "text"), EXTENDS_SPELLINGS)
def test_an_explicit_config_with_extends_is_passed_as_written(
    name, text, host, tmp_path
):
    """-Config is the scan's own --config: it is not read for an ``extends`` entry,
    not refused, and nothing is mounted for it."""
    (tmp_path / "base.yaml").write_text("project_name: p\n", encoding="utf-8")
    config = tmp_path / name
    config.write_text(text, encoding="utf-8")

    result, calls = host(f"-NoBuild -Config '{config.as_posix()}'")

    assert result.returncode == 0, result.stdout + result.stderr
    assert calls[calls.index("--config") + 1] == config.as_posix()
    assert [call for call in calls if "destination=/ash" in call] == []


@pytestmark_posix
def test_an_outside_config_without_extends_still_runs(host, tmp_path):
    """Control."""
    config = tmp_path / "ash.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")

    result, calls = host(f"-NoBuild -Config '{config.as_posix()}'")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "run" in calls


@pytestmark_posix
def test_an_outside_ash_config_without_extends_still_runs(host, tmp_path):
    """Control for the refusal above: the same file, without the entry, is carried
    into the container."""
    config = tmp_path / "ash.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")

    result, calls = host("-NoBuild", extra_env={"ASH_CONFIG": config.as_posix()})

    assert result.returncode == 0, result.stdout + result.stderr
    assert "run" in calls
    carried = calls[calls.index("--ash-config-from-host") + 1]
    assert carried == "/ash-env-config/ash.yaml"


@pytestmark_posix
def test_a_missing_config_names_the_path(host):
    result, calls = host("-NoBuild", extra_env={"ASH_CONFIG": "missing.yaml"})

    assert result.returncode == 3, result.stdout + result.stderr
    assert calls == []
    assert "Config file not found: missing.yaml" in result.stderr
