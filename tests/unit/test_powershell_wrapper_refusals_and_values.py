# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``Invoke-ASH`` refuses with the code it means and passes each given path as a value.

utils/ash_helpers.ps1:

- Each refusal sets ``$LASTEXITCODE`` to 3 (or 1) and throws. A CI step wraps the
  call, ``try { Invoke-ASH ... } catch { Write-Error -ErrorRecord $_ -ErrorAction
  Continue; exit ... }``, and these tests run it that way, under
  ``$ErrorActionPreference = 'Stop'``, which GitHub Actions sets for every ``pwsh``
  step. ``Write-Error`` would not do for a refusal:
  under ``Stop`` it is a terminating error raised before the code is set.
- The build and run commands are strings run by ``Invoke-Expression``, which parses
  them as PowerShell. Every path and value the operator gives is written into them
  by its variable name (``"$sourceDirFull"``), which ``Invoke-Expression`` expands
  as a value without parsing it, so a directory named ``a$(...)`` is passed as that
  name. ``AshArgs``, the arguments passed through to ASH as written, is parsed
  again; that is the documented limit of passing it through at all.

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
from typing import List

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS = REPO_ROOT / "utils" / "ash_helpers.ps1"
PWSH = shutil.which("pwsh")
_IN_CI = "true" in (os.environ.get("CI"), os.environ.get("GITHUB_ACTIONS"))

#: Variables the command strings may still splice in: the commands themselves, the
#: runner's wrapper (a prefix meant to be split), the fixed stage, the lists
#: assembled from constants or from references, YES/NO and the terminal size, and
#: AshArgs, passed through as written. The runner is not among them: it can be a
#: path the operator gave, so it is written in by name like any other path.
SPLICE_ALLOWED = {
    "buildCmd",
    "runCmd",
    "OCI_WRAPPER",
    "BuildTarget",
    "buildArgs",
    "runArgs",
    "ashCmdArgs",
    "configMountArg",
    "AshArgs",
    "ashDebug",
    "Offline",
    "COLUMNS",
    "LINES",
    "i",
    "null",
}

_SINGLE_QUOTED = re.compile(r"'[^']*'")
#: A variable reference; a backtick before ``$`` makes it a literal dollar sign.
_VARIABLE = re.compile(r"(?<!`)\$(?:\{([^}]+)\}|((?:env:)?[A-Za-z_]\w*))")


def _command_lines(text: str) -> List[str]:
    """The lines that add to a command Invoke-Expression runs."""
    lines: List[str] = []
    in_block = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("#"):
            continue
        if in_block:
            if line == ")":
                in_block = False
                continue
            lines.append(line)
            continue
        if re.match(r"\$(buildCmd|runCmd)\s*\+=\s*@\($", line):
            in_block = True
            continue
        if re.match(
            r"(\$(buildCmd|runCmd)\s*\+=|\$configMountArg\s*=|\$ashCmdArgs\.Add\()",
            line,
        ):
            lines.append(line)
    return lines


def _spliced(lines: List[str]) -> List[str]:
    """Each variable a command line splices into the string, outside single quotes."""
    found = []
    for line in lines:
        for match in _VARIABLE.finditer(_SINGLE_QUOTED.sub("''", line)):
            name = match.group(1) or match.group(2)
            if name not in SPLICE_ALLOWED:
                found.append(f"{name}: {line}")
    return found


def test_the_commands_name_operator_values_instead_of_splicing_them():
    lines = _command_lines(HELPERS.read_text(encoding="utf-8"))

    assert len(lines) > 20, "the command assembly was not found"
    assert _spliced(lines) == []


def test_the_check_sees_a_spliced_value():
    """Control for the checker: two lines splicing a value, and their by-name form."""
    old = [
        '$runCmd += "--mount `"type=bind,source=$sourceDirFull,destination=/src`""',
        "$ashCmdArgs.Add($scanner)",
    ]
    new = [
        "$runCmd += '--mount \"type=bind,source=$sourceDirFull,destination=/src\"'",
        '$ashCmdArgs.Add("`$Scanners[$i]")',
    ]

    assert len(_spliced(old)) == 2
    assert _spliced(new) == []


def test_no_refusal_writes_with_write_error():
    """Under ``$ErrorActionPreference = 'Stop'`` a Write-Error is itself a terminating
    error, raised before the refusal sets ``$LASTEXITCODE``. Refusals go through
    Stop-AshRefusal, which sets the code and throws."""
    lines = [line.strip() for line in HELPERS.read_text(encoding="utf-8").splitlines()]

    assert [line for line in lines if line.startswith("Write-Error")] == []
    assert any(line.startswith("Stop-AshRefusal 3 ") for line in lines)


@pytest.fixture
def pwsh():
    if PWSH is None:
        if _IN_CI:
            pytest.fail("pwsh is not on PATH; CI runners must run this test")
        pytest.skip("pwsh is not on PATH (local run only; CI fails instead)")
    return PWSH


@pytest.fixture
def recording_docker(tmp_path, pwsh) -> Path:
    """A PATH whose docker writes its arguments, one per line, and succeeds."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "docker-args.txt"
    if os.name == "nt":
        (bin_dir / "docker.cmd").write_text("@exit /b 0\r\n", encoding="utf-8")
    else:
        runner = bin_dir / "docker"
        runner.write_text(
            f"#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done >> '{log}'\n",
            encoding="utf-8",
        )
        runner.chmod(0o755)
    return bin_dir


def _invoke(pwsh, tmp_path: Path, bin_dir: Path, arguments: str):
    """Run Invoke-ASH as a CI step does: under ``Stop``, wrapped so a refusal, which
    throws, ends the step with its code (docs/content/docs/cli-reference.md)."""
    script = (
        f"$ErrorActionPreference = 'Stop'; . '{HELPERS.as_posix()}'; "
        f"try {{ Invoke-ASH -OCIRunner docker -NoBuild {arguments} }} "
        "catch { Write-Error -ErrorRecord $_ -ErrorAction Continue; "
        "exit $(if ($LASTEXITCODE) { $LASTEXITCODE } else { 1 }) }; "
        "exit [int]$LASTEXITCODE"
    )
    env = {k: v for k, v in os.environ.items() if k not in ("PATH", "ASH_CONFIG")}
    env["PATH"] = os.pathsep.join(
        [bin_dir.as_posix(), Path(pwsh).resolve().parent.as_posix()]
    )
    return subprocess.run(  # nosec B603 - fixed interpreter, script built here
        [pwsh, "-NoProfile", "-NonInteractive", "-Command", script],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
        check=False,
    )


@pytest.mark.parametrize(
    "arguments",
    [
        pytest.param("-SourceDir src -OutputDir out -Config missing.yaml", id="config"),
        pytest.param("-SourceDir src -OutputDir 'a,b'", id="mount-path"),
    ],
)
def test_a_refusal_exits_3_under_error_action_stop(
    arguments, pwsh, recording_docker, tmp_path
):
    (tmp_path / "src").mkdir()

    result = _invoke(pwsh, tmp_path, recording_docker, arguments)

    assert result.returncode == 3, result.stdout + result.stderr
    assert not (tmp_path / "docker-args.txt").exists()


@pytest.mark.parametrize(
    "arguments",
    [
        pytest.param("-SourceDir src -OutputDir src", id="the-source"),
        pytest.param("-SourceDir src/inner -OutputDir src", id="its-parent"),
    ],
)
def test_an_output_directory_over_the_source_is_refused(
    arguments, pwsh, recording_docker, tmp_path
):
    """/out is read-write and /src read-only: an output directory holding the
    source tree would make it writable through /out."""
    (tmp_path / "src" / "inner").mkdir(parents=True)

    result = _invoke(pwsh, tmp_path, recording_docker, arguments)

    assert result.returncode == 3, result.stdout + result.stderr
    assert not (tmp_path / "docker-args.txt").exists()
    assert "above it" in " ".join(result.stderr.split())


@pytest.mark.skipif(
    os.name == "nt",
    reason="the recording runner is a POSIX shell script; Windows gets a .cmd stub",
)
def test_a_source_and_output_named_with_wildcard_characters_are_those_names(
    pwsh, recording_docker, tmp_path
):
    """'src[1]' is a name, not a pattern that also matches 'src1'."""
    (tmp_path / "src[1]").mkdir()
    (tmp_path / "src1").mkdir()
    (tmp_path / "out1").mkdir()

    result = _invoke(
        pwsh, tmp_path, recording_docker, "-SourceDir 'src[1]' -OutputDir 'out[1]'"
    )

    assert result.returncode == 0, result.stdout + result.stderr
    args = (tmp_path / "docker-args.txt").read_text(encoding="utf-8").splitlines()
    assert f"type=bind,source={tmp_path / 'src[1]'},destination=/src,readonly" in args
    assert f"type=bind,source={tmp_path / 'out[1]'},destination=/out" in args
    assert (tmp_path / "out[1]").is_dir()


def _recorded(tmp_path: Path) -> List[str]:
    log = tmp_path / "docker-args.txt"
    return log.read_text(encoding="utf-8").splitlines() if log.exists() else []


def _mount_destinations(args: List[str]) -> List[str]:
    return [
        part.partition("=")[2]
        for i, arg in enumerate(args[:-1])
        if arg == "--mount"
        for part in args[i + 1].split(",")
        if part.startswith("destination=")
    ]


@pytest.fixture
def checkout(tmp_path) -> Path:
    """repo/.git, repo/svc (the source), repo/ci, and an operator dir outside."""
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    (root / "svc").mkdir()
    (root / "ci").mkdir()
    (tmp_path / "operator").mkdir()
    return root


_POSIX_ONLY = pytest.mark.skipif(
    os.name == "nt",
    reason="the recording runner is a POSIX shell script; Windows gets a .cmd stub",
)


@_POSIX_ONLY
def test_a_source_named_through_a_link_still_finds_its_checkout(
    pwsh, recording_docker, checkout, tmp_path
):
    """The checkout is found from the source's real path too, as ./ash finds it."""
    (checkout / "ci" / "ash.yaml").write_text("project_name: p\n", encoding="utf-8")
    (tmp_path / "alias").symlink_to(checkout / "svc", target_is_directory=True)

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        f"-SourceDir alias -OutputDir out -Config '{checkout / 'ci' / 'ash.yaml'}'",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "--config-from-scanned-repository" in _recorded(tmp_path)


@_POSIX_ONLY
def test_a_config_in_the_source_linked_out_of_the_tree_is_refused(
    pwsh, recording_docker, checkout, tmp_path
):
    (tmp_path / "operator" / "ash.yaml").write_text(
        "project_name: p\n", encoding="utf-8"
    )
    (checkout / "svc" / "ash.yaml").symlink_to(tmp_path / "operator" / "ash.yaml")

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        "-SourceDir repo/svc -OutputDir out -Config repo/svc/ash.yaml",
    )

    assert result.returncode == 3, result.stdout + result.stderr
    assert _recorded(tmp_path) == []
    assert "link" in result.stderr


@_POSIX_ONLY
def test_a_config_in_the_source_linked_inside_it_is_read_through_src(
    pwsh, recording_docker, checkout, tmp_path
):
    """Control: a link that stays inside the source names its target under /src."""
    (checkout / "svc" / "conf").mkdir()
    (checkout / "svc" / "conf" / "real.yaml").write_text(
        "project_name: p\n", encoding="utf-8"
    )
    (checkout / "svc" / "ash.yaml").symlink_to("conf/real.yaml")

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        "-SourceDir repo/svc -OutputDir out -Config repo/svc/ash.yaml",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    args = _recorded(tmp_path)
    assert args[args.index("--config") + 1] == "/src/conf/real.yaml"
    assert sorted(_mount_destinations(args)) == ["/out", "/src"]


def test_an_output_directory_inside_the_source_runs(pwsh, recording_docker, tmp_path):
    """Control: the default .ash/ash_output is inside the source."""
    (tmp_path / "src").mkdir()

    result = _invoke(
        pwsh, tmp_path, recording_docker, "-SourceDir src -OutputDir src/.ash/out"
    )

    assert result.returncode == 0, result.stdout + result.stderr


@pytest.fixture
def elsewhere(tmp_path) -> Path:
    """Where a link points the output directory; nothing may be written to it."""
    path = tmp_path / "elsewhere"
    path.mkdir()
    return path


@pytest.mark.parametrize(
    "where",
    [
        "the-output-directory",
        "a-directory-on-the-way",
        "an-outside-output-directory",
        "a-dangling-link",
    ],
)
def test_a_linked_output_directory_is_refused(
    where, pwsh, recording_docker, elsewhere, tmp_path
):
    """/out is read-write: with a linked output directory the scan would write
    wherever the link leads. Refused with exit 3 before the directory is created:
    the output directory when it is a link, and any link below SourceDir on the way
    to it."""
    src = tmp_path / "src"
    src.mkdir()
    if where == "the-output-directory":
        (src / ".ash").mkdir()
        link = src / ".ash" / "out"
        link.symlink_to(elsewhere, target_is_directory=True)
        output = "src/.ash/out"
    elif where == "a-directory-on-the-way":
        link = src / ".ash"
        link.symlink_to(elsewhere, target_is_directory=True)
        output = "src/.ash/out"
    elif where == "an-outside-output-directory":
        link = tmp_path / "out-link"
        link.symlink_to(elsewhere, target_is_directory=True)
        output = "out-link"
    else:
        (src / ".ash").mkdir()
        link = src / ".ash" / "out"
        link.symlink_to(tmp_path / "not-there", target_is_directory=True)
        output = "src/.ash/out"

    result = _invoke(
        pwsh, tmp_path, recording_docker, f"-SourceDir src -OutputDir {output}"
    )

    assert result.returncode == 3, result.stdout + result.stderr
    assert not (tmp_path / "docker-args.txt").exists()
    assert list(elsewhere.iterdir()) == []
    assert str(link) in " ".join(result.stderr.split())


def test_a_link_on_the_way_is_seen_under_the_real_name_of_the_source(
    pwsh, recording_docker, elsewhere, tmp_path
):
    """SourceDir is named through a link and OutputDir through the real path, so
    only the real name shows that .ash is below the source."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src-link").symlink_to(tmp_path / "src", target_is_directory=True)
    (tmp_path / "src" / ".ash").symlink_to(elsewhere, target_is_directory=True)

    result = _invoke(
        pwsh, tmp_path, recording_docker, "-SourceDir src-link -OutputDir src/.ash/out"
    )

    assert result.returncode == 3, result.stdout + result.stderr
    assert not (tmp_path / "docker-args.txt").exists()
    assert list(elsewhere.iterdir()) == []


def test_a_linked_output_directory_is_refused_without_a_run_too(
    pwsh, recording_docker, elsewhere, tmp_path
):
    """-NoRun still creates the output directory, so it is refused as well."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / ".ash").symlink_to(elsewhere, target_is_directory=True)

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        "-SourceDir src -OutputDir src/.ash/out -NoRun",
    )

    assert result.returncode == 3, result.stdout + result.stderr
    assert list(elsewhere.iterdir()) == []


@pytest.mark.parametrize("where", ["a-real-directory", "a-source-named-through-a-link"])
def test_a_real_output_directory_runs(where, pwsh, recording_docker, tmp_path):
    """Control: a real directory inside the source, also when the source is named
    through a link above it, which is the operator's own spelling."""
    (tmp_path / "work" / "src").mkdir(parents=True)
    base = "work"
    if where == "a-source-named-through-a-link":
        (tmp_path / "work-link").symlink_to(tmp_path / "work", target_is_directory=True)
        base = "work-link"

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        f"-SourceDir {base}/src -OutputDir {base}/src/.ash/out",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    output = tmp_path / "work" / "src" / ".ash" / "out"
    assert output.is_dir() and not output.is_symlink()


@pytest.mark.skipif(
    os.name == "nt",
    reason="the recording runner is a POSIX shell script; Windows gets a .cmd stub",
)
def test_a_source_path_is_passed_as_a_value_and_not_run(
    pwsh, recording_docker, tmp_path
):
    source = tmp_path / "a$(New-Item -ItemType File -Path marker)"
    source.mkdir()

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        f"-SourceDir '{source.as_posix()}' -OutputDir out",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert not (tmp_path / "marker").exists(), "the path was parsed as PowerShell"
    args = (tmp_path / "docker-args.txt").read_text(encoding="utf-8").splitlines()
    assert f"type=bind,source={source},destination=/src,readonly" in args


def _self_recording_runner(directory: Path, log: Path) -> Path:
    """A ``docker`` that appends its own path and its first argument to *log*."""
    directory.mkdir(parents=True)
    runner = directory / "docker"
    runner.write_text(
        f"#!/bin/sh\nprintf '%s %s\\n' \"$0\" \"$1\" >> '{log}'\nexit 0\n",
        encoding="utf-8",
    )
    runner.chmod(0o755)
    return runner


@pytest.mark.skipif(
    os.name == "nt", reason="the stand-in runners are POSIX shell scripts"
)
@pytest.mark.parametrize("given", ["a-path", "a-name", "a-path-under-a-wrapper"])
def test_an_explicit_runner_path_runs_that_path(given, pwsh, tmp_path):
    """Two runners named ``docker``: one at the path given to -OCIRunner, one first
    on PATH. A path runs exactly that file; a bare name resolves on PATH, as before.
    The path holds a space and ``$(...)``, which a spliced command name would break
    on or run. Under OCI_RUNNER_WRAPPER the path is the wrapper's first argument."""
    (tmp_path / "src").mkdir()
    log = tmp_path / "runner-calls.txt"
    explicit = _self_recording_runner(tmp_path / "given dir $(x)", log)
    on_path = _self_recording_runner(tmp_path / "path-bin", log)
    runner = "docker" if given == "a-name" else f"'{explicit.as_posix()}'"
    wrapper = tmp_path / "wrapper-bin" / "wrap"
    wrapper.parent.mkdir()
    wrapper.write_text(
        f"#!/bin/sh\nprintf 'wrap %s\\n' \"$1\" >> '{log}'\nexec \"$@\"\n",
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    script = (
        f"$ErrorActionPreference = 'Stop'; . '{HELPERS.as_posix()}'; "
        f"try {{ Invoke-ASH -OCIRunner {runner} -NoBuild -SourceDir src -OutputDir out }} "
        "catch { Write-Error -ErrorRecord $_ -ErrorAction Continue; "
        "exit $(if ($LASTEXITCODE) { $LASTEXITCODE } else { 1 }) }; "
        "exit [int]$LASTEXITCODE"
    )
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in ("PATH", "ASH_CONFIG", "OCI_RUNNER_WRAPPER")
    }
    env["PATH"] = os.pathsep.join(
        [on_path.parent.as_posix(), Path(pwsh).resolve().parent.as_posix()]
    )
    if given == "a-path-under-a-wrapper":
        env["OCI_RUNNER_WRAPPER"] = wrapper.as_posix()

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

    assert result.returncode == 0, result.stdout + result.stderr
    calls = log.read_text(encoding="utf-8").splitlines()
    if given == "a-name":
        assert calls == [f"{on_path} run"]
    elif given == "a-path":
        assert calls == [f"{explicit} run"]
    else:
        assert calls == [f"wrap {explicit}", f"{explicit} run"]


# ---------------------------------------------------------------------------
# What reaches the run command: the config, the stage, the scanner lists
# ---------------------------------------------------------------------------


def _mount_at(args: List[str], destination: str) -> str:
    values = [
        args[i + 1]
        for i, arg in enumerate(args[:-1])
        if arg == "--mount" and f"destination={destination}," in args[i + 1] + ","
    ]
    assert len(values) == 1, f"expected one mount at {destination} in {args}"
    return values[0]


@_POSIX_ONLY
def test_an_operator_config_outside_the_checkout_is_mounted_read_only(
    pwsh, recording_docker, checkout, tmp_path
):
    config = tmp_path / "operator" / "ash.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        f"-SourceDir repo/svc -OutputDir out -Config '{config}'",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    args = _recorded(tmp_path)
    assert (
        _mount_at(args, "/ash-config/ash.yaml")
        == f"type=bind,source={config},destination=/ash-config/ash.yaml,readonly"
    )
    assert args[args.index("--config") + 1] == "/ash-config/ash.yaml"
    assert "--config-from-scanned-repository" not in args


@_POSIX_ONLY
def test_a_config_elsewhere_in_the_checkout_is_marked_as_the_repositorys(
    pwsh, recording_docker, checkout, tmp_path
):
    (checkout / "ci" / "ash.yaml").write_text("project_name: p\n", encoding="utf-8")

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        "-SourceDir repo/svc -OutputDir out -Config repo/ci/ash.yaml",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    args = _recorded(tmp_path)
    assert args[args.index("--config") + 1] == "/ash-config/ash.yaml"
    assert "--config-from-scanned-repository" in args


@_POSIX_ONLY
def test_a_config_reached_through_a_link_out_of_the_checkout_is_refused(
    pwsh, recording_docker, checkout, tmp_path
):
    (tmp_path / "operator" / "ash.yaml").write_text(
        "project_name: p\n", encoding="utf-8"
    )
    (checkout / "linked").symlink_to(tmp_path / "operator", target_is_directory=True)

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        "-SourceDir repo/svc -OutputDir out -Config repo/linked/ash.yaml",
    )

    assert result.returncode == 3, result.stdout + result.stderr
    assert _recorded(tmp_path) == []


@_POSIX_ONLY
def test_a_config_inside_the_source_is_read_through_src_with_no_mount(
    pwsh, recording_docker, checkout, tmp_path
):
    (checkout / "svc" / ".ash").mkdir()
    (checkout / "svc" / ".ash" / "ash.yaml").write_text(
        "project_name: p\n", encoding="utf-8"
    )

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        "-SourceDir repo/svc -OutputDir out -Config repo/svc/.ash/ash.yaml",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    args = _recorded(tmp_path)
    assert args[args.index("--config") + 1] == "/src/.ash/ash.yaml"
    assert sorted(_mount_destinations(args)) == ["/out", "/src"]
    assert "--config-from-scanned-repository" not in args


@_POSIX_ONLY
def test_ci_variables_do_not_choose_the_stage(
    pwsh, recording_docker, tmp_path, monkeypatch
):
    """Windows defaults to ci on its own; elsewhere the stage is non-root unless
    -BuildTarget names another, CI or not."""
    for name, value in (("CI", "true"), ("IsCI", "1"), ("CODEBUILD_BUILD_ID", "p:1")):
        monkeypatch.setenv(name, value)
    (tmp_path / "src").mkdir()

    result = _invoke(pwsh, tmp_path, recording_docker, "-SourceDir src -OutputDir out")

    assert result.returncode == 0, result.stdout + result.stderr
    args = _recorded(tmp_path)
    assert "automated-security-helper:non-root" in args
    assert "automated-security-helper:ci" not in args


@_POSIX_ONLY
def test_the_scanner_lists_reach_the_scan(pwsh, recording_docker, tmp_path):
    (tmp_path / "src").mkdir()

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        "-SourceDir src -OutputDir out -Scanners bandit,checkov -ExcludeScanners grype",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    args = _recorded(tmp_path)
    inner = args[args.index("ash") + 1 :]
    pairs = [
        (inner[i], inner[i + 1])
        for i in range(len(inner) - 1)
        if inner[i] in ("--scanners", "--exclude-scanners")
    ]
    assert pairs == [
        ("--scanners", "bandit"),
        ("--scanners", "checkov"),
        ("--exclude-scanners", "grype"),
    ]


@pytest.mark.parametrize(
    "arguments",
    [
        pytest.param("-SourceDir src -OutputDir 'a,b'", id="unmountable-output"),
        pytest.param("-SourceDir src -OutputDir out -Config missing.yaml", id="config"),
    ],
)
def test_a_build_without_a_run_checks_nothing_it_would_mount(
    arguments, pwsh, recording_docker, tmp_path
):
    """-NoRun mounts nothing, so neither the mount paths nor the config are checked."""
    (tmp_path / "src").mkdir()

    result = _invoke(pwsh, tmp_path, recording_docker, f"-NoRun {arguments}")

    assert result.returncode == 0, result.stdout + result.stderr
