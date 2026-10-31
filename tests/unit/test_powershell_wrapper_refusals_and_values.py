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
- The build and run commands are arrays of arguments, and the runner is called with
  them directly (``& $command @arguments``). Every path and value the operator gives
  is one element of an array and reaches the runner as one argument, exactly as
  written, so a directory named ``a$(...)`` is passed as that name. Nothing is passed
  through ``Invoke-Expression``, which would parse the text as PowerShell.
  ``AshArgs``, the arguments passed through to ASH as written, is read once with
  PowerShell's own tokenizer and parser, and a word PowerShell would expand is
  refused instead of being parsed again.

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

from tests.utils.config_link_layouts import (
    LINKS_IN_ANOTHER_CHECKOUT,
    LINKS_IN_THE_SCANNED_CHECKOUT,
    LINKS_OUTSIDE_EVERY_CHECKOUT,
    config_through_a_link_in,
    config_through_links,
)
from tests.utils.helpers import mark_git_checkout
from tests.utils.pwsh_env import inherited_env, scratch_home

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS = REPO_ROOT / "utils" / "ash_helpers.ps1"
PWSH = shutil.which("pwsh")
_IN_CI = "true" in (os.environ.get("CI"), os.environ.get("GITHUB_ACTIONS"))

#: What turns a string into code or a command line for PowerShell to parse, which
#: would read every value in it again: Invoke-Expression and its alias iex, a script
#: block made from text, Invoke-Command, the engine's InvokeScript and ExpandString,
#: and a command written as a quoted string after the call operator.
_REPARSES = re.compile(
    r"\bInvoke-Expression\b"
    r"|(?<![\w$.-])iex\b"
    r"|\[scriptblock\]::Create\b"
    r"|\bInvoke-Command\b"
    r"|\.(?:InvokeScript|ExpandString)\("
    r"|(?<![\w&])&\s*[\"']",
    re.IGNORECASE,
)

#: How the build and run commands reach the runner, in file order: each array, less
#: its first word (the program), is checked to hold one argument per element and is
#: then splatted, so no value is joined into text on the way.
_HAND_OFF = [
    "$buildArgv = @($buildCmd | Select-Object -Skip 1)",
    "Assert-OneArgumentEach $buildArgv @($buildCmd[0], $RESOLVED_OCI_RUNNER)",
    "& $buildCmd[0] @buildArgv",
    "$runArgv = @($runCmd | Select-Object -Skip 1)",
    "Assert-OneArgumentEach $runArgv @($runCmd[0], $RESOLVED_OCI_RUNNER)",
    "& $runCmd[0] @runArgv",
]
_HAND_OFF_LINE = re.compile(
    r"\$(?:buildArgv|runArgv) =|Assert-OneArgumentEach \$|& \$(?:buildCmd|runCmd)\b"
)

#: A throw with a message, also one that shares its line with an ``if``; a bare
#: ``throw`` rethrows the error in flight.
_MESSAGE_THROW = re.compile(r"\bthrow\s+[\"']")
#: The statement that leaves a refusal's code: one of the codes the helper names, or a
#: number that is not 0, set in the global scope, which is the one a caller reads.
_REFUSAL_CODE = re.compile(
    r"\$global:LASTEXITCODE = "
    r"(?:\$(?:refusalExitCode|usageErrorExitCode|sandboxRefusalExitCode)|[1-9][0-9]*)"
)
#: The line that opens the block of a failed native command, whose code is its own.
_NATIVE_FAILURE = "if ($LASTEXITCODE -ne 0) {"


def _command_lines(text: str) -> List[str]:
    """The lines that add to a command array the runner is called with."""
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


def _code_lines(text: str) -> List[str]:
    """The lines of code, indentation kept: no blank line, no comment and no
    comment-based help."""
    lines: List[str] = []
    in_help = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("<#"):
            in_help = True
        if in_help:
            in_help = not line.endswith("#>")
            continue
        if line and not line.startswith("#"):
            lines.append(raw.rstrip())
    return lines


def _reparsing(lines: List[str]) -> List[str]:
    """The lines that hand a string to PowerShell to run as code or as a command."""
    return [line.strip() for line in lines if _REPARSES.search(line)]


def _hand_off(lines: List[str]) -> List[str]:
    """The lines that derive the argument arrays, check them and call the runner."""
    stripped = [line.strip() for line in lines]
    return [line for line in stripped if _HAND_OFF_LINE.match(line)]


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def _code_set_before(lines: List[str], at: int) -> bool:
    """Whether a refusal code is set before ``lines[at]`` in its block or in a block
    around it. Indentation marks the blocks: a line indented deeper than the one being
    looked back from belongs to a block that closed, and a shallower one opens the
    block around it."""
    level = _indent(lines[at])
    for earlier in reversed(lines[:at]):
        depth = _indent(earlier)
        if depth > level:
            continue
        level = depth
        if _REFUSAL_CODE.fullmatch(earlier.strip()):
            return True
    return False


def _refusals_without_a_code(lines: List[str]) -> List[str]:
    """The throws with a message that have no code set before them, apart from the one
    that reports a failed native command, which keeps that command's own code."""
    return [
        line.strip()
        for at, line in enumerate(lines)
        if _MESSAGE_THROW.search(line)
        and not (at and lines[at - 1].strip() == _NATIVE_FAILURE)
        and not _code_set_before(lines, at)
    ]


@pytest.mark.unit
def test_the_commands_name_operator_values_instead_of_splicing_them():
    """The build and run commands are argument arrays handed to the runner whole.

    A value is one element of an array, so it reaches the runner as one argument,
    exactly as the operator wrote it. Nothing builds text for PowerShell to parse:
    Invoke-Expression, a script block made from text or a quoted command after the
    call operator would read a ``$(...)``, a ``;`` or a ``|`` in a value as code."""
    text = HELPERS.read_text(encoding="utf-8")
    code = _code_lines(text)

    assert len(_command_lines(text)) > 20, "the command assembly was not found"
    assert _reparsing(code) == []
    assert _hand_off(code) == _HAND_OFF


@pytest.mark.unit
def test_the_check_sees_a_spliced_value():
    """Control for the checker: lines that read a value as code, and the array form."""
    parsed_again = [
        'Invoke-Expression ($runCmd -join " ")',
        'iex "$buildCmd"',
        "& ([scriptblock]::Create($runCmd -join ' '))",
        'Invoke-Command -ScriptBlock ([scriptblock]::Create("$buildCmd"))',
        '& "$runCmd"',
        '$ExecutionContext.InvokeCommand.ExpandString("$runCmd")',
    ]
    as_elements = [
        '$runCmd += "--mount", "type=bind,source=$sourceDirFull,destination=/src"',
        "$ashCmdArgs.Add(@('--config', $Config))",
        'Write-Verbose "Run command: $shownRunCmd"',
        *_HAND_OFF,
    ]
    commented = "    # Invoke-Expression would parse it as PowerShell\n    $x = 1"
    one_string = [*_HAND_OFF[:5], "& $runCmd[0] ($runArgv -join ' ')"]
    unchecked = [line for line in _HAND_OFF if not line.startswith("Assert-")]

    assert len(_reparsing(parsed_again)) == len(parsed_again)
    assert _reparsing(as_elements) == []
    assert _reparsing(_code_lines(commented)) == []
    assert _hand_off(["$x = 1", *_HAND_OFF, "$y = 2"]) == _HAND_OFF
    assert _hand_off(one_string) == one_string
    assert one_string != _HAND_OFF
    assert _hand_off(unchecked) == unchecked
    assert unchecked != _HAND_OFF


@pytest.mark.unit
def test_no_refusal_writes_with_write_error():
    """Under ``$ErrorActionPreference = 'Stop'`` a Write-Error is itself a terminating
    error, raised before the refusal sets ``$LASTEXITCODE``. A refusal sets the code
    and then throws: every ``throw`` with a message has ``$global:LASTEXITCODE =
    <code>`` before it in its block. The one that reports a failed build is the
    exception, since it keeps the build's own code."""
    text = HELPERS.read_text(encoding="utf-8")
    lines = [line.strip() for line in text.splitlines()]
    code = _code_lines(text)

    assert [line for line in lines if line.startswith("Write-Error")] == []
    throws = [line for line in code if _MESSAGE_THROW.search(line)]
    assert len(throws) > 30, "the refusals were not found"
    assert _refusals_without_a_code(code) == []


@pytest.mark.unit
def test_the_check_sees_a_refusal_that_throws_before_the_code():
    """Control for the checker: a throw with no code set in its block is found, and
    the shapes the wrapper uses are not."""
    unset = {
        "no code": ["if ($bad) {", '    throw "refused"', "}"],
        "no code, the throw shares its line with the if": [
            'if ($bad) { throw "refused" }'
        ],
        "the code comes after the throw": [
            "if ($bad) {",
            '    throw "refused"',
            "    $global:LASTEXITCODE = $refusalExitCode",
            "}",
        ],
        "the code was set in a block that closed": [
            "if ($first) {",
            "    $global:LASTEXITCODE = $refusalExitCode",
            '    throw "first"',
            "}",
            "if ($second) {",
            '    throw "second"',
            "}",
        ],
        "the code is set in the local scope": [
            "if ($bad) {",
            "    $LASTEXITCODE = $refusalExitCode",
            '    throw "refused"',
            "}",
        ],
        "the code is 0": [
            "if ($bad) {",
            "    $global:LASTEXITCODE = 0",
            '    throw "refused"',
            "}",
        ],
        "the value is not a code": [
            "if ($bad) {",
            "    $global:LASTEXITCODE = $savedExitCode",
            '    throw "refused"',
            "}",
        ],
    }
    set_before = {
        "the code on the line before": [
            "if ($bad) {",
            "    $global:LASTEXITCODE = $refusalExitCode",
            '    throw "refused"',
            "}",
        ],
        "a literal code": [
            "if ($bad) {",
            "    $global:LASTEXITCODE = 3",
            '    throw "refused"',
            "}",
        ],
        "the code before an if that holds the throw": [
            "$global:LASTEXITCODE = 3",
            'if ($bad) { throw "refused" }',
        ],
        "one code for two throws": [
            "if ($null -eq $item) {",
            "    $global:LASTEXITCODE = $usageErrorExitCode",
            "    if ($denied) {",
            '        throw "cannot be entered"',
            "    }",
            '    throw "does not exist"',
            "}",
        ],
        "a statement between the code and a nested throw": [
            "for ($i = 0; $i -lt $n; $i++) {",
            "    $global:LASTEXITCODE = $sandboxRefusalExitCode",
            "    $shown = Format-AshShownValue $mode",
            "    if ($known) {",
            '        throw "a"',
            "    }",
            '    throw "b"',
            "}",
        ],
        "a failed command keeps its own code": [
            "& $runCmd[0] @runArgv",
            "if ($LASTEXITCODE -ne 0) {",
            '    throw "Failed to build the image"',
            "}",
        ],
        "a rethrow": ["catch {", "    throw", "}"],
    }

    for name, lines in unset.items():
        last_throw = [line.strip() for line in lines if "throw" in line][-1]
        assert _refusals_without_a_code(lines) == [last_throw], name
    for name, lines in set_before.items():
        assert _refusals_without_a_code(lines) == [], name


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


def _invoke(
    pwsh,
    tmp_path: Path,
    bin_dir: Path,
    arguments: str,
    extra_env=None,
    helpers: Path = HELPERS,
    cwd: Path | None = None,
):
    """Run Invoke-ASH as a CI step does: under ``Stop``, wrapped so a refusal, which
    throws, ends the step with its code (docs/content/docs/cli-reference.md).

    *extra_env* is set after the scrub of ASH_CONFIG, so a test gives the variable
    the file it means. *helpers* is the script that is dot-sourced, the repository's
    unless a test gives a copy it changed. *cwd* is the working directory, *tmp_path*
    unless a test needs a link it made to sit outside it. pwsh gets a HOME and XDG
    directories of its own under *tmp_path* (``scratch_home``): it writes its startup
    cache and its telemetry id under them, and the test's HOME must hold no tool's
    files when the test ends (tests/unit/conftest.py, ``_unit_tool_guard``)."""
    script = (
        f"$ErrorActionPreference = 'Stop'; . '{helpers.as_posix()}'; "
        f"try {{ Invoke-ASH -OCIRunner docker -NoBuild {arguments} }} "
        "catch { Write-Error -ErrorRecord $_ -ErrorAction Continue; "
        "exit $(if ($LASTEXITCODE) { $LASTEXITCODE } else { 1 }) }; "
        "exit [int]$LASTEXITCODE"
    )
    env = inherited_env("PATH", "ASH_CONFIG")
    env["PATH"] = os.pathsep.join(
        [bin_dir.as_posix(), Path(pwsh).resolve().parent.as_posix()]
    )
    env.update(scratch_home(tmp_path))
    env.update(extra_env or {})
    return subprocess.run(  # nosec B603 - fixed interpreter, script built here
        [pwsh, "-NoProfile", "-NonInteractive", "-Command", script],
        cwd=cwd or tmp_path,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
        check=False,
    )


@pytest.mark.integration
@pytest.mark.parametrize(
    ("arguments", "extra_env"),
    [
        pytest.param(
            "-SourceDir src -OutputDir out", {"ASH_CONFIG": "missing.yaml"}, id="config"
        ),
        pytest.param("-SourceDir src -OutputDir 'a,b'", None, id="mount-path"),
        pytest.param(
            "-SourceDir src -OutputDir 'a\"b'", None, id="mount-path-double-quote"
        ),
    ],
)
def test_a_refusal_exits_3_under_error_action_stop(
    arguments, extra_env, pwsh, recording_docker, tmp_path
):
    (tmp_path / "src").mkdir()

    result = _invoke(pwsh, tmp_path, recording_docker, arguments, extra_env)

    assert result.returncode == 3, result.stdout + result.stderr
    assert not (tmp_path / "docker-args.txt").exists()


@pytest.mark.integration
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


@pytest.mark.integration
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


@pytest.mark.integration
@_POSIX_ONLY
def test_a_source_named_through_a_link_still_finds_its_checkout(
    pwsh, recording_docker, checkout, tmp_path
):
    """The checkout is found from the source's real path too, as ./ash finds it."""
    config = checkout / "ci" / "ash.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")
    (tmp_path / "alias").symlink_to(checkout / "svc", target_is_directory=True)

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        "-SourceDir alias -OutputDir out",
        {"ASH_CONFIG": str(config)},
    )

    assert result.returncode == 0, result.stdout + result.stderr
    args = _recorded(tmp_path)
    assert _values_of(args, SCANNED_FILE_FLAG) == ["/ash-env-config/ash.yaml"]
    assert SCANNED_CHAIN_FLAG in args


@pytest.mark.integration
@_POSIX_ONLY
def test_an_ash_config_file_in_the_source_linked_out_of_the_tree_is_refused(
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
        "-SourceDir repo/svc -OutputDir out",
        {"ASH_CONFIG": "repo/svc/ash.yaml"},
    )

    assert result.returncode == 3, result.stdout + result.stderr
    assert _recorded(tmp_path) == []
    assert "link" in result.stderr


@pytest.mark.integration
@_POSIX_ONLY
def test_an_ash_config_file_in_the_source_linked_inside_it_is_read_through_src(
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
        "-SourceDir repo/svc -OutputDir out",
        {"ASH_CONFIG": "repo/svc/ash.yaml"},
    )

    assert result.returncode == 0, result.stdout + result.stderr
    args = _recorded(tmp_path)
    assert _values_of(args, "--config") == ["/src/conf/real.yaml"]
    assert sorted(_mount_destinations(args)) == ["/out", "/src"]


@pytest.mark.integration
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


@pytest.mark.integration
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


@pytest.mark.integration
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


@pytest.mark.integration
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


@pytest.mark.integration
@pytest.mark.parametrize("where", ["a-real-directory", "a-source-named-through-a-link"])
def test_a_real_output_directory_runs(where, pwsh, recording_docker, tmp_path):
    """Control: a real directory inside the source, also when the source is named
    through a link above it, which is the operator's own spelling. That link sits
    beside the working directory, not below it: a link below the working directory
    or -SourceDir on the way to the output is refused (the next test), since in CI
    the working directory is the scanned checkout and the repository could have
    committed it."""
    (tmp_path / "work" / "src").mkdir(parents=True)
    cwd = tmp_path
    base = "work"
    if where == "a-source-named-through-a-link":
        (tmp_path / "work-link").symlink_to(tmp_path / "work", target_is_directory=True)
        cwd = tmp_path / "here"
        cwd.mkdir()
        base = (tmp_path / "work-link").as_posix()

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        f"-SourceDir '{base}/src' -OutputDir '{base}/src/.ash/out'",
        cwd=cwd,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    output = tmp_path / "work" / "src" / ".ash" / "out"
    assert output.is_dir() and not output.is_symlink()


@pytest.mark.integration
def test_a_link_below_the_working_directory_on_the_way_to_the_output_is_refused(
    pwsh, recording_docker, tmp_path
):
    """The same spelling from the directory that holds the link: a link below the
    working directory on the way to the output may be one the scanned repository
    committed, so nothing is written through it and nothing runs."""
    (tmp_path / "work" / "src").mkdir(parents=True)
    (tmp_path / "work-link").symlink_to(tmp_path / "work", target_is_directory=True)

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        "-SourceDir work-link/src -OutputDir work-link/src/.ash/out",
    )

    assert result.returncode == 3, result.stdout + result.stderr
    assert "reached through a link" in " ".join(result.stderr.split())
    assert not (tmp_path / "docker-args.txt").exists()
    assert not (tmp_path / "work" / "src" / ".ash").exists()


@pytest.mark.integration
@_POSIX_ONLY
@pytest.mark.parametrize("output", ["the-default", "given-through-the-source"])
def test_a_linked_source_directory_is_the_operators_own_spelling(
    output, pwsh, recording_docker, tmp_path
):
    """-SourceDir is a link below the working directory, as `Invoke-ASH -SourceDir
    linked` from a checkout root spells it. The default output directory sits inside
    the source, so its path runs through that link; the link is the operator's own
    spelling of the source, as `./ash --source-dir linked` takes it, and is not
    refused. Before, the walk counted it as a link below the working directory and
    refused the default with 3. A link below the source still counts (the tests
    above)."""
    (tmp_path / "real").mkdir()
    (tmp_path / "linked").symlink_to(tmp_path / "real", target_is_directory=True)
    arguments = "-SourceDir linked"
    if output == "given-through-the-source":
        arguments += " -OutputDir linked/.ash/ash_output"

    result = _invoke(pwsh, tmp_path, recording_docker, arguments)

    assert result.returncode == 0, result.stdout + result.stderr
    assert (tmp_path / "real" / ".ash" / "ash_output").is_dir()
    assert (tmp_path / "docker-args.txt").exists()


@pytest.mark.integration
@_POSIX_ONLY
@pytest.mark.parametrize("run", ["-NoRun", "a-run"])
def test_the_linked_source_itself_as_the_output_directory_is_refused(
    run, pwsh, recording_docker, tmp_path
):
    """-OutputDir names the same link -SourceDir does. The link is the operator's
    spelling of the source, but the output directory itself is never written through
    a link, as `./ash` refuses a linked output directory wherever it is: the scan's
    output and the cleanup of the previous run's would go where the link points.
    Before, the exemption of the source link covered this case too; a run was still
    refused as the source directory itself, but -NoRun skips that check, so -NoRun
    accepted the output and the write check made and deleted a file in the link's
    target. Refused as a link with 3 either way now, before anything runs."""
    (tmp_path / "real").mkdir()
    (tmp_path / "linked").symlink_to(tmp_path / "real", target_is_directory=True)
    arguments = "-SourceDir linked -OutputDir linked"
    if run == "-NoRun":
        arguments = "-NoRun " + arguments

    result = _invoke(pwsh, tmp_path, recording_docker, arguments)

    stderr = " ".join(result.stderr.split())
    assert result.returncode == 3, result.stdout + result.stderr
    assert "reached through a link" in stderr, result.stderr
    assert "is the source directory" not in stderr, result.stderr
    assert not (tmp_path / "docker-args.txt").exists()


@pytest.mark.integration
@pytest.mark.parametrize("output", ["the-default", "given"])
def test_a_refused_default_output_directory_names_the_parameter(
    output, pwsh, recording_docker, tmp_path
):
    """A file sits where the output directory would be. The refusal of the default
    names -OutputDir as the way to write elsewhere, as ./ash names --output-dir
    (tests/unit/test_ash_bash_entrypoint_refusals.py); the refusal of an -OutputDir
    that was given does not, since the choice was already made."""
    (tmp_path / "src" / ".ash").mkdir(parents=True)
    (tmp_path / "src" / ".ash" / "ash_output").write_text("", encoding="utf-8")
    (tmp_path / "a-file").write_text("", encoding="utf-8")
    arguments = "-SourceDir src"
    if output == "given":
        arguments += " -OutputDir a-file"

    result = _invoke(pwsh, tmp_path, recording_docker, arguments)

    stderr = " ".join(result.stderr.split())
    assert result.returncode == 5, result.stdout + result.stderr
    assert "Output directory is not a directory:" in stderr, result.stderr
    hinted = "pass -OutputDir to write elsewhere" in stderr
    assert hinted == (output == "the-default"), result.stderr
    assert not (tmp_path / "docker-args.txt").exists()


@pytest.mark.integration
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


@pytest.mark.integration
@pytest.mark.parametrize(
    "flag",
    ["--workspace /src/ash.code-workspace", "--workspace=/src/ash.code-workspace"],
    ids=["separate", "joined"],
)
def test_a_workspace_scan_is_refused(flag, pwsh, recording_docker, tmp_path):
    """Invoke-ASH scans one directory and hands the scan inside ``--source-dir
    /src``, which that scan refuses next to ``--workspace``, so it cannot run a
    workspace scan or mark a workspace's -Config. A --workspace passed through is
    refused with exit 3 before anything is built or mounted; the case that matters is
    a config in the checkout but outside the workspace."""
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / "ws" / "proj").mkdir(parents=True)
    config = repo / "other" / "ash-config.yaml"
    config.parent.mkdir()
    config.write_text("project_name: tier\n", encoding="utf-8")

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        f"-SourceDir repo/ws -OutputDir out -Config '{config.as_posix()}' {flag}",
    )

    assert result.returncode == 3, result.stdout + result.stderr
    assert not (tmp_path / "docker-args.txt").exists()
    assert "ash --mode container --workspace" in " ".join(result.stderr.split())


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


@pytest.mark.integration
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
    env = inherited_env("PATH", "ASH_CONFIG", "OCI_RUNNER_WRAPPER")
    env["PATH"] = os.pathsep.join(
        [on_path.parent.as_posix(), Path(pwsh).resolve().parent.as_posix()]
    )
    # pwsh's own HOME and caches, as in _invoke.
    env.update(scratch_home(tmp_path))
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


@pytest.mark.integration
@_POSIX_ONLY
def test_an_ash_config_file_outside_the_checkout_is_mounted_read_only(
    pwsh, recording_docker, checkout, tmp_path
):
    config = tmp_path / "operator" / "ash.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")

    args = _run_with_ash_config(pwsh, recording_docker, tmp_path, config)

    assert (
        _mount_at(args, "/ash-env-config/ash.yaml")
        == f"type=bind,source={config},destination=/ash-env-config/ash.yaml,readonly"
    )
    assert _values_of(args, "--config") == ["/ash-env-config/ash.yaml"]
    assert SCANNED_CHAIN_FLAG not in args
    assert SCANNED_FILE_FLAG not in args


@pytest.mark.integration
@_POSIX_ONLY
def test_an_ash_config_file_elsewhere_in_the_checkout_is_marked_as_the_repositorys(
    pwsh, recording_docker, checkout, tmp_path
):
    (checkout / "ci" / "ash.yaml").write_text("project_name: p\n", encoding="utf-8")

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        "-SourceDir repo/svc -OutputDir out",
        {"ASH_CONFIG": "repo/ci/ash.yaml"},
    )

    assert result.returncode == 0, result.stdout + result.stderr
    args = _recorded(tmp_path)
    assert _values_of(args, "--config") == ["/ash-env-config/ash.yaml"]
    assert _values_of(args, SCANNED_FILE_FLAG) == ["/ash-env-config/ash.yaml"]
    assert SCANNED_CHAIN_FLAG in args
    assert ELSEWHERE_FLAG not in args


@pytest.mark.integration
@_POSIX_ONLY
@pytest.mark.parametrize("layout", LINKS_IN_THE_SCANNED_CHECKOUT)
def test_an_ash_config_file_reached_through_a_link_in_the_scanned_checkout_is_marked(
    layout, pwsh, recording_docker, checkout, tmp_path
):
    """As a local scan treats it (config/sandbox_grants.links_followed), and as
    ./ash does: whoever wrote a link on the way chose the file the name resolves
    to, though neither the name given nor that file is in the scanned checkout. It is
    the scanned repository's, so it is not also marked as in another checkout; a link
    in some other checkout is marked as that (see the cells below)."""
    config = config_through_links(layout, checkout, tmp_path)

    args = _run_with_ash_config(pwsh, recording_docker, tmp_path, config)

    assert _values_of(args, "--config") == ["/ash-env-config/ash.yaml"]
    assert _values_of(args, SCANNED_FILE_FLAG) == ["/ash-env-config/ash.yaml"]
    assert SCANNED_CHAIN_FLAG in args
    assert ELSEWHERE_FLAG not in args


@pytest.mark.integration
@_POSIX_ONLY
def test_an_ash_config_file_reached_through_a_link_in_the_scanned_directory_is_marked(
    pwsh, recording_docker, tmp_path
):
    """Outside every checkout, the scanned directory is the scanned tree."""
    config = config_through_a_link_in(tmp_path / "pkg", tmp_path)

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        "-SourceDir pkg -OutputDir out",
        {"ASH_CONFIG": str(config)},
    )

    assert result.returncode == 0, result.stdout + result.stderr
    args = _recorded(tmp_path)
    assert _values_of(args, "--config") == ["/ash-env-config/ash.yaml"]
    assert _values_of(args, SCANNED_FILE_FLAG) == ["/ash-env-config/ash.yaml"]
    assert SCANNED_CHAIN_FLAG in args


@pytest.mark.integration
@_POSIX_ONLY
def test_an_ash_config_link_chain_outside_every_checkout_is_not_marked(
    pwsh, recording_docker, checkout, tmp_path
):
    """Control."""
    config = config_through_links(LINKS_OUTSIDE_EVERY_CHECKOUT, checkout, tmp_path)

    args = _run_with_ash_config(pwsh, recording_docker, tmp_path, config)

    assert _values_of(args, "--config") == ["/ash-env-config/ash.yaml"]
    assert SCANNED_CHAIN_FLAG not in args
    assert SCANNED_FILE_FLAG not in args
    assert ELSEWHERE_FLAG not in args


@pytest.mark.integration
@_POSIX_ONLY
def test_an_ash_config_file_reached_through_a_link_out_of_the_checkout_is_refused(
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
        "-SourceDir repo/svc -OutputDir out",
        {"ASH_CONFIG": "repo/linked/ash.yaml"},
    )

    assert result.returncode == 3, result.stdout + result.stderr
    assert _recorded(tmp_path) == []


@pytest.mark.integration
@_POSIX_ONLY
def test_an_ash_config_file_inside_the_source_is_read_through_src_with_no_mount(
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
        "-SourceDir repo/svc -OutputDir out",
        {"ASH_CONFIG": "repo/svc/.ash/ash.yaml"},
    )

    assert result.returncode == 0, result.stdout + result.stderr
    args = _recorded(tmp_path)
    assert _values_of(args, "--config") == ["/src/.ash/ash.yaml"]
    assert sorted(_mount_destinations(args)) == ["/out", "/src"]
    assert SCANNED_CHAIN_FLAG not in args
    assert SCANNED_FILE_FLAG not in args


# ---------------------------------------------------------------------------
# The ASH_CONFIG file, the one file Invoke-ASH mounts (-Config goes through as
# written): marked as ./ash and `ash --mode container` mark it
# ---------------------------------------------------------------------------

#: The mark for a file in a git checkout other than the scanned one
#: (run_ash_container.CONFIG_FILE_FROM_ANOTHER_CHECKOUT_FLAG).
ELSEWHERE_FLAG = "--config-file-from-another-checkout"
SCANNED_FILE_FLAG = "--config-file-from-scanned-repository"
SCANNED_CHAIN_FLAG = "--config-from-scanned-repository"


def _values_of(args: List[str], flag: str) -> List[str]:
    return [args[i + 1] for i, arg in enumerate(args[:-1]) if arg == flag]


def _run_with_ash_config(
    pwsh,
    recording_docker,
    tmp_path: Path,
    config,
    source: str = "repo/svc",
):
    """*config* is what ASH_CONFIG holds: a path, or the text of a relative name."""
    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        f"-SourceDir {source} -OutputDir out",
        {"ASH_CONFIG": str(config)},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return _recorded(tmp_path)


# ---------------------------------------------------------------------------
# -Config: handed to the scan as written, whatever the file is
# ---------------------------------------------------------------------------

#: Where an explicit -Config can point. The scan inside the container resolves the
#: value from /src, its working directory, so Invoke-ASH does not look at the file:
#: nothing is refused, mounted or marked for it, as it is for the file ASH_CONFIG
#: names (the cells around this block).
_EXPLICIT_CONFIG_SHAPES = [
    "a-file-that-does-not-exist",
    "outside-the-checkout",
    "with-an-extends-entry",
    "elsewhere-in-the-checkout",
    "inside-the-source",
    "link-in-the-source-out-of-the-tree",
    "directory-link-out-of-the-checkout",
    *LINKS_IN_THE_SCANNED_CHECKOUT,
    *LINKS_IN_ANOTHER_CHECKOUT,
    LINKS_OUTSIDE_EVERY_CHECKOUT,
]

#: Every option with which Invoke-ASH tells the scan about a config file it mounted.
_CONFIG_FILE_OPTIONS = (
    "--ash-config-from-host",
    ELSEWHERE_FLAG,
    SCANNED_FILE_FLAG,
    SCANNED_CHAIN_FLAG,
)


def _plant_an_explicit_config(shape: str, checkout: Path, tmp_path: Path) -> str:
    """Make *shape* under *tmp_path* and return the value to give -Config for it."""
    operator = tmp_path / "operator"
    plain = "project_name: p\n"
    if shape == "a-file-that-does-not-exist":
        return "missing.yaml"
    if shape == "outside-the-checkout":
        (operator / "ash.yaml").write_text(plain, encoding="utf-8")
        return str(operator / "ash.yaml")
    if shape == "with-an-extends-entry":
        (operator / "ash.yaml").write_text("extends: base.yaml\n", encoding="utf-8")
        return str(operator / "ash.yaml")
    if shape == "elsewhere-in-the-checkout":
        (checkout / "ci" / "ash.yaml").write_text(plain, encoding="utf-8")
        return "repo/ci/ash.yaml"
    if shape == "inside-the-source":
        (checkout / "svc" / ".ash").mkdir()
        (checkout / "svc" / ".ash" / "ash.yaml").write_text(plain, encoding="utf-8")
        return "repo/svc/.ash/ash.yaml"
    if shape == "link-in-the-source-out-of-the-tree":
        (operator / "ash.yaml").write_text(plain, encoding="utf-8")
        (checkout / "svc" / "ash.yaml").symlink_to(operator / "ash.yaml")
        return "repo/svc/ash.yaml"
    if shape == "directory-link-out-of-the-checkout":
        (operator / "ash.yaml").write_text(plain, encoding="utf-8")
        (checkout / "linked").symlink_to(operator, target_is_directory=True)
        return "repo/linked/ash.yaml"
    return str(config_through_links(shape, checkout, tmp_path))


@pytest.mark.integration
@_POSIX_ONLY
@pytest.mark.parametrize("shape", _EXPLICIT_CONFIG_SHAPES)
def test_an_explicit_config_reaches_the_scan_as_written(
    shape, pwsh, recording_docker, checkout, tmp_path
):
    """-Config is the scan's own --config, in the spelling the caller wrote. The scan
    resolves it from /src inside the container, so Invoke-ASH does not read the file:
    a name that is missing, that links out of the checkout or that holds an
    ``extends`` entry is not refused, nothing is mounted for it and no mark goes with
    it. The marks are for the file ASH_CONFIG names (the cells around this block)."""
    given = _plant_an_explicit_config(shape, checkout, tmp_path)

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        f"-SourceDir repo/svc -OutputDir out -Config '{given}'",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    args = _recorded(tmp_path)
    assert _values_of(args, "--config") == [given]
    assert sorted(_mount_destinations(args)) == ["/out", "/src"]
    for option in _CONFIG_FILE_OPTIONS:
        assert option not in args


@pytest.mark.integration
@_POSIX_ONLY
def test_an_ash_config_file_in_another_checkout_is_marked_as_such(
    pwsh, recording_docker, checkout, tmp_path
):
    """Not the scanned repository's, and not the operator's: it cannot grant, as on
    the host. The mark is the container path and nothing else."""
    mark_git_checkout(tmp_path / "ops")
    config = tmp_path / "ops" / "ash.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")

    args = _run_with_ash_config(pwsh, recording_docker, tmp_path, config)

    assert _values_of(args, "--ash-config-from-host") == ["/ash-env-config/ash.yaml"]
    assert _values_of(args, "--config") == ["/ash-env-config/ash.yaml"]
    assert _values_of(args, ELSEWHERE_FLAG) == ["/ash-env-config/ash.yaml"]
    assert SCANNED_FILE_FLAG not in args
    assert SCANNED_CHAIN_FLAG not in args
    assert [
        arg for arg in args if str(tmp_path / "ops") in arg and "source=" not in arg
    ] == []


@pytest.mark.integration
@_POSIX_ONLY
def test_an_ash_config_file_in_another_checkout_is_marked_beside_an_explicit_config(
    pwsh, recording_docker, checkout, tmp_path
):
    """-Config goes through as written, and the file ASH_CONFIG names is still the
    scan's base, so it is judged and marked whether or not -Config was given."""
    mark_git_checkout(tmp_path / "ops")
    config = tmp_path / "ops" / "ash.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        "-SourceDir repo/svc -OutputDir out -Config .ash/strict.yaml",
        {"ASH_CONFIG": str(config)},
    )

    assert result.returncode == 0, result.stdout + result.stderr
    args = _recorded(tmp_path)
    assert _values_of(args, "--config") == [".ash/strict.yaml"]
    assert _values_of(args, ELSEWHERE_FLAG) == ["/ash-env-config/ash.yaml"]


@pytest.mark.integration
@_POSIX_ONLY
@pytest.mark.parametrize("layout", LINKS_IN_ANOTHER_CHECKOUT)
def test_an_ash_config_file_reached_through_a_link_in_another_checkout_is_marked(
    layout, pwsh, recording_docker, checkout, tmp_path
):
    config = config_through_links(layout, checkout, tmp_path)

    args = _run_with_ash_config(pwsh, recording_docker, tmp_path, config)

    assert _values_of(args, ELSEWHERE_FLAG) == ["/ash-env-config/ash.yaml"]
    assert SCANNED_FILE_FLAG not in args


@pytest.mark.integration
@_POSIX_ONLY
@pytest.mark.parametrize(
    "shape",
    ["directory-with-head", "gitfile", "link-to-a-directory", "dangling-link"],
)
def test_each_shape_of_git_entry_that_counts_marks_the_ash_config_file(
    shape, pwsh, recording_docker, checkout, tmp_path
):
    """Shapes sandbox_grants._git_shaped counts as a checkout boundary."""
    ops = tmp_path / "ops"
    ops.mkdir()
    entry = ops / ".git"
    if shape == "directory-with-head":
        mark_git_checkout(ops)
    elif shape == "gitfile":
        entry.write_text("gitdir: ../repo/.git/worktrees/ops\n", encoding="utf-8")
    elif shape == "link-to-a-directory":
        mark_git_checkout(tmp_path / "gitdir-home")
        entry.symlink_to(tmp_path / "gitdir-home" / ".git", target_is_directory=True)
    else:
        entry.symlink_to(tmp_path / "nowhere")
    config = ops / "ash.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")

    args = _run_with_ash_config(pwsh, recording_docker, tmp_path, config)

    assert _values_of(args, ELSEWHERE_FLAG) == ["/ash-env-config/ash.yaml"]


@pytest.mark.integration
@_POSIX_ONLY
def test_an_ash_config_file_beside_an_empty_git_directory_is_not_marked(
    pwsh, recording_docker, checkout, tmp_path
):
    """Control: git would not open an empty .git, and neither does a local scan."""
    (tmp_path / "ops" / ".git").mkdir(parents=True)
    config = tmp_path / "ops" / "ash.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")

    args = _run_with_ash_config(pwsh, recording_docker, tmp_path, config)

    assert ELSEWHERE_FLAG not in args
    assert SCANNED_FILE_FLAG not in args
    assert _values_of(args, "--config") == ["/ash-env-config/ash.yaml"]


@pytest.mark.integration
@_POSIX_ONLY
def test_an_ash_config_file_beside_a_fifo_named_git_is_not_marked(
    pwsh, recording_docker, checkout, tmp_path
):
    """Control: a FIFO is not a gitfile. A local scan counts a regular file only, and
    so does ./ash."""
    (tmp_path / "ops").mkdir()
    os.mkfifo(tmp_path / "ops" / ".git")
    config = tmp_path / "ops" / "ash.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")

    args = _run_with_ash_config(pwsh, recording_docker, tmp_path, config)

    assert ELSEWHERE_FLAG not in args
    assert _values_of(args, "--config") == ["/ash-env-config/ash.yaml"]


@pytest.mark.integration
@_POSIX_ONLY
def test_an_ash_config_file_outside_every_checkout_is_not_marked(
    pwsh, recording_docker, checkout, tmp_path
):
    """Control."""
    config = tmp_path / "operator" / "ash.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")

    args = _run_with_ash_config(pwsh, recording_docker, tmp_path, config)

    assert ELSEWHERE_FLAG not in args
    assert SCANNED_FILE_FLAG not in args
    assert SCANNED_CHAIN_FLAG not in args


@pytest.mark.integration
@_POSIX_ONLY
def test_an_ash_config_file_in_the_scanned_checkout_is_not_marked_as_another(
    pwsh, recording_docker, checkout, tmp_path
):
    """Control: the scanned repository's file keeps its own mark alone.

    The repository's .git holds HEAD, so the judgment would count it a checkout if
    it ran on this file; the control fails when the file that already carries the
    scanned tree's mark is judged as well."""
    mark_git_checkout(checkout)
    (checkout / "ci" / "ash.yaml").write_text("project_name: p\n", encoding="utf-8")

    args = _run_with_ash_config(
        pwsh, recording_docker, tmp_path, checkout / "ci" / "ash.yaml"
    )

    assert _values_of(args, SCANNED_FILE_FLAG) == ["/ash-env-config/ash.yaml"]
    assert ELSEWHERE_FLAG not in args


@pytest.mark.integration
@_POSIX_ONLY
def test_a_checkout_in_a_directory_others_can_write_counts_for_its_owner(
    pwsh, recording_docker, checkout, tmp_path
):
    """sandbox_grants._left_by_a_trusted_user: in a directory group members or
    others can write, a .git counts when the scanning user owns it. Invoke-ASH reads
    the mode of the directory and the owners of both from the item itself."""
    ops = tmp_path / "ops"
    mark_git_checkout(ops)
    config = ops / "ash.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")
    ops.chmod(0o777)

    args = _run_with_ash_config(pwsh, recording_docker, tmp_path, config)

    assert _values_of(args, ELSEWHERE_FLAG) == ["/ash-env-config/ash.yaml"]


@pytest.mark.integration
@_POSIX_ONLY
def test_the_outermost_checkout_is_the_scanned_tree_when_checkouts_nest(
    pwsh, recording_docker, tmp_path
):
    """outer/.git and outer/svc/.git: the scanned tree is outer, as a local scan
    defines it, so a config in outer/ci is the repository's and not another
    checkout's."""
    outer = tmp_path / "outer"
    mark_git_checkout(outer)
    mark_git_checkout(outer / "svc")
    (outer / "ci").mkdir()
    config = outer / "ci" / "ash.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")

    args = _run_with_ash_config(
        pwsh, recording_docker, tmp_path, config, source="outer/svc"
    )

    assert _values_of(args, SCANNED_FILE_FLAG) == ["/ash-env-config/ash.yaml"]
    assert ELSEWHERE_FLAG not in args


@pytest.mark.integration
@_POSIX_ONLY
def test_an_ash_config_file_deep_below_the_checkout_root_is_marked(
    pwsh, recording_docker, checkout, tmp_path
):
    mark_git_checkout(tmp_path / "ops")
    config = tmp_path / "ops" / "conf" / "prod" / "ash.yaml"
    config.parent.mkdir(parents=True)
    config.write_text("project_name: p\n", encoding="utf-8")

    args = _run_with_ash_config(pwsh, recording_docker, tmp_path, config)

    assert _values_of(args, ELSEWHERE_FLAG) == ["/ash-env-config/ash.yaml"]


@pytest.mark.integration
@_POSIX_ONLY
@pytest.mark.parametrize("given", ["ops/ash.yaml", "operator/../ops/ash.yaml"])
def test_a_relative_ash_config_name_is_judged_from_the_working_directory(
    given, pwsh, recording_docker, checkout, tmp_path
):
    mark_git_checkout(tmp_path / "ops")
    (tmp_path / "ops" / "ash.yaml").write_text("project_name: p\n", encoding="utf-8")

    args = _run_with_ash_config(pwsh, recording_docker, tmp_path, given)

    assert _values_of(args, ELSEWHERE_FLAG) == ["/ash-env-config/ash.yaml"]
    assert SCANNED_FILE_FLAG not in args


@pytest.mark.integration
@_POSIX_ONLY
def test_an_ash_config_name_that_climbs_out_of_the_checkout_to_a_file_in_none_is_not_marked(
    pwsh, recording_docker, checkout, tmp_path
):
    """``repo/ci/../../operator/ash.yaml``: the directories above the name as spelled
    lead to the scanned checkout's .git, but each ``..`` is applied as the kernel
    applies it and the file is in the operator directory beside the checkout, in no
    checkout. Judged as text it would be marked as a file in another checkout; it
    is the operator's own."""
    mark_git_checkout(checkout)
    (tmp_path / "operator" / "ash.yaml").write_text(
        "project_name: p\n", encoding="utf-8"
    )

    args = _run_with_ash_config(
        pwsh, recording_docker, tmp_path, f"{checkout}/ci/../../operator/ash.yaml"
    )

    assert ELSEWHERE_FLAG not in args
    assert SCANNED_FILE_FLAG not in args
    assert SCANNED_CHAIN_FLAG not in args


@pytest.mark.integration
@_POSIX_ONLY
def test_an_ash_config_file_beside_a_git_directory_without_head_is_not_marked(
    pwsh, recording_docker, checkout, tmp_path
):
    """Control: git would not open a .git that holds no HEAD, and neither does a
    local scan."""
    (tmp_path / "ops" / ".git" / "objects").mkdir(parents=True)
    config = tmp_path / "ops" / "ash.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")

    args = _run_with_ash_config(pwsh, recording_docker, tmp_path, config)

    assert ELSEWHERE_FLAG not in args
    assert _values_of(args, "--config") == ["/ash-env-config/ash.yaml"]


@pytest.mark.integration
@_POSIX_ONLY
def test_a_checkout_reached_through_a_link_of_the_operators_own_is_marked(
    pwsh, recording_docker, checkout, tmp_path
):
    """The name goes through a link to the checkout: the directories above the name
    as spelled lead to the checkout's .git, and so do those of the real path."""
    mark_git_checkout(tmp_path / "ops")
    (tmp_path / "ops" / "ash.yaml").write_text("project_name: p\n", encoding="utf-8")
    (tmp_path / "alias").symlink_to(tmp_path / "ops", target_is_directory=True)

    args = _run_with_ash_config(
        pwsh, recording_docker, tmp_path, tmp_path / "alias" / "ash.yaml"
    )

    assert _values_of(args, ELSEWHERE_FLAG) == ["/ash-env-config/ash.yaml"]


@pytest.mark.integration
@_POSIX_ONLY
def test_a_name_outside_every_checkout_that_resolves_into_one_is_marked(
    pwsh, recording_docker, checkout, tmp_path
):
    """The file is the checkout's though the name given is not in it: the real path
    is judged as well as the name."""
    mark_git_checkout(tmp_path / "ops")
    (tmp_path / "ops" / "ash.yaml").write_text("project_name: p\n", encoding="utf-8")
    (tmp_path / "plain").mkdir()
    (tmp_path / "plain" / "cfg.yaml").symlink_to(tmp_path / "ops" / "ash.yaml")

    args = _run_with_ash_config(
        pwsh, recording_docker, tmp_path, tmp_path / "plain" / "cfg.yaml"
    )

    assert _values_of(args, ELSEWHERE_FLAG) == ["/ash-env-config/ash.yaml"]


@pytest.mark.integration
@_POSIX_ONLY
def test_a_dotdot_after_a_link_in_another_checkout_is_judged_from_the_link(
    pwsh, recording_docker, checkout, tmp_path
):
    """``ops/lnk/../x.yaml`` with ``lnk`` a link the checkout holds: the kernel
    follows the link before the ``..``, so the name reaches the file beside the
    link's target, outside the checkout. Neither that name as the kernel reads it
    nor the file is in the checkout; the link that chose the way is."""
    ops = tmp_path / "ops"
    mark_git_checkout(ops)
    far = tmp_path / "far"
    (far / "d").mkdir(parents=True)
    (far / "x.yaml").write_text("project_name: p\n", encoding="utf-8")
    (ops / "lnk").symlink_to(far / "d", target_is_directory=True)

    args = _run_with_ash_config(
        pwsh, recording_docker, tmp_path, f"{ops}/lnk/../x.yaml"
    )

    assert _values_of(args, ELSEWHERE_FLAG) == ["/ash-env-config/x.yaml"]


@pytest.mark.integration
@_POSIX_ONLY
@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason=(
        "recorded gap: a .git another user left needs chown, which needs root; a "
        "non-root run cannot plant that entry, so only a root run measures it"
    ),
)
def test_a_checkout_another_user_left_in_a_directory_others_can_write_does_not_count(
    pwsh, recording_docker, checkout, tmp_path
):
    """sandbox_grants._left_by_a_trusted_user, the other half of the cell above: in
    a directory group members or others can write, a .git counts only when root, the
    directory's owner or the scanning user left it. The scanning user's id comes from
    ``id -u``, which the PATH of this suite does not hold unless a test links it in."""
    _link_ls_and_id_into(recording_docker)
    ops = tmp_path / "ops"
    mark_git_checkout(ops)
    for entry in (ops / ".git" / "HEAD", ops / ".git"):
        os.chown(entry, 65534, 65534)
    config = ops / "ash.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")
    ops.chmod(0o777)

    args = _run_with_ash_config(pwsh, recording_docker, tmp_path, config)

    assert ELSEWHERE_FLAG not in args
    assert _values_of(args, "--config") == ["/ash-env-config/ash.yaml"]


@pytest.mark.integration
@_POSIX_ONLY
@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason=(
        "recorded gap: a .git another user left needs chown, which needs root; a "
        "non-root run cannot plant that entry, so only a root run measures it"
    ),
)
def test_a_git_link_another_user_left_in_a_directory_others_can_write_does_not_count(
    pwsh, recording_docker, checkout, tmp_path
):
    """The same rule for an entry that is a link, which counts before its type is
    looked at: the owner read is the link's own. A user id with no name in the
    passwd file is not the scanning user, root or the directory's owner either."""
    _link_ls_and_id_into(recording_docker)
    ops = tmp_path / "ops"
    ops.mkdir()
    gitdir = tmp_path / "gitdirs" / "ops.git"
    gitdir.mkdir(parents=True)
    (gitdir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (ops / ".git").symlink_to(gitdir, target_is_directory=True)
    os.lchown(ops / ".git", 3000000, 3000000)
    config = ops / "ash.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")
    ops.chmod(0o777)

    args = _run_with_ash_config(pwsh, recording_docker, tmp_path, config)

    assert ELSEWHERE_FLAG not in args
    assert _values_of(args, "--config") == ["/ash-env-config/ash.yaml"]


#: What a runtime older than .NET 7 lacks, written into a copy of the helpers: the
#: mode bits of an item (File.GetUnixFileMode, and the UnixMode text). Each pair is
#: replaced once, so a change to the helpers that moves one of them fails the first
#: assertion below instead of leaving a replacement that changes nothing. The owner
#: is read from the item's UnixStat (Get-AshOwnerId), never from its User name, and
#: is taken away on its own by ``_helpers_that_know_no_owner_ids``.
_ABSENT_PERMISSION_APIS = (
    (
        "[System.IO.File]::GetUnixFileMode($Path)",
        "[System.IO.File]::GetUnixFileModeAbsent($Path)",
    ),
    (
        "$item.PSObject.Properties['UnixMode']",
        "$item.PSObject.Properties['UnixModeAbsent']",
    ),
)


def _helpers_of_a_runtime_that_gives_no_permissions(tmp_path: Path) -> Path:
    text = HELPERS.read_text(encoding="utf-8")
    for present, absent in _ABSENT_PERMISSION_APIS:
        assert text.count(present) == 1, present
        text = text.replace(present, absent)
    copy = tmp_path / "old-runtime" / "utils" / "ash_helpers.ps1"
    copy.parent.mkdir(parents=True)
    copy.write_text(text, encoding="utf-8")
    return copy


def _link_ls_and_id_into(bin_dir: Path) -> None:
    for name in ("ls", "id"):
        found = shutil.which(name)
        assert found is not None, f"{name} is not on the path of this machine"
        (bin_dir / name).symlink_to(found)


@pytest.mark.integration
@_POSIX_ONLY
@pytest.mark.parametrize(
    "others_can_write", [False, True], ids=["private-directory", "writable-directory"]
)
def test_a_runtime_that_gives_no_permissions_asks_ls_and_id(
    others_can_write, pwsh, recording_docker, checkout, tmp_path
):
    """PowerShell 7.0 to 7.2 run on a .NET without File.GetUnixFileMode, and their
    items may carry no UnixMode. The wrapper then reads the mode of the .git entry's
    directory from ``ls -ldn``, as ./ash does, instead of refusing a checkout it
    could judge; the owners come from the items' UnixStat, or from ``ls`` and ``id``
    when that is absent too (the owner-id tests below)."""
    helpers = _helpers_of_a_runtime_that_gives_no_permissions(tmp_path)
    _link_ls_and_id_into(recording_docker)
    ops = tmp_path / "ops"
    mark_git_checkout(ops)
    config = ops / "ash.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")
    if others_can_write:
        ops.chmod(0o777)

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        "-SourceDir repo/svc -OutputDir out",
        {"ASH_CONFIG": str(config)},
        helpers=helpers,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert _values_of(_recorded(tmp_path), ELSEWHERE_FLAG) == [
        "/ash-env-config/ash.yaml"
    ]


@pytest.mark.integration
@_POSIX_ONLY
def test_a_runtime_that_gives_no_permissions_and_has_no_ls_refuses(
    pwsh, recording_docker, checkout, tmp_path
):
    """The same layout with neither ls nor id on the path: the wrapper cannot say
    whether a local scan would count the file as in another checkout, and an unmarked
    file is read inside as the operator's, so it refuses with the code of any other
    refusal and starts nothing. Also the control that the copy of the helpers does
    take the .NET and the item permissions away: with them, the mark would be sent
    here without ls."""
    helpers = _helpers_of_a_runtime_that_gives_no_permissions(tmp_path)
    search_path = os.pathsep.join(
        [recording_docker.as_posix(), Path(pwsh).resolve().parent.as_posix()]
    )
    if shutil.which("ls", path=search_path) or shutil.which("id", path=search_path):
        pytest.skip("ls or id sits beside pwsh here, so the path cannot be without it")
    ops = tmp_path / "ops"
    mark_git_checkout(ops)
    config = ops / "ash.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        "-SourceDir repo/svc -OutputDir out",
        {"ASH_CONFIG": str(config)},
        helpers=helpers,
    )

    assert result.returncode == 3, result.stdout + result.stderr
    assert not (tmp_path / "docker-args.txt").exists()
    message = " ".join(result.stderr.split())
    assert "could not be judged" in message
    assert "cannot be read here" in message


def _helpers_that_know_no_owner_ids(tmp_path: Path) -> Path:
    """The helpers of a runtime that gives no permissions (above), without the item's
    ``UnixStat`` either, so the owners of a ``.git`` entry and of its directory come
    from ``ls`` and ``id`` alone."""
    copy = _helpers_of_a_runtime_that_gives_no_permissions(tmp_path)
    text = copy.read_text(encoding="utf-8")
    present = "$item.PSObject.Properties['UnixStat']"
    assert text.count(present) == 1, present
    copy.write_text(
        text.replace(present, "$item.PSObject.Properties['UnixStatAbsent']"),
        encoding="utf-8",
    )
    return copy


def _stub_ls_and_id(
    bin_dir: Path, *, holder_owner: int, entry_owner: int, current: int
) -> None:
    """An ``ls`` that lists every directory as one others can write and owned by
    *holder_owner*, and every entry as owned by *entry_owner*, and an ``id`` that
    names *current* as the user running the scan."""
    ls = bin_dir / "ls"
    ls.write_text(
        "#!/bin/sh\n"
        'case "$1" in\n'
        f'  -Ldn) echo "drwxrwxrwx 2 {holder_owner} {holder_owner} 4096 Jan 1 00:00 $3" ;;\n'
        f'  -ldn) echo "drwxr-xr-x 3 {entry_owner} {entry_owner} 4096 Jan 1 00:00 $3" ;;\n'
        "  *) exit 1 ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    ls.chmod(0o755)
    ident = bin_dir / "id"
    ident.write_text(f"#!/bin/sh\necho {current}\n", encoding="utf-8")
    ident.chmod(0o755)


@pytest.mark.integration
@_POSIX_ONLY
@pytest.mark.parametrize(
    ("entry_owner", "marked"),
    [(4242, False), (1000, True), (1001, True), (0, True)],
    ids=["a-stranger", "the-scanning-user", "the-directorys-owner", "root"],
)
def test_a_git_entry_in_a_directory_others_can_write_counts_by_who_left_it(
    entry_owner, marked, pwsh, recording_docker, checkout, tmp_path
):
    """In a directory group members or others can write, a .git entry counts only
    when root, the directory's owner or the user running the scan left it, by the
    numeric ids ``ls`` and ``id`` give. Here the scanning user is 1000 and the
    directory belongs to 1001; no name is involved."""
    helpers = _helpers_that_know_no_owner_ids(tmp_path)
    _stub_ls_and_id(
        recording_docker, holder_owner=1001, entry_owner=entry_owner, current=1000
    )
    ops = tmp_path / "ops"
    mark_git_checkout(ops)
    config = ops / "ash.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        "-SourceDir repo/svc -OutputDir out",
        {"ASH_CONFIG": str(config)},
        helpers=helpers,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    args = _recorded(tmp_path)
    if marked:
        assert _values_of(args, ELSEWHERE_FLAG) == ["/ash-env-config/ash.yaml"]
    else:
        assert ELSEWHERE_FLAG not in args
    assert _values_of(args, "--config") == ["/ash-env-config/ash.yaml"]


@pytest.mark.integration
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


@pytest.mark.integration
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


@pytest.mark.integration
@pytest.mark.parametrize(
    ("arguments", "extra_env"),
    [
        pytest.param("-SourceDir src -OutputDir 'a,b'", None, id="unmountable-output"),
        pytest.param(
            "-SourceDir src -OutputDir out", {"ASH_CONFIG": "missing.yaml"}, id="config"
        ),
    ],
)
def test_a_build_without_a_run_checks_nothing_it_would_mount(
    arguments, extra_env, pwsh, recording_docker, tmp_path
):
    """-NoRun mounts nothing, so neither the mount paths nor the ASH_CONFIG file are
    checked."""
    (tmp_path / "src").mkdir()

    result = _invoke(pwsh, tmp_path, recording_docker, f"-NoRun {arguments}", extra_env)

    assert result.returncode == 0, result.stdout + result.stderr
