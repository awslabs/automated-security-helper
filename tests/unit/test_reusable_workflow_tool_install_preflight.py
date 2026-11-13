# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An ASH too old for the tool-install steps must be named before they fail.

Why this file exists
--------------------
The reusable workflow installs grype, syft and OpenGrep with
`ash dependencies install --tool`, and its install-* inputs default to true. ASH
v3.7.0 and v3.7.1 have no `--tool` option. A caller that pins either one, as
`ash-version: v3.7.0` or `v3` (which points at 3.7.1) does, would fail at "Install Grype"
with click's "No such option: --tool", which names neither the input that chose the
ASH nor the inputs that asked for the installs.

So a preflight step asks that ASH's `ash dependencies install --help` for `--tool`
and, when it is absent, fails with a message naming ash-version and the three
install inputs. It fails rather than turning the installs off with a notice: on
3.7.0 and 3.7.1 `ash scan` does not fail on a MISSING scanner, so skipping the
installs would turn the default request into a green scan without three scanners.

What is asserted
----------------
The step runs when any of install-grype, install-syft or install-opengrep is on and
not otherwise; it comes after uv is set up and before every step that runs
`ash dependencies install`; and its shell, run against a stand-in `uvx` that prints
each help text, passes for help that lists `--tool` (plain, and split by the color
codes rich prints) and fails, with that message, for help that lacks it and for an
ASH with no `ash dependencies install` at all.
"""

from __future__ import annotations

import itertools
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from tests.utils.github_expressions import evaluate
from tests.utils.workflow_one_line import (
    COMMAND_TEXT,
    COMMAND_TEXT_SHOWN,
    honored_commands,
    write_helper,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "run-ash-security-scan.yml"
STEP_ID = "install-preflight"
INSTALLS = ("install-grype", "install-syft", "install-opengrep")


def _steps() -> list[dict]:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["ash"]["steps"]


def _step() -> dict:
    (step,) = [step for step in _steps() if step.get("id") == STEP_ID]
    return step


@pytest.mark.unit
@pytest.mark.parametrize(
    "values", list(itertools.product([True, False], repeat=3)), ids=str
)
def test_the_check_runs_when_any_tool_install_is_on(values):
    context = {f"inputs.{name}": value for name, value in zip(INSTALLS, values)}

    assert evaluate(_step()["if"], context, "success") is any(values)


@pytest.mark.unit
def test_the_check_comes_after_uv_and_before_every_tool_install():
    steps = _steps()
    order = [step.get("id") or step.get("name") for step in steps]
    check = order.index(STEP_ID)
    installs = [
        index
        for index, step in enumerate(steps)
        if "ash dependencies install" in str(step.get("run", ""))
        and step.get("id") != STEP_ID
    ]

    assert installs, "no step runs ash dependencies install"
    assert order.index("setup-uv") < check < min(installs)


MODERN_HELP = (
    " Usage: ash dependencies install [OPTIONS]\n"
    " --bin-path  -b  <str>  Where to install the binaries\n"
    " --tool      -T  <str>  Install dependencies for these tools only\n"
)
# rich, which typer prints help with, colors each dash separately, so the raw text
# holds no "--tool" at all.
RICH_HELP = (
    " Usage: ash dependencies install [OPTIONS]\n"
    " \x1b[1;36m-\x1b[0m\x1b[1;36m-tool\x1b[0m  \x1b[1;32m-T\x1b[0m  <str>  Install\n"
)
OLD_HELP = (
    " Usage: ash dependencies install [OPTIONS]\n"
    " --bin-path  -b  <str>  Where to install the binaries\n"
)


# v3.7.1 appended rather than written out, so the repository's walk for stale
# install references does not read this stand-in as one a user would follow.
SOURCE = (
    "automated-security-helper[cdk] @ "
    "git+https://github.com/awslabs/automated-security-helper" + "@v3.7.1"
)


def _run(
    tmp_path: Path,
    help_text: str,
    status: int = 0,
    source: str = SOURCE,
    stderr_text: str = "",
    od_fails: bool = False,
):
    """Run the step against a uvx that prints ``help_text`` on stdout, then
    ``stderr_text`` on stderr, where click writes a usage error, and exits
    ``status``. With ``od_fails``, with_commands_stopped cannot read a token, so
    it runs nothing."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    if od_fails:
        (bin_dir / "od").write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        (bin_dir / "od").chmod(0o755)
    (tmp_path / "help.txt").write_text(help_text, encoding="utf-8")
    (tmp_path / "stderr.txt").write_text(stderr_text, encoding="utf-8")
    argv_file = tmp_path / "argv.txt"
    uvx = bin_dir / "uvx"
    # NUL-separated, so an argument holding a line break reads back whole.
    uvx.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\0" "$@" > "{argv_file}"\n'
        f'cat "{tmp_path / "help.txt"}"\n'
        f'cat "{tmp_path / "stderr.txt"}" >&2\n'
        f"exit {status}\n",
        encoding="utf-8",
    )
    uvx.chmod(0o755)
    steps = _steps()
    # The job's definer runs before this step does, into the same RUNNER_TEMP.
    runner_temp = tmp_path / "runner_temp"
    write_helper(steps, runner_temp)
    step = _step()
    result = subprocess.run(
        [shutil.which("bash") or "bash", "-e", "-o", "pipefail", "-c", step["run"]],
        env={
            "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            "RUNNER_TEMP": str(runner_temp),
            "ASH_UVX_SOURCE": source,
            **{k: str(v) for k, v in (step.get("env") or {}).items()},
        },
        capture_output=True,
        text=True,
        check=False,
    )
    if od_fails:
        assert not argv_file.exists(), "uvx ran without a stop-commands window"
        return result
    # Bytes, decoded by hand: read_text would turn a carriage return into a line feed.
    argv = argv_file.read_bytes().decode("utf-8").split("\0")[:-1]
    assert argv == ["--from", source, "ash", "dependencies", "install", "--help"]
    return result


@pytest.mark.integration
@pytest.mark.skipif(os.name == "nt", reason="runs the step's bash script")
def test_a_check_that_could_not_run_uvx_ends_with_the_helpers_error(tmp_path):
    """with_commands_stopped returns 1 without running uvx when it cannot make a
    token. That is not uvx's answer, so the step ends there, with the helper's
    error as its only one, rather than diagnosing an ASH it never ran."""
    result = _run(tmp_path, MODERN_HELP, od_fails=True)

    output = result.stdout + result.stderr
    assert result.returncode != 0, output
    (line,) = honored_commands(output)
    assert line.startswith("::error::no random token could be read"), line


posix_only = pytest.mark.skipif(
    os.name == "nt",
    reason="runs the step's bash script, which the workflow runs on Linux",
)


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize("help_text", [MODERN_HELP, RICH_HELP], ids=["plain", "rich"])
def test_an_ash_with_the_tool_option_passes(tmp_path, help_text):
    result = _run(tmp_path, help_text)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "::error::" not in result.stdout + result.stderr


#: click's usage error for an ASH with no `ash dependencies install`. click writes
#: it to stderr, so the step must read stderr as well as stdout.
NO_COMMAND = "Error: No such command 'dependencies'.\n"


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize(
    "help_text, status, stderr_text",
    [(OLD_HELP, 0, ""), ("", 2, NO_COMMAND), (NO_COMMAND, 2, "")],
    ids=["no-tool-option", "no-command", "no-command-on-stdout"],
)
def test_an_ash_without_it_fails_naming_the_inputs(
    tmp_path, help_text, status, stderr_text
):
    result = _run(tmp_path, help_text, status, stderr_text=stderr_text)

    output = result.stdout + result.stderr
    assert result.returncode != 0, output
    assert "::error::" in output
    for name in ("ash-version", *INSTALLS):
        assert name in output, (name, output)


@pytest.mark.integration
@posix_only
def test_an_ash_that_cannot_be_run_shows_why(tmp_path):
    """uv's own error is the diagnosis; the --tool message would be a wrong one.

    A mistyped ash-version makes uv fail to fetch the ref. The step prints uv's
    message, not only "has no 'ash dependencies install --tool'", which would send
    the caller to the install inputs.
    """
    marker = "fatal: couldn't find remote ref v3.8.O"
    result = _run(
        tmp_path,
        f"  Updating https://github.com/awslabs/automated-security-helper (v3.8.O)\n"
        f"error: Git operation failed\n  Caused by: {marker}\n",
        status=2,
    )

    output = result.stdout + result.stderr
    assert result.returncode != 0, output
    assert marker in output, output
    assert "::error::" in output
    assert "ash dependencies install --tool" not in output, output
    assert "ash-version" in output, output


@pytest.mark.integration
@posix_only
def test_a_refused_command_line_still_shows_uvs_output(tmp_path):
    """An ASH without the command: its own message is printed with the diagnosis."""
    result = _run(tmp_path, "", status=2, stderr_text=NO_COMMAND)

    output = result.stdout + result.stderr
    assert "No such command 'dependencies'" in output, output
    assert "ash dependencies install --tool" in output, output


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize(
    "help_text, status, message",
    [
        ("error: Git operation failed\n", 2, "::error::Could not install or start"),
        (OLD_HELP, 0, "::error::The ASH this workflow installs ("),
        ("Error: No such command 'dependencies'.\n", 2, "::error::The ASH this"),
    ],
    ids=["cannot-run", "no-tool-option", "no-command"],
)
def test_the_source_cannot_add_a_workflow_command(tmp_path, help_text, status, message):
    """Every line that prints ASH_UVX_SOURCE prints it through one_line.

    This step does not check the value; the step that wrote it did. So a line break
    or `::` in it would start a command of its own here, in the error line or in the
    plain line that names the uvx command.
    """
    source = SOURCE + COMMAND_TEXT
    result = _run(tmp_path, help_text, status, source=source)

    output = result.stdout + result.stderr
    assert result.returncode != 0, output
    (line,) = honored_commands(output)
    assert line.startswith(message), line
    assert COMMAND_TEXT_SHOWN in line, "the value must be shown, not dropped"


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize(
    "status, message",
    [(2, "::error::Could not install or start"), (0, "::error::The ASH this")],
    ids=["cannot-run", "no-tool-option"],
)
def test_uvs_output_starts_no_command(tmp_path, status, message):
    """uv's own words are shown as the diagnosis, inside a stop-commands region.

    uv prints what it was given and what it fetched, so a `::` line there would be a
    command of its own. The token is made for the run, so that output cannot end
    the region early.
    """
    output_from_uv = "error: failed\n::warning::from-uv\n##[warning]from-uv\n"
    result = _run(tmp_path, output_from_uv + ("" if status else OLD_HELP), status)

    output = result.stdout + result.stderr
    assert result.returncode != 0, output
    if status:
        assert "::warning::from-uv" in output, "uv's output must still be shown"
    (line,) = honored_commands(output)
    assert line.startswith(message), line


@pytest.mark.integration
@posix_only
def test_each_run_makes_its_own_stop_token(tmp_path):
    """Every window gets its own token: the capture of uvx's output and the copy
    of its last lines, in each run."""
    tokens = []
    for attempt in ("a", "b"):
        run_dir = tmp_path / attempt
        run_dir.mkdir()
        result = _run(run_dir, "error: failed\n", 2)
        run_tokens = [
            line.split("::stop-commands::", 1)[1]
            for line in (result.stdout + result.stderr).splitlines()
            if line.startswith("::stop-commands::")
        ]
        assert run_tokens, result.stdout + result.stderr
        tokens += run_tokens
    assert len(set(tokens)) == len(tokens), tokens
    assert all(len(token) >= 32 for token in tokens), tokens


@pytest.mark.unit
def test_uvx_runs_only_with_commands_stopped():
    """What uvx prints comes from the network and the fetched ASH, so it runs
    through with_commands_stopped, as every tool the workflow runs does. Its
    output is captured there, not with `$(...)`."""
    lines = [
        line.strip()
        for line in _step()["run"].replace("\\\n", " ").splitlines()
        if not line.lstrip().startswith("#")
        and re.search(r"(?<![\w-])uvx\s", line)
        and not line.lstrip().startswith("echo ")
    ]

    assert lines, "control: the step runs uvx"
    assert all("with_commands_stopped --capture help " in line for line in lines), lines
    assert all("$(uvx" not in line for line in lines), lines


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize(
    "help_text, status, stderr_text",
    [
        (MODERN_HELP + "::warning::from-help\n", 0, "##[warning]from-help\n"),
        ("::warning::from-help\n", 2, NO_COMMAND + "##[warning]from-help\n"),
    ],
    ids=["passes", "no-command"],
)
def test_what_uvx_prints_is_never_read_as_a_command(
    tmp_path, help_text, status, stderr_text
):
    """Neither stream of uvx's output reaches the log as commands: a passing
    check prints none of it, and a failing one shows it inside a window."""
    result = _run(tmp_path, help_text, status, stderr_text=stderr_text)

    output = result.stdout + result.stderr
    acted_on = honored_commands(output)
    if status == 0:
        assert result.returncode == 0, output
        assert acted_on == [], acted_on
        assert "from-help" not in output, "a passing check prints none of uvx's output"
    else:
        assert result.returncode != 0, output
        assert "from-help" in output, "a failing check shows uvx's output"
        (line,) = acted_on
        assert line.startswith("::error::The ASH this workflow installs ("), line
