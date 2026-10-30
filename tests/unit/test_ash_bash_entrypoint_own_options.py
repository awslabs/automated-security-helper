# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`./ash` reads its own options in both spellings and keeps the scan's words.

The wrapper's value options (--source-dir, --output-dir, --oci-runner and the CLI's
--oci and --runner aliases, --build-target, --container-uid, --container-gid,
--offline-semgrep-rulesets, --ash-revision) take `--opt value` and `--opt=value`, as
the CLI inside the container does. `-v` is the CLI's --verbose, not the wrapper's
--version, so `./ash scan -v` scans. `--help` and `--version` run the CLI from the
wrapper's own directory, not the caller's, so a package planted in a scanned checkout
is not what runs. The script's own directory is read with CDPATH unset, and the
container is run with its stdin open when the caller's stdin is a pipe or a file.

A fake OCI runner stands in for docker, as in
test_ash_bash_entrypoint_container_inputs.py, and records each call's argv
NUL-separated. Bash-wrapper tests are integration tier (tests/NAMING_CONVENTIONS.md).
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import threading
from pathlib import Path
from typing import Dict, List, Optional

import pytest

from tests.utils.host_ids import with_fixed_ids

REPO_ROOT = Path(__file__).resolve().parents[2]
ASH_SCRIPT = REPO_ROOT / "ash"
IMAGE = "automated-security-helper:non-root"
SANDBOX_OFF = ["--sandbox", "off"]

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.name == "nt",
        reason="bash on Windows runners is the WSL stub; ./ash is the POSIX entrypoint",
    ),
    pytest.mark.skipif(
        shutil.which("bash") is None, reason="the entrypoint under test is bash"
    ),
    pytest.mark.skipif(
        not ASH_SCRIPT.is_file(),
        reason="repository ash entrypoint not present (installed-package layout)",
    ),
]

# Records each call's arguments, NUL-separated, in the next numbered file under
# $FAKE_RUNNER_LOG_DIR. A build fails when BUILD_FAILS is set, so a test that only
# needs the build's argv never reaches the run step.
RECORDING_RUNNER = """#!/bin/bash
count=$(find "$FAKE_RUNNER_LOG_DIR" -type f | wc -l)
printf '%s\\0' "$@" > "$FAKE_RUNNER_LOG_DIR/$(printf '%03d' "$count")"
if [ "$1" = build ] && [ -n "${BUILD_FAILS:-}" ]; then
  echo 'fake runner: refusing to build, argv recorded' >&2
  exit 1
fi
exit 0
"""

# The runner the environment names: a test that passes another on the command line
# expects this one never to run.
GUARD_RUNNER = """#!/bin/bash
echo "GUARD-RUNNER-RAN: $*" >&2
exit 99
"""

#: Environment that would change the wrapper's commands if the suite itself runs in
#: a CI job that exported it.
_SCRUBBED_ENV = (
    "CI",
    "ASH_IMAGE_NAME",
    "OCI_RUNNER",
    "OCI_RUNNER_WRAPPER",
    "ASH_BASE_OCI_LAYOUT",
    "ASH_BASE_IMAGE_OVERRIDE",
    "DOCKER_EXTRA_ARGS",
    "ASH_CONFIG",
    "CDPATH",
)


def _executable(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
    return path


@pytest.fixture
def runner(tmp_path):
    """The recording runner and the directory its calls land in."""
    log_dir = tmp_path / "runner-calls"
    log_dir.mkdir()
    return _executable(tmp_path / "bin" / "fake-oci-runner", RECORDING_RUNNER), log_dir


@pytest.fixture
def guard(tmp_path):
    return _executable(tmp_path / "bin" / "guard-runner", GUARD_RUNNER)


def _calls(log_dir: Path) -> List[List[str]]:
    calls = []
    for record in sorted(log_dir.iterdir()):
        calls.append(record.read_bytes().decode("utf-8").split("\0")[:-1])
    return calls


def _run(
    runner,
    args: List[str],
    *,
    cwd: Optional[Path] = None,
    env: Optional[Dict[str, str]] = None,
    script: Optional[str] = None,
    stdin=subprocess.DEVNULL,
    stdout=subprocess.PIPE,
):
    """Run ./ash against the recording runner: (result, calls).

    stdout is captured unless a caller hands in its own (a pseudo-terminal, to
    make the wrapper see a terminal there); stderr is always captured."""
    program, log_dir = runner
    environment = with_fixed_ids(
        {k: v for k, v in os.environ.items() if k not in _SCRUBBED_ENV},
        log_dir.parent / "fixed-id-bin",
    )
    environment.update(
        {"OCI_RUNNER": str(program), "FAKE_RUNNER_LOG_DIR": str(log_dir)}
    )
    environment.update(env or {})
    result = subprocess.run(  # nosec B603 B607 - fixed script path, list args, no shell
        ["bash", script or str(ASH_SCRIPT), *args],
        stdout=stdout,
        stderr=subprocess.PIPE,
        text=True,
        cwd=str(cwd or REPO_ROOT),
        env=environment,
        stdin=stdin,
        timeout=180,
        check=False,
    )
    return result, _calls(log_dir)


def _only_run(calls: List[List[str]], shown: str) -> List[str]:
    runs = [call for call in calls if call[:1] == ["run"]]
    assert len(runs) == 1, f"expected one run call, got {calls}\n{shown}"
    return runs[0]


def _mounts(run: List[str]) -> Dict[str, Dict[str, str]]:
    """The run's --mount values, keyed by destination."""
    mounts = {}
    for at, word in enumerate(run):
        if word == "--mount":
            fields = dict(part.partition("=")[::2] for part in run[at + 1].split(","))
            mounts[fields["destination"]] = fields
    return mounts


def _inner(run: List[str], image: str = IMAGE) -> List[str]:
    assert image in run, f"the image name {image!r} is not one argument in {run}"
    return run[run.index(image) + 1 :]


def _runner_options(run: List[str], image: str = IMAGE) -> List[str]:
    assert image in run, f"the image name {image!r} is not one argument in {run}"
    return run[1 : run.index(image)]


def _dirs(tmp_path: Path):
    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    return source, tmp_path / "out"


def test_the_equals_spelling_of_the_wrappers_own_value_options(runner, tmp_path):
    """--source-dir=X, --output-dir=X and --build-target=X are the wrapper's own.

    At the base only the spaced form was read: the three words fell through to the
    scan inside the container, the working directory was mounted at /src and the
    default stage's image ran.
    """
    source, out = _dirs(tmp_path)
    result, calls = _run(
        runner,
        [
            "--no-build",
            f"--source-dir={source}",
            f"--output-dir={out}",
            "--build-target=ci",
            "--scanners",
            "bandit",
        ],
    )
    shown = result.stdout + result.stderr
    assert result.returncode == 0, shown
    run = _only_run(calls, shown)
    image = "automated-security-helper:ci"
    mounts = _mounts(run)
    assert Path(mounts["/src"]["source"]).resolve() == source.resolve(), run
    assert Path(mounts["/out"]["source"]).resolve() == out.resolve(), run
    assert _inner(run, image) == ["ash", *SANDBOX_OFF, "--scanners", "bandit"], run


@pytest.mark.parametrize(
    "spelling",
    [
        pytest.param(["--oci-runner={runner}"], id="oci-runner-equals"),
        pytest.param(["--oci", "{runner}"], id="oci"),
        pytest.param(["--oci={runner}"], id="oci-equals"),
        pytest.param(["--runner", "{runner}"], id="runner"),
        pytest.param(["--runner={runner}"], id="runner-equals"),
    ],
)
def test_the_runner_option_in_every_spelling_names_the_wrappers_runner(
    runner, guard, tmp_path, spelling
):
    """--oci and --runner are the CLI's aliases of --oci-runner; the wrapper takes
    them, and the = spelling, as its own. At the base they reached the scan inside
    while the wrapper ran the runner the environment named."""
    source, out = _dirs(tmp_path)
    program, _ = runner
    words = [word.format(runner=program) for word in spelling]
    result, calls = _run(
        runner,
        ["--no-build", "--source-dir", str(source), "--output-dir", str(out), *words],
        env={"OCI_RUNNER": str(guard)},
    )
    shown = result.stdout + result.stderr
    assert result.returncode == 0, shown
    assert "GUARD-RUNNER-RAN" not in shown, shown
    run = _only_run(calls, shown)
    assert _inner(run) == ["ash", *SANDBOX_OFF], run


@pytest.mark.parametrize(
    "word, option",
    [
        pytest.param("--source-dir=", "--source-dir", id="source-dir"),
        pytest.param("--oci-runner=", "--oci-runner", id="oci-runner"),
        pytest.param("--build-target= ", "--build-target", id="build-target-blank"),
    ],
)
def test_an_equals_spelling_with_no_value_is_refused(runner, tmp_path, word, option):
    source, out = _dirs(tmp_path)
    result, calls = _run(
        runner,
        ["--no-build", "--source-dir", str(source), "--output-dir", str(out), word],
    )
    # The usage error the CLI exits 5 for: an option that requires an argument.
    assert result.returncode == 5, result.stdout + result.stderr
    assert f"ERROR: {option} needs a value." in result.stderr, result.stderr
    assert calls == []


def test_dash_v_is_the_scans_verbose_not_the_wrappers_version(runner, tmp_path):
    """`./ash scan -v` scans, verbosely. At the base -v anywhere on the line printed
    a version and exited 0 before anything was built or run."""
    source, out = _dirs(tmp_path)
    result, calls = _run(
        runner,
        [
            "--no-build",
            "--source-dir",
            str(source),
            "--output-dir",
            str(out),
            "scan",
            "-v",
        ],
    )
    shown = result.stdout + result.stderr
    assert result.returncode == 0, shown
    run = _only_run(calls, shown)
    assert _inner(run) == ["ash", "scan", *SANDBOX_OFF, "-v"], run


@pytest.mark.skipif(
    shutil.which("python") is None, reason="./ash --version runs python"
)
def test_the_long_version_option_is_still_the_wrappers_own(runner, tmp_path):
    source, out = _dirs(tmp_path)
    result, calls = _run(
        runner,
        [
            "--no-build",
            "--source-dir",
            str(source),
            "--output-dir",
            str(out),
            "--version",
        ],
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert calls == [], "the version is printed on the host; no image is built or run"


@pytest.mark.skipif(shutil.which("python") is None, reason="./ash --help runs python")
def test_help_runs_the_wrappers_own_cli_not_a_package_in_the_working_directory(
    runner, tmp_path
):
    """`python -m` puts the working directory first on sys.path. Run from a checkout
    that holds a package under the CLI's name, --help imported that package at the
    base; it now runs from the wrapper's own directory."""
    planted = tmp_path / "checkout" / "automated_security_helper" / "cli"
    planted.mkdir(parents=True)
    (planted.parent / "__init__.py").write_text("", encoding="utf-8")
    (planted / "__init__.py").write_text("", encoding="utf-8")
    (planted / "main.py").write_text(
        "import sys\nprint('PLANTED-PACKAGE-RAN')\nsys.exit(7)\n", encoding="utf-8"
    )
    result, calls = _run(runner, ["--help"], cwd=tmp_path / "checkout")
    shown = result.stdout + result.stderr
    assert "PLANTED-PACKAGE-RAN" not in shown, shown
    assert result.returncode == 0, shown
    assert calls == []


def test_the_scripts_directory_is_read_with_cdpath_unset(runner, tmp_path):
    """With CDPATH exported, `cd` searches its entries for a relative directory whose
    first component is not "." or "..", and prints the directory it went to. Invoked as
    `utils/../ash` from the repository, the script's directory is `utils/..`; with a
    CDPATH entry that holds a `utils` of its own, the base went to that entry and the
    root directory held its path twice on two lines, so the build got a Dockerfile
    path and a context with a newline in them. (`./ash` and `ash` give "." and are
    never searched, so they cannot show this.)"""
    source, out = _dirs(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "utils").mkdir(parents=True)
    result, calls = _run(
        runner,
        ["--source-dir", str(source), "--output-dir", str(out)],
        cwd=REPO_ROOT,
        script="utils/../ash",
        env={"CDPATH": str(elsewhere), "BUILD_FAILS": "1"},
    )
    shown = result.stdout + result.stderr
    builds = [call for call in calls if call[:1] == ["build"]]
    assert len(builds) == 1, f"expected one build call, got {calls}\n{shown}"
    build = builds[0]
    dockerfile = Path(build[build.index("--file") + 1])
    assert dockerfile.resolve() == REPO_ROOT / "Dockerfile", build
    assert Path(build[-1]).resolve() == REPO_ROOT, build
    assert not any("\n" in word for word in build), build


def test_the_containers_stdin_is_kept_open_for_piped_input(runner, tmp_path):
    """An MCP client drives `./ash mcp` over stdin: without -i the container got no
    input. Here stdin is not a terminal (a file), so the container's stdin is kept
    open."""
    source, out = _dirs(tmp_path)
    result, calls = _run(
        runner,
        ["--no-build", "--source-dir", str(source), "--output-dir", str(out), "mcp"],
        stdin=subprocess.DEVNULL,
    )
    shown = result.stdout + result.stderr
    assert result.returncode == 0, shown
    run = _only_run(calls, shown)
    options = _runner_options(run)
    assert "-i" in options, options
    # Captured stdout is not a terminal, so no pseudo-terminal is asked for.
    assert "-t" not in options, options
    assert _inner(run) == ["ash", "mcp"], run


def test_a_terminal_stdin_does_not_keep_the_containers_stdin_open(runner, tmp_path):
    """`./ash scan &` from an interactive shell: the terminal is on stdin AND stdout.
    With -i the runner reads the terminal and the background job stops on that read,
    so a terminal stdin gets no -i, whatever stdout is. The terminal is a real
    pseudo-terminal on both ends, which is the shape the earlier `[ -t 1 ]` arm
    gave -i to; a captured stdout would not tell the two apart. The runner's options
    come from the recording runner's log, not from the wrapper's output."""
    source, out = _dirs(tmp_path)
    try:
        controller, terminal = os.openpty()
    except OSError as error:  # pragma: no cover - a venue without pseudo-terminals
        pytest.skip(f"no pseudo-terminal on this host: {error}")
    printed: List[bytes] = []

    def drain() -> None:
        # Whatever the wrapper prints to its terminal is read here, so a write can
        # never block on a full pseudo-terminal buffer.
        while True:
            try:
                chunk = os.read(controller, 4096)
            except OSError:
                return
            if not chunk:
                return
            printed.append(chunk)

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    try:
        result, calls = _run(
            runner,
            ["--no-build", "--source-dir", str(source), "--output-dir", str(out)],
            stdin=terminal,
            stdout=terminal,
        )
    finally:
        os.close(terminal)
        os.close(controller)
    reader.join(timeout=10)
    shown = b"".join(printed).decode("utf-8", "replace") + result.stderr
    assert result.returncode == 0, shown
    run = _only_run(calls, shown)
    options = _runner_options(run)
    assert "-i" not in options, options
