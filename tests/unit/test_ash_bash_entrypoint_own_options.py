# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`./ash` reads its own options in both spellings and keeps the scan's words.

The wrapper's value options (--source-dir, --output-dir, --oci-runner and the CLI's
--oci and --runner aliases, --build-target, --container-uid, --container-gid,
--offline-semgrep-rulesets, --ash-revision) take `--opt value` and `--opt=value`, as
the CLI inside the container does. `-v` after a subcommand is that subcommand's
--verbose, so `./ash scan -v` scans; `-v` before any subcommand is the wrapper's
--version. `--help`, `--version` and that `-v` run the CLI from the wrapper's own
directory, not the caller's, so a package planted in a scanned checkout is not what
runs, and exit with the CLI's own status. The script's own directory is read with CDPATH unset, and the
container is run with its stdin open only for the subcommands that read it (`mcp`,
`inspect`, `config`) and for a run given `--cli-json-input -`.

A fake OCI runner stands in for docker, as in
test_ash_bash_entrypoint_container_inputs.py, and records each call's argv
NUL-separated. Bash-wrapper tests are integration tier (tests/NAMING_CONVENTIONS.md).
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
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
    path_prefix: Optional[Path] = None,
):
    """Run ./ash against the recording runner: (result, calls).

    stdout is captured unless a caller hands in its own (a pseudo-terminal, to
    make the wrapper see a terminal there); stderr is always captured. A
    *path_prefix* goes first on PATH, ahead of the fixed-id bin and the caller's
    PATH, so a test can choose which `python` the wrapper finds."""
    program, log_dir = runner
    environment = with_fixed_ids(
        {k: v for k, v in os.environ.items() if k not in _SCRUBBED_ENV},
        log_dir.parent / "fixed-id-bin",
    )
    environment.update(
        {"OCI_RUNNER": str(program), "FAKE_RUNNER_LOG_DIR": str(log_dir)}
    )
    environment.update(env or {})
    if path_prefix is not None:
        environment["PATH"] = os.pathsep.join(
            [str(path_prefix), environment.get("PATH", "")]
        )
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


#: A group of short flags that holds i: `-i`, `-it`, `-ti`.
_SHORT_FLAGS_WITH_I = re.compile(r"^-[A-Za-z]*i[A-Za-z]*$")


def _keeps_stdin(options: List[str]) -> bool:
    """Whether the runner's options keep the container's stdin open, in any of the
    spellings a runtime takes: `-i`, `-it`, `-ti`, `--interactive`,
    `--interactive=true`. A check for the exact word `-i` alone would pass a wrapper
    that regressed to `-it`, the usual spelling for a terminal, in every case that
    expects no -i."""
    return any(
        option in ("--interactive", "--interactive=true")
        or _SHORT_FLAGS_WITH_I.match(option) is not None
        for option in options
    )


@pytest.fixture
def suite_python(tmp_path: Path) -> Path:
    """A directory holding one `python`: the interpreter running the suite, which is
    the one that can import the CLI and its dependencies. Put first on PATH so the
    wrapper's `python` is exactly that interpreter and nothing else is shadowed:
    `shutil.which("python")` alone found any python (a venv's pytest run without
    activating it, or a system python with no CLI installed, failed the tests below
    with an import error instead of skipping), and putting sys.executable's own
    directory first put the whole of it, /usr/bin for a system interpreter, ahead of
    the fixed-id bin, so the real `id` and every other host tool hid the test's
    fakes, and the `python` found there need not have been sys.executable.

    The `python` is a small script that runs sys.executable by its own path, not a
    symlink to it: a virtual environment's interpreter finds the environment's
    packages from the directory it is started in, so one reached through a link in
    some other directory ran as the base interpreter, without the CLI's
    dependencies, and the three tests below failed with an import error."""
    bin_dir = tmp_path / "suite-python"
    bin_dir.mkdir()
    python = bin_dir / "python"
    python.write_text(
        f'#!/bin/bash\nexec {shlex.quote(sys.executable)} "$@"\n', encoding="utf-8"
    )
    python.chmod(0o755)
    return bin_dir


def test_the_suite_python_keeps_the_suites_own_environment(suite_python):
    """The `python` the fixture puts on PATH is the interpreter running the suite,
    in the environment the suite runs in: it reports the same prefix, so it can
    import what the suite imports. Started through a link in another directory, a
    virtual environment's interpreter reported the base prefix instead."""
    result = subprocess.run(  # nosec B603 - the fixture's own script, list args, no shell
        [str(suite_python / "python"), "-c", "import sys; print(sys.prefix)"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == sys.prefix, result.stderr


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
        pytest.param(["-o{runner}"], id="o-attached"),
    ],
)
def test_the_runner_option_in_every_spelling_names_the_wrappers_runner(
    runner, guard, tmp_path, spelling
):
    """--oci and --runner are the CLI's aliases of --oci-runner; the wrapper takes
    them, the = spelling and the short form with its value attached (`-opodman`, as
    click reads it) as its own. At the base they reached the scan inside while the
    wrapper ran the runner the environment named."""
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
        pytest.param("-o ", "-o", id="o-attached-blank"),
    ],
)
def test_an_equals_spelling_with_no_value_is_refused(runner, tmp_path, word, option):
    """An option whose value is attached but empty or blank (`--source-dir=`, `-o `)
    is refused as the usage error the CLI exits 5 for, before anything is run."""
    source, out = _dirs(tmp_path)
    result, calls = _run(
        runner,
        ["--no-build", "--source-dir", str(source), "--output-dir", str(out), word],
    )
    # The usage error the CLI exits 5 for: an option that requires an argument.
    assert result.returncode == 5, result.stdout + result.stderr
    assert f"ERROR: {option} needs a value." in result.stderr, result.stderr
    assert calls == []


def test_the_short_uid_and_gid_options_take_an_attached_value(runner, tmp_path):
    """`-u1234 -g1235`, as click reads a short option with its value attached, name
    the image's UID and GID. At the base the words fell through to the scan inside
    while the image was built with the caller's ids."""
    source, out = _dirs(tmp_path)
    result, calls = _run(
        runner,
        [
            "--no-run",
            "--source-dir",
            str(source),
            "--output-dir",
            str(out),
            "-u1234",
            "-g1235",
        ],
    )
    shown = result.stdout + result.stderr
    assert result.returncode == 0, shown
    builds = [call for call in calls if call[:1] == ["build"]]
    assert len(builds) == 1, f"expected one build call, got {calls}\n{shown}"
    assert "UID=1234" in builds[0] and "GID=1235" in builds[0], builds[0]


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


def test_dash_v_before_any_subcommand_is_still_the_wrappers_version(
    runner, suite_python, tmp_path
):
    """`./ash -v`, with no subcommand before it, prints the version on the host and
    exits, as it always did: a habit or a health check must never fall through to a
    build and a verbose scan of the working directory."""
    source, out = _dirs(tmp_path)
    result, calls = _run(
        runner,
        ["--no-build", "--source-dir", str(source), "--output-dir", str(out), "-v"],
        path_prefix=suite_python,
    )
    shown = result.stdout + result.stderr
    assert result.returncode == 0, shown
    assert "awslabs/automated-security-helper v" in result.stdout, shown
    assert calls == [], "the version is printed on the host; no image is built or run"


def test_the_long_version_option_is_still_the_wrappers_own(
    runner, suite_python, tmp_path
):
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
        path_prefix=suite_python,
    )
    shown = result.stdout + result.stderr
    assert result.returncode == 0, shown
    # The version line itself is what shows the real CLI ran; the exit status is the
    # CLI's own (test_a_failing_host_cli_fails_the_version_check).
    assert "awslabs/automated-security-helper v" in result.stdout, shown
    assert calls == [], "the version is printed on the host; no image is built or run"


def test_help_runs_the_wrappers_own_cli_not_a_package_in_the_working_directory(
    runner, suite_python, tmp_path
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
    result, calls = _run(
        runner,
        ["--help"],
        cwd=tmp_path / "checkout",
        path_prefix=suite_python,
    )
    shown = result.stdout + result.stderr
    assert "PLANTED-PACKAGE-RAN" not in shown, shown
    assert result.returncode == 0, shown
    # The help text itself is what shows the real CLI ran; the exit status is the
    # CLI's own (test_a_failing_host_cli_fails_the_version_check).
    assert "Usage" in result.stdout, shown
    assert calls == []


@pytest.mark.parametrize("words", [["-v"], ["--version"], ["--help"]])
def test_a_failing_host_cli_fails_the_version_check(runner, tmp_path, words):
    """`./ash -v`, `--version` and `--help` run the CLI on the host and exit with ITS
    status. An `exit 0` after the subshell reported success when the host python
    could not run the CLI at all (no python, no package), so a health check on
    `./ash -v` could never fail. Here a planted `python` first on PATH prints a
    marker and exits 7, and the wrapper exits 7 with it."""
    # Not tmp_path/"bin": the runner fixture already keeps the fake runner there.
    planted_bin = tmp_path / "planted-bin"
    planted_bin.mkdir()
    _executable(
        planted_bin / "python",
        "#!/bin/bash\necho PLANTED-PYTHON-RAN\nexit 7\n",
    )
    # The planted bin goes first; the fixed-id bin _run puts on PATH stays behind it,
    # since an env PATH given here replaces the one _run built.
    _, log_dir = runner
    path = os.pathsep.join(
        [
            str(planted_bin),
            str(log_dir.parent / "fixed-id-bin"),
            os.environ.get("PATH", ""),
        ]
    )
    result, calls = _run(runner, words, env={"PATH": path})
    shown = result.stdout + result.stderr
    assert "PLANTED-PYTHON-RAN" in shown, shown
    assert result.returncode == 7, shown
    assert calls == [], "the host CLI is run; no image is built or run"


def test_the_scripts_directory_is_read_with_cdpath_unset(runner, tmp_path):
    """With CDPATH exported, `cd` searches its entries for a relative directory whose
    first component is not "." or "..", and prints the directory it went to. Invoked
    as `<checkout>/ash` from the checkout's parent with that parent in CDPATH (a shell
    whose CDPATH names a projects directory, run from it), the base found the
    checkout through the CDPATH entry and printed it, so the root directory held its
    path twice on two lines and the build got a Dockerfile path and a context with a
    newline in them. (`./ash` and `ash` give "." and are never searched, so they
    cannot show this.)"""
    source, out = _dirs(tmp_path)
    result, calls = _run(
        runner,
        ["--source-dir", str(source), "--output-dir", str(out)],
        cwd=REPO_ROOT.parent,
        script=f"{REPO_ROOT.name}/ash",
        env={"CDPATH": str(REPO_ROOT.parent), "BUILD_FAILS": "1"},
    )
    shown = result.stdout + result.stderr
    builds = [call for call in calls if call[:1] == ["build"]]
    assert len(builds) == 1, f"expected one build call, got {calls}\n{shown}"
    build = builds[0]
    dockerfile = Path(build[build.index("--file") + 1])
    assert dockerfile.resolve() == REPO_ROOT / "Dockerfile", build
    assert Path(build[-1]).resolve() == REPO_ROOT, build
    assert not any("\n" in word for word in build), build


def test_an_mcp_run_over_a_pipe_keeps_stdin_open_and_asks_for_no_terminal(
    runner, tmp_path
):
    """An MCP client drives `./ash mcp` over a pipe on the default stdio transport:
    without -i the container got no input. Stdin here is a pipe, the client's shape
    (the parametrized test below covers mcp, inspect and config, the three
    subcommands that keep stdin open, with a regular file and /dev/null on stdin);
    this one also pins that a captured stdout asks for no pseudo-terminal and that
    the subcommand reaches the container whole."""
    source, out = _dirs(tmp_path)
    result, calls = _run(
        runner,
        ["--no-build", "--source-dir", str(source), "--output-dir", str(out), "mcp"],
        stdin=subprocess.PIPE,
    )
    shown = result.stdout + result.stderr
    assert result.returncode == 0, shown
    run = _only_run(calls, shown)
    options = _runner_options(run)
    assert _keeps_stdin(options), options
    # Captured stdout is not a terminal, so no pseudo-terminal is asked for.
    assert "-t" not in options, options
    assert _inner(run) == ["ash", "mcp"], run


@pytest.mark.parametrize(
    ("words", "kept_open"),
    [
        pytest.param([], False, id="default-scan"),
        pytest.param(["scan"], False, id="scan"),
        pytest.param(["report"], False, id="report"),
        pytest.param(["mcp"], True, id="mcp"),
        pytest.param(["inspect"], True, id="inspect"),
        pytest.param(["config"], True, id="config"),
        pytest.param(
            ["scan", "--cli-json-input", "-"], True, id="scan-with-its-json-on-stdin"
        ),
        pytest.param(
            ["report", "--cli-json-input=-"], True, id="report-with-its-json-attached"
        ),
        pytest.param(
            ["scan", "--cli-json-input", "params.json"],
            False,
            id="scan-with-its-json-in-a-file",
        ),
    ],
)
@pytest.mark.parametrize("stdin_kind", ["a-regular-file", "dev-null"])
def test_only_the_subcommands_that_read_stdin_keep_the_containers_stdin_open(
    runner, tmp_path, words, kept_open, stdin_kind
):
    """Stdin is a regular file (the shape of `./ash --source-dir "$d" < dirs.txt`
    inside a `while read` loop, or a job script fed to bash on stdin) or /dev/null.
    A scan given -i consumed that input, so the loop ended after one directory and
    the script lost the commands after ./ash; only mcp, inspect and config read
    stdin, and any subcommand given `--cli-json-input -` reads its parameters from
    it, so only those get -i. The list is checked against the CLI's own readers in
    test_ash_bash_entrypoint_subcommand_args.py. The file's offset is read after the
    run: the wrapper itself must consume none of it, whichever way it decides."""
    source, out = _dirs(tmp_path)
    arguments = [
        "--no-build",
        "--source-dir",
        str(source),
        "--output-dir",
        str(out),
        *words,
    ]
    if stdin_kind == "a-regular-file":
        feed = tmp_path / "dirs.txt"
        feed.write_text("one\ntwo\n", encoding="utf-8")
        with feed.open("rb") as handle:
            result, calls = _run(runner, arguments, stdin=handle)
            # The child shares the file's offset; a read by the wrapper moves it.
            consumed = handle.tell()
        assert consumed == 0, "the wrapper read the caller's stdin"
    else:
        result, calls = _run(runner, arguments, stdin=subprocess.DEVNULL)
    shown = result.stdout + result.stderr
    assert result.returncode == 0, shown
    options = _runner_options(_only_run(calls, shown))
    assert _keeps_stdin(options) is kept_open, options


@pytest.mark.parametrize(
    ("words", "kept_open"),
    [
        pytest.param([], False, id="scan-in-the-background"),
        pytest.param(["inspect"], True, id="inspect-at-the-terminal"),
    ],
)
def test_a_terminal_stdin_does_not_keep_the_containers_stdin_open(
    runner, tmp_path, words, kept_open
):
    """`./ash scan &` from an interactive shell: the terminal is on stdin AND stdout.
    With -i the runner reads the terminal and the background job stops on that read,
    so a scan gets no -i there. `./ash inspect` at the same terminal reads keys, so
    it keeps -i. The terminal is a real pseudo-terminal on both ends, which is the
    shape an earlier condition (-i whenever stdout was a terminal) gave -i to for a
    scan; a captured stdout would not tell the shapes apart. The runner's options
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
            [
                "--no-build",
                "--source-dir",
                str(source),
                "--output-dir",
                str(out),
                *words,
            ],
            stdin=terminal,
            stdout=terminal,
        )
    finally:
        # The terminal end first: with it closed the drain's read ends (EIO on
        # Linux), the thread is joined, and only then is the controller closed, so
        # the thread never reads a closed, or reused, descriptor.
        os.close(terminal)
        reader.join(timeout=10)
        os.close(controller)
    shown = b"".join(printed).decode("utf-8", "replace") + result.stderr
    assert result.returncode == 0, shown
    run = _only_run(calls, shown)
    options = _runner_options(run)
    assert _keeps_stdin(options) is kept_open, options
