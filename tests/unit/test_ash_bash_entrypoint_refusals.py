# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every refusal the `./ash` bash entrypoint makes itself exits 3.

A wrapper refusal is a problem with the wrapper's own arguments or environment,
found before anything is built or run: no OCI runner, a malformed
ASH_BASE_OCI_LAYOUT, an option given without its value or with an empty one, a
--source-dir that does not exist, an --output-dir that is not a directory. ./ash
refuses with 3, the code ASH uses for input it refuses. A failed image build is
not one of them: it keeps the build's own status.

`./ash --source-dir typo` and an --output-dir naming a file are refused, and an
option at the end of the line with no value, or with "", is refused rather than
set to the empty string. A --source-dir of `--`, `-L`, `-P` or `-` names the
directory it spells, and an exported CDPATH does not choose the source.

The script runs under bash with a PATH holding only the tools it needs and four
guard runners named docker, finch, nerdctl and podman that record the call and
fail. OCI_RUNNER, where set, names a recording runner too. So no case here can
reach a real container runner, and each asserts that no runner was called.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess  # nosec B404 - running the repository's own wrapper script is the point
import unicodedata
from pathlib import Path

import pytest

# The module is already skipped on Windows (pytestmark below), but later lines build
# a name from bytes that are not UTF-8 and call os.uname() when the module is
# imported, so the skip has to come first.
if os.name == "nt":
    pytest.skip(
        "./ash is the POSIX entrypoint, and a file name that is not UTF-8 cannot "
        "exist on NTFS (names are UTF-16)",
        allow_module_level=True,
    )

REPO_ROOT = Path(__file__).resolve().parents[2]
ASH_SCRIPT = REPO_ROOT / "ash"

#: The exit status every wrapper refusal uses.
WRAPPER_REFUSAL_EXIT = 3

#: The exit status of the usage errors `ash` itself refuses with 5: a --sandbox
#: other than off, a --source-dir that names no directory to scan, and an
#: --output-dir that is a file.
USAGE_ERROR_EXIT = 5

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

#: The utilities ./ash calls besides bash builtins and the runner. tr lower-cases a
#: --sandbox mode other than off, so without it such a mode is still refused (see
#: test_sandbox_off_is_taken_without_tr). rm removes the file the output directory's
#: write check makes.
_TOOLS = ("dirname", "basename", "mkdir", "id", "date", "cat", "tr", "rm")

#: Records every call, prints nothing a test could mistake for success, and fails.
#: Each argument is written on its own line after the call's first line, so a test
#: can read a --mount value whole.
_GUARD_RUNNER = """#!/bin/bash
echo "$(basename "$0") $*" >> "$RUNNER_LOG"
printf 'arg:%s\\n' "$@" >> "$RUNNER_ARGS"
exit 99
"""

#: The same, but the call succeeds: for a build that is expected to run.
_SUCCEEDING_RUNNER = _GUARD_RUNNER.replace("exit 99", "exit 0")


@pytest.fixture
def bare_path(tmp_path: Path) -> Path:
    """A PATH with only the tools ./ash needs and the four guard runners."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool in _TOOLS:
        found = shutil.which(tool)
        assert found, f"{tool} is not installed; ./ash needs it"
        (bin_dir / tool).symlink_to(found)
    runners = dict.fromkeys(
        ("docker", "finch", "nerdctl", "podman", "recording-runner"), _GUARD_RUNNER
    )
    runners["succeeding-runner"] = _SUCCEEDING_RUNNER
    for runner, script in runners.items():
        path = bin_dir / runner
        path.write_text(script, encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return bin_dir


@pytest.fixture
def run_ash(tmp_path: Path, bare_path: Path):
    log = tmp_path / "runner.log"
    (tmp_path / "src").mkdir()

    def _run(*args: str, path: Path | None = None, cwd: Path | None = None, **env: str):
        result = subprocess.run(  # nosec B603 - fixed interpreter and script, list args
            [shutil.which("bash"), str(ASH_SCRIPT), *args],
            cwd=cwd or tmp_path,
            env={
                "PATH": str(path or bare_path),
                "HOME": str(tmp_path),
                "RUNNER_LOG": str(log),
                "RUNNER_ARGS": str(tmp_path / "runner.args"),
                **env,
            },
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
        return result, calls

    return _run


def _mounts(tmp_path: Path) -> list[str]:
    """The --mount values the runner was given, each whole."""
    args_file = tmp_path / "runner.args"
    if not args_file.exists():
        return []
    args = args_file.read_text(encoding="utf-8").split("\narg:")
    args[0] = args[0].removeprefix("arg:")
    args[-1] = args[-1].removesuffix("\n")
    return [value for option, value in zip(args, args[1:]) if option == "--mount"]


def test_no_runner_on_path(tmp_path, run_ash):
    tools_only = tmp_path / "tools-only"
    tools_only.mkdir()
    for tool in _TOOLS:
        (tools_only / tool).symlink_to(shutil.which(tool))

    result, calls = run_ash("--source-dir", "src", path=tools_only)

    assert result.returncode == WRAPPER_REFUSAL_EXIT, result.stdout + result.stderr
    assert "Unable to resolve an OCI_RUNNER" in result.stderr
    assert calls == []


def test_the_output_dir_is_made_before_a_runner_is_looked_for(tmp_path, run_ash):
    """A missing --output-dir is made, parents and all, and a run that then finds no
    runtime stops at the runner refusal with the directory in place: the shape
    tests/unit/cli/test_directory_refusals_agree.py pins for a PATH with no runtime.
    Making it just before the build or the run left it unmade here."""
    tools_only = tmp_path / "tools-only"
    tools_only.mkdir()
    for tool in _TOOLS:
        (tools_only / tool).symlink_to(shutil.which(tool))
    out = tmp_path / "p" / "q" / "out"

    result, calls = run_ash(
        "--source-dir", "src", "--output-dir", str(out), path=tools_only
    )

    assert result.returncode == WRAPPER_REFUSAL_EXIT, result.stdout + result.stderr
    assert "Unable to resolve an OCI_RUNNER" in result.stderr
    assert out.is_dir(), result.stdout + result.stderr
    assert calls == []


def test_an_output_dir_that_cannot_be_made_is_refused_before_a_runner_is_looked_for(
    tmp_path, run_ash
):
    """The usage refusal, exit 5 in `ash scan`'s words, comes before the runtime
    lookup, so it is the same with and without a runtime on PATH. Made just before
    the build or the run, it came after "Unable to resolve an OCI_RUNNER"."""
    tools_only = tmp_path / "tools-only"
    tools_only.mkdir()
    for tool in _TOOLS:
        (tools_only / tool).symlink_to(shutil.which(tool))
    blocker = tmp_path / "blocker"
    blocker.write_text("x\n", encoding="utf-8")
    out = blocker / "out"

    result, calls = run_ash(
        "--source-dir", "src", "--output-dir", str(out), path=tools_only
    )

    assert result.returncode == USAGE_ERROR_EXIT, result.stdout + result.stderr
    assert "Output directory cannot be created: " in result.stderr, result.stderr
    assert "Unable to resolve an OCI_RUNNER" not in result.stderr, result.stderr
    assert calls == []


def test_a_malformed_base_oci_layout(tmp_path, run_ash, bare_path):
    result, calls = run_ash(
        "--source-dir",
        "src",
        OCI_RUNNER=str(bare_path / "recording-runner"),
        ASH_BASE_OCI_LAYOUT="/layouts/base",
    )

    assert result.returncode == WRAPPER_REFUSAL_EXIT, result.stdout + result.stderr
    # Quoted as Invoke-ASH and ash scan quote it, and as the bash wrapper's snapshot
    # (test_snapshot_container_bash_wrapper.py) pins it.
    assert "ASH_BASE_OCI_LAYOUT is '/layouts/base', which is not" in result.stderr, (
        result.stderr
    )
    assert calls == []


@pytest.mark.parametrize(
    "option",
    [
        "--source-dir",
        "--output-dir",
        "--offline-semgrep-rulesets",
        "--oci-runner",
        "-o",
        "--container-uid",
        "-u",
        "--container-gid",
        "-g",
        "--build-target",
        "--ash-revision",
        "-rev",
    ],
)
def test_an_option_without_its_value(run_ash, bare_path, option):
    """The option is last, so there is no value to take: refused, not set to ""."""
    result, calls = run_ash(
        "--no-build",
        option,
        OCI_RUNNER=str(bare_path / "recording-runner"),
    )

    # A value option with no value is the usage error the CLI exits 5 for.
    assert result.returncode == USAGE_ERROR_EXIT, result.stdout + result.stderr
    assert f"{option} needs a value" in result.stderr
    assert calls == []


def test_an_attached_empty_value_is_refused(run_ash, bare_path):
    """`--build-target=` is the attached spelling with nothing after the "=": refused
    like `--build-target ""`, naming the option without the "=", before the stage is
    read, so an empty stage never reaches the name check or the image tag."""
    result, calls = run_ash(
        "--no-build",
        "--source-dir",
        "src",
        "--build-target=",
        OCI_RUNNER=str(bare_path / "recording-runner"),
    )

    assert result.returncode == USAGE_ERROR_EXIT, result.stdout + result.stderr
    assert "--build-target needs a value" in result.stderr, result.stderr
    assert calls == []


#: Every ./ash option that takes a value, as typed.
_VALUE_OPTIONS = [
    "--source-dir",
    "--output-dir",
    "--offline-semgrep-rulesets",
    "--oci-runner",
    "-o",
    "--container-uid",
    "-u",
    "--container-gid",
    "-g",
    "--build-target",
    "--ash-revision",
    "-rev",
]


@pytest.mark.parametrize("option", _VALUE_OPTIONS)
def test_an_option_given_an_empty_value(run_ash, bare_path, option):
    """`--source-dir ""` and `--oci-runner ""` are refused: an empty value is no value."""
    result, calls = run_ash(
        "--no-build",
        "--source-dir",
        "src",
        option,
        "",
        OCI_RUNNER=str(bare_path / "recording-runner"),
    )

    # A value option with no value is the usage error the CLI exits 5 for.
    assert result.returncode == USAGE_ERROR_EXIT, result.stdout + result.stderr
    assert f"{option} needs a value" in result.stderr
    assert calls == []


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("does-not-exist", id="missing"),
        # cd read these as its own options: `cd --` and `cd -L` went to $HOME, so
        # the home directory was mounted at /src and scanned.
        pytest.param("--", id="double-dash"),
        pytest.param("-L", id="dash-L"),
        pytest.param("-P", id="dash-P"),
        # `cd -` went to $OLDPWD and printed it, so two lines reached the mount.
        pytest.param("-", id="dash"),
    ],
)
def test_a_source_dir_that_does_not_exist(tmp_path, run_ash, bare_path, value):
    result, calls = run_ash(
        "--no-build",
        "--source-dir",
        value,
        OCI_RUNNER=str(bare_path / "recording-runner"),
        OLDPWD=str(tmp_path / "src"),
    )

    assert result.returncode == USAGE_ERROR_EXIT, result.stdout + result.stderr
    # The whole line: a value such as "-" is in every line.
    assert (
        f"ERROR: Source directory does not exist: {value}" in result.stderr.splitlines()
    ), result.stderr
    assert calls == [], "another directory was scanned instead"


def test_a_source_dir_that_starts_with_a_dash_is_the_directory_it_names(
    tmp_path, run_ash, bare_path
):
    """It was refused: cd read "-dashdir" as options and failed."""
    (tmp_path / "-dashdir").mkdir()

    result, calls = run_ash(
        "--no-build",
        "--source-dir",
        "-dashdir",
        "--output-dir",
        "-dashout",
        OCI_RUNNER=str(bare_path / "recording-runner"),
    )

    assert [call.split()[:2] for call in calls] == [["recording-runner", "run"]], (
        result.stdout + result.stderr
    )
    mounts = _mounts(tmp_path)
    # The source mount is read-only wherever the output is; only its start is read.
    assert mounts[0].startswith(
        f"source={tmp_path / '-dashdir'},type=bind,destination=/src"
    ), mounts
    assert mounts[1] == f"source={tmp_path / '-dashout'},type=bind,destination=/out"
    assert (tmp_path / "-dashout").is_dir()


def test_cdpath_does_not_choose_the_source_dir(tmp_path, run_ash, bare_path):
    """With CDPATH exported, ./src is still the source directory."""
    (tmp_path / "elsewhere" / "src").mkdir(parents=True)

    result, calls = run_ash(
        "--no-build",
        "--source-dir",
        "src",
        OCI_RUNNER=str(bare_path / "recording-runner"),
        CDPATH=str(tmp_path / "elsewhere"),
    )

    assert len(calls) == 1, result.stdout + result.stderr
    assert _mounts(tmp_path)[0].startswith(f"source={tmp_path / 'src'},type=bind,"), (
        _mounts(tmp_path)
    )


def test_an_output_dir_that_cannot_be_created_says_why(tmp_path, run_ash, bare_path):
    """The reason, in the refusal itself: mkdir's own line quotes the path its own way.

    GNU mkdir writes a control character in the path as an escape, but other
    mkdirs (BSD's, on macOS) need not, so its line is not printed.
    """
    (tmp_path / "a-file").write_text("", encoding="utf-8")

    result, calls = run_ash(
        "--no-build",
        "--source-dir",
        "src",
        "--output-dir",
        "a-file/\x1b[2Jout",
        OCI_RUNNER=str(bare_path / "recording-runner"),
    )

    assert result.returncode == USAGE_ERROR_EXIT, result.stdout + result.stderr
    assert "Output directory cannot be created: " in result.stderr, result.stderr
    assert result.stderr.rstrip().endswith(" (Not a directory)"), result.stderr
    assert "mkdir:" not in result.stderr, result.stderr
    assert "\x1b" not in result.stderr, repr(result.stderr)
    assert "--output-dir" not in result.stderr, result.stderr
    assert calls == []


@pytest.mark.skipif(
    # os.geteuid does not exist on Windows, and the module is skipped there
    # (pytestmark), but this expression is evaluated when the module is imported.
    os.name == "nt" or os.geteuid() == 0,
    reason="root creates a directory whatever its parent's mode says",
)
def test_a_default_output_dir_that_cannot_be_created_names_the_option(
    tmp_path, run_ash, bare_path
):
    """The default output directory is inside the scanned directory. A scanned
    directory that cannot take it (read-only here) refuses with the reason, as any
    output directory does, and names --output-dir as the way to write elsewhere; the
    refusal of an --output-dir the operator chose carries no such hint (the check
    above), since the choice was already theirs."""
    source = tmp_path / "src"
    source.chmod(0o555)
    try:
        result, calls = run_ash(
            "--no-build",
            "--source-dir",
            "src",
            OCI_RUNNER=str(bare_path / "recording-runner"),
        )
    finally:
        source.chmod(0o755)

    assert result.returncode == USAGE_ERROR_EXIT, result.stdout + result.stderr
    assert "Output directory cannot be created: " in result.stderr, result.stderr
    assert "(Permission denied)" in result.stderr, result.stderr
    assert "pass --output-dir to write elsewhere" in result.stderr, result.stderr
    assert "mkdir:" not in result.stderr, result.stderr
    assert calls == []


def test_a_default_output_dir_that_is_a_file_names_the_option(
    tmp_path, run_ash, bare_path
):
    """The hint goes on every refusal the default alone can draw, not only the one
    of a directory that cannot be created: a file at `<source>/.ash/ash_output`
    (here), a default that cannot be written (the next test), and one reached
    through a link the repository commits
    (tests/unit/test_ash_bash_entrypoint_output_paths.py)."""
    (tmp_path / "src" / ".ash").mkdir()
    (tmp_path / "src" / ".ash" / "ash_output").write_text("", encoding="utf-8")

    result, calls = run_ash(
        "--no-build",
        "--source-dir",
        "src",
        OCI_RUNNER=str(bare_path / "recording-runner"),
    )

    assert result.returncode == USAGE_ERROR_EXIT, result.stdout + result.stderr
    assert "Output directory is not a directory: " in result.stderr, result.stderr
    assert ".ash/ash_output" in result.stderr, result.stderr
    assert "pass --output-dir to write elsewhere" in result.stderr, result.stderr
    assert calls == [], "the results were sent to the working directory instead"


@pytest.mark.skipif(
    # The module is skipped on Windows before this line is reached (the
    # module-level skip above), so os.geteuid exists wherever it is evaluated.
    os.geteuid() == 0,
    reason="root writes into a directory whatever its mode says",
)
def test_a_default_output_dir_that_cannot_be_written_names_the_option(
    tmp_path, run_ash, bare_path
):
    """A default output directory that is there but takes no file (read-only here)
    is refused with the reason and names --output-dir, as the other refusals of a
    default do."""
    output = tmp_path / "src" / ".ash" / "ash_output"
    output.mkdir(parents=True)
    output.chmod(0o555)
    try:
        result, calls = run_ash(
            "--no-build",
            "--source-dir",
            "src",
            OCI_RUNNER=str(bare_path / "recording-runner"),
        )
    finally:
        output.chmod(0o755)

    assert result.returncode == USAGE_ERROR_EXIT, result.stdout + result.stderr
    assert "Output directory cannot be written: " in result.stderr, result.stderr
    assert "(Permission denied)" in result.stderr, result.stderr
    assert "pass --output-dir to write elsewhere" in result.stderr, result.stderr
    assert calls == []


@pytest.mark.skipif(
    os.geteuid() == 0,
    reason="root writes into a directory whatever its mode says",
)
def test_an_output_dir_that_cannot_be_written(tmp_path, run_ash, bare_path):
    """Control: an --output-dir the operator chose is refused with the reason, in
    `ash scan`'s words, and with no hint, since the choice was already theirs."""
    output = tmp_path / "out"
    output.mkdir()
    output.chmod(0o555)
    try:
        result, calls = run_ash(
            "--no-build",
            "--source-dir",
            "src",
            "--output-dir",
            "out",
            OCI_RUNNER=str(bare_path / "recording-runner"),
        )
    finally:
        output.chmod(0o755)

    assert result.returncode == USAGE_ERROR_EXIT, result.stdout + result.stderr
    assert (
        "ERROR: Output directory cannot be written: out (Permission denied)"
        in result.stderr.splitlines()
    ), result.stderr
    assert "--output-dir to write elsewhere" not in result.stderr, result.stderr
    assert calls == []


@pytest.mark.parametrize("option", _VALUE_OPTIONS)
@pytest.mark.parametrize(
    "blank", [pytest.param(" ", id="space"), pytest.param("\t", id="tab")]
)
def test_an_option_given_only_whitespace(run_ash, bare_path, option, blank):
    """`--oci-runner " "` is refused, because a blank is no value either."""
    result, calls = run_ash(
        "--no-build",
        "--source-dir",
        "src",
        option,
        blank,
        OCI_RUNNER=str(bare_path / "recording-runner"),
    )

    # A value option with no value is the usage error the CLI exits 5 for.
    assert result.returncode == USAGE_ERROR_EXIT, result.stdout + result.stderr
    assert f"{option} needs a value" in result.stderr
    assert calls == []


@pytest.mark.parametrize(
    "output_dir",
    [
        # A sibling whose name starts with the source dir's: the prefix test once
        # read it as inside the source, where the mount differed.
        pytest.param("src-out", id="sibling-with-the-same-prefix"),
        pytest.param("src/out", id="inside-the-source-dir"),
        pytest.param("out", id="elsewhere"),
    ],
)
def test_the_source_mount_is_read_only_wherever_the_output_is(
    tmp_path, run_ash, bare_path, output_dir
):
    """The output has its own read-write mount at /out and the scan inside writes
    there, so /src is read-only also when the output directory is inside the source
    (the default .ash/ash_output is)."""
    result, calls = run_ash(
        "--no-build",
        "--source-dir",
        "src",
        "--output-dir",
        output_dir,
        OCI_RUNNER=str(bare_path / "recording-runner"),
    )

    assert len(calls) == 1, result.stdout + result.stderr
    source_mount = _mounts(tmp_path)[0]
    assert source_mount.endswith(",readonly"), source_mount


def test_a_root_source_dir_holds_an_output_dir_beneath_it(tmp_path, run_ash, bare_path):
    """With / as the source the prefix was "//", so the output under it read as
    outside. The output beneath / is not above the source, so the run is not
    refused, and / is mounted at /src read-only as every source is."""
    result, calls = run_ash(
        "--no-build",
        "--source-dir",
        "/",
        "--output-dir",
        str(tmp_path / "out"),
        OCI_RUNNER=str(bare_path / "recording-runner"),
    )

    assert len(calls) == 1, result.stdout + result.stderr
    assert _mounts(tmp_path)[0] == "source=/,type=bind,destination=/src,readonly"


def test_a_source_dir_whose_name_ends_in_a_newline_is_refused(
    tmp_path, run_ash, bare_path
):
    """Not mounted as ./src, nor as itself.

    $(...) strips trailing newlines, so a source dir whose name ends in a newline is
    refused rather than resolved to ./src. The runtimes read --mount as CSV, one
    record per line, so the name as it is cannot be mounted either: it is refused,
    naming the option.
    """
    (tmp_path / "src\n").mkdir()

    result, calls = run_ash(
        "--no-build",
        "--source-dir",
        "src\n",
        OCI_RUNNER=str(bare_path / "recording-runner"),
    )

    assert result.returncode == WRAPPER_REFUSAL_EXIT, result.stdout + result.stderr
    assert "--source-dir $'src\\n'" in result.stderr, result.stderr
    assert "newline" in result.stderr, result.stderr
    assert calls == [], "a directory was mounted"


def test_an_output_dir_whose_name_holds_a_newline_is_refused_before_it_is_made(
    tmp_path, run_ash, bare_path
):
    result, calls = run_ash(
        "--no-build",
        "--source-dir",
        "src",
        "--output-dir",
        "out\nmore",
        OCI_RUNNER=str(bare_path / "recording-runner"),
    )

    assert result.returncode == WRAPPER_REFUSAL_EXIT, result.stdout + result.stderr
    assert "--output-dir $'out\\nmore'" in result.stderr, result.stderr
    assert not (tmp_path / "out\nmore").exists()
    assert calls == []


def test_an_output_dir_under_a_working_directory_with_a_newline_is_refused(
    tmp_path, run_ash, bare_path
):
    """The name as typed holds no newline, its path does: refused before mkdir.

    It was created and then refused, leaving "w\\nx/out" behind. The path is shown
    quoted, on the refusal's one line.
    """
    workdir = tmp_path / "w\nx"
    workdir.mkdir()

    result, calls = run_ash(
        "--no-build",
        "--source-dir",
        str(tmp_path / "src"),
        "--output-dir",
        "out",
        cwd=workdir,
        OCI_RUNNER=str(bare_path / "recording-runner"),
    )

    assert result.returncode == WRAPPER_REFUSAL_EXIT, result.stdout + result.stderr
    (line,) = [line for line in result.stderr.splitlines() if "resolves to" in line]
    shown = "$'" + str(workdir).replace("\n", "\\n") + "/out'"
    assert f"--output-dir out resolves to {shown}, a path with a newline" in line, line
    assert line.endswith("Rename the directory or give another."), line
    assert not (workdir / "out").exists(), "the refused directory was created"
    assert calls == []


def test_an_output_dir_under_a_working_directory_with_a_comma_is_refused(
    tmp_path, run_ash, bare_path
):
    """The comma is the working directory's alone: refused before mkdir as well."""
    workdir = tmp_path / "c,wd"
    workdir.mkdir()

    result, calls = run_ash(
        "--no-build",
        "--source-dir",
        str(tmp_path / "src"),
        "--output-dir",
        "out",
        cwd=workdir,
        OCI_RUNNER=str(bare_path / "recording-runner"),
    )

    assert result.returncode == WRAPPER_REFUSAL_EXIT, result.stdout + result.stderr
    assert (
        f"--output-dir out resolves to {workdir}/out, a path with a comma"
        in result.stderr
    ), result.stderr
    assert not (workdir / "out").exists(), "the refused directory was created"
    assert calls == []


@pytest.mark.parametrize(
    "out_exists",
    [
        pytest.param(False, id="out-not-made-yet"),
        pytest.param(True, id="out-made-already"),
    ],
)
def test_an_output_dir_through_a_link_is_made_where_it_resolves(
    tmp_path, run_ash, bare_path, out_exists
):
    """mkdir -p reads ".." after a link physically, and cd and the check by name.

    With "lnk" pointing into "deep,x", "lnk/../out" is made and mounted where the
    check resolves it, the working directory's "out", and "deep,x/out" is never
    made.
    """
    workdir = tmp_path / "w"
    workdir.mkdir()
    target = tmp_path / "deep,x" / "inner"
    target.mkdir(parents=True)
    (workdir / "lnk").symlink_to(target, target_is_directory=True)
    if out_exists:
        (workdir / "out").mkdir()

    result, calls = run_ash(
        "--no-build",
        "--source-dir",
        str(tmp_path / "src"),
        "--output-dir",
        "lnk/../out",
        cwd=workdir,
        OCI_RUNNER=str(bare_path / "recording-runner"),
    )

    assert len(calls) == 1, result.stdout + result.stderr
    assert (workdir / "out").is_dir()
    assert not (tmp_path / "deep,x" / "out").exists(), "made where nothing checked"
    assert f"source={workdir}/out,type=bind,destination=/out" in _mounts(tmp_path)


def test_an_output_dir_that_stays_under_a_working_directory_with_a_comma_is_refused(
    tmp_path, run_ash, bare_path
):
    """Folding "x/.." away keeps the check: "x/../out" is still under the comma."""
    workdir = tmp_path / "c,wd"
    workdir.mkdir()

    result, calls = run_ash(
        "--no-build",
        "--source-dir",
        str(tmp_path / "src"),
        "--output-dir",
        "x/../out",
        cwd=workdir,
        OCI_RUNNER=str(bare_path / "recording-runner"),
    )

    assert result.returncode == WRAPPER_REFUSAL_EXIT, result.stdout + result.stderr
    assert (
        f"--output-dir x/../out resolves to {workdir}/out, a path with a comma"
        in result.stderr
    ), result.stderr
    assert not (workdir / "x").exists() and not (workdir / "out").exists()
    assert calls == []


@pytest.mark.parametrize(
    "output_dir",
    [
        pytest.param("../out", id="parent"),
        # "x" does not exist: the check read the rest of the path as given, so this
        # was refused as ".../c,wd/x/../../out", though mkdir -p makes .../out.
        pytest.param("x/../../out", id="through-a-directory-not-made-yet"),
        pytest.param("./x/./../.././out", id="with-dot-segments"),
    ],
)
def test_an_output_dir_that_leaves_a_working_directory_with_a_comma_is_mounted(
    tmp_path, run_ash, bare_path, output_dir
):
    """The control: a path that leaves a working directory with a comma resolves to
    one without, which is mounted, so the check reads where it resolves to and not
    the working directory joined to the name."""
    workdir = tmp_path / "c,wd"
    workdir.mkdir()

    result, calls = run_ash(
        "--no-build",
        "--source-dir",
        str(tmp_path / "src"),
        "--output-dir",
        output_dir,
        cwd=workdir,
        OCI_RUNNER=str(bare_path / "recording-runner"),
    )

    assert len(calls) == 1, result.stdout + result.stderr
    assert (tmp_path / "out").is_dir()
    assert f"source={tmp_path}/out,type=bind,destination=/out" in _mounts(tmp_path)


def test_the_default_source_dir_keeps_the_working_directorys_newline(
    tmp_path, run_ash, bare_path
):
    """The default source dir keeps the working directory's trailing newline, so
    "w\\n" is refused rather than mounted as its sibling "w"."""
    (tmp_path / "w").mkdir()
    workdir = tmp_path / "w\n"
    workdir.mkdir()

    result, calls = run_ash(
        "--no-build",
        "--output-dir",
        str(tmp_path / "out"),
        cwd=workdir,
        OCI_RUNNER=str(bare_path / "recording-runner"),
    )

    assert result.returncode == WRAPPER_REFUSAL_EXIT, result.stdout + result.stderr
    assert "--source-dir . resolves to" in result.stderr, result.stderr
    assert calls == [], "the sibling directory was mounted"


def test_the_default_source_dir_under_a_working_directory_with_a_comma_is_refused(
    tmp_path, run_ash, bare_path
):
    """No --source-dir: the working directory is the source, and its comma counts."""
    workdir = tmp_path / "c,wd"
    workdir.mkdir()

    result, calls = run_ash(
        "--no-build",
        "--output-dir",
        str(tmp_path / "out"),
        cwd=workdir,
        OCI_RUNNER=str(bare_path / "recording-runner"),
    )

    assert result.returncode == WRAPPER_REFUSAL_EXIT, result.stdout + result.stderr
    assert (
        f"--source-dir . resolves to {workdir}, a path with a comma" in result.stderr
    ), result.stderr
    assert calls == []


@pytest.mark.parametrize(
    "option, value, made",
    [
        # Created first: the comma is in the resolved path of a directory that exists.
        pytest.param("--source-dir", "s,c", True, id="source-dir"),
        # docker and podman read a later key over an earlier one, and src is
        # source's alias: this mounted host /etc read-write at /out.
        pytest.param("--output-dir", "o,src=/etc", False, id="output-dir"),
    ],
)
def test_a_comma_in_a_mounted_path_is_refused(
    tmp_path, run_ash, bare_path, option, value, made
):
    """--mount is CSV, so a comma in the path starts a field of the operator's own."""
    if made:
        (tmp_path / value).mkdir()
    args = ["--source-dir", "src", option, value]
    if option == "--source-dir":
        args = [option, value]

    result, calls = run_ash(
        "--no-build", *args, OCI_RUNNER=str(bare_path / "recording-runner")
    )

    assert result.returncode == WRAPPER_REFUSAL_EXIT, result.stdout + result.stderr
    assert f"{option} {value} " in result.stderr, result.stderr
    assert "comma" in result.stderr, result.stderr
    assert (tmp_path / value).exists() is made, "the refused directory was created"
    assert calls == []


@pytest.mark.parametrize(
    "option, value, made, held, shown",
    [
        pytest.param(
            "--source-dir", 's"q', True, "a double quote", 's"q', id="quote-source"
        ),
        pytest.param(
            "--output-dir", 'o"q', False, "a double quote", 'o"q', id="quote-output"
        ),
        pytest.param(
            "--source-dir",
            "s\rq",
            True,
            "a carriage return",
            "$'s\\rq'",
            id="cr-source",
        ),
        pytest.param(
            "--output-dir",
            "o\rq",
            False,
            "a carriage return",
            "$'o\\rq'",
            id="cr-output",
        ),
    ],
)
def test_a_quote_or_a_carriage_return_in_a_mounted_path_is_refused(
    tmp_path, run_ash, bare_path, option, value, made, held, shown
):
    """--mount is CSV: a double quote starts quoting, and a carriage return can end
    the record. Refused like a comma or a newline, before any runner call, with a
    carriage return shown escaped."""
    if made:
        (tmp_path / value).mkdir()
    args = ["--source-dir", "src", option, value]
    if option == "--source-dir":
        args = [option, value]

    result, calls = run_ash(
        "--no-build", *args, OCI_RUNNER=str(bare_path / "recording-runner")
    )

    assert result.returncode == WRAPPER_REFUSAL_EXIT, result.stdout + result.stderr
    assert f"{option} {shown} " in result.stderr, repr(result.stderr)
    assert held in result.stderr, result.stderr
    assert (tmp_path / value).exists() is made, "the refused directory was created"
    assert calls == []


@pytest.mark.parametrize(
    "name", ["s'q", "s\tq", "s\x7fq"], ids=["apostrophe", "tab", "delete"]
)
def test_control_other_characters_in_a_mounted_path_are_mounted(
    tmp_path, run_ash, bare_path, name
):
    """Only the characters --mount cannot carry are refused."""
    (tmp_path / name).mkdir()

    result, calls = run_ash(
        "--no-build",
        "--source-dir",
        str(tmp_path / name),
        OCI_RUNNER=str(bare_path / "recording-runner"),
    )

    assert len(calls) == 1, result.stdout + result.stderr
    assert _mounts(tmp_path)[0].startswith(f"source={tmp_path / name},"), _mounts(
        tmp_path
    )


#: A directory name whose bytes are not UTF-8: "caf" and a lone 0xE9.
_NOT_UTF8 = os.fsdecode(b"caf\xe9")


@pytest.mark.skipif(
    os.uname().sysname == "Darwin", reason="APFS refuses a name that is not UTF-8"
)
@pytest.mark.parametrize("locale", ["C", "C.UTF-8"])
@pytest.mark.parametrize(
    "case",
    ["source-dir", "output-dir", "output-dir-under-the-working-directory", "control"],
)
def test_a_mount_path_that_is_not_utf8_is_refused_before_the_runtime(
    tmp_path, bare_path, case, locale
):
    """A runtime reads --mount as text, so a path that is not UTF-8 names another
    directory to it, one with U+FFFD in place of each byte it cannot decode.

    Refused before any runner call, with the path shown escaped, so the message is
    UTF-8 itself; an output dir named so is refused before it is made. A relative
    output dir under such a working directory is refused on its resolved path. The
    control, with UTF-8 paths and the same options, is mounted.
    """
    odd = tmp_path / _NOT_UTF8
    plain = tmp_path / "src"
    plain.mkdir()
    args = ["--source-dir", str(plain), "--output-dir", str(tmp_path / "out")]
    option = "--source-dir"
    cwd = tmp_path
    if case == "source-dir":
        odd.mkdir()
        args[1] = str(odd)
    elif case == "output-dir":
        args[3] = str(odd / "out")
        option = "--output-dir"
    elif case == "output-dir-under-the-working-directory":
        odd.mkdir()
        cwd = odd
        args[3] = "out"
        option = "--output-dir"
    log = tmp_path / "runner.log"
    env = {
        "PATH": str(bare_path),
        "HOME": str(tmp_path),
        "RUNNER_LOG": str(log),
        "RUNNER_ARGS": str(tmp_path / "runner.args"),
        "OCI_RUNNER": str(bare_path / "recording-runner"),
    }
    if locale != "C":
        env["LC_ALL"] = locale

    result = subprocess.run(  # nosec B603 - fixed interpreter and script, list args
        [shutil.which("bash"), str(ASH_SCRIPT), "--no-build", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        timeout=120,
        check=False,
    )
    calls = log.read_bytes().splitlines() if log.exists() else []
    output = (result.stdout + result.stderr).decode("utf-8", "backslashreplace")

    if case == "control":
        assert len(calls) == 1, output
        assert _mounts(tmp_path)[0].startswith(f"source={plain},"), _mounts(tmp_path)
        return
    assert result.returncode == WRAPPER_REFUSAL_EXIT, output
    assert calls == [], "a path that is not UTF-8 was handed to the runtime"
    stderr = result.stderr.decode("utf-8")  # shown escaped: the message is UTF-8
    assert option in stderr and "UTF-8" in stderr, stderr
    if case == "output-dir":
        assert not (odd / "out").exists(), "the refused output directory was made"


@pytest.mark.parametrize(
    "name",
    ["src", "café", "日本", "\U0001f600", "\U0010ffff"],
    ids=["ascii", "two-byte", "three-byte", "four-byte", "highest"],
)
def test_a_utf8_path_is_mounted_with_no_tool_beyond_bash(
    tmp_path, run_ash, bare_path, name
):
    """./ash judges UTF-8 in bash, so a UTF-8 path outside ASCII mounts on a PATH
    with no iconv."""
    assert not (bare_path / "iconv").exists()
    (tmp_path / name).mkdir(exist_ok=True)

    result, calls = run_ash(
        "--no-build",
        "--source-dir",
        name,
        OCI_RUNNER=str(bare_path / "recording-runner"),
    )

    assert len(calls) == 1, result.stdout + result.stderr


@pytest.mark.skipif(
    os.uname().sysname == "Darwin", reason="APFS refuses a name that is not UTF-8"
)
@pytest.mark.parametrize(
    "raw",
    [
        b"x\xf4\x90\x80\x80",
        b"x\xf5\x80\x80\x80",
        b"x\xf8\x88\x80\x80\x80",
        b"x\xed\xa0\x80",
        b"x\xc0\x80",
        b"x\xe0\x80\x80",
        b"x\xc3",
    ],
    ids=[
        "above-U+10FFFF",
        "lead-byte-f5",
        "five-byte-form",
        "encoded-surrogate",
        "overlong-two-byte",
        "overlong-three-byte",
        "truncated",
    ],
)
def test_each_form_python_does_not_decode_is_refused(tmp_path, bare_path, raw):
    """The forms RFC 3629 does not allow, as Python's strict UTF-8 refuses them.

    With iconv on PATH too: glibc 2.34's iconv accepts the first three (measured),
    so a check that asks it would let them through.
    """
    (bare_path / "iconv").symlink_to(shutil.which("iconv"))
    odd = tmp_path / os.fsdecode(raw)
    odd.mkdir()
    log = tmp_path / "runner.log"

    result = subprocess.run(  # nosec B603 - fixed interpreter and script, list args
        [shutil.which("bash"), str(ASH_SCRIPT), "--no-build", "--source-dir", str(odd)],
        cwd=tmp_path,
        env={
            "PATH": str(bare_path),
            "HOME": str(tmp_path),
            "RUNNER_LOG": str(log),
            "RUNNER_ARGS": str(tmp_path / "runner.args"),
            "OCI_RUNNER": str(bare_path / "recording-runner"),
        },
        capture_output=True,
        timeout=120,
        check=False,
    )

    output = (result.stdout + result.stderr).decode("utf-8", "backslashreplace")
    assert result.returncode == WRAPPER_REFUSAL_EXIT, output
    assert not log.exists(), "a path that is not UTF-8 was handed to the runtime"
    assert "UTF-8" in result.stderr.decode("utf-8"), output


#: A digest-pinned ASH_BASE_OCI_LAYOUT, well formed.
_LAYOUT = "/layouts/base@sha256:" + "0" * 64


@pytest.mark.parametrize(
    "case",
    [
        "runner-name",
        # The runner's name is echoed a second time when ASH_BASE_OCI_LAYOUT is set,
        # by the runtimes that load the layout into their own store.
        "layout-runner-name",
        "image-name",
        "base-image-override",
    ],
)
def test_operator_values_in_progress_lines_are_shown_not_obeyed(
    tmp_path, run_ash, bare_path, case
):
    """Lines that echo a runner path or image name show ESC and OSC 8 escaped.

    An image name or base image reference holding them is not one ./ash takes, so it
    is refused, and the refusal shows it the same way.
    """
    env = {"OCI_RUNNER": str(bare_path / "recording-runner")}
    if case in ("runner-name", "layout-runner-name"):
        runner = bare_path / "ok\x1b[31mrunner"
        runner.write_text(_GUARD_RUNNER, encoding="utf-8")
        runner.chmod(runner.stat().st_mode | stat.S_IXUSR)
        env["OCI_RUNNER"] = str(runner)
        if case == "layout-runner-name":
            env["ASH_BASE_OCI_LAYOUT"] = _LAYOUT
    elif case == "image-name":
        env["ASH_IMAGE_NAME"] = "image\x1b[31mname"
    else:
        env["ASH_BASE_IMAGE_OVERRIDE"] = "base\x1b]8;;x\x07image"

    result, calls = run_ash("--source-dir", "src", **env)

    output = result.stdout + result.stderr
    assert "\x1b" not in output and "\x07" not in output, repr(output)
    if case in ("image-name", "base-image-override"):
        assert result.returncode == WRAPPER_REFUSAL_EXIT, output
        assert calls == [], output
        return
    assert calls, output
    if case == "layout-runner-name":
        assert "Base image expected in $'ok\\E[31mrunner'" in result.stderr, output


def test_a_printable_value_is_shown_as_typed(run_ash, bare_path):
    """Quoting is for a value a terminal would act on: a spaced path prints as is."""
    result, calls = run_ash(
        "--no-build",
        "--source-dir",
        "no such dir",
        OCI_RUNNER=str(bare_path / "recording-runner"),
    )

    assert result.returncode == USAGE_ERROR_EXIT, result.stdout + result.stderr
    assert "ERROR: Source directory does not exist: no such dir" in result.stderr, (
        result.stderr
    )
    assert calls == []


def _utf8_locale() -> str | None:
    """A UTF-8 locale this host has, for the cases bash's own quoting differs in."""
    try:
        listed = subprocess.run(  # nosec B603 B607 - fixed command, no input
            ["locale", "-a"], capture_output=True, text=True, timeout=30, check=False
        ).stdout.split()
    except (OSError, subprocess.SubprocessError):
        return None
    for name in ("C.UTF-8", "C.utf8", "en_US.UTF-8", "en_US.utf8"):
        if name in listed:
            return name
    return None


@pytest.mark.parametrize(
    "code",
    [
        pytest.param(0x202E, id="right-to-left-override"),
        pytest.param(0x2066, id="left-to-right-isolate"),
        pytest.param(0x200B, id="zero-width-space"),
        pytest.param(0xFEFF, id="byte-order-mark"),
        pytest.param(0x2028, id="line-separator"),
        pytest.param(0xE0041, id="tag-character"),
    ],
)
def test_a_format_character_is_shown_in_a_utf8_locale(run_ash, bare_path, code):
    """In a UTF-8 locale bash counts these printable, and its %q leaves them raw.

    U+202E is shown in place, reversing the text after it; so the value is quoted in
    the C locale, which writes each of its bytes as octal. None of them is a character
    an image name may hold, so the name is refused, and the refusal shows it so.
    """
    locale_name = _utf8_locale()
    if locale_name is None:
        pytest.skip("no UTF-8 locale on this host")
    value = f"image{chr(code)}name"

    result, calls = run_ash(
        "--source-dir",
        "src",
        OCI_RUNNER=str(bare_path / "recording-runner"),
        ASH_IMAGE_NAME=value,
        LC_ALL=locale_name,
    )

    output = result.stdout + result.stderr
    assert chr(code) not in output, repr(output)
    octal = "".join(f"\\{byte:03o}" for byte in chr(code).encode("utf-8"))
    assert result.returncode == WRAPPER_REFUSAL_EXIT, output
    assert calls == [], output
    assert f"The image name '$'image{octal}name''" in result.stderr, output


def test_a_letter_is_shown_as_typed_in_a_utf8_locale(run_ash, bare_path):
    """The control: a printable non-ASCII letter is not one of them.

    It is not a character an image name may hold either, so the name is refused, and
    the refusal shows the letter as typed.
    """
    locale_name = _utf8_locale()
    if locale_name is None:
        pytest.skip("no UTF-8 locale on this host")

    result, calls = run_ash(
        "--source-dir",
        "src",
        OCI_RUNNER=str(bare_path / "recording-runner"),
        ASH_IMAGE_NAME="caf\xe9",
        LC_ALL=locale_name,
    )

    assert result.returncode == WRAPPER_REFUSAL_EXIT, result.stdout + result.stderr
    assert calls == []
    assert "The image name 'caf\xe9' starts" in result.stderr, result.stderr


def test_a_quoted_value_keeps_its_letters_in_a_utf8_locale(run_ash, bare_path):
    """Quoted for its ESC, in the caller's locale: the letter is not made octal.

    Only a value holding a format character is quoted in the C locale, because only
    there does a UTF-8 locale's %q leave a character raw.
    """
    locale_name = _utf8_locale()
    if locale_name is None:
        pytest.skip("no UTF-8 locale on this host")

    result, calls = run_ash(
        "--source-dir",
        "src",
        OCI_RUNNER=str(bare_path / "recording-runner"),
        ASH_IMAGE_NAME="caf\xe9\x1b[31m",
        LC_ALL=locale_name,
    )

    assert result.returncode == WRAPPER_REFUSAL_EXIT, result.stdout + result.stderr
    assert calls == []
    assert "The image name '$'caf\xe9\\E[31m'' starts" in result.stderr, result.stderr


def _function_source(name: str) -> str:
    """One function of ./ash, as written there: name() ( ... ) up to its closing line."""
    text = ASH_SCRIPT.read_text(encoding="utf-8")
    match = re.search(rf"^{name}\(\) \(\n.*?^\)\n", text, re.MULTILINE | re.DOTALL)
    assert match, f"{name}() not found in ./ash"
    return match.group()


def test_every_format_character_python_knows_is_quoted_in_a_utf8_locale():
    """./ash's list agrees with merge's helper, which writes out Cf, Zl and Zp.

    Every such code point this Python's Unicode tables know, run through ./ash's
    own shown() in one bash process. U+0600 to U+0605 and nine other ranges printed
    raw while merge wrote them out.
    """
    locale_name = _utf8_locale()
    if locale_name is None:
        pytest.skip("no UTF-8 locale on this host")
    codes = [
        code
        for code in range(0x110000)
        if unicodedata.category(chr(code)) in ("Cf", "Zl", "Zp")
    ]
    script = (
        _function_source("has_format_character")
        + _function_source("shown")
        + 'for value in "$@"; do shown "$value"; printf "\\0"; done\n'
    )

    result = subprocess.run(  # nosec B603 - fixed interpreter, the script's own functions
        [shutil.which("bash"), "-c", script, "bash", *(f"a{chr(c)}b" for c in codes)],
        env={"PATH": os.defpath, "LC_ALL": locale_name},
        capture_output=True,
        timeout=120,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    shown = result.stdout.split(b"\0")[:-1]
    assert len(shown) == len(codes)
    raw = [
        f"U+{code:04X}"
        for code, text in zip(codes, shown)
        if chr(code).encode("utf-8") in text or not text.startswith(b"$'")
    ]
    assert raw == [], f"shown as typed: {', '.join(raw)}"


def test_a_private_use_character_is_quoted_in_a_utf8_locale():
    """A private-use code point (Co) is written out, as Invoke-ASH writes it.

    A UTF-8 locale counts one printable, so %q left it raw, and what a terminal
    shows for it is the font's, not the text's. Every one in the Basic Multilingual
    Plane, and the first and last of planes 15 and 16, run through ./ash's shown().
    """
    locale_name = _utf8_locale()
    if locale_name is None:
        pytest.skip("no UTF-8 locale on this host")
    codes = [*range(0xE000, 0xF900), 0xF0000, 0xF0001, 0xFFFFD, 0x100000, 0x10FFFD]
    assert {unicodedata.category(chr(code)) for code in codes} == {"Co"}
    script = (
        _function_source("has_format_character")
        + _function_source("shown")
        + 'for value in "$@"; do shown "$value"; printf "\\0"; done\n'
    )

    result = subprocess.run(  # nosec B603 - fixed interpreter, the script's own functions
        [shutil.which("bash"), "-c", script, "bash", *(f"a{chr(c)}b" for c in codes)],
        env={"PATH": os.defpath, "LC_ALL": locale_name},
        capture_output=True,
        timeout=120,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    shown = result.stdout.split(b"\0")[:-1]
    assert len(shown) == len(codes)
    raw = [
        f"U+{code:04X}"
        for code, text in zip(codes, shown)
        if chr(code).encode("utf-8") in text or not text.startswith(b"$'")
    ]
    assert raw == [], f"shown as typed: {', '.join(raw[:20])} ({len(raw)} in all)"


#: Values shown() must print apart, each reading back to itself: the text of a bash
#: quoting next to the value it quotes, a backslash or $' in an otherwise printable
#: value, and a printable path with a space, which stays readable as typed.
_QUOTING_LOOKALIKES = (
    "$'a\\E[2Jb'",
    "a\x1b[2Jb",
    "$'a\\342\\200\\256b'",
    "a" + chr(0x202E) + "b",
    "a\\ b",
    "my dir",
    "C:\\src\\ash",
    "a$'b",
    "$'x'",
    "trailing\\",
    "\\E",
    "\x1b",
)


def _read_back(shown: bytes, locale_name: str) -> bytes:
    """The value bash reads from shown()'s output.

    Output with no backslash is a value printed as typed, which shown() does only
    for one holding no backslash and no $'; anything else is bash's own quoting.
    """
    if b"\\" not in shown:
        return shown
    result = subprocess.run(  # nosec B603 - fixed interpreter; the word is %q output
        [
            shutil.which("bash"),
            "-c",
            'eval "value=$1"; printf %s "$value"',
            "bash",
            shown,
        ],
        env={"PATH": os.defpath, "LC_ALL": locale_name},
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


@pytest.mark.parametrize("locale_kind", ["C", "UTF-8"])
def test_the_shown_form_reads_back_to_the_value_one_to_one(locale_kind):
    """The text $'a\\E[2Jb' and a real ESC in a\\E[2Jb were printed alike.

    shown() printed a printable value as typed, so text that reads as bash's quoting
    looked like the quoting of another value. A value holding a backslash or $' is
    now quoted too: every quoted form holds a backslash and no value printed as
    typed does, so each display reads back to one value.
    """
    locale_name = "C" if locale_kind == "C" else _utf8_locale()
    if locale_name is None:
        pytest.skip("no UTF-8 locale on this host")
    script = (
        _function_source("has_format_character")
        + _function_source("shown")
        + 'for value in "$@"; do shown "$value"; printf "\\0"; done\n'
    )

    result = subprocess.run(  # nosec B603 - fixed interpreter, the script's own functions
        [shutil.which("bash"), "-c", script, "bash", *_QUOTING_LOOKALIKES],
        env={"PATH": os.defpath, "LC_ALL": locale_name},
        capture_output=True,
        timeout=120,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    shown = result.stdout.split(b"\0")[:-1]
    assert len(shown) == len(_QUOTING_LOOKALIKES)
    assert len(set(shown)) == len(shown), shown
    for value, text in zip(_QUOTING_LOOKALIKES, shown):
        assert _read_back(text, locale_name) == value.encode("utf-8"), (value, text)
        assert b"\x1b" not in text and chr(0x202E).encode("utf-8") not in text, text
    assert shown[_QUOTING_LOOKALIKES.index("my dir")] == b"my dir"


@pytest.mark.parametrize(
    "where", ["ash-config-warning", "config-refusal", "source-dir-refusal"]
)
def test_quoting_text_and_the_value_it_quotes_are_shown_apart(
    run_ash, bare_path, where
):
    """The ASH_CONFIG warning and two refusals, each given both values.

    The warning fires for a command the config handling does not cover
    (report); for a scan, an ASH_CONFIG that names no file is the config
    refusal, with the value shown the same way.
    """
    lines = []
    for value in ("$'a\\E[2Jb'", "a\x1b[2Jb"):
        if where == "ash-config-warning":
            result, _ = run_ash(
                "--no-build",
                "--source-dir",
                "src",
                "report",
                OCI_RUNNER=str(bare_path / "recording-runner"),
                ASH_CONFIG=value,
            )
            before, after = "ASH_CONFIG is set (", "), but"
        elif where == "config-refusal":
            result, calls = run_ash(
                "--no-build",
                "--source-dir",
                "src",
                OCI_RUNNER=str(bare_path / "recording-runner"),
                ASH_CONFIG=value,
            )
            assert result.returncode == WRAPPER_REFUSAL_EXIT, result.stderr
            assert calls == []
            before, after = "Config file not found: ", ". --config"
        else:
            result, calls = run_ash(
                "--no-build",
                "--source-dir",
                value,
                OCI_RUNNER=str(bare_path / "recording-runner"),
            )
            assert result.returncode == USAGE_ERROR_EXIT, result.stderr
            assert calls == []
            # The value ends the line.
            before, after = "Source directory does not exist: ", None
        found = [line for line in result.stderr.splitlines() if before in line]
        assert len(found) == 1, result.stderr
        start = found[0].index(before) + len(before)
        shown = found[0][start : found[0].index(after) if after else None]
        assert _read_back(shown.encode("utf-8"), "C") == value.encode("utf-8"), shown
        lines.append(found[0])

    assert lines[0] != lines[1], lines


@pytest.mark.parametrize(
    "code",
    [
        pytest.param(0x00A0, id="no-break-space"),
        pytest.param(0x3000, id="ideographic-space"),
        pytest.param(0x0301, id="combining-acute-accent"),
        pytest.param(0x3164, id="hangul-filler"),
    ],
)
def test_a_space_mark_or_filler_is_shown_as_typed_only_in_a_utf8_locale(code):
    """What the help and the CHANGELOG say of Zs, Mn and fillers, measured.

    They are outside the set shown() writes out, so a UTF-8 locale prints them as
    typed. In the C locale their bytes are not printable, so the value is quoted with
    them in octal.
    """
    locale_name = _utf8_locale()
    if locale_name is None:
        pytest.skip("no UTF-8 locale on this host")
    value = f"img{chr(code)}name"
    octal = "".join(f"\\{byte:03o}" for byte in chr(code).encode("utf-8"))
    script = (
        _function_source("has_format_character")
        + _function_source("shown")
        + 'shown "$1"\n'
    )

    shown = {}
    for name in ("C", locale_name):
        result = subprocess.run(  # nosec B603 - fixed interpreter, the script's own functions
            [shutil.which("bash"), "-c", script, "bash", value],
            env={"PATH": os.defpath, "LC_ALL": name},
            capture_output=True,
            timeout=60,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        shown[name] = result.stdout

    assert shown["C"] == f"$'img{octal}name'".encode("ascii"), shown
    assert shown[locale_name] == value.encode("utf-8"), shown


def test_a_malformed_base_oci_layout_is_shown_not_obeyed(tmp_path, run_ash, bare_path):
    """The refusal quotes the variable as bash would read it back, inside the quotes
    every refusal of the variable puts around it."""
    result, calls = run_ash(
        "--source-dir",
        "src",
        OCI_RUNNER=str(bare_path / "recording-runner"),
        ASH_BASE_OCI_LAYOUT="/layouts/\x1b[2Jbase",
    )

    assert result.returncode == WRAPPER_REFUSAL_EXIT, result.stdout + result.stderr
    assert "ASH_BASE_OCI_LAYOUT is '$'/layouts/\\E[2Jbase'', which" in result.stderr, (
        result.stderr
    )
    assert "\x1b" not in result.stderr
    assert calls == []


@pytest.mark.parametrize(
    "blank", [pytest.param(" ", id="space"), pytest.param("\t", id="tab")]
)
def test_a_blank_oci_runner_from_the_environment_is_refused(run_ash, bare_path, blank):
    """OCI_RUNNER=" " is refused by the empty check before any runner call."""
    build = bare_path / "build"
    build.write_text(_GUARD_RUNNER, encoding="utf-8")
    build.chmod(build.stat().st_mode | stat.S_IXUSR)

    result, calls = run_ash("--source-dir", "src", OCI_RUNNER=blank)

    assert result.returncode == WRAPPER_REFUSAL_EXIT, result.stdout + result.stderr
    # Its own refusal, not the no-runner one, which also names OCI_RUNNER.
    assert "OCI_RUNNER is set to only whitespace" in result.stderr, result.stderr
    assert calls == [], "a command named build ran"


def test_the_empty_runner_check_comes_before_the_wrapper_prefix(
    tmp_path, run_ash, bare_path
):
    """The empty-runner check runs before OCI_RUNNER_WRAPPER is prefixed, so an
    empty runner is still refused."""
    tools_only = tmp_path / "tools-only"
    tools_only.mkdir()
    for tool in _TOOLS:
        (tools_only / tool).symlink_to(shutil.which(tool))

    result, calls = run_ash(
        "--source-dir",
        "src",
        path=tools_only,
        OCI_RUNNER_WRAPPER=str(bare_path / "recording-runner"),
    )

    assert result.returncode == WRAPPER_REFUSAL_EXIT, result.stdout + result.stderr
    assert "Unable to resolve an OCI_RUNNER" in result.stderr
    assert calls == []


@pytest.mark.parametrize(
    "args",
    [
        pytest.param(["--source-dir", "typo"], id="source-dir"),
        pytest.param(["--output-dir", "a-file"], id="output-dir"),
    ],
)
def test_a_build_without_a_run_reads_neither_directory(
    tmp_path, run_ash, bare_path, args
):
    """--no-run builds the image only, so the scan's directories are not checked."""
    (tmp_path / "a-file").write_text("", encoding="utf-8")

    result, calls = run_ash(
        "--no-run", *args, OCI_RUNNER=str(bare_path / "succeeding-runner")
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert [call.split()[:2] for call in calls] == [["succeeding-runner", "build"]]


@pytest.mark.parametrize(
    "args, code",
    [
        pytest.param(
            ["--source-dir", "no\x1b]8;;x\x07where"], USAGE_ERROR_EXIT, id="source-dir"
        ),
        # Under a file, not a file itself: mkdir cannot make it, a usage error.
        pytest.param(
            ["--source-dir", "src", "--output-dir", "a-file/\x1b[2Jout"],
            USAGE_ERROR_EXIT,
            id="output-dir",
        ),
    ],
)
def test_a_refusal_shows_control_characters_in_the_path(
    tmp_path, run_ash, bare_path, args, code
):
    """The refusal shows control characters in the path escaped, so no OSC 8 link
    or CSI sequence reaches stderr raw."""
    (tmp_path / "a-file").write_text("", encoding="utf-8")

    result, calls = run_ash(
        "--no-build", *args, OCI_RUNNER=str(bare_path / "recording-runner")
    )

    assert result.returncode == code, result.stdout + result.stderr
    assert "\x1b" not in result.stderr and "\x07" not in result.stderr, repr(
        result.stderr
    )
    assert calls == []


def test_an_output_dir_that_is_a_file(tmp_path, run_ash, bare_path):
    (tmp_path / "a-file").write_text("", encoding="utf-8")

    result, calls = run_ash(
        "--no-build",
        "--source-dir",
        "src",
        "--output-dir",
        "a-file",
        OCI_RUNNER=str(bare_path / "recording-runner"),
    )

    assert result.returncode == USAGE_ERROR_EXIT, result.stdout + result.stderr
    assert (
        "ERROR: Output directory is not a directory: a-file"
        in result.stderr.splitlines()
    ), result.stderr
    assert calls == [], "the results were sent to the working directory instead"


#: The code ./ash refuses an explicit --sandbox other than off with, the one
#: exception to WRAPPER_REFUSAL_EXIT: ASH in a container refuses it as a usage error.
SANDBOX_REFUSAL_EXIT = 5

_WORKSPACE_MESSAGE = "./ash scans one directory and cannot run a workspace scan"

#: Every refusal site in ./ash, with the code it exits with. Each cell: the arguments,
#: what the test directory needs first, the environment (a name of a runner in
#: bare_path, or a value), the code, and text found in the message. A cell either
#: names no runner or names the guard runner, so a refusal that did not happen shows
#: as a runner call and exit 99.
_ASH_SITES = {
    # A value option with no value is a usage error, 5, as the CLI's own is.
    "option-without-value": (["--oci-runner"], {}, {}, 5, "--oci-runner needs a value"),
    "option-empty": (["--output-dir", ""], {}, {}, 5, "--output-dir needs a value"),
    "option-blank": (
        ["--build-target", " "],
        {},
        {},
        5,
        "--build-target needs a value",
    ),
    "mount-path-with-a-comma": (
        ["--source-dir", "s,c"],
        {"dirs": ["s,c"]},
        {},
        3,
        "--mount cannot take",
    ),
    # A relative --source-dir whose absolute path holds a comma, from the directory
    # above it. (A link named plain to a,b is mountable: --mount is given .../plain.)
    "mount-path-resolving-to-a-comma": (
        ["--source-dir", "src"],
        {"dirs": ["a,b/src"], "cwd": "a,b"},
        {},
        3,
        "resolves to",
    ),
    "sandbox": (
        ["--sandbox", "bwrap"],
        {},
        {},
        SANDBOX_REFUSAL_EXIT,
        "--sandbox bwrap",
    ),
    "sandbox-in-a-quoted-argument": (
        ["scan --sandbox bwrap"],
        {},
        {},
        SANDBOX_REFUSAL_EXIT,
        "--sandbox bwrap",
    ),
    # An image name holds only A-Z, a-z, 0-9 and . _ : / @ -, and does not start with
    # '-', as Invoke-ASH requires, with the same message. A value it refuses is shown
    # as bash's %q quotes it when a terminal would not show it as typed (the harness
    # runs in the C locale, where a non-ASCII letter is one).
    "image-name-dash": ([], {}, {"ASH_IMAGE_NAME": "-x"}, 3, "The image name '-x'"),
    "image-name-space-inside": (
        [],
        {},
        {"ASH_IMAGE_NAME": "my image:tag"},
        3,
        "The image name 'my image:tag'",
    ),
    "image-name-leading-space": (
        [],
        {},
        {"ASH_IMAGE_NAME": " ash:ci"},
        3,
        "The image name ' ash:ci'",
    ),
    "image-name-trailing-space": (
        [],
        {},
        {"ASH_IMAGE_NAME": "ash:ci "},
        3,
        "The image name 'ash:ci '",
    ),
    "image-name-tab": (
        [],
        {},
        {"ASH_IMAGE_NAME": "ash\t:ci"},
        3,
        "The image name '$'ash\\t:ci''",
    ),
    "image-name-newline": (
        [],
        {},
        {"ASH_IMAGE_NAME": "ash:ci\nx"},
        3,
        "The image name '$'ash:ci\\nx''",
    ),
    "image-name-glob-character": (
        [],
        {},
        {"ASH_IMAGE_NAME": "ash:c*"},
        3,
        "The image name 'ash:c*'",
    ),
    "image-name-non-ascii-letter": (
        [],
        {},
        {"ASH_IMAGE_NAME": "caf\xe9:ci"},
        3,
        "The image name '$'caf\\303\\251:ci''",
    ),
    # The build target is the default image name's tag, and a stage name holds only
    # A-Z, a-z, 0-9 and . _ -.
    "build-target-dash": (["--build-target", "-x"], {}, {}, 3, "--build-target '-x'"),
    "build-target-space-inside": (
        ["--build-target", "non root"],
        {},
        {},
        3,
        "--build-target 'non root'",
    ),
    "build-target-tab": (
        ["--build-target", "ci\t"],
        {},
        {},
        3,
        "--build-target '$'ci\\t''",
    ),
    "build-target-colon": (
        ["--build-target", "ci:x"],
        {},
        {},
        3,
        "--build-target 'ci:x'",
    ),
    # A base image reference holds the same characters as an image name.
    "base-image-override-space": (
        ["--build"],
        {},
        {"ASH_BASE_IMAGE_OVERRIDE": "python:3.12 --network=host"},
        3,
        "ASH_BASE_IMAGE_OVERRIDE 'python:3.12 --network=host'",
    ),
    "base-image-override-dash": (
        ["--build"],
        {},
        {"ASH_BASE_IMAGE_OVERRIDE": "-x"},
        3,
        "ASH_BASE_IMAGE_OVERRIDE '-x'",
    ),
    "base-image-override-non-ascii-letter": (
        ["--build"],
        {},
        {"ASH_BASE_IMAGE_OVERRIDE": "pyth\xf6n:3.12"},
        3,
        "ASH_BASE_IMAGE_OVERRIDE '$'pyth\\303\\266n:3.12''",
    ),
    "source-dir-missing": (
        ["--source-dir", "no-such-dir"],
        {},
        {},
        5,
        "ERROR: Source directory does not exist: no-such-dir",
    ),
    "output-dir-under-a-file": (
        ["--output-dir", "blocker/out"],
        {"files": ["blocker"]},
        {},
        5,
        "ERROR: Output directory cannot be created: blocker/out (Not a directory)",
    ),
    "oci-runner-blank": ([], {}, {"OCI_RUNNER": "  "}, 3, "OCI_RUNNER is set to only"),
    "base-oci-layout": (
        ["--build"],
        {},
        {"ASH_BASE_OCI_LAYOUT": "/layouts/base"},
        3,
        "ASH_BASE_OCI_LAYOUT",
    ),
    "workspace": (["--workspace", "w.code-workspace"], {}, {}, 3, _WORKSPACE_MESSAGE),
    "workspace-attached": (["--workspace=auto"], {}, {}, 3, _WORKSPACE_MESSAGE),
    "workspace-config": (
        ["--workspace-config", "c.yaml"],
        {},
        {},
        3,
        _WORKSPACE_MESSAGE,
    ),
    "workspace-config-attached": (
        ["--workspace-config=c.yaml"],
        {},
        {},
        3,
        _WORKSPACE_MESSAGE,
    ),
    "workspace-after-a-subcommand": (
        ["scan", "--workspace", "auto"],
        {},
        {},
        3,
        _WORKSPACE_MESSAGE,
    ),
    "workspace-in-a-quoted-argument": (
        ["scan --workspace auto"],
        {},
        {},
        3,
        _WORKSPACE_MESSAGE,
    ),
    # Accepted, for contrast: the guard runner is called, so the exit is its 99.
    "sandbox-off": (["--sandbox", "off"], {}, {}, 99, None),
}


@pytest.mark.parametrize("site", sorted(_ASH_SITES))
def test_every_ash_refusal_exits_with_its_code(tmp_path, run_ash, bare_path, site):
    args, needs, env, code, text = _ASH_SITES[site]
    for name in needs.get("dirs", []):
        (tmp_path / name).mkdir(parents=True)
    for name in needs.get("files", []):
        (tmp_path / name).write_text("not a directory\n", encoding="utf-8")
    build = args[:1] == ["--build"]
    args = args[1:] if build else ["--no-build", *args]
    if "--source-dir" not in args:
        args = ["--source-dir", "src", *args]
    env = {"OCI_RUNNER": str(bare_path / "recording-runner"), **env}
    cwd = tmp_path / needs["cwd"] if "cwd" in needs else None

    result, calls = run_ash(*args, cwd=cwd, **env)

    assert result.returncode == code, result.stdout + result.stderr
    if text is None:
        assert calls, "the accepted call did not reach the runner"
        return
    assert text in result.stderr, result.stderr
    assert calls == []


@pytest.mark.parametrize(
    "args",
    [
        pytest.param(["--sandbox", "off"], id="option"),
        pytest.param(["--sandbox", "OFF"], id="option-upper-case"),
        pytest.param(["--sandbox=Off"], id="attached"),
        pytest.param(["scan --sandbox off"], id="quoted-argument"),
    ],
)
def test_sandbox_off_is_taken_without_tr(run_ash, bare_path, args):
    """`--sandbox off`, the mode a container takes, needs no tool to be read.

    The mode was lower-cased with tr, so without tr on PATH it read as '' and was
    refused with a message saying off is the mode a container takes. Any other mode
    is still refused, with 5, without tr: the check fails closed.
    """
    (bare_path / "tr").unlink()
    result, calls = run_ash(
        "--no-build",
        "--source-dir",
        "src",
        *args,
        OCI_RUNNER=str(bare_path / "recording-runner"),
    )

    assert result.returncode == 99, result.stdout + result.stderr
    assert calls, "the accepted call did not reach the runner"


def test_another_sandbox_mode_is_still_refused_without_tr(run_ash, bare_path):
    (bare_path / "tr").unlink()
    result, calls = run_ash(
        "--no-build",
        "--source-dir",
        "src",
        "--sandbox",
        "bwrap",
        OCI_RUNNER=str(bare_path / "recording-runner"),
    )

    assert result.returncode == SANDBOX_REFUSAL_EXIT, result.stdout + result.stderr
    assert calls == []


@pytest.mark.parametrize(
    "args",
    [
        pytest.param([], id="default-stage"),
        pytest.param(["--build-target", "ci"], id="lower-case-stage"),
    ],
)
def test_a_lower_case_build_target_needs_no_tr(run_ash, bare_path, args):
    """A stage name with no upper-case letter, the default non-root among them, is
    its own lower-case: it is taken without tr on PATH, as `--sandbox off` is. Every
    run lower-cased the stage through tr, so a run without tr was refused for a
    stage it never had to change."""
    (bare_path / "tr").unlink()
    result, calls = run_ash(
        "--no-build",
        "--source-dir",
        "src",
        *args,
        OCI_RUNNER=str(bare_path / "recording-runner"),
    )

    assert result.returncode == 99, result.stdout + result.stderr
    assert "lower-cased" not in result.stderr, result.stderr
    assert calls, "the accepted call did not reach the runner"


def test_an_upper_case_build_target_without_tr_is_refused(run_ash, bare_path):
    """A stage with an upper-case letter needs tr to be lower-cased; without it the
    stage to build is unknown, and the check fails closed with the reason."""
    (bare_path / "tr").unlink()
    result, calls = run_ash(
        "--no-build",
        "--source-dir",
        "src",
        "--build-target",
        "NON-ROOT",
        OCI_RUNNER=str(bare_path / "recording-runner"),
    )

    assert result.returncode == WRAPPER_REFUSAL_EXIT, result.stdout + result.stderr
    assert "could not be lower-cased" in result.stderr, result.stderr
    assert calls == []


def test_a_failed_build_keeps_its_own_status(run_ash, bare_path):
    """Not a refusal: the build ran and failed, so its status is what is returned."""
    result, calls = run_ash(
        "--source-dir", "src", OCI_RUNNER=str(bare_path / "recording-runner")
    )

    assert result.returncode == 99, result.stdout + result.stderr
    assert [call.split()[:2] for call in calls] == [["recording-runner", "build"]]
