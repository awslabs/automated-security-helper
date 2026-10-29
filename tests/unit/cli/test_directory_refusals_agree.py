# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A --source-dir that names no directory to scan, and an --output-dir that is a
file, are refused the same way everywhere: exit 5, with one text per case.

They were refused four ways. ./ash exited 3 with "is not a directory that can be
entered" whatever the reason; ``ash scan`` exited 5 with its own two texts; the
``ash config`` commands did not check --source-dir at all and reported "No config
file found in <the missing directory>" with exit 1 or 3; and an --output-dir that
was a file ended ``ash scan`` in a FileExistsError traceback, exit 1, where ./ash
refused it with 3. The texts name which case it is and no flag, so the MCP server,
whose parameter is directory_path, can give the same ones
(utils/directory_refusals.py). A missing --output-dir is still created.
"""

from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404 - each surface runs as a child process, as an operator runs it
import sys
from pathlib import Path

import pytest

from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from tests.utils.helpers import module_from_this_checkout

pytestmark = pytest.mark.integration

_ROOT = Path(__file__).resolve().parents[3]
_ASH_SCRIPT = _ROOT / "ash"
_HELPERS_PS1 = _ROOT / "utils" / "ash_helpers.ps1"

#: The utilities ./ash calls besides bash builtins. No container runtime: every
#: refusal here comes before ./ash looks for one, and without one a run that got
#: past the checks stops at "Unable to resolve an OCI_RUNNER" instead of running.
_TOOLS = ("dirname", "basename", "mkdir", "id", "date", "cat", "tr", "rm")


def _cases(base: Path) -> dict:
    """Each source directory case: the value given, and the text it is refused with.

    A link to nothing names nothing, as a path that is not there does, and so does a
    link that leads back to itself."""
    (base / "a-file").write_text("x\n", encoding="utf-8")
    if os.name != "nt":
        (base / "a-link").symlink_to(base / "nowhere")
        (base / "a-loop").symlink_to(base / "a-loop")
    return {
        "does-not-exist": (
            str(base / "nope"),
            f"Source directory does not exist: {base / 'nope'}",
        ),
        "a-file": (
            str(base / "a-file"),
            f"Source directory is not a directory: {base / 'a-file'}",
        ),
        "a-link-to-nothing": (
            str(base / "a-link"),
            f"Source directory does not exist: {base / 'a-link'}",
        ),
        "a-link-to-itself": (
            str(base / "a-loop"),
            f"Source directory does not exist: {base / 'a-loop'}",
        ),
    }


_NEEDS_SYMLINKS = pytest.mark.skipif(
    os.name == "nt", reason="a symbolic link needs a privilege on Windows"
)

#: The ids of _cases, for parametrize.
_SOURCE_CASES = [
    "does-not-exist",
    "a-file",
    pytest.param("a-link-to-nothing", marks=_NEEDS_SYMLINKS),
    pytest.param("a-link-to-itself", marks=_NEEDS_SYMLINKS),
]


@pytest.fixture(params=["no-search", "no-read", "under-no-search"])
def unenterable(tmp_path, request):
    """A source directory that is there but cannot be scanned, and its refusal text:
    one without search permission, one without read permission, whose entries
    cannot be listed, and one under a directory without search permission, which
    cannot be reached. A path that cannot be reached is not one that does not
    exist: the OS answers EACCES for it, not ENOENT."""
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("root enters and lists a directory without those permissions")
    if os.name == "nt":
        pytest.skip("Windows has no search permission on a directory")
    locked = tmp_path / "locked"
    locked.mkdir()
    given = locked
    mode = 0o600
    if request.param == "no-read":
        mode = 0o300
    elif request.param == "under-no-search":
        given = locked / "inner"
        given.mkdir()
    locked.chmod(mode)
    try:
        yield str(given), f"Source directory cannot be entered: {given}"
    finally:
        locked.chmod(0o700)


def _without_permissions_skip() -> None:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("root writes and enters a directory without those permissions")
    if os.name == "nt":
        pytest.skip("Windows has no search permission on a directory")


@pytest.fixture(params=["under-a-file", "in-a-read-only-directory"])
def unmakeable(tmp_path, request):
    """An output directory that cannot be made, and its refusal text, whose reason is
    the system's own (its strerror): a file on the way to it, or a parent that
    cannot be written. Nothing is made either way."""
    if request.param == "under-a-file":
        (tmp_path / "blocker").write_text("x\n", encoding="utf-8")
        out = tmp_path / "blocker" / "out"
        yield out, f"Output directory cannot be created: {out} (Not a directory)"
        return
    _without_permissions_skip()
    parent = tmp_path / "read-only"
    parent.mkdir()
    parent.chmod(0o500)
    out = parent / "out"
    try:
        yield out, f"Output directory cannot be created: {out} (Permission denied)"
    finally:
        parent.chmod(0o700)


@pytest.fixture
def unenterable_output(tmp_path):
    """An output directory that is there but cannot be entered, and its refusal text."""
    _without_permissions_skip()
    out = tmp_path / "locked-out"
    out.mkdir()
    out.chmod(0o600)
    try:
        yield out, f"Output directory cannot be entered: {out}"
    finally:
        out.chmod(0o700)


@pytest.fixture
def unwritable_output(tmp_path):
    """An output directory that is there and can be entered but not written, and its
    refusal text. A read-only mount is refused the same way, with that reason; it
    needs a mount, so it is checked once, on the shared check, in
    tests/unit/utils/test_output_dir_write_check.py."""
    _without_permissions_skip()
    out = tmp_path / "read-only-out"
    out.mkdir()
    out.chmod(0o555)
    try:
        yield out, f"Output directory cannot be written: {out} (Permission denied)"
    finally:
        out.chmod(0o755)


def _cli(cwd: Path, *args: str, **env: str) -> subprocess.CompletedProcess:
    # A HOME of its own: where a check is missing, the run goes on to scan, and
    # what its tools cache must not land in the session's HOME.
    home = cwd / "home"
    home.mkdir(exist_ok=True)
    homes = {
        "HOME": str(home),
        "USERPROFILE": str(home),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_DATA_HOME": str(home / ".local" / "share"),
        "XDG_STATE_HOME": str(home / ".local" / "state"),
        # tests/unit/conftest.py points these at the HOME it checks afterwards.
        "UV_CACHE_DIR": str(home / ".cache" / "uv"),
        "UV_TOOL_DIR": str(home / ".local" / "share" / "uv" / "tools"),
        "UV_OFFLINE": "1",
    }
    return subprocess.run(  # nosec B603 - fixed interpreter and arguments
        [
            sys.executable,
            "-I",
            "-c",
            module_from_this_checkout("automated_security_helper.cli.main"),
            *args,
        ],
        cwd=cwd,
        env={**os.environ, "COLUMNS": "400", "TERMINAL_WIDTH": "400", **homes, **env},
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


def _ash(tmp_path: Path, *args: str) -> subprocess.CompletedProcess:
    tools = tmp_path / "tools"
    if not tools.exists():
        tools.mkdir()
        for tool in _TOOLS:
            found = shutil.which(tool)
            assert found, f"{tool} is not installed; ./ash needs it"
            (tools / tool).symlink_to(found)
    return subprocess.run(  # nosec B603 - fixed interpreter and script, list args
        [shutil.which("bash"), str(_ASH_SCRIPT), "--no-build", *args],
        cwd=tmp_path,
        env={"PATH": str(tools), "HOME": str(tmp_path)},
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def _assert_refused(
    result: subprocess.CompletedProcess, text: str, *, whole_line: bool = True
) -> None:
    """Exit 5, and *text* as a line of its own: the same message on every surface,
    with nothing added to it (PowerShell's error record frames its message, so
    there it is looked for inside its line)."""
    output = result.stdout + result.stderr
    assert result.returncode == ASH_EXIT_USAGE_ERROR, output
    if whole_line:
        assert text in [line.rstrip() for line in result.stderr.splitlines()], output
    else:
        assert text in output, output
    assert "Traceback" not in output, output


_SCAN = ("scan", "--mode", "local", "--offline", "--scanners", "detect-secrets")


@pytest.mark.parametrize("case", _SOURCE_CASES)
def test_ash_scan_refuses_a_source_dir(tmp_path, case):
    given, text = _cases(tmp_path)[case]

    _assert_refused(
        _cli(
            tmp_path,
            *_SCAN,
            "--source-dir",
            given,
            "--output-dir",
            str(tmp_path / "out"),
        ),
        text,
    )


def test_ash_scan_refuses_a_source_dir_that_cannot_be_entered(tmp_path, unenterable):
    given, text = unenterable

    _assert_refused(
        _cli(
            tmp_path,
            *_SCAN,
            "--source-dir",
            given,
            "--output-dir",
            str(tmp_path / "out"),
        ),
        text,
    )


def test_ash_scan_refuses_ash_source_dir_the_same_way(tmp_path):
    given, text = _cases(tmp_path)["does-not-exist"]

    _assert_refused(
        _cli(
            tmp_path,
            *_SCAN,
            "--output-dir",
            str(tmp_path / "out"),
            ASH_SOURCE_DIR=given,
        ),
        text,
    )


#: A directory named so that its refusal, printed with the newline as it is, would
#: read as a second message saying all is well.
_FORGED = "n\nSource directory is fine"


def _one_line(path: Path) -> str:
    return str(path).replace("\n", "\\x0a")


@pytest.mark.parametrize(
    "command",
    [pytest.param(_SCAN, id="scan"), pytest.param(("config", "validate"), id="config")],
)
def test_a_source_dir_refusal_stays_on_one_line(tmp_path, command):
    """The path's newline is shown as an escape, as ./ash shows it, so the name
    cannot make a line of its own."""
    given = tmp_path / _FORGED

    result = _cli(tmp_path, *command, "--source-dir", str(given))

    _assert_refused(result, f"Source directory does not exist: {_one_line(given)}")
    assert "Source directory is fine" not in result.stderr.splitlines(), result.stderr


def test_an_output_dir_refusal_stays_on_one_line(tmp_path):
    (tmp_path / "src").mkdir()
    blocker = tmp_path / _FORGED
    blocker.write_text("x\n", encoding="utf-8")

    result = _cli(
        tmp_path,
        *_SCAN,
        "--source-dir",
        str(tmp_path / "src"),
        "--output-dir",
        str(blocker),
    )

    _assert_refused(
        result, f"Output directory is not a directory: {_one_line(blocker)}"
    )
    assert "Source directory is fine" not in result.stderr.splitlines(), result.stderr


def _no_forged_line(stderr: str) -> None:
    assert not any(
        line.startswith("Source directory is fine") for line in stderr.splitlines()
    ), stderr


def test_the_use_existing_refusal_names_the_output_dir_on_one_line(tmp_path):
    """--use-existing with no results there exits 1 naming where it looked, on one
    line whatever the --output-dir holds."""
    (tmp_path / "src").mkdir()
    out = tmp_path / _FORGED
    out.mkdir()

    result = _cli(
        tmp_path,
        *_SCAN,
        "--use-existing",
        "--source-dir",
        str(tmp_path / "src"),
        "--output-dir",
        str(out),
    )

    assert result.returncode == 1, result.stdout + result.stderr
    assert f"{_one_line(out)}/ash_aggregated_results.json" in result.stderr
    _no_forged_line(result.stderr)


def test_ash_report_without_results_names_the_output_dir_on_one_line(tmp_path):
    out = tmp_path / _FORGED
    out.mkdir()

    result = _cli(tmp_path, "report", "--output-dir", str(out))

    assert result.returncode == 1, result.stdout + result.stderr
    assert "No scan results found" in result.stderr, result.stderr
    assert _one_line(out) in result.stderr, result.stderr
    _no_forged_line(result.stderr)


def test_ash_report_that_cannot_read_its_results_names_them_on_one_line(tmp_path):
    out = tmp_path / _FORGED
    out.mkdir()
    (out / "ash_aggregated_results.json").write_text("{", encoding="utf-8")

    result = _cli(tmp_path, "report", "--output-dir", str(out))

    assert result.returncode == 1, result.stdout + result.stderr
    assert "Could not read the scan results in" in result.stderr, result.stderr
    assert _one_line(out) in result.stderr, result.stderr
    _no_forged_line(result.stderr)


def test_ash_scan_refuses_an_output_dir_that_is_a_file(tmp_path):
    (tmp_path / "src").mkdir()
    blocker = tmp_path / "out-file"
    blocker.write_text("x\n", encoding="utf-8")

    result = _cli(
        tmp_path,
        *_SCAN,
        "--source-dir",
        str(tmp_path / "src"),
        "--output-dir",
        str(blocker),
    )

    _assert_refused(result, f"Output directory is not a directory: {blocker}")
    assert blocker.read_text(encoding="utf-8") == "x\n"


def test_ash_scan_refuses_an_output_dir_that_cannot_be_created(tmp_path, unmakeable):
    """It ended in a NotADirectoryError or PermissionError traceback, exit 1, from
    the first mkdir of the directory."""
    (tmp_path / "src").mkdir()
    out, text = unmakeable

    result = _cli(
        tmp_path,
        *_SCAN,
        "--source-dir",
        str(tmp_path / "src"),
        "--output-dir",
        str(out),
    )

    _assert_refused(result, text)
    assert not out.exists()


def test_ash_scan_refuses_an_output_dir_that_cannot_be_entered(
    tmp_path, unenterable_output
):
    (tmp_path / "src").mkdir()
    out, text = unenterable_output

    result = _cli(
        tmp_path,
        *_SCAN,
        "--source-dir",
        str(tmp_path / "src"),
        "--output-dir",
        str(out),
    )

    _assert_refused(result, text)


def test_ash_scan_refuses_an_output_dir_that_cannot_be_written(
    tmp_path, unwritable_output
):
    """It ended in a PermissionError traceback, exit 1, writing ash.log."""
    (tmp_path / "src").mkdir()
    out, text = unwritable_output

    result = _cli(
        tmp_path,
        *_SCAN,
        "--source-dir",
        str(tmp_path / "src"),
        "--output-dir",
        str(out),
    )

    _assert_refused(result, text)
    assert list(out.iterdir()) == []


_CONFIG_COMMANDS = [
    pytest.param(["config", "get"], id="get"),
    pytest.param(["config", "validate"], id="validate"),
    pytest.param(["config", "lint"], id="lint"),
    pytest.param(
        ["config", "validate-plugin-dependencies"], id="validate-plugin-dependencies"
    ),
]


@pytest.mark.parametrize("command", _CONFIG_COMMANDS)
@pytest.mark.parametrize("case", _SOURCE_CASES)
def test_a_config_command_refuses_a_source_dir(tmp_path, command, case):
    """The refusal names the missing source directory; it does not read "No
    config file found in" it, as if it had looked in one."""
    given, text = _cases(tmp_path)[case]

    _assert_refused(_cli(tmp_path, *command, "--source-dir", given), text)


@pytest.mark.parametrize("command", _CONFIG_COMMANDS)
def test_a_config_command_refuses_a_source_dir_that_cannot_be_entered(
    tmp_path, command, unenterable
):
    given, text = unenterable

    _assert_refused(_cli(tmp_path, *command, "--source-dir", given), text)


@pytest.mark.skipif(os.name == "nt", reason="./ash is a bash script")
@pytest.mark.parametrize("case", _SOURCE_CASES)
def test_the_bash_wrapper_refuses_a_source_dir(tmp_path, case):
    given, text = _cases(tmp_path)[case]

    _assert_refused(_ash(tmp_path, "--source-dir", given), f"ERROR: {text}")


@pytest.mark.skipif(os.name == "nt", reason="./ash is a bash script")
def test_the_bash_wrapper_refuses_a_source_dir_that_cannot_be_entered(
    tmp_path, unenterable
):
    given, text = unenterable

    _assert_refused(_ash(tmp_path, "--source-dir", given), f"ERROR: {text}")


@pytest.mark.skipif(os.name == "nt", reason="./ash is a bash script")
def test_the_bash_wrapper_refuses_an_output_dir_that_is_a_file(tmp_path):
    (tmp_path / "src").mkdir()
    blocker = tmp_path / "out-file"
    blocker.write_text("x\n", encoding="utf-8")

    result = _ash(tmp_path, "--source-dir", "src", "--output-dir", str(blocker))

    _assert_refused(result, f"ERROR: Output directory is not a directory: {blocker}")
    assert blocker.read_text(encoding="utf-8") == "x\n"


@pytest.mark.skipif(os.name == "nt", reason="./ash is a bash script")
def test_the_bash_wrapper_refuses_an_output_dir_that_cannot_be_created(
    tmp_path, unmakeable
):
    """It exited 3 with a text of its own, naming --output-dir."""
    (tmp_path / "src").mkdir()
    out, text = unmakeable

    result = _ash(tmp_path, "--source-dir", "src", "--output-dir", str(out))

    _assert_refused(result, f"ERROR: {text}")
    assert not out.exists()


@pytest.mark.skipif(os.name == "nt", reason="./ash is a bash script")
def test_the_bash_wrapper_refuses_an_output_dir_that_cannot_be_entered(
    tmp_path, unenterable_output
):
    (tmp_path / "src").mkdir()
    out, text = unenterable_output

    result = _ash(tmp_path, "--source-dir", "src", "--output-dir", str(out))

    _assert_refused(result, f"ERROR: {text}")


@pytest.mark.skipif(os.name == "nt", reason="./ash is a bash script")
def test_the_bash_wrapper_refuses_an_output_dir_that_cannot_be_written(
    tmp_path, unwritable_output
):
    """It was mounted and the scan in the container failed to write there."""
    (tmp_path / "src").mkdir()
    out, text = unwritable_output

    result = _ash(tmp_path, "--source-dir", "src", "--output-dir", str(out))

    _assert_refused(result, f"ERROR: {text}")
    assert list(out.iterdir()) == []


@pytest.mark.skipif(os.name == "nt", reason="./ash is a bash script")
def test_the_bash_wrapper_leaves_nothing_in_a_writable_output_dir(tmp_path):
    """The control: one that can be written is not refused, and the file the check
    makes there is gone."""
    (tmp_path / "src").mkdir()
    out = tmp_path / "out"
    out.mkdir()

    result = _ash(tmp_path, "--source-dir", "src", "--output-dir", str(out))

    assert "Unable to resolve an OCI_RUNNER" in result.stderr, result.stderr
    assert list(out.iterdir()) == []


@pytest.mark.skipif(os.name == "nt", reason="./ash is a bash script")
def test_the_bash_wrapper_still_makes_a_missing_output_dir(tmp_path):
    """The control: a missing --output-dir, parents and all, is made, not refused."""
    (tmp_path / "src").mkdir()
    out = tmp_path / "p" / "q" / "out"

    result = _ash(tmp_path, "--source-dir", "src", "--output-dir", str(out))

    assert out.is_dir(), result.stdout + result.stderr
    assert "Unable to resolve an OCI_RUNNER" in result.stderr, result.stderr


def _invoke_ash(tmp_path: Path, arguments: str) -> subprocess.CompletedProcess:
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("pwsh is not on PATH; these run in CI, where it is")
    from tests.utils.pwsh_env import QUIET_PWSH, inherited_env, scratch_home

    return subprocess.run(  # nosec B603 - fixed interpreter and script
        [
            pwsh,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            (
                f". '{_HELPERS_PS1}'; "
                f"try {{ Invoke-ASH -NoBuild {arguments} }} "
                "catch { Write-Error -ErrorRecord $_ -ErrorAction Continue; "
                "exit $(if ($LASTEXITCODE) { $LASTEXITCODE } else { 1 }) }"
            ),
        ],
        cwd=tmp_path,
        env={**inherited_env(), **scratch_home(tmp_path), **QUIET_PWSH},
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


@pytest.mark.parametrize("case", _SOURCE_CASES)
def test_invoke_ash_refuses_a_source_dir(tmp_path, case):
    given, text = _cases(tmp_path)[case]

    _assert_refused(
        _invoke_ash(tmp_path, f"-SourceDir '{given}'"), text, whole_line=False
    )


@_NEEDS_SYMLINKS
def test_a_link_into_a_directory_that_cannot_be_searched_cannot_be_entered(tmp_path):
    """The link's target cannot be reached, so stat answers EACCES, as it does for
    the target itself: ash scan and Invoke-ASH say "cannot be entered". Invoke-ASH
    did not catch the UnauthorizedAccessException of resolving the link, and ended
    with no exit 5. (./ash cannot follow a link without a tool, and says "does not
    exist" for it, a known difference.)"""
    _without_permissions_skip()
    locked = tmp_path / "locked"
    (locked / "inner").mkdir(parents=True)
    link = tmp_path / "a-link"
    link.symlink_to(locked / "inner")
    locked.chmod(0o600)
    text = f"Source directory cannot be entered: {link}"
    try:
        scanned = _cli(
            tmp_path,
            *_SCAN,
            "--source-dir",
            str(link),
            "--output-dir",
            str(tmp_path / "out"),
        )
        invoked = (
            _invoke_ash(tmp_path, f"-SourceDir '{link}'")
            if shutil.which("pwsh")
            else None
        )
    finally:
        locked.chmod(0o700)

    _assert_refused(scanned, text)
    if invoked is None:
        pytest.skip("pwsh is not on PATH; the Invoke-ASH half runs in CI, where it is")
    _assert_refused(invoked, text, whole_line=False)


def test_invoke_ash_refuses_a_source_dir_that_cannot_be_entered(tmp_path, unenterable):
    given, text = unenterable

    _assert_refused(
        _invoke_ash(tmp_path, f"-SourceDir '{given}'"), text, whole_line=False
    )


def test_invoke_ash_refuses_an_output_dir_that_is_a_file(tmp_path):
    (tmp_path / "src").mkdir()
    blocker = tmp_path / "out-file"
    blocker.write_text("x\n", encoding="utf-8")

    result = _invoke_ash(tmp_path, f"-SourceDir src -OutputDir '{blocker}'")

    _assert_refused(
        result, f"Output directory is not a directory: {blocker}", whole_line=False
    )
    assert blocker.read_text(encoding="utf-8") == "x\n"


def test_invoke_ash_refuses_an_output_dir_that_cannot_be_created(tmp_path, unmakeable):
    """It exited 3 with a text of its own, naming -OutputDir; under a file, New-Item
    on Linux makes nothing and reports nothing, so no reason was given."""
    (tmp_path / "src").mkdir()
    out, text = unmakeable

    result = _invoke_ash(tmp_path, f"-SourceDir src -OutputDir '{out}'")

    _assert_refused(result, text, whole_line=False)
    assert not out.exists()


def test_invoke_ash_refuses_an_output_dir_that_cannot_be_entered(
    tmp_path, unenterable_output
):
    (tmp_path / "src").mkdir()
    out, text = unenterable_output

    result = _invoke_ash(tmp_path, f"-SourceDir src -OutputDir '{out}'")

    _assert_refused(result, text, whole_line=False)


def test_invoke_ash_refuses_an_output_dir_that_cannot_be_written(
    tmp_path, unwritable_output
):
    (tmp_path / "src").mkdir()
    out, text = unwritable_output

    result = _invoke_ash(tmp_path, f"-SourceDir src -OutputDir '{out}'")

    _assert_refused(result, text, whole_line=False)
    assert list(out.iterdir()) == []


def test_invoke_ash_leaves_nothing_in_a_writable_output_dir(tmp_path):
    """The control: not refused, so it gets as far as looking for a runner, and the
    file the check makes is gone."""
    (tmp_path / "src").mkdir()
    out = tmp_path / "out"
    out.mkdir()

    result = _invoke_ash(
        tmp_path, f"-SourceDir src -OutputDir '{out}' -OCIRunner no-such-oci-runner"
    )

    output = result.stdout + result.stderr
    assert "UnabletoresolveanOCI_RUNNER" in "".join(output.split()), output
    assert list(out.iterdir()) == []
