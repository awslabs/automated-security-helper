# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``utils/ash_helpers.sh`` must work when sourced from bash, zsh, ksh93, and POSIX sh.

The file is meant to be sourced from a shell profile, so it finds the checkout from
the sourced file's own path, not from ``$0``: a sourced file's ``$0`` is the shell
("bash", "-bash") or the script that sourced it, never the file itself (zsh is the
exception), so under bash ``ASH_ROOT_DIR`` would be the current directory (or the
sourcing script's parent) and ``invoke-ash`` would run an ``ash`` that is not there.
It defines ``invoke_ash``, and ``invoke-ash`` only where the shell accepts a hyphen in
a function name: under dash, ``bash --posix`` and ksh93, ``invoke-ash() {`` is a
syntax error that would keep the file from loading at all.

Each test sources a copy of the real file placed in a scratch checkout whose path
contains a space, from a different working directory, the way a profile does.
The checkout's ``ash`` is a stub that records its arguments, so a test can tell
which ``ash`` a call reached and with what.

A shell that is not installed is skipped: which ones exist differs by runner
image, and every Linux and macOS runner has bash and sh, which are the two most
users source this from.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess  # nosec B404 - sourcing the helper in each shell is the point
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS = REPO_ROOT / "utils" / "ash_helpers.sh"

pytestmark = [
    # The helper is for POSIX shells. On a GitHub Windows runner shutil.which("bash")
    # finds the WSL launcher stub, which exits 1 without a distribution installed, so
    # a which() guard is not enough to keep these off Windows.
    pytest.mark.skipif(
        os.name == "nt",
        reason="ash_helpers.sh is for POSIX shells; see ash_helpers.ps1",
    ),
    pytest.mark.skipif(
        not HELPERS.is_file(),
        reason="utils/ash_helpers.sh not present (installed-package layout)",
    ),
]

# Shells that report the path of a file being sourced (BASH_SOURCE, zsh's %x and
# ksh93's .sh.file), so the helper must find the checkout by itself under them.
# "sh" is left out on purpose: it is dash on Debian and Ubuntu and bash on Amazon
# Linux and macOS, so whether it can is a property of the host.
LOCATING_SHELLS = ["bash", "zsh", "ksh"]
# A shell with no way to name the sourced file. It must use a preset ASH_ROOT_DIR,
# and without one refuse clearly instead of guessing.
NON_LOCATING_SHELLS = ["dash"]
ALL_SHELLS = ["bash", "sh", "dash", "zsh", "ksh"]
# A refusal of the wrappers returns 3, the code ASH uses for input it refuses (the
# same for ./ash, Invoke-ASH and this helper), as printed by the probe's
# `echo "rc=$rc"`.
REFUSAL_EXIT = "3"

STUB_ASH = """#!/bin/sh
for arg in "$@"; do
  printf '%s\\n' "$arg" >> "$ASH_STUB_LOG"
done
printf -- '--\\n' >> "$ASH_STUB_LOG"
"""

# The function and the hyphenated name are both called, each on its own line: an
# alias (how POSIX sh gets invoke-ash) applies only to lines read after it is
# defined, which is also how a profile followed by an interactive prompt works.
CALLS = """
echo "rc=$rc"
echo "root=$ASH_ROOT_DIR"
invoke_ash --first "two words"
invoke-ash --second
echo "after=ok"
"""


def _shell_or_skip(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        pytest.skip(f"{name} is not installed on this host")
    return path


@pytest.fixture
def checkout(tmp_path: Path) -> Path:
    """A scratch ASH checkout holding a copy of the helper and a recording ``ash``."""
    root = tmp_path / "ash checkout"
    (root / "utils").mkdir(parents=True)
    shutil.copy2(HELPERS, root / "utils" / "ash_helpers.sh")
    stub = root / "ash"
    stub.write_text(STUB_ASH, encoding="utf-8")
    stub.chmod(0o755)
    return root


def _source(
    shell: str,
    checkout: Path,
    tmp_path: Path,
    preamble: str = "",
    extra_env=None,
    timeout: float = 60,
) -> tuple[subprocess.CompletedProcess, list[str]]:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(exist_ok=True)
    log = tmp_path / "ash-stub.log"
    log.unlink(missing_ok=True)
    # No startup file of the developer's may run: BASH_ENV (non-interactive bash),
    # ENV (sh and ksh), and ZDOTDIR or HOME (zsh reads .zshenv from either).
    env = {
        k: v
        for k, v in os.environ.items()
        if k
        not in (
            "ASH_ROOT_DIR",
            "ASH_UTILS_DIR",
            "ASH_HELPERS_SCRIPT",
            "BASH_ENV",
            "ENV",
            "ZDOTDIR",
        )
    }
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env["HOME"] = str(home)
    env["ZDOTDIR"] = str(home)
    env["ASH_STUB_LOG"] = str(log)
    env["HELPERS"] = str(checkout / "utils" / "ash_helpers.sh")
    env.update(extra_env or {})
    script = preamble + '. "$HELPERS"\nrc=$?\n' + CALLS
    try:
        result = subprocess.run(  # nosec B603 - fixed shell, script built here
            [_shell_or_skip(shell), "-c", script],
            cwd=elsewhere,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"sourcing the helper under {shell} did not end in {timeout}s")
    calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    return result, calls


def _reported(result: subprocess.CompletedProcess, key: str) -> str:
    prefix = f"{key}="
    for line in result.stdout.splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :]
    raise AssertionError(
        f"the shell never printed {key}=; stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )


def _assert_working(result, calls, checkout: Path) -> None:
    detail = f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    assert _reported(result, "rc") == "0", detail
    assert Path(_reported(result, "root")).resolve() == checkout.resolve(), detail
    assert calls == ["--first", "two words", "--", "--second", "--"], detail
    assert _reported(result, "after") == "ok", detail


@pytest.mark.parametrize("shell", LOCATING_SHELLS)
def test_sourcing_finds_the_checkout_from_the_file_itself(shell, checkout, tmp_path):
    result, calls = _source(shell, checkout, tmp_path)
    _assert_working(result, calls, checkout)


@pytest.mark.parametrize("shell", LOCATING_SHELLS)
def test_the_files_own_location_wins_over_a_stale_ash_root_dir(
    shell, checkout, tmp_path
):
    stale = tmp_path / "some other checkout"
    stale.mkdir()
    (stale / "ash").write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
    (stale / "ash").chmod(0o755)
    result, calls = _source(
        shell, checkout, tmp_path, extra_env={"ASH_ROOT_DIR": str(stale)}
    )
    _assert_working(result, calls, checkout)


@pytest.mark.parametrize("shell", ALL_SHELLS)
def test_a_preset_ash_root_dir_works_in_every_shell(shell, checkout, tmp_path):
    result, calls = _source(
        shell, checkout, tmp_path, extra_env={"ASH_ROOT_DIR": str(checkout)}
    )
    _assert_working(result, calls, checkout)


@pytest.mark.parametrize("shell", ALL_SHELLS)
def test_sourcing_twice_still_works(shell, checkout, tmp_path):
    # A profile re-read with `. ~/.profile` sources the helper a second time. Where
    # invoke-ash is an alias, a careless redefinition expands the alias inside its own
    # definition and produces a function that calls itself forever.
    result, calls = _source(
        shell,
        checkout,
        tmp_path,
        preamble='. "$HELPERS"\n',
        extra_env={"ASH_ROOT_DIR": str(checkout)},
    )
    _assert_working(result, calls, checkout)


@pytest.mark.parametrize("shell", LOCATING_SHELLS)
def test_a_relative_path_resolves_even_with_cdpath_set(shell, checkout, tmp_path):
    # With CDPATH set, `cd` into a relative path that does not start with ./ looks it
    # up through CDPATH first. The first entry here is a decoy holding the same
    # relative path, with an ash that fails, so a helper that does not clear CDPATH
    # adopts the decoy and invoke_ash runs the wrong ash.
    decoy = tmp_path / "cdpath decoy"
    (decoy / checkout.name / "utils").mkdir(parents=True)
    decoy_ash = decoy / checkout.name / "ash"
    decoy_ash.write_text(
        '#!/bin/sh\necho ran-the-decoy >> "$ASH_STUB_LOG"\nexit 99\n', encoding="utf-8"
    )
    decoy_ash.chmod(0o755)
    result, calls = _source(
        shell,
        checkout,
        tmp_path,
        preamble='cd "$CHECKOUT_PARENT"\nHELPERS="ash checkout/utils/ash_helpers.sh"\n',
        extra_env={"CDPATH": f"{decoy}:.", "CHECKOUT_PARENT": str(tmp_path)},
    )
    _assert_working(result, calls, checkout)


@pytest.mark.parametrize("shell", LOCATING_SHELLS)
def test_a_failing_cd_under_set_e_keeps_the_preset_and_the_shell(
    shell, checkout, tmp_path
):
    # The cd that computes the checkout's path runs inside $(...) in an assignment,
    # whose status is the substitution's, so under set -e a failing cd would end the
    # shell that sources the helper: the user's profile. A cd function stands in for a
    # cd that fails; the helper must go on and use the preset ASH_ROOT_DIR.
    result, calls = _source(
        shell,
        checkout,
        tmp_path,
        preamble=(
            "set -e\n"
            'cd() { case "$*" in *utils/..*) return 1 ;; esac; command cd "$@"; }\n'
        ),
        extra_env={"ASH_ROOT_DIR": str(checkout)},
    )
    _assert_working(result, calls, checkout)


def _outside_link(checkout: Path, tmp_path: Path) -> Path:
    """A link to the checkout's helper from a directory with no ash above it."""
    outside = tmp_path / "bin"
    outside.mkdir()
    link = outside / "ash_helpers.sh"
    link.symlink_to(checkout / "utils" / "ash_helpers.sh")
    return link


@pytest.mark.parametrize("shell", LOCATING_SHELLS)
def test_a_failing_readlink_under_set_e_keeps_the_preset_and_the_shell(
    shell, checkout, tmp_path
):
    # The helper follows a link with readlink inside $(...) in an assignment, whose
    # status is the substitution's, so under set -e a failing readlink would end the
    # shell that sources it. A readlink function stands in for one that fails.
    result, calls = _source(
        shell,
        checkout,
        tmp_path,
        preamble="set -e\nreadlink() { return 1; }\n",
        extra_env={
            "ASH_ROOT_DIR": str(checkout),
            "HELPERS": str(_outside_link(checkout, tmp_path)),
        },
    )
    _assert_working(result, calls, checkout)


def _documented_hop_cap() -> int:
    """How many links deep the helper says it follows a link, from its own comment.

    The comment is the cap's statement: the number in the loop is what a mutant
    changes, and an expectation read from there would move with it.
    """
    found = re.search(r"followed at most (\d+) links deep", HELPERS.read_text("utf-8"))
    assert found, "the helper no longer says how many links deep it follows a link"
    return int(found.group(1))


@pytest.mark.parametrize("shell", LOCATING_SHELLS)
def test_a_link_that_names_itself_ends_the_search(shell, checkout, tmp_path):
    # A readlink that keeps returning the link (a loop the file system would refuse,
    # stood in by a function) would follow it forever; the search stops at the
    # documented cap and uses the preset ASH_ROOT_DIR. The stand-in writes a line per
    # call, so the count is the cap the helper keeps to, not only that it stopped.
    # The 60 s budget catches a search that never stops: zsh's 40 hops took 1.1 s
    # alone and over 10 s in a 24-worker run on a loaded host.
    readlink_calls = tmp_path / "readlink.calls"
    result, calls = _source(
        shell,
        checkout,
        tmp_path,
        preamble=(
            'readlink() { printf \'%s\\n\' "$1" >> "$READLINK_CALLS"; '
            "printf '%s\\n' \"$1\"; }\n"
        ),
        extra_env={
            "ASH_ROOT_DIR": str(checkout),
            "HELPERS": str(_outside_link(checkout, tmp_path)),
            "READLINK_CALLS": str(readlink_calls),
        },
        timeout=60,
    )
    _assert_working(result, calls, checkout)
    followed = readlink_calls.read_text(encoding="utf-8").splitlines()
    assert len(followed) == _documented_hop_cap(), len(followed)


@pytest.mark.parametrize("shell", ALL_SHELLS)
def test_a_profile_running_under_set_eu_is_not_broken(shell, checkout, tmp_path):
    result, calls = _source(
        shell,
        checkout,
        tmp_path,
        preamble="set -eu\n",
        extra_env={"ASH_ROOT_DIR": str(checkout)},
    )
    _assert_working(result, calls, checkout)


@pytest.mark.parametrize("relative", [False, True])
@pytest.mark.parametrize("shell", LOCATING_SHELLS)
def test_a_link_to_the_helper_from_outside_the_checkout_is_followed(
    shell, relative, checkout, tmp_path
):
    # A profile often sources a link in ~/bin or similar. The link's own directory is
    # not in the checkout, so the checkout is found by following the link.
    # Two levels below tmp_path, while the shell's working directory is one level
    # below: a relative target resolved against the working directory instead of the
    # link's own directory names a path that does not exist.
    links = tmp_path / "home bin" / "deep"
    links.mkdir(parents=True)
    target = checkout / "utils" / "ash_helpers.sh"
    link = links / "ash_helpers.sh"
    link.symlink_to(
        Path("..") / ".." / checkout.name / "utils" / target.name
        if relative
        else target
    )
    result, calls = _source(shell, checkout, tmp_path, extra_env={"HELPERS": str(link)})
    _assert_working(result, calls, checkout)


@pytest.mark.parametrize("shell", LOCATING_SHELLS)
def test_a_symlinked_utils_directory_is_resolved(shell, checkout, tmp_path):
    # The file is not a link, its directory is: `cd dir/..` without -P goes to the
    # link's parent, not the checkout.
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "ash-utils").symlink_to(checkout / "utils", target_is_directory=True)
    result, calls = _source(
        shell,
        checkout,
        tmp_path,
        extra_env={"HELPERS": str(tools / "ash-utils" / "ash_helpers.sh")},
    )
    _assert_working(result, calls, checkout)


def test_a_zsh_chpwd_hook_that_prints_is_not_taken_for_the_path(checkout, tmp_path):
    # zsh runs chpwd functions on every cd, including the one in the $(...) that
    # computes the checkout's path, and whatever they print lands in it.
    result, calls = _source(
        "zsh", checkout, tmp_path, preamble="chpwd() { echo chpwd-hook-output }\n"
    )
    _assert_working(result, calls, checkout)


@pytest.mark.parametrize("shell", LOCATING_SHELLS)
def test_a_copy_outside_the_checkout_uses_the_preset_ash_root_dir(
    shell, checkout, tmp_path
):
    # The file's own location has no ash above it, so a correct preset is kept rather
    # than replaced by that location.
    copies = tmp_path / "copies" / "utils"
    copies.mkdir(parents=True)
    shutil.copy2(checkout / "utils" / "ash_helpers.sh", copies / "ash_helpers.sh")
    result, calls = _source(
        shell,
        checkout,
        tmp_path,
        extra_env={
            "HELPERS": str(copies / "ash_helpers.sh"),
            "ASH_ROOT_DIR": str(checkout),
        },
    )
    _assert_working(result, calls, checkout)


@pytest.mark.parametrize("shell", LOCATING_SHELLS)
def test_a_copy_outside_the_checkout_without_a_preset_is_refused(
    shell, checkout, tmp_path
):
    copies = tmp_path / "copies" / "utils"
    copies.mkdir(parents=True)
    shutil.copy2(checkout / "utils" / "ash_helpers.sh", copies / "ash_helpers.sh")
    result, calls = _source(
        shell, checkout, tmp_path, extra_env={"HELPERS": str(copies / "ash_helpers.sh")}
    )
    detail = f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    assert _reported(result, "rc") == REFUSAL_EXIT, detail
    assert "has no ash entrypoint" in result.stderr, detail
    assert "Set ASH_ROOT_DIR" in result.stderr, detail
    assert calls == [], detail


@pytest.mark.parametrize("shell", ["bash", "zsh"])
def test_the_developers_shell_startup_files_are_not_read(
    shell, checkout, tmp_path, monkeypatch
):
    # A non-interactive bash reads $BASH_ENV, and every zsh reads $ZDOTDIR/.zshenv
    # (or ~/.zshenv). One that sets ASH_ROOT_DIR would point invoke-ash at the
    # developer's real checkout, and the test would run that checkout's ./ash.
    canary_log = tmp_path / "canary.log"
    decoy = tmp_path / "decoy checkout"
    decoy.mkdir()
    (decoy / "ash").write_text(
        f"#!/bin/sh\necho ran-decoy-ash >> '{canary_log}'\nexit 99\n", encoding="utf-8"
    )
    (decoy / "ash").chmod(0o755)
    startup = (
        f"echo read-startup-file >> '{canary_log}'\nexport ASH_ROOT_DIR='{decoy}'\n"
    )
    bash_env = tmp_path / "bash_env.sh"
    bash_env.write_text(startup, encoding="utf-8")
    zdotdir = tmp_path / "zdotdir"
    zdotdir.mkdir()
    (zdotdir / ".zshenv").write_text(startup, encoding="utf-8")
    monkeypatch.setenv("BASH_ENV", str(bash_env))
    monkeypatch.setenv("ENV", str(bash_env))
    monkeypatch.setenv("ZDOTDIR", str(zdotdir))
    # zsh reads ~/.zshenv when ZDOTDIR is unset, so the developer's HOME holds one
    # too: _source must replace HOME as well as drop ZDOTDIR.
    monkeypatch.setenv("HOME", str(zdotdir))
    result, calls = _source(shell, checkout, tmp_path)
    assert not canary_log.exists(), canary_log.read_text(encoding="utf-8")
    _assert_working(result, calls, checkout)


@pytest.mark.parametrize("shell", NON_LOCATING_SHELLS)
def test_without_ash_root_dir_a_shell_that_cannot_locate_the_file_refuses(
    shell, checkout, tmp_path
):
    result, calls = _source(shell, checkout, tmp_path)
    detail = f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    assert _reported(result, "rc") == REFUSAL_EXIT, detail
    assert "Set ASH_ROOT_DIR" in result.stderr, detail
    # Refused by returning from the sourced file, not by exiting the user's shell.
    assert _reported(result, "after") == "ok", detail
    assert calls == [], detail


#: Every refusal of ash_helpers.sh, each in a shell that reaches it whatever the
#: host's sh is: the shell, whether the file is sourced from a copy outside the
#: checkout, the ASH_ROOT_DIR preset ("empty" for a directory with no ash), and text
#: found in the message. Each returns 3 from the sourced file, and the shell that
#: sourced it goes on.
_HELPER_SITES = {
    "the-shell-cannot-name-the-file": (
        "dash",
        False,
        None,
        "this shell does not report the path of a sourced file",
    ),
    "no-ash-above-the-file": (
        "bash",
        True,
        None,
        "the directory above this file, has no ash entrypoint",
    ),
    "ash-root-dir-without-ash": ("bash", True, "empty", "which has no ash entrypoint"),
}


@pytest.mark.parametrize("site", sorted(_HELPER_SITES))
def test_every_helper_refusal_returns_3(checkout, tmp_path, site):
    shell, from_a_copy, preset, text = _HELPER_SITES[site]
    extra_env = {}
    if from_a_copy:
        copies = tmp_path / "copies" / "utils"
        copies.mkdir(parents=True)
        shutil.copy2(checkout / "utils" / "ash_helpers.sh", copies / "ash_helpers.sh")
        extra_env["HELPERS"] = str(copies / "ash_helpers.sh")
    if preset == "empty":
        empty = tmp_path / "not a checkout"
        empty.mkdir()
        extra_env["ASH_ROOT_DIR"] = str(empty)
    result, calls = _source(shell, checkout, tmp_path, extra_env=extra_env)
    detail = f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    assert _reported(result, "rc") == REFUSAL_EXIT, detail
    assert text in result.stderr, detail
    assert _reported(result, "after") == "ok", detail
    assert calls == [], detail


def test_an_ash_root_dir_without_an_ash_entrypoint_is_refused(checkout, tmp_path):
    shell = "dash" if shutil.which("dash") else "sh"
    empty = tmp_path / "not a checkout"
    empty.mkdir()
    result, calls = _source(
        shell, checkout, tmp_path, extra_env={"ASH_ROOT_DIR": str(empty)}
    )
    if _reported(result, "rc") == "0":
        # This sh located the file itself, so the preset value was not used at all.
        _assert_working(result, calls, checkout)
        return
    detail = f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    assert _reported(result, "rc") == REFUSAL_EXIT, detail
    assert "has no ash entrypoint" in result.stderr, detail
    assert calls == [], detail
