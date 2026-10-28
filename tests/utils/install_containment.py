# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Containment for tests that run real dependency checks with install paths.

Why this module exists
----------------------
Several scanners' dependency checks install their tool when it is missing
(``uv tool install`` with retries and a 300-second timeout), and the version
probe's fallback, ``uv tool run <tool> --version``, downloads the tool into
uv's cache. A test that runs such a check for real must make every one of
those paths observable and harmless, or a regression installs software during
the unit suite.

This is that containment, shared by the tests that need it
(``tests/unit/core/test_inventory_installs_nothing.py`` and
``tests/unit/cli/test_dependencies_sweep_installs_nothing.py``). Each of those
modules wraps :func:`sandbox_env` in its own ``sandbox`` fixture, so neither
imports fixtures from the other and a change here is a change to a named
contract, not an accident of test-module layout.

What it does
------------
HOME, the XDG directories, UV_TOOL_DIR, UV_CACHE_DIR and ASH_BIN_PATH are
scratch directories, UV_OFFLINE is set, and PATH holds only stand-ins. The two
places ASH looks for its own install's programs whatever PATH says are hidden
too: the uv installed with ASH (``bundled_uv_executable``), which
``find_uv_or_none`` prefers to PATH, and the scripts directory of ASH's
environment (``subprocess_utils.own_environment_dirs``), which holds the real
uv and the scanners installed with ASH. The fixed directories
``find_executable`` searches whatever PATH says (``path_independent_dirs``:
/usr/local/bin) are dropped too, because a machine can really carry a uv
there; the sandboxed search keeps only directories under the sandbox root.
The ``uv`` stand-in answers
``--version``, ``tool list``, ``tool dir``, ``cache dir`` and an offline
``tool run`` (which finds nothing in the cache), and logs and refuses
everything else; the stand-ins for pip, pipx, docker, finch, podman, nerdctl,
npm, npx, gem and brew log and refuse every call.
``UVToolRunner.install_tool_with_version`` is replaced by a recorder that
installs nothing.

Limits
------
POSIX only: the stand-ins are ``/bin/sh`` scripts, so modules using this carry
a win32 skip. The containment is per-test; :func:`reset_tool_caches` runs on
the way in and out because the lookups it clears are process-wide.
"""

from __future__ import annotations

import stat
from pathlib import Path
from typing import Callable, Iterator, List

UV_STAND_IN = r"""#!/bin/sh
printf '%s\n' "uv $*" >> "$ASH_TEST_STAND_IN_LOG"
case "$*" in
  "--version"|"version") echo "uv 0.9.0"; exit 0 ;;
  "tool list"*) exit 0 ;;
  "tool dir"*) echo "$UV_TOOL_DIR"; exit 0 ;;
  "cache dir"*) echo "$UV_CACHE_DIR"; exit 0 ;;
esac
case " $* " in
  *" tool run "*" --offline "*|*" tool run --offline "*)
    echo "error: the requested package was not found in the cache" >&2; exit 2 ;;
esac
echo "stand-in uv refuses: $*" >&2
exit 99
"""

#: The refusing stand-in. Its name comes from ``${0##*/}``, the shell's own
#: expansion: PATH inside the sandbox holds only the stand-ins, so an external
#: ``basename`` is not found there, and the log line would start with no name
#: and be counted by nothing (``installs()`` reads the first word).
GUARD = r"""#!/bin/sh
name="${0##*/}"
printf '%s\n' "$name $*" >> "$ASH_TEST_STAND_IN_LOG"
echo "stand-in $name refuses: $*" >&2
exit 99
"""

GUARDED = (
    "uvx",
    "pip",
    "pip3",
    "pipx",
    "docker",
    "finch",
    "podman",
    "nerdctl",
    "npm",
    "npx",
    "gem",
    "brew",
)


def write_executable(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def reset_tool_caches() -> None:
    from automated_security_helper.utils import subprocess_utils, uv_tool_runner

    subprocess_utils.clear_find_executable_cache()
    uv_tool_runner._reset_uv_tool_runner_caches()
    uv_tool_runner.reset_uv_tool_runner()


class InstallSandbox:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.log = root / "stand-ins.log"
        self.guards = root / "guards"
        self.installer_calls: List[tuple] = []
        #: The unsandboxed ``path_independent_dirs``, captured before the
        #: sandbox replaces it. A test that plants a tool through the real
        #: function's inputs (``own_environment_dirs``) uses this to show the
        #: plant is findable before checking the sandbox hides it.
        self.real_path_independent_dirs: Callable[[], List[Path]] = list

    def calls(self) -> List[str]:
        if not self.log.exists():
            return []
        return [line for line in self.log.read_text().splitlines() if line]

    def installs(self) -> List[str]:
        """Every call that installs or downloads: the stub, and the stand-ins."""
        found = [f"install_tool_with_version{args}" for args in self.installer_calls]
        for line in self.calls():
            words = line.split()
            if words[0] == "uv":
                if words[1:3] == ["tool", "install"]:
                    found.append(line)
                elif words[1:3] == ["tool", "run"] and "--offline" not in words:
                    found.append(line)
            elif words[0] in GUARDED:
                found.append(line)
        return found

    def remove_uv(self) -> None:
        (self.guards / "uv").unlink()
        reset_tool_caches()


def sandbox_env(tmp_path, monkeypatch) -> Iterator[InstallSandbox]:
    """The containment, as a generator a module's ``sandbox`` fixture wraps:

    ``yield from install_containment.sandbox_env(tmp_path, monkeypatch)``
    """
    from automated_security_helper.utils import subprocess_utils, uv_tool_runner
    from automated_security_helper.utils.uv_tool_runner import UVToolRunner

    box = InstallSandbox(tmp_path)
    box.guards.mkdir()
    for name in ("home", "config", "cache", "data", "uv-tools", "uv-cache", "bin"):
        (tmp_path / name).mkdir()
    write_executable(box.guards / "uv", UV_STAND_IN)
    for name in GUARDED:
        write_executable(box.guards / name, GUARD)

    monkeypatch.setenv("ASH_TEST_STAND_IN_LOG", str(box.log))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("UV_TOOL_DIR", str(tmp_path / "uv-tools"))
    monkeypatch.setenv("UV_TOOL_BIN_DIR", str(tmp_path / "bin"))
    monkeypatch.setenv("UV_CACHE_DIR", str(tmp_path / "uv-cache"))
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    monkeypatch.setenv("UV_OFFLINE", "1")
    monkeypatch.setenv("PATH", str(box.guards))
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.setattr(
        "automated_security_helper.utils.subprocess_utils.ASH_BIN_PATH",
        tmp_path / "bin",
    )

    def no_install(self, *args, **kwargs):
        box.installer_calls.append(args)
        return False

    monkeypatch.setattr(UVToolRunner, "install_tool_with_version", no_install)
    # The uv beside the interpreter would be found before PATH's stand-in, and
    # ASH's environment's scripts directory after it; both hold the real uv.
    monkeypatch.setattr(uv_tool_runner, "bundled_uv_executable", lambda: None)
    monkeypatch.setattr(subprocess_utils, "own_environment_dirs", list)
    # The fixed tail of ``path_independent_dirs`` (/usr/local/bin) is searched
    # whatever PATH says, and a machine can really carry a uv there -- Homebrew
    # on Intel Macs installs to it -- so hiding PATH, the bundled uv and ASH's
    # environment alone left such a machine finding its real uv and the
    # "without uv" questions answering for that machine, not the sandbox. The
    # sandboxed search keeps only directories under the sandbox root. A test
    # plants a "machine" directory by patching ``own_environment_dirs``, which
    # the real function reads, so the plant reaches the search and only this
    # filter hides it.
    real_path_independent_dirs = subprocess_utils.path_independent_dirs
    box.real_path_independent_dirs = real_path_independent_dirs

    def _sandboxed_path_independent_dirs() -> List[Path]:
        dirs = list(real_path_independent_dirs())
        return [d for d in dirs if Path(d).is_relative_to(tmp_path)]

    monkeypatch.setattr(
        subprocess_utils, "path_independent_dirs", _sandboxed_path_independent_dirs
    )
    reset_tool_caches()
    yield box
    reset_tool_caches()
