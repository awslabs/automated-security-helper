# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The pinned Capslock module: its version, its digest, and the install that builds it.

Capslock publishes no release binaries, so ``ash dependencies install`` builds the
pinned module with the Go toolchain on ``PATH``, the toolchain the scan needs anyway:
``go install github.com/google/capslock/cmd/capslock@v0.3.4`` (``INSTALL_COMMAND``),
with the executable placed in ASH's bin directory.

Why this lives in the plugin module and not in ``utils/tool_downloads.py``: that table
is the registry of release assets the core installer downloads. Capslock has none, and
an alpha plugin must not need an edit there to exist.

What is pinned, and how each pin is checked
-------------------------------------------
- The module: ``CAPSLOCK_MODULE_SUM`` is the digest the Go checksum database records
  for ``github.com/google/capslock@v0.3.4``. Before anything is built, the installer
  has the go command download the module (``go mod download -json``) and refuses it
  unless the digest the go command reports is the pin. The go command also checks the
  download against the checksum database, unless the caller's environment turns that
  off (``GONOSUMDB``, ``GOSUMDB=off``); the pin is checked either way.
- The dependencies: the module's own ``go.sum``, part of the pinned module, records
  each dependency's digest, and the go command refuses a dependency that does not
  match it.
- The executable: after the build, the build information the go command embeds in the
  binary (``go version -m``) has to name the pinned module, version and digest, and
  the toolchain's host platform. The executable's SHA256 goes in the install receipt,
  so a later install is a no-op only while the file still hashes to what was built.

The toolchain is the one on ``PATH``, at Go 1.26.0 or later (``MINIMUM_GO``, the ``go``
line of the module's ``go.mod`` at v0.3.4). The go commands run with
``GOTOOLCHAIN=local``, so no other toolchain is downloaded for the build, and an older
Go is refused with its version named. They run in an empty directory of their own, with
``GOFLAGS`` empty, ``GOWORK=off`` and the shell's ``GOOS``/``GOARCH`` removed, so no
``go.mod``, ``go.work``, flag or cross-compilation variable from the caller's shell
changes what is built; a binary built for another platform than the toolchain's host
(which a ``GOOS`` or ``GOARCH`` stored with ``go env -w`` would give) is refused after
the build. The rest of the Go settings (``GOPROXY``, ``GOPRIVATE``, ``GOPATH`` and so
on, from the shell or from ``go env -w``) are the caller's: they choose where the
module comes from and where it is cached, not what is built.

The executable is built into a staging directory inside the destination and moved into
place with one rename, so a build that fails or a binary that fails its check leaves
nothing in the bin directory.

Bumping the version means replacing ``CAPSLOCK_VERSION``, ``CAPSLOCK_MODULE_SUM`` and,
when the module's ``go.mod`` asks for a newer Go, ``MINIMUM_GO``, together with the
plugin's ``CAPSLOCK_COMMIT`` and license pins.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import shutil
import subprocess  # nosec B404 - runs the go command found on PATH, argv only
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Tuple

from automated_security_helper.base.plugin_base import CustomCommand
from automated_security_helper.core.exceptions import ToolNotProvisionableError

#: The tagged module version the plugin is read against and the installer builds.
CAPSLOCK_VERSION = "v0.3.4"

#: The module path, and the package of the command it installs.
CAPSLOCK_MODULE = "github.com/google/capslock"
CAPSLOCK_PACKAGE = f"{CAPSLOCK_MODULE}/cmd/capslock"

#: The Go checksum database's digest of the ``v0.3.4`` module zip.
CAPSLOCK_MODULE_SUM = (
    "h1:eS3/PLl++R96+Ub8b7uIDgCWzQh8CsY1CzVQbnt+Vhs="  # pragma: allowlist secret
)

#: The oldest Go that builds the module: the ``go`` line of its ``go.mod`` at v0.3.4.
MINIMUM_GO: Tuple[int, int, int] = (1, 26, 0)

#: The install command, as a user runs it by hand and as the installer runs it.
INSTALL_COMMAND = f"go install {CAPSLOCK_PACKAGE}@{CAPSLOCK_VERSION}"

#: The platforms and architectures the install command is declared for. Capslock is
#: pure Go and the build is for the machine it runs on, so every pair Go and ASH both
#: name is covered.
GO_PLATFORMS: Tuple[Tuple[str, str], ...] = tuple(
    (platform, arch)
    for platform in ("darwin", "linux", "windows")
    for arch in ("amd64", "arm64")
)

#: Seconds each go command may take: the module download, the build, the quick reads.
DOWNLOAD_TIMEOUT_SECONDS = 900
BUILD_TIMEOUT_SECONDS = 1800
QUERY_TIMEOUT_SECONDS = 120

#: Variables removed from the go command's environment; see the module docstring.
_DROPPED_GO_ENV = ("GOFLAGS", "GOOS", "GOARCH", "GOBIN", "GOWORK", "GOTOOLCHAIN")

_GO_VERSION = re.compile(r"\bgo(\d+)\.(\d+)(?:\.(\d+))?")


def module_sum_hex(module_sum: str = CAPSLOCK_MODULE_SUM) -> str:
    """The SHA256 a ``h1:`` module digest holds, as 64 hex digits.

    The receipt records digests as hex; ``h1:`` is the base64 of one SHA256.
    """
    if not module_sum.startswith("h1:"):
        raise ValueError(f"{module_sum!r} is not an h1 module digest")
    try:
        raw = base64.b64decode(module_sum[3:], validate=True)
    except (binascii.Error, ValueError) as bad:
        raise ValueError(f"{module_sum!r} is not an h1 module digest") from bad
    if len(raw) != 32:
        raise ValueError(f"{module_sum!r} does not hold a SHA256")
    return raw.hex()


def install_name(host_platform: Optional[str] = None) -> str:
    """The executable's file name in the bin directory."""
    name = host_platform if host_platform is not None else sys.platform
    return "capslock.exe" if name.startswith(("win", "windows")) else "capslock"


def parse_go_version(text: str) -> Optional[Tuple[int, int, int]]:
    """``go1.26.11`` -> (1, 26, 11); a release candidate reads as its release
    (``go1.27rc1`` -> (1, 27, 0)); None when ``text`` names no Go version."""
    found = _GO_VERSION.search(text or "")
    if found is None:
        return None
    major, minor, patch = found.groups()
    return int(major), int(minor), int(patch or 0)


def go_environment(
    base: Mapping[str, str], gobin: Optional[Path] = None
) -> Dict[str, str]:
    """The go command's environment: ``base`` with the build-shaping settings fixed."""
    env = {k: v for k, v in base.items() if k not in _DROPPED_GO_ENV}
    env["GOFLAGS"] = ""
    env["GOWORK"] = "off"
    env["GOTOOLCHAIN"] = "local"
    if gobin is not None:
        env["GOBIN"] = str(gobin)
    return env


def _run_go(
    go: str, args: List[str], cwd: Path, env: Mapping[str, str], timeout: int
) -> subprocess.CompletedProcess:
    """Run ``go args`` and refuse, with the go command's words, when it fails."""
    from automated_security_helper.utils.output_excerpt import tool_output_excerpt

    command = " ".join(["go", *args])
    try:
        result = subprocess.run(  # nosec B603 - go is an absolute path from PATH, argv only
            [go, *args],
            cwd=str(cwd),
            env=dict(env),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as late:
        raise ToolNotProvisionableError(
            f"`{command}` did not finish in {timeout} seconds; Capslock is not installed."
        ) from late
    except OSError as failed:
        raise ToolNotProvisionableError(
            f"`{command}` could not be started ({failed}); Capslock is not installed."
        ) from failed
    if result.returncode != 0:
        said = tool_output_excerpt((result.stderr or result.stdout or "").strip(), 1500)
        raise ToolNotProvisionableError(
            f"`{command}` exited {result.returncode}; Capslock is not installed. "
            f"The go command said: {said}"
        )
    return result


def check_go_version(
    go: str, cwd: Path, env: Mapping[str, str]
) -> Tuple[str, str, str]:
    """(version, host OS, host architecture) of the toolchain on PATH.

    Refused when the version is older than ``MINIMUM_GO``. An unreadable version is
    left to the go command, which refuses an old toolchain itself under
    ``GOTOOLCHAIN=local``.
    """
    lines = _run_go(
        go,
        ["env", "GOVERSION", "GOHOSTOS", "GOHOSTARCH"],
        cwd,
        env,
        QUERY_TIMEOUT_SECONDS,
    ).stdout.splitlines()
    version, host_os, host_arch = (lines + ["", "", ""])[:3]
    version = version.strip()
    parsed = parse_go_version(version)
    if parsed is not None and parsed < MINIMUM_GO:
        wanted = ".".join(str(part) for part in MINIMUM_GO)
        raise ToolNotProvisionableError(
            f"Capslock {CAPSLOCK_VERSION} needs Go {wanted} or later to build, and the "
            f"go command on PATH is {version}. Install a newer Go "
            "(https://go.dev/dl/) and run `ash dependencies install --tool capslock` "
            "again."
        )
    return version, host_os.strip(), host_arch.strip()


def check_module_download(go: str, cwd: Path, env: Mapping[str, str]) -> None:
    """Have the go command download the pinned module; refuse a digest that differs."""
    result = _run_go(
        go,
        ["mod", "download", "-json", f"{CAPSLOCK_MODULE}@{CAPSLOCK_VERSION}"],
        cwd,
        env,
        DOWNLOAD_TIMEOUT_SECONDS,
    )
    try:
        record = json.loads(result.stdout)
    except json.JSONDecodeError as bad:
        raise ToolNotProvisionableError(
            "`go mod download -json` printed no module record; Capslock is not "
            "installed."
        ) from bad
    if not isinstance(record, dict) or record.get("Error"):
        reason = record.get("Error") if isinstance(record, dict) else record
        raise ToolNotProvisionableError(
            f"The go command could not download {CAPSLOCK_MODULE}@{CAPSLOCK_VERSION}: "
            f"{reason}"
        )
    if record.get("Sum") != CAPSLOCK_MODULE_SUM:
        raise ToolNotProvisionableError(
            f"{CAPSLOCK_MODULE}@{CAPSLOCK_VERSION} downloaded with digest "
            f"{record.get('Sum')!r}, not the pinned {CAPSLOCK_MODULE_SUM}; nothing "
            "was built."
        )


def check_build_info(
    go: str,
    binary: Path,
    cwd: Path,
    env: Mapping[str, str],
    host: Tuple[str, str],
) -> None:
    """Refuse a binary whose build information is not the pinned module's, or that
    was built for another platform than ``host`` (GOHOSTOS, GOHOSTARCH)."""
    lines = _run_go(
        go, ["version", "-m", str(binary)], cwd, env, QUERY_TIMEOUT_SECONDS
    ).stdout.splitlines()
    fields = [line.strip().split("\t") for line in lines]
    package = next((f[1] for f in fields if len(f) >= 2 and f[0] == "path"), None)
    module = next((f[1:4] for f in fields if len(f) >= 4 and f[0] == "mod"), None)
    settings = dict(
        f[1].split("=", 1)
        for f in fields
        if len(f) >= 2 and f[0] == "build" and "=" in f[1]
    )
    expected = [CAPSLOCK_MODULE, CAPSLOCK_VERSION, CAPSLOCK_MODULE_SUM]
    if package != CAPSLOCK_PACKAGE or module != expected:
        raise ToolNotProvisionableError(
            f"The built executable records package {package!r} from module "
            f"{module!r}, not {CAPSLOCK_PACKAGE} from {' '.join(expected)}; it was "
            "not installed."
        )
    built_for = (settings.get("GOOS"), settings.get("GOARCH"))
    if built_for != host:
        raise ToolNotProvisionableError(
            f"The built executable is for {built_for[0]}/{built_for[1]}, not this "
            f"machine's {host[0]}/{host[1]} (a GOOS or GOARCH from `go env -w`?); it "
            "was not installed."
        )


def install_capslock(destination: Optional[Path] = None) -> Path:
    """Build the pinned Capslock with the Go toolchain on PATH and place it.

    See the module docstring for what is checked before, during and after the build.
    Returns the installed executable's path.
    """
    from automated_security_helper.utils import download_utils as du
    from automated_security_helper.utils.log import ASH_LOGGER
    from automated_security_helper.utils.subprocess_utils import find_executable

    bin_dir = Path(destination) if destination is not None else du.current_bin_path()
    if bin_dir is None:
        raise RuntimeError(du.NO_BIN_DIRECTORY)
    bin_dir = bin_dir.absolute()
    bin_dir.mkdir(parents=True, exist_ok=True)
    installed_as = install_name()
    target = bin_dir.joinpath(installed_as)
    pinned = module_sum_hex()
    if du._already_installed(bin_dir, installed_as, INSTALL_COMMAND, pinned):
        ASH_LOGGER.info(f"capslock {CAPSLOCK_VERSION} already installed at {target}")
        return target
    if du.is_offline_mode():
        raise ToolNotProvisionableError(
            f"capslock {CAPSLOCK_VERSION} is not installed and ASH is offline "
            "(ASH_OFFLINE), so nothing is downloaded or built. Install it while online."
        )
    go = find_executable("go")
    if not go:
        raise ToolNotProvisionableError(
            "Capslock is built from source with the Go toolchain, and there is no "
            "`go` on PATH. Install Go 1.26 or later (https://go.dev/dl/), put it on "
            "PATH, and run `ash dependencies install --tool capslock` again."
        )
    staging = Path(tempfile.mkdtemp(prefix=".ash-capslock-build-", dir=bin_dir))
    try:
        workdir = staging / "work"
        gobin = staging / "bin"
        workdir.mkdir()
        gobin.mkdir()
        env = go_environment(os.environ, gobin)
        go_version, host_os, host_arch = check_go_version(go, workdir, env)
        check_module_download(go, workdir, env)
        _run_go(
            go,
            ["install", f"{CAPSLOCK_PACKAGE}@{CAPSLOCK_VERSION}"],
            workdir,
            env,
            BUILD_TIMEOUT_SECONDS,
        )
        built = gobin / installed_as
        if not built.is_file():
            raise ToolNotProvisionableError(
                f"`{INSTALL_COMMAND}` reported success but wrote no {installed_as}."
            )
        check_build_info(go, built, workdir, env, (host_os, host_arch))
        installed_digest = du.sha256_file(built)
        du.make_executable(built)
        os.replace(built, target)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    du.unquarantine_macos_binary(target)
    du.write_receipt(
        bin_dir,
        installed_as,
        {
            "tool": "capslock",
            "version": CAPSLOCK_VERSION,
            "url": INSTALL_COMMAND,
            "sha256": pinned,
            "module_sum": CAPSLOCK_MODULE_SUM,
            "installed_sha256": installed_digest,
            "installed_as": installed_as,
            "go_version": go_version,
        },
    )
    ASH_LOGGER.info(f"Installed capslock {CAPSLOCK_VERSION} to {target} ({go_version})")
    return target


_INSTALL_SCRIPT = (
    "import sys; from pathlib import Path; "
    "from automated_security_helper.plugin_modules.ash_capslock_plugins."
    "capslock_install import install_capslock; "
    "install_capslock(Path(sys.argv[1]))"
)


def capslock_install_commands() -> Dict[str, Dict[str, List[CustomCommand]]]:
    """The ``custom_install_commands`` table: the same build on every pair.

    Never raises. With no usable bin directory every entry is a command that refuses
    with the reason, so constructing the scanner during a scan cannot fail.
    """
    from automated_security_helper.utils import download_utils as du

    bin_dir = du.current_bin_path()
    if bin_dir is None:
        command = du.refusing_install_command(du.NO_BIN_DIRECTORY)
    else:
        command = CustomCommand(
            args=[
                sys.executable,
                "-c",
                _INSTALL_SCRIPT,
                du._destination_text(Path(bin_dir).absolute()),
            ],
            shell=False,
        )
    table: Dict[str, Dict[str, List[CustomCommand]]] = {}
    for target_platform, arch in GO_PLATFORMS:
        table.setdefault(target_platform, {})[arch] = [command]
    return table


__all__ = [
    "BUILD_TIMEOUT_SECONDS",
    "CAPSLOCK_MODULE",
    "CAPSLOCK_MODULE_SUM",
    "CAPSLOCK_PACKAGE",
    "CAPSLOCK_VERSION",
    "DOWNLOAD_TIMEOUT_SECONDS",
    "GO_PLATFORMS",
    "INSTALL_COMMAND",
    "MINIMUM_GO",
    "QUERY_TIMEOUT_SECONDS",
    "capslock_install_commands",
    "check_build_info",
    "check_go_version",
    "check_module_download",
    "go_environment",
    "install_capslock",
    "install_name",
    "module_sum_hex",
    "parse_go_version",
]
