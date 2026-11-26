# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The pinned DevSkim release: the package, its digest and the install command.

Why this lives in the plugin module and not in ``utils/tool_downloads.py``: the shared
table is the registry for tools the core installer provisions, and an alpha plugin must
not need an edit there to exist. The install goes through the shared verified download,
so a package that does not hash to its pin is never unpacked.

What is installed
-----------------
DevSkim ships as one NuGet package, ``Microsoft.CST.DevSkim.CLI``, a .NET tool; its
v1.0.103 GitHub release carries no assets. ``NUPKG_SHA256`` is the SHA256 of the
package nuget.org serves for 1.0.103 (58,204,625 bytes, downloaded and hashed on
2026-11-26). The SHA512 of the same file equals the ``packageHash`` of nuget.org's
catalog entry for the version, read the same day, and the package's nuspec names the
repository commit its ``v1.0.103`` tag points to
(``7f8e5e24f62d9ba95f261e7f45b4b1c293a59a51``).

The package holds framework-dependent builds under ``tools/net8.0/any/``,
``tools/net9.0/any/`` and ``tools/net10.0/any/``, and no executable: its
``DotnetToolSettings.xml`` names ``devskim.dll`` with ``Runner="dotnet"``. The install
unpacks the net8.0 build into ``<bin>/.devskim/1.0.103/`` and writes a ``devskim``
launcher beside the other tools::

    #!/bin/sh
    exec dotnet --roll-forward Major '<bin>/.devskim/1.0.103/devskim.dll' "$@"

Why the net8.0 build with ``--roll-forward Major``: its runtimeconfig asks for .NET 8.0
and sets no roll-forward policy, so the host's default (minor) refuses it on a machine
whose newest runtime is a later major (measured with the 10.0.15 runtime: "You must
install or update .NET to run this application", exit 150). With the flag it runs on
.NET 8 where that is installed and on the next later major otherwise (measured on
10.0.15: ``devskim --version`` prints ``devskim 1.0.103+7f8e5e24f6``). The net10.0
build would refuse every host whose runtime is older than 10.

A .NET runtime (8 or later) is a prerequisite ASH does not install; the launcher runs
whatever ``dotnet`` is on ``PATH``. Windows is not installed by this module: a
launcher there would be a batch file, whose arguments ``cmd.exe`` parses again. Put
DevSkim's own ``devskim`` on ``PATH`` there (``dotnet tool install``).

DevSkim is MIT-licensed and is downloaded at install time, never vendored.

Bumping the version means replacing ``DEVSKIM_VERSION`` and ``NUPKG_SHA256`` together
and checking that the new package still carries the ``TARGET_FRAMEWORK`` build; the
receipt names the version, so an old install is replaced, not trusted.
"""

from __future__ import annotations

import hashlib
import os
import shlex
import shutil
import stat
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Dict, List, Optional

from automated_security_helper.base.plugin_base import CustomCommand
from automated_security_helper.core.exceptions import ToolNotProvisionableError

#: The DevSkim CLI release ASH installs (a stable release: no prerelease suffix).
DEVSKIM_VERSION = "1.0.103"

#: The NuGet package (a .NET tool) that provides the ``devskim`` command.
DEVSKIM_PACKAGE = "Microsoft.CST.DevSkim.CLI"

#: The package's file name as nuget.org's flat container serves it (lower-case id).
NUPKG_NAME = f"{DEVSKIM_PACKAGE.lower()}.{DEVSKIM_VERSION}.nupkg"

#: The package download (nuget.org's flat container).
NUPKG_URL = (
    "https://api.nuget.org/v3-flatcontainer/"
    f"{DEVSKIM_PACKAGE.lower()}/{DEVSKIM_VERSION}/{NUPKG_NAME}"
)

#: SHA256 of that package; see the module docstring for how it was taken.
NUPKG_SHA256 = "ea8c70cca113563919909b64534b6d50f97af4b2941e1ea4bb434db7890a28af"  # pragma: allowlist secret

#: The download is refused past this size (the 1.0.103 package is 58,204,625 bytes).
NUPKG_MAX_BYTES = 256 * 1024 * 1024

#: The build the launcher runs; see the module docstring.
TARGET_FRAMEWORK = "net8.0"

#: The package members unpacked: the build for TARGET_FRAMEWORK.
MEMBER_PREFIX = f"tools/{TARGET_FRAMEWORK}/any/"

#: The build's entry point and its runtime configuration.
ENTRY_POINT = "devskim.dll"
RUNTIME_CONFIG = "devskim.runtimeconfig.json"

#: The launcher's name in the bin directory: the command the scanner runs.
INSTALL_NAME = "devskim"

#: The directory, inside the bin directory, that holds the unpacked builds.
HOME_DIR_NAME = ".devskim"

#: The (platform, arch) pairs the POSIX launcher is installed on.
PLATFORMS = (
    ("darwin", "amd64"),
    ("darwin", "arm64"),
    ("linux", "amd64"),
    ("linux", "arm64"),
)

_CHUNK = 1024 * 1024


def install_home(bin_dir: Path) -> Path:
    """Where the pinned build is unpacked for ``bin_dir``."""
    return Path(bin_dir).joinpath(HOME_DIR_NAME, DEVSKIM_VERSION)


def launcher_script(entry_point: Path) -> str:
    """The ``devskim`` launcher for an unpacked build whose entry point is given.

    The path is single-quoted for the shell, so no character in the bin directory's
    name is read as shell syntax.
    """
    return (
        "#!/bin/sh\n"
        f'exec dotnet --roll-forward Major {shlex.quote(str(entry_point))} "$@"\n'
    )


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _member_parts(relative: str) -> List[str]:
    """The path components of one unpacked member, refusing anything but a plain
    relative path (no empty, ``.`` or ``..`` component, no backslash, no drive)."""
    parts = relative.split("/")
    if (
        not relative
        or "\\" in relative
        or ":" in relative
        or any(part in ("", ".", "..") for part in parts)
    ):
        raise ToolNotProvisionableError(
            f"Refusing the DevSkim package member {relative!r}: not a plain "
            "relative path"
        )
    return parts


def _is_regular_member(info: zipfile.ZipInfo) -> bool:
    """A zip made on Unix keeps the entry's mode in the high 16 bits of
    ``external_attr``; one made elsewhere keeps 0 there, read as a plain file."""
    if info.is_dir():
        return False
    kind = stat.S_IFMT(info.external_attr >> 16)
    return kind in (0, stat.S_IFREG)


def extract_build(package: Path, root: Path) -> Dict[str, str]:
    """Unpack the ``TARGET_FRAMEWORK`` build of ``package`` into ``root``.

    ``root`` must be an empty directory this process created. Returns the SHA256 of
    every file written, by its path relative to ``root``. A member that is not a
    regular file, or whose name is not a plain relative path, refuses the whole
    package; so does a package without the entry point or its runtimeconfig.
    """
    files: Dict[str, str] = {}
    with zipfile.ZipFile(package) as archive:
        for info in archive.infolist():
            name = info.filename
            if not name.startswith(MEMBER_PREFIX) or name.endswith("/"):
                continue
            relative = name[len(MEMBER_PREFIX) :]
            parts = _member_parts(relative)
            if not _is_regular_member(info):
                raise ToolNotProvisionableError(
                    f"Refusing the DevSkim package member {name!r}: not a regular file"
                )
            if relative in files:
                raise ToolNotProvisionableError(
                    f"Refusing the DevSkim package: {name!r} appears twice"
                )
            target = Path(root).joinpath(*parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            with archive.open(info) as source, open(target, "xb") as sink:
                for chunk in iter(lambda: source.read(_CHUNK), b""):
                    digest.update(chunk)
                    sink.write(chunk)
            os.chmod(target, 0o644)
            files[relative] = digest.hexdigest()
    missing = [n for n in (ENTRY_POINT, RUNTIME_CONFIG) if n not in files]
    if missing:
        raise ToolNotProvisionableError(
            f"The DevSkim package holds no {', '.join(missing)} under {MEMBER_PREFIX}; "
            "the pinned build is not in it"
        )
    return files


def _file_matches(path: Path, expected_sha256: str) -> bool:
    """Whether ``path`` is a regular file (not a link) whose bytes hash to the pin."""
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_BINARY", 0)
    )
    try:
        fd = os.open(path, flags)
    except OSError:
        return False
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return False
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, _CHUNK)
            if not chunk:
                break
            digest.update(chunk)
        return digest.hexdigest() == expected_sha256.lower()
    except OSError:
        return False
    finally:
        os.close(fd)


def installed_tree_matches(bin_dir: Path) -> bool:
    """Whether the pinned build and its launcher are still the bytes ASH installed.

    The launcher is checked by the shared receipt rule (a regular, executable file
    that still hashes to what was written for this package and digest); then every
    unpacked file is checked against the digest the receipt recorded when the
    verified package was unpacked, through no symbolic link. Anything else is not
    installed, so the next install replaces it.
    """
    from automated_security_helper.utils import download_utils as du

    bin_dir = Path(bin_dir)
    if not du._already_installed(bin_dir, INSTALL_NAME, NUPKG_URL, NUPKG_SHA256):
        return False
    receipt = du.read_receipt(bin_dir, INSTALL_NAME) or {}
    home = install_home(bin_dir)
    files = receipt.get("files")
    if receipt.get("version") != DEVSKIM_VERSION or receipt.get("home") != str(home):
        return False
    if receipt.get("installed_sha256") != _sha256_text(
        launcher_script(home / ENTRY_POINT)
    ):
        return False
    if not isinstance(files, dict) or ENTRY_POINT not in files:
        return False
    if home.parent.is_symlink() or home.is_symlink() or not home.is_dir():
        return False
    real_home = os.path.realpath(home)
    for relative, digest in files.items():
        if not isinstance(relative, str) or not isinstance(digest, str):
            return False
        try:
            parts = _member_parts(relative)
        except ToolNotProvisionableError:
            return False
        path = home.joinpath(*parts)
        if os.path.realpath(path) != os.path.join(real_home, *parts):
            return False
        if not _file_matches(path, digest):
            return False
    return True


def _replace_directory(staged: Path, home: Path) -> None:
    """Put ``staged`` at ``home``, removing whatever was there."""
    if home.is_symlink() or home.is_file():
        home.unlink()
    elif home.exists():
        old = Path(tempfile.mkdtemp(prefix=f".{home.name}.old-", dir=home.parent))
        os.replace(home, old / home.name)
        os.replace(staged, home)
        shutil.rmtree(old, ignore_errors=True)
        return
    os.replace(staged, home)


def _write_launcher(launcher: Path, script: str) -> None:
    """Write the launcher through a staged file renamed over the name, mode 0755."""
    fd, staged = tempfile.mkstemp(prefix=f".{launcher.name}.", dir=launcher.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(script)
        os.chmod(staged, 0o755)
        os.replace(staged, launcher)
    except BaseException:
        Path(staged).unlink(missing_ok=True)
        raise


def install_devskim(destination: Optional[Path] = None) -> Path:
    """Download the pinned package, verify it, unpack its build and write the launcher.

    The package digest is checked as the bytes land; nothing is unpacked from a
    package that does not match. Returns the launcher's path.
    """
    from automated_security_helper.utils import download_utils as du
    from automated_security_helper.utils.log import ASH_LOGGER

    bin_dir = Path(destination) if destination is not None else du.current_bin_path()
    if bin_dir is None:
        raise RuntimeError(du.NO_BIN_DIRECTORY)
    bin_dir = Path(os.path.abspath(bin_dir))
    bin_dir.mkdir(parents=True, exist_ok=True)
    launcher = bin_dir.joinpath(INSTALL_NAME)
    home = install_home(bin_dir)
    if installed_tree_matches(bin_dir):
        ASH_LOGGER.info(f"devskim {DEVSKIM_VERSION} already installed at {launcher}")
        return launcher
    if du.is_offline_mode():
        raise ToolNotProvisionableError(
            f"devskim {DEVSKIM_VERSION} is not installed and ASH is offline "
            "(ASH_OFFLINE), so nothing is downloaded. Install it while online."
        )
    # A link (or a file) at the builds directory is replaced, never written through:
    # the unpacked files must land in the bin directory, not wherever a link points.
    if home.parent.is_symlink() or home.parent.is_file():
        home.parent.unlink()
    home.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ash-devskim-download-") as download_dir:
        package = du.download_file(
            NUPKG_URL,
            Path(download_dir),
            rename_to=NUPKG_NAME,
            expected_sha256=NUPKG_SHA256,
            mode=0o644,
            max_bytes=NUPKG_MAX_BYTES,
        )
        staged = Path(tempfile.mkdtemp(prefix=f".{home.name}.new-", dir=home.parent))
        try:
            files = extract_build(package, staged)
            _replace_directory(staged, home)
        except BaseException:
            shutil.rmtree(staged, ignore_errors=True)
            raise
    script = launcher_script(home / ENTRY_POINT)
    _write_launcher(launcher, script)
    du.write_receipt(
        bin_dir,
        INSTALL_NAME,
        {
            "tool": "devskim",
            "version": DEVSKIM_VERSION,
            "url": NUPKG_URL,
            "sha256": NUPKG_SHA256.lower(),
            "installed_sha256": _sha256_text(script),
            "installed_as": INSTALL_NAME,
            "home": str(home),
            "files": files,
        },
    )
    ASH_LOGGER.info(f"Installed devskim {DEVSKIM_VERSION} to {launcher}")
    return launcher


_INSTALL_SCRIPT = (
    "import sys; from pathlib import Path; "
    "from automated_security_helper.plugin_modules.ash_devskim_plugins."
    "devskim_install import install_devskim; "
    "install_devskim(Path(sys.argv[1]))"
)


def devskim_install_commands() -> "Dict[str, Dict[str, List[CustomCommand]]]":
    """The ``custom_install_commands`` table: one entry per platform the launcher
    runs on.

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
    for target_platform, arch in PLATFORMS:
        table.setdefault(target_platform, {})[arch] = [command]
    return table


__all__ = [
    "DEVSKIM_PACKAGE",
    "DEVSKIM_VERSION",
    "ENTRY_POINT",
    "HOME_DIR_NAME",
    "INSTALL_NAME",
    "MEMBER_PREFIX",
    "NUPKG_NAME",
    "NUPKG_SHA256",
    "NUPKG_URL",
    "PLATFORMS",
    "TARGET_FRAMEWORK",
    "devskim_install_commands",
    "extract_build",
    "install_devskim",
    "install_home",
    "installed_tree_matches",
    "launcher_script",
]
