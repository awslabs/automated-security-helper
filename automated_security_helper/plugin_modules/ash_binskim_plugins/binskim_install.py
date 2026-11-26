# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The pinned BinSkim release: the package, its digests and the install command.

Why this lives in the plugin module and not in ``utils/tool_downloads.py``: the shared
table is the registry for tools the core installer provisions, and an alpha plugin must
not need an edit there to exist. The install goes through the same verified download the
shared installer uses, so a package that does not hash to its pin is never opened.

What is installed
-----------------
BinSkim ships as one NuGet package, ``Microsoft.CodeAnalysis.BinSkim``, holding a
self-contained build per .NET runtime identifier under ``tools/<rid>/``: the ``BinSkim``
executable and the 214 to 223 files it loads from beside it (the .NET runtime, BinSkim's
assemblies, native libraries). So an install is a directory, not one file. The files of
the host's build are extracted into ``binskim-<version>-<rid>/`` in the bin directory,
and on Linux and macOS a symbolic link ``BinSkim`` beside that directory names the
executable inside it, so ``BinSkim`` is found on PATH and through ASH_BIN_PATH. The
executable resolves its own location through the link and loads its files from the real
directory (measured with the linux-x64 build, through an absolute and a relative link).
Windows gets no link; the scanner finds the executable in the directory itself
(:func:`installed_executable`).

Digests
-------
``PACKAGE_SHA256`` is the SHA256 of the ``.nupkg`` as downloaded from nuget.org on
2026-11-26; the SHA512 of the same bytes equals the ``packageHash`` nuget.org publishes
in the package's catalog entry. ``TREE_SHA256`` commits to every file of one build: the
SHA256 of the sorted lines ``<name> NUL <sha256 of the file> LF``, one line per file
(:func:`tree_digest`). ``EXECUTABLE_SHA256`` is the executable's own digest, part of that
tree. All three were taken from the downloaded package on 2026-11-26. The installer
refuses a package, or an extracted build, that does not match.

BinSkim is MIT-licensed and is downloaded at install time, never vendored.

Bumping the version means replacing ``BINSKIM_VERSION``, ``PACKAGE_SHA256``,
``TREE_SHA256`` and ``EXECUTABLE_SHA256`` together; ``pinned_build`` refuses a
half-applied bump.
"""

from __future__ import annotations

import hashlib
import os
import platform
import re
import secrets
import shutil
import stat
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from automated_security_helper.base.plugin_base import CustomCommand
from automated_security_helper.core.exceptions import (
    ToolDownloadIntegrityError,
    ToolNotProvisionableError,
)

BINSKIM_VERSION = "4.4.9.14"

PACKAGE_URL = (
    "https://api.nuget.org/v3-flatcontainer/microsoft.codeanalysis.binskim/"
    f"{BINSKIM_VERSION}/microsoft.codeanalysis.binskim.{BINSKIM_VERSION}.nupkg"
)

#: SHA256 of the package (153,894,969 bytes).
PACKAGE_SHA256 = "ea2f48ed02e6d7ff569614d0895b80c2669fbc261c8b386639de551af049bcf4"

#: Bound on the download, on the wire: the package is about 147 MiB.
PACKAGE_MAX_BYTES = 256 * 1024 * 1024

PlatformArch = Tuple[str, str]

#: (platform, arch) -> the .NET runtime identifier of the build in the package. BinSkim
#: publishes no osx-arm64, linux 32-bit or win-arm64 build.
RIDS: Dict[PlatformArch, str] = {
    ("linux", "amd64"): "linux-x64",
    ("linux", "arm64"): "linux-arm64",
    ("darwin", "amd64"): "osx-x64",
    ("windows", "amd64"): "win-x64",
}

#: The digest of each build's files (see :func:`tree_digest`).
TREE_SHA256: Dict[str, str] = {
    "linux-x64": "93047c0e5bb6c065b2a20f7b60c5fd5ca5199c10f3d3adf7c6e887f16eed8836",
    "linux-arm64": "2368fa374fa8ec4f0e462a91c6a08e7a48b1f4975841a5f38402e8989d19adf5",
    "osx-x64": "18f2826e00d501a827c7930f5ca6c92709b38f487b931944453af4c58a62d6ef",
    "win-x64": "8ff25b3dac65c629c4d92f7cff19c9463c0223dccf0e540c11a80c46e0adbdd1",
}

#: SHA256 of the executable of each build.
EXECUTABLE_SHA256: Dict[str, str] = {
    "linux-x64": "1c587424acd112daeb31e0ecde819e24402f544a4919d4fe707729ef4948da0d",
    "linux-arm64": "8bebeb5c03abd8f4d4954362ee9179b617857e47aa40caa3be97e30726257337",
    "osx-x64": "b80dea5ac9358b543be15240129e397766252f44142f6618aed6898419d37780",
    "win-x64": "a685658c0b19fbb8bbd5c7fe3eb2f8ff1cc55e162fd76afe93b13d4fb3920c64",
}

#: What a file of a build may be called: a plain file name. Every name in the four
#: builds of the pinned package matches; a path, ``..`` or a drive is refused.
_PLAIN_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_BINARY = getattr(os, "O_BINARY", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_CHUNK = 1024 * 1024


class _NotARegularFile(OSError):
    """A name in an installed build that is not a regular file."""


def _install_name(target_platform: str) -> str:
    return "BinSkim.exe" if target_platform == "windows" else "BinSkim"


def tree_name(rid: str) -> str:
    """The directory one build is installed into, beside the link."""
    return f"binskim-{BINSKIM_VERSION}-{rid}"


def tree_digest(files: Iterable[Tuple[str, str]]) -> str:
    """The SHA256 of the sorted ``<name> NUL <sha256> LF`` lines of a build's files."""
    lines = "".join(f"{name}\0{digest}\n" for name, digest in sorted(files))
    return hashlib.sha256(lines.encode("utf-8")).hexdigest()


def pinned_build(target_platform: str, arch: str) -> Tuple[str, str, str, str]:
    """(rid, tree sha256, executable sha256, executable name) for one platform/arch.

    Raises ``ToolNotProvisionableError`` for a pair BinSkim publishes no build for, and
    for tables whose digests no longer cover their builds.
    """
    rid = RIDS.get((target_platform, arch))
    if rid is None:
        available = ", ".join(f"{p}/{a}" for p, a in sorted(RIDS))
        raise ToolNotProvisionableError(
            f"ASH's BinSkim table has no build for {target_platform}/{arch}. "
            f"Available: {available}"
        )
    tree = TREE_SHA256.get(rid)
    executable = EXECUTABLE_SHA256.get(rid)
    if tree is None or executable is None:
        raise ToolNotProvisionableError(
            f"No pinned digest for the {rid} build; the build table and the digest "
            "tables of ash_binskim_plugins/binskim_install.py disagree (a "
            "half-applied bump)."
        )
    return rid, tree, executable, _install_name(target_platform)


def host_platform() -> Optional[PlatformArch]:
    """This host's (platform, arch), in the vocabulary ``ash dependencies`` uses."""
    system = platform.system().lower()
    arch = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }.get(platform.machine().lower())
    if system not in ("linux", "darwin", "windows") or arch is None:
        return None
    return system, arch


def installed_executable(bin_dir: Optional[Path] = None) -> Optional[Path]:
    """The executable of the build ASH installed for this host, when it is there.

    Only that the file is in place, a regular file, and (off Windows) executable: no
    digest is taken here, because this runs before every scan. The install verified the
    build when it placed it.
    """
    from automated_security_helper.utils import download_utils as du

    pair = host_platform()
    if pair is None or pair not in RIDS:
        return None
    directory = Path(bin_dir) if bin_dir is not None else du.current_bin_path()
    if directory is None:
        return None
    candidate = directory / tree_name(RIDS[pair]) / _install_name(pair[0])
    try:
        info = os.lstat(candidate)
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode):
        return None
    if pair[0] != "windows" and not info.st_mode & 0o111:
        return None
    return candidate


def _sha256_of_regular_file(path: Path) -> str:
    """The SHA256 of ``path``, refused unless it is a regular file and not a link."""
    fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_BINARY | _O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise _NotARegularFile(f"{path} is not a regular file")
        digest = hashlib.sha256()
        for chunk in iter(lambda: os.read(fd, _CHUNK), b""):
            digest.update(chunk)
        return digest.hexdigest()
    finally:
        os.close(fd)


def _installed_tree_matches(tree_dir: Path, rid: str, install_as: str) -> bool:
    """Whether ``tree_dir`` holds exactly the pinned files of ``rid``, unmodified.

    A link at the directory's name, an extra or missing file, a file that is a link,
    changed bytes, and an executable without its execute bit all read as not installed,
    so the install replaces the directory.
    """
    try:
        if not stat.S_ISDIR(os.lstat(tree_dir).st_mode):
            return False
        files: List[Tuple[str, str]] = []
        with os.scandir(tree_dir) as entries:
            for entry in entries:
                files.append((entry.name, _sha256_of_regular_file(Path(entry.path))))
        if tree_digest(files) != TREE_SHA256[rid]:
            return False
        mode = os.lstat(tree_dir / install_as).st_mode
    except OSError:
        return False
    return install_as.endswith(".exe") or bool(mode & 0o111)


def _members(archive: zipfile.ZipFile, rid: str) -> List[Tuple[str, zipfile.ZipInfo]]:
    """The (name, entry) pairs of ``tools/<rid>/``, each a plain regular file."""
    from automated_security_helper.utils import download_utils as du

    prefix = f"tools/{rid}/"
    found: Dict[str, zipfile.ZipInfo] = {}
    for info in archive.infolist():
        name = info.filename.replace("\\", "/")
        if not name.startswith(prefix) or name == prefix:
            continue
        rest = name[len(prefix) :]
        if (
            not _PLAIN_NAME.fullmatch(rest)
            or info.is_dir()
            or not du._zip_entry_is_a_regular_file(info)
        ):
            raise ToolDownloadIntegrityError(
                f"{name} in the BinSkim package is not a plain file of the {rid} "
                "build; refusing to install from it"
            )
        if rest in found:
            raise ToolDownloadIntegrityError(
                f"The BinSkim package holds {name} twice; refusing to install from it"
            )
        found[rest] = info
    if not found:
        raise ToolDownloadIntegrityError(
            f"The BinSkim package holds no {prefix} build; refusing to install from it"
        )
    return sorted(found.items())


def _extract_build(package: Path, rid: str, staging: Path) -> List[Tuple[str, str]]:
    """Write the files of ``rid`` into the empty directory ``staging``.

    Each file is created with O_EXCL (and O_NOFOLLOW where the platform has it) and
    hashed as it is written. Returns the (name, sha256) of every file.
    """
    written: List[Tuple[str, str]] = []
    try:
        with zipfile.ZipFile(package) as archive:
            for name, info in _members(archive, rid):
                fd = os.open(
                    staging / name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_BINARY,
                    0o600,
                )
                digest = hashlib.sha256()
                with os.fdopen(fd, "wb") as sink, archive.open(info) as source:
                    for chunk in iter(lambda: source.read(_CHUNK), b""):
                        digest.update(chunk)
                        sink.write(chunk)
                written.append((name, digest.hexdigest()))
    except zipfile.BadZipFile as e:
        raise ToolDownloadIntegrityError(
            f"{package.name} is not a readable zip archive ({e}); refusing to "
            "install from it"
        ) from e
    return written


def _remove(path: Path) -> None:
    """Remove a directory this module made, or whatever stands at a name it replaces."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISDIR(info.st_mode):
        shutil.rmtree(path)
    else:
        os.unlink(path)


def _swap_into_place(staging: Path, final: Path) -> None:
    """Rename ``staging`` to ``final``; what stood at ``final`` is removed after."""
    aside: Optional[Path] = None
    if os.path.lexists(final):
        aside = final.with_name(f".{final.name}.replaced-{secrets.token_hex(6)}")
        os.rename(final, aside)
    try:
        os.rename(staging, final)
    except BaseException:
        if aside is not None:
            try:
                os.rename(aside, final)
            except OSError:
                pass
        raise
    if aside is not None:
        _remove(aside)


def _link_target(rid: str, install_as: str) -> str:
    return f"{tree_name(rid)}/{install_as}"


def _place_link(bin_dir: Path, rid: str, install_as: str) -> None:
    """Point ``bin_dir/BinSkim`` at the build's executable (not on Windows).

    The link is made at a fresh name and renamed over ``BinSkim``, so the name is
    replaced, never written through, and never missing in between.
    """
    if install_as.endswith(".exe"):
        return
    link = bin_dir / install_as
    target = _link_target(rid, install_as)
    try:
        if os.readlink(link) == target:
            return
    except OSError:
        pass
    staged = bin_dir / f".{install_as}.link-{secrets.token_hex(6)}"
    os.symlink(target, staged)
    try:
        os.replace(staged, link)
    except BaseException:
        os.unlink(staged)
        raise


def install_binskim(
    target_platform: str, arch: str, destination: Optional[Path] = None
) -> Path:
    """Download the pinned package, verify it, and install the build for one platform.

    The package digest is checked as the bytes land, and the extracted build is refused
    unless every file matches the pinned tree. Returns the executable's path.
    """
    from automated_security_helper.utils import download_utils as du
    from automated_security_helper.utils.log import ASH_LOGGER

    rid, tree_sha, executable_sha, install_as = pinned_build(target_platform, arch)
    bin_dir = Path(destination) if destination is not None else du.current_bin_path()
    if bin_dir is None:
        raise RuntimeError(du.NO_BIN_DIRECTORY)
    bin_dir.mkdir(parents=True, exist_ok=True)
    final = bin_dir / tree_name(rid)
    executable = final / install_as
    if _installed_tree_matches(final, rid, install_as):
        _place_link(bin_dir, rid, install_as)
        ASH_LOGGER.info(f"BinSkim {BINSKIM_VERSION} already installed at {executable}")
        return executable
    if du.is_offline_mode():
        raise ToolNotProvisionableError(
            f"BinSkim {BINSKIM_VERSION} is not installed and ASH is offline "
            "(ASH_OFFLINE), so nothing is downloaded. Install it while online."
        )
    with tempfile.TemporaryDirectory(prefix="ash-binskim-download-") as download_dir:
        package = du.download_file(
            PACKAGE_URL,
            Path(download_dir),
            rename_to=PACKAGE_URL.rsplit("/", 1)[-1],
            expected_sha256=PACKAGE_SHA256,
            mode=0o644,
            max_bytes=PACKAGE_MAX_BYTES,
        )
        staging = Path(
            tempfile.mkdtemp(prefix=f".{tree_name(rid)}.staging-", dir=bin_dir)
        )
        try:
            files = _extract_build(package, rid, staging)
            found = tree_digest(files)
            if found != tree_sha:
                raise ToolDownloadIntegrityError(
                    f"The {rid} build in the BinSkim package does not match its pinned "
                    f"tree digest (expected {tree_sha}, found {found}). The package "
                    "matched its own pin, so the tree digest in binskim_install.py is "
                    "wrong; refusing to install it."
                )
            if dict(files).get(install_as) != executable_sha:
                raise ToolDownloadIntegrityError(
                    f"{install_as} of the {rid} build does not match its pinned "
                    "executable digest; the digest tables of binskim_install.py "
                    "disagree. Refusing to install it."
                )
            for name, _digest in files:
                os.chmod(staging / name, 0o755 if name == install_as else 0o644)
            os.chmod(staging, 0o755)
            _swap_into_place(staging, final)
        except BaseException:
            _remove(staging)
            raise
    du.unquarantine_macos_binary(executable)
    _place_link(bin_dir, rid, install_as)
    ASH_LOGGER.info(f"Installed BinSkim {BINSKIM_VERSION} ({rid}) to {final}")
    return executable


_INSTALL_SCRIPT = (
    "import sys; from pathlib import Path; "
    "from automated_security_helper.plugin_modules.ash_binskim_plugins."
    "binskim_install import install_binskim; "
    "install_binskim(sys.argv[1], sys.argv[2], Path(sys.argv[3]))"
)


def binskim_install_commands() -> "Dict[str, Dict[str, List[CustomCommand]]]":
    """The ``custom_install_commands`` table: one entry per published platform/arch.

    Never raises. With no usable bin directory every entry is a command that refuses
    with the reason, so constructing the scanner during a scan cannot fail.
    """
    from automated_security_helper.utils import download_utils as du

    bin_dir = du.current_bin_path()
    table: Dict[str, Dict[str, List[CustomCommand]]] = {}
    for target_platform, arch in sorted(RIDS):
        if bin_dir is None:
            command = du.refusing_install_command(du.NO_BIN_DIRECTORY)
        else:
            command = CustomCommand(
                args=[
                    sys.executable,
                    "-c",
                    _INSTALL_SCRIPT,
                    target_platform,
                    arch,
                    du._destination_text(Path(bin_dir).absolute()),
                ],
                shell=False,
            )
        table.setdefault(target_platform, {})[arch] = [command]
    return table
