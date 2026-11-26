# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The pinned capa release: versions, digests and the install command.

Why this lives in the plugin module and not in ``utils/tool_downloads.py``: the shared
table is the registry for tools the core installer provisions, and an alpha plugin must
not need an edit there to exist. The module-local table has the same shape (a pinned
version, one asset per platform/arch, a SHA256 per asset) and the install goes through
the same verified download and single-member extraction the shared installer uses, so a
binary that does not hash to its pin is never placed.

The assets are capa's standalone releases: one zip per platform holding a single
executable (``capa``, ``capa.exe`` on Windows), a PyInstaller build with capa's rules and
signatures embedded. ``ARCHIVE_SHA256`` is the ``digest`` GitHub reports for each asset of
the v10.0.0 release (https://github.com/mandiant/capa/releases/tag/v10.0.0), and every
archive was downloaded and hashed against it on 2026-11-26. ``MEMBER_SHA256`` is the
SHA256 of the executable inside each archive, taken from those downloads; the installer
refuses an archive whose executable does not match. Each executable's embedded
``capa.version`` reads ``10.0.0``.

The release has two linux/amd64 builds, ``capa-v10.0.0-linux.zip`` (Python 3.10 inside)
and ``capa-v10.0.0-linux-py313.zip`` (Python 3.13 inside); the first is pinned. Every
Linux build needs glibc 2.38 or newer: the libpython it unpacks at start requires
``GLIBC_2.38`` from libm. Measured on 2026-11-26 for both amd64 builds, which exit 255
with "version `GLIBC_2.38' not found" on glibc 2.34 and 2.36, and read from the arm64
build's bundled libpython, which requires the same version.

capa is Apache-2.0 and is downloaded at install time, never vendored.

Bumping the version means replacing ``CAPA_VERSION``, ``ASSETS``, ``ARCHIVE_SHA256`` and
``MEMBER_SHA256`` together; ``pinned_asset`` refuses a half-applied bump.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from automated_security_helper.base.plugin_base import CustomCommand
from automated_security_helper.core.exceptions import ToolNotProvisionableError

CAPA_VERSION = "v10.0.0"

#: The oldest glibc the pinned Linux builds run on. See the module docstring.
LINUX_GLIBC_FLOOR = "2.38"

_RELEASE_BASE = "https://github.com/mandiant/capa/releases/download"

PlatformArch = Tuple[str, str]

#: (platform, arch) -> release asset. capa publishes no Windows arm64 build and no 386
#: build. The macOS assets are named for the architecture only on arm64.
ASSETS: Dict[PlatformArch, str] = {
    ("linux", "amd64"): "capa-v10.0.0-linux.zip",
    ("linux", "arm64"): "capa-v10.0.0-linux-arm64.zip",
    ("darwin", "amd64"): "capa-v10.0.0-macos.zip",
    ("darwin", "arm64"): "capa-v10.0.0-macos-arm64.zip",
    ("windows", "amd64"): "capa-v10.0.0-windows.zip",
}

#: SHA256 of each release archive, the digest GitHub reports for the asset.
ARCHIVE_SHA256: Dict[str, str] = {
    "capa-v10.0.0-linux.zip": "96cb5115f495024a478b0e9f9f77f9027058155589235fbd4c50e7382055fcca",
    "capa-v10.0.0-linux-arm64.zip": "1da5512f75220c79e2f9f59609673af7329828f91b1d020ada60b859221d9793",
    "capa-v10.0.0-macos.zip": "566617317a46a7c7c215a2004d55cf0175a0a9ec31419dfeb6a0b4c2aff8b5da",
    "capa-v10.0.0-macos-arm64.zip": "04a827aef9517da045403da6927721c6489263a4a7e3846cc7da05f745062b73",
    "capa-v10.0.0-windows.zip": "8712991044321dbb2a5b0d60f7a5327a50c9c30a295e7ddb5c1088cb17fb59df",
}

#: SHA256 of the executable inside each archive.
MEMBER_SHA256: Dict[str, str] = {
    "capa-v10.0.0-linux.zip": "a85d61a30c9323de628f0027c08665ca5fddc4b72cf0d094058653362ac22742",
    "capa-v10.0.0-linux-arm64.zip": "c0e7015050c1e5af5a74992ecca1cd4343be3bccaa991fb9bc0091b6f9d32699",
    "capa-v10.0.0-macos.zip": "d19e0f61d9cdc36287bec4dc2743eec2989254e1dc450a4aed97fa51885656d1",
    "capa-v10.0.0-macos-arm64.zip": "203ecddf9215b039f1d11150f6cb75c48a9967aab1e8d71f1b4dea95cb6db78e",
    "capa-v10.0.0-windows.zip": "edda89c65a445ce45b35959459932880d78b9f886065336eb3d1e38152b6c01f",
}


def _install_name(target_platform: str) -> str:
    return "capa.exe" if target_platform == "windows" else "capa"


def _host_glibc() -> Optional[str]:
    """The running glibc's version (``"2.34"``), or None where there is none."""
    import os

    try:
        text = os.confstr("CS_GNU_LIBC_VERSION")
    except (AttributeError, OSError, ValueError):
        return None
    if not text or not text.startswith("glibc "):
        return None
    return text.split(" ", 1)[1].strip() or None


def glibc_too_old(version: Optional[str], floor: str = LINUX_GLIBC_FLOOR) -> bool:
    """Whether glibc *version* is older than *floor*; False when it is unknown."""
    if not version:
        return False
    found = re.findall(r"\d+", version)[:2]
    if len(found) < 2:
        return False
    major, minor = (int(part) for part in found)
    want_major, want_minor = (int(part) for part in floor.split(".")[:2])
    return (major, minor) < (want_major, want_minor)


def pinned_asset(target_platform: str, arch: str) -> Tuple[str, str, str, str]:
    """(url, archive sha256, member sha256, install name) for one platform/arch.

    Raises ``ToolNotProvisionableError`` for a pair capa publishes nothing for, and for
    a table whose digests no longer match its assets.
    """
    filename = ASSETS.get((target_platform, arch))
    if filename is None:
        available = ", ".join(f"{p}/{a}" for p, a in sorted(ASSETS))
        raise ToolNotProvisionableError(
            f"ASH's capa table has no asset for {target_platform}/{arch}. "
            f"Available: {available}"
        )
    archive = ARCHIVE_SHA256.get(filename)
    member = MEMBER_SHA256.get(filename)
    if archive is None or member is None:
        raise ToolNotProvisionableError(
            f"No pinned digest for {filename}; the asset table and the digest tables "
            "of ash_capa_plugins/capa_install.py disagree (a half-applied bump)."
        )
    url = f"{_RELEASE_BASE}/{CAPA_VERSION}/{filename}"
    return url, archive, member, _install_name(target_platform)


def install_capa(
    target_platform: str, arch: str, destination: Optional[Path] = None
) -> Path:
    """Download the pinned archive, verify it, and place the verified executable.

    The archive digest is checked as the bytes land, and the executable is refused
    unless it hashes to its own pin.
    """
    import tempfile

    from automated_security_helper.utils import download_utils as du
    from automated_security_helper.utils.log import ASH_LOGGER

    url, archive_sha, member_sha, install_as = pinned_asset(target_platform, arch)
    bin_dir = Path(destination) if destination is not None else du.current_bin_path()
    if bin_dir is None:
        raise RuntimeError(du.NO_BIN_DIRECTORY)
    bin_dir.mkdir(parents=True, exist_ok=True)
    target = bin_dir.joinpath(install_as)
    if du._already_installed(bin_dir, install_as, url, archive_sha):
        ASH_LOGGER.info(f"capa {CAPA_VERSION} already installed at {target}")
        return target
    if du.is_offline_mode():
        raise ToolNotProvisionableError(
            f"capa {CAPA_VERSION} is not installed and ASH is offline "
            "(ASH_OFFLINE), so nothing is downloaded. Install it while online."
        )
    with tempfile.TemporaryDirectory(prefix="ash-capa-download-") as staging:
        archive_name = url.rsplit("/", 1)[-1]
        downloaded = du.download_file(
            url,
            Path(staging),
            rename_to=archive_name,
            expected_sha256=archive_sha,
            mode=0o644,
        )
        installed_digest = du._extract_single_member(
            downloaded, install_as, target, expected_member_sha256=member_sha
        )
    du.unquarantine_macos_binary(target)
    du.write_receipt(
        bin_dir,
        install_as,
        {
            "tool": "capa",
            "version": CAPA_VERSION,
            "url": url,
            "sha256": archive_sha.lower(),
            "installed_sha256": installed_digest,
            "installed_as": install_as,
        },
    )
    ASH_LOGGER.info(f"Installed capa {CAPA_VERSION} to {target}")
    host = _host_glibc() if target_platform == "linux" else None
    if glibc_too_old(host):
        ASH_LOGGER.warning(
            f"capa {CAPA_VERSION} is installed, but this host's glibc {host} is older "
            f"than the {LINUX_GLIBC_FLOOR} its Linux builds need, so capa will not "
            "start here (it exits 255 naming GLIBC_"
            f"{LINUX_GLIBC_FLOOR})."
        )
    return target


_INSTALL_SCRIPT = (
    "import sys; from pathlib import Path; "
    "from automated_security_helper.plugin_modules.ash_capa_plugins."
    "capa_install import install_capa; "
    "install_capa(sys.argv[1], sys.argv[2], Path(sys.argv[3]))"
)


def capa_install_commands() -> "Dict[str, Dict[str, List[CustomCommand]]]":
    """The ``custom_install_commands`` table: one entry per published platform/arch.

    Never raises. With no usable bin directory every entry is a command that refuses
    with the reason, so constructing the scanner during a scan cannot fail.
    """
    from automated_security_helper.utils import download_utils as du

    bin_dir = du.current_bin_path()
    table: Dict[str, Dict[str, List[CustomCommand]]] = {}
    for target_platform, arch in sorted(ASSETS):
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
