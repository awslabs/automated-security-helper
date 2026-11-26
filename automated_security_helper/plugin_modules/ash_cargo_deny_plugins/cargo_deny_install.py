# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The pinned cargo-deny release: versions, digests and the install command.

Why this lives in the plugin module and not in ``utils/tool_downloads.py``: the shared
table is the registry for tools the core installer provisions, and an alpha plugin must
not need an edit there to exist. The module-local table has the same shape (a pinned
version, one asset per platform/arch, a SHA256 per asset) and the install goes through
the same verified download and single-member extraction the shared installer uses, so a
binary that does not hash to its pin is never placed.

Digests are the ones cargo-deny publishes beside each archive in the 0.21.0 release
(``<asset>.sha256``, e.g.
https://github.com/EmbarkStudios/cargo-deny/releases/download/0.21.0/cargo-deny-0.21.0-x86_64-unknown-linux-musl.tar.gz.sha256),
read again against the ``digest`` field GitHub reports for each asset, and every
archive was downloaded and hashed on 2026-11-26. ``MEMBER_SHA256`` is the SHA256 of the
executable inside each archive, taken from the downloaded archives on the same day; the
installer refuses an archive whose executable does not match. The linux x86_64 binary
printed ``cargo-deny 0.21.0`` for ``--version``.

cargo-deny is MIT OR Apache-2.0 and is downloaded at install time, never vendored. It
runs ``cargo metadata``, so a Rust toolchain on PATH is a prerequisite this module does
not install.

Bumping the version means replacing ``CARGO_DENY_VERSION``, ``ASSETS``,
``ARCHIVE_SHA256`` and ``MEMBER_SHA256`` together; ``pinned_asset`` refuses a
half-applied bump.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from automated_security_helper.core.exceptions import ToolNotProvisionableError
from automated_security_helper.base.plugin_base import CustomCommand

CARGO_DENY_VERSION = "0.21.0"

_RELEASE_BASE = "https://github.com/EmbarkStudios/cargo-deny/releases/download"

PlatformArch = Tuple[str, str]

#: (platform, arch) -> release asset. cargo-deny 0.21.0 publishes no x86_64 macOS
#: build, no 32-bit build, and its Windows build is x86_64 only.
ASSETS: Dict[PlatformArch, str] = {
    ("linux", "amd64"): "cargo-deny-0.21.0-x86_64-unknown-linux-musl.tar.gz",
    ("linux", "arm64"): "cargo-deny-0.21.0-aarch64-unknown-linux-musl.tar.gz",
    ("darwin", "arm64"): "cargo-deny-0.21.0-aarch64-apple-darwin.tar.gz",
    ("windows", "amd64"): "cargo-deny-0.21.0-x86_64-pc-windows-msvc.tar.gz",
}

#: SHA256 of each release archive, from the release's ``<asset>.sha256`` files.
ARCHIVE_SHA256: Dict[str, str] = {
    "cargo-deny-0.21.0-x86_64-unknown-linux-musl.tar.gz": "a2170b854ff697e79e39c4c538981c9c1bdd803addbae6719a4cb66b4585a903",
    "cargo-deny-0.21.0-aarch64-unknown-linux-musl.tar.gz": "47cc5d88d43cd568028080fece02d729f56f0ff8e6c168563ce6589e3c0f4738",
    "cargo-deny-0.21.0-aarch64-apple-darwin.tar.gz": "c99a789160775ada8cb54aed72cfdae5a9b72e27434f8868d17c9634c3f52425",
    "cargo-deny-0.21.0-x86_64-pc-windows-msvc.tar.gz": "8c445ef95217269d3cee234b18e2f543f8f1653f4a9801d9439df24bfcef4824",
}

#: SHA256 of the executable inside each archive.
MEMBER_SHA256: Dict[str, str] = {
    "cargo-deny-0.21.0-x86_64-unknown-linux-musl.tar.gz": "33c3aeb3c0e154060ee6784ae4fb38dd52d51454138f0596ed86252a8b84375b",
    "cargo-deny-0.21.0-aarch64-unknown-linux-musl.tar.gz": "f3e7616ad8593d6a82524e07fbe6ddf7d2bf29bfab14e848032a50ea27e1fcc1",
    "cargo-deny-0.21.0-aarch64-apple-darwin.tar.gz": "982e63b3b11c6f6775b5ff64242d49ea63f85596ecca2ea08365d2b757ecf1d1",
    "cargo-deny-0.21.0-x86_64-pc-windows-msvc.tar.gz": "3e9f7c6a17367eaf2d33d8c2ff81999c0b9911ead353c16f308b9d253390b0d5",
}


def _install_name(target_platform: str) -> str:
    return "cargo-deny.exe" if target_platform == "windows" else "cargo-deny"


def pinned_asset(target_platform: str, arch: str) -> Tuple[str, str, str, str]:
    """(url, archive sha256, member sha256, install name) for one platform/arch.

    Raises ``ToolNotProvisionableError`` for a pair cargo-deny publishes nothing for,
    and for a table whose digests no longer match its assets.
    """
    filename = ASSETS.get((target_platform, arch))
    if filename is None:
        available = ", ".join(f"{p}/{a}" for p, a in sorted(ASSETS))
        raise ToolNotProvisionableError(
            f"ASH's cargo-deny table has no asset for {target_platform}/{arch}. "
            f"Available: {available}"
        )
    archive = ARCHIVE_SHA256.get(filename)
    member = MEMBER_SHA256.get(filename)
    if archive is None or member is None:
        raise ToolNotProvisionableError(
            f"No pinned digest for {filename}; the asset table and the digest tables "
            "of ash_cargo_deny_plugins/cargo_deny_install.py disagree (a half-applied "
            "bump)."
        )
    url = f"{_RELEASE_BASE}/{CARGO_DENY_VERSION}/{filename}"
    return url, archive, member, _install_name(target_platform)


def install_cargo_deny(
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
        ASH_LOGGER.info(
            f"cargo-deny {CARGO_DENY_VERSION} already installed at {target}"
        )
        return target
    if du.is_offline_mode():
        raise ToolNotProvisionableError(
            f"cargo-deny {CARGO_DENY_VERSION} is not installed and ASH is offline "
            "(ASH_OFFLINE), so nothing is downloaded. Install it while online."
        )
    with tempfile.TemporaryDirectory(prefix="ash-cargo-deny-download-") as staging:
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
            "tool": "cargo-deny",
            "version": CARGO_DENY_VERSION,
            "url": url,
            "sha256": archive_sha.lower(),
            "installed_sha256": installed_digest,
            "installed_as": install_as,
        },
    )
    ASH_LOGGER.info(f"Installed cargo-deny {CARGO_DENY_VERSION} to {target}")
    return target


_INSTALL_SCRIPT = (
    "import sys; from pathlib import Path; "
    "from automated_security_helper.plugin_modules.ash_cargo_deny_plugins."
    "cargo_deny_install import install_cargo_deny; "
    "install_cargo_deny(sys.argv[1], sys.argv[2], Path(sys.argv[3]))"
)


def cargo_deny_install_commands() -> "Dict[str, Dict[str, List[CustomCommand]]]":
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
