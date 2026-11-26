# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The pinned cargo-audit release: versions, digests and the install command.

Why this lives in the plugin module and not in ``utils/tool_downloads.py``: the shared
table is the registry for tools the core installer provisions, and an alpha plugin must
not need an edit there to exist. The module-local table has the same shape (a pinned
version, one asset per platform/arch, a SHA256 per asset) and the install goes through
the same verified download and single-member extraction the shared installer uses, so a
binary that does not hash to its pin is never placed.

cargo-audit lives in the RustSec monorepo (https://github.com/rustsec/rustsec), whose
releases are tagged per crate: this one is ``cargo-audit/v0.23.0``. The release
publishes no checksums file, so ``ARCHIVE_SHA256`` is the ``digest`` field GitHub
reports for each asset, and every archive was downloaded and hashed against it on
2026-11-26. ``MEMBER_SHA256`` is the SHA256 of the executable inside each archive,
taken from the downloaded archives on the same day; the installer refuses an archive
whose executable does not match.

Which build each platform gets: linux/amd64 takes the statically linked
``x86_64-unknown-linux-musl`` build, which runs on glibc and musl distributions alike;
linux/arm64 has only the ``aarch64-unknown-linux-gnu`` build, which needs glibc 2.18 or
newer (its newest versioned glibc symbol). The release's ``armv7`` build has no ASH
platform name, so it is not listed.

cargo-audit is Apache-2.0 OR MIT and is downloaded at install time, never vendored.

Bumping the version means replacing ``CARGO_AUDIT_VERSION``, ``ASSETS``,
``ARCHIVE_SHA256`` and ``MEMBER_SHA256`` together; ``pinned_asset`` refuses a
half-applied bump.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from automated_security_helper.core.exceptions import ToolNotProvisionableError
from automated_security_helper.base.plugin_base import CustomCommand

CARGO_AUDIT_VERSION = "v0.23.0"

#: The release tag: the monorepo tags each crate's releases under its own prefix.
RELEASE_TAG = f"cargo-audit/{CARGO_AUDIT_VERSION}"

_RELEASE_BASE = "https://github.com/rustsec/rustsec/releases/download"

PlatformArch = Tuple[str, str]

#: (platform, arch) -> release asset. No 386 build is published, and the Windows build
#: is amd64 only.
ASSETS: Dict[PlatformArch, str] = {
    ("linux", "amd64"): "cargo-audit-x86_64-unknown-linux-musl-v0.23.0.tgz",
    ("linux", "arm64"): "cargo-audit-aarch64-unknown-linux-gnu-v0.23.0.tgz",
    ("darwin", "amd64"): "cargo-audit-x86_64-apple-darwin-v0.23.0.tgz",
    ("darwin", "arm64"): "cargo-audit-aarch64-apple-darwin-v0.23.0.tgz",
    ("windows", "amd64"): "cargo-audit-x86_64-pc-windows-msvc-v0.23.0.zip",
}

#: SHA256 of each release archive, the digest GitHub reports for the asset.
ARCHIVE_SHA256: Dict[str, str] = {
    "cargo-audit-x86_64-unknown-linux-musl-v0.23.0.tgz": "4f01c74ed84b2dffd0b1d37012a62cdf2a92c96e25bdf8eec7fcc0d4d3eb7811",
    "cargo-audit-aarch64-unknown-linux-gnu-v0.23.0.tgz": "00eff3158429b9629abe8748e971f29f99ee53d4cff54a25072cbb15167bdda8",
    "cargo-audit-x86_64-apple-darwin-v0.23.0.tgz": "845ec02452dd233c292be887700ac99a38a697299423081ee0d8ea1a0c961464",
    "cargo-audit-aarch64-apple-darwin-v0.23.0.tgz": "84101204e5b8013c9a8d7251766aebdef3e7fa1a3ef040cde44d65b48b8c4056",
    "cargo-audit-x86_64-pc-windows-msvc-v0.23.0.zip": "aafeb61206730029601a72e669a12231f8674427e6248d02f6cb382cb36d56b4",
}

#: SHA256 of the executable inside each archive.
MEMBER_SHA256: Dict[str, str] = {
    "cargo-audit-x86_64-unknown-linux-musl-v0.23.0.tgz": "ae133cc7bdfc6d61d1f9d000da3259423f1a232e6275e9ade45b4b4c67207b64",
    "cargo-audit-aarch64-unknown-linux-gnu-v0.23.0.tgz": "9307386968f817987bcae4192d113d94d69539f5c58f0b8a9b1a9a31d074a446",
    "cargo-audit-x86_64-apple-darwin-v0.23.0.tgz": "16cf8cf04e0fba3d7cdebbb344e501367be404fe1ccac8ba2633f12e665042de",
    "cargo-audit-aarch64-apple-darwin-v0.23.0.tgz": "d0077fd0e21972623699c1fcf61d7e87bbbfb0570b5fbb57d9e5b91b5e85e425",
    "cargo-audit-x86_64-pc-windows-msvc-v0.23.0.zip": "da6176c4ff085a66c3c56053d373b9599f72dabad90fc8e318f0f054929cbb5a",
}


def _install_name(target_platform: str) -> str:
    return "cargo-audit.exe" if target_platform == "windows" else "cargo-audit"


def pinned_asset(target_platform: str, arch: str) -> Tuple[str, str, str, str]:
    """(url, archive sha256, member sha256, install name) for one platform/arch.

    Raises ``ToolNotProvisionableError`` for a pair cargo-audit publishes nothing for,
    and for a table whose digests no longer match its assets.
    """
    filename = ASSETS.get((target_platform, arch))
    if filename is None:
        available = ", ".join(f"{p}/{a}" for p, a in sorted(ASSETS))
        raise ToolNotProvisionableError(
            f"ASH's cargo-audit table has no asset for {target_platform}/{arch}. "
            f"Available: {available}"
        )
    archive = ARCHIVE_SHA256.get(filename)
    member = MEMBER_SHA256.get(filename)
    if archive is None or member is None:
        raise ToolNotProvisionableError(
            f"No pinned digest for {filename}; the asset table and the digest tables "
            "of ash_cargo_audit_plugins/cargo_audit_install.py disagree (a "
            "half-applied bump)."
        )
    url = f"{_RELEASE_BASE}/{RELEASE_TAG}/{filename}"
    return url, archive, member, _install_name(target_platform)


def install_cargo_audit(
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
            f"cargo-audit {CARGO_AUDIT_VERSION} already installed at {target}"
        )
        return target
    if du.is_offline_mode():
        raise ToolNotProvisionableError(
            f"cargo-audit {CARGO_AUDIT_VERSION} is not installed and ASH is offline "
            "(ASH_OFFLINE), so nothing is downloaded. Install it while online."
        )
    with tempfile.TemporaryDirectory(prefix="ash-cargo-audit-download-") as staging:
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
            "tool": "cargo-audit",
            "version": CARGO_AUDIT_VERSION,
            "url": url,
            "sha256": archive_sha.lower(),
            "installed_sha256": installed_digest,
            "installed_as": install_as,
        },
    )
    ASH_LOGGER.info(f"Installed cargo-audit {CARGO_AUDIT_VERSION} to {target}")
    return target


_INSTALL_SCRIPT = (
    "import sys; from pathlib import Path; "
    "from automated_security_helper.plugin_modules.ash_cargo_audit_plugins."
    "cargo_audit_install import install_cargo_audit; "
    "install_cargo_audit(sys.argv[1], sys.argv[2], Path(sys.argv[3]))"
)


def cargo_audit_install_commands() -> "Dict[str, Dict[str, List[CustomCommand]]]":
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
