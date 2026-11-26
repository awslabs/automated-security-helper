# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The pinned YARA-X release: versions, digests and the install command.

Why this lives in the plugin module and not in ``utils/tool_downloads.py``: the shared
table is the registry for tools the core installer provisions, and an alpha plugin must
not need an edit there to exist. The shared table also names the executable after the
tool, and YARA-X's executable is ``yr``, not ``yara-x``. The module-local table has the
same shape (a pinned version, one asset per platform/arch, a SHA256 per asset) and the
install goes through the same verified download and single-member extraction the shared
installer uses, so a binary that does not hash to its pin is never placed.

YARA-X publishes no checksums file. The archive digests are the ``digest`` field GitHub
reports for each asset of the v1.23.0 release, and each was confirmed on 2026-11-26 by
downloading the asset and hashing it (all five agreed). ``MEMBER_SHA256`` is the SHA256
of the executable inside each archive (``yr``, or ``yr.exe`` in the Windows zip, the only
file each archive holds), taken from those downloaded archives the same day. The
extracted linux/amd64 binary reports ``yara-x-cli 1.23.0``. The installer refuses an
archive whose executable does not match.

The linux builds are statically linked (no program interpreter and no needed shared
library, read from the binaries), so one build per architecture serves glibc and musl
hosts alike. The release publishes no windows/arm64 build.

YARA-X is BSD-3-Clause and is downloaded at install time, never vendored.

Bumping the version means replacing ``YARA_X_VERSION``, ``ASSETS``, ``ARCHIVE_SHA256``
and ``MEMBER_SHA256`` together; ``pinned_asset`` refuses a half-applied bump.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from automated_security_helper.core.exceptions import ToolNotProvisionableError
from automated_security_helper.base.plugin_base import CustomCommand

YARA_X_VERSION = "v1.23.0"

_RELEASE_BASE = "https://github.com/VirusTotal/yara-x/releases/download"

PlatformArch = Tuple[str, str]

#: (platform, arch) -> release asset. The release publishes no windows/arm64 build.
ASSETS: Dict[PlatformArch, str] = {
    ("linux", "amd64"): "yara-x-v1.23.0-x86_64-unknown-linux-gnu.tar.gz",
    ("linux", "arm64"): "yara-x-v1.23.0-aarch64-unknown-linux-gnu.tar.gz",
    ("darwin", "amd64"): "yara-x-v1.23.0-x86_64-apple-darwin.tar.gz",
    ("darwin", "arm64"): "yara-x-v1.23.0-aarch64-apple-darwin.tar.gz",
    ("windows", "amd64"): "yara-x-v1.23.0-x86_64-pc-windows-msvc.zip",
}

#: SHA256 of each release archive, from GitHub's asset digests, confirmed by download.
ARCHIVE_SHA256: Dict[str, str] = {
    "yara-x-v1.23.0-x86_64-unknown-linux-gnu.tar.gz": "da0c17f23fc743dcd44ad6d3135c906a4c0d197685b661c4cdc923c2f8967a64",  # pragma: allowlist secret
    "yara-x-v1.23.0-aarch64-unknown-linux-gnu.tar.gz": "3547bc532d2861c6408c990d0b28047d921d32241791e755ae48c3368fa2be93",  # pragma: allowlist secret
    "yara-x-v1.23.0-x86_64-apple-darwin.tar.gz": "876747c16313a0d993fa494ee88b64fff0489e66799f09bfd649683e234711b7",  # pragma: allowlist secret
    "yara-x-v1.23.0-aarch64-apple-darwin.tar.gz": "6fa89c1b366e3106f84275d6f262cddd7a408655b4b4b44c935743e5dc811d8b",  # pragma: allowlist secret
    "yara-x-v1.23.0-x86_64-pc-windows-msvc.zip": "b72fd2001c0902981afe9b86ffb152412d904db94e2da9fa626f622b8c5b6a79",  # pragma: allowlist secret
}

#: SHA256 of the executable inside each archive.
MEMBER_SHA256: Dict[str, str] = {
    "yara-x-v1.23.0-x86_64-unknown-linux-gnu.tar.gz": "b1b045bc346c60d5389f78b5fd2037027e1f24268169bbc3abf20e655cec7c45",  # pragma: allowlist secret
    "yara-x-v1.23.0-aarch64-unknown-linux-gnu.tar.gz": "66402b61f6a26d676b6b46bd86c2775b23f9ac47d0f1e64118575cdfd6c2c01a",  # pragma: allowlist secret
    "yara-x-v1.23.0-x86_64-apple-darwin.tar.gz": "4e426a4b1644d0233d6d36619e7fddfe808ba647bb6315c5c75cbaa76c27513d",  # pragma: allowlist secret
    "yara-x-v1.23.0-aarch64-apple-darwin.tar.gz": "018fb5b31e6d13d5a38910ad348f3d65a7546108e47fd5bfd19396b95e146fbd",  # pragma: allowlist secret
    "yara-x-v1.23.0-x86_64-pc-windows-msvc.zip": "807bb4164b32255bf6d07a3327fd660b250886f2121bc2c33b4965b06eeffa1a",  # pragma: allowlist secret
}


def _install_name(target_platform: str) -> str:
    return "yr.exe" if target_platform == "windows" else "yr"


def pinned_asset(target_platform: str, arch: str) -> Tuple[str, str, str, str]:
    """(url, archive sha256, member sha256, install name) for one platform/arch.

    Raises ``ToolNotProvisionableError`` for a pair YARA-X publishes nothing for, and
    for a table whose digests no longer match its assets.
    """
    filename = ASSETS.get((target_platform, arch))
    if filename is None:
        available = ", ".join(f"{p}/{a}" for p, a in sorted(ASSETS))
        raise ToolNotProvisionableError(
            f"ASH's YARA-X table has no asset for {target_platform}/{arch}. "
            f"Available: {available}"
        )
    archive = ARCHIVE_SHA256.get(filename)
    member = MEMBER_SHA256.get(filename)
    if archive is None or member is None:
        raise ToolNotProvisionableError(
            f"No pinned digest for {filename}; the asset table and the digest tables "
            "of ash_yara_x_plugins/yara_x_install.py disagree (a half-applied bump)."
        )
    url = f"{_RELEASE_BASE}/{YARA_X_VERSION}/{filename}"
    return url, archive, member, _install_name(target_platform)


def install_yara_x(
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
        ASH_LOGGER.info(f"yara-x {YARA_X_VERSION} already installed at {target}")
        return target
    if du.is_offline_mode():
        raise ToolNotProvisionableError(
            f"yara-x {YARA_X_VERSION} is not installed and ASH is offline "
            "(ASH_OFFLINE), so nothing is downloaded. Install it while online."
        )
    with tempfile.TemporaryDirectory(prefix="ash-yara-x-download-") as staging:
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
            "tool": "yara-x",
            "version": YARA_X_VERSION,
            "url": url,
            "sha256": archive_sha.lower(),
            "installed_sha256": installed_digest,
            "installed_as": install_as,
        },
    )
    ASH_LOGGER.info(f"Installed yara-x {YARA_X_VERSION} to {target}")
    return target


_INSTALL_SCRIPT = (
    "import sys; from pathlib import Path; "
    "from automated_security_helper.plugin_modules.ash_yara_x_plugins."
    "yara_x_install import install_yara_x; "
    "install_yara_x(sys.argv[1], sys.argv[2], Path(sys.argv[3]))"
)


def yara_x_install_commands() -> "Dict[str, Dict[str, List[CustomCommand]]]":
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
