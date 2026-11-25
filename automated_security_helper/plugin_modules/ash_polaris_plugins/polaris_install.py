# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The pinned Polaris release: versions, digests and the install command.

Why this lives in the plugin module and not in ``utils/tool_downloads.py``: the shared
table is the registry for tools the core installer provisions, and an alpha plugin must
not need an edit there to exist. The module-local table has the same shape (a pinned
version, one asset per platform/arch, a SHA256 per asset) and the install goes through
the same verified download and single-member extraction the shared installer uses, so a
binary that does not hash to its pin is never placed.

Digests are the ones Polaris publishes in the release's ``checksums.txt``
(https://github.com/FairwindsOps/polaris/releases/download/v10.2.6/checksums.txt),
read again against the ``digest`` field GitHub reports for each asset, and the archive
for linux/amd64 was downloaded and hashed on 2026-11-25 (87856194...). ``MEMBER_SHA256``
is the SHA256 of the executable inside each archive, taken from the downloaded archives
on the same day; the installer refuses an archive whose executable does not match.

Polaris is Apache-2.0 and is downloaded at install time, never vendored.

Bumping the version means replacing ``POLARIS_VERSION``, ``ASSETS``, ``ARCHIVE_SHA256``
and ``MEMBER_SHA256`` together; ``pinned_asset`` refuses a half-applied bump.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from automated_security_helper.core.exceptions import ToolNotProvisionableError
from automated_security_helper.base.plugin_base import CustomCommand

POLARIS_VERSION = "v10.2.6"

_RELEASE_BASE = "https://github.com/FairwindsOps/polaris/releases/download"

PlatformArch = Tuple[str, str]

#: (platform, arch) -> release asset. Polaris publishes no 386 build, and its Windows
#: build is amd64 only.
ASSETS: Dict[PlatformArch, str] = {
    ("linux", "amd64"): "polaris_10.2.6_linux_amd64.tar.gz",
    ("linux", "arm64"): "polaris_10.2.6_linux_arm64.tar.gz",
    ("darwin", "amd64"): "polaris_10.2.6_darwin_amd64.tar.gz",
    ("darwin", "arm64"): "polaris_10.2.6_darwin_arm64.tar.gz",
    ("windows", "amd64"): "polaris_10.2.6_windows_amd64.tar.gz",
}

#: SHA256 of each release archive, from the release's checksums.txt.
ARCHIVE_SHA256: Dict[str, str] = {
    "polaris_10.2.6_linux_amd64.tar.gz": "87856194124409f7f21912775c0d6ac0804061ddaded5b527a1326f1850e9491",
    "polaris_10.2.6_linux_arm64.tar.gz": "e1c2774aa8100c6c5c23f2aa49cbf02476fd7b43a226a6372b405b6772acb585",
    "polaris_10.2.6_darwin_amd64.tar.gz": "e716e37b3a4eaa0af6a76f5f46caf5dc3384094155659c01fa786c1f9f0633ce",
    "polaris_10.2.6_darwin_arm64.tar.gz": "6c92a34f3db0f6a00434c8eb7e7a6e68388f1e6371ce7b12cd8ddac8029ddaaa",
    "polaris_10.2.6_windows_amd64.tar.gz": "75547305577721384c3ccfd64012688eb0cf28dbe95e9eec6b076f4d224f5a84",
}

#: SHA256 of the executable inside each archive.
MEMBER_SHA256: Dict[str, str] = {
    "polaris_10.2.6_linux_amd64.tar.gz": "abd90774c807922af764cade9aa2ec463d883530ef67c2db71288d324493c774",
    "polaris_10.2.6_linux_arm64.tar.gz": "71fbf4176ccb91d3cee0a19865f08b447e3aa934181907b8721f29c3a0dcb729",
    "polaris_10.2.6_darwin_amd64.tar.gz": "70453c4744bed0ae9dd6b70265b2e2bec286483b84fafaa6554c4b44da861130",
    "polaris_10.2.6_darwin_arm64.tar.gz": "78e0306878d6b3d647064037d5d36045773ed30a707d42045d488aaca4946277",
    "polaris_10.2.6_windows_amd64.tar.gz": "87a78d80683f475970c1e6a911b30b4bb0a3de7531e40630942f5897258cda80",
}


def _install_name(target_platform: str) -> str:
    return "polaris.exe" if target_platform == "windows" else "polaris"


def pinned_asset(target_platform: str, arch: str) -> Tuple[str, str, str, str]:
    """(url, archive sha256, member sha256, install name) for one platform/arch.

    Raises ``ToolNotProvisionableError`` for a pair Polaris publishes nothing for, and
    for a table whose digests no longer match its assets.
    """
    filename = ASSETS.get((target_platform, arch))
    if filename is None:
        available = ", ".join(f"{p}/{a}" for p, a in sorted(ASSETS))
        raise ToolNotProvisionableError(
            f"ASH's Polaris table has no asset for {target_platform}/{arch}. "
            f"Available: {available}"
        )
    archive = ARCHIVE_SHA256.get(filename)
    member = MEMBER_SHA256.get(filename)
    if archive is None or member is None:
        raise ToolNotProvisionableError(
            f"No pinned digest for {filename}; the asset table and the digest tables "
            "of ash_polaris_plugins/polaris_install.py disagree (a half-applied bump)."
        )
    url = f"{_RELEASE_BASE}/{POLARIS_VERSION}/{filename}"
    return url, archive, member, _install_name(target_platform)


def install_polaris(
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
        ASH_LOGGER.info(f"polaris {POLARIS_VERSION} already installed at {target}")
        return target
    if du.is_offline_mode():
        raise ToolNotProvisionableError(
            f"polaris {POLARIS_VERSION} is not installed and ASH is offline "
            "(ASH_OFFLINE), so nothing is downloaded. Install it while online."
        )
    with tempfile.TemporaryDirectory(prefix="ash-polaris-download-") as staging:
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
            "tool": "polaris",
            "version": POLARIS_VERSION,
            "url": url,
            "sha256": archive_sha.lower(),
            "installed_sha256": installed_digest,
            "installed_as": install_as,
        },
    )
    ASH_LOGGER.info(f"Installed polaris {POLARIS_VERSION} to {target}")
    return target


_INSTALL_SCRIPT = (
    "import sys; from pathlib import Path; "
    "from automated_security_helper.plugin_modules.ash_polaris_plugins."
    "polaris_install import install_polaris; "
    "install_polaris(sys.argv[1], sys.argv[2], Path(sys.argv[3]))"
)


def polaris_install_commands() -> "Dict[str, Dict[str, List[CustomCommand]]]":
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
