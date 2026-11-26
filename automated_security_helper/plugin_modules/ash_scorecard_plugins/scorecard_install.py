# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The pinned OpenSSF Scorecard release: versions, digests and the install command.

Why this lives in the plugin module and not in ``utils/tool_downloads.py``: the shared
table is the registry for tools the core installer provisions, and an alpha plugin must
not need an edit there to exist (the reasoning ``ash_polaris_plugins/polaris_install.py``
records). The module-local table has the same shape (a pinned version, one asset per
platform/arch, a SHA256 per asset) and the install goes through the same verified
download and single-member extraction the shared installer uses, so a binary that does
not hash to its pin is never placed.

Digests are the ones Scorecard publishes in the release's ``scorecard_checksums.txt``
(https://github.com/ossf/scorecard/releases/download/v5.7.0/scorecard_checksums.txt),
read again against the ``digest`` field GitHub reports for each asset; all six archives
were downloaded and hashed to these values on 2026-11-26. ``MEMBER_SHA256`` is the
SHA256 of the executable inside each archive, taken from the downloaded archives on the
same day; the installer refuses an archive whose executable does not match. Each archive
holds the executable (``scorecard``, or ``scorecard.exe`` on Windows), ``LICENSE`` and
``README.md``; the linux/amd64 executable reports ``GitVersion: v5.7.0`` and
``GitCommit: d7552fb3cdc05e9f6426177d3328887304fce554`` from ``scorecard version``.

Scorecard is Apache-2.0 and is downloaded at install time, never vendored.

Bumping the version means replacing ``SCORECARD_VERSION``, ``ASSETS``,
``ARCHIVE_SHA256`` and ``MEMBER_SHA256`` together; ``pinned_asset`` refuses a
half-applied bump.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from automated_security_helper.core.exceptions import ToolNotProvisionableError
from automated_security_helper.base.plugin_base import CustomCommand

SCORECARD_VERSION = "v5.7.0"

_RELEASE_BASE = "https://github.com/ossf/scorecard/releases/download"

PlatformArch = Tuple[str, str]

#: (platform, arch) -> release asset. Scorecard publishes no 386 build.
ASSETS: Dict[PlatformArch, str] = {
    ("linux", "amd64"): "scorecard_5.7.0_linux_amd64.tar.gz",
    ("linux", "arm64"): "scorecard_5.7.0_linux_arm64.tar.gz",
    ("darwin", "amd64"): "scorecard_5.7.0_darwin_amd64.tar.gz",
    ("darwin", "arm64"): "scorecard_5.7.0_darwin_arm64.tar.gz",
    ("windows", "amd64"): "scorecard_5.7.0_windows_amd64.tar.gz",
    ("windows", "arm64"): "scorecard_5.7.0_windows_arm64.tar.gz",
}

#: SHA256 of each release archive, from the release's scorecard_checksums.txt.
ARCHIVE_SHA256: Dict[str, str] = {
    "scorecard_5.7.0_linux_amd64.tar.gz": "3b08ec0a8681806c3e744ec9210742a502c7d66f06f25523b70f7128738235d3",
    "scorecard_5.7.0_linux_arm64.tar.gz": "4e1e472e629689aff5877ddf160e3df0d0bc9a94694342d91b17a5f3f83581e2",
    "scorecard_5.7.0_darwin_amd64.tar.gz": "d996794804b497d8bb267b8e7c6d5d91416437218cfbae97ecf85c7030c103dc",
    "scorecard_5.7.0_darwin_arm64.tar.gz": "5b9d68508787a16edadabc9559743d0ef8388b730dbccaaf3052788947050202",
    "scorecard_5.7.0_windows_amd64.tar.gz": "f050ec52248c434764e4f2228cba150151568b8bcc1c2b095d027afe0c32bea2",
    "scorecard_5.7.0_windows_arm64.tar.gz": "f6ede11a52bbd1e72ff20ed0578a01fd9d5beef4c92f7fa716b7b9cc26ad3ba1",
}

#: SHA256 of the executable inside each archive.
MEMBER_SHA256: Dict[str, str] = {
    "scorecard_5.7.0_linux_amd64.tar.gz": "9b2868dec1ca9f9c32fda97caeb7f3aba28bc74c1f982bd222f16749fe4b9211",
    "scorecard_5.7.0_linux_arm64.tar.gz": "69d55bb217095449f9de544ba40871cb145c68d0ead2ee36791f9c3b2e7c9ac0",
    "scorecard_5.7.0_darwin_amd64.tar.gz": "2d1703748b8403470a97ff59f3eaefdea7bb6664fdf8920ec2ea97abeb5bbe73",
    "scorecard_5.7.0_darwin_arm64.tar.gz": "db2928f13b02368c23bf534fce0e0ee4098dc262a4353aea0412aa58cf4e2d7e",
    "scorecard_5.7.0_windows_amd64.tar.gz": "e7373c59662395a2390f0934cb351bd9b29b04bb7901fd74b8aca1311d28cdf6",
    "scorecard_5.7.0_windows_arm64.tar.gz": "3867c206d16f9df29b09367a1e0e09b02ace512255a621ab719ea330332b3d84",
}


def _install_name(target_platform: str) -> str:
    return "scorecard.exe" if target_platform == "windows" else "scorecard"


def pinned_asset(target_platform: str, arch: str) -> Tuple[str, str, str, str]:
    """(url, archive sha256, member sha256, install name) for one platform/arch.

    Raises ``ToolNotProvisionableError`` for a pair Scorecard publishes nothing for, and
    for a table whose digests no longer match its assets.
    """
    filename = ASSETS.get((target_platform, arch))
    if filename is None:
        available = ", ".join(f"{p}/{a}" for p, a in sorted(ASSETS))
        raise ToolNotProvisionableError(
            f"ASH's Scorecard table has no asset for {target_platform}/{arch}. "
            f"Available: {available}"
        )
    archive = ARCHIVE_SHA256.get(filename)
    member = MEMBER_SHA256.get(filename)
    if archive is None or member is None:
        raise ToolNotProvisionableError(
            f"No pinned digest for {filename}; the asset table and the digest tables "
            "of ash_scorecard_plugins/scorecard_install.py disagree (a half-applied "
            "bump)."
        )
    url = f"{_RELEASE_BASE}/{SCORECARD_VERSION}/{filename}"
    return url, archive, member, _install_name(target_platform)


def install_scorecard(
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
        ASH_LOGGER.info(f"scorecard {SCORECARD_VERSION} already installed at {target}")
        return target
    if du.is_offline_mode():
        raise ToolNotProvisionableError(
            f"scorecard {SCORECARD_VERSION} is not installed and ASH is offline "
            "(ASH_OFFLINE), so nothing is downloaded. Install it while online."
        )
    with tempfile.TemporaryDirectory(prefix="ash-scorecard-download-") as staging:
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
            "tool": "scorecard",
            "version": SCORECARD_VERSION,
            "url": url,
            "sha256": archive_sha.lower(),
            "installed_sha256": installed_digest,
            "installed_as": install_as,
        },
    )
    ASH_LOGGER.info(f"Installed scorecard {SCORECARD_VERSION} to {target}")
    return target


_INSTALL_SCRIPT = (
    "import sys; from pathlib import Path; "
    "from automated_security_helper.plugin_modules.ash_scorecard_plugins."
    "scorecard_install import install_scorecard; "
    "install_scorecard(sys.argv[1], sys.argv[2], Path(sys.argv[3]))"
)


def scorecard_install_commands() -> "Dict[str, Dict[str, List[CustomCommand]]]":
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
