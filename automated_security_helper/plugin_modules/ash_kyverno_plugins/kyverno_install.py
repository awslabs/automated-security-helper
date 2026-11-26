# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The pinned Kyverno CLI release: versions, digests and the install command.

Why this lives in the plugin module and not in ``utils/tool_downloads.py``: the shared
table is the registry for tools the core installer provisions, and an alpha plugin must
not need an edit there to exist. The module-local table has the same shape (a pinned
version, one asset per platform/arch, a SHA256 per asset) and the install goes through
the same verified download and single-member extraction the shared installer uses, so a
binary that does not hash to its pin is never placed.

Digests are the ones Kyverno publishes in the release's ``checksums.txt``
(https://github.com/kyverno/kyverno/releases/download/v1.19.2/checksums.txt), read
again against the ``digest`` field GitHub reports for each asset. Every archive below
was downloaded and hashed on 2026-11-26 and matched its ``checksums.txt`` line. ``MEMBER_SHA256`` is the SHA256 of the executable inside each
archive, taken from those downloaded archives the same day; the installer refuses an
archive whose executable does not match.

Kyverno is Apache-2.0 and is downloaded at install time, never vendored.

v1.19.2 and not a later release: v1.20.0 no longer loads the legacy ``kyverno.io/v1``
``ClusterPolicy`` and ``Policy`` kinds (see ``kyverno_scanner.py``).

Bumping the version means replacing ``KYVERNO_VERSION``, ``ASSETS``, ``ARCHIVE_SHA256``
and ``MEMBER_SHA256`` together; ``pinned_asset`` refuses a half-applied bump.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from automated_security_helper.core.exceptions import ToolNotProvisionableError
from automated_security_helper.base.plugin_base import CustomCommand

KYVERNO_VERSION = "v1.19.2"

_RELEASE_BASE = "https://github.com/kyverno/kyverno/releases/download"

PlatformArch = Tuple[str, str]

#: (platform, arch) -> release asset. Kyverno names amd64 ``x86_64``; its linux/s390x
#: build has no row because ASH installs for amd64 and arm64 only.
ASSETS: Dict[PlatformArch, str] = {
    ("linux", "amd64"): "kyverno-cli_v1.19.2_linux_x86_64.tar.gz",
    ("linux", "arm64"): "kyverno-cli_v1.19.2_linux_arm64.tar.gz",
    ("darwin", "amd64"): "kyverno-cli_v1.19.2_darwin_x86_64.tar.gz",
    ("darwin", "arm64"): "kyverno-cli_v1.19.2_darwin_arm64.tar.gz",
    ("windows", "amd64"): "kyverno-cli_v1.19.2_windows_x86_64.zip",
    ("windows", "arm64"): "kyverno-cli_v1.19.2_windows_arm64.zip",
}

#: SHA256 of each release archive, from the release's checksums.txt.
ARCHIVE_SHA256: Dict[str, str] = {
    "kyverno-cli_v1.19.2_linux_x86_64.tar.gz": "357eaf1df8bc24ddd5a73979fadeaae6a032e8710f11af264229756e4956bf4a",
    "kyverno-cli_v1.19.2_linux_arm64.tar.gz": "250f2a02f143d5c6425e686b13c130d3a3ba7372dba6a7210d599d1b0dd12e92",
    "kyverno-cli_v1.19.2_darwin_x86_64.tar.gz": "b645654ab8e65bd4aa64de9228e274b388bab19b3404a4e9af70174b3d5ad230",
    "kyverno-cli_v1.19.2_darwin_arm64.tar.gz": "7915c03c613c22363a100adb3da8d06f2e2626d9d21a98b97f921795ffdc536f",
    "kyverno-cli_v1.19.2_windows_x86_64.zip": "c787cd56d2c2571e5470b1d070fff851c05d104513fcf5cb1652021bb187a1f6",
    "kyverno-cli_v1.19.2_windows_arm64.zip": "4862b9cace01752d19d24e071b1c98f70ac89a387eafa4cf1c255d0013e68cc2",
}

#: SHA256 of the executable inside each archive.
MEMBER_SHA256: Dict[str, str] = {
    "kyverno-cli_v1.19.2_linux_x86_64.tar.gz": "dd492a230e3f7c68235efbf925932cdb34cefbabbd4436d932c3287d9450eea8",
    "kyverno-cli_v1.19.2_linux_arm64.tar.gz": "f65fe04214b92c026aadd512b20582701150dec4c8bbf75add854a63c5cdb02f",
    "kyverno-cli_v1.19.2_darwin_x86_64.tar.gz": "57721aca7fd183e87207fc87537bd925b1803417d5c4caa8007d840f8f8b3eec",
    "kyverno-cli_v1.19.2_darwin_arm64.tar.gz": "cdf8eac3745ea9f41abf6f8e0a6053feee50b27425b37c16e46cb92dd6afc897",
    "kyverno-cli_v1.19.2_windows_x86_64.zip": "c614dc78b9e045f699d020778b5d6a1ad12eaab55a0d18397e87c99d693a272a",
    "kyverno-cli_v1.19.2_windows_arm64.zip": "1357b1865d5b3791b742c46c52ae08792cd63f27f8d5a50c1d7a8983e1776349",
}


def _install_name(target_platform: str) -> str:
    return "kyverno.exe" if target_platform == "windows" else "kyverno"


def pinned_asset(target_platform: str, arch: str) -> Tuple[str, str, str, str]:
    """(url, archive sha256, member sha256, install name) for one platform/arch.

    Raises ``ToolNotProvisionableError`` for a pair ASH's table has no asset for, and
    for a table whose digests no longer match its assets.
    """
    filename = ASSETS.get((target_platform, arch))
    if filename is None:
        available = ", ".join(f"{p}/{a}" for p, a in sorted(ASSETS))
        raise ToolNotProvisionableError(
            f"ASH's Kyverno table has no asset for {target_platform}/{arch}. "
            f"Available: {available}"
        )
    archive = ARCHIVE_SHA256.get(filename)
    member = MEMBER_SHA256.get(filename)
    if archive is None or member is None:
        raise ToolNotProvisionableError(
            f"No pinned digest for {filename}; the asset table and the digest tables "
            "of ash_kyverno_plugins/kyverno_install.py disagree (a half-applied bump)."
        )
    url = f"{_RELEASE_BASE}/{KYVERNO_VERSION}/{filename}"
    return url, archive, member, _install_name(target_platform)


def install_kyverno(
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
        ASH_LOGGER.info(f"kyverno {KYVERNO_VERSION} already installed at {target}")
        return target
    if du.is_offline_mode():
        raise ToolNotProvisionableError(
            f"kyverno {KYVERNO_VERSION} is not installed and ASH is offline "
            "(ASH_OFFLINE), so nothing is downloaded. Install it while online."
        )
    with tempfile.TemporaryDirectory(prefix="ash-kyverno-download-") as staging:
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
            "tool": "kyverno",
            "version": KYVERNO_VERSION,
            "url": url,
            "sha256": archive_sha.lower(),
            "installed_sha256": installed_digest,
            "installed_as": install_as,
        },
    )
    ASH_LOGGER.info(f"Installed kyverno {KYVERNO_VERSION} to {target}")
    return target


_INSTALL_SCRIPT = (
    "import sys; from pathlib import Path; "
    "from automated_security_helper.plugin_modules.ash_kyverno_plugins."
    "kyverno_install import install_kyverno; "
    "install_kyverno(sys.argv[1], sys.argv[2], Path(sys.argv[3]))"
)


def kyverno_install_commands() -> "Dict[str, Dict[str, List[CustomCommand]]]":
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
