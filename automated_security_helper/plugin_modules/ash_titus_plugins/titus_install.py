# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The pinned Titus release: version, digests and the install command.

Why this lives in the plugin module and not in ``utils/tool_downloads.py``: the shared
table is the registry for tools the core installer provisions, and an alpha plugin must
not need an edit there to exist. The module-local table has the same shape (a pinned
version, one asset per platform/arch, a SHA256 per asset), and the install goes through
the same verified download and staged, pin-checked rename the shared installer gives a
release that publishes bare executables (hadolint, opengrep), so a binary that does not
hash to its pin is never placed.

Titus publishes each release executable bare, with no archive around it, so one digest
per asset covers the file that runs. The digests are the ones Titus publishes in the
release's ``checksums.txt``
(https://github.com/praetorian-inc/titus/releases/download/v1.3.0/checksums.txt), read
again against the ``digest`` field GitHub reports for each asset, and all five assets
were downloaded and hashed on 2026-11-26 (linux/amd64: 74c665b8...). The asset names
carry no version, so the version lives only in the release tag in the URL, and
``DIGESTS_TAKEN_AT`` records the release the digests were read from.

Titus is Apache-2.0 and is downloaded at install time, never vendored.

Bumping the version means replacing ``TITUS_VERSION``, ``DIGESTS_TAKEN_AT`` and
``ASSET_SHA256`` together; ``pinned_asset`` refuses a half-applied bump.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from automated_security_helper.core.exceptions import ToolNotProvisionableError
from automated_security_helper.base.plugin_base import CustomCommand

TITUS_VERSION = "v1.3.0"

#: The release the digests below were read from. The asset names carry no version,
#: so without this a version bump that left the digests behind would look complete.
DIGESTS_TAKEN_AT = "v1.3.0"

_RELEASE_BASE = "https://github.com/praetorian-inc/titus/releases/download"

PlatformArch = Tuple[str, str]

#: (platform, arch) -> release asset. Titus publishes no 386 build and no
#: windows/arm64 build.
ASSETS: Dict[PlatformArch, str] = {
    ("linux", "amd64"): "titus-linux-amd64",
    ("linux", "arm64"): "titus-linux-arm64",
    ("darwin", "amd64"): "titus-darwin-amd64",
    ("darwin", "arm64"): "titus-darwin-arm64",
    ("windows", "amd64"): "titus-windows-amd64.exe",
}

#: SHA256 of each release executable, from the release's checksums.txt.
ASSET_SHA256: Dict[str, str] = {
    "titus-linux-amd64": "74c665b8222501793e9399052c4c4b6ffb3ecee1cd83a78950c759b2112fdabc",
    "titus-linux-arm64": "12edf39b68d2e22c35c4931837a3c08fc95d2d626281d84b1fcbdd1c5429ca21",
    "titus-darwin-amd64": "a05f73cd2f3f3c19d6dba5dd46ce7dfa1dd06d38d3fe79a259fb75c654595ee5",
    "titus-darwin-arm64": "68cca24f204c86835cbb0dca186de2e75f2b8df315f5a5a7664a2f518ec1689e",
    "titus-windows-amd64.exe": "0c738c03df9c1b433e40ff80ae9e7ca2f3bd7c67384f96700d1e62c8c12b95e1",
}


def _install_name(target_platform: str) -> str:
    return "titus.exe" if target_platform == "windows" else "titus"


def pinned_asset(target_platform: str, arch: str) -> Tuple[str, str, str]:
    """(url, sha256, install name) for one platform/arch.

    Raises ``ToolNotProvisionableError`` for a pair Titus publishes nothing for, and
    for a table whose digests no longer match its assets or its version.
    """
    filename = ASSETS.get((target_platform, arch))
    if filename is None:
        available = ", ".join(f"{p}/{a}" for p, a in sorted(ASSETS))
        raise ToolNotProvisionableError(
            f"ASH's Titus table has no asset for {target_platform}/{arch}. "
            f"Available: {available}"
        )
    digest = ASSET_SHA256.get(filename)
    if digest is None or DIGESTS_TAKEN_AT != TITUS_VERSION:
        raise ToolNotProvisionableError(
            f"No pinned digest for {filename} at {TITUS_VERSION}; the version, the "
            "asset table and the digest table of ash_titus_plugins/titus_install.py "
            "disagree (a half-applied bump)."
        )
    url = f"{_RELEASE_BASE}/{TITUS_VERSION}/{filename}"
    return url, digest, _install_name(target_platform)


def install_titus(
    target_platform: str, arch: str, destination: Optional[Path] = None
) -> Path:
    """Download the pinned executable, verify it, and place it.

    The digest is checked as the bytes land, and again on the staged copy that is
    renamed into place, so a file that does not hash to its pin is never placed.
    """
    import tempfile

    from automated_security_helper.utils import download_utils as du
    from automated_security_helper.utils.log import ASH_LOGGER

    url, sha256, install_as = pinned_asset(target_platform, arch)
    bin_dir = Path(destination) if destination is not None else du.current_bin_path()
    if bin_dir is None:
        raise RuntimeError(du.NO_BIN_DIRECTORY)
    bin_dir.mkdir(parents=True, exist_ok=True)
    target = bin_dir.joinpath(install_as)
    if du._already_installed(bin_dir, install_as, url, sha256):
        ASH_LOGGER.info(f"titus {TITUS_VERSION} already installed at {target}")
        return target
    if du.is_offline_mode():
        raise ToolNotProvisionableError(
            f"titus {TITUS_VERSION} is not installed and ASH is offline "
            "(ASH_OFFLINE), so nothing is downloaded. Install it while online."
        )
    with tempfile.TemporaryDirectory(prefix="ash-titus-download-") as staging:
        asset_name = url.rsplit("/", 1)[-1]
        downloaded = du.download_file(
            url,
            Path(staging),
            rename_to=asset_name,
            expected_sha256=sha256,
            mode=0o755,
        )
        installed_digest = du._replace_atomically(
            downloaded, target, expected_sha256=sha256, mode=0o755
        )
    du.unquarantine_macos_binary(target)
    du.write_receipt(
        bin_dir,
        install_as,
        {
            "tool": "titus",
            "version": TITUS_VERSION,
            "url": url,
            "sha256": sha256.lower(),
            "installed_sha256": installed_digest,
            "installed_as": install_as,
        },
    )
    ASH_LOGGER.info(f"Installed titus {TITUS_VERSION} to {target}")
    return target


_INSTALL_SCRIPT = (
    "import sys; from pathlib import Path; "
    "from automated_security_helper.plugin_modules.ash_titus_plugins."
    "titus_install import install_titus; "
    "install_titus(sys.argv[1], sys.argv[2], Path(sys.argv[3]))"
)


def titus_install_commands() -> "Dict[str, Dict[str, List[CustomCommand]]]":
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
