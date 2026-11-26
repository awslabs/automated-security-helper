# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The pinned OSV-Scanner release: version, digests and the install command.

Why this lives in the plugin module and not in ``utils/tool_downloads.py``: the shared
table is the registry for tools the core installer provisions, and an alpha plugin must
not need an edit there to exist (``ash_polaris_plugins/polaris_install.py`` has the same
shape). The module-local table holds a pinned version, one asset per platform/arch and a
SHA256 per asset.

OSV-Scanner publishes bare executables, not archives, so the install is the shared
verified single-file download, ``download_utils.install_binary_from_url``: the bytes are
hashed as they land and a binary that does not hash to its pin is never placed, a copy
already installed is re-hashed against its receipt before the download is skipped, and
nothing is downloaded in offline mode.

Digests are the ones OSV-Scanner publishes in the release's ``osv-scanner_SHA256SUMS``
(https://github.com/google/osv-scanner/releases/download/v2.7.1/osv-scanner_SHA256SUMS),
equal to the ``digest`` field GitHub reports for each asset. All six assets were
downloaded and hashed to these values on 2026-11-26, and the linux/amd64 executable
reports ``osv-scanner version: 2.7.1`` and commit
02f96a40691c2d155fdda799af436e111231e365, the commit the v2.7.1 tag points to.

OSV-Scanner is Apache-2.0 and is downloaded at install time, never vendored.

Bumping the version means replacing ``OSV_SCANNER_VERSION`` and every value of
``ASSET_SHA256`` together. The asset names carry no version, so a bump that leaves the
digests stale downloads the new release and is refused by the digest check before
anything is placed; ``pinned_asset`` refuses a table whose assets and digests disagree.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from automated_security_helper.base.plugin_base import CustomCommand
from automated_security_helper.core.exceptions import ToolNotProvisionableError

OSV_SCANNER_VERSION = "v2.7.1"

_RELEASE_BASE = "https://github.com/google/osv-scanner/releases/download"

PlatformArch = Tuple[str, str]

#: (platform, arch) -> release asset. OSV-Scanner publishes no 386 build.
ASSETS: Dict[PlatformArch, str] = {
    ("linux", "amd64"): "osv-scanner_linux_amd64",
    ("linux", "arm64"): "osv-scanner_linux_arm64",
    ("darwin", "amd64"): "osv-scanner_darwin_amd64",
    ("darwin", "arm64"): "osv-scanner_darwin_arm64",
    ("windows", "amd64"): "osv-scanner_windows_amd64.exe",
    ("windows", "arm64"): "osv-scanner_windows_arm64.exe",
}

#: SHA256 of each release asset (the executable itself), from osv-scanner_SHA256SUMS.
ASSET_SHA256: Dict[str, str] = {
    "osv-scanner_linux_amd64": "fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8",  # pragma: allowlist secret
    "osv-scanner_linux_arm64": "983d22fbad9724514e3fcc6acc83b5fa64c5ffa6b0d9f510028f22c1b223ff81",  # pragma: allowlist secret
    "osv-scanner_darwin_amd64": "b8420d5485ba792626315f1bf9a5a2046e971d38eea75bf9090c38852dbc3b1b",  # pragma: allowlist secret
    "osv-scanner_darwin_arm64": "b22c02877a811c8f78956e8643efa554932b7378f590d13f8e97d4e9448a29f3",  # pragma: allowlist secret
    "osv-scanner_windows_amd64.exe": "7121dcf420aefbbf89a7f0050c4d3094e079ff93afd334dfc96f16b02ec85800",  # pragma: allowlist secret
    "osv-scanner_windows_arm64.exe": "5f3998b55c9268f8468502bbcb60645038fd5b145ee5e685e6ae2a32e923afc7",  # pragma: allowlist secret
}


def _install_name(target_platform: str) -> str:
    return "osv-scanner.exe" if target_platform == "windows" else "osv-scanner"


def pinned_asset(target_platform: str, arch: str) -> Tuple[str, str, str]:
    """(url, sha256, install name) for one platform/arch.

    Raises ``ToolNotProvisionableError`` for a pair OSV-Scanner publishes nothing for,
    and for a table whose digests no longer match its assets.
    """
    filename = ASSETS.get((target_platform, arch))
    if filename is None:
        available = ", ".join(f"{p}/{a}" for p, a in sorted(ASSETS))
        raise ToolNotProvisionableError(
            f"ASH's OSV-Scanner table has no asset for {target_platform}/{arch}. "
            f"Available: {available}"
        )
    digest = ASSET_SHA256.get(filename)
    if digest is None:
        raise ToolNotProvisionableError(
            f"No pinned digest for {filename}; the asset table and the digest table "
            "of ash_osv_scanner_plugins/osv_scanner_install.py disagree (a "
            "half-applied bump)."
        )
    url = f"{_RELEASE_BASE}/{OSV_SCANNER_VERSION}/{filename}"
    return url, digest, _install_name(target_platform)


def install_osv_scanner(
    target_platform: str, arch: str, destination: Optional[Path] = None
) -> Path:
    """Download the pinned executable, verify it, and place it in the bin directory."""
    from automated_security_helper.utils import download_utils as du
    from automated_security_helper.utils.log import ASH_LOGGER

    url, digest, install_as = pinned_asset(target_platform, arch)
    bin_dir = Path(destination) if destination is not None else du.current_bin_path()
    if bin_dir is None:
        raise RuntimeError(du.NO_BIN_DIRECTORY)
    bin_dir.mkdir(parents=True, exist_ok=True)
    target = du.install_binary_from_url(
        url, bin_dir, rename_to=install_as, expected_sha256=digest
    )
    ASH_LOGGER.info(f"osv-scanner {OSV_SCANNER_VERSION} is at {target}")
    return target


_INSTALL_SCRIPT = (
    "import sys; from pathlib import Path; "
    "from automated_security_helper.plugin_modules.ash_osv_scanner_plugins."
    "osv_scanner_install import install_osv_scanner; "
    "install_osv_scanner(sys.argv[1], sys.argv[2], Path(sys.argv[3]))"
)


def osv_scanner_install_commands() -> "Dict[str, Dict[str, List[CustomCommand]]]":
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
