# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The pinned Spectral release: version, per-platform executables, digests, install command.

Why this lives in the plugin module and not in ``utils/tool_downloads.py``: the shared
table is the registry for tools the core installer provisions, and an alpha plugin must
not need an edit there to exist (the same reason as ``ash_polaris_plugins``). The
module-local table has the shared table's shape (a pinned version, one asset per
platform/arch, a SHA256 per asset), and the install goes through the verified download
the shared installer uses for a bare executable (``download_utils.install_binary_from_url``,
reached through ``create_url_download_command``), so a binary that does not hash to its
pin is never placed.

Spectral publishes each release as bare executables (its Node.js program packaged into
one native binary per platform), not archives, so the asset digest covers the very bytes
that run and there is no second digest for a member inside. The asset names carry no
version (``spectral-linux-x64`` in every release), so the release the digests were taken
at is recorded in ``DIGESTS_TAKEN_AT``, and ``pinned_asset`` refuses a version bump that
left the digests behind by name, instead of failing it later as an integrity mismatch.

Digests are the ones GitHub reports in the ``digest`` field of each asset of the v6.17.1
release (https://github.com/stoplightio/spectral/releases/tag/v6.17.1), and every asset
was downloaded and hashed again on 2026-11-26; all five agreed. The linux x64 executable
was run and prints ``6.17.1``. The release's ``spectral-alpine-x64`` and
``spectral-alpine-arm64`` (musl builds) are not used: ASH's platform vocabulary names no
libc, and the ASH image is glibc.

Spectral is Apache-2.0 and is downloaded at install time, never vendored.

Bumping the version means replacing ``SPECTRAL_VERSION``, ``DIGESTS_TAKEN_AT`` and
``SHA256`` together; ``pinned_asset`` refuses a half-applied bump.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

from automated_security_helper.base.plugin_base import CustomCommand
from automated_security_helper.core.exceptions import ToolNotProvisionableError

SPECTRAL_VERSION = "v6.17.1"

#: The release ``SHA256`` was taken at. The asset names carry no version, so this is
#: what tells a bumped ``SPECTRAL_VERSION`` from the digests it still needs.
DIGESTS_TAKEN_AT = "v6.17.1"

_RELEASE_BASE = "https://github.com/stoplightio/spectral/releases/download"

PlatformArch = Tuple[str, str]

#: (platform, arch) -> release asset. Spectral publishes no Windows arm64 build.
ASSETS: Dict[PlatformArch, str] = {
    ("linux", "amd64"): "spectral-linux-x64",
    ("linux", "arm64"): "spectral-linux-arm64",
    ("darwin", "amd64"): "spectral-macos-x64",
    ("darwin", "arm64"): "spectral-macos-arm64",
    ("windows", "amd64"): "spectral.exe",
}

#: SHA256 of each release asset, which is the executable itself.
SHA256: Dict[str, str] = {
    "spectral-linux-x64": "0196c72234478e4e23df28b662afa7c9f80a47cfd31dc697e674151ad060bb35",
    "spectral-linux-arm64": "730005664bbe95680f6b348790bb04da220e824b6e0a6768d16a1a988a86b31e",
    "spectral-macos-x64": "42355e6dd861ba959164c6f24877fc77430001e263855e7379bb935e6566d836",
    "spectral-macos-arm64": "ac0814fa86af3b57bb802f2290bb74e558b9522b9928ef16ac26c0d01ae6f9c5",
    "spectral.exe": "333705178ced9c7f815eed2fb5de99620643fd39a2373225e513eeb644648e57",
}


def _install_name(target_platform: str) -> str:
    return "spectral.exe" if target_platform == "windows" else "spectral"


def pinned_asset(target_platform: str, arch: str) -> Tuple[str, str, str]:
    """(url, sha256, install name) for one platform/arch.

    Raises ``ToolNotProvisionableError`` for a pair Spectral publishes nothing for, for
    a version the digests were not taken at, and for an asset with no digest.
    """
    filename = ASSETS.get((target_platform, arch))
    if filename is None:
        available = ", ".join(f"{p}/{a}" for p, a in sorted(ASSETS))
        raise ToolNotProvisionableError(
            f"ASH's Spectral table has no asset for {target_platform}/{arch}. "
            f"Available: {available}"
        )
    if SPECTRAL_VERSION != DIGESTS_TAKEN_AT:
        raise ToolNotProvisionableError(
            f"SPECTRAL_VERSION is {SPECTRAL_VERSION}, but the digests in "
            f"ash_spectral_plugins/spectral_install.py were taken at {DIGESTS_TAKEN_AT} "
            "(a half-applied bump): the asset names carry no version, so the old "
            "digests would be checked against another release's bytes."
        )
    digest = SHA256.get(filename)
    if digest is None:
        raise ToolNotProvisionableError(
            f"No pinned digest for {filename}; the asset table and the digest table "
            "of ash_spectral_plugins/spectral_install.py disagree (a half-applied bump)."
        )
    url = f"{_RELEASE_BASE}/{SPECTRAL_VERSION}/{filename}"
    return url, digest, _install_name(target_platform)


def spectral_install_commands() -> "Dict[str, Dict[str, List[CustomCommand]]]":
    """The ``custom_install_commands`` table: one entry per published platform/arch.

    Each entry runs ``download_utils.install_binary_from_url`` with the pinned digest:
    a download that does not match is refused, nothing is downloaded offline
    (``ASH_OFFLINE``), and an install a receipt already records is reused.

    Never raises. A pair whose pin cannot be resolved, and every pair when there is no
    usable bin directory, gets a command that refuses with the reason, so constructing
    the scanner during a scan cannot fail.
    """
    from automated_security_helper.utils.download_utils import (
        create_url_download_command,
        refusing_install_command,
    )

    table: Dict[str, Dict[str, List[CustomCommand]]] = {}
    for target_platform, arch in sorted(ASSETS):
        try:
            url, digest, install_as = pinned_asset(target_platform, arch)
            command = create_url_download_command(
                url, rename_to=install_as, expected_sha256=digest
            )
        except (ToolNotProvisionableError, ValueError) as exc:
            command = refusing_install_command(str(exc))
        table.setdefault(target_platform, {})[arch] = [command]
    return table
