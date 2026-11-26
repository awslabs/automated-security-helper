# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The pinned Composer release: version, phar digest and the install command.

Why this lives in the plugin module and not in ``utils/tool_downloads.py``: the shared
table is the registry for tools the core installer provisions, and an alpha plugin must
not need an edit there to exist. The install goes through the shared verified download
(``download_utils.install_binary_from_url``: the digest is checked as the bytes land,
the install is skipped when a receipt shows the same bytes are still in place, and an
offline run downloads nothing), so a phar that does not hash to its pin is never placed.

Composer ships as one platform-independent PHP archive, ``composer.phar``, whose first
line is ``#!/usr/bin/env php``. It is installed as ``composer`` with the execute bit, the
way Composer's own download page installs it, so it runs wherever ``php`` is on
``PATH``. ASH installs Composer, never PHP: PHP is the user's (``external_programs`` in
the scanner's register row). Windows is not installed: there a ``.phar`` needs a
``composer.bat`` launcher, and Composer-Setup.exe is the documented route.

The digest is the one Composer publishes beside the phar
(https://getcomposer.org/download/2.11.3/composer.phar.sha256sum). On 2026-11-26 the
phar was downloaded and hashed to it on a development host, its own SHA-512 phar
signature verified, and the ``VERSION`` constant compiled into it read as ``2.11.3``
(release date 2026-11-24 10:14:18). ``COMPOSER_COMMIT`` is the commit the 2.11.3 tag
points to, and ``LICENSE_SHA256`` the digest of the repository ``LICENSE`` there (MIT,
"Copyright (c) Nils Adermann, Jordi Boggiano"); the phar carries that file byte for byte
(compared the same day). Composer is downloaded at install time and never vendored.

Bumping the version means replacing ``COMPOSER_VERSION``, ``PHAR_SHA256``,
``COMPOSER_COMMIT`` and ``LICENSE_SHA256`` together, after reading the new release's
license.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from automated_security_helper.base.plugin_base import CustomCommand

COMPOSER_VERSION = "2.11.3"

#: The release asset: platform independent, so one URL and one digest serve every
#: platform it is installed on.
PHAR_URL = f"https://getcomposer.org/download/{COMPOSER_VERSION}/composer.phar"

#: SHA-256 of that asset, as Composer publishes it in ``composer.phar.sha256sum``.
PHAR_SHA256 = "04f8b003da4e3a2459056591fbfebd02b4dc3e5adeb158616b90cf55a65113ec"  # pragma: allowlist secret

#: The commit ``refs/tags/2.11.3`` points to in https://github.com/composer/composer.
COMPOSER_COMMIT = "e4a580d4d41edb0eb5a470f441c9780ba49df75f"  # pragma: allowlist secret

#: SHA-256 of the repository ``LICENSE`` at ``COMPOSER_COMMIT`` (1068 bytes, MIT).
LICENSE_SHA256 = "7855ac293067aebe7e51afdd23b9dea54b8be24187dbecc9b9142581c37f596c"  # pragma: allowlist secret

#: The name the phar is installed under: the command the scanner runs.
INSTALL_NAME = "composer"

PlatformArch = Tuple[str, str]

#: Where the phar is installed: the platforms whose kernels honor its ``php`` shebang.
PLATFORMS: Tuple[PlatformArch, ...] = (
    ("darwin", "amd64"),
    ("darwin", "arm64"),
    ("linux", "amd64"),
    ("linux", "arm64"),
)


def install_composer(destination: Optional[Path] = None) -> Path:
    """Download the pinned phar, verify it, and place it as ``composer``.

    The digest is checked as the bytes land, so a mismatch leaves nothing at the
    destination, and a receipt makes a second install of the same bytes a no-op.
    """
    from automated_security_helper.utils import download_utils as du
    from automated_security_helper.utils.log import ASH_LOGGER

    bin_dir = Path(destination) if destination is not None else du.current_bin_path()
    if bin_dir is None:
        raise RuntimeError(du.NO_BIN_DIRECTORY)
    bin_dir.mkdir(parents=True, exist_ok=True)
    target = du.install_binary_from_url(
        PHAR_URL,
        bin_dir,
        rename_to=INSTALL_NAME,
        expected_sha256=PHAR_SHA256,
    )
    ASH_LOGGER.info(
        f"Composer {COMPOSER_VERSION} is at {target}; it runs with the php on PATH"
    )
    return target


_INSTALL_SCRIPT = (
    "import sys; from pathlib import Path; "
    "from automated_security_helper.plugin_modules.ash_composer_audit_plugins."
    "composer_install import install_composer; "
    "install_composer(Path(sys.argv[1]))"
)


def composer_install_commands() -> "Dict[str, Dict[str, List[CustomCommand]]]":
    """The ``custom_install_commands`` table: one entry per platform in ``PLATFORMS``.

    Never raises. With no usable bin directory every entry is a command that refuses
    with the reason, so constructing the scanner during a scan cannot fail.
    """
    from automated_security_helper.utils import download_utils as du

    bin_dir = du.current_bin_path()
    if bin_dir is None:
        command = du.refusing_install_command(du.NO_BIN_DIRECTORY)
    else:
        command = CustomCommand(
            args=[
                sys.executable,
                "-c",
                _INSTALL_SCRIPT,
                du._destination_text(Path(bin_dir).absolute()),
            ],
            shell=False,
        )
    table: Dict[str, Dict[str, List[CustomCommand]]] = {}
    for target_platform, arch in PLATFORMS:
        table.setdefault(target_platform, {})[arch] = [command]
    return table


__all__ = [
    "COMPOSER_COMMIT",
    "COMPOSER_VERSION",
    "INSTALL_NAME",
    "LICENSE_SHA256",
    "PHAR_SHA256",
    "PHAR_URL",
    "PLATFORMS",
    "composer_install_commands",
    "install_composer",
]
