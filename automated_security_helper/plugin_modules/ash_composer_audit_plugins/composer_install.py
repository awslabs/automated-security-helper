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
line is ``#!/usr/bin/env php``. On Linux and macOS it is installed as ``composer`` with
the execute bit, the way Composer's own download page installs it, so it runs wherever
``php`` is on ``PATH``. Windows does not read a shebang, so there the phar keeps its
name and a ``composer.bat`` launcher is written beside it: the layout of Composer's own
manual Windows install (``doc/00-intro.md`` at ``COMPOSER_COMMIT``, "Create a new
``composer.bat`` file alongside ``composer.phar``", holding
``@php "%~dp0composer.phar" %*``). The launcher is what ``composer`` resolves to on
``PATH``; the scanner itself runs the phar with ``php`` directly when the launcher has
it beside it, so cmd.exe never reads the audit's arguments. ASH installs Composer, never
PHP: PHP is the user's (``external_programs`` in the scanner's register row).

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

import hashlib
import os
import platform
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

#: The name the phar is installed under where its ``php`` shebang is honored (Linux and
#: macOS): the command the scanner runs.
INSTALL_NAME = "composer"

#: On Windows the phar keeps its own name, and the launcher beside it is what
#: ``composer`` resolves to.
WINDOWS_PHAR_NAME = "composer.phar"
WINDOWS_LAUNCHER_NAME = "composer.bat"

#: The launcher's bytes: the line Composer's manual Windows install writes with
#: ``echo @php "%~dp0composer.phar" %*>composer.bat``, ended as cmd.exe ends it.
WINDOWS_LAUNCHER = b'@php "%~dp0composer.phar" %*\r\n'

PlatformArch = Tuple[str, str]

#: Where the phar is installed: every platform and architecture ASH installs for. The
#: phar is platform independent; what differs is how it is started (see the module
#: docstring).
PLATFORMS: Tuple[PlatformArch, ...] = (
    ("darwin", "amd64"),
    ("darwin", "arm64"),
    ("linux", "amd64"),
    ("linux", "arm64"),
    ("windows", "amd64"),
    ("windows", "arm64"),
)


def _holds(path: Path, data: bytes) -> bool:
    """Whether *path* is a regular file, not a link, holding exactly *data*."""
    try:
        if path.is_symlink() or not path.is_file():
            return False
        return path.read_bytes() == data
    except OSError:
        return False


def _place_windows_launcher(bin_dir: Path) -> Path:
    """Write ``composer.bat`` into *bin_dir*, unless it already holds the same bytes.

    Staged beside the target and renamed over it as the verified downloads are
    (``download_utils._open_staging`` and ``_finalize_staged``): the bytes are checked
    against their own digest before and after the rename, and a link at the target is
    replaced, never followed.
    """
    from automated_security_helper.utils import download_utils as du

    target = bin_dir / WINDOWS_LAUNCHER_NAME
    if _holds(target, WINDOWS_LAUNCHER):
        return target
    fd, staging = du._open_staging(target)
    try:
        with os.fdopen(fd, "wb") as sink:
            sink.write(WINDOWS_LAUNCHER)
        du._finalize_staged(
            staging,
            target,
            hashlib.sha256(WINDOWS_LAUNCHER).hexdigest(),
            mode=0o755,
        )
    except BaseException:
        staging.unlink(missing_ok=True)
        raise
    return target


def install_composer(
    destination: Optional[Path] = None, target_platform: Optional[str] = None
) -> Path:
    """Download the pinned phar, verify it, and place it where ``composer`` resolves.

    On Linux and macOS the phar is placed as ``composer``. On Windows
    (*target_platform* ``windows``, or the running platform when it is None) it is
    placed as ``composer.phar`` with the ``composer.bat`` launcher beside it, and the
    launcher is returned. The digest is checked as the bytes land, so a mismatch
    leaves nothing at the destination, and a receipt makes a second install of the
    same bytes a no-op.
    """
    from automated_security_helper.utils import download_utils as du
    from automated_security_helper.utils.log import ASH_LOGGER

    target_platform = (target_platform or platform.system()).lower()
    bin_dir = Path(destination) if destination is not None else du.current_bin_path()
    if bin_dir is None:
        raise RuntimeError(du.NO_BIN_DIRECTORY)
    bin_dir.mkdir(parents=True, exist_ok=True)
    if target_platform == "windows":
        phar = du.install_binary_from_url(
            PHAR_URL,
            bin_dir,
            rename_to=WINDOWS_PHAR_NAME,
            expected_sha256=PHAR_SHA256,
        )
        launcher = _place_windows_launcher(bin_dir)
        ASH_LOGGER.info(
            f"Composer {COMPOSER_VERSION} is at {phar}, started by {launcher} with "
            "the php on PATH"
        )
        return launcher
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
    "install_composer(Path(sys.argv[2]), sys.argv[1])"
)


def composer_install_commands() -> "Dict[str, Dict[str, List[CustomCommand]]]":
    """The ``custom_install_commands`` table: one entry per platform in ``PLATFORMS``.

    Each command names its platform, so a Windows entry places the phar and its
    launcher. Never raises. With no usable bin directory every entry is a command that
    refuses with the reason, so constructing the scanner during a scan cannot fail.
    """
    from automated_security_helper.utils import download_utils as du

    bin_dir = du.current_bin_path()
    table: Dict[str, Dict[str, List[CustomCommand]]] = {}
    for target_platform, arch in PLATFORMS:
        if bin_dir is None:
            command = du.refusing_install_command(du.NO_BIN_DIRECTORY)
        else:
            command = CustomCommand(
                args=[
                    sys.executable,
                    "-c",
                    _INSTALL_SCRIPT,
                    target_platform,
                    du._destination_text(Path(bin_dir).absolute()),
                ],
                shell=False,
            )
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
    "WINDOWS_LAUNCHER",
    "WINDOWS_LAUNCHER_NAME",
    "WINDOWS_PHAR_NAME",
    "composer_install_commands",
    "install_composer",
]
