# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The pinned retire.js install: the whole npm tree, not only the top package.

Why this lives in the plugin module and not in ``utils/tool_downloads.py``: the shared
table is the registry for tools the core installer provisions, and an alpha plugin must
not need an edit there to exist (``ash_polaris_plugins/polaris_install.py`` is the same
shape). What ``tool_downloads.py`` does carry is the attribution: the
``THIRD_PARTY_LICENSES`` entries of retire and of the five packages its tree holds,
which the container image stages beside the tree.

What is pinned
--------------
``npm install -g retire@6.1.1`` pinned the top package and nothing under it. The
retire tarball holds no shrinkwrap or lockfile (the registry records
``_hasShrinkwrap: false``), and retire 6.1.1 declares ``zod ^4.6.5``,
``commander ^14.0.3``, ``walkdir 0.4.1`` and ``astronomical ^3.2.0``, which declares
``meriyah ^7.1.0``, so each install took the newest release in every range on the day.

Here the tree is a lockfile. ``LOCKED_PACKAGES`` is the ``packages`` table npm 10.9
wrote for ``{"dependencies": {"retire": "6.1.1"}}`` with ``npm install
--package-lock-only`` on 2026-11-26: six packages, each with the ``resolved`` URL and
the ``integrity`` (SHA-512) the registry publishes for that release. ``npm ci``
installs exactly those six, checks every tarball it downloads against its integrity
and refuses a mismatch, and never resolves a range. Each tarball was downloaded and
hashed to its integrity on the same day.

``TREE_SHA256`` is :func:`tree_digest` of the tree ``npm ci`` installed from this
lockfile on 2026-11-26 (986 files, every package's files byte for byte its tarball's).
The install is refused unless the tree it staged hashes to it, and a tree already in
place that still hashes to it is the answer to "is it installed". That answer needs no
install receipt, so the container image's non-root stage, whose receipts would live in
another home, finds the tree the root stage put in place instead of installing again.

Where it goes
-------------
``<bin dir>/ash-retire-js`` holds ``package.json``, ``package-lock.json`` and
``node_modules``. The command is ``<bin dir>/retire``: on Linux and macOS a relative
symbolic link to the tree's ``node_modules/retire/lib/cli.js``, whose
``#!/usr/bin/env node`` line runs it on the ``node`` on PATH (``npm ci`` links bins,
which makes it executable); on Windows ``retire.cmd``, which runs ``node`` on that
file. The bin directory is the one ``ash dependencies install --bin-path`` names, so a
user installs into a directory it can write, and the scanner sandbox, which mounts
ASH's bin directory, can read the tree.

retire.js and the five packages are Apache-2.0, MIT and ISC. They are downloaded from
the npm registry at install time and are not vendored in ASH's source.

Bumping
-------
Replace ``RETIRE_VERSION``, ``LOCKED_PACKAGES`` (from a fresh ``npm install
--package-lock-only`` of the new release) and ``TREE_SHA256`` together, and the
``THIRD_PARTY_LICENSES`` entries of retire and of every package the new lockfile
names. A tree that does not hash to ``TREE_SHA256`` is refused, so a half-applied bump
installs nothing.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess  # nosec B404 - runs the npm found on PATH with a fixed argv
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from automated_security_helper.base.plugin_base import CustomCommand
from automated_security_helper.core.exceptions import ToolNotProvisionableError

#: The npm package that provides the ``retire`` command, and the version ASH installs.
RETIRE_NPM_PACKAGE = "retire"
RETIRE_VERSION = "6.1.1"

#: The directory under the bin directory that holds the tree.
TREE_DIRECTORY = "ash-retire-js"

#: Platforms the tree is installed on. Every package in it is plain JavaScript.
INSTALL_PLATFORMS: Tuple[Tuple[str, str], ...] = tuple(
    (platform, arch)
    for platform in ("linux", "darwin", "windows")
    for arch in ("amd64", "arm64")
)

#: The project ``npm ci`` installs: retire, at exactly the pinned release.
PACKAGE_JSON: Dict[str, Any] = {
    "name": TREE_DIRECTORY,
    "version": RETIRE_VERSION,
    "private": True,
    "dependencies": {RETIRE_NPM_PACKAGE: RETIRE_VERSION},
}

#: The lockfile's ``packages`` table, as npm wrote it (see the module docstring).
LOCKED_PACKAGES: Dict[str, Dict[str, Any]] = {
    "node_modules/astronomical": {
        "version": "3.2.0",
        "resolved": "https://registry.npmjs.org/astronomical/-/astronomical-3.2.0.tgz",
        "integrity": "sha512-nRKPza8f1nYpAyymI5edTgWwo4+BRgeqFtyVrKgN0tBwi9eIlVL4UpSyAOYhUSoSTln7IEHtShGSYUPgnHzveg==",  # pragma: allowlist secret
        "license": "Apache-2.0",
        "dependencies": {"meriyah": "^7.1.0"},
    },
    "node_modules/commander": {
        "version": "14.0.3",
        "resolved": "https://registry.npmjs.org/commander/-/commander-14.0.3.tgz",
        "integrity": "sha512-H+y0Jo/T1RZ9qPP4Eh1pkcQcLRglraJaSLoyOtHxu6AapkjWVCy2Sit1QQ4x3Dng8qDlSsZEet7g5Pq06MvTgw==",  # pragma: allowlist secret
        "license": "MIT",
        "engines": {"node": ">=20"},
    },
    "node_modules/meriyah": {
        "version": "7.4.3",
        "resolved": "https://registry.npmjs.org/meriyah/-/meriyah-7.4.3.tgz",
        "integrity": "sha512-XIqTw35yWAg02tem6pp9964KTihoi0HKqP5f9rzS1Ajq9OfxWeVbpWeIACCk64diXxGFmEPJOM7jlzz0cbpYaA==",  # pragma: allowlist secret
        "license": "ISC",
        "engines": {"node": ">=20.0.0"},
    },
    "node_modules/retire": {
        "version": "6.1.1",
        "resolved": "https://registry.npmjs.org/retire/-/retire-6.1.1.tgz",
        "integrity": "sha512-66CXnfvUeKgWtuOvV9XkYQ1LCPdZTpt3Lgb7va+jq4Ylh3BkIFz6bDP2X+kQN6tSCvzWdlw9Oeb5w0qYdw/BFg==",  # pragma: allowlist secret
        "license": "Apache-2.0",
        "dependencies": {
            "astronomical": "^3.2.0",
            "commander": "^14.0.3",
            "walkdir": "0.4.1",
            "zod": "^4.6.5",
        },
        "bin": {"retire": "lib/cli.js"},
        "engines": {"node": "^20.19.0 || >=22.12.0"},
    },
    "node_modules/walkdir": {
        "version": "0.4.1",
        "resolved": "https://registry.npmjs.org/walkdir/-/walkdir-0.4.1.tgz",
        "integrity": "sha512-3eBwRyEln6E1MSzcxcVpQIhRG8Q1jLvEqRmCZqS3dsfXEDR/AhOF4d+jHg1qvDCpYaVRZjENPQyrVxAkQqxPgQ==",  # pragma: allowlist secret
        "license": "MIT",
        "engines": {"node": ">=6.0.0"},
    },
    "node_modules/zod": {
        "version": "4.6.7",
        "resolved": "https://registry.npmjs.org/zod/-/zod-4.6.7.tgz",
        "integrity": "sha512-g8W2D2kU6a8untc053fX1uVBKzM7yqAxW/3zwk83+6RyF2+SKOuV+c0wBDhUwzV1PaGapmZH+rmcUzPf+3CGwg==",  # pragma: allowlist secret
        "license": "MIT",
        "funding": {"url": "https://github.com/sponsors/colinhacks"},
    },
}

#: :func:`tree_digest` of the tree ``npm ci`` installs from :func:`lockfile`.
TREE_SHA256 = "2eca201d806d2648a6431d364e4168a9e18ab59ac9dee27f29e5fde61855c9be"  # pragma: allowlist secret

#: How many files ``TREE_SHA256`` covers, for the messages.
TREE_FILE_COUNT = 986

#: What npm itself writes into ``node_modules`` beside the packages: the bin links and
#: its own record of the install. Both differ by npm version and platform, and neither
#: is code retire loads, so neither is part of the digest.
_NPM_OWN_ENTRIES = frozenset({".bin", ".package-lock.json"})

#: ``npm ci``'s options, each overriding whatever the user's npm configuration says.
#: No lifecycle scripts run (none of the six packages declares one); the layout is the
#: flat one the digest was taken over; bins are linked, which is what makes the command
#: script executable; a Node.js outside retire's ``engines`` range fails the install
#: instead of the first scan.
_NPM_CI_ARGS: Tuple[str, ...] = (
    "ci",
    "--ignore-scripts",
    "--install-strategy=hoisted",
    "--bin-links",
    "--engine-strict",
    "--no-audit",
    "--no-fund",
    "--no-update-notifier",
)

#: Seconds ``npm ci`` may take before the install is abandoned.
_NPM_TIMEOUT_SECONDS = 900


def lockfile() -> Dict[str, Any]:
    """The ``package-lock.json`` ``npm ci`` installs from."""
    root = {
        "name": PACKAGE_JSON["name"],
        "version": PACKAGE_JSON["version"],
        "dependencies": dict(PACKAGE_JSON["dependencies"]),
    }
    return {
        "name": PACKAGE_JSON["name"],
        "version": PACKAGE_JSON["version"],
        "lockfileVersion": 3,
        "requires": True,
        "packages": {"": root, **json.loads(json.dumps(LOCKED_PACKAGES))},
    }


def _json_text(data: Dict[str, Any]) -> str:
    return json.dumps(data, indent=2) + "\n"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_digest(tree: Path) -> str:
    """SHA256 over every file of the locked packages under ``tree``.

    One line per file, ``<path relative to tree>\\0<SHA256 of its bytes>\\n``, sorted
    by that path; the digest is of their concatenation, encoded as UTF-8. Only the
    locked package directories are read, never npm's own entries
    (``_NPM_OWN_ENTRIES``). The content alone is hashed: file modes and times differ
    by platform and umask, and the bytes are what runs.

    Raises:
        ValueError: a package directory is missing, or holds a symbolic link or
            anything else that is neither a regular file nor a directory.
    """
    entries: List[Tuple[str, str]] = []
    for package in sorted(LOCKED_PACKAGES):
        directory = tree.joinpath(*package.split("/"))
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError(f"{package} is missing")
        for dirpath, dirnames, filenames in os.walk(directory):
            for name in [*dirnames, *filenames]:
                path = Path(dirpath, name)
                mode = os.lstat(path).st_mode
                if stat.S_ISDIR(mode):
                    continue
                relative = path.relative_to(tree).as_posix()
                if not stat.S_ISREG(mode):
                    raise ValueError(f"{relative} is not a regular file")
                entries.append((relative, _sha256_file(path)))
    entries.sort()
    text = "".join(f"{relative}\0{digest}\n" for relative, digest in entries)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def tree_problem(tree: Path) -> Optional[str]:
    """Why ``tree`` is not the pinned tree, or None when it is."""
    if tree.is_symlink() or not tree.is_dir():
        return f"{tree} does not exist"
    modules = tree / "node_modules"
    if modules.is_symlink() or not modules.is_dir():
        return f"{modules} does not exist"
    expected = {package.split("/", 1)[1] for package in LOCKED_PACKAGES}
    present = set(os.listdir(modules)) - _NPM_OWN_ENTRIES
    if present != expected:
        extra = ", ".join(sorted(present - expected)) or "none"
        missing = ", ".join(sorted(expected - present)) or "none"
        return (
            f"{modules} does not hold exactly the locked packages "
            f"(extra: {extra}; missing: {missing})"
        )
    try:
        digest = tree_digest(tree)
    except (OSError, ValueError) as exc:
        return f"its files cannot be read as the pinned tree ({exc})"
    if digest != TREE_SHA256:
        return (
            f"its files hash to {digest}, not to the pinned tree digest "
            f"{TREE_SHA256} ({TREE_FILE_COUNT} files)"
        )
    return None


def _cli_in_tree() -> str:
    """The command script retire's ``bin`` names, relative to the bin directory."""
    script = LOCKED_PACKAGES[f"node_modules/{RETIRE_NPM_PACKAGE}"]["bin"]["retire"]
    return f"{TREE_DIRECTORY}/node_modules/{RETIRE_NPM_PACKAGE}/{script}"


def _command_name(target_platform: str) -> str:
    return "retire.cmd" if target_platform == "windows" else "retire"


def windows_shim() -> str:
    """``retire.cmd``: run ``node`` on the tree's command script, passing every argument.

    ``%~dp0`` is the directory the file is in, with its trailing separator, so the
    shim finds the tree beside it wherever the bin directory is.
    """
    target = _cli_in_tree().replace("/", "\\")
    return f'@ECHO off\r\nnode "%~dp0{target}" %*\r\n'


def place_command(bin_dir: Path, target_platform: str) -> Path:
    """Put ``retire`` (``retire.cmd`` on Windows) in ``bin_dir``, pointing into the tree.

    Left alone when it already says what it should. Otherwise written beside its final
    name and renamed over it, so a scan never finds half a command.
    """
    command = bin_dir / _command_name(target_platform)
    staged = bin_dir / f".{command.name}.ash-install-{os.getpid()}"
    if staged.is_symlink() or staged.exists():
        staged.unlink()
    if target_platform == "windows":
        text = windows_shim()
        if (
            command.is_file()
            and not command.is_symlink()
            and command.read_bytes() == text.encode("utf-8")
        ):
            return command
        staged.write_bytes(text.encode("utf-8"))
    else:
        target = _cli_in_tree()
        if command.is_symlink() and os.readlink(command) == target:
            return command
        os.symlink(target, staged)
    os.replace(staged, command)
    return command


def _replace_tree(staged: Path, tree: Path) -> None:
    """Rename ``staged`` to ``tree``, moving an earlier tree aside and removing it.

    A link or a file at ``tree`` is removed itself, never followed.
    """
    if tree.is_symlink() or tree.is_file():
        tree.unlink()
    retired: Optional[Path] = None
    if tree.exists():
        retired = Path(
            tempfile.mkdtemp(prefix=f".{TREE_DIRECTORY}-old-", dir=tree.parent)
        )
        os.replace(tree, retired / "tree")
    os.replace(staged, tree)
    if retired is not None:
        shutil.rmtree(retired, ignore_errors=True)


def _npm_ci(npm: str, project: Path) -> None:
    """Run ``npm ci`` in ``project`` with a cache of its own, removed afterwards.

    The cache, and the debug log npm keeps in it, stay out of the user's npm cache and
    out of an image layer.
    """
    with tempfile.TemporaryDirectory(prefix="ash-retire-js-npm-cache-") as cache:
        try:
            result = subprocess.run(  # nosec B603 - npm from PATH, fixed arguments
                [npm, *_NPM_CI_ARGS, f"--cache={cache}"],
                cwd=project,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=_NPM_TIMEOUT_SECONDS,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ToolNotProvisionableError(
                f"npm ci did not finish in {_NPM_TIMEOUT_SECONDS} seconds; "
                "nothing was installed"
            ) from exc
    if result.returncode != 0:
        tail = (result.stderr or result.stdout).strip()[-2000:]
        raise ToolNotProvisionableError(
            f"npm ci exited {result.returncode} installing retire {RETIRE_VERSION}'s "
            f"locked tree; nothing was installed. npm said: {tail}"
        )


def install_retire(
    target_platform: str, arch: str, destination: Optional[Path] = None
) -> Path:
    """Install the locked tree under ``destination`` and the ``retire`` command beside it.

    A tree already in place that hashes to ``TREE_SHA256`` is kept, and only the
    command is checked. Otherwise ``npm ci`` installs the lockfile into a staging
    directory beside the tree, the staged tree must hash to ``TREE_SHA256``, and only
    then does it replace the old one.
    """
    from automated_security_helper.utils import download_utils as du
    from automated_security_helper.utils.log import ASH_LOGGER
    from automated_security_helper.utils.subprocess_utils import find_executable

    if (target_platform, arch) not in INSTALL_PLATFORMS:
        available = ", ".join(f"{p}/{a}" for p, a in INSTALL_PLATFORMS)
        raise ToolNotProvisionableError(
            f"ASH's retire.js install has no entry for {target_platform}/{arch}. "
            f"Available: {available}"
        )
    bin_dir = Path(destination) if destination is not None else du.current_bin_path()
    if bin_dir is None:
        raise RuntimeError(du.NO_BIN_DIRECTORY)
    bin_dir.mkdir(parents=True, exist_ok=True)
    tree = bin_dir / TREE_DIRECTORY

    problem = tree_problem(tree)
    if problem is None:
        command = place_command(bin_dir, target_platform)
        ASH_LOGGER.info(f"retire {RETIRE_VERSION} already installed at {tree}")
        return command
    ASH_LOGGER.debug(f"Installing retire {RETIRE_VERSION} into {tree}: {problem}")
    if du.is_offline_mode():
        raise ToolNotProvisionableError(
            f"retire {RETIRE_VERSION} is not installed and ASH is offline "
            "(ASH_OFFLINE), so nothing is downloaded. Install it while online."
        )
    npm = find_executable("npm")
    if npm is None:
        raise ToolNotProvisionableError(
            f"retire {RETIRE_VERSION} needs npm to install, and npm is not on PATH. "
            "Install Node.js 20.19+ or 22.12+ with npm, then install again."
        )

    staged = Path(tempfile.mkdtemp(prefix=f".{TREE_DIRECTORY}-staging-", dir=bin_dir))
    try:
        # mkdtemp makes the directory 0700; the tree is read by whoever runs a scan.
        os.chmod(staged, 0o755)
        (staged / "package.json").write_text(_json_text(PACKAGE_JSON), encoding="utf-8")
        (staged / "package-lock.json").write_text(
            _json_text(lockfile()), encoding="utf-8"
        )
        _npm_ci(npm, staged)
        problem = tree_problem(staged)
        if problem is not None:
            raise ToolNotProvisionableError(
                f"npm ci installed a tree that is not the one ASH pins: {problem}. "
                "Nothing was installed."
            )
        _replace_tree(staged, tree)
    finally:
        if staged.exists():
            shutil.rmtree(staged, ignore_errors=True)
    command = place_command(bin_dir, target_platform)
    ASH_LOGGER.info(f"Installed retire {RETIRE_VERSION} to {tree} ({command})")
    return command


_INSTALL_SCRIPT = (
    "import sys; from pathlib import Path; "
    "from automated_security_helper.plugin_modules.ash_retire_js_plugins."
    "retire_js_install import install_retire; "
    "install_retire(sys.argv[1], sys.argv[2], Path(sys.argv[3]))"
)


def retire_install_commands() -> Dict[str, Dict[str, List[CustomCommand]]]:
    """The ``custom_install_commands`` table: one entry per platform/arch.

    Never raises. With no usable bin directory every entry is a command that refuses
    with the reason, so constructing the scanner during a scan cannot fail.
    """
    from automated_security_helper.utils import download_utils as du

    bin_dir = du.current_bin_path()
    table: Dict[str, Dict[str, List[CustomCommand]]] = {}
    for target_platform, arch in INSTALL_PLATFORMS:
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


__all__ = [
    "INSTALL_PLATFORMS",
    "LOCKED_PACKAGES",
    "PACKAGE_JSON",
    "RETIRE_NPM_PACKAGE",
    "RETIRE_VERSION",
    "TREE_DIRECTORY",
    "TREE_FILE_COUNT",
    "TREE_SHA256",
    "install_retire",
    "lockfile",
    "place_command",
    "retire_install_commands",
    "tree_digest",
    "tree_problem",
    "windows_shim",
]
