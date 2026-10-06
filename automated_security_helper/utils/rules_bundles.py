# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Install and verify pinned rules bundles: archives of rule files, not binaries.

Why this module exists
----------------------
The cfn-guard scanner evaluates templates against the AWS Guard Rules Registry, which
ships as one zip of ``.guard`` files. ``download_utils.install_pinned_tool`` installs
exactly one executable out of an archive and refuses anything else, so a rules bundle
needs its own installer. The pin itself (url, version, SHA256) lives with the binary pins
in ``utils/tool_downloads.py`` so that file stays the one place ASH's external artifacts
are pinned.

What an installed bundle is
---------------------------
``<rules root>/<bundle>-<version>/`` holding the bundle's rule files, each extracted to
its basename, plus ``MANIFEST_NAME``: a JSON record of the pinned url, the archive's
SHA256 and the SHA256 of every file extracted. The rules root is
``$ASH_CFN_GUARD_RULES_DIR`` when set (the container image sets it), otherwise
``<ASH_BIN_PATH>/../share/cfn-guard-rules``, so ``ash dependencies install --bin-path X``
keeps the rules beside the binaries it installed.

The manifest is checked twice. The installer skips a bundle whose manifest names the
current pin and whose files still hash to what it records, so a second
``ash dependencies install`` (the image runs it twice, once per stage) is a no-op and
does not need write access to a directory root created. The scanner checks it again
before every scan, for the rule files it is about to load, so a partial or corrupted
install is reported as MISSING with a reason instead of evaluating a template against
whatever is left.

Extraction rules, and why
-------------------------
Only regular files directly inside ``RulesBundle.member_dir`` whose names end in
``member_suffix`` are extracted, and each is written to its basename under a staging
directory the installer created. No path from inside the archive is ever used as a
destination, so an entry named ``../../x`` or ``/etc/x`` cannot escape. Basenames must
match ``_SAFE_MEMBER_NAME``, duplicates are refused, and each member and the total are
size-capped so a hostile archive cannot fill the disk. The registry's zip carries
``__MACOSX/`` resource-fork entries; they fail the directory test and are skipped.

The finished directory is moved into place with one rename, so a reader never sees a
half-extracted bundle under the final name.

Known limitation, stated plainly
--------------------------------
The manifest sits beside the files it describes. It detects truncation, a partial
extraction and accidental edits. It does not stop someone who can write the bundle
directory from replacing a rule file and rewriting the manifest to match; that is
prevented by who can write the directory, not by this check. The container image
installs the bundle as root with mode 0755/0644 for that reason, and the per-file
digests are not pinned in the repository because the archive digest already pins the
same bytes at install time.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

from automated_security_helper.core.exceptions import ToolDownloadIntegrityError
from automated_security_helper.utils.log import ASH_LOGGER

#: The manifest file written into an installed bundle directory.
MANIFEST_NAME = ".ash-rules-manifest.json"

#: Environment variable naming the directory rules bundles are installed under.
RULES_DIR_ENV = "ASH_CFN_GUARD_RULES_DIR"

# Basenames a bundle member may have. The registry's files are all of this shape
# (letters, digits, '.', '_' and '-'); anything else is refused rather than written.
_SAFE_MEMBER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

# Size caps. The registry's largest file is ~120KB and the whole archive extracts to
# ~4MB, so these are two orders of magnitude of headroom and still bound a zip bomb.
_MAX_MEMBER_BYTES = 16 * 1024 * 1024
_MAX_TOTAL_BYTES = 128 * 1024 * 1024


class RulesBundleUnavailable(Exception):
    """The installed bundle is absent, incomplete, or not the pinned one.

    The message is written to be shown to an operator as the reason a scanner is
    MISSING, so it says what was checked and how to fix it.
    """


@dataclass(frozen=True)
class InstalledBundle:
    """A bundle directory whose manifest matched the pin."""

    directory: Path
    files: Dict[str, str]


def rules_root() -> Path:
    """Where rules bundles are installed, resolved at call time.

    At call time for the reason ``download_utils.current_bin_path`` gives:
    ``ash dependencies install --bin-path`` exports ``ASH_BIN_PATH`` after the
    constants module was imported.
    """
    from_env = os.environ.get(RULES_DIR_ENV)
    if from_env:
        return Path(from_env)
    from automated_security_helper.utils.download_utils import current_bin_path

    return current_bin_path().parent.joinpath("share", "cfn-guard-rules")


def bundle_dir_name(bundle) -> str:
    """The directory name one pinned bundle installs as."""
    return f"{bundle.name}-{bundle.version}"


def _sha256(path: Path) -> str:
    from automated_security_helper.utils.download_utils import sha256_file

    return sha256_file(path)


def _member_basename(
    info: zipfile.ZipInfo, member_dir: str, suffix: str
) -> Optional[str]:
    """The basename to extract ``info`` to, or None when it is not a bundle member."""
    if info.is_dir():
        return None
    parts = info.filename.replace("\\", "/").split("/")
    if len(parts) != 2 or parts[0] != member_dir:
        return None
    name = parts[1]
    if not name.endswith(suffix):
        return None
    if not _SAFE_MEMBER_NAME.match(name):
        raise ToolDownloadIntegrityError(
            f"bundle member {info.filename!r} has a name ASH will not write; refusing "
            "the archive"
        )
    return name


def extract_bundle(archive: Path, bundle, staging: Path) -> Dict[str, str]:
    """Extract ``bundle``'s rule files from ``archive`` into ``staging``.

    Returns the basename -> SHA256 map of what was written.

    Raises:
        ToolDownloadIntegrityError: the archive is unreadable, holds no members,
            holds two members with one name, or exceeds a size cap.
    """
    try:
        bundle_zip = zipfile.ZipFile(archive)
    except (zipfile.BadZipFile, OSError) as exc:
        raise ToolDownloadIntegrityError(
            f"{archive.name} is not a readable zip archive ({exc}); refusing to "
            "install from it"
        ) from exc

    written: Dict[str, str] = {}
    total = 0
    with bundle_zip:
        for info in bundle_zip.infolist():
            name = _member_basename(info, bundle.member_dir, bundle.member_suffix)
            if name is None:
                continue
            if name in written:
                raise ToolDownloadIntegrityError(
                    f"{archive.name} holds two members named {name}; refusing to guess "
                    "which one is the rule file"
                )
            if info.file_size > _MAX_MEMBER_BYTES:
                raise ToolDownloadIntegrityError(
                    f"{archive.name}: {name} declares {info.file_size} bytes, over the "
                    f"{_MAX_MEMBER_BYTES}-byte cap for one rule file"
                )
            target = staging.joinpath(name)
            size = 0
            digest = hashlib.sha256()
            # O_EXCL: the staging directory is ours and fresh, so an existing name
            # here means something raced us, and that is refused. O_BINARY because
            # os.open on Windows otherwise opens in text mode and rewrites newlines,
            # which would make every file disagree with the digest recorded below.
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
            fd = os.open(target, flags, 0o644)
            with bundle_zip.open(info) as source, os.fdopen(fd, "wb") as handle:
                for chunk in iter(lambda: source.read(1024 * 256), b""):
                    size += len(chunk)
                    total += len(chunk)
                    # Checked on the bytes read, not only on the declared size, which
                    # an archive can understate.
                    if size > _MAX_MEMBER_BYTES or total > _MAX_TOTAL_BYTES:
                        raise ToolDownloadIntegrityError(
                            f"{archive.name} expands past ASH's size cap; refusing it"
                        )
                    digest.update(chunk)
                    handle.write(chunk)
            written[name] = digest.hexdigest()

    if not written:
        raise ToolDownloadIntegrityError(
            f"{archive.name} holds no {bundle.member_suffix} files under "
            f"{bundle.member_dir}/; the pin and the archive layout disagree"
        )
    return written


def _manifest_for(bundle, files: Dict[str, str]) -> dict:
    return {
        "bundle": bundle.name,
        "version": bundle.version,
        "url": bundle.url,
        "sha256": bundle.sha256.lower(),
        "files": dict(sorted(files.items())),
    }


def verify_installed_bundle(
    bundle, root: Optional[Path] = None, files: Optional[list] = None
) -> InstalledBundle:
    """Check an installed bundle against its pin, and ``files`` against the manifest.

    ``files`` names the rule files the caller is about to use; each must be listed in
    the manifest and still hash to the digest recorded there. When ``files`` is None
    every file in the manifest is checked, which is what the installer does before it
    decides to skip.

    Raises:
        RulesBundleUnavailable: with a reason an operator can act on.
    """
    root = rules_root() if root is None else Path(root)
    directory = root.joinpath(bundle_dir_name(bundle))
    reinstall = (
        "Run `ash dependencies install --tool cfn-guard` with network access, or use "
        "the ASH container image, which ships it."
    )
    manifest_path = directory.joinpath(MANIFEST_NAME)
    if not manifest_path.is_file():
        raise RulesBundleUnavailable(
            f"the {bundle.name} {bundle.version} rules are not installed: "
            f"{manifest_path} does not exist. {reinstall}"
        )
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RulesBundleUnavailable(
            f"the {bundle.name} rules manifest at {manifest_path} is unreadable "
            f"({exc}). {reinstall}"
        ) from exc
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), dict):
        raise RulesBundleUnavailable(
            f"the {bundle.name} rules manifest at {manifest_path} is malformed. "
            f"{reinstall}"
        )
    if (
        manifest.get("url") != bundle.url
        or str(manifest.get("sha256", "")).lower() != bundle.sha256.lower()
    ):
        raise RulesBundleUnavailable(
            f"the rules installed at {directory} are not the pinned {bundle.name} "
            f"{bundle.version} (manifest names {manifest.get('url')!r}). {reinstall}"
        )
    recorded: Dict[str, str] = {str(k): str(v) for k, v in manifest["files"].items()}
    to_check = recorded if files is None else {}
    if files is not None:
        for name in files:
            if name not in recorded:
                raise RulesBundleUnavailable(
                    f"{name} is not part of the installed {bundle.name} "
                    f"{bundle.version} rules. Available: "
                    f"{', '.join(sorted(recorded))}"
                )
            to_check[name] = recorded[name]
    for name, expected in to_check.items():
        path = directory.joinpath(name)
        if not path.is_file():
            raise RulesBundleUnavailable(
                f"{path} is listed in the {bundle.name} rules manifest but is missing. "
                f"{reinstall}"
            )
        try:
            actual = _sha256(path)
        except OSError as exc:
            raise RulesBundleUnavailable(
                f"{path} could not be read ({exc}). {reinstall}"
            ) from exc
        if actual != expected:
            raise RulesBundleUnavailable(
                f"{path} no longer matches the digest recorded when the "
                f"{bundle.name} rules were installed. {reinstall}"
            )
    return InstalledBundle(directory=directory, files=recorded)


def install_rules_bundle(
    name: str, root: Optional[Path] = None, force: bool = False
) -> Path:
    """Download, verify and install the pinned rules bundle ``name``.

    Returns the installed bundle directory.

    Raises:
        ToolNotProvisionableError: ``name`` is not a pinned bundle.
        ToolDownloadIntegrityError: the download does not match its pinned digest,
            or the archive is unusable.
    """
    from automated_security_helper.utils.download_utils import download_file
    from automated_security_helper.utils.tool_downloads import get_rules_bundle

    bundle = get_rules_bundle(name)
    root = rules_root() if root is None else Path(root)
    final = root.joinpath(bundle_dir_name(bundle))

    if not force:
        try:
            verify_installed_bundle(bundle, root)
            ASH_LOGGER.info(
                f"{bundle.name} {bundle.version} rules already installed at {final}, "
                "skipping download"
            )
            return final
        except RulesBundleUnavailable as reason:
            ASH_LOGGER.debug(f"Installing {bundle.name}: {reason}")

    root.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".ash-rules-staging-", dir=root))
    try:
        with tempfile.TemporaryDirectory(prefix="ash-rules-download-") as download_dir:
            archive = download_file(
                bundle.url,
                Path(download_dir),
                rename_to=bundle.url.rsplit("/", 1)[-1],
                expected_sha256=bundle.sha256,
            )
            files = extract_bundle(archive, bundle, staging)
        staging.joinpath(MANIFEST_NAME).write_text(
            json.dumps(_manifest_for(bundle, files), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        # A directory: group/other need read and search (x) to load the rules, and
        # nothing beyond the owner may write. B103 flags any group x bit.
        os.chmod(staging, 0o755)  # nosec B103 - read-only rules directory
        for child in staging.iterdir():
            os.chmod(child, 0o644)
        if final.exists() or final.is_symlink():
            # Moved aside, not deleted in place, so the final name is never a
            # half-removed directory. A symlink is unlinked rather than followed.
            aside = Path(tempfile.mkdtemp(prefix=".ash-rules-old-", dir=root))
            os.replace(final, aside.joinpath("old"))
            shutil.rmtree(aside, ignore_errors=True)
        os.replace(staging, final)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    ASH_LOGGER.info(f"Installed {bundle.name} {bundle.version} rules to {final}")
    return final


def create_rules_bundle_install_command(name: str):
    """The CustomCommand that installs rules bundle ``name`` in a subprocess.

    The same execution model as ``create_pinned_tool_install_command``: plugins
    declare commands and ``ash dependencies install`` runs and counts them.
    """
    import sys

    from automated_security_helper.base.plugin_base import CustomCommand

    script = (
        "import sys; "
        "from automated_security_helper.utils.rules_bundles import install_rules_bundle; "
        "install_rules_bundle(sys.argv[1])"
    )
    return CustomCommand(args=[sys.executable, "-c", script, name], shell=False)
