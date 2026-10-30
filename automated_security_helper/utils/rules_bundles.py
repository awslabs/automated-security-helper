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
its basename. The rules root is ``$ASH_CFN_GUARD_RULES_DIR`` when set (the container
image sets it), otherwise ``<ASH_BIN_PATH>/../share/cfn-guard-rules``, so
``ash dependencies install --bin-path X`` keeps the rules beside the binaries it
installed. With neither the variable nor a bin directory (``ASH_BIN_PATH`` unset and
no usable home for ``~/.ash/bin``) there is no rules root, and ``rules_root`` raises
``RulesBundleUnavailable`` saying so.

The directory also holds ``MANIFEST_NAME``, a JSON record of the pinned url, the
archive's SHA256 and the SHA256 of every file extracted. It is a record: the image's
license check reads the installed version from it, and a person can read what was
installed. No check reads it to decide whether the rules may be used.

What is checked, and when
-------------------------
``RulesBundle.contents_sha256`` in ``utils/tool_downloads.py`` pins what the archive
extracts to: the SHA256 of the sorted ``"<basename>\\t<sha256>\\n"`` lines of every
rule file (``contents_digest``). The archive's own SHA256 pins the bytes downloaded;
this pins the files the extraction rules below select from them, which is what
cfn-guard reads.

An installed bundle's rule files are every entry in its directory whose name ends in
``member_suffix``. Each must be a regular file with a name the installer would write,
and together they must give the pinned digest, so a rule file edited, added, removed
or renamed fails the check. Any other file there, the manifest among them, is not part
of the bundle and is not read.

The check is made in three places, each against the pin and nothing stored beside the
files:

* by the installer, on its own extraction before the final rename, so a changed
  archive layout cannot install contents nobody pinned;
* by the installer before it skips a bundle that is already in place, so a second
  ``ash dependencies install`` (the image runs it twice, once per stage) is a no-op
  and does not need write access to a directory root created. A bundle that fails is
  downloaded and installed again; when that download fails, the installer refuses and
  says the rules there do not match the pinned contents and that network access, or
  the ASH container image, is needed;
* by the scanner before every scan, so a partial or changed install is reported as
  MISSING with a reason instead of evaluating a template against it.

The nix shell makes the installer's check as well, on every entry, through
``install-pinned-tool --rules-bundle --check``, which cannot import this module;
tests/unit/test_nix_cfn_guard_rules_reseed.py keeps the two checks giving one answer.

Every check hashes every rule file. For the registry's 50 files, about 4 MB, that
measured about 5 ms per check, and it keeps the pin one value that moves with the
archive's digest. A per-file table in ``tool_downloads.py`` would allow checking only the files
a scan selects, at the price of 50 more pinned values to keep in step.

Extraction rules, and why
-------------------------
Only regular files directly inside ``RulesBundle.member_dir`` whose names end in
``member_suffix`` are extracted, and each is written to its basename under a staging
directory the installer created. No path from inside the archive is ever used as a
destination, so an entry named ``../../x`` or ``/etc/x`` cannot escape. Basenames must
match ``_SAFE_MEMBER_NAME``, duplicates are refused, and each member and the total are
size-capped so no archive can fill the disk. The registry's zip carries
``__MACOSX/`` resource-fork entries; they fail the directory test and are skipped.

The finished directory is moved into place with one rename, so a reader never sees a
half-extracted bundle under the final name.

Known limitation, stated plainly
--------------------------------
The check reads the files when it runs. A rule file changed after the scanner checked
it and before cfn-guard reads it is not detected, so who can write the bundle
directory still matters. The container image installs the bundle as root with mode
0755/0644 for that reason, and checks at build time that no other user can change it
or any directory above it.
"""

from __future__ import annotations

import contextlib
import hashlib
import http.client
import json
import os
import re
import shutil
import socket
import ssl
import tempfile
import urllib.error
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Mapping, Optional, Tuple

from automated_security_helper.core.exceptions import ToolDownloadIntegrityError
from automated_security_helper.utils.log import ASH_LOGGER

if TYPE_CHECKING:
    from automated_security_helper.base.plugin_base import CustomCommand
    from automated_security_helper.utils.tool_downloads import RulesBundle

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
    """The installed bundle is absent, incomplete, or not the pinned one, or ASH has
    no rules directory to look for it in (``rules_root``).

    The message is written to be shown to an operator as the reason a scanner is
    MISSING, so it says what was checked and how to fix it.
    """


@dataclass(frozen=True)
class InstalledBundle:
    """A bundle directory whose rule files matched the pinned contents.

    ``files`` maps each rule file's basename to its SHA256.
    """

    directory: Path
    files: Dict[str, str]


def rules_root() -> Path:
    """Where rules bundles are installed, resolved at call time.

    At call time for the reason ``download_utils.current_bin_path`` gives:
    ``ash dependencies install --bin-path`` exports ``ASH_BIN_PATH`` after the
    constants module was imported.

    Raises:
        RulesBundleUnavailable: ``$ASH_CFN_GUARD_RULES_DIR`` is not set and
            ``current_bin_path`` has no directory (``ASH_BIN_PATH`` unset and no
            usable home for ``~/.ash/bin``), so there is nothing to put ``share``
            beside. The tool installs refuse for the same reason, with the same
            text (``download_utils.NO_BIN_DIRECTORY``). Or
            ``$ASH_CFN_GUARD_RULES_DIR`` is set to a relative path: the install
            runs in a child whose working directory is an empty temporary one,
            cfn-guard reads the rules from the source directory, and the scan
            checks them from ASH's own, so a relative path names a different
            directory in each. A leading ``~`` is expanded first.
    """
    from_env = os.environ.get(RULES_DIR_ENV)
    if from_env:
        expanded = os.path.expanduser(from_env)
        if not os.path.isabs(expanded):
            raise RulesBundleUnavailable(
                f"{RULES_DIR_ENV} must be an absolute path: a relative one is "
                "read against the working directory of whichever process reads "
                "it (the install child's temporary directory, the scanned "
                "source directory, ASH's own), so the rules installed under it "
                "are not the ones the scan reads."
            )
        return Path(expanded)
    from automated_security_helper.utils.download_utils import (
        NO_BIN_DIRECTORY,
        current_bin_path,
    )

    bin_dir = current_bin_path()
    if bin_dir is None:
        raise RulesBundleUnavailable(
            "The cfn-guard rules directory cannot be found: "
            f"{RULES_DIR_ENV} is not set, and by default it is beside the bin "
            f"directory. {NO_BIN_DIRECTORY} Or set {RULES_DIR_ENV} to an absolute path."
        )
    return bin_dir.parent.joinpath("share", "cfn-guard-rules")


def bundle_dir_name(bundle: "RulesBundle") -> str:
    """The directory name one pinned bundle installs as."""
    return f"{bundle.name}-{bundle.version}"


def _sha256(path: Path) -> str:
    from automated_security_helper.utils.download_utils import sha256_file

    return sha256_file(path)


def contents_digest(files: Mapping[str, str]) -> str:
    """The digest ``RulesBundle.contents_sha256`` pins, for ``files``.

    ``files`` maps each rule file's basename to its SHA256. The result is the SHA256
    of one ``"<basename>\\t<sha256>\\n"`` line per file, sorted by basename. Member
    names are ASCII (``_SAFE_MEMBER_NAME``), so that order is byte order and the
    value can be reproduced with ``sha256sum`` and ``LC_ALL=C sort``.
    """
    lines = "".join(
        f"{name}\t{digest.lower()}\n" for name, digest in sorted(files.items())
    )
    return hashlib.sha256(lines.encode("utf-8")).hexdigest()


def _installed_members(
    directory: Path, suffix: str
) -> Tuple[Dict[str, str], Optional[str]]:
    """(basename -> SHA256 of each rule file in ``directory``, problem or None).

    A rule file is any entry whose name ends in ``suffix``, which covers every file
    the installer extracts. An entry of that name that is not a regular file, or
    whose name the installer would not write, is reported as the problem rather
    than hashed. Other names are not part of the bundle and are not opened.
    """
    members: Dict[str, str] = {}
    try:
        with os.scandir(directory) as listing:
            entries = sorted(listing, key=lambda entry: entry.name)
    except OSError as exc:
        return members, f"{directory} could not be read ({exc})"
    for entry in entries:
        if not entry.name.endswith(suffix):
            continue
        path = directory.joinpath(entry.name)
        if not _SAFE_MEMBER_NAME.match(entry.name):
            return members, f"{path} has a name the installer does not write"
        if not entry.is_file(follow_symlinks=False):
            return members, f"{path} is not a regular file"
        try:
            members[entry.name] = _sha256(path)
        except OSError as exc:
            return members, f"{path} could not be read ({exc})"
    return members, None


def _bundle_problem(
    bundle: "RulesBundle", directory: Path
) -> Tuple[Dict[str, str], Optional[str]]:
    """(the rule files found, why ``directory`` is not the pinned bundle or None).

    The test both the installer and the scanner make, described in the module
    docstring. It reads the rule files only; the manifest plays no part.
    """
    try:
        is_dir = directory.is_dir()
        present = is_dir or directory.exists() or directory.is_symlink()
    except OSError as exc:
        # On Python 3.10-3.13 Path.is_dir and Path.exists re-raise PermissionError
        # for a directory under an ancestor this process may not search. That is
        # a reason the bundle cannot be used, reported as one, not an exception
        # past the RulesBundleUnavailable contract of the dependency check.
        return {}, (
            f"{directory} could not be read ({exc}), so the {bundle.name} "
            f"{bundle.version} rules there cannot be checked"
        )
    if not is_dir:
        if present:
            return {}, (
                f"{directory} is not a directory, so the {bundle.name} "
                f"{bundle.version} rules are not installed there"
            )
        return {}, (
            f"the {bundle.name} {bundle.version} rules are not installed: "
            f"{directory} does not exist"
        )
    members, problem = _installed_members(directory, bundle.member_suffix)
    detail = f" ({problem})" if problem else ""
    if problem or contents_digest(members) != bundle.contents_sha256.lower():
        return members, (
            f"the rules installed at {directory} do not match the pinned contents "
            f"of {bundle.name} {bundle.version}{detail}"
        )
    return members, None


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


def extract_bundle(
    archive: Path, bundle: "RulesBundle", staging: Path
) -> Dict[str, str]:
    """Extract ``bundle``'s rule files from ``archive`` into ``staging``.

    Returns the basename -> SHA256 map of what was written.

    Raises:
        ToolDownloadIntegrityError: the archive is unreadable, holds no members,
            holds two members with one name (or two names that differ only in
            case, which one filesystem keeps apart and another does not), a
            member that cannot be read, or exceeds a size cap.
    """
    try:
        bundle_zip = zipfile.ZipFile(archive)
    except (zipfile.BadZipFile, OSError) as exc:
        raise ToolDownloadIntegrityError(
            f"{archive.name} is not a readable zip archive ({exc}); refusing to "
            "install from it"
        ) from exc

    written: Dict[str, str] = {}
    written_folded: Dict[str, str] = {}
    total = 0
    with bundle_zip:
        for info in bundle_zip.infolist():
            name = _member_basename(info, bundle.member_dir, bundle.member_suffix)
            if name is None:
                continue
            if name.lower() in written_folded:
                earlier = written_folded[name.lower()]
                raise ToolDownloadIntegrityError(
                    f"{archive.name} holds two members named {earlier} and {name}; "
                    "refusing to guess which one is the rule file"
                )
            if info.file_size > _MAX_MEMBER_BYTES:
                raise ToolDownloadIntegrityError(
                    f"{archive.name}: {name} declares {info.file_size} bytes, over the "
                    f"{_MAX_MEMBER_BYTES}-byte cap for one rule file"
                )
            target = staging.joinpath(name)
            size = 0
            digest = hashlib.sha256()
            # The member is opened BEFORE the destination: a member that cannot be
            # opened (a bad local header, an unsupported compression, an encrypted
            # entry) used to leave the destination's descriptor open, and its
            # error was not the integrity error the callers handle.
            try:
                source = bundle_zip.open(info)
            except (
                zipfile.BadZipFile,
                RuntimeError,
                NotImplementedError,
                OSError,
            ) as exc:
                raise ToolDownloadIntegrityError(
                    f"{archive.name}: {name} cannot be read from the archive ({exc}); "
                    "refusing to install from it"
                ) from exc
            with source:
                # O_EXCL: the staging directory is ours and fresh, so an existing name
                # here means something raced us, and that is refused. O_BINARY because
                # os.open on Windows otherwise opens in text mode and rewrites newlines,
                # which would make every file disagree with the digest recorded below.
                flags = (
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
                )
                try:
                    fd = os.open(target, flags, 0o644)
                except FileExistsError as exc:
                    raise ToolDownloadIntegrityError(
                        f"{archive.name}: {name} was already written into the staging "
                        "directory; refusing to guess which member is the rule file"
                    ) from exc
                with os.fdopen(fd, "wb") as handle:
                    try:
                        for chunk in iter(lambda: source.read(1024 * 256), b""):
                            size += len(chunk)
                            total += len(chunk)
                            # Checked on the bytes read, not only on the declared
                            # size, which an archive can understate.
                            if size > _MAX_MEMBER_BYTES or total > _MAX_TOTAL_BYTES:
                                raise ToolDownloadIntegrityError(
                                    f"{archive.name} expands past ASH's size cap; "
                                    "refusing it"
                                )
                            digest.update(chunk)
                            handle.write(chunk)
                    except (zipfile.BadZipFile, zlib.error, EOFError) as exc:
                        # A member whose data does not decompress or whose CRC does
                        # not match is a damaged archive, the integrity error the
                        # callers handle, not an untyped exception out of them.
                        raise ToolDownloadIntegrityError(
                            f"{archive.name}: {name} is damaged ({exc}); refusing to "
                            "install from it"
                        ) from exc
            written[name] = digest.hexdigest()
            written_folded[name.lower()] = name

    if not written:
        raise ToolDownloadIntegrityError(
            f"{archive.name} holds no {bundle.member_suffix} files under "
            f"{bundle.member_dir}/; the pin and the archive layout disagree"
        )
    return written


def _manifest_for(bundle: "RulesBundle", files: Dict[str, str]) -> Dict[str, object]:
    return {
        "bundle": bundle.name,
        "version": bundle.version,
        "url": bundle.url,
        "sha256": bundle.sha256.lower(),
        "files": dict(sorted(files.items())),
    }


def verify_installed_bundle(
    bundle: "RulesBundle",
    root: Optional[Path] = None,
    files: Optional[List[str]] = None,
) -> InstalledBundle:
    """Check an installed bundle's rule files against the pinned contents.

    Every rule file is checked whatever ``files`` holds; see the module docstring.
    ``files`` names the rule files the caller is about to use, and each must be one
    of them.

    Raises:
        RulesBundleUnavailable: with a reason an operator can act on.
    """
    root = rules_root() if root is None else Path(root)
    directory = root.joinpath(bundle_dir_name(bundle))
    members, problem = _bundle_problem(bundle, directory)
    if problem is not None:
        raise RulesBundleUnavailable(
            f"{problem}. Run `ash dependencies install --tool cfn-guard` with network "
            "access, or use the ASH container image, which ships it."
        )
    for name in files or []:
        if name not in members:
            raise RulesBundleUnavailable(
                f"{name} is not part of the installed {bundle.name} "
                f"{bundle.version} rules. Available: {', '.join(sorted(members))}"
            )
    return InstalledBundle(directory=directory, files=members)


def install_rules_bundle(
    name: str, root: Optional[Path] = None, force: bool = False
) -> Path:
    """Download, verify and install the pinned rules bundle ``name``.

    Returns the installed bundle directory.

    A bundle already in place is kept when its rule files match the pinned
    contents; otherwise the pinned archive is downloaded and installed over it.

    Raises:
        ToolNotProvisionableError: ``name`` is not a pinned bundle.
        ToolDownloadIntegrityError: the download does not match its pinned digest,
            the files extracted from it do not match the pinned contents, or the
            archive is unusable.
        RulesBundleUnavailable: the bundle needs installing and the download
            failed, or the rules root cannot be written; the rules in place, if
            any, are left as they were. Also raised before anything is created or
            downloaded when ``root`` is not given and ``rules_root`` has no
            directory.

    Two installs of one bundle at a time (two ``ash dependencies install``
    processes, or two scans installing on demand) are serialized on a lock file
    in the rules root; the second finds the bundle in place and skips. Replacing
    a bundle still moves the old directory aside before the new one is renamed
    in, so a scan reading at that instant can find no bundle under the final
    name; a swap with no such instant needs a different layout (a versioned
    directory behind a link) and is not attempted here.
    """
    from automated_security_helper.utils.download_utils import download_file
    from automated_security_helper.utils.file_lock import exclusive_lock
    from automated_security_helper.utils.tool_downloads import get_rules_bundle

    bundle = get_rules_bundle(name)
    root = rules_root() if root is None else Path(root)
    final = root.joinpath(bundle_dir_name(bundle))

    problem = f"reinstalling the {bundle.name} {bundle.version} rules at {final}"
    if not force:
        _, found = _bundle_problem(bundle, final)
        if found is None:
            ASH_LOGGER.info(
                f"{bundle.name} {bundle.version} rules already installed at {final}, "
                "skipping download"
            )
            return final
        ASH_LOGGER.debug(f"Installing {bundle.name}: {found}")
        problem = found

    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        # The documented refusal, not a raw PermissionError: the reason a
        # reinstall was attempted rides with it, so an operator reading the
        # error knows both what was wrong and why nothing could be done.
        raise RulesBundleUnavailable(
            f"{problem}, and the rules directory {root} could not be created "
            f"({exc}). Make it writable, or set {RULES_DIR_ENV} to a directory "
            "ASH can write."
        ) from exc

    lock_path = root.joinpath(".ash-rules-install.lock")
    with contextlib.ExitStack() as held:
        try:
            held.enter_context(exclusive_lock(lock_path))
        except TimeoutError as exc:
            raise RulesBundleUnavailable(
                f"{problem}, and another ASH process held the install lock "
                f"{lock_path} for too long ({exc}). Wait for that install to "
                "finish, then run the install again."
            ) from exc
        except OSError as exc:
            # The lock is a file in the rules root. A root that exists but is
            # not writable (the image's root-owned directory, run as another
            # user) passes the mkdir above and fails here, so this is the same
            # documented refusal, not a raw PermissionError out of the lock.
            raise RulesBundleUnavailable(
                f"{problem}, and the install lock {lock_path} could not be opened "
                f"({exc}). Make the rules directory writable, or set "
                f"{RULES_DIR_ENV} to a directory ASH can write."
            ) from exc
        if not force:
            # Another install may have finished while this one waited for the
            # lock: the check is made again under it, so two concurrent installs
            # never race on the final rename and the first one's work is kept.
            _, found = _bundle_problem(bundle, final)
            if found is None:
                ASH_LOGGER.info(
                    f"{bundle.name} {bundle.version} rules already installed at "
                    f"{final}, skipping download"
                )
                return final
        return _install_locked(bundle, root, final, problem, download_file)


def _install_locked(
    bundle: "RulesBundle", root: Path, final: Path, problem: str, download_file
) -> Path:
    """The download, extraction and rename of ``install_rules_bundle``, under its lock."""
    try:
        staging = Path(tempfile.mkdtemp(prefix=".ash-rules-staging-", dir=root))
    except OSError as exc:
        raise RulesBundleUnavailable(
            f"{problem}, and nothing can be written under the rules directory "
            f"{root} ({exc}). Make it writable, or set {RULES_DIR_ENV} to a "
            "directory ASH can write."
        ) from exc
    try:
        with tempfile.TemporaryDirectory(prefix="ash-rules-download-") as download_dir:
            try:
                archive = download_file(
                    bundle.url,
                    Path(download_dir),
                    rename_to=bundle.url.rsplit("/", 1)[-1],
                    expected_sha256=bundle.sha256,
                    # A rules bundle is data, not a program to run.
                    mode=0o644,
                )
            except (OSError, http.client.HTTPException) as exc:
                # URLError, HTTPError, timeouts and dropped connections, once
                # download_file's retries are spent. A digest mismatch is a
                # ToolDownloadIntegrityError and is not caught here. A local
                # OSError (a full disk, a download directory that cannot be
                # written) is not a network failure, and is worded as what it is.
                if _is_network_failure(exc):
                    remedy = (
                        "Installing the pinned rules needs network access, or use "
                        "the ASH container image, which ships them."
                    )
                else:
                    remedy = (
                        "The failure is local, not the network: check the free "
                        "space and the permissions of the temporary directory."
                    )
                raise RulesBundleUnavailable(
                    f"{problem}, and the pinned archive {bundle.url} could not be "
                    f"downloaded ({exc}). {remedy}"
                ) from exc
            files = extract_bundle(archive, bundle, staging)
        actual = contents_digest(files)
        if actual != bundle.contents_sha256.lower():
            # The archive matched its pin, so the extraction rules selected other
            # files than the ones pinned: a changed layout, or a pin not updated
            # with the archive's.
            raise ToolDownloadIntegrityError(
                f"the {len(files)} files extracted from {bundle.url} do not match the "
                f"pinned contents of {bundle.name} {bundle.version}: expected "
                f"{bundle.contents_sha256.lower()}, got {actual}. Refusing to install."
            )
        staging.joinpath(MANIFEST_NAME).write_text(
            json.dumps(_manifest_for(bundle, files), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        # A directory: group/other need read and search (x) to load the rules, and
        # nothing beyond the owner may write. B103 flags any group x bit.
        os.chmod(staging, 0o755)  # nosec B103 - read-only rules directory
        for child in staging.iterdir():
            os.chmod(child, 0o644)
        aside: Optional[Path] = None
        if final.exists() or final.is_symlink():
            # Moved aside, not deleted in place, so the final name is never a
            # half-removed directory. A symlink is unlinked rather than followed.
            aside = Path(tempfile.mkdtemp(prefix=".ash-rules-old-", dir=root))
            try:
                os.replace(final, aside.joinpath("old"))
            except OSError as exc:
                # The old bundle stays where it was; the empty directory made
                # for it is not left behind in the rules root. The documented
                # refusal, as for every other local failure of the install: a
                # rule file a scan holds open (Windows refuses the rename), or
                # a root this user may not write into.
                shutil.rmtree(aside, ignore_errors=True)
                raise RulesBundleUnavailable(
                    f"{problem}, and the rules in place at {final} could not be "
                    f"moved aside ({exc}). Make sure no scan is reading them and "
                    f"the rules directory is writable, or set {RULES_DIR_ENV} to "
                    "a directory ASH can write."
                ) from exc
        try:
            os.replace(staging, final)
        except OSError as exc:
            # The rules that were in place go back before the refusal, so a
            # failed rename leaves the bundle as it was, as the docstring
            # promises, not a rules root with no bundle under the final name.
            # The aside is kept until the new bundle is in place for this.
            restored = aside is None
            if aside is not None:
                try:
                    os.replace(aside.joinpath("old"), final)
                    restored = True
                except OSError:
                    restored = False
            if aside is not None and restored:
                shutil.rmtree(aside, ignore_errors=True)
            where = (
                ""
                if aside is None
                else (
                    " The rules that were in place were moved back."
                    if restored
                    else " The rules that were in place could not be moved back; "
                    f"they are at {aside.joinpath('old')}."
                )
            )
            raise RulesBundleUnavailable(
                f"{problem}, and the downloaded rules could not be moved into "
                f"place at {final} ({exc}).{where} Make the rules directory "
                f"writable, or set {RULES_DIR_ENV} to a directory ASH can write."
            ) from exc
        if aside is not None:
            shutil.rmtree(aside, ignore_errors=True)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    ASH_LOGGER.info(f"Installed {bundle.name} {bundle.version} rules to {final}")
    return final


def _is_network_failure(error: BaseException) -> bool:
    """Whether ``error`` from the download is the network's, not this host's.

    urllib's URLError and HTTPError, an HTTP protocol error, a connection reset
    or refused, a socket timeout, a TLS failure while the body is read (an
    ``ssl.SSLEOFError`` from a proxy that drops the connection) and a name that
    does not resolve are the network's. Any other OSError (a PermissionError or
    a full disk writing the archive) is local, and telling the operator to find
    network access for it sends them the wrong way.
    """
    return isinstance(
        error,
        (
            urllib.error.URLError,
            http.client.HTTPException,
            ConnectionError,
            TimeoutError,
            ssl.SSLError,
            socket.gaierror,
            socket.herror,
        ),
    )


def create_rules_bundle_install_command(name: str) -> "CustomCommand":
    """The CustomCommand that installs rules bundle ``name`` in a subprocess.

    The same execution model as ``create_pinned_tool_install_command``: plugins
    declare commands and ``ash dependencies install`` runs and counts them. Run
    only there, through ``cli.dependencies.run_command``, which starts this
    ``-c`` argv through ``utils.python_child`` (``-P`` and an empty start
    directory), so the script imports nothing from the directory ASH runs in.
    Spawn it any other way and it would.
    """
    import sys

    from automated_security_helper.base.plugin_base import CustomCommand

    script = (
        "import sys; "
        "from automated_security_helper.utils.rules_bundles import install_rules_bundle; "
        "install_rules_bundle(sys.argv[1])"
    )
    return CustomCommand(args=[sys.executable, "-c", script, name], shell=False)
