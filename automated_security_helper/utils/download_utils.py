"""Utility functions for downloading and installing binaries."""

import hashlib
import json
import os
import platform
import shutil
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Literal, Optional
import urllib.request

from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.subprocess_utils import run_command
from automated_security_helper.base.plugin_base import CustomCommand
from automated_security_helper.core.constants import ASH_BIN_PATH
from automated_security_helper.core.exceptions import ToolDownloadIntegrityError

# Name of the directory holding install receipts. See receipt_root() for why it is
# NOT under the bin directory a tool is installed into: a receipt records the digest
# an installed binary is checked against, so it is a trust anchor, and the bin
# directory is world-writable in ASH's own image.
RECEIPT_DIR_NAME = "install-receipts"

# Read the download in chunks rather than into one buffer. syft's linux asset is
# ~30MB and trivy's is larger; holding a whole release archive in memory to hash
# it is avoidable.
_HASH_CHUNK_BYTES = 1024 * 1024


def sha256_file(file_path: Path) -> str:
    """Return the lowercase hex SHA256 of a file's contents."""
    digest = hashlib.sha256()
    with open(file_path, "rb") as handle:
        for chunk in iter(lambda: handle.read(_HASH_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _digest_or_none(file_path: Path) -> Optional[str]:
    """Hash a just-installed file, or return None if it cannot be read.

    Used only to fill the ``installed_sha256`` field of a receipt. Hashing a file
    that is already in place must not be able to fail the install that put it there,
    and the degradation is in the safe direction: a receipt with no
    ``installed_sha256`` is treated by ``_already_installed`` as not installed, so
    the next run re-downloads rather than trusting bytes it cannot check.
    """
    try:
        return sha256_file(file_path)
    except OSError as e:
        ASH_LOGGER.warning(
            f"Could not hash {file_path} after installing it ({e}); the next install "
            "will re-download rather than trust it"
        )
        return None


def verify_sha256(file_path: Path, expected_sha256: str, source: str) -> str:
    """Verify a file against an expected SHA256, raising if it does not match.

    Args:
        file_path: The file to hash
        expected_sha256: The pinned digest, hex, case-insensitive
        source: What produced the file, used in the error message (usually the URL)

    Returns:
        The actual digest, when it matches.

    Raises:
        ToolDownloadIntegrityError: on any mismatch. Never downgraded to a
            warning -- a digest that is compared and then ignored is the same as
            no digest at all.
    """
    actual = sha256_file(file_path)
    if actual.lower() != expected_sha256.lower():
        raise ToolDownloadIntegrityError(
            f"SHA256 mismatch for {source}: expected {expected_sha256.lower()}, "
            f"got {actual}. Refusing to install."
        )
    return actual


def download_file(
    url: str,
    destination: Path,
    rename_to: Optional[str] = None,
    expected_sha256: Optional[str] = None,
) -> Path:
    """Download a file from a URL to the specified destination.

    Args:
        url: The URL to download from
        destination: The directory to save the file to
        rename_to: Optional name to rename the file to
        expected_sha256: Pinned SHA256 to verify the download against. Verified
            while the bytes are still in the temporary file, so a mismatch leaves
            nothing at the destination. When omitted, the download is unverified
            and says so in the log rather than passing silently.

    Returns:
        Path to the downloaded file

    Raises:
        ToolDownloadIntegrityError: if expected_sha256 is given and does not match
    """
    # Create the destination directory if it doesn't exist
    destination.mkdir(parents=True, exist_ok=True)

    # Get the filename from the URL if rename_to is not specified
    if rename_to is None:
        rename_to = url.split("/")[-1]

    # Download to a temporary file first
    if not url.startswith("https://"):
        raise ValueError(f"Invalid URL: {url}")

    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        ASH_LOGGER.info(f"Downloading {url} to {temp_file.name}")
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        with urllib.request.urlopen(url) as response:  # nosec B310 - This url is evaluated for https scheme a few lines above
            shutil.copyfileobj(response, temp_file)

    # Verify before the bytes are allowed anywhere near the install location. On a
    # mismatch the temporary file is removed, so a failed verification cannot
    # leave a partially-trusted artifact behind for a later run to pick up.
    if expected_sha256 is not None:
        try:
            verify_sha256(Path(temp_file.name), expected_sha256, url)
        except ToolDownloadIntegrityError:
            Path(temp_file.name).unlink(missing_ok=True)
            raise
        ASH_LOGGER.verbose(f"Verified SHA256 {expected_sha256.lower()} for {url}")
    else:
        ASH_LOGGER.warning(
            f"Downloaded {url} without a pinned SHA256; integrity was not verified"
        )

    # Move the verified bytes into place without ever following a symlink at the
    # destination.
    #
    # `shutil.move` was not safe enough here. It is `os.rename` -- which is
    # symlink-safe -- only while source and destination share a filesystem. On EXDEV
    # it falls back through copy2 to copyfile, which does `open(dst, "wb")` and
    # follows a link at the destination. The source is a NamedTemporaryFile in
    # TMPDIR and the destination is ASH_BIN_PATH, so a relocated TMPDIR or a
    # `--tmpfs /tmp` container puts that fallback on the normal path rather than an
    # exotic one. This matters most for opengrep, which reaches here through
    # create_url_download_command, passes no digest, and therefore re-downloads on
    # every single install.
    dest_path = destination.joinpath(rename_to)
    _replace_atomically(Path(temp_file.name), dest_path)

    ASH_LOGGER.info(f"Downloaded {url} to {dest_path}")
    return dest_path


def _open_staging(target: Path) -> "tuple[int, Path]":
    """Create an unpredictably-named staging file beside ``target``.

    The name has to be unpredictable, not merely exclusive. An earlier version staged
    at ``<target>.ash-partial`` with O_CREAT|O_EXCL|O_NOFOLLOW, which stops a symlink
    being *planted* at that path but does nothing about ``rename``: in a 0777
    directory with no sticky bit -- which is what ASH's image leaves ASH_BIN_PATH as
    (Dockerfile:243) -- rename permission comes from the directory's write bit, not
    the file's. So anyone with write access to the directory could rename their own
    file over the staging path between the open and the ``os.replace``, and the
    replace would then install their bytes.

    ``mkstemp`` closes that by construction: O_EXCL against a name the attacker cannot
    guess, created 0600, in the directory the final rename has to happen in so that
    the rename stays same-filesystem and therefore atomic.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(
        dir=target.parent, prefix=f".{target.name}.", suffix=".ash-partial"
    )
    return fd, Path(name)


def _finalize_staged(staging: Path, target: Path, expected_sha256: str) -> None:
    """Put ``staging`` at ``target``, then verify the bytes that landed.

    The re-hash after the rename is the part that matters, and it is deliberately
    redundant with the unpredictable staging name. If a future change reintroduces a
    guessable name -- or if some other race puts different bytes at the target -- this
    catches it, because the receipt written afterwards records the digest of whatever
    is at the target. Without this check that receipt would record the *attacker's*
    digest, and ``_already_installed`` would then agree with it forever: the same
    persistent-trust outcome that moving receipts out of the bin directory was meant
    to close, reached through a different door.

    On mismatch the target is removed. Leaving unverified bytes at an install path is
    worse than leaving nothing there.
    """
    if platform.system() != "Windows":
        # Set the final mode here rather than leaving make_executable to OR 0o111 onto
        # the 0o600 mkstemp creates, which would produce 0o711 and quietly differ from
        # the 0o755 the previous umask-dependent code produced. A scanner binary must
        # be executable by whoever runs the scan, which is not always whoever
        # installed it.
        os.chmod(staging, 0o755)  # nosec B103 - an executable must be executable
    os.replace(staging, target)
    landed = sha256_file(target)
    if landed != expected_sha256:
        target.unlink(missing_ok=True)
        raise ToolDownloadIntegrityError(
            f"{target} does not match the bytes just written to it (expected "
            f"{expected_sha256}, found {landed}). Something replaced the staging file "
            "between writing and installing it; refusing to leave it in place."
        )


def _replace_atomically(source: Path, target: Path) -> Path:
    """Move ``source`` onto ``target`` without ever following or trusting a link.

    Staging in the target's directory keeps the final step a same-filesystem
    ``os.replace``, which cannot follow a symlink at the target and cannot leave a
    partially written file there.
    """
    fd, staging = _open_staging(target)
    try:
        digest = hashlib.sha256()
        with os.fdopen(fd, "wb") as sink, open(source, "rb") as src:
            for chunk in iter(lambda: src.read(_HASH_CHUNK_BYTES), b""):
                digest.update(chunk)
                sink.write(chunk)
        _finalize_staged(staging, target, digest.hexdigest())
    except BaseException:
        staging.unlink(missing_ok=True)
        raise
    finally:
        source.unlink(missing_ok=True)
    return target


def make_executable(file_path: Path) -> None:
    """Make a file executable, refusing to act through a symlink.

    Args:
        file_path: Path to the file to make executable

    ``Path.chmod`` and ``Path.stat`` both follow symlinks, so a link planted at the
    install location would have had its *target* made executable -- turning an
    arbitrary file chosen by whoever planted the link into an executable one. The
    install paths now stage and rename so a link should never be here, and refusing
    outright rather than dereferencing means a bug that reintroduces one is loud.
    """
    if platform.system() == "Windows":
        return
    if file_path.is_symlink():
        ASH_LOGGER.warning(
            f"Refusing to change the mode of {file_path}: it is a symlink, and "
            "following it would make its target executable instead"
        )
        return
    ASH_LOGGER.info(f"Making {file_path} executable")
    file_path.chmod(file_path.stat().st_mode | 0o111)  # Add execute permission


def unquarantine_macos_binary(file_path: Path) -> None:
    """Remove the quarantine attribute from a macOS binary.

    Args:
        file_path: Path to the binary to unquarantine
    """
    if platform.system() == "Darwin":
        ASH_LOGGER.info(f"Unquarantining {file_path}")
        try:
            run_command(["xattr", "-r", "-d", "com.apple.quarantine", str(file_path)])
        except Exception as e:
            ASH_LOGGER.warning(f"Failed to unquarantine {file_path}: {e}")


def receipt_root() -> Path:
    """Directory holding install receipts, deliberately NOT inside any bin directory.

    Receipts used to live in ``<bin dir>/.ash-install-receipts``, and that made the
    whole re-hash check worthless. A receipt records the digest an installed binary
    is compared against, so it is a trust anchor -- and ASH's own image runs
    ``chmod -R 777 ${ASH_BIN_PATH}`` (Dockerfile:243) with no sticky bit. Anything
    able to replace the binary could equally unlink the receipts directory, recreate
    it, and write a receipt naming its substitute's digest. ``_already_installed``
    would then agree with itself and skip forever, exactly as it did before the
    re-hash existed.

    Keyed by a hash of the resolved destination, because the same tool can be
    installed into several bin directories and each needs its own record.

    ``$HOME`` rather than the bin directory: the container sets the non-root home to
    0750 and leaves root's at its default, so neither is world-writable, and
    ``read_receipt`` refuses a receipt in a group- or other-writable location anyway.
    """
    return Path.home().joinpath(".ash", RECEIPT_DIR_NAME)


def receipt_path(destination: Path, installed_as: str) -> Path:
    """Path of the install receipt for ``installed_as`` installed into ``destination``."""
    try:
        key_source = str(Path(destination).resolve())
    except OSError:  # pragma: no cover - resolve() on an unreadable parent
        key_source = str(destination)
    key = hashlib.sha256(key_source.encode("utf-8")).hexdigest()[:16]
    return receipt_root().joinpath(key, f"{installed_as}.json")


def _untrusted_reason(path: Path) -> Optional[str]:
    """Why ``path`` cannot be trusted to hold a reference digest, or None if it can.

    Two checks, because mode alone is not enough. A directory owned by someone else
    can be replaced wholesale regardless of how tight its mode looks, so ownership is
    checked as well as write bits.

    POSIX only. Windows does not express permissions in st_mode, so this returns None
    there and the whole location check contributes nothing on that platform. Stated
    plainly rather than implied, because a check that silently does nothing on one
    platform is exactly the kind that gets trusted everywhere.
    """
    if platform.system() == "Windows":
        return None
    try:
        info = path.stat()
    except OSError:
        return None
    if info.st_mode & 0o022:
        return f"{path} is writable by group or other (mode {oct(info.st_mode & 0o777)})"
    if info.st_uid != os.getuid():
        return f"{path} is owned by uid {info.st_uid}, not {os.getuid()}"
    return None


def _receipt_trust_chain(path: Path) -> "list[Path]":
    """The receipt file and every directory up to and including the receipt root.

    Checking only the immediate parent was not enough: with the parents of the receipt
    root left at the umask's default, a group member could rename the per-destination
    key directory away and put a conforming 0700/0600 receipt in its place. Every level
    ASH creates has to be as trustworthy as the file itself.
    """
    root = receipt_root()
    chain = [path]
    for parent in path.parents:
        chain.append(parent)
        if parent == root:
            break
    return chain


def _private_dir(path: Path) -> None:
    """Create ``path`` and each level below the home directory at 0o700.

    ``Path.mkdir(parents=True, mode=0o700)`` does not do this. CPython applies the
    mode to the final component only; the parents get 0o777 masked by the umask.
    Measured under umask 002: ~/.ash and ~/.ash/install-receipts both came out 0o775
    while only the leaf was 0o700. Unreachable inside ASH's container, where $HOME is
    0750 or tighter, but perfectly reachable on a umask-002 developer host or runner.
    """
    home = Path.home()
    levels = [path, *[p for p in path.parents if p != home and home in p.parents]]
    for level in reversed(levels):
        level.mkdir(exist_ok=True)
        if platform.system() != "Windows":
            os.chmod(level, 0o700)


def read_receipt(destination: Path, installed_as: str) -> Optional[dict]:
    """Read an install receipt, or None if absent, unreadable or untrustworthy.

    An unreadable receipt is treated as absent rather than fatal: the recovery is
    to reinstall, and refusing to install because a cache marker is corrupt would
    be worse than the corruption.

    A receipt whose file or containing directory is writable by group or other is
    also treated as absent. Anyone who can rewrite it chooses the digest an installed
    scanner is checked against, which makes it worth nothing -- and re-downloading is
    the cheap, safe answer.
    """
    path = receipt_path(destination, installed_as)
    if not path.is_file():
        return None
    for level in _receipt_trust_chain(path):
        reason = _untrusted_reason(level)
        if reason is not None:
            ASH_LOGGER.warning(
                f"Ignoring install receipt at {path}: {reason}, so it cannot be "
                "trusted to say what was installed"
            )
            return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        ASH_LOGGER.debug(f"Ignoring unreadable install receipt at {path}")
        return None
    # `[]`, `"x"` and `3` are all valid JSON and none of them has .get(), so a
    # receipt containing one would crash the caller with AttributeError instead of
    # being treated as absent -- which is what this function's contract promises for
    # anything it cannot read.
    if not isinstance(data, dict):
        ASH_LOGGER.debug(f"Ignoring install receipt at {path}: not a JSON object")
        return None
    return data


def write_receipt(
    destination: Path, installed_as: str, receipt: dict
) -> Optional[Path]:
    """Write an install receipt recording which pinned asset was installed.

    Best-effort on purpose. The receipt is a cache that makes the *next* install a
    no-op; the tool itself is already in place by the time this runs. Failing the
    install because a marker file could not be written would report a successful
    install as a failure, which is the same class of wrong answer -- in the other
    direction -- as the silent success this change exists to remove. The cost of a
    missing receipt is one redundant download next time, and it is logged.

    The directory is created 0o700 and the file written 0o600, so ``read_receipt``'s
    location check passes for receipts ASH wrote and fails for a receipt someone else
    left group- or other-writable. Modes are set explicitly rather than left to the
    umask, since a permissive umask would otherwise produce a receipt this code then
    declines to trust.
    """
    path = receipt_path(destination, installed_as)
    try:
        _private_dir(path.parent)
        path.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")
        if platform.system() != "Windows":
            os.chmod(path, 0o600)
    except OSError as e:
        ASH_LOGGER.warning(
            f"Installed {installed_as} but could not write its install receipt to "
            f"{path}: {e}. The next install will re-download it."
        )
        return None
    return path


def _already_installed(
    destination: Path, installed_as: str, url: str, expected_sha256: Optional[str]
) -> bool:
    """Whether ``installed_as`` on disk is still the bytes that were verified.

    Not "was installed once" -- *is still*. That distinction is the whole security
    content of this function, and getting it wrong turns skipping a download into
    trusting a file nobody checked.

    Five conditions, each closing a specific hole:

    1. The target exists and is a regular file. A receipt whose file was deleted is
       not an install.
    2. There is a pinned digest at all. An unpinned download has nothing to be
       idempotent against, so ``sha256: null`` in a receipt would match every later
       unpinned install and cache a substituted binary forever. opengrep is in that
       state until it gets a pin, so it re-downloads.
    3. A receipt exists. A file with no receipt came from somewhere else -- a
       package manager, a nix profile, an ASH that predates receipts -- and must not
       be assumed to be the pinned version.
    4. The receipt names this exact url and pinned digest, so a version bump
       reinstalls rather than finding the old binary and reporting success.
    5. **The file on disk still hashes to what was installed.** This is the one a
       receipt alone cannot give: the pinned digest covers the release *archive*,
       not the extracted executable, so comparing it proves nothing about the file
       that will actually run.

    Why (5) is not paranoia. ASH's own image does ``chmod -R 777 ${ASH_BIN_PATH}``
    (Dockerfile:243), puts that directory first on PATH (:254), and runs
    ``ash dependencies install`` into it twice (:253 and :328). Before idempotence
    existed every install re-downloaded, so the second run overwrote anything
    substituted in between -- the redundant download was accidentally a self-healing
    property. Skipping on a receipt alone would have converted that into a persistent
    one, in the one directory the image makes world-writable, in a tool whose output
    is used to make security decisions. Re-hashing costs well under a second on a
    30-100MB binary.
    """
    target = destination.joinpath(installed_as)
    if not target.is_file():
        return False
    if expected_sha256 is None:
        return False
    receipt = read_receipt(destination, installed_as)
    if receipt is None:
        return False
    if receipt.get("url") != url:
        return False
    if receipt.get("sha256") != expected_sha256.lower():
        return False
    installed_digest = receipt.get("installed_sha256")
    if not installed_digest:
        # Written by an ASH that recorded only the archive digest. Treated as not
        # installed, so the next run replaces it with a receipt that can be checked.
        return False
    try:
        if sha256_file(target) != installed_digest:
            ASH_LOGGER.warning(
                f"{target} no longer matches the digest recorded when it was "
                "installed; reinstalling"
            )
            return False
    except OSError as e:
        ASH_LOGGER.debug(f"Could not hash {target} ({e}); treating as not installed")
        return False
    return True


def install_binary_from_url(
    url: str,
    destination: Path,
    rename_to: Optional[str] = None,
    expected_sha256: Optional[str] = None,
    force: bool = False,
) -> Path:
    """Download and install a binary from a URL.

    Idempotent: if a receipt shows the same url and digest already produced the
    installed file, the download is skipped. Before this, every
    ``ash dependencies install`` re-fetched every binary, so re-running the
    installer in CI paid for the whole toolchain again and a network blip turned a
    no-op into a failure.

    Args:
        url: The URL to download from
        destination: The directory to install the binary to
        rename_to: Optional name to rename the binary to
        expected_sha256: Pinned SHA256 to verify the download against
        force: Re-download even when a matching receipt exists

    Returns:
        Path to the installed binary
    """
    installed_as = rename_to if rename_to is not None else url.split("/")[-1]
    target = destination.joinpath(installed_as)

    if not force and _already_installed(destination, installed_as, url, expected_sha256):
        ASH_LOGGER.info(f"{installed_as} already installed from {url}, skipping download")
        return target

    # Download the file
    binary_path = download_file(url, destination, rename_to, expected_sha256=expected_sha256)

    # Make it executable
    make_executable(binary_path)

    # Platform-specific post-installation steps
    if platform.system() == "Darwin":
        unquarantine_macos_binary(binary_path)

    write_receipt(
        destination,
        installed_as,
        {
            "url": url,
            "sha256": expected_sha256.lower() if expected_sha256 else None,
            "installed_sha256": _digest_or_none(binary_path),
            "installed_as": installed_as,
        },
    )

    return binary_path


def _extract_single_member(
    archive_path: Path, member_name: str, target: Path
) -> Path:
    """Extract the one archive member named ``member_name`` to ``target``.

    ``member_name`` is matched against each entry's *basename*, and the archive is
    rejected unless exactly one regular-file entry matches. Two properties follow
    from doing it this way rather than calling ``extractall``:

    * No path from inside the archive is ever used as a filesystem destination, so
      an entry named ``../../bin/sh`` or an absolute path cannot escape -- the
      only destination is the one the caller passed.
    * A vendor moving the binary from the archive root into a subdirectory keeps
      working, while an archive that contains two entries with the same basename
      is refused instead of resolved arbitrarily.

    The extraction is staged and then renamed into place, and the staging file is
    opened with O_CREAT|O_EXCL (plus O_NOFOLLOW where the platform has it). Three
    things follow, and since the destination directory is world-writable in ASH's own
    image (Dockerfile:243) none of them is hypothetical:

    * A pre-existing symlink at the target is not written *through*. A plain
      ``open(target, "wb")`` follows the link, so a link planted at
      ``$ASH_BIN_PATH/grype`` would receive the vendor's ELF and then have its own
      target made executable. ``os.replace`` replaces the link itself. Reachable
      because ASH executes repository code during a scan -- cdk-nag synthesizes CDK
      apps, npm-audit runs a package manager -- so a scanned project can plant the
      link before a later install.
    * A symlink cannot be planted at the staging path either, because O_EXCL fails on
      an existing name, including a dangling link.
    * An interrupted extraction cannot leave a truncated binary at the target,
      because the target is only ever created by an atomic rename.

    The mode is set explicitly on the staging file rather than left to
    ``make_executable``'s read-modify-write of whatever the umask produced.

    Raises:
        ToolDownloadIntegrityError: if zero or more than one member matches.
    """
    suffixes = "".join(archive_path.suffixes[-2:]).lower()
    fd, staging = _open_staging(target)
    written = hashlib.sha256()
    staged = False

    def _stage(source) -> None:
        nonlocal staged
        with os.fdopen(fd, "wb") as sink:
            for chunk in iter(lambda: source.read(_HASH_CHUNK_BYTES), b""):
                written.update(chunk)
                sink.write(chunk)
        staged = True

    try:
        if suffixes.endswith(".zip"):
            with zipfile.ZipFile(archive_path) as archive:
                # ZipFile normalizes separators to "/" on read, so splitting on "/"
                # is correct for archives built on Windows too.
                matches = [
                    info
                    for info in archive.infolist()
                    if not info.is_dir()
                    and info.filename.split("/")[-1] == member_name
                ]
                _require_one_match(matches, member_name, archive_path)
                with archive.open(matches[0]) as source:
                    _stage(source)
        else:
            with tarfile.open(archive_path, "r:*") as archive:
                matches = [
                    member
                    for member in archive.getmembers()
                    if member.isfile() and member.name.split("/")[-1] == member_name
                ]
                _require_one_match(matches, member_name, archive_path)
                extracted = archive.extractfile(matches[0])
                if extracted is None:  # pragma: no cover - isfile() excludes this
                    raise ToolDownloadIntegrityError(
                        f"Archive member {member_name} in {archive_path} is not "
                        "readable"
                    )
                with extracted as source:
                    _stage(source)

        # 0o755, and the digest of what was written, are both handled here. See
        # _finalize_staged: the post-rename re-hash is what stops a race on the
        # staging path from getting an attacker's bytes recorded in the receipt as
        # though ASH had installed them.
        _finalize_staged(staging, target, written.hexdigest())
    except BaseException:
        if not staged:
            # The fd was never handed to fdopen, so nothing closed it.
            os.close(fd)
        staging.unlink(missing_ok=True)
        raise
    return target


def _require_one_match(matches: list, member_name: str, archive_path: Path) -> None:
    if len(matches) == 1:
        return
    if not matches:
        raise ToolDownloadIntegrityError(
            f"Archive {archive_path.name} contains no member named {member_name}"
        )
    raise ToolDownloadIntegrityError(
        f"Archive {archive_path.name} contains {len(matches)} members named "
        f"{member_name}; refusing to guess which is the executable"
    )


def install_pinned_tool(
    tool: str,
    target_platform: str,
    arch: str,
    destination: Optional[Path] = None,
    force: bool = False,
) -> Path:
    """Install one of ASH's pinned scanner binaries, verified against its digest.

    The digest is never passed in by the caller -- it is looked up from
    ``tool_downloads`` inside this function. That is deliberate: a digest that can
    be supplied on a command line can also be supplied wrongly, and the whole
    point of pinning is that the expected value comes from the repository.

    Args:
        tool: Tool name, one of ``tool_downloads.downloadable_tools()``
        target_platform: linux, darwin or windows
        arch: amd64 or arm64
        destination: Directory to install into; defaults to ASH_BIN_PATH
        force: Re-download even when a matching receipt exists

    Returns:
        Path to the installed executable

    Raises:
        ToolNotProvisionableError: if the tool publishes nothing for this platform
        ToolDownloadIntegrityError: if the download does not match its pinned digest
    """
    from automated_security_helper.utils.tool_downloads import get_tool_asset

    asset = get_tool_asset(tool, target_platform, arch)
    bin_dir = Path(destination) if destination is not None else current_bin_path()
    bin_dir.mkdir(parents=True, exist_ok=True)
    target = bin_dir.joinpath(asset.install_as)

    if not force and _already_installed(
        bin_dir, asset.install_as, asset.url, asset.sha256
    ):
        ASH_LOGGER.info(
            f"{asset.tool} {asset.version} already installed at {target}, "
            "skipping download"
        )
        return target

    with tempfile.TemporaryDirectory(prefix="ash-tool-download-") as staging:
        staging_dir = Path(staging)
        archive = download_file(
            asset.url,
            staging_dir,
            rename_to=asset.url.split("/")[-1],
            expected_sha256=asset.sha256,
        )
        _extract_single_member(archive, asset.member_name, target)

    # _extract_single_member already set the mode on the staged file before renaming
    # it into place; this covers the Windows branch, where it does not.
    make_executable(target)
    if platform.system() == "Darwin":
        unquarantine_macos_binary(target)

    write_receipt(
        bin_dir,
        asset.install_as,
        {
            "tool": asset.tool,
            "version": asset.version,
            "url": asset.url,
            "sha256": asset.sha256.lower(),
            # The digest of the *extracted executable*, which is what a later run
            # re-hashes. asset.sha256 covers the archive and says nothing about the
            # file that will actually be executed.
            "installed_sha256": _digest_or_none(target),
            "installed_as": asset.install_as,
        },
    )
    ASH_LOGGER.info(f"Installed {asset.tool} {asset.version} to {target}")
    return target


def current_bin_path() -> Path:
    """Resolve ASH_BIN_PATH at call time rather than at import time.

    ``core.constants.ASH_BIN_PATH`` is computed when that module is first imported.
    ``ash dependencies install --bin-path`` sets the environment variable *after*
    that import has happened, so a function that closed over the constant would
    install into the default directory while reporting the requested one.
    """
    from_env = os.environ.get("ASH_BIN_PATH")
    return Path(from_env) if from_env else ASH_BIN_PATH


def create_pinned_tool_install_command(
    tool: str,
    target_platform: str,
    arch: str,
    destination: str | None = None,
) -> CustomCommand:
    """Build the CustomCommand that installs a pinned tool in a subprocess.

    Mirrors ``create_url_download_command``, which is how opengrep is provisioned,
    so the installer keeps one execution model for every tool: plugins declare
    commands, the CLI runs them and counts them.
    """
    if destination is None:
        destination = str(current_bin_path()).replace("\\", "/")

    script = (
        "import sys; from pathlib import Path; "
        "from automated_security_helper.utils.download_utils import install_pinned_tool; "
        "install_pinned_tool(sys.argv[1], sys.argv[2], sys.argv[3], Path(sys.argv[4]))"
    )
    return CustomCommand(
        args=[sys.executable, "-c", script, tool, target_platform, arch, destination],
        shell=False,
    )


def create_url_download_command(
    url: str,
    destination: str | None = None,
    rename_to: str | None = None,
) -> CustomCommand:
    """Create a CustomCommand to download and install a binary from a URL.

    Args:
        url: The URL to download from
        destination: The directory to install the binary to (defaults to ASH_BIN_PATH)
        rename_to: Optional name to rename the binary to

    Returns:
        CustomCommand object
    """
    # Use the provided destination or get the current ASH_BIN_PATH.
    #
    # Resolved from the environment rather than from the imported constant. The
    # constant is fixed when core.constants is first imported, which happens before
    # `ash dependencies install --bin-path X` exports ASH_BIN_PATH -- so opengrep
    # installed into the default directory while the installer reported the
    # requested one, and the post-install sweep then found nothing there.
    if destination is None:
        destination = str(current_bin_path()).replace(
            "\\", "/"
        )  # Ensure forward slashes for cross-platform compatibility

    if not Path(destination).exists():
        ASH_LOGGER.verbose(f"Creating ASH bin path directory @ {destination}")
        Path(destination).mkdir(parents=True, exist_ok=True)

    script = (
        "import sys; from pathlib import Path; "
        "from automated_security_helper.utils.download_utils import install_binary_from_url; "
        "install_binary_from_url(sys.argv[1], Path(sys.argv[2]), sys.argv[3] if sys.argv[3] != 'None' else None)"
    )
    return CustomCommand(
        args=[
            sys.executable,
            "-c",
            script,
            url,
            str(destination),
            str(rename_to) if rename_to is not None else "None",
        ],
        shell=False,
    )


def pinned_tool_install_commands(
    tool: str,
) -> "dict[str, dict[str, list[CustomCommand]]]":
    """Build the ``custom_install_commands`` table for one pinned tool.

    Only the platform/arch pairs the vendor actually publishes get an entry. A
    pair with no asset is left *absent* rather than mapped to an empty list, and
    that distinction is the whole point: ``_has_install_commands`` reports
    ``len(...) > 0``, so an empty list made syft and npm-audit look like they had
    an install path while installing nothing, and the installer then reported
    success for a tool it had not installed.
    """
    from automated_security_helper.utils.tool_downloads import supported_platforms

    table: dict[str, dict[str, list[CustomCommand]]] = {}
    for target_platform, arch in supported_platforms(tool):
        table.setdefault(target_platform, {})[arch] = [
            create_pinned_tool_install_command(tool, target_platform, arch)
        ]
    return table


def get_opengrep_url(
    target_platform: Literal["linux", "darwin", "macos", "windows"],
    arch: Literal["amd64", "arm64", "x86_64", "aarch64"],
    version: str = "v1.1.5",
    linux_type: Literal["musllinux", "manylinux"] = "manylinux",
) -> str:
    """Get the URL for the opengrep binary based on platform and architecture.

    Args:
        target_platform: The platform (e.g., "linux", "darwin", "windows")
        arch: The architecture (e.g., "amd64", "arm64")
        version: The version of opengrep to download (default: "v1.1.5")
        linux_type: Type of Linux build to use (manylinux or musllinux)

    Returns:
        URL for the opengrep binary
    """
    # Base URL for opengrep releases
    base_url = f"https://github.com/opengrep/opengrep/releases/download/{version}"

    # Map platform and architecture to the appropriate binary name
    if target_platform == "linux":
        # Validate linux_type
        if linux_type not in ["manylinux", "musllinux"]:
            ASH_LOGGER.warning(
                f"Invalid linux_type: {linux_type}, defaulting to manylinux"
            )
            linux_type = "manylinux"

        if arch == "amd64" or arch == "x86_64":
            return f"{base_url}/opengrep_{linux_type}_x86"
        elif arch == "arm64" or arch == "aarch64":
            return f"{base_url}/opengrep_{linux_type}_aarch64"
    elif target_platform == "darwin" or target_platform == "macos":
        if arch == "amd64" or arch == "x86_64":
            return f"{base_url}/opengrep_osx_x86"
        elif arch == "arm64" or arch == "aarch64":
            return f"{base_url}/opengrep_osx_arm64"
    elif target_platform == "windows":
        return f"{base_url}/opengrep_windows_x86.exe"

    # Default case
    raise ValueError(f"Unsupported platform/architecture: {target_platform}/{arch}")
