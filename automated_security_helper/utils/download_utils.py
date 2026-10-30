"""Utility functions for downloading and installing binaries."""

import errno
import hashlib
import http.client
import json
import os
import platform
import re
import shutil
import ssl
import stat
import sys
import tarfile
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Optional
import urllib.error
import urllib.parse
import urllib.request

from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import run_command
from automated_security_helper.base.plugin_base import CustomCommand
from automated_security_helper.core.constants import (
    ASH_BIN_PATH,
    ash_bin_path_from_environment,
    is_offline_mode,
    usable_home,
    warn_if_home_unusable,
)
from automated_security_helper.core.exceptions import (
    ToolDownloadIntegrityError,
    ToolNotProvisionableError,
)

# Name of the directory holding install receipts. See receipt_root() for why it is
# NOT under the bin directory a tool is installed into: a receipt records the digest
# an installed binary is checked against, so it is a trust anchor, and a bin
# directory can be writable by other users.
RECEIPT_DIR_NAME = "install-receipts"

# Read the download in chunks rather than into one buffer. syft's linux asset is
# ~30MB and trivy's is larger; holding a whole release archive in memory to hash
# it is avoidable.
_HASH_CHUNK_BYTES = 1024 * 1024

# Retry policy for the fetch inside _download_verified.
#
# WHY THIS EXISTS
#
# A single transient 5xx used to fail an entire install, and through it an entire
# container build. Measured on job 104983960003 of this repository: grype's pinned
# asset returned `HTTP Error 500: Internal Server Error` in the non-root image
# stage, `ash dependencies install` exited 1, and the podman build died at
# `RUN ash dependencies install`. The same URL had returned 200 minutes earlier in
# the same build's first stage, so the asset was fine and the request was not.
#
# The shell side of the toolchain already had this: assets/with-retry.sh wraps the
# curl-based installers for exactly this failure, and its own header records a
# 2026-08-20 "Recv failure: Connection reset by peer" on grype's installer. The
# Python download path had no equivalent, so the same class of blip was fatal here
# and survivable there.
#
# WHAT IS DELIBERATELY NOT RETRIED
#
# A digest mismatch. See _download_verified: verification happens outside the retry
# loop, so a ToolDownloadIntegrityError is raised on its first occurrence and never
# repeated. Retrying an integrity failure would turn a supply-chain control into a
# coin flip -- the point of a pinned digest is that one mismatch is disqualifying.
#
# 4xx, except 429. A 404 for a pinned asset means the asset table is wrong, and
# three attempts only delay that message; a 403 will be 403 again. 429 is the one
# status that explicitly means "you may succeed later", so it is treated as
# transient. Retry-After is not honoured -- the exponential backoff below is the
# approximation, and bounded at _DOWNLOAD_MAX_DELAY.
#
# Five attempts, matching the default on assets/with-retry.sh, which retries the
# same class of failure from the container build. Raised from three there because
# three exhausted its budget in about 15 seconds against a runner egress that was
# impaired for longer; the reasoning and the measurements are on the assignment in
# that script. Kept equal to it deliberately -- two retry budgets for the same
# hazard that disagree would mean the tool version a scan runs depends on which
# install path provisioned it.
#
# With the doubling below and the 60s bound, five attempts sleep 5s, 10s, 20s and
# 40s: a 75-second window, none of it clipped by _DOWNLOAD_MAX_DELAY.
_DOWNLOAD_MAX_ATTEMPTS_DEFAULT = 5
_DOWNLOAD_BASE_DELAY_DEFAULT = 5.0
_DOWNLOAD_MAX_DELAY = 60.0
_TRANSIENT_HTTP_STATUS = frozenset({429})

# How long one socket operation of a download may block before the attempt is
# given up as a TimeoutError, which the retry policy treats as transient. Without
# it urlopen waited without end, so a connection that stalled mid-body hung the
# install, and the TimeoutError branch of _is_transient_download_error never ran.
# A bound per read, not per download: a slow link still finishes a large asset.
_DOWNLOAD_SOCKET_TIMEOUT_SECONDS = 60.0


def _download_retry_policy() -> "tuple[int, float]":
    """``(attempts, base delay)`` for one download, from the environment.

    Overridable so a test can exercise the retry without waiting out the real
    backoff, mirroring the WITH_RETRY_* knobs on assets/with-retry.sh. Read per
    call rather than at import, so a test does not have to reload the module.

    Clamped rather than rejected, which is where this differs from with-retry.sh.
    That script exits 2 on a malformed value because it is a container-build entry
    point, where a silently-wrong backoff is invisible. This runs as library code
    partway through an install, and failing an install over a typo in an
    environment variable is the worse trade. ``max(1, ...)`` in particular: zero
    attempts would skip the fetch entirely and leave the caller with a missing file
    rather than an error, which is the never-ran-but-reported hazard with-retry.sh
    guards its own max=0 against.
    """
    try:
        attempts = int(os.environ["ASH_DOWNLOAD_MAX_ATTEMPTS"])
    except (KeyError, ValueError):
        attempts = _DOWNLOAD_MAX_ATTEMPTS_DEFAULT
    try:
        base_delay = float(os.environ["ASH_DOWNLOAD_RETRY_DELAY"])
    except (KeyError, ValueError):
        base_delay = _DOWNLOAD_BASE_DELAY_DEFAULT
    return max(1, attempts), max(0.0, base_delay)


#: Socket errors raised past the connection phase (while the body is read) that
#: name the network, not the asset: the same class as ConnectionError.
_TRANSIENT_ERRNOS = frozenset(
    code
    for code in (
        getattr(errno, "ENETUNREACH", None),
        getattr(errno, "EHOSTUNREACH", None),
        getattr(errno, "ENETDOWN", None),
        getattr(errno, "ENETRESET", None),
        getattr(errno, "EHOSTDOWN", None),
    )
    if code is not None
)


def _is_certificate_failure(exc: object) -> bool:
    """Whether ``exc`` is a TLS trust failure: the same on every attempt.

    ``ssl.SSLCertVerificationError`` is the typed form; an ``ssl.SSLError`` whose
    reason names the verification is the untyped one some stacks raise.
    """
    if isinstance(exc, ssl.SSLCertVerificationError):
        return True
    return isinstance(exc, ssl.SSLError) and "CERTIFICATE_VERIFY_FAILED" in str(exc)


def _is_transient_download_error(exc: BaseException) -> bool:
    """Whether a failed download attempt is worth repeating.

    ``HTTPError`` is tested before ``URLError`` because it is a subclass of it.
    Reversing the two would classify every 4xx as transient, which is the whole
    distinction this function exists to draw.

    A ``URLError`` is transient for what it wraps: a DNS failure, a refused
    connection or a TLS reset may work on a second try, while a certificate that
    does not verify fails the same way every time, so retrying it only delays the
    message by the whole backoff. A TLS error raised past the connection, while
    the body is read (``ssl.SSLError``, an unexpected EOF say), is the same blip
    a reset is, and a socket error naming the network (``EHOSTUNREACH``) too.
    """
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code >= 500 or exc.code in _TRANSIENT_HTTP_STATUS
    if isinstance(exc, urllib.error.URLError):
        return not _is_certificate_failure(exc.reason)
    if _is_certificate_failure(exc):
        return False
    if isinstance(exc, ssl.SSLError):
        return True
    if isinstance(exc, OSError) and exc.errno in _TRANSIENT_ERRNOS:
        return True
    return isinstance(
        exc,
        (
            ConnectionError,  # includes ConnectionResetError
            TimeoutError,  # socket.timeout is an alias of this from 3.10
            http.client.IncompleteRead,
            http.client.RemoteDisconnected,
        ),
    )


def _retry_delay(attempt: int, base_delay: float) -> float:
    """The backoff before the next attempt: doubling, bounded.

    The exponent is bounded as well as the result: ``2 ** (attempt - 1)`` as an
    int converted to float raises OverflowError past 2 ** 1023, so with
    ``ASH_DOWNLOAD_MAX_ATTEMPTS`` above that the backoff replaced the download
    error with its own. Past the bound every delay is the maximum anyway.
    """
    return min(base_delay * (2.0 ** min(attempt - 1, 32)), _DOWNLOAD_MAX_DELAY)


def _url_basename(url: str) -> str:
    """The name a download from ``url`` is installed under when none is given.

    The last segment of the URL's PATH, decoded: a query string or a fragment is
    no part of a filename, and the raw text after the last ``/`` of the whole URL
    was. A URL whose path ends in ``/`` names no file: refused here, where the
    URL is named, rather than after the download as an untyped OSError from a
    rename onto the destination directory.
    """
    name = urllib.parse.unquote(urllib.parse.urlsplit(url).path.rsplit("/", 1)[-1])
    if not name or name in (".", "..") or "/" in name or "\\" in name:
        raise ValueError(
            f"{url} names no file to install: its path ends in a directory, so "
            "pass rename_to"
        )
    return name


def _copy_whole_body(response, sink, url: str) -> int:
    """Copy the response body to ``sink``, refusing a body the server cut short.

    ``HTTPResponse.read(amt)`` returns an empty read when the connection closes
    before ``Content-Length`` bytes have arrived (http.client leaves the
    IncompleteRead unraised there for compatibility), so ``shutil.copyfileobj``
    ended a dropped download as if it were complete. The retry loop then saw no
    error, and the digest check reported the short file as an integrity failure,
    which reads as a tampered asset rather than the dropped connection it was.
    The bytes are counted against the declared length instead, and a shortfall
    is raised as the connection error it is, which the retry policy repeats.

    The length is read as http.client reads it: not at all for a chunked body
    (``Transfer-Encoding: chunked`` wins over a Content-Length, which the server
    may have left stale, and http.client raises IncompleteRead itself on a
    chunked body that is cut short), and only from an ASCII decimal header. A
    header of any other shape (a non-ASCII digit that ``str.isdigit`` accepts
    and ``int`` refuses, say) carries no usable length, so nothing is compared.

    An ``http.client.HTTPResponse`` has already parsed the header into ``length``
    (None for a chunked or unusable value, else the bytes still to read), so that
    is the length of record where it exists, read before the first read moves
    it; the header is parsed here only for a response object without it.

    Returns the number of bytes copied.
    """
    expected = _declared_body_length(response)
    copied = 0
    for chunk in iter(lambda: response.read(_HASH_CHUNK_BYTES), b""):
        sink.write(chunk)
        copied += len(chunk)
    if expected is not None and copied != expected:
        raise ConnectionError(
            f"the connection closed after {copied} of {expected} bytes of {url}"
        )
    return copied


def _declared_body_length(response) -> Optional[int]:
    """The body length the response declares, or None when it declares none usable.

    ``HTTPResponse.length`` is http.client's own reading of the headers: None for
    a chunked body, a missing header or a value it rejects, and otherwise the
    byte count, which it counts down as the body is read, so it is taken before
    any read. Where the object carries no such attribute (a fake, another
    client), the raw header is read: skipped for a chunked body, and only an
    ASCII decimal counts, so a negative or non-ASCII value is no length rather
    than a wrong one.
    """
    length = getattr(response, "length", None)
    if isinstance(length, int) and not isinstance(length, bool):
        return length if length >= 0 else None
    if getattr(response, "chunked", False):
        return None
    headers = getattr(response, "headers", None)
    declared = headers.get("Content-Length") if headers else None
    if declared is not None and re.fullmatch(r"[0-9]+", declared.strip()):
        return int(declared.strip())
    return None


def _sha256_of_open_file(fd: int) -> str:
    """The lowercase hex SHA256 of the file open at ``fd``, read from its start."""
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    with open(fd, "rb", closefd=False) as handle:
        for chunk in iter(lambda: handle.read(_HASH_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_file(file_path: Path) -> str:
    """Return the lowercase hex SHA256 of a file's contents."""
    digest = hashlib.sha256()
    with open(file_path, "rb") as handle:
        for chunk in iter(lambda: handle.read(_HASH_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
    *,
    mode: int = 0o644,
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
        mode: The mode the landed file gets on POSIX: ``0o644`` by default, since
            what this helper fetches is data (a rules bundle, a release archive).
            A caller that downloads a program it will run passes ``0o755``; the
            bit is then set on the staged file's own descriptor before the rename,
            never by a later chmod of the landed path. Every download used to land
            executable whatever it was; the data default is least privilege.

    Returns:
        Path to the downloaded file

    Raises:
        ToolDownloadIntegrityError: if expected_sha256 is given and does not match
    """
    landed, _digest = _download_verified(
        url, destination, rename_to, expected_sha256, mode=mode
    )
    return landed


def _download_verified(
    url: str,
    destination: Path,
    rename_to: Optional[str] = None,
    expected_sha256: Optional[str] = None,
    *,
    mode: int = 0o644,
) -> "tuple[Path, str]":
    """``download_file``, and also the digest of the bytes that landed.

    Exists so a caller writing an install receipt never has to re-derive the digest of
    what it installed. See ``_finalize_staged``: a hash taken afterwards describes
    whatever is at the path by then, which is the thing the post-rename check exists to
    reject. ``download_file`` keeps its plain ``Path`` return, because it is a public
    helper and a scanner plugin may be calling it.

    ``mode`` is the mode the landed file gets: ``0o644`` by default, since what
    this downloads is data (a release archive, a rules bundle);
    ``install_binary_from_url`` passes ``0o755`` for the executable it lands, and
    the extraction of an archive member sets its own.
    """
    # The URL first, before anything is made for the download: a refused URL
    # used to leave a freshly created destination directory behind.
    if not url.startswith("https://"):
        raise ValueError(f"Invalid URL: {url}")

    # Get the filename from the URL if rename_to is not specified
    if rename_to is None:
        rename_to = _url_basename(url)

    # Create the destination directory if it doesn't exist
    destination.mkdir(parents=True, exist_ok=True)

    # Download to a temporary file first. Removed on any failure out of the
    # fetch: created with delete=False so the verified bytes can be moved into
    # place below, it was left in TMPDIR by every download that ran out of
    # attempts or hit a non-transient error.
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    try:
        with temp_file:
            attempts, base_delay = _download_retry_policy()
            for attempt in range(1, attempts + 1):
                # Rewound and truncated on every attempt. A retry after a partial
                # transfer would otherwise APPEND to the bytes the failed attempt
                # already wrote. The digest check below would catch the result,
                # but it would report it as an integrity failure -- which reads
                # as a supply-chain compromise rather than as the dropped
                # connection it is.
                temp_file.seek(0)
                temp_file.truncate()
                ASH_LOGGER.info(
                    f"Downloading {url} to {temp_file.name}"
                    + (f" (attempt {attempt}/{attempts})" if attempts > 1 else "")
                )
                try:
                    # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
                    with urllib.request.urlopen(  # nosec B310 - This url is evaluated for https scheme a few lines above
                        url, timeout=_DOWNLOAD_SOCKET_TIMEOUT_SECONDS
                    ) as response:
                        _refuse_a_non_https_landing(url, response)
                        _copy_whole_body(response, temp_file, url)
                    break
                except Exception as exc:
                    # Re-raised unless the error is both transient and there is
                    # an attempt left, so nothing is swallowed: a 4xx, a bad URL
                    # or an exhausted budget still leaves this function raising
                    # exactly what it raised before the retry existed.
                    if attempt == attempts or not _is_transient_download_error(exc):
                        raise
                    delay = _retry_delay(attempt, base_delay)
                    ASH_LOGGER.warning(
                        f"Download of {url} failed with {type(exc).__name__}: {exc}. "
                        f"Retrying in {delay:.1f}s "
                        f"(attempt {attempt}/{attempts} failed)"
                    )
                    time.sleep(delay)
    except BaseException:
        Path(temp_file.name).unlink(missing_ok=True)
        raise

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
    # exotic one.
    #
    # The pin goes with it. The bytes verified above and the bytes copied below are two
    # separate reads of a file in TMPDIR, so the copy has to be checked against the pin
    # rather than against itself -- see _replace_atomically.
    dest_path = destination.joinpath(rename_to)
    landed = _replace_atomically(
        Path(temp_file.name), dest_path, expected_sha256=expected_sha256, mode=mode
    )

    ASH_LOGGER.info(f"Downloaded {url} to {dest_path}")
    return dest_path, landed


def _refuse_a_non_https_landing(url: str, response) -> None:
    """Refuse a response that arrived at a URL other than an https one.

    The scheme check above covers the URL given; ``urlopen`` follows redirects,
    and a server can send one to plain http, where the asset arrives unverified
    by transport. The URL the response was read from is checked before a byte of
    the body is taken, so such a download is refused rather than installed (an
    unpinned download would otherwise have completed over http). A response that
    cannot say where it came from (a test's stand-in) is taken as it is.
    """
    get_url = getattr(response, "geturl", None)
    if not callable(get_url):
        return
    landed_at = get_url()
    if isinstance(landed_at, str) and not landed_at.startswith("https://"):
        raise ValueError(
            f"Refusing {url}: the server redirected the download to {landed_at}, "
            "which is not https"
        )


def _open_staging(target: Path) -> "tuple[int, Path]":
    """Create an unpredictably-named staging file beside ``target``.

    The name has to be unpredictable, not merely exclusive. An earlier version staged
    at ``<target>.ash-partial`` with O_CREAT|O_EXCL|O_NOFOLLOW, which stops a symlink
    being *planted* at that path but does nothing about ``rename``: in a 0777
    directory with no sticky bit -- which an install directory can be --
    rename permission comes from the directory's write bit, not
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


def _finalize_staged(
    staging: Path, target: Path, expected_sha256: str, mode: int = 0o755
) -> str:
    """Put ``staging`` at ``target``, verify what landed, and return its digest.

    ``mode`` is the mode the landed file gets on POSIX: ``0o755`` for an
    executable, which is what the archive members and the pinned binaries are;
    ``download_file`` passes its caller's mode, ``0o644`` for the data files it
    lands by default.

    Two checks, covering two different intervals, and neither makes the other
    redundant.

    The first runs before the rename, so bytes that do not match never reach the
    install path at all. Without it this function renamed first and detected
    afterwards, which left rejected bytes sitting at the install path -- executable,
    because the mode is set on the staging file before the rename -- for however long
    hashing them took. That is roughly 200ms on a 100MB asset, not a microsecond, and
    it contradicted the rule stated at the bottom of this docstring. It costs one extra
    read of the staged file per install.

    The second runs after the rename, and it is deliberately redundant with the
    unpredictable staging name rather than with the check above. It covers what the
    first cannot: staging replaced in the gap between hashing it and renaming it, or
    the target replaced in the gap between the rename and the hash. If a future change
    reintroduces a guessable staging name -- or some other race puts different bytes at
    the target -- this is what catches it.

    Returning that digest is the other half of the same property, and without it the
    check above is necessary but not sufficient. The caller has to record a digest in
    the install receipt, and re-deriving it from the target afterwards hands back
    exactly what this check exists to reject: ``make_executable`` runs between here and
    the receipt write, on macOS ``unquarantine_macos_binary`` spawns ``xattr`` as a
    subprocess as well, and the install directory can be writable by other users,
    with no sticky bit, under a threat model where ASH
    executes repository code during a scan -- cdk-nag synthesizes CDK apps, npm-audit
    runs a package manager. A receipt built from a fresh hash of the target records
    whatever is there by then, and ``_already_installed`` re-hashes, agrees, and skips
    the download on every later run: the persistent-trust outcome that moving receipts
    out of the bin directory was meant to close, reached through a different door. The
    digest verified here is the only one worth writing down.

    On mismatch after the rename the target is removed. Leaving unverified bytes at an
    install path is worse than leaving nothing there.
    """
    # One open of the staging path, refusing to follow a link there, and both the
    # hash and the mode change made on that open file: the mode was set by name
    # after the hash, so an entry renamed over the staging name in between (the
    # directory can be writable by others) had its mode set instead, and a symlink
    # there was followed to whatever file it named. The post-rename hash still
    # covers a swap between this open and the rename. O_BINARY where the platform
    # has it: without it Windows opens the descriptor in text mode, the read folds
    # CR LF and stops at the first 0x1A, and every executable or archive, which
    # holds both, hashed short of its bytes and was refused as replaced.
    # O_NONBLOCK: a FIFO renamed over the staging name would block this open
    # before the digest check could refuse it; the descriptor is asked what it
    # is before anything is read from it.
    fd = os.open(staging, os.O_RDONLY | _O_NOFOLLOW | _O_BINARY | _O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ToolDownloadIntegrityError(
                f"The file staged for {target} is not a regular file. Something "
                "replaced it before installing it; refusing to put it at the "
                "install path."
            )
        staged = _sha256_of_open_file(fd)
        if staged != expected_sha256:
            # Not unlinked here: both callers already remove the staging file on
            # any exception, and one of them also has an fd to close.
            raise ToolDownloadIntegrityError(
                f"The file staged for {target} does not match the digest it was "
                f"verified against (expected {expected_sha256}, found {staged}). "
                "Something replaced it before installing it; refusing to put it at "
                "the install path."
            )
        if platform.system() != "Windows":
            # Set the final mode here rather than leaving make_executable to OR
            # 0o111 onto the 0o600 mkstemp creates, which would produce 0o711 and
            # quietly differ from the 0o755 the previous umask-dependent code
            # produced. A scanner binary must be executable by whoever runs the
            # scan, which is not always whoever installed it.
            os.fchmod(fd, mode)  # nosec B103 - an executable must be executable
    finally:
        os.close(fd)
    os.replace(staging, target)
    # The post-rename read opens the target itself, refusing to follow a link:
    # hashed by path, a link swapped in at the target and pointing at a file with
    # the right bytes passed the check and was recorded as the installed binary.
    # A target that cannot be read back is removed too: the rule is to leave
    # nothing unverified at the install path, and an unreadable file is that.
    try:
        # O_NONBLOCK: a FIFO swapped in at the install path would block this
        # open before the digest check could refuse it.
        landed_fd = os.open(target, os.O_RDONLY | _O_NOFOLLOW | _O_BINARY | _O_NONBLOCK)
    except OSError as error:
        target.unlink(missing_ok=True)
        raise ToolDownloadIntegrityError(
            f"{target} could not be read back after it was installed ({error}); "
            "refusing to leave it in place."
        ) from error
    try:
        landed = _sha256_of_open_file(landed_fd)
    except OSError as error:
        target.unlink(missing_ok=True)
        raise ToolDownloadIntegrityError(
            f"{target} could not be read back after it was installed ({error}); "
            "refusing to leave it in place."
        ) from error
    finally:
        os.close(landed_fd)
    if landed != expected_sha256:
        target.unlink(missing_ok=True)
        raise ToolDownloadIntegrityError(
            f"{target} does not match the bytes it was verified against (expected "
            f"{expected_sha256}, found {landed}). Something replaced the file between "
            "verifying it and installing it; refusing to leave it in place."
        )
    return landed


def _replace_atomically(
    source: Path,
    target: Path,
    expected_sha256: Optional[str] = None,
    mode: int = 0o755,
) -> str:
    """Move ``source`` onto ``target`` without ever following or trusting a link.

    Staging in the target's directory keeps the final step a same-filesystem
    ``os.replace``, which cannot follow a symlink at the target and cannot leave a
    partially written file there.

    ``expected_sha256`` is the pinned digest ``source`` was already verified against,
    and threading it in rather than defaulting to what this function reads is the
    difference between checking the install and checking it against itself. Verifying
    the source and copying it are two separate reads of a file in TMPDIR:
    ``verify_sha256`` streams the whole thing, which is 30-100MB for syft and trivy, so
    the window is hundreds of milliseconds. The sticky bit on /tmp stops another *user*
    unlinking or renaming that file; it stops nothing done by another process running as
    this one, which is what ASH has during a scan, since it executes repository code.
    Compare the copy against itself and a source replaced in that window installs
    cleanly with a self-consistent digest and a receipt that matches it -- while the
    bytes never matched the pin.

    With no pin there is nothing better to compare against than the bytes the copy read,
    so that is what is used. opengrep is the one tool in that state: it arrives through
    ``create_url_download_command``, which passes no digest.

    ``mode`` is the mode the landed file gets (``_finalize_staged``).

    Returns:
        The digest of the bytes now at ``target``.
    """
    try:
        # Inside the try whose finally removes the source: opened before it, a
        # staging file that could not be made (a destination this process may
        # not write) left the verified source behind in TMPDIR.
        fd, staging = _open_staging(target)
        try:
            copied = hashlib.sha256()
            with os.fdopen(fd, "wb") as sink, open(source, "rb") as src:
                for chunk in iter(lambda: src.read(_HASH_CHUNK_BYTES), b""):
                    copied.update(chunk)
                    sink.write(chunk)
            expected = (
                expected_sha256.lower()
                if expected_sha256 is not None
                else copied.hexdigest()
            )
            return _finalize_staged(staging, target, expected, mode)
        except BaseException:
            staging.unlink(missing_ok=True)
            raise
    finally:
        source.unlink(missing_ok=True)


def make_executable(file_path: Path) -> None:
    """Make a file executable, refusing to act through a symlink.

    Args:
        file_path: Path to the file to make executable

    ``Path.chmod`` and ``Path.stat`` both follow symlinks, so a link planted at the
    install location would have had its *target* made executable -- turning an
    arbitrary file chosen by whoever planted the link into an executable one. The
    install paths now stage and rename so a link should never be here, and refusing
    outright rather than dereferencing means a bug that reintroduces one is loud.

    The mode is read and set on one open descriptor, opened without following a
    link (``O_NOFOLLOW``): the ``is_symlink`` check alone left a window in which a
    link swapped in after it was followed by the chmod.
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
    try:
        # O_NONBLOCK: a FIFO at the install path would block this open; opened,
        # the descriptor says what it is and anything but a regular file is
        # refused below.
        fd = os.open(file_path, os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK)
    except OSError as error:
        if error.errno in (errno.ELOOP, getattr(errno, "EMLINK", errno.ELOOP)):
            ASH_LOGGER.warning(
                f"Refusing to change the mode of {file_path}: it is a symlink, and "
                "following it would make its target executable instead"
            )
            return
        raise
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            ASH_LOGGER.warning(
                f"Refusing to change the mode of {file_path}: it is not a regular file"
            )
            return
        os.fchmod(fd, info.st_mode | 0o111)  # Add execute permission
    finally:
        os.close(fd)


def unquarantine_macos_binary(file_path: Path) -> None:
    """Remove the quarantine attribute from a macOS binary.

    Args:
        file_path: Path to the binary to unquarantine
    """
    if platform.system() == "Darwin":
        ASH_LOGGER.info(f"Unquarantining {file_path}")
        try:
            # The file itself, not a recursive walk: the installed binary is one
            # file, and a path swapped for a directory meanwhile would have had
            # every file under it unquarantined.
            result = run_command(
                ["xattr", "-d", "com.apple.quarantine", str(file_path)]
            )
        except Exception as e:
            ASH_LOGGER.warning(f"Failed to unquarantine {file_path}: {e}")
            return
        # run_command raises nothing on a non-zero exit, so the exit is read here:
        # a binary xattr could not clear stays quarantined, and the install was
        # reported as done with nothing saying so.
        if result.returncode != 0:
            detail = str(result.stderr or result.stdout or "").strip()
            if "No such xattr" in detail:
                # A file urllib downloaded carries no quarantine attribute (the
                # browser and the Finder set it); xattr -d then exits 1 with this
                # text, and there is nothing to remove.
                ASH_LOGGER.debug(f"{file_path} carries no quarantine attribute")
                return
            ASH_LOGGER.warning(
                f"Failed to unquarantine {file_path}: xattr exited "
                f"{result.returncode}{': ' + detail if detail else ''}. macOS may "
                "refuse to run it until the quarantine attribute is removed."
            )


def receipt_root() -> Path:
    """Directory holding install receipts, deliberately NOT inside any bin directory.

    Receipts used to live in ``<bin dir>/.ash-install-receipts``, and that made the
    whole re-hash check worthless. A receipt records the digest an installed binary
    is compared against, so it is a trust anchor -- and a bin directory can be
    writable by other users, with no sticky bit. Anything
    able to replace the binary could equally unlink the receipts directory, recreate
    it, and write a receipt naming its substitute's digest. ``_already_installed``
    would then agree with itself and skip forever, exactly as it did before the
    re-hash existed.

    Keyed by a hash of the resolved destination, because the same tool can be
    installed into several bin directories and each needs its own record.

    ``$HOME`` rather than the bin directory: the container sets the non-root home to
    0750 and leaves root's at its default, so neither is world-writable, and
    ``read_receipt`` refuses a receipt in a group- or other-writable location anyway.

    The home is ``core.constants.usable_home``, the one place ASH decides whether
    there is one, not ``Path.home()``: an empty HOME put the receipts at ``/.ash``, a
    relative one under the working directory (the scanned repository), and an unset
    HOME with no passwd entry raised RuntimeError out of every install. With no
    usable home there is no receipt store: this raises ``ReceiptStoreUnavailable``,
    which ``read_receipt`` reads as no receipt and ``write_receipt`` as a receipt it
    could not write, so an install still installs and is reported as it went.

    Raises:
        ReceiptStoreUnavailable: there is no usable home directory.
    """
    home = usable_home()
    if home is None:
        raise ReceiptStoreUnavailable(
            "no usable home directory (HOME is unset, empty or relative, and no "
            "absolute home is on record for this user), so install receipts have "
            "nowhere to live"
        )
    return home.joinpath(".ash", RECEIPT_DIR_NAME)


class ReceiptStoreUnavailable(OSError):
    """There is no usable home directory to keep install receipts in."""


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

    The entry is judged as it is, without following a link (``lstat``): judged
    through a link, a substituted link in a loose ``~/.ash`` was trusted for its
    target's owner and mode. A link is not trusted, whatever it points at. An
    entry that cannot be examined at all is not trusted either: a location the
    check cannot see is not one it can vouch for.
    """
    if platform.system() == "Windows":
        return None
    try:
        info = path.lstat()
    except OSError as error:
        return f"{path} cannot be examined ({error})"
    return _untrusted_stat(path, info)


def _untrusted_stat(path: Path, info: os.stat_result) -> Optional[str]:
    """``_untrusted_reason`` over a stat result already taken (``lstat`` or
    ``fstat`` of an open descriptor)."""
    if stat.S_ISLNK(info.st_mode):
        return f"{path} is a symbolic link"
    if info.st_mode & 0o022:
        return (
            f"{path} is writable by group or other (mode {oct(info.st_mode & 0o777)})"
        )
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
    """Create ``path`` and each level down from the receipt root at 0o700.

    ``Path.mkdir(parents=True, mode=0o700)`` does not do this. CPython applies the
    mode to the final component only; the parents get 0o777 masked by the umask.
    Measured under umask 002: ~/.ash/install-receipts came out 0o775 while only the leaf
    was 0o700. Unreachable inside ASH's container, where $HOME is 0750 or tighter, but
    perfectly reachable on a umask-002 developer host or runner.

    It stops at ``receipt_root()`` rather than walking up to $HOME, and that boundary is
    deliberate. ``receipt_root()``'s parent is ``~/.ash``, which is ASH's general
    per-user directory and the parent of the *default* ASH_BIN_PATH -- ``~/.ash/bin``,
    see ``core.constants`` -- not part of the receipt store. Tightening it from here cost
    two things. Writing a receipt would narrow a directory this code does not own, and
    other accounts need to traverse it to reach an installed toolchain. Worse, if
    ``~/.ash`` already exists owned by someone else -- root, from an earlier ``sudo``
    run -- ``os.chmod`` raises PermissionError, ``write_receipt`` swallows it because
    receipts are best-effort by design, and install idempotence is then off permanently
    behind a single warning, for a reason that has nothing to do with the receipts.

    Nothing is given up by stopping here. ``_receipt_trust_chain`` already ends at the
    receipt root, and ``_untrusted_reason`` rejects a receipt root owned by another uid
    -- so a directory an attacker substitutes for it is theirs, and is refused. A loose
    ``~/.ash`` therefore costs a redundant download, not a bad trust decision.
    """
    root = receipt_root()
    # Above the root, create without touching modes: those levels are shared with the
    # rest of ~/.ash and are not part of the trust chain.
    root.parent.mkdir(parents=True, exist_ok=True)
    levels = [path, *[p for p in path.parents if p == root or root in p.parents]]
    for level in reversed(levels):
        level.mkdir(exist_ok=True)
        if level.is_symlink():
            # ``os.chmod`` follows a link, so a link substituted for a receipt
            # level in a loose ~/.ash had its target made 0o700 and took the
            # receipt writes. Refused as an OSError, which write_receipt reports
            # as a receipt it could not write.
            raise _receipt_level_is_a_link(level)
        if platform.system() != "Windows":
            # The mode is set on a descriptor opened without following a link
            # (O_NOFOLLOW) and only on a directory (O_DIRECTORY): the check
            # above alone left the window make_executable's docstring names, in
            # which a link swapped in after it was followed by the chmod and
            # its target made 0o700.
            try:
                fd = os.open(level, os.O_RDONLY | os.O_DIRECTORY | _O_NOFOLLOW)
            except OSError as error:
                # EMLINK is what some BSDs give an O_NOFOLLOW open of a link;
                # ENOTDIR is a link to a file, or a file, at the level's name.
                if error.errno in (
                    errno.ELOOP,
                    getattr(errno, "EMLINK", errno.ELOOP),
                    errno.ENOTDIR,
                ):
                    raise _receipt_level_is_a_link(level) from error
                raise
            try:
                os.fchmod(fd, 0o700)
            finally:
                os.close(fd)


def _receipt_level_is_a_link(level: Path) -> OSError:
    return OSError(
        errno.ELOOP,
        f"{level} is a symbolic link; the receipt store is not written through a link",
        str(level),
    )


def read_receipt(destination: Path, installed_as: str) -> Optional[dict]:
    """Read an install receipt, or None if absent, unreadable or untrustworthy.

    An unreadable receipt is treated as absent rather than fatal: the recovery is
    to reinstall, and refusing to install because a cache marker is corrupt would
    be worse than the corruption.

    A receipt whose file or containing directory is writable by group or other is
    also treated as absent. Anyone who can rewrite it chooses the digest an installed
    scanner is checked against, which makes it worth nothing -- and re-downloading is
    the cheap, safe answer.

    So is a receipt whose directory cannot be traversed, or that has no usable home to
    live under: ``Path.is_file`` raises PermissionError for a directory this user may
    not search (pathlib swallows only a missing path), and that crashed every pinned
    install instead of reinstalling.
    """
    try:
        path = receipt_path(destination, installed_as)
        present = path.is_file()
    except OSError as e:
        ASH_LOGGER.debug(
            f"No install receipt for {installed_as} in {destination} can be read "
            f"({e}); treating it as absent"
        )
        return None
    if not present:
        return None
    # The directories by path, the file on the descriptor it is read from: judged
    # by path and then re-opened by path, a file swapped in between the check and
    # the read was read as trusted.
    for level in _receipt_trust_chain(path)[1:]:
        reason = _untrusted_reason(level)
        if reason is not None:
            ASH_LOGGER.warning(
                f"Ignoring install receipt at {path}: {reason}, so it cannot be "
                "trusted to say what was installed"
            )
            return None
    try:
        # O_NONBLOCK: a FIFO swapped in at the receipt path after the is_file
        # check would block this open; the regular-file check below refuses it.
        fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_BINARY | _O_NONBLOCK)
    except OSError as e:
        ASH_LOGGER.debug(f"Ignoring unreadable install receipt at {path} ({e})")
        return None
    try:
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            reason = (
                None
                if platform.system() == "Windows"
                else _untrusted_stat(path, info)
                or (None if stat.S_ISREG(info.st_mode) else f"{path} is not a file")
            )
            if reason is not None:
                ASH_LOGGER.warning(
                    f"Ignoring install receipt at {path}: {reason}, so it cannot be "
                    "trusted to say what was installed"
                )
                return None
            data = json.loads(handle.read().decode("utf-8"))
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
    path: Optional[Path] = None
    try:
        path = receipt_path(destination, installed_as)
        _private_dir(path.parent)
        path.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")
        if platform.system() != "Windows":
            os.chmod(path, 0o600)
    except OSError as e:
        where = f"to {path}" if path is not None else "anywhere"
        ASH_LOGGER.warning(
            f"Installed {installed_as} but could not write its install receipt "
            f"{where}: {e}. The next install will re-download it."
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
       unpinned install and cache a substituted binary forever. install_binary_from_url
       now refuses an unpinned install outright; this stays as the second guard.
    3. A receipt exists. A file with no receipt came from somewhere else -- a
       package manager, a nix profile, an ASH that predates receipts -- and must not
       be assumed to be the pinned version.
    4. The receipt names this exact url and pinned digest, so a version bump
       reinstalls rather than finding the old binary and reporting success.
    5. **The file on disk still hashes to what was installed.** This is the one a
       receipt alone cannot give: the pinned digest covers the release *archive*,
       not the extracted executable, so comparing it proves nothing about the file
       that will actually run.

    Why (5) is not paranoia. ASH's own image puts ASH_BIN_PATH first on PATH and
    runs ``ash dependencies install`` into it twice. Before idempotence
    existed every install re-downloaded, so the second run overwrote anything
    substituted in between -- the redundant download was accidentally a self-healing
    property. Skipping on a receipt alone would have converted that into a persistent
    one, in a directory other users may be able to write, in a tool whose output
    is used to make security decisions. Re-hashing costs well under a second on a
    30-100MB binary.
    """
    target = destination.joinpath(installed_as)
    # Not a link: a link planted at the install path to a file with the installed
    # bytes passed every check below and skipped every later install, while the
    # scan ran whatever the link named by then. Not installed, so the install
    # replaces the link through its staging rename. This lookup is an early
    # refusal only; what the file IS is read from the descriptor below.
    if target.is_symlink():
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
    # One descriptor for everything read or set about the file: what it is
    # (fstat), its bytes (the digest) and its mode (the repair). The install
    # directory may be writable by other users (the module docstring), so a
    # digest read through one open and a chmod through another were not pinned
    # to the same inode: the file could be swapped between them, and the mode
    # set on bytes nobody hashed.
    try:
        # O_NONBLOCK: a FIFO planted at the install path would block the open
        # itself, before the regular-file check below could refuse it. A
        # regular file reads the same with or without it.
        fd = os.open(target, os.O_RDONLY | _O_NOFOLLOW | _O_BINARY | _O_NONBLOCK)
    except OSError as e:
        ASH_LOGGER.debug(f"Could not open {target} ({e}); treating as not installed")
        return False
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            ASH_LOGGER.warning(
                f"{target} is not a regular file; treating it as not installed"
            )
            return False
        try:
            matches = _sha256_of_open_file(fd) == installed_digest
        except OSError as e:
            ASH_LOGGER.debug(
                f"Could not hash {target} ({e}); treating as not installed"
            )
            return False
        if not matches:
            ASH_LOGGER.warning(
                f"{target} no longer matches the digest recorded when it was "
                "installed; reinstalling"
            )
            return False
        if platform.system() == "Windows" or info.st_mode & 0o111:
            return True
        # The bytes match and the mode is wrong: a binary that lost its execute
        # bit was skipped as installed while no scan could run it. The bytes
        # were just verified on this descriptor, so the mode is put back on the
        # same descriptor rather than the file downloaded again. Only a file
        # with this one name: a second hard link would have another name's
        # mode changed with it, so that file is reinstalled instead (the
        # staging rename replaces the name, never the shared inode).
        if info.st_nlink != 1:
            ASH_LOGGER.warning(
                f"{target} is not executable and has another name on disk; "
                "reinstalling it"
            )
            return False
        ASH_LOGGER.warning(f"{target} was not executable; making it executable")
        try:
            os.fchmod(fd, stat.S_IMODE(info.st_mode) | 0o111)
        except OSError as e:
            ASH_LOGGER.warning(
                f"Could not make {target} executable ({e}); reinstalling it"
            )
            return False
        return bool(os.fstat(fd).st_mode & 0o111)
    finally:
        os.close(fd)


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
        expected_sha256: Pinned SHA256 to verify the download against. Required:
            ``None`` is refused before anything is fetched.
        force: Re-download even when a matching receipt exists

    Returns:
        Path to the installed binary

    Offline mode (``ASH_OFFLINE``, set by ``--offline``) downloads nothing: a
    receipted install is used, and with none the install is refused.

    Raises:
        ToolDownloadIntegrityError: if no digest is given, or the download does not
            match it.
        ToolNotProvisionableError: if ASH is offline and nothing is installed.
    """
    if not expected_sha256:
        # This used to download, log "integrity was not verified", chmod +x and
        # install. It was opengrep's only install path, so every opengrep ASH
        # provisioned was an unverified binary. There is no caller left that has a
        # reason to want that, so the parameter stays optional only in its type.
        raise ToolDownloadIntegrityError(
            f"Refusing to install {url} without a pinned SHA256: ASH installs no "
            "binary it cannot verify."
        )
    installed_as = rename_to if rename_to is not None else _url_basename(url)
    target = destination.joinpath(installed_as)

    if not force and _already_installed(
        destination, installed_as, url, expected_sha256
    ):
        ASH_LOGGER.info(
            f"{installed_as} already installed from {url}, skipping download"
        )
        return target

    if is_offline_mode():
        raise ToolNotProvisionableError(
            f"{installed_as} is not installed and ASH is offline (ASH_OFFLINE), so "
            f"{url} is not downloaded. Install it while online."
        )

    # Download the file, keeping the digest that was verified as the bytes landed.
    # It lands executable: the mode is set on the staged file's own descriptor
    # before the rename (_finalize_staged), as install_pinned_tool's binaries
    # are. A make_executable afterwards reopened the landed file by name, and
    # once _download_verified defaulted to 0o644 it was the only thing making
    # the binary runnable, with the install reported as done when it bailed.
    # The mode is named here, not left to a default: the binary's mode is this
    # installer's choice, whatever the download helpers' defaults read.
    binary_path, installed_digest = _download_verified(
        url, destination, rename_to, expected_sha256=expected_sha256, mode=0o755
    )

    # Platform-specific post-installation steps
    if platform.system() == "Darwin":
        unquarantine_macos_binary(binary_path)

    write_receipt(
        destination,
        installed_as,
        {
            "url": url,
            "sha256": expected_sha256.lower() if expected_sha256 else None,
            # The digest verified when the bytes landed, never a fresh hash of the file
            # taken here. make_executable has run by this point, and on macOS so has
            # unquarantine_macos_binary's xattr subprocess; see _finalize_staged for
            # what re-hashing after that window records instead.
            "installed_sha256": installed_digest,
            "installed_as": installed_as,
        },
    )

    return binary_path


def _unreadable_archive(
    archive_path: Path, cause: Exception
) -> ToolDownloadIntegrityError:
    """The typed error for an asset that is not the archive its name implies.

    Dispatch below is on the last two suffixes, and anything that is not ``.zip`` falls
    through to ``tarfile.open(..., "r:*")``. An asset with no recognizable archive
    extension -- a vendor publishing a bare executable, or changing an extension between
    releases -- therefore surfaced ``tarfile.ReadError``, which is outside the
    ``ToolDownloadIntegrityError`` contract every other rejection in this module honors
    and that three docstrings here promise.

    What that costs, stated at its real size rather than inflated: nothing in ASH catches
    either type today, so both reach the installer subprocess as a non-zero exit. The
    difference is a diagnosable message instead of a traceback out of the tarfile module,
    and a contract a caller can actually rely on if one ever does catch it.

    The zip branch needs the same treatment for ``zipfile.BadZipFile``, which is a
    different exception on a different code path -- fixing one arm would have left the
    other raising an untyped error.
    """
    return ToolDownloadIntegrityError(
        f"{archive_path.name} is not a readable zip or tar archive ({cause}); "
        "refusing to install from it"
    )


def _extract_single_member(
    archive_path: Path,
    member_name: str,
    target: Path,
    expected_member_sha256: Optional[str] = None,
) -> str:
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
    things follow, and since the destination directory can be writable by other
    users, none of them is hypothetical:

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

    ``expected_member_sha256``, when given, is the pinned digest of the member itself
    (``ToolAsset.executable_digest``). A member that does not hash to it is refused
    before it is renamed into place. The archive digest has already been checked by
    then, so this can only fire on a wrong entry in ``_EXECUTABLE_DIGESTS`` or an
    archive that holds a different executable than the one that was pinned. Either
    way the pin no longer describes what would be installed, and a binary already on
    disk could no longer be recognized by it, so the install stops.

    Returns:
        The SHA256 of the extracted member, verified after it landed at ``target``.
        Returned rather than left for the caller to recompute, because the caller records
        it in the install receipt and the pinned digest cannot stand in for it: the pin
        covers the release *archive* and says nothing about the executable inside. See
        ``_finalize_staged`` for why re-hashing ``target`` afterwards is a different
        value.

    Raises:
        ToolDownloadIntegrityError: if zero or more than one member matches, or if the
            asset is not a readable zip or tar archive.
    """
    suffixes = "".join(archive_path.suffixes[-2:]).lower()
    fd, staging = _open_staging(target)
    written = hashlib.sha256()
    # Whether the fd has been handed to a file object, which then owns closing it.
    # Set the moment fdopen takes it, not once the copy is through: a copy that
    # failed midway had its fd closed by the file object's exit, and the handler
    # below then closed it again, raising EBADF over the real error and skipping
    # the unlink of the partial staging file.
    fd_handed = False

    def _stage(source) -> None:
        nonlocal fd_handed
        sink = os.fdopen(fd, "wb")
        fd_handed = True
        with sink:
            for chunk in iter(lambda: source.read(_HASH_CHUNK_BYTES), b""):
                written.update(chunk)
                sink.write(chunk)

    try:
        # The inner handler converts only the two archive-format errors, and only
        # around the archive handling. It deliberately does not catch OSError: a
        # disk-full while staging is not "this asset is not an archive", and saying so
        # would be a wrong diagnosis rather than a missing one.
        try:
            if suffixes.endswith(".zip"):
                with zipfile.ZipFile(archive_path) as archive:
                    # Both separators: zipfile rewrites a backslash to "/" only
                    # where os.sep is a backslash, so on POSIX an archive built
                    # with backslash names keeps them, and a split on "/" alone
                    # found no member. Regular files only, as the tar branch
                    # requires: a zip can carry a symlink entry, whose bytes are
                    # the link's target path, not an executable.
                    matches = [
                        info
                        for info in archive.infolist()
                        if _zip_entry_is_a_regular_file(info)
                        and _archive_basename(info.filename) == member_name
                    ]
                    _require_one_match(matches, member_name, archive_path)
                    with archive.open(matches[0]) as source:
                        _stage(source)
            else:
                with tarfile.open(archive_path, "r:*") as archive:
                    matches = [
                        member
                        for member in archive.getmembers()
                        if member.isfile()
                        and _archive_basename(member.name) == member_name
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
        except (tarfile.ReadError, zipfile.BadZipFile) as e:
            raise _unreadable_archive(archive_path, e) from e

        if (
            expected_member_sha256 is not None
            and written.hexdigest() != expected_member_sha256.lower()
        ):
            raise ToolDownloadIntegrityError(
                f"{member_name} in {archive_path.name} does not match its pinned "
                f"executable digest (expected {expected_member_sha256.lower()}, found "
                f"{written.hexdigest()}). The archive matched its own pin, so the "
                "executable digest in tool_downloads.py is wrong or the archive holds "
                "a different executable; refusing to install it."
            )

        # 0o755, and the digest of what was written, are both handled here. See
        # _finalize_staged: the post-rename re-hash is what stops a race on the
        # staging path from getting an attacker's bytes recorded in the receipt as
        # though ASH had installed them, and returning that digest is what stops the
        # caller re-deriving it from the target after the fact.
        return _finalize_staged(staging, target, written.hexdigest())
    except BaseException:
        if not fd_handed:
            # The fd was never handed to fdopen, so nothing closed it.
            os.close(fd)
        staging.unlink(missing_ok=True)
        raise


def _archive_basename(name: str) -> str:
    """The last path component of an archive entry's name, either separator."""
    return re.split(r"[\\/]", name)[-1]


def _zip_entry_is_a_regular_file(info: zipfile.ZipInfo) -> bool:
    """Whether a zip entry is a regular file, by the Unix mode it may carry.

    A zip made on Unix stores the entry's mode in the high 16 bits of
    ``external_attr``; one made elsewhere stores 0 there, which is read as a
    plain file. A directory, a symlink or a device is never the executable.
    """
    if info.is_dir():
        return False
    kind = stat.S_IFMT(info.external_attr >> 16)
    return kind in (0, stat.S_IFREG)


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


# Directory of release assets kept between runs, set by CI (ASH_TOOL_DOWNLOAD_CACHE).
#
# It holds the downloaded release ASSETS, never extracted binaries and never install
# receipts. That choice is what lets a restored copy be re-verified against a trust
# anchor the cache cannot touch: the pinned digest in tool_downloads covers the asset
# itself, and it lives in the repository. Caching the extracted executables would
# need their digests from somewhere, and the only record of those is the install
# receipt -- which receipt_root keeps out of every bin directory precisely so that
# whatever can write binaries cannot also rewrite the digests they are checked
# against. A cache holding both would be exactly that.
#
# So a cached asset is used only if it hashes to the pinned digest, every time it is
# read. Anything else -- a tampered file, a truncated one, a stale version under the
# same name -- is deleted and the asset is downloaded and verified as if the cache
# were empty. The operator approved caching these public, digest-pinned upstream
# release assets in the Actions cache; ASH's own wheel and image never go here.
_TOOL_DOWNLOAD_CACHE_ENV = "ASH_TOOL_DOWNLOAD_CACHE"


#: The relative cache values already warned about in this process.
_warned_relative_cache: set = set()


def _tool_download_cache() -> Optional[Path]:
    """The release-asset cache directory, or None when there is none to use.

    An absolute path only. The install commands run in an empty directory of
    their own (``utils/python_child.py``), so a relative value named a directory
    under that one: the cache never hit, and the assets stored there went with
    the directory. Such a value is not used, and says so once.
    """
    value = os.environ.get(_TOOL_DOWNLOAD_CACHE_ENV, "").strip()
    if not value:
        return None
    if not os.path.isabs(value):
        if value not in _warned_relative_cache:
            _warned_relative_cache.add(value)
            ASH_LOGGER.warning(
                f"{_TOOL_DOWNLOAD_CACHE_ENV}={value!r} is not an absolute path; the "
                "install command runs in a directory of its own, where a relative "
                "path names another place, so the tool download cache is not used. "
                "Set it to an absolute path."
            )
        return None
    return Path(value)


# The cache directory is restored from the Actions cache, so every entry in it is
# untrusted -- including what KIND of entry it is. A symlink planted at an asset's
# name would make a read follow it to any file on the runner, and a write follow it
# to anywhere the job can write. So nothing here follows a link: entries are judged
# by lstat, opened with O_NOFOLLOW where the platform has it, and written by
# os.replace of a temporary file, which replaces whatever sits at the name -- link
# included -- rather than writing through it.
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_BINARY = getattr(os, "O_BINARY", 0)
#: So an open of a cache entry that is not a regular file (a FIFO swapped in
#: after the lstat) returns at once instead of blocking for a writer.
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


def _usable_cache_dir(cache_dir: Path) -> bool:
    """The cache root must be a real directory, not a link to one, if it exists."""
    try:
        st = os.lstat(cache_dir)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    if stat.S_ISDIR(st.st_mode):
        return True
    ASH_LOGGER.warning(
        f"{_TOOL_DOWNLOAD_CACHE_ENV}={cache_dir} is not a plain directory; "
        "not using the tool download cache"
    )
    return False


def _discard_cache_entry(path: Path, why: str) -> None:
    """Remove a cache entry without following it, whatever it is.

    A directory at an asset's name is removed with what it holds: ``unlink``
    alone could not remove it, so it stayed, and every run logged this line and
    downloaded the asset again. The cache directory is ASH's own, restored from
    a CI cache, so nothing under an asset's name is anything but junk.
    """
    ASH_LOGGER.warning(f"Discarding cached {path.name}: {why}. Downloading it again.")
    try:
        kind = os.lstat(path).st_mode
    except OSError:
        return
    try:
        if stat.S_ISDIR(kind):
            shutil.rmtree(path)
        else:
            os.unlink(path)  # removes a symlink itself, never its target
    except OSError as error:
        ASH_LOGGER.warning(f"Could not discard cached {path.name}: {error}")


def _restore_cached_asset(
    asset_name: str, expected_sha256: str, staging_dir: Path
) -> Optional[Path]:
    """A verified copy of a cached release asset in ``staging_dir``, or None.

    The copy is hashed after it lands in the private staging directory, so the bytes
    that get extracted are the bytes that were verified, whatever happens to the
    cache directory in between. A cached entry that is anything but a regular file
    -- a symlink above all -- is removed unread.
    """
    cache_dir = _tool_download_cache()
    if cache_dir is None or not _usable_cache_dir(cache_dir):
        return None
    cached = cache_dir.joinpath(asset_name)
    try:
        st = os.lstat(cached)
    except FileNotFoundError:
        return None
    except OSError as e:
        ASH_LOGGER.debug(f"Could not stat cached {asset_name}: {e}")
        return None
    if not stat.S_ISREG(st.st_mode):
        _discard_cache_entry(cached, "not a regular file")
        return None
    staged = staging_dir.joinpath(asset_name)
    try:
        # O_NOFOLLOW closes the gap between the lstat above and this open: a link
        # swapped in meanwhile makes the open fail instead of being followed, and
        # O_NONBLOCK keeps a FIFO swapped in from blocking the open. What the
        # descriptor names is checked once more on it.
        fd = os.open(cached, os.O_RDONLY | _O_NOFOLLOW | _O_BINARY | _O_NONBLOCK)
    except OSError as e:
        _discard_cache_entry(cached, str(e))
        return None
    # The copy tells a failure on the cache side (the entry cannot be read) from
    # one on the staging side (the private directory cannot be written, a full
    # TMPDIR): only the first says anything about the entry. The entry used to be
    # discarded for either, destroying the only offline install source over a
    # local condition. Either outcome is only recorded inside the two ``with``
    # blocks and acted on once both files are closed: the discard removed the
    # entry while ``source`` still held it open, and a failed copy unlinked the
    # staging file while ``target`` held it open, which Windows refuses
    # (PermissionError, the file is in use) and so turned a kept-entry fallback
    # into an install failure. The ``with target`` block is what the staging-side
    # handler wraps, so the error a close raises when it flushes the last
    # buffered bytes (ENOSPC, EDQUOT, EIO on a quota or network TMPDIR) is a
    # staging-side failure too, where it used to escape the function. A partial
    # staging file is not removed here: ``staging_dir`` is the caller's
    # TemporaryDirectory, removed whole.
    cache_failure: Optional[str] = None
    staging_failure: Optional[str] = None
    source = os.fdopen(fd, "rb")
    with source:
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                cache_failure = "not a regular file"
        except OSError as e:
            cache_failure = str(e)
        if cache_failure is None:
            try:
                with open(staged, "wb") as target:
                    while True:
                        try:
                            chunk = source.read(_HASH_CHUNK_BYTES)
                        except OSError as e:
                            cache_failure = str(e)
                            break
                        if not chunk:
                            break
                        target.write(chunk)
            except OSError as e:
                staging_failure = str(e)
    if cache_failure is not None:
        _discard_cache_entry(cached, cache_failure)
        return None
    if staging_failure is not None:
        ASH_LOGGER.warning(
            f"Could not stage cached {asset_name} in {staging_dir}: "
            f"{staging_failure}. The cache entry is kept; downloading it again."
        )
        return None
    try:
        verify_sha256(staged, expected_sha256, f"cached asset {cached}")
    except ToolDownloadIntegrityError as e:
        staged.unlink(missing_ok=True)
        _discard_cache_entry(cached, str(e))
        return None
    except OSError as e:
        staged.unlink(missing_ok=True)
        ASH_LOGGER.warning(
            f"Could not read back the staged copy of {asset_name}: {e}. The cache "
            "entry is kept; downloading it again."
        )
        return None
    ASH_LOGGER.info(f"Using cached {asset_name}, verified against its pinned digest")
    return staged


def _store_cached_asset(archive: Path, asset_name: str) -> None:
    """Keep a verified download for the next run. Best effort: a failure costs a download.

    Written to a temporary file in the cache directory and moved into place with
    os.replace, which swaps whatever is at the name -- a planted symlink included --
    for the new file instead of writing through it.
    """
    cache_dir = _tool_download_cache()
    if cache_dir is None or not _usable_cache_dir(cache_dir):
        return
    tmp_path: Optional[str] = None
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=cache_dir, prefix=".ash-asset-")
        with os.fdopen(fd, "wb") as target, open(archive, "rb") as source:
            shutil.copyfileobj(source, target)
        os.replace(tmp_path, cache_dir.joinpath(asset_name))
        tmp_path = None
    except OSError as e:
        ASH_LOGGER.debug(f"Could not cache {asset_name} in {cache_dir}: {e}")
    finally:
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


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

    Offline mode (``ASH_OFFLINE``, set by ``--offline``) downloads nothing: an
    installed copy or a verified copy already present is used as at any other time,
    a verified copy in the release-asset cache is installed from there, and with
    none of those the install is refused.

    Raises:
        ToolNotProvisionableError: if the tool publishes nothing for this platform,
            or ASH is offline and has no verified copy to install from
        ToolDownloadIntegrityError: if the download does not match its pinned digest
    """
    from automated_security_helper.utils.tool_downloads import get_tool_asset

    asset = get_tool_asset(tool, target_platform, arch)
    bin_dir = Path(destination) if destination is not None else current_bin_path()
    if bin_dir is None:
        raise RuntimeError(NO_BIN_DIRECTORY)
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

    if not force:
        present = find_verified_pinned_executable(tool, target_platform, arch, bin_dir)
        if present is not None:
            ASH_LOGGER.info(
                f"{present.tool} {present.version} is already present at "
                f"{present.path} (SHA256 {present.sha256} matches the pin); "
                "not installing a second copy"
            )
            return present.path

    with tempfile.TemporaryDirectory(prefix="ash-tool-download-") as staging:
        staging_dir = Path(staging)
        asset_name = _url_basename(asset.url)
        # A verified cached copy, or a fresh verified download that is then cached.
        # Both are hashed against the pin in this private directory before use.
        downloaded = _restore_cached_asset(asset_name, asset.sha256, staging_dir)
        if downloaded is None and is_offline_mode():
            raise ToolNotProvisionableError(
                f"{asset.tool} {asset.version} is not installed and ASH is offline "
                "(ASH_OFFLINE), so nothing is downloaded. Install it while online, or "
                f"put a copy that matches the pin in {bin_dir}."
            )
        if downloaded is None:
            downloaded = download_file(
                asset.url,
                staging_dir,
                rename_to=asset_name,
                expected_sha256=asset.sha256,
                # An archive is data; the executable asset is placed below with
                # the mode an executable gets.
                mode=0o644 if asset.archive else 0o755,
            )
            _store_cached_asset(downloaded, asset_name)
        if not asset.archive:
            # The asset is the executable (opengrep). It goes to its final name through
            # the same staged, symlink-safe, pin-checked rename the unarchived URL path
            # uses; _replace_atomically refuses anything but the pinned digest.
            installed_digest = _replace_atomically(
                downloaded, target, expected_sha256=asset.sha256
            )
        else:
            installed_digest = _extract_single_member(
                downloaded,
                asset.member_name,
                target,
                expected_member_sha256=asset.executable_digest,
            )

    # The mode was set on the staged file's own descriptor before the rename
    # (_finalize_staged), on both install paths. No make_executable here: it
    # returns at once on Windows, where there is no execute bit to set, and on
    # POSIX it reopened by name a file the staged rename had already finished.
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
            #
            # Taken from the extraction, which verified it as the bytes landed, rather
            # than by hashing the target here -- make_executable and, on macOS,
            # unquarantine_macos_binary's xattr subprocess have run in between, in a
            # directory other users may be able to write. See _finalize_staged.
            "installed_sha256": installed_digest,
            "installed_as": asset.install_as,
        },
    )
    ASH_LOGGER.info(f"Installed {asset.tool} {asset.version} to {target}")
    return target


def _executable_by_caller(candidate: Path, info: os.stat_result) -> bool:
    """Whether the file behind ``info``, found at ``candidate``, is executable by
    this process.

    Two readings, both required. The kernel's, ``os.access(candidate, X_OK)``,
    which knows what a reimplementation from the mode bits did not: ACLs, a
    ``noexec`` mount (where the bits say executable and the kernel refuses to
    run the file, so the install was skipped in favour of a copy that could not
    run), and root's rule that any execute bit is enough (the image runs
    ``ash dependencies install`` as root). And the mode bits on ``info``, the
    descriptor's own stat: a candidate with no execute bit at all is not
    installed, whatever the kernel would let this caller do with it. The file
    type and the hash are read on the same descriptor, so the by-name access
    check adds nothing a swapped link could exploit.
    """
    return bool(info.st_mode & 0o111) and os.access(candidate, os.X_OK)


@dataclass(frozen=True)
class VerifiedPresentTool:
    """A pinned tool found on disk whose bytes hash to its pinned executable digest."""

    tool: str
    version: str
    path: Path
    sha256: str


def find_verified_pinned_executable(
    tool: str, target_platform: str, arch: str, destination: Path
) -> Optional[VerifiedPresentTool]:
    """Find a copy of the pinned ``tool`` that is already installed, by its bytes.

    Why this exists: ASH's container image installs syft, grype and trivy into
    /usr/local/bin from their pinned release assets, and then runs
    ``ash dependencies install`` twice -- once as root, once as the non-root user
    -- which installed the pinned grype and syft again into ASH_BIN_PATH each time.
    Each copy is a separate image layer, 167 MB for the two tools per stage.

    A candidate is accepted only if it is a regular file (not a symlink), is
    executable, and its bytes hash to ``executable_digest``, the pinned SHA256 of
    the executable inside the verified release archive. The name proves nothing: a
    same-named binary from a package manager, another version, or a file someone
    replaced does not hash to the pin, so it is reported as not present and the
    verified install runs exactly as it did before this existed. The version is
    not checked separately because it does not need to be: the digest is pinned
    per release asset, so a match is that release's binary.

    Where it looks, and why only there:

    1. ``destination``/``install_as``, where the install would write. If anything
       is at that path -- a file, a symlink, a dangling symlink -- it is the only
       candidate. A file there that does not verify is what the install is about
       to replace, and accepting some other copy instead would leave it in place
       to shadow that copy whenever ``destination`` is on PATH, which in the
       image it is. A symlink there is never accepted, even to the right bytes:
       its target can change after this check, and the install replaces the link
       itself with a real file.
    2. Otherwise, what ``find_executable(tool)`` resolves -- the lookup a scanner
       makes at run time -- but only if that file sits in one of
       ``subprocess_utils.path_independent_dirs()``. Skipping the install is only
       correct if every later scan finds the verified copy, and a copy found only
       through this process's PATH may be invisible to a scan run from another
       shell, a CI job or a cron entry. One in ASH_BIN_PATH or /usr/local/bin is
       found by ``find_executable`` whatever PATH holds.

    The file is re-hashed on every call. Nothing is cached and no receipt is
    consulted, so a binary replaced after a previous run is caught on the next one,
    the same property ``_already_installed`` keeps for receipts.

    Returns:
        The verified copy, or None when there is no pinned executable digest for
        this asset, no acceptable candidate, or the candidate's bytes do not match.

    Raises:
        ToolNotProvisionableError: as ``get_tool_asset`` does.
    """
    from automated_security_helper.utils.tool_downloads import get_tool_asset

    asset = get_tool_asset(tool, target_platform, arch)
    expected = asset.executable_digest
    if expected is None:
        return None

    at_destination = Path(destination).joinpath(asset.install_as)
    if os.path.lexists(at_destination):
        candidate = at_destination
    else:
        found = subprocess_utils.find_executable(asset.tool)
        if not found:
            return None
        candidate = Path(found)
        try:
            # Anchored only, as find_executable searches them: resolve() would
            # read a relative ASH_BIN_PATH against the working directory.
            allowed = {
                d.resolve()
                for d in subprocess_utils.path_independent_dirs()
                if subprocess_utils._is_anchored(str(d))
            }
            in_allowed = candidate.parent.resolve() in allowed
        except OSError:
            in_allowed = False
        if not in_allowed:
            ASH_LOGGER.debug(
                f"{candidate} is outside the directories every scan searches; "
                f"installing {tool} rather than relying on this PATH"
            )
            return None

    if candidate.is_symlink():
        return None
    # Judged on one open descriptor from here: is_file and os.access by name and
    # then a plain open that follows a link left a window in which a link swapped
    # in at the candidate's name, pointing at the pinned bytes, was accepted,
    # against the rule above that a symlink here is never accepted. O_NOFOLLOW
    # refuses such a link at the open, O_NONBLOCK keeps a FIFO there from blocking
    # it, and the file type, the mode and the hash are all read from what was
    # opened.
    try:
        fd = os.open(candidate, os.O_RDONLY | _O_NOFOLLOW | _O_BINARY | _O_NONBLOCK)
    except OSError as e:
        ASH_LOGGER.debug(f"Could not open {candidate} ({e}); installing {tool}")
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return None
        if platform.system() != "Windows" and not _executable_by_caller(
            candidate, info
        ):
            return None
        actual = _sha256_of_open_file(fd)
    except OSError as e:
        ASH_LOGGER.debug(f"Could not hash {candidate} ({e}); installing {tool}")
        return None
    finally:
        os.close(fd)
    if actual != expected.lower():
        ASH_LOGGER.debug(
            f"{candidate} is named {asset.install_as} but is not the pinned "
            f"{tool} {asset.version} (SHA256 {actual}, pinned {expected.lower()}); "
            "installing the pinned build"
        )
        return None
    return VerifiedPresentTool(
        tool=asset.tool, version=asset.version, path=candidate, sha256=actual
    )


def current_bin_path() -> Optional[Path]:
    """Resolve ASH_BIN_PATH at call time rather than at import time.

    ``core.constants.ASH_BIN_PATH`` is computed when that module is first imported.
    ``ash dependencies install --bin-path`` sets the environment variable *after*
    that import has happened, so a function that closed over the constant would
    install into the default directory while reporting the requested one.

    Absolute, because the install commands built from it run in an empty directory
    of their own (``utils/python_child.py``), where a relative path names another
    place.

    None when ASH_BIN_PATH is unset and there is no default either, because there
    is no usable home for ``~/.ash/bin`` (``core.constants.home_bin_path``):
    nothing can be installed then (:data:`NO_BIN_DIRECTORY`).
    """
    from_env = ash_bin_path_from_environment()
    if from_env:
        # Read against the working directory here, where the caller named it,
        # not against the empty directory the install command later runs in.
        return Path(os.path.abspath(from_env))
    if ASH_BIN_PATH is None:
        warn_if_home_unusable()
    return ASH_BIN_PATH


#: Why nothing is installed when :func:`current_bin_path` has no directory.
NO_BIN_DIRECTORY = (
    "ASH has no bin directory to install tools into: ASH_BIN_PATH is not an "
    "absolute path, and HOME is empty or relative, so ~/.ash/bin is not used. Set "
    "ASH_BIN_PATH or HOME to an absolute path, or give ash dependencies install a "
    "--bin-path."
)


def refusing_install_command(reason: str) -> CustomCommand:
    """An install command that writes ``reason`` to stderr and exits 1.

    Plugins build their install commands whenever they are constructed, a scan
    included, so one that cannot install is declared as this rather than raised:
    ``ash dependencies install`` runs it, counts it as failed and shows why. The
    reason travels as an argument rather than inside the ``-c`` source, so nothing
    in it is read as code.
    """
    return CustomCommand(
        args=[sys.executable, "-c", "import sys; sys.exit(sys.argv[1])", reason],
        shell=False,
    )


# The script every pinned-tool install command runs. A constant so that
# pinned_install_already_satisfied can recognize these commands by exact text.
_PINNED_TOOL_INSTALL_SCRIPT = (
    "import sys; from pathlib import Path; "
    "from automated_security_helper.utils.download_utils import install_pinned_tool; "
    "install_pinned_tool(sys.argv[1], sys.argv[2], sys.argv[3], Path(sys.argv[4]))"
)


def create_pinned_tool_install_command(
    tool: str,
    target_platform: str,
    arch: str,
    destination: str | None = None,
) -> CustomCommand:
    """Build the CustomCommand that installs a pinned tool in a subprocess.

    Mirrors ``create_url_download_command``, which installs an opengrep version the
    configuration pins itself, so the installer keeps one execution model for every
    tool: plugins declare commands, the CLI runs them and counts them. With no
    destination and no bin directory, the command only refuses.
    """
    # Absolute either way: the command runs in an empty directory of its own.
    if destination is None:
        bin_dir = current_bin_path()
        if bin_dir is None:
            return refusing_install_command(NO_BIN_DIRECTORY)
        destination = _destination_text(bin_dir)
    else:
        destination = _destination_text(Path(destination).absolute())

    return CustomCommand(
        args=[
            sys.executable,
            "-c",
            _PINNED_TOOL_INSTALL_SCRIPT,
            tool,
            target_platform,
            arch,
            destination,
        ],
        shell=False,
    )


def _destination_text(path: "Path | str") -> str:
    """The destination as an install command's argument.

    Forward slashes on Windows only, where either separator names the same
    directory. On POSIX a backslash is an ordinary filename character, so the
    rewrite there named another directory than ASH_BIN_PATH.
    """
    text = str(path)
    return text.replace("\\", "/") if os.name == "nt" else text


def pinned_install_already_satisfied(
    args: "list[str]",
) -> "Optional[VerifiedPresentTool]":
    """For an argv built by ``create_pinned_tool_install_command``: is it a no-op?

    ``ash dependencies install`` runs each plugin's install commands as argv lists
    and only sees an exit code, so a pinned install that found its tool already
    present would read as INSTALLED. Calling this first lets the installer skip
    the subprocess and report the tool as present and verified instead, naming the
    path and digest it checked.

    Recognized by the exact script text, which only ``create_pinned_tool_install_command``
    produces, rather than by sniffing tool names out of arbitrary commands. Any other
    argv, or one whose tool has no pinned executable digest, returns None and is run
    as before.
    """
    if len(args) != 7 or args[1] != "-c" or args[2] != _PINNED_TOOL_INSTALL_SCRIPT:
        return None
    tool, target_platform, arch, destination = args[3:7]
    try:
        return find_verified_pinned_executable(
            tool, target_platform, arch, Path(destination)
        )
    except ToolNotProvisionableError:
        # Let the install command itself report it, with its own message.
        return None


def create_url_download_command(
    url: str,
    destination: str | None = None,
    rename_to: str | None = None,
    expected_sha256: str | None = None,
) -> CustomCommand:
    """Create a CustomCommand to download and install a binary from a URL.

    Args:
        url: The URL to download from
        destination: The directory to install the binary to (defaults to ASH_BIN_PATH)
        rename_to: Optional name to rename the binary to
        expected_sha256: SHA256 the download must match. Required; the default of
            ``None`` exists only so a caller that omits it gets this error instead
            of a TypeError that does not say why.

    Returns:
        CustomCommand object

    Raises:
        ValueError: if ``expected_sha256`` is missing or not 64 hex characters. The
            command would be refused when it ran anyway; refusing here names the
            caller that built it.
    """
    if not expected_sha256 or len(expected_sha256) != 64:
        raise ValueError(
            f"create_url_download_command({url!r}) needs expected_sha256, a 64-character "
            "hex SHA256: ASH installs no binary it cannot verify."
        )
    # Plain hex digits only. int(x, 16) also accepted a 0x prefix, underscores, a
    # sign and surrounding whitespace, so such a pin passed here and failed at
    # install time as an integrity mismatch, which reads as a tampered asset.
    if not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256):
        raise ValueError(f"expected_sha256 for {url!r} is not hex: {expected_sha256!r}")
    # Use the provided destination or get the current ASH_BIN_PATH.
    #
    # Resolved from the environment rather than from the imported constant. The
    # constant is fixed when core.constants is first imported, which happens before
    # `ash dependencies install --bin-path X` exports ASH_BIN_PATH -- so opengrep
    # installed into the default directory while the installer reported the
    # requested one, and the post-install sweep then found nothing there.
    # With no bin directory the command only refuses, and nothing is created here.
    # Forward slashes for cross-platform compatibility, and absolute either way:
    # the command runs in an empty directory of its own.
    if destination is None:
        bin_dir = current_bin_path()
        if bin_dir is None:
            return refusing_install_command(NO_BIN_DIRECTORY)
        destination = _destination_text(bin_dir)
    else:
        destination = _destination_text(Path(destination).absolute())

    # No directory is created here. OpengrepScanner builds this command when it is
    # constructed, during a scan, so creating current_bin_path() here made a
    # relative ASH_BIN_PATH under the scanned checkout (and raised in a read-only
    # one). install_binary_from_url creates it when the command runs.

    # An absent rename_to travels as an empty argument: an empty name is no
    # filename, so it cannot collide with a real one, where the string 'None'
    # it used to travel as could not be told from a binary to be named None.
    script = (
        "import sys; from pathlib import Path; "
        "from automated_security_helper.utils.download_utils import install_binary_from_url; "
        "install_binary_from_url(sys.argv[1], Path(sys.argv[2]), sys.argv[4] or None, expected_sha256=sys.argv[3])"
    )
    return CustomCommand(
        args=[
            sys.executable,
            "-c",
            script,
            url,
            str(destination),
            expected_sha256.lower(),
            str(rename_to) if rename_to is not None else "",
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

    # platform.machine() answers "AMD64" on Windows and "x86_64" or "aarch64"
    # elsewhere; the comparisons below are on the lowercase names.
    arch = arch.lower()  # type: ignore[assignment]

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
        # opengrep publishes one Windows build, for x86-64. Windows 11 on ARM
        # runs x86-64 executables under emulation, so an arm64 request gets that
        # build too, said once: refusing it here failed a working install, and
        # did so where the scanner builds its install commands.
        if arch in ("amd64", "x86_64", "arm64", "aarch64"):
            if arch in ("arm64", "aarch64"):
                ASH_LOGGER.info(
                    "opengrep has no Windows arm64 build; installing its x86-64 "
                    "build, which Windows on ARM runs under emulation"
                )
            return f"{base_url}/opengrep_windows_x86.exe"

    # Default case
    raise ValueError(f"Unsupported platform/architecture: {target_platform}/{arch}")
