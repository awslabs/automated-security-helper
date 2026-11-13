# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The download and install path at its edges: stalled or cut-short transfers, a link
at the install or staging path, and a home or receipt store that is not there.

Each test pins one property of utils/download_utils.py:

- the fetch bounds every socket operation, so a stalled connection ends the attempt
  as a TimeoutError the retry policy repeats;
- a body the server cuts short is retried, not accepted and then reported as a
  digest mismatch;
- the staged file's mode is set on the file that was hashed, never through a link
  renamed over the staging name;
- with no usable home there is no receipt store: an install still installs, the
  receipt is skipped with a warning, and nothing raises;
- a receipt directory this user cannot search reads as no receipt;
- a symlink at the install path is not an installed tool;
- a copy that fails while staging an archive member raises the copy's own error
  and removes the partial staging file, instead of closing the staging fd twice.
"""

from __future__ import annotations

import errno
import hashlib
import http.client
import inspect
import io
import logging
import os
import platform
import stat
import zipfile

import pytest

from automated_security_helper.core.exceptions import ToolDownloadIntegrityError
from automated_security_helper.utils import download_utils

pytestmark = pytest.mark.unit

_URL = "https://example.invalid/tool.bin"
_BODY = b"the whole asset, every byte of it"
_DIGEST = hashlib.sha256(_BODY).hexdigest()

posix_only = pytest.mark.skipif(
    platform.system() == "Windows", reason="file modes and symlinks on POSIX only"
)
not_root = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="root traverses anything"
)


_UNSET = object()


class _Response:
    """What urlopen yields: a body read in chunks, a Content-Length header, and
    http.client's ``chunked`` flag (True when Transfer-Encoding: chunked framed the
    body, in which case http.client ignores any Content-Length).

    The headers are an ``HTTPMessage``, as a real response's are, so a lookup is
    case-insensitive; ``header`` spells the name another way. ``length`` is
    http.client's parsed length: a number, or None for a chunked body or a header
    it rejected. Left out, the object carries no such field, as a fake or another
    client's response does; a chunked response sets it to None, as http.client
    does."""

    def __init__(
        self,
        body: bytes,
        declared,
        chunked: bool = False,
        length=_UNSET,
        header: str = "Content-Length",
    ):
        self._body = io.BytesIO(body)
        self.headers = http.client.HTTPMessage()
        self.headers[header] = str(declared)
        self.chunked = chunked
        if chunked and length is _UNSET:
            length = None
        if length is not _UNSET:
            self.length = length

    def read(self, amount=-1):
        chunk = self._body.read(amount)
        # As http.client does: ``length`` is the number of bytes still to read, so
        # it goes down with every read and is 0 after a whole body. A fake that
        # kept it constant would have let the product read the field during or
        # after its loop and still pass here.
        if getattr(self, "length", None) is not None:
            self.length -= len(chunk)
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def quick_retry(monkeypatch):
    monkeypatch.setenv("ASH_DOWNLOAD_MAX_ATTEMPTS", "2")
    monkeypatch.setenv("ASH_DOWNLOAD_RETRY_DELAY", "0")
    monkeypatch.setattr(download_utils.time, "sleep", lambda _s: None)


def test_the_fetch_bounds_every_socket_operation(monkeypatch, tmp_path, quick_retry):
    seen = {}

    def urlopen(url, **kwargs):
        seen.update(kwargs)
        return _Response(_BODY, len(_BODY))

    monkeypatch.setattr(download_utils.urllib.request, "urlopen", urlopen)
    download_utils.download_file(_URL, tmp_path / "bin", expected_sha256=_DIGEST)
    assert seen.get("timeout") == download_utils._DOWNLOAD_SOCKET_TIMEOUT_SECONDS
    assert seen["timeout"] > 0


def test_a_body_cut_short_is_retried_not_reported_as_tampering(
    monkeypatch, tmp_path, quick_retry
):
    attempts = []

    def urlopen(url, **kwargs):
        attempts.append(url)
        # The first connection closes after half the body; the second is whole.
        body = _BODY[: len(_BODY) // 2] if len(attempts) == 1 else _BODY
        return _Response(body, len(_BODY))

    monkeypatch.setattr(download_utils.urllib.request, "urlopen", urlopen)
    installed = download_utils.download_file(
        _URL, tmp_path / "bin", expected_sha256=_DIGEST
    )
    assert len(attempts) == 2
    assert installed.read_bytes() == _BODY
    # The first attempt's partial file is gone: only the installed file remains.
    assert [p.name for p in (tmp_path / "bin").iterdir()] == ["tool.bin"]


def test_a_body_cut_short_on_the_last_attempt_raises_the_connection_error(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("ASH_DOWNLOAD_MAX_ATTEMPTS", "1")
    monkeypatch.setattr(
        download_utils.urllib.request,
        "urlopen",
        lambda url, **kwargs: _Response(_BODY[:5], len(_BODY)),
    )
    with pytest.raises(ConnectionError, match="closed after 5 of"):
        download_utils.download_file(_URL, tmp_path / "bin", expected_sha256=_DIGEST)
    assert not (tmp_path / "bin" / "tool.bin").exists()
    # No staging file is left beside where the tool would have been installed.
    bin_dir = tmp_path / "bin"
    assert not bin_dir.exists() or [p.name for p in bin_dir.iterdir()] == []


def test_a_content_length_header_is_found_whatever_its_case(monkeypatch, tmp_path):
    """A response's headers are looked up without regard to case; a fake holding a
    plain dict under the one spelling hid a lookup that would have missed
    ``content-length``."""
    monkeypatch.setenv("ASH_DOWNLOAD_MAX_ATTEMPTS", "1")
    monkeypatch.setattr(
        download_utils.urllib.request,
        "urlopen",
        lambda url, **kwargs: _Response(_BODY[:5], len(_BODY), header="content-length"),
    )
    with pytest.raises(ConnectionError, match="closed after 5 of"):
        download_utils.download_file(_URL, tmp_path / "bin", expected_sha256=_DIGEST)


class _StallsAfterTheFirstChunk(_Response):
    """A body whose socket times out in the middle of the transfer."""

    def __init__(self, body: bytes, declared):
        super().__init__(body, declared)
        self._reads = 0

    def read(self, amount=-1):
        self._reads += 1
        if self._reads > 1:
            raise TimeoutError("the read timed out")
        return self._body.read(5)


def test_a_timeout_in_the_middle_of_the_body_is_retried(
    monkeypatch, tmp_path, quick_retry
):
    """The connect timeout is covered above; this one fires after bytes have
    arrived. The attempt ends as a TimeoutError the retry policy repeats, and the
    second connection delivers the whole file."""
    attempts = []

    def urlopen(url, **kwargs):
        attempts.append(url)
        if len(attempts) == 1:
            return _StallsAfterTheFirstChunk(_BODY, len(_BODY))
        return _Response(_BODY, len(_BODY))

    monkeypatch.setattr(download_utils.urllib.request, "urlopen", urlopen)
    installed = download_utils.download_file(
        _URL, tmp_path / "bin", expected_sha256=_DIGEST
    )
    assert len(attempts) == 2
    assert installed.read_bytes() == _BODY
    assert hashlib.sha256(installed.read_bytes()).hexdigest() == _DIGEST
    assert [p.name for p in (tmp_path / "bin").iterdir()] == ["tool.bin"]


@posix_only
def test_the_staged_files_mode_is_never_set_through_a_link(tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.write_bytes(_BODY)
    os.chmod(elsewhere, 0o600)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    staging = bin_dir / ".tool.ash-partial"
    staging.symlink_to(elsewhere)
    with pytest.raises(OSError):
        download_utils._finalize_staged(staging, bin_dir / "tool", _DIGEST, mode=0o755)
    assert stat.S_IMODE(elsewhere.stat().st_mode) == 0o600
    assert not (bin_dir / "tool").exists()


@posix_only
def test_with_no_usable_home_receipts_are_skipped_and_nothing_raises(
    monkeypatch, tmp_path, caplog
):
    monkeypatch.setenv("HOME", "")
    with pytest.raises(download_utils.ReceiptStoreUnavailable):
        download_utils.receipt_root()
    assert download_utils.read_receipt(tmp_path / "bin", "tool") is None
    written = download_utils.write_receipt(
        tmp_path / "bin", "tool", {"url": _URL, "sha256": _DIGEST}
    )
    assert written is None
    assert not download_utils._already_installed(
        tmp_path / "bin", "tool", _URL, _DIGEST
    )


@posix_only
def test_an_install_with_no_usable_home_still_installs_and_warns_once(
    monkeypatch, tmp_path, caplog
):
    """The receipt is skipped, the tool is not: the install returns the installed
    file, and the one thing said about the missing store is a WARNING that names the
    receipt and says the next install downloads again."""
    monkeypatch.setenv("HOME", "")
    monkeypatch.setattr(
        download_utils.urllib.request,
        "urlopen",
        lambda url, **kwargs: _Response(_BODY, len(_BODY)),
    )
    with caplog.at_level(logging.WARNING):
        installed = download_utils.install_binary_from_url(
            _URL, tmp_path / "bin", expected_sha256=_DIGEST
        )
    assert installed.read_bytes() == _BODY
    warnings = [
        record.getMessage()
        for record in caplog.records
        if record.levelno >= logging.WARNING and "receipt" in record.getMessage()
    ]
    assert len(warnings) == 1, warnings
    assert "re-download" in warnings[0]


@posix_only
@not_root
def test_a_receipt_directory_this_user_cannot_search_reads_as_no_receipt(
    monkeypatch, tmp_path
):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    destination = tmp_path / "bin"
    destination.mkdir()
    path = download_utils.write_receipt(
        destination, "tool", {"url": _URL, "sha256": _DIGEST}
    )
    assert path is not None and path.is_file()
    os.chmod(path.parent, 0o000)
    try:
        assert download_utils.read_receipt(destination, "tool") is None
    finally:
        os.chmod(path.parent, 0o700)


@posix_only
@not_root
def test_a_receipt_level_this_user_cannot_read_skips_the_receipt_and_raises_nothing(
    monkeypatch, tmp_path
):
    """The mode of each receipt level is set on a read-only descriptor, so a level
    without the read bit fails the open. The receipt is best-effort: it is not
    written, the call returns None, and the install it follows stays installed."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    destination = tmp_path / "bin"
    destination.mkdir()
    path = download_utils.write_receipt(
        destination, "tool", {"url": _URL, "sha256": _DIGEST}
    )
    assert path is not None
    os.chmod(path.parent, 0o300)
    try:
        assert (
            download_utils.write_receipt(
                destination, "tool", {"url": _URL, "sha256": _DIGEST}
            )
            is None
        )
    finally:
        os.chmod(path.parent, 0o700)


@posix_only
@not_root
def test_a_write_only_file_is_not_made_executable_and_the_error_is_raised(tmp_path):
    """The mode is read and set on a descriptor opened read-only, so a file this
    user may not read fails the open; the by-name chmod that would have repaired
    it is the call that followed links. The error is raised, the mode is left."""
    tool = tmp_path / "tool"
    tool.write_bytes(_BODY)
    tool.chmod(0o200)
    try:
        with pytest.raises(PermissionError):
            download_utils.make_executable(tool)
        assert stat.S_IMODE(tool.stat().st_mode) == 0o200
    finally:
        tool.chmod(0o600)


@posix_only
def test_a_symlink_at_the_install_path_is_not_an_installed_tool(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    destination = tmp_path / "bin"
    destination.mkdir()
    real = tmp_path / "real-tool"
    real.write_bytes(_BODY)
    (destination / "tool").symlink_to(real)
    receipt = {"url": _URL, "sha256": _DIGEST, "installed_sha256": _DIGEST}
    assert download_utils.write_receipt(destination, "tool", receipt) is not None
    assert not download_utils._already_installed(destination, "tool", _URL, _DIGEST)
    (destination / "tool").unlink()
    (destination / "tool").write_bytes(_BODY)
    assert download_utils._already_installed(destination, "tool", _URL, _DIGEST)


def test_a_copy_that_fails_while_staging_raises_its_own_error_and_cleans_up(
    patch_module_os, tmp_path
):
    archive = tmp_path / "tool.zip"
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("tool-1.0/tool", _BODY)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    real_fdopen = os.fdopen

    class _FullDisk:
        def __init__(self, fd, mode="r", *args, **kwargs):
            self._file = real_fdopen(fd, mode, *args, **kwargs)

        def write(self, chunk):
            raise OSError(errno.ENOSPC, "No space left on device")

        def __getattr__(self, name):
            return getattr(self._file, name)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self._file.close()
            return False

    # Only the module under test sees the full disk: patched on the shared ``os``
    # module, every other reader of ``os.fdopen`` in the process would too.
    patch_module_os(download_utils, fdopen=_FullDisk)
    with pytest.raises(OSError) as raised:
        download_utils._extract_single_member(archive, "tool", bin_dir / "tool")
    assert raised.value.errno == errno.ENOSPC
    assert [p.name for p in bin_dir.iterdir()] == []


def test_a_whole_body_download_is_still_verified(monkeypatch, tmp_path, quick_retry):
    monkeypatch.setattr(
        download_utils.urllib.request,
        "urlopen",
        lambda url, **kwargs: _Response(_BODY, len(_BODY)),
    )
    with pytest.raises(ToolDownloadIntegrityError):
        download_utils.download_file(_URL, tmp_path / "bin", expected_sha256="0" * 64)


#: Bytes a text-mode read mangles: CR LF pairs, which it folds to LF, and 0x1A,
#: the CRT's end-of-file mark, which stops it. Every executable and archive holds
#: both, so a staged file hashed through a text-mode descriptor hashed short.
_BINARY_BODY = b"MZ\x90\x00\r\n\x1a\x00rest of the image\r\n" * 3 + b"\x1a"
_BINARY_DIGEST = hashlib.sha256(_BINARY_BODY).hexdigest()


def test_the_staged_file_is_hashed_byte_for_byte_whatever_bytes_it_holds(tmp_path):
    """The staging open carries O_BINARY where the platform has it: the body below
    hashes to its pinned digest and lands, instead of being refused as replaced
    because a text-mode read folded its CR LF pairs and stopped at its 0x1A."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    staging = bin_dir / ".tool.ash-partial"
    staging.write_bytes(_BINARY_BODY)
    target = bin_dir / "tool"
    landed = download_utils._finalize_staged(
        staging, target, _BINARY_DIGEST, mode=0o755
    )
    assert landed == _BINARY_DIGEST
    assert target.read_bytes() == _BINARY_BODY
    assert not staging.exists()


def test_a_chunked_body_is_not_held_to_a_stale_content_length(
    monkeypatch, tmp_path, quick_retry
):
    """Transfer-Encoding: chunked frames the body and wins over any Content-Length,
    which http.client ignores; a stale one must not fail every attempt here."""
    attempts = []

    def urlopen(url, **kwargs):
        attempts.append(url)
        return _Response(_BODY, declared=99, chunked=True)

    monkeypatch.setattr(download_utils.urllib.request, "urlopen", urlopen)
    installed = download_utils.download_file(
        _URL, tmp_path / "bin", expected_sha256=_DIGEST
    )
    assert installed.read_bytes() == _BODY
    assert len(attempts) == 1


def test_a_content_length_that_is_not_an_ascii_number_carries_no_length(
    monkeypatch, tmp_path, quick_retry
):
    """``str.isdigit`` admits a superscript digit that ``int`` refuses; such a header
    is no length, so nothing is compared and nothing raises ValueError."""
    monkeypatch.setattr(
        download_utils.urllib.request,
        "urlopen",
        lambda url, **kwargs: _Response(_BODY, declared="3²"),
    )
    installed = download_utils.download_file(
        _URL, tmp_path / "bin", expected_sha256=_DIGEST
    )
    assert installed.read_bytes() == _BODY


def test_the_parsed_length_of_an_http_response_outranks_the_raw_header(
    monkeypatch, tmp_path, quick_retry
):
    """http.client has read the headers already: its ``length`` is the length of
    record, so a header it rejected or did not use cannot fail a whole body."""
    attempts = []

    def urlopen(url, **kwargs):
        attempts.append(url)
        return _Response(_BODY, declared=99, length=len(_BODY))

    monkeypatch.setattr(download_utils.urllib.request, "urlopen", urlopen)
    installed = download_utils.download_file(
        _URL, tmp_path / "bin", expected_sha256=_DIGEST
    )
    assert installed.read_bytes() == _BODY
    assert len(attempts) == 1


def test_a_short_body_is_still_refused_against_the_parsed_length(monkeypatch, tmp_path):
    monkeypatch.setenv("ASH_DOWNLOAD_MAX_ATTEMPTS", "1")
    monkeypatch.setattr(
        download_utils.urllib.request,
        "urlopen",
        lambda url, **kwargs: _Response(_BODY[:5], declared=5, length=len(_BODY)),
    )
    with pytest.raises(ConnectionError, match="closed after 5 of"):
        download_utils.download_file(_URL, tmp_path / "bin", expected_sha256=_DIGEST)


def test_a_negative_content_length_is_no_length(monkeypatch, tmp_path, quick_retry):
    """http.client reads a negative Content-Length as unknown and reads to the
    close; so does this check, so the whole body lands on the first attempt."""
    monkeypatch.setattr(
        download_utils.urllib.request,
        "urlopen",
        lambda url, **kwargs: _Response(_BODY, declared=-1),
    )
    installed = download_utils.download_file(
        _URL, tmp_path / "bin", expected_sha256=_DIGEST
    )
    assert installed.read_bytes() == _BODY


@pytest.mark.parametrize(
    "helper", ["_download_verified", "_replace_atomically", "_finalize_staged"]
)
def test_the_internal_helpers_take_their_mode_as_a_required_keyword(helper):
    """The helpers used to disagree on a default (0o644 for the download, 0o755
    for the other two), the trap a caller that forgot the argument fell into.
    Each caller now states the mode it means, and a call without one is a
    TypeError rather than a file that lands with the other helper's mode."""
    parameter = inspect.signature(getattr(download_utils, helper)).parameters["mode"]
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert parameter.default is inspect.Parameter.empty


def test_a_directory_swapped_in_after_the_rename_is_a_typed_refusal(
    tmp_path, patch_module_os
):
    """The read-back asked what the landed path is only by reading it. A directory
    swapped in at the install path after the rename opens read-only on POSIX and
    fails at the read, and the cleanup of it then raised an untyped OSError over
    the integrity error. The descriptor is asked first, and a path that cannot be
    removed is left and named, not raised."""
    real_replace = os.replace

    def replace_then_swap(source, target, *args, **kwargs):
        real_replace(source, target, *args, **kwargs)
        os.unlink(target)
        os.mkdir(target)

    patch_module_os(download_utils, replace=replace_then_swap)
    staging = tmp_path / ".tool.ash-partial"
    staging.write_bytes(_BODY)
    target = tmp_path / "tool"
    with pytest.raises(ToolDownloadIntegrityError):
        download_utils._finalize_staged(staging, target, _DIGEST, mode=0o755)
    # Not the installer's to delete: a directory is left where it is.
    assert target.is_dir()


@pytest.mark.parametrize(
    "tail",
    ["a%2Fb", "a%5Cb", "a%00b", "C%3Aevil", "%2E%2E%2Fescape"],
    ids=["slash", "backslash", "nul", "drive prefix", "dot-dot slash"],
)
def test_a_name_that_decodes_to_a_path_is_refused_before_any_request(
    monkeypatch, tmp_path, tail
):
    """The installed name is the URL's last segment, decoded. A decoded separator
    was refused; a NUL and a drive prefix were not, and reached the filesystem
    calls after the download. None reaches a request: urlopen fails the test."""

    def no_request(*args, **kwargs):
        pytest.fail("a request was made for a name that cannot be installed")

    monkeypatch.setattr(download_utils.urllib.request, "urlopen", no_request)
    destination = tmp_path / "bin"
    with pytest.raises(ValueError, match="names no file"):
        download_utils.download_file(
            f"https://example.invalid/dir/{tail}", destination, expected_sha256=_DIGEST
        )
    assert not destination.exists()


def test_a_call_without_a_mode_is_refused(tmp_path):
    staging = tmp_path / ".tool.ash-partial"
    staging.write_bytes(_BODY)
    with pytest.raises(TypeError, match="mode"):
        download_utils._finalize_staged(staging, tmp_path / "tool", _DIGEST)
