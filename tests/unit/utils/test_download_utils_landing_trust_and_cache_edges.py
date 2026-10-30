# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Downloads land only what was verified, trust only what they examined, and keep
the cache when the failure is local.

Properties of ``utils/download_utils.py`` that nothing else pins:

- a URL with a scheme other than https is refused before the destination
  directory is created, and a download redirected off https is refused before
  a byte is taken;
- a certificate that does not verify is not retried, while a TLS error past the
  connection and a socket error naming the network are;
- the backoff is bounded for any attempt number, so a large attempt budget does
  not replace the download error with an OverflowError;
- the installed name comes from the URL's path, decoded, and a URL that names a
  directory is refused where the URL is named;
- a download that fails leaves no temporary file behind;
- ``download_file`` lands what it fetched executable unless the caller names a
  mode, a data caller lands 0o644 by saying so, and the pinned-tool install
  never reopens the landed binary by name to set its mode;
- the post-rename digest is read on the landed file itself, so a link swapped in
  at the target is refused;
- ``make_executable`` sets the mode on the file it opened, never on a link's
  target;
- ``unquarantine_macos_binary`` names the file alone and reports a non-zero exit;
- a receipt level that is a link, or cannot be examined, is untrusted, and the
  receipt store is never written through a link;
- an installed binary without its execute bit is not "already installed";
- archive members are matched on either separator and a zip symlink entry is not
  an executable;
- a relative tool download cache is not used; a directory at an asset's name is
  discarded; a staging-side failure, the one a close raises included, keeps the
  cache entry;
- the install command carries an absent rename as an empty argument, keeps a
  POSIX backslash, and refuses a digest that is not plain hex;
- opengrep on Windows arm64 gets the x86-64 build Windows on ARM runs under
  emulation, said once, instead of a refusal.
"""

from __future__ import annotations

import errno
import io
import logging
import os
import platform
import ssl
import stat
import sys
import tempfile
import time
import urllib.error
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.core.exceptions import ToolDownloadIntegrityError
from automated_security_helper.utils import download_utils as du

pytestmark = pytest.mark.unit

POSIX_ONLY = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX modes and symlinks"
)

DIGEST_A = "a" * 64


class _Body(io.BytesIO):
    """A response stand-in: a body, and the URL it says it was read from."""

    def __init__(self, payload: bytes, landed_at=None):
        super().__init__(payload)
        self._landed_at = landed_at
        # _copy_whole_body reads the response headers for Content-Length; a
        # stand-in without them raised AttributeError at the copy.
        self.headers: dict = {}

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()
        return False

    def geturl(self):
        return self._landed_at


def _fetch(monkeypatch, payload: bytes, landed_at=None):
    monkeypatch.setattr(
        du.urllib.request,
        "urlopen",
        lambda url, timeout=None: _Body(payload, landed_at or url),
    )


def _single_attempt(monkeypatch):
    monkeypatch.setenv("ASH_DOWNLOAD_MAX_ATTEMPTS", "1")
    monkeypatch.setattr(du.time, "sleep", lambda _s: None)


# --- the URL, before anything is made -----------------------------------------


def test_a_refused_scheme_creates_no_destination_directory(tmp_path):
    destination = tmp_path / "never-made"
    with pytest.raises(ValueError):
        du.download_file("http://example.com/tool", destination)
    assert not destination.exists()


def test_a_download_redirected_off_https_is_refused_before_it_lands(
    monkeypatch, tmp_path
):
    _single_attempt(monkeypatch)
    _fetch(monkeypatch, b"payload", landed_at="http://mirror.example.com/tool")
    with pytest.raises(ValueError) as raised:
        du.download_file("https://example.com/tool", tmp_path)
    assert "http://mirror.example.com/tool" in str(raised.value)
    assert not (tmp_path / "tool").exists()


def test_a_response_landing_on_https_is_taken(monkeypatch, tmp_path):
    _fetch(monkeypatch, b"payload", landed_at="https://cdn.example.com/tool")
    landed = du.download_file("https://example.com/tool", tmp_path)
    assert landed.read_bytes() == b"payload"


# --- which failures are worth a retry ----------------------------------------


def test_a_certificate_failure_is_not_transient():
    reason = ssl.SSLCertVerificationError("certificate verify failed")
    assert du._is_transient_download_error(urllib.error.URLError(reason)) is False
    assert du._is_transient_download_error(reason) is False
    # The control: a refused connection wrapped the same way still is.
    assert du._is_transient_download_error(
        urllib.error.URLError(ConnectionRefusedError())
    )


def test_a_tls_error_past_the_connection_and_a_network_errno_are_transient():
    assert du._is_transient_download_error(ssl.SSLError("unexpected eof"))
    unreachable = OSError(errno.EHOSTUNREACH, "No route to host")
    assert du._is_transient_download_error(unreachable)
    # The control: an errno that names the local disk is not.
    assert not du._is_transient_download_error(OSError(errno.ENOSPC, "full"))


def test_the_backoff_is_bounded_for_any_attempt_number():
    assert du._retry_delay(1, 5.0) == 5.0
    assert du._retry_delay(2, 5.0) == 10.0
    assert du._retry_delay(2000, 5.0) == du._DOWNLOAD_MAX_DELAY


# --- the installed name --------------------------------------------------------


def test_the_installed_name_is_the_decoded_last_path_segment():
    assert du._url_basename("https://x.example/v1/tool%2Bextra?sig=1#top") == (
        "tool+extra"
    )


@pytest.mark.parametrize(
    "url",
    [
        "https://x.example/releases/",
        "https://x.example/releases/..",
        "https://x.example",
    ],
)
def test_a_url_naming_a_directory_is_refused_where_the_url_is_named(url, tmp_path):
    with pytest.raises(ValueError) as raised:
        du.download_file(url, tmp_path / "dest")
    assert "rename_to" in str(raised.value)
    assert not (tmp_path / "dest").exists()


# --- the temporary file ---------------------------------------------------------


def test_a_failed_download_leaves_no_temporary_file(monkeypatch, tmp_path):
    _single_attempt(monkeypatch)
    temp_root = tmp_path / "tmp"
    temp_root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(temp_root))

    def failing(url, timeout=None):
        raise urllib.error.HTTPError(url, 404, "gone", None, None)

    monkeypatch.setattr(du.urllib.request, "urlopen", failing)
    with pytest.raises(urllib.error.HTTPError):
        du.download_file("https://example.com/tool", tmp_path / "dest")
    assert list(temp_root.iterdir()) == []


# --- what lands, and with which mode -------------------------------------------


@POSIX_ONLY
def test_download_file_lands_an_executable_unless_told_otherwise(monkeypatch, tmp_path):
    """The public helper's default is the mode every caller got before the mode
    parameter existed: a plugin that downloads a binary through it, with nothing
    in its own code changed, gets a file it can run."""
    _fetch(monkeypatch, b"#!/bin/sh\nexit 0\n")
    landed = du.download_file("https://example.com/tool", tmp_path)
    assert stat.S_IMODE(landed.stat().st_mode) == 0o755


@POSIX_ONLY
def test_a_data_caller_lands_its_download_without_the_execute_bit(
    monkeypatch, tmp_path
):
    """A caller fetching data says so, and the rules bundle and the release
    archive do (``mode=0o644``); nothing is landed executable on their behalf."""
    _fetch(monkeypatch, b"rules: []\n")
    landed = du.download_file("https://example.com/rules.yaml", tmp_path, mode=0o644)
    assert stat.S_IMODE(landed.stat().st_mode) == 0o644


@POSIX_ONLY
def test_install_binary_from_url_lands_an_executable(monkeypatch, tmp_path):
    import hashlib

    payload = b"#!/bin/sh\nexit 0\n"
    _fetch(monkeypatch, payload)
    installed = du.install_binary_from_url(
        "https://example.com/tool",
        tmp_path / "bin",
        expected_sha256=hashlib.sha256(payload).hexdigest(),
    )
    assert stat.S_IMODE(installed.stat().st_mode) == 0o755


@POSIX_ONLY
def test_a_link_swapped_in_at_the_target_after_the_rename_is_refused(
    monkeypatch, tmp_path
):
    import hashlib

    payload = b"the verified bytes"
    staging = tmp_path / "staging"
    staging.write_bytes(payload)
    target = tmp_path / "tool"
    elsewhere = tmp_path / "elsewhere"
    elsewhere.write_bytes(payload)
    real_replace = os.replace

    def replace_then_swap(src, dst):
        real_replace(src, dst)
        os.unlink(dst)
        os.symlink(elsewhere, dst)

    monkeypatch.setattr(du.os, "replace", replace_then_swap)
    with pytest.raises(ToolDownloadIntegrityError):
        du._finalize_staged(staging, target, hashlib.sha256(payload).hexdigest())
    assert not target.exists() and not target.is_symlink()
    # The target of the planted link is untouched.
    assert elsewhere.read_bytes() == payload


@POSIX_ONLY
def test_a_staging_file_that_cannot_be_made_removes_the_source(tmp_path):
    source = tmp_path / "verified"
    source.write_bytes(b"x")
    # A plain file where the destination directory would be made: the staging
    # file's directory cannot be created, so no staging file is.
    (tmp_path / "blocked").write_bytes(b"")
    target = tmp_path / "blocked" / "tool"
    with pytest.raises(OSError):
        du._replace_atomically(source, target, expected_sha256=DIGEST_A)
    assert not source.exists()
    assert (tmp_path / "blocked").is_file()


@POSIX_ONLY
def test_make_executable_sets_the_mode_on_the_file_it_opened(tmp_path):
    plain = tmp_path / "plain"
    plain.write_bytes(b"x")
    plain.chmod(0o644)
    du.make_executable(plain)
    assert stat.S_IMODE(plain.stat().st_mode) == 0o755


@POSIX_ONLY
def test_make_executable_never_follows_a_link_swapped_in_after_the_check(
    monkeypatch, tmp_path, caplog
):
    victim = tmp_path / "victim"
    victim.write_bytes(b"x")
    victim.chmod(0o644)
    link = tmp_path / "link"
    link.write_bytes(b"y")

    def swap_then_answer(_self):
        # The is_symlink check reads a plain file; the link is planted after it.
        link.unlink()
        os.symlink(victim, link)
        return False

    monkeypatch.setattr(Path, "is_symlink", swap_then_answer)
    with caplog.at_level(logging.WARNING):
        du.make_executable(link)
    assert stat.S_IMODE(victim.stat().st_mode) == 0o644
    assert "symlink" in caplog.text


def test_unquarantine_names_the_file_alone_and_reports_a_nonzero_exit(
    monkeypatch, caplog
):
    seen = {}

    def fake_run(args, **kwargs):
        seen["args"] = args
        return SimpleNamespace(
            returncode=1, stdout="", stderr="Operation not permitted"
        )

    monkeypatch.setattr(du.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(du, "run_command", fake_run)
    with caplog.at_level(logging.WARNING):
        du.unquarantine_macos_binary(Path("/opt/ash/bin/tool"))
    assert "-r" not in seen["args"]
    assert seen["args"][-1] == "/opt/ash/bin/tool"
    assert "exited 1" in caplog.text and "Operation not permitted" in caplog.text


def test_a_file_with_no_quarantine_attribute_is_not_a_failed_unquarantine(
    monkeypatch, caplog
):
    """A file the downloader wrote carries no quarantine attribute, so
    ``xattr -d`` exits 1 with "No such xattr": nothing to remove, no warning."""

    def fake_run(args, **kwargs):
        return SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="/opt/ash/bin/tool: No such xattr: com.apple.quarantine",
        )

    monkeypatch.setattr(du.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(du, "run_command", fake_run)
    with caplog.at_level(logging.DEBUG):
        du.unquarantine_macos_binary(Path("/opt/ash/bin/tool"))
    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert warnings == [], [r.getMessage() for r in warnings]
    assert "carries no quarantine attribute" in caplog.text


# --- the receipt store -----------------------------------------------------------


@POSIX_ONLY
def test_a_receipt_level_that_is_a_link_or_unexaminable_is_untrusted(tmp_path):
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(real)
    assert "symbolic link" in (du._untrusted_reason(link) or "")
    assert "cannot be examined" in (du._untrusted_reason(tmp_path / "gone") or "")
    # The control: the real 0o700 directory of this user is trusted.
    assert du._untrusted_reason(real) is None


@POSIX_ONLY
def test_the_receipt_store_is_not_written_through_a_link(receipt_home, tmp_path):
    root = du.receipt_root()
    root.parent.mkdir(parents=True, exist_ok=True)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o755)
    root.symlink_to(elsewhere)
    with pytest.raises(OSError):
        du._private_dir(root / "key")
    assert stat.S_IMODE(elsewhere.stat().st_mode) == 0o755
    assert not (elsewhere / "key").exists()


@POSIX_ONLY
def test_a_receipt_that_is_a_link_is_not_read(receipt_home, tmp_path):
    destination = tmp_path / "bin"
    destination.mkdir()
    written = du.write_receipt(destination, "tool", {"url": "u", "sha256": DIGEST_A})
    assert written is not None
    elsewhere = tmp_path / "forged.json"
    elsewhere.write_text('{"url": "u", "sha256": "%s"}' % DIGEST_A)
    elsewhere.chmod(0o600)
    written.unlink()
    written.symlink_to(elsewhere)
    assert du.read_receipt(destination, "tool") is None


@POSIX_ONLY
def test_a_verified_binary_that_lost_its_execute_bit_gets_it_back(
    receipt_home, tmp_path, caplog
):
    """The bytes still match the receipt, so the install is kept and the mode
    put back, rather than the file downloaded again."""
    import hashlib

    destination = tmp_path / "bin"
    destination.mkdir()
    payload = b"binary"
    digest = hashlib.sha256(payload).hexdigest()
    target = destination / "tool"
    target.write_bytes(payload)
    target.chmod(0o755)
    du.write_receipt(
        destination,
        "tool",
        {"url": "https://x.example/tool", "sha256": digest, "installed_sha256": digest},
    )
    assert du._already_installed(destination, "tool", "https://x.example/tool", digest)
    target.chmod(0o644)
    with caplog.at_level(logging.WARNING):
        assert du._already_installed(
            destination, "tool", "https://x.example/tool", digest
        )
    assert "not executable" in caplog.text
    assert stat.S_IMODE(target.stat().st_mode) & 0o111 == 0o111
    # The control: bytes that no longer match the receipt are not repaired.
    target.write_bytes(b"other")
    target.chmod(0o644)
    assert not du._already_installed(
        destination, "tool", "https://x.example/tool", digest
    )
    assert stat.S_IMODE(target.stat().st_mode) & 0o111 == 0


class _RecordingOs:
    """The ``os`` module as the download module sees it, with the calls that open
    the installed file or set a mode recorded; everything else is the real one."""

    def __init__(self):
        self.opens: list = []
        self.fchmods: list = []
        self.path_chmods: list = []

    def open(self, path, flags, *args, **kwargs):
        fd = os.open(path, flags, *args, **kwargs)
        self.opens.append((os.fspath(path), flags, fd))
        return fd

    def fchmod(self, fd, mode):
        self.fchmods.append((fd, mode))
        return os.fchmod(fd, mode)

    def chmod(self, *args, **kwargs):
        self.path_chmods.append(args)
        return os.chmod(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(os, name)


@POSIX_ONLY
def test_the_repair_hashes_and_sets_the_mode_on_one_descriptor(
    receipt_home, tmp_path, monkeypatch
):
    """The digest and the mode are read and set through ONE open of the file
    (O_NOFOLLOW), never through a second path lookup: the install directory may
    be writable by others, and a file swapped in between a path-based hash and a
    path-based chmod would have had its mode set on bytes nobody hashed."""
    import hashlib

    destination = tmp_path / "bin"
    destination.mkdir()
    payload = b"binary"
    digest = hashlib.sha256(payload).hexdigest()
    target = destination / "tool"
    target.write_bytes(payload)
    target.chmod(0o644)
    du.write_receipt(
        destination,
        "tool",
        {"url": "https://x.example/tool", "sha256": digest, "installed_sha256": digest},
    )
    recording = _RecordingOs()
    monkeypatch.setattr(du, "os", recording)

    def never(*args, **kwargs):
        raise AssertionError("a path-based read or chmod of the installed file")

    monkeypatch.setattr(du, "sha256_file", never)
    monkeypatch.setattr(du, "make_executable", never)
    assert du._already_installed(destination, "tool", "https://x.example/tool", digest)
    opens = [entry for entry in recording.opens if entry[0] == str(target)]
    assert len(opens) == 1, recording.opens
    assert opens[0][1] & os.O_NOFOLLOW, opens[0]
    assert [fd for fd, _mode in recording.fchmods] == [opens[0][2]], recording.fchmods
    assert recording.path_chmods == []
    assert stat.S_IMODE(target.stat().st_mode) & 0o111 == 0o111


@POSIX_ONLY
def test_a_file_with_a_second_name_is_reinstalled_not_repaired(
    receipt_home, tmp_path, caplog
):
    """A hard link shares its mode with its other name, so the repair would
    change a file outside the install directory; the install replaces the name
    instead."""
    import hashlib

    destination = tmp_path / "bin"
    destination.mkdir()
    payload = b"binary"
    digest = hashlib.sha256(payload).hexdigest()
    target = destination / "tool"
    target.write_bytes(payload)
    target.chmod(0o644)
    os.link(target, tmp_path / "other-name")
    du.write_receipt(
        destination,
        "tool",
        {"url": "https://x.example/tool", "sha256": digest, "installed_sha256": digest},
    )
    with caplog.at_level(logging.WARNING):
        assert not du._already_installed(
            destination, "tool", "https://x.example/tool", digest
        )
    assert "another name" in caplog.text
    assert stat.S_IMODE((tmp_path / "other-name").stat().st_mode) & 0o111 == 0
    # The control: with the other name gone, the same file is repaired.
    (tmp_path / "other-name").unlink()
    assert du._already_installed(destination, "tool", "https://x.example/tool", digest)
    assert stat.S_IMODE(target.stat().st_mode) & 0o111 == 0o111


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs os.mkfifo")
def test_a_fifo_at_the_install_path_is_refused_without_blocking(
    receipt_home, tmp_path, caplog
):
    """A FIFO planted at the install path, in a directory other users can write,
    must be refused by the regular-file check; an open that followed the FIFO's
    own rules would block there, with no writer ever coming, and the check would
    never return."""
    import hashlib

    destination = tmp_path / "bin"
    destination.mkdir()
    payload = b"binary"
    digest = hashlib.sha256(payload).hexdigest()
    os.mkfifo(destination / "tool")
    du.write_receipt(
        destination,
        "tool",
        {"url": "https://x.example/tool", "sha256": digest, "installed_sha256": digest},
    )
    started = time.monotonic()
    with caplog.at_level(logging.WARNING):
        assert not du._already_installed(
            destination, "tool", "https://x.example/tool", digest
        )
    # Promptly: a blocked open would hold the test until its runner's timeout,
    # which is the failure this pins; the bound only has to be far below that.
    assert time.monotonic() - started < 5
    assert "not a regular file" in caplog.text
    # The control: the same path holding a regular file with those bytes is
    # installed.
    (destination / "tool").unlink()
    (destination / "tool").write_bytes(payload)
    (destination / "tool").chmod(0o755)
    assert du._already_installed(destination, "tool", "https://x.example/tool", digest)


@POSIX_ONLY
@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs os.mkfifo")
def test_a_fifo_renamed_over_the_staging_name_is_refused_without_blocking(
    tmp_path,
):
    """The staging file is created with O_EXCL, which stops a plant but not a
    rename over its name in a directory other users can write. A FIFO renamed
    there must be refused by the regular-file check on the open descriptor; an
    open that honored the FIFO would block with no writer ever coming."""
    staging = tmp_path / ".tool.staged.ash-partial"
    os.mkfifo(staging)
    target = tmp_path / "tool"
    started = time.monotonic()
    with pytest.raises(ToolDownloadIntegrityError, match="not a regular file"):
        du._finalize_staged(staging, target, DIGEST_A)
    assert time.monotonic() - started < 5
    assert not target.exists()


@POSIX_ONLY
@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs os.mkfifo")
def test_make_executable_refuses_a_fifo_without_blocking(tmp_path, caplog):
    fifo = tmp_path / "tool"
    os.mkfifo(fifo, 0o600)
    started = time.monotonic()
    with caplog.at_level(logging.WARNING):
        du.make_executable(fifo)
    assert time.monotonic() - started < 5
    assert "not a regular file" in caplog.text
    # No execute bit was set on it.
    assert stat.S_IMODE(os.stat(fifo).st_mode) & 0o111 == 0


@POSIX_ONLY
@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs os.mkfifo")
def test_a_fifo_swapped_in_at_the_receipt_path_is_not_read(
    receipt_home, tmp_path, monkeypatch, caplog
):
    """``read_receipt`` asks ``is_file`` by path first, so a FIFO that sits there
    is already treated as absent; the one swapped in after that answer reaches
    the open, which must not block on it."""
    destination = tmp_path / "bin"
    destination.mkdir()
    written = du.write_receipt(destination, "tool", {"url": "u", "sha256": DIGEST_A})
    assert written is not None
    written.unlink()
    os.mkfifo(written, 0o600)
    real_is_file = Path.is_file

    def answer_present(self):
        return True if self == written else real_is_file(self)

    monkeypatch.setattr(Path, "is_file", answer_present)
    started = time.monotonic()
    with caplog.at_level(logging.WARNING):
        assert du.read_receipt(destination, "tool") is None
    assert time.monotonic() - started < 5
    assert "is not a file" in caplog.text


# --- archive members ---------------------------------------------------------------


def test_archive_members_are_matched_on_either_separator():
    assert du._archive_basename("dist\\bin\\tool.exe") == "tool.exe"
    assert du._archive_basename("dist/bin/tool") == "tool"


def test_a_zip_symlink_entry_is_not_a_regular_file():
    link = zipfile.ZipInfo("tool")
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    regular = zipfile.ZipInfo("tool")
    regular.external_attr = (stat.S_IFREG | 0o755) << 16
    unknown = zipfile.ZipInfo("tool")  # made on a platform storing no mode
    assert not du._zip_entry_is_a_regular_file(link)
    assert du._zip_entry_is_a_regular_file(regular)
    assert du._zip_entry_is_a_regular_file(unknown)


# --- the tool download cache -----------------------------------------------------------


def test_a_relative_cache_is_not_used_and_says_so_once(monkeypatch, caplog):
    monkeypatch.setenv(du._TOOL_DOWNLOAD_CACHE_ENV, "relative/cache")
    du._warned_relative_cache.discard("relative/cache")
    with caplog.at_level(logging.WARNING):
        assert du._tool_download_cache() is None
        assert du._tool_download_cache() is None
    assert caplog.text.count("not an absolute path") == 1


def test_a_directory_at_an_assets_name_is_discarded(monkeypatch, tmp_path, caplog):
    cache = tmp_path / "cache"
    (cache / "asset.tar.gz").mkdir(parents=True)
    (cache / "asset.tar.gz" / "junk").write_bytes(b"x")
    monkeypatch.setenv(du._TOOL_DOWNLOAD_CACHE_ENV, str(cache))
    staging = tmp_path / "staging"
    staging.mkdir()
    with caplog.at_level(logging.WARNING):
        assert du._restore_cached_asset("asset.tar.gz", DIGEST_A, staging) is None
    assert not (cache / "asset.tar.gz").exists()


def test_a_staging_side_failure_keeps_the_cache_entry(monkeypatch, tmp_path, caplog):
    import hashlib

    cache = tmp_path / "cache"
    cache.mkdir()
    payload = b"the asset"
    (cache / "asset.tar.gz").write_bytes(payload)
    monkeypatch.setenv(du._TOOL_DOWNLOAD_CACHE_ENV, str(cache))
    staging = tmp_path / "no-such-staging-dir"
    with caplog.at_level(logging.WARNING):
        restored = du._restore_cached_asset(
            "asset.tar.gz", hashlib.sha256(payload).hexdigest(), staging
        )
    assert restored is None
    assert (cache / "asset.tar.gz").read_bytes() == payload
    assert "cache entry is kept" in caplog.text


def test_a_staging_copy_that_fails_at_its_close_keeps_the_cache_entry(
    monkeypatch, tmp_path, caplog
):
    """The error a buffered write defers to the close (ENOSPC on the last chunk,
    EDQUOT or EIO on a quota or network TMPDIR) is a staging-side failure: the entry
    is kept and the caller downloads. It used to escape the function uncaught."""
    import hashlib

    cache = tmp_path / "cache"
    cache.mkdir()
    payload = b"the asset"
    (cache / "asset.tar.gz").write_bytes(payload)
    monkeypatch.setenv(du._TOOL_DOWNLOAD_CACHE_ENV, str(cache))
    staging = tmp_path / "staging"
    staging.mkdir()
    real_open = open

    class _FailsAtClose:
        def __init__(self, inner):
            self._inner = inner

        def write(self, data):
            return self._inner.write(data)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self._inner.close()
            raise OSError(errno.ENOSPC, "No space left on device")

    def opened(path, mode="r", *args, **kwargs):
        handle = real_open(path, mode, *args, **kwargs)
        return _FailsAtClose(handle) if mode == "wb" else handle

    monkeypatch.setattr(du, "open", opened, raising=False)
    with caplog.at_level(logging.WARNING):
        restored = du._restore_cached_asset(
            "asset.tar.gz", hashlib.sha256(payload).hexdigest(), staging
        )
    assert restored is None
    assert (cache / "asset.tar.gz").read_bytes() == payload
    assert "No space left on device" in caplog.text
    assert "cache entry is kept" in caplog.text


# --- the install commands ----------------------------------------------------------------


def test_an_absent_rename_travels_as_an_empty_argument():
    cmd = du.create_url_download_command(
        url="https://example.com/tool", rename_to=None, expected_sha256=DIGEST_A
    )
    assert cmd.args[-1] == ""
    assert "sys.argv[4] or None" in cmd.args[2]


@pytest.mark.parametrize(
    "digest",
    ["0x" + "a" * 62, "a" * 63 + " ", "+" + "a" * 63, "a_" + "a" * 62],
)
def test_a_digest_that_is_not_plain_hex_is_refused(digest):
    assert len(digest) == 64
    with pytest.raises(ValueError):
        du.create_url_download_command(
            url="https://example.com/tool", expected_sha256=digest
        )


@POSIX_ONLY
def test_a_backslash_in_a_posix_destination_is_kept(monkeypatch):
    monkeypatch.setattr(du.os, "name", "posix")
    assert du._destination_text(Path("/opt/odd\\name")) == "/opt/odd\\name"
    monkeypatch.setattr(du.os, "name", "nt")
    assert du._destination_text("C:\\ash\\bin") == "C:/ash/bin"


def test_opengrep_on_windows_arm64_gets_the_x86_64_build_it_runs_under_emulation(
    caplog,
):
    """opengrep has no Windows arm64 build, and Windows 11 on ARM runs x86-64
    executables under emulation: the arm64 request gets that build, with a line
    saying so. A ValueError here failed a working install at scanner construction."""
    with caplog.at_level(logging.INFO):
        url = du.get_opengrep_url("windows", "arm64")
    assert url.endswith("opengrep_windows_x86.exe")
    assert "emulation" in caplog.text
    # The control: the one Windows build it has, asked for by its own name.
    assert du.get_opengrep_url("windows", "amd64") == url
    with pytest.raises(ValueError):
        du.get_opengrep_url("windows", "mips")


def test_platform_module_is_the_one_patched():
    # Guards the fake above: unquarantine reads platform.system through the module.
    assert du.platform is platform
