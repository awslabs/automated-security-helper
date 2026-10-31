"""Unit tests for download_utils.py."""

import io
import pytest
import stat
import sys
from pathlib import Path
from unittest.mock import patch
from automated_security_helper.core.exceptions import ToolDownloadIntegrityError

from automated_security_helper.utils.download_utils import (
    download_file,
    make_executable,
    unquarantine_macos_binary,
    install_binary_from_url,
    create_url_download_command,
    get_opengrep_url,
    receipt_root,
)

pytestmark = pytest.mark.usefixtures("receipt_home")


@pytest.mark.unit
def test_receipts_from_this_module_stay_out_of_the_real_home(tmp_path):
    """An install writes its receipt under Path.home(), here the test's own home.

    This module wrote a receipt into the developer's real ~/.ash/install-receipts.
    """
    assert receipt_root().is_relative_to(tmp_path), receipt_root()


@pytest.mark.unit
@patch("automated_security_helper.utils.download_utils.urllib.request.urlopen")
def test_download_file(mock_urlopen, tmp_path):
    """Test download_file function.

    Driven against a real directory rather than a mocked ``shutil.move`` onto
    ``/test/destination``. The move is no longer a single ``shutil.move`` call: it
    stages a file in the destination directory and ``os.replace``s it into position,
    so that a symlink planted at the destination is replaced rather than written
    through. A test that asserted on the ``shutil.move`` call could only ever check
    that one implementation was still in use, and it broke the moment that changed --
    while telling us nothing about whether the bytes arrived.
    """
    payload = b"hello from a fake release asset"

    class _Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            self.close()
            return False

    mock_urlopen.return_value = _Response(payload)

    dest = tmp_path / "destination"
    result = download_file("https://example.com/file.txt", dest)

    # The fetch is bounded: the URL is the one positional argument and a positive
    # socket timeout rides with it (its exact value is pinned in
    # test_download_utils_transfer_and_receipt_edges.py). A stalled connection
    # must end the attempt, so a call without the bound is the defect here.
    assert mock_urlopen.call_count == 1
    (called_url,), kwargs = mock_urlopen.call_args
    assert called_url == "https://example.com/file.txt"
    assert kwargs.get("timeout", 0) > 0
    assert result == dest.joinpath("file.txt")
    assert result.read_bytes() == payload
    # No staging file is left behind on the happy path.
    assert not result.with_name("file.txt.ash-partial").exists()


@pytest.mark.unit
@patch("automated_security_helper.utils.download_utils.urllib.request.urlopen")
@patch("pathlib.Path.mkdir")
def test_download_file_invalid_url(mock_mkdir, mock_urlopen):
    """Test download_file with invalid URL."""
    with pytest.raises(ValueError):
        download_file("http://example.com/file.txt", Path("/test/destination"))


@pytest.mark.unit
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
def test_make_executable_unix(tmp_path):
    """make_executable adds the execute bits to the file's own mode.

    Driven against a real file: the mode is read and set on one open descriptor
    (``os.fstat`` / ``os.fchmod``), so a test pinned to ``Path.chmod`` and
    ``Path.stat`` measured an implementation, not the property.
    """
    target = tmp_path / "file"
    target.write_bytes(b"x")
    target.chmod(0o644)
    with patch("platform.system", return_value="Linux"):
        make_executable(target)
    assert stat.S_IMODE(target.stat().st_mode) == 0o755  # 0o644 | 0o111


@pytest.mark.unit
def test_make_executable_on_windows_leaves_the_mode_alone(tmp_path):
    """On Windows make_executable sets nothing, so a real file's mode is unchanged.

    The test this replaces skipped on every platform (``sys.platform`` reads
    ``win32`` on Windows, never ``windows``) and patched ``Path.chmod``, which the
    implementation no longer calls, so it measured nothing anywhere. The Windows
    branch is the subject here, so the platform is faked and the test runs
    everywhere.
    """
    target = tmp_path / "file"
    target.write_bytes(b"x")
    before = stat.S_IMODE(target.stat().st_mode)
    with patch("platform.system", return_value="Windows"):
        make_executable(target)
    assert stat.S_IMODE(target.stat().st_mode) == before


@pytest.mark.unit
@pytest.mark.skipif(
    sys.platform.lower() != "darwin",
    reason="macOS specific test",
)
@patch("automated_security_helper.utils.download_utils.run_command")
def test_unquarantine_macos_binary(mock_run_command):
    """Test unquarantine_macos_binary on macOS.

    The attribute is removed from the file itself: ``xattr -d`` names the one
    installed binary, never ``-r`` over a path that could have become a directory.
    """
    mock_run_command.return_value.returncode = 0
    # Mock platform.system to return Darwin (macOS)
    with patch("platform.system", return_value="Darwin"):
        # Call function
        unquarantine_macos_binary(Path("/test/file"))

        # Verify run_command was called with correct arguments
        mock_run_command.assert_called_once_with(
            ["xattr", "-d", "com.apple.quarantine", "/test/file"]
        )


@pytest.mark.unit
@patch("automated_security_helper.utils.download_utils.run_command")
def test_unquarantine_macos_binary_non_macos(mock_run_command):
    """Test unquarantine_macos_binary on non-macOS platforms."""
    # Mock platform.system to return Linux
    with patch("platform.system", return_value="Linux"):
        # Call function
        unquarantine_macos_binary(Path("/test/file"))

        # Verify run_command was not called
        mock_run_command.assert_not_called()


@pytest.mark.unit
@patch("automated_security_helper.utils.download_utils.write_receipt")
@patch("automated_security_helper.utils.download_utils._download_verified")
@patch("automated_security_helper.utils.download_utils.make_executable")
@patch("automated_security_helper.utils.download_utils.unquarantine_macos_binary")
def test_install_binary_from_url(
    mock_unquarantine, mock_make_executable, mock_download_verified, mock_write_receipt
):
    """Test install_binary_from_url function.

    Driven through ``_download_verified`` rather than ``download_file``, because the
    receipt has to record the digest that was verified as the bytes landed. Re-hashing
    the installed file here instead would read it back after ``unquarantine_macos_binary``
    has spawned ``xattr`` on macOS -- see ``_finalize_staged``. ``download_file`` still
    returns a plain path for callers outside this module.

    The binary's mode is the download's business: the install names ``mode=0o755`` on
    the call, and the staged file gets it on its own descriptor before the rename, so
    no ``make_executable`` reopens the landed path by name afterwards.

    ``write_receipt`` is mocked, not run: the whole call runs under a faked
    ``platform.system() == "Darwin"``, and the real receipt writer reads that answer
    too, so on a Windows host it took its POSIX branch (``os.O_DIRECTORY``, absent
    there). What this test checks of the receipt is what the install hands it: the
    digest verified as the bytes landed, not a fresh hash.
    """
    # Setup mocks
    mock_download_verified.return_value = (Path("/test/destination/file"), "d" * 64)

    # Mock platform.system for platform-specific behavior
    with patch("platform.system", return_value="Darwin"):
        # Call function
        result = install_binary_from_url(
            "https://example.com/file",
            Path("/test/destination"),
            "renamed_file",
            expected_sha256="e" * 64,
        )

        # expected_sha256 is threaded through to the download that verifies it, and
        # the executable mode is named on the same call.
        mock_download_verified.assert_called_once_with(
            "https://example.com/file",
            Path("/test/destination"),
            "renamed_file",
            expected_sha256="e" * 64,
            mode=0o755,
        )
        mock_make_executable.assert_not_called()
        mock_unquarantine.assert_called_once_with(Path("/test/destination/file"))
        mock_write_receipt.assert_called_once()
        receipt_dir, _installed_as, receipt = mock_write_receipt.call_args.args
        assert receipt_dir == Path("/test/destination")
        assert receipt["sha256"] == "e" * 64
        assert receipt["installed_sha256"] == "d" * 64

        # Verify result
        assert result == Path("/test/destination/file")


@pytest.mark.unit
@patch("pathlib.Path.exists")
@patch("pathlib.Path.mkdir")
def test_create_url_download_command(mock_mkdir, mock_exists):
    """Test create_url_download_command function."""
    # Mock Path.exists to return False
    mock_exists.return_value = False

    # Call function
    result = create_url_download_command(
        "https://example.com/file",
        "/custom/destination",
        "renamed_file",
        expected_sha256="A" * 64,
    )

    # Building a command creates nothing: the install creates the directory when it
    # runs. OpengrepScanner builds this command when it is constructed.
    mock_mkdir.assert_not_called()

    # Verify result
    assert result.args[0] == sys.executable
    assert result.args[1] == "-c"
    assert "install_binary_from_url" in result.args[2]
    # After the code-injection fix, values are passed as separate args
    # rather than interpolated into the -c script
    assert "https://example.com/file" in result.args
    # The destination is made absolute and written with forward slashes
    # (create_url_download_command), so on Windows it carries the drive.
    assert Path("/custom/destination").absolute().as_posix() in result.args
    assert "renamed_file" in result.args
    # Lowercased on the way in, and handed to the verified install as an argument.
    assert "a" * 64 in result.args
    assert "expected_sha256=sys.argv[3]" in result.args[2]
    assert result.shell is False


@pytest.mark.unit
def test_building_the_download_command_creates_no_directory(tmp_path, monkeypatch):
    """A scan constructs OpengrepScanner, which builds this command for a custom version.

    The builder created current_bin_path() there and then: with ASH_BIN_PATH=newbin
    a scan made <cwd>/newbin, and in a read-only checkout the scanner's validator
    raised.
    """
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    monkeypatch.setenv("ASH_BIN_PATH", "newbin")
    create_url_download_command(
        "https://example.com/tool", rename_to="tool", expected_sha256="a" * 64
    )
    monkeypatch.setenv("ASH_BIN_PATH", str(work / "absolute-bin"))
    create_url_download_command(
        "https://example.com/tool", rename_to="tool", expected_sha256="a" * 64
    )
    assert sorted(p.name for p in work.iterdir()) == []


# integration although urlopen is patched: on macOS install_binary_from_url ends by
# unquarantining the file with a child xattr process, a path this test takes there.
@pytest.mark.integration
def test_the_install_creates_its_directory_when_it_runs(tmp_path):
    """What the builder leaves undone, the run does."""
    payload = b"#!/bin/sh\necho tool\n"
    destination = tmp_path / "not-yet" / "bin"
    with patch(
        "automated_security_helper.utils.download_utils.urllib.request.urlopen",
        return_value=_bytes_response(payload),
    ):
        installed = install_binary_from_url(
            "https://example.com/tool",
            destination,
            rename_to="tool",
            expected_sha256=_sha256(payload),
        )
    assert installed == destination / "tool"
    assert installed.read_bytes() == payload


def _sha256(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def _bytes_response(data: bytes):
    class _Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            self.close()
            return False

    return _Response(data)


@pytest.mark.unit
@pytest.mark.parametrize("digest", [None, "", "a" * 63, "g" * 64])
def test_create_url_download_command_refuses_a_missing_or_malformed_digest(digest):
    """No command that installs an unverified binary can be built at all."""
    with pytest.raises(ValueError, match="expected_sha256"):
        create_url_download_command(
            "https://example.com/file", "/custom/destination", expected_sha256=digest
        )


@pytest.mark.unit
@patch("automated_security_helper.utils.download_utils._download_verified")
def test_install_binary_from_url_refuses_without_a_digest(mock_download_verified):
    """The unverified install this function used to perform is gone."""
    with pytest.raises(ToolDownloadIntegrityError, match="without a pinned SHA256"):
        install_binary_from_url("https://example.com/file", Path("/test/destination"))
    mock_download_verified.assert_not_called()


@pytest.mark.unit
def test_get_opengrep_url():
    """Test get_opengrep_url function for different platforms and architectures."""
    # Test Linux amd64
    url = get_opengrep_url("linux", "amd64", "v1.1.5", "manylinux")
    assert (
        url
        == "https://github.com/opengrep/opengrep/releases/download/v1.1.5/opengrep_manylinux_x86"
    )

    # Test Linux arm64
    url = get_opengrep_url("linux", "arm64", "v1.1.5", "musllinux")
    assert (
        url
        == "https://github.com/opengrep/opengrep/releases/download/v1.1.5/opengrep_musllinux_aarch64"
    )

    # Test macOS amd64
    url = get_opengrep_url("darwin", "amd64", "v1.1.5")
    assert (
        url
        == "https://github.com/opengrep/opengrep/releases/download/v1.1.5/opengrep_osx_x86"
    )

    # Test macOS arm64
    url = get_opengrep_url("darwin", "arm64", "v1.1.5")
    assert (
        url
        == "https://github.com/opengrep/opengrep/releases/download/v1.1.5/opengrep_osx_arm64"
    )

    # Test Windows
    url = get_opengrep_url("windows", "amd64", "v1.1.5")
    assert (
        url
        == "https://github.com/opengrep/opengrep/releases/download/v1.1.5/opengrep_windows_x86.exe"
    )

    # Test invalid linux_type (should log warning but still work)
    with patch(
        "automated_security_helper.utils.download_utils.platform.system"
    ) as mock_system:
        mock_system.return_value = "Linux"
        # Should not raise ValueError, just log warning and default to manylinux
        url = get_opengrep_url("linux", "amd64", "v1.1.5", "invalid_linux_type")
        assert (
            url
            == "https://github.com/opengrep/opengrep/releases/download/v1.1.5/opengrep_manylinux_x86"
        )
