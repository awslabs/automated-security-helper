"""Unit tests for download_utils.py."""

import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

from automated_security_helper.utils.download_utils import (
    download_file,
    make_executable,
    unquarantine_macos_binary,
    install_binary_from_url,
    create_url_download_command,
    get_opengrep_url,
)


@patch("automated_security_helper.utils.download_utils.urllib.request.urlopen")
@patch("automated_security_helper.utils.download_utils.shutil.copyfileobj")
@patch("automated_security_helper.utils.download_utils.shutil.move")
@patch("automated_security_helper.utils.download_utils.tempfile.NamedTemporaryFile")
def test_download_file(mock_temp_file, mock_move, mock_copyfileobj, mock_urlopen):
    """Test download_file function."""
    # Setup mocks
    mock_temp = MagicMock()
    mock_temp.name = "/tmp/tempfile"
    mock_temp_file.return_value.__enter__.return_value = mock_temp

    mock_response = MagicMock()
    mock_urlopen.return_value.__enter__.return_value = mock_response

    # Create test destination
    dest = Path("/test/destination")

    # Call function
    result = download_file("https://example.com/file.txt", dest)

    # Verify mocks were called correctly
    mock_urlopen.assert_called_once_with("https://example.com/file.txt")
    mock_copyfileobj.assert_called_once_with(mock_response, mock_temp)
    mock_move.assert_called_once_with("/tmp/tempfile", dest.joinpath("file.txt"))

    # Verify result
    assert result == dest.joinpath("file.txt")


@patch("automated_security_helper.utils.download_utils.urllib.request.urlopen")
def test_download_file_invalid_url(mock_urlopen):
    """Test download_file with invalid URL."""
    with pytest.raises(ValueError):
        download_file("http://example.com/file.txt", Path("/test/destination"))


@patch("pathlib.Path.chmod")
@patch("pathlib.Path.stat")
def test_make_executable_unix(mock_stat, mock_chmod):
    """Test make_executable on Unix-like systems."""
    # Mock platform.system to return non-Windows
    with patch("platform.system", return_value="Linux"):
        # Mock stat to return a mode
        mock_stat_result = MagicMock()
        mock_stat_result.st_mode = 0o644
        mock_stat.return_value = mock_stat_result

        # Call function
        make_executable(Path("/test/file"))

        # Verify chmod was called with correct permissions
        mock_chmod.assert_called_once_with(0o755)  # 0o644 | 0o111


@patch("pathlib.Path.chmod")
def test_make_executable_windows(mock_chmod):
    """Test make_executable on Windows."""
    # Mock platform.system to return Windows
    with patch("platform.system", return_value="Windows"):
        # Call function
        make_executable(Path("/test/file"))

        # Verify chmod was not called
        mock_chmod.assert_not_called()


@patch("automated_security_helper.utils.download_utils.run_command")
def test_unquarantine_macos_binary(mock_run_command):
    """Test unquarantine_macos_binary on macOS."""
    # Mock platform.system to return Darwin (macOS)
    with patch("platform.system", return_value="Darwin"):
        # Call function
        unquarantine_macos_binary(Path("/test/file"))

        # Verify run_command was called with correct arguments
        mock_run_command.assert_called_once_with(
            ["xattr", "-r", "-d", "com.apple.quarantine", "/test/file"]
        )


@patch("automated_security_helper.utils.download_utils.run_command")
def test_unquarantine_macos_binary_non_macos(mock_run_command):
    """Test unquarantine_macos_binary on non-macOS platforms."""
    # Mock platform.system to return Linux
    with patch("platform.system", return_value="Linux"):
        # Call function
        unquarantine_macos_binary(Path("/test/file"))

        # Verify run_command was not called
        mock_run_command.assert_not_called()


@patch("automated_security_helper.utils.download_utils.download_file")
@patch("automated_security_helper.utils.download_utils.make_executable")
@patch("automated_security_helper.utils.download_utils.unquarantine_macos_binary")
def test_install_binary_from_url(
    mock_unquarantine, mock_make_executable, mock_download_file
):
    """Test install_binary_from_url function."""
    # Setup mocks
    mock_download_file.return_value = Path("/test/destination/file")

    # Mock platform.system for platform-specific behavior
    with patch("platform.system", return_value="Darwin"):
        # Call function
        result = install_binary_from_url(
            "https://example.com/file", Path("/test/destination"), "renamed_file"
        )

        # Verify mocks were called correctly
        mock_download_file.assert_called_once_with(
            "https://example.com/file", Path("/test/destination"), "renamed_file"
        )
        mock_make_executable.assert_called_once_with(Path("/test/destination/file"))
        mock_unquarantine.assert_called_once_with(Path("/test/destination/file"))

        # Verify result
        assert result == Path("/test/destination/file")


@patch("pathlib.Path.exists")
@patch("pathlib.Path.mkdir")
def test_create_url_download_command(mock_mkdir, mock_exists):
    """Test create_url_download_command function."""
    # Mock Path.exists to return False
    mock_exists.return_value = False

    # Call function
    result = create_url_download_command(
        "https://example.com/file", "/custom/destination", "renamed_file"
    )

    # Verify mkdir was called
    mock_mkdir.assert_called_once_with(parents=True, exist_ok=True)

    # Verify result
    assert result.args[0] == sys.executable
    assert result.args[1] == "-c"
    assert "install_binary_from_url" in result.args[2]
    assert "https://example.com/file" in result.args[2]
    assert "/custom/destination" in result.args[2]
    assert "renamed_file" in result.args[2]
    assert result.shell is False


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

    # Test invalid linux_type
    with patch(
        "automated_security_helper.utils.download_utils.platform.system"
    ) as mock_system:
        mock_system.return_value = "Linux"
        with pytest.raises(ValueError):
            get_opengrep_url("linux", "amd64", "v1.1.5", "invalid_linux_type")
