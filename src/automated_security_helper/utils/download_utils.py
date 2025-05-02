"""Utility functions for downloading and installing binaries."""

import platform
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Literal, Optional
import urllib.request


from automated_security_helper.core.constants import ASH_BIN_PATH
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.subprocess_utils import run_command
from automated_security_helper.base.plugin_base import CustomCommand


def download_file(url: str, destination: Path, rename_to: Optional[str] = None) -> Path:
    """Download a file from a URL to the specified destination.

    Args:
        url: The URL to download from
        destination: The directory to save the file to
        rename_to: Optional name to rename the file to

    Returns:
        Path to the downloaded file
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
        with urllib.request.urlopen(url) as response:
            shutil.copyfileobj(response, temp_file)

    # Move the temporary file to the destination
    dest_path = destination / rename_to
    shutil.move(temp_file.name, dest_path)

    ASH_LOGGER.info(f"Downloaded {url} to {dest_path}")
    return dest_path


def make_executable(file_path: Path) -> None:
    """Make a file executable.

    Args:
        file_path: Path to the file to make executable
    """
    if platform.system() != "Windows":
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


def install_binary_from_url(
    url: str, destination: Path, rename_to: Optional[str] = None
) -> Path:
    """Download and install a binary from a URL.

    Args:
        url: The URL to download from
        destination: The directory to install the binary to
        rename_to: Optional name to rename the binary to

    Returns:
        Path to the installed binary
    """
    # Download the file
    binary_path = download_file(url, destination, rename_to)

    # Make it executable
    make_executable(binary_path)

    # Platform-specific post-installation steps
    if platform.system() == "Darwin":
        unquarantine_macos_binary(binary_path)

    return binary_path


def create_url_download_command(
    url: str,
    destination: str = ASH_BIN_PATH,
    rename_to: str | None = None,
) -> CustomCommand:
    """Create a CustomCommand to download and install a binary from a URL.

    Args:
        url: The URL to download from
        destination: The directory to install the binary to
        rename_to: Optional name to rename the binary to

    Returns:
        CustomCommand object
    """
    if not Path(destination).exists():
        ASH_LOGGER.verbose(f"Creating ASH bin path directory @ {destination}")
        Path(destination).mkdir(parents=True, exist_ok=True)
    return CustomCommand(
        args=[
            sys.executable,
            "-c",
            f"from automated_security_helper.utils.download_utils import install_binary_from_url; "
            f"install_binary_from_url('{url}', Path('{destination}'), '{rename_to}')",
        ],
        shell=False,
    )


def get_opengrep_url(
    platform: Literal["linux", "darwin", "windows"],
    arch: Literal["amd64", "arm64"],
    version: str = "v1.1.5",
    linux_type: Literal["musllinux", "manylinux"] = "manylinux",
) -> str:
    """Get the URL for the opengrep binary based on platform and architecture.

    Args:
        platform: The platform (e.g., "linux", "darwin", "windows")
        arch: The architecture (e.g., "amd64", "arm64")
        version: The version of opengrep to download (default: "v1.1.5")
        linux_type: Type of Linux build to use (manylinux or musllinux)

    Returns:
        URL for the opengrep binary
    """
    # Base URL for opengrep releases
    base_url = f"https://github.com/opengrep/opengrep/releases/download/{version}"

    # Map platform and architecture to the appropriate binary name
    if platform == "linux":
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
    elif platform == "darwin" or platform == "macos":
        if arch == "amd64" or arch == "x86_64":
            return f"{base_url}/opengrep_osx_x86"
        elif arch == "arm64" or arch == "aarch64":
            return f"{base_url}/opengrep_osx_arm64"
    elif platform == "windows":
        return f"{base_url}/opengrep_windows_x86.exe"

    # Default case
    raise ValueError(f"Unsupported platform/architecture: {platform}/{arch}")
