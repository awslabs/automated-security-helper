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

# Where install receipts live, relative to the bin directory a tool is installed
# into. A receipt records which pinned asset produced the installed file, which is
# what makes a second install a no-op instead of a second download.
RECEIPT_DIR_NAME = ".ash-install-receipts"

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

    # Move the temporary file to the destination
    dest_path = destination.joinpath(rename_to)
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


def receipt_path(destination: Path, installed_as: str) -> Path:
    """Path of the install receipt for ``installed_as`` under ``destination``."""
    return destination.joinpath(RECEIPT_DIR_NAME, f"{installed_as}.json")


def read_receipt(destination: Path, installed_as: str) -> Optional[dict]:
    """Read an install receipt, or None if absent or unreadable.

    An unreadable receipt is treated as absent rather than fatal: the recovery is
    to reinstall, and refusing to install because a cache marker is corrupt would
    be worse than the corruption.
    """
    path = receipt_path(destination, installed_as)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        ASH_LOGGER.debug(f"Ignoring unreadable install receipt at {path}")
        return None


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
    """
    path = receipt_path(destination, installed_as)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")
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
    """Whether ``installed_as`` was already installed from exactly this asset.

    Both halves are required. A receipt with no file means the binary was deleted
    out from under it; a file with no receipt means it came from somewhere else
    (a package manager, a nix profile, an earlier ASH that predates receipts) and
    ASH should not assume it is the pinned version.

    The receipt is matched on url *and* digest rather than on the tool name, so a
    version bump reinstalls instead of finding the old binary and reporting
    success.
    """
    target = destination.joinpath(installed_as)
    if not target.exists():
        return False
    receipt = read_receipt(destination, installed_as)
    if receipt is None:
        return False
    if receipt.get("url") != url:
        return False
    # A receipt written before digests existed has no sha256; treat it as not
    # matching a pinned install so the verified download happens once.
    return receipt.get("sha256") == (
        expected_sha256.lower() if expected_sha256 else None
    )


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

    Raises:
        ToolDownloadIntegrityError: if zero or more than one member matches.
    """
    suffixes = "".join(archive_path.suffixes[-2:]).lower()
    target.parent.mkdir(parents=True, exist_ok=True)

    if suffixes.endswith(".zip"):
        with zipfile.ZipFile(archive_path) as archive:
            # ZipFile normalizes separators to "/" on read, so splitting on "/" is
            # correct for archives built on Windows too.
            matches = [
                info
                for info in archive.infolist()
                if not info.is_dir() and info.filename.split("/")[-1] == member_name
            ]
            _require_one_match(matches, member_name, archive_path)
            with archive.open(matches[0]) as source, open(target, "wb") as sink:
                shutil.copyfileobj(source, sink)
        return target

    with tarfile.open(archive_path, "r:*") as archive:
        matches = [
            member
            for member in archive.getmembers()
            if member.isfile() and member.name.split("/")[-1] == member_name
        ]
        _require_one_match(matches, member_name, archive_path)
        extracted = archive.extractfile(matches[0])
        if extracted is None:  # pragma: no cover - isfile() already excludes this
            raise ToolDownloadIntegrityError(
                f"Archive member {member_name} in {archive_path} is not readable"
            )
        with extracted as source, open(target, "wb") as sink:
            shutil.copyfileobj(source, sink)
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


def current_platform_arch() -> "tuple[str, str]":
    """The (platform, arch) key pair for the machine this is running on.

    Matches the vocabulary ``cli/dependencies.py`` uses, and derives the
    architecture from ``platform.machine()``.

    The older per-scanner helpers derived it from ``struct.calcsize("P") * 8``,
    which answers 64-vs-32-bit and not amd64-vs-arm64 -- so on an arm64 host they
    reported "amd64". That was harmless only because the tables they indexed had
    identical entries for both arches. It stops being harmless the moment a table
    has an asset for one arch and not the other, which is now the case.
    """
    system = platform.system().lower()
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        arch = "amd64"
    elif machine in ("aarch64", "arm64"):
        arch = "arm64"
    else:
        arch = "unknown"
    return system, arch


def has_install_commands_for_current_platform(table: dict) -> bool:
    """Whether a ``custom_install_commands`` table has commands for this machine."""
    system, arch = current_platform_arch()
    return len(table.get(system, {}).get(arch, [])) > 0


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
