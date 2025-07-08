"""Data models for UV tool installation status and command configuration."""

from dataclasses import dataclass
from typing import List, Optional
from datetime import datetime


@dataclass
class UVToolInstallationStatus:
    """Data class for tracking UV tool installation state.

    This class provides a structured way to track the installation status
    of UV tools, including success/failure information and timing data.
    Enhanced to include pre-installed tool detection.
    """

    tool_name: str
    """Name of the tool (e.g., 'bandit', 'checkov', 'semgrep')"""

    is_installed: bool
    """Whether the tool is currently installed via UV tool"""

    installed_version: Optional[str] = None
    """Version of the installed tool, if available"""

    installation_attempted: bool = False
    """Whether installation was attempted during this session"""

    installation_successful: bool = False
    """Whether the installation attempt was successful"""

    installation_error: Optional[str] = None
    """Error message if installation failed"""

    installation_time: Optional[float] = None
    """Time taken for installation in seconds"""

    installation_timestamp: Optional[datetime] = None
    """Timestamp when installation was attempted"""

    version_constraint: Optional[str] = None
    """Version constraint used for installation (e.g., '>=1.7.0')"""

    # Pre-installed tool detection fields
    is_pre_installed: bool = False
    """Whether the tool is available as a pre-installed executable"""

    pre_installed_version: Optional[str] = None
    """Version of the pre-installed tool, if available"""

    pre_installed_path: Optional[str] = None
    """Path to the pre-installed executable"""

    preferred_source: str = "none"
    """Preferred source for the tool: 'uv', 'pre_installed', or 'none'"""

    available: bool = False
    """Whether the tool is available from any source (UV or pre-installed)"""

    def to_dict(self) -> dict:
        """Convert the installation status to a dictionary for serialization.

        Returns:
            Dictionary representation of the installation status
        """
        return {
            "tool_name": self.tool_name,
            "is_installed": self.is_installed,
            "installed_version": self.installed_version,
            "installation_attempted": self.installation_attempted,
            "installation_successful": self.installation_successful,
            "installation_error": self.installation_error,
            "installation_time": self.installation_time,
            "installation_timestamp": self.installation_timestamp.isoformat()
            if self.installation_timestamp
            else None,
            "version_constraint": self.version_constraint,
            "is_pre_installed": self.is_pre_installed,
            "pre_installed_version": self.pre_installed_version,
            "pre_installed_path": self.pre_installed_path,
            "preferred_source": self.preferred_source,
            "available": self.available,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "UVToolInstallationStatus":
        """Create an installation status from a dictionary.

        Args:
            data: Dictionary containing installation status data

        Returns:
            UVToolInstallationStatus instance
        """
        # Handle timestamp conversion
        timestamp = None
        if data.get("installation_timestamp"):
            timestamp = datetime.fromisoformat(data["installation_timestamp"])

        return cls(
            tool_name=data["tool_name"],
            is_installed=data["is_installed"],
            installed_version=data.get("installed_version"),
            installation_attempted=data.get("installation_attempted", False),
            installation_successful=data.get("installation_successful", False),
            installation_error=data.get("installation_error"),
            installation_time=data.get("installation_time"),
            installation_timestamp=timestamp,
            version_constraint=data.get("version_constraint"),
            is_pre_installed=data.get("is_pre_installed", False),
            pre_installed_version=data.get("pre_installed_version"),
            pre_installed_path=data.get("pre_installed_path"),
            preferred_source=data.get("preferred_source", "none"),
            available=data.get("available", False),
        )

    def mark_installation_attempted(
        self, version_constraint: Optional[str] = None
    ) -> None:
        """Mark that installation was attempted.

        Args:
            version_constraint: Version constraint used for installation
        """
        self.installation_attempted = True
        self.installation_timestamp = datetime.now()
        if version_constraint:
            self.version_constraint = version_constraint

    def mark_installation_successful(
        self,
        installed_version: Optional[str] = None,
        installation_time: Optional[float] = None,
    ) -> None:
        """Mark installation as successful.

        Args:
            installed_version: Version of the installed tool
            installation_time: Time taken for installation in seconds
        """
        self.installation_successful = True
        self.is_installed = True
        self.installation_error = None
        if installed_version:
            self.installed_version = installed_version
        if installation_time is not None:
            self.installation_time = installation_time

    def mark_installation_failed(
        self, error_message: str, installation_time: Optional[float] = None
    ) -> None:
        """Mark installation as failed.

        Args:
            error_message: Error message describing the failure
            installation_time: Time taken for the failed installation attempt
        """
        self.installation_successful = False
        self.installation_error = error_message
        if installation_time is not None:
            self.installation_time = installation_time

    def update_pre_installed_info(
        self,
        is_pre_installed: bool,
        version: Optional[str] = None,
        path: Optional[str] = None,
    ) -> None:
        """Update pre-installed tool information.

        Args:
            is_pre_installed: Whether the tool is pre-installed
            version: Version of the pre-installed tool
            path: Path to the pre-installed executable
        """
        self.is_pre_installed = is_pre_installed
        if version:
            self.pre_installed_version = version
        if path:
            self.pre_installed_path = path

        # Update availability and preferred source
        self._update_availability_and_preference()

    def _update_availability_and_preference(self) -> None:
        """Update availability status and preferred source based on installation status."""
        # Tool is available if it's installed via UV or pre-installed
        self.available = self.is_installed or self.is_pre_installed

        # Determine preferred source
        if self.is_installed:
            # Prefer UV-managed tools for consistency and isolation
            self.preferred_source = "uv"
        elif self.is_pre_installed:
            # Fall back to pre-installed tools
            self.preferred_source = "pre_installed"
        else:
            self.preferred_source = "none"

    def get_effective_version(self) -> Optional[str]:
        """Get the version of the tool from the preferred source.

        Returns:
            Version string from the preferred source, or None if not available
        """
        if self.preferred_source == "uv":
            return self.installed_version
        elif self.preferred_source == "pre_installed":
            return self.pre_installed_version
        return None

    def get_effective_source_info(self) -> dict:
        """Get information about the effective tool source.

        Returns:
            Dictionary with information about the tool source being used
        """
        if self.preferred_source == "uv":
            return {
                "source": "uv",
                "version": self.installed_version,
                "path": None,  # UV tools don't have a direct path
                "managed": True,
            }
        elif self.preferred_source == "pre_installed":
            return {
                "source": "pre_installed",
                "version": self.pre_installed_version,
                "path": self.pre_installed_path,
                "managed": False,
            }
        else:
            return {"source": "none", "version": None, "path": None, "managed": False}

    def is_tool_available(self) -> bool:
        """Check if the tool is available from any source.

        Returns:
            True if tool is available, False otherwise
        """
        return self.available

    def prefers_uv_installation(self) -> bool:
        """Check if UV installation is preferred over pre-installed.

        Returns:
            True if UV installation is preferred, False otherwise
        """
        return self.preferred_source == "uv"


@dataclass
class UVToolInstallCommand:
    """Data class for UV tool installation command configuration.

    This class encapsulates the configuration needed to install a UV tool,
    including version constraints, additional arguments, and execution parameters.
    """

    tool_name: str
    """Name of the tool to install"""

    version_constraint: Optional[str] = None
    """Version constraint for installation (e.g., '>=1.7.0', '==3.2.0')"""

    additional_args: List[str] = None
    """Additional arguments to pass to the UV tool install command"""

    timeout: int = 300
    """Timeout in seconds for the installation command"""

    retry_count: int = 0
    """Number of retry attempts if installation fails"""

    retry_delay: float = 1.0
    """Delay in seconds between retry attempts"""

    def __post_init__(self):
        """Initialize default values after dataclass creation."""
        if self.additional_args is None:
            self.additional_args = []

    def build_install_command(self, uv_executable: str = "uv") -> List[str]:
        """Build the complete UV tool install command.

        Args:
            uv_executable: Path to the UV executable

        Returns:
            List of command arguments for subprocess execution
        """
        # Build tool specification with version constraint
        if self.version_constraint:
            tool_spec = f"{self.tool_name}{self.version_constraint}"
        else:
            tool_spec = self.tool_name

        # Build command
        command = [uv_executable, "tool", "install", tool_spec]

        # Add additional arguments
        command.extend(self.additional_args)

        return command

    def build_install_command_string(self, uv_executable: str = "uv") -> str:
        """Build the complete UV tool install command as a string.

        Args:
            uv_executable: Path to the UV executable

        Returns:
            Command string for display or logging
        """
        command_parts = self.build_install_command(uv_executable)
        return " ".join(command_parts)

    def to_dict(self) -> dict:
        """Convert the install command to a dictionary for serialization.

        Returns:
            Dictionary representation of the install command
        """
        return {
            "tool_name": self.tool_name,
            "version_constraint": self.version_constraint,
            "additional_args": self.additional_args,
            "timeout": self.timeout,
            "retry_count": self.retry_count,
            "retry_delay": self.retry_delay,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "UVToolInstallCommand":
        """Create an install command from a dictionary.

        Args:
            data: Dictionary containing install command data

        Returns:
            UVToolInstallCommand instance
        """
        return cls(
            tool_name=data["tool_name"],
            version_constraint=data.get("version_constraint"),
            additional_args=data.get("additional_args", []),
            timeout=data.get("timeout", 300),
            retry_count=data.get("retry_count", 0),
            retry_delay=data.get("retry_delay", 1.0),
        )

    def with_version_constraint(
        self, version_constraint: str
    ) -> "UVToolInstallCommand":
        """Create a new install command with a different version constraint.

        Args:
            version_constraint: New version constraint

        Returns:
            New UVToolInstallCommand instance with updated version constraint
        """
        return UVToolInstallCommand(
            tool_name=self.tool_name,
            version_constraint=version_constraint,
            additional_args=self.additional_args.copy(),
            timeout=self.timeout,
            retry_count=self.retry_count,
            retry_delay=self.retry_delay,
        )

    def with_timeout(self, timeout: int) -> "UVToolInstallCommand":
        """Create a new install command with a different timeout.

        Args:
            timeout: New timeout in seconds

        Returns:
            New UVToolInstallCommand instance with updated timeout
        """
        return UVToolInstallCommand(
            tool_name=self.tool_name,
            version_constraint=self.version_constraint,
            additional_args=self.additional_args.copy(),
            timeout=timeout,
            retry_count=self.retry_count,
            retry_delay=self.retry_delay,
        )

    def with_retry_config(
        self, retry_count: int, retry_delay: float = 1.0
    ) -> "UVToolInstallCommand":
        """Create a new install command with retry configuration.

        Args:
            retry_count: Number of retry attempts
            retry_delay: Delay between retries in seconds

        Returns:
            New UVToolInstallCommand instance with updated retry configuration
        """
        return UVToolInstallCommand(
            tool_name=self.tool_name,
            version_constraint=self.version_constraint,
            additional_args=self.additional_args.copy(),
            timeout=self.timeout,
            retry_count=retry_count,
            retry_delay=retry_delay,
        )
