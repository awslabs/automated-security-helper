"""Module containing the ScannerPlugin base class."""

from abc import abstractmethod
from pathlib import Path
import shutil
from typing import Any, Dict, List, Optional
import subprocess

from automated_security_helper.config.config import ScannerPluginConfig
from automated_security_helper.models.data_interchange import (
    ExportFormat,
    SecurityReport,
)
from automated_security_helper.models.interfaces import IScanner


class ScannerPlugin(IScanner):
    """Abstract base class for ASH scanner plugins."""

    source_dir: Path = Path("/src")
    output_dir: Path = Path("/out")
    work_dir: Path = output_dir.joinpath("work")
    results_dir: Path = output_dir.joinpath("results")

    _name: str = "<unknown>"
    _type: str = ""
    _process = None
    _output: List[str] = []
    _output_format: ExportFormat = ExportFormat.TEXT
    _errors: List[str] = []
    _options: Dict[str, Any] = {}
    _config: ScannerPluginConfig | None = None
    _default_config: ScannerPluginConfig | None = None
    _protected_config_properties: List[str] = ["name", "type", "options"]

    def __init__(self) -> None:
        """Initialize the scanner.

        Args:
            config: Scanner configuration as dict or ScannerConfig object
        """
        self._config = self._default_config

    def _set_config(self, config: ScannerPluginConfig = None) -> None:
        """Set scanner configuration."""
        self._config = config

    @property
    def name(self) -> str:
        """Get scanner name from config."""
        if self._config and hasattr(self._config, "name"):
            return self._config.name
        return self._name

    @property
    def type(self) -> str:
        """Get the scanner type."""
        return self._type

    @property
    def config(self) -> Optional[ScannerPluginConfig]:
        """Get the scanner configuration."""
        return self._config

    @property
    def default_config(self) -> ScannerPluginConfig:
        """Get the scanner default configuration."""
        return self._default_config

    @property
    def options(self) -> Dict[str, Any]:
        """Get the scanner options."""
        return self._options

    @property
    def output(self) -> List[str]:
        """Get the scanner output."""
        return self._output

    @property
    def output_format(self) -> List[str]:
        """Get the scanner output format."""
        return self._output_format

    @property
    def errors(self) -> List[str]:
        """Get the scanner errors."""
        return self._errors

    def configure(self, config: ScannerPluginConfig | None = None):
        """Configure the scanner with the provided config, doing a deep merge if config already exists.

        Args:
            config: Scanner configuration as ScannerPluginConfig object or dict
        """
        # Return if no new config and no existing config
        if config is None and (
            self._config is None or len(self._config.command.__str__()) == 0
        ):
            raise ScannerError(
                "No configuration provided for this scanner, unable to run scanner"
            )

        # Convert dict config to ScannerPluginConfig
        if isinstance(config, dict) and "name" in config:
            config = ScannerPluginConfig(**config)

        # If we have a new config object
        if isinstance(config, ScannerPluginConfig):
            if self._config is None:
                # No existing config, just set directly
                self._name = config.name
                self._type = config.type
                if hasattr(config, "options"):
                    self._options.update(config.options)
                self._config = config
            else:
                # Merge with existing config
                self._name = config.name or self._name
                self._type = config.type
                if hasattr(config, "options"):
                    self._options.update(config.options)

            # Deep merge other attributes from new config into existing
            # Prevent overridding of protected configuration values.
            for attr, value in vars(config).items():
                if (
                    value is not None
                    and f"{value}" != ""
                    and attr not in self._protected_config_properties
                ):
                    setattr(self._config, attr, value)

        if config is None and (
            self._config is None or len(self._config.command.__str__()) == 0
        ):
            raise ScannerError(
                "No configuration provided for this scanner, unable to run scanner"
            )

        if isinstance(config, dict) and "name" in config:
            config = ScannerPluginConfig(**config)
        if isinstance(config, ScannerPluginConfig):
            self._name = config.name
            self._type = config.type
            if hasattr(config, "options"):
                self._options.update(config.options)

        self._config = config

    def validate(self) -> bool:
        """Verify scanner configuration and requirements."""
        exists = shutil.which(self.config.command) is not None
        return exists and self._config is not None

    @abstractmethod
    def scan(
        self, target: str, options: Optional[Dict[str, Any]] = None
    ) -> SecurityReport:
        """Execute the security scan.

        Args:
            target: The target to scan (file, directory, etc.)
            options: Optional dictionary of scan options specific to the scanner

        Raises:
            ScannerError: If there is an error during scanning
        """
        pass

    def _resolve_arguments(self, target: str) -> List[str]:
        """Resolve command arguments for the scanner.

        Args:
            target: The target to scan

        Returns:
            List of command arguments
        """
        if not target:
            raise ScannerError("No target specified")
        if not self._config:
            raise ScannerError("Scanner configuration not set")
        if not self._config.command:
            raise ScannerError("No command specified")

        path_arg = [
            item
            for item in [
                self._config.scan_path_arg,
                target,
            ]
            if item
        ]
        format_arg = [
            item
            for item in [
                self._config.format_arg,
                self._config.format_arg_value,
            ]
            if item
        ]

        args = [
            item
            for item in [
                self._config.command,
                *(
                    format_arg
                    if self._config.format_arg_position == "before_args"
                    else []
                ),
                *(
                    path_arg
                    if self._config.scan_path_arg_position == "before_args"
                    else []
                ),
                *self._config.args,
                *(
                    format_arg
                    if self._config.format_arg_position == "after_args"
                    else []
                ),
                *(
                    path_arg
                    if self._config.scan_path_arg_position == "after_args"
                    else []
                ),
            ]
            if item
        ]
        return args

    def _pre_scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> None:
        """Execute the actual scan operation.

        Args:
            target: The target to scan

        Raises:
            ScannerError: If there is an error during scanning
        """
        if not target:
            raise ScannerError("No target specified")
        if options:
            self._options.update(options)

    def _run_subprocess(self, command: List[str]) -> None:
        """Run a subprocess with the given command.

        Args:
            command: Command to execute as list of strings

        Raises:
            ScannerError: If subprocess execution fails
        """
        try:
            self._process = subprocess.run(
                command,
                capture_output=True,
                check=True,
            )
            if self._process.stdout:
                self._output.extend(self._process.stdout.decode().splitlines())
            if self._process.stderr:
                self._errors.extend(self._process.stderr.decode().splitlines())
        except subprocess.CalledProcessError as e:
            raise ScannerError(f"Scanner {self._name} failed: {e.stderr}") from e
        except Exception as e:
            raise ScannerError(
                f"Exception running scanner {self._name}: {str(e)}"
            ) from e


class ScannerError(Exception):
    """Exception raised when scanner execution fails."""

    pass
