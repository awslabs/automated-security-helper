"""Module containing the AbstractScanner base class."""

from abc import abstractmethod
import shutil
from typing import Any, Dict, List, Optional, Union
import subprocess

from automated_security_helper.models.config import ScannerConfig
from automated_security_helper.models.interfaces import IScanner


class AbstractScanner(IScanner):
    """Abstract base class for security scanners."""

    def __init__(self) -> None:
        """Initialize the scanner.

        Args:
            config: Scanner configuration as dict or ScannerConfig object
        """
        self._name = "<unknown>"
        self._config = None
        self._type = ""
        self._process = None
        self._output = []
        self._output_format = "text"
        self._errors = []
        self._options = {}

    def _set_config(
        self, config: Optional[Union[Dict[str, Any], ScannerConfig]]
    ) -> None:
        """Set scanner configuration."""
        self._config = config

    @property
    def name(self) -> str:
        """Get scanner name from config."""
        return self._name

    @property
    def type(self) -> str:
        """Get the scanner type."""
        return self._type

    @property
    def config(self) -> Optional[Union[Dict[str, Any], ScannerConfig]]:
        """Get the scanner configuration."""
        return self._config

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

    def configure(self, config: Dict[str, Any] | ScannerConfig | None = None):
        if config is None:
            self._set_config(ScannerConfig())

        if isinstance(config, dict) and "name" in config:
            config = ScannerConfig(**config)
        if isinstance(config, ScannerConfig):
            self._name = config.name
            self._type = config.type
            if hasattr(config, "options"):
                self._options.update(config.options)

        self._set_config(config)

    def validate(self) -> bool:
        """Verify scanner configuration and requirements."""
        exists = shutil.which(self.config.command) is not None
        return exists and self._config is not None

    @abstractmethod
    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> None:
        """Execute the security scan.

        Args:
            target: The target to scan (file, directory, etc.)
            options: Optional dictionary of scan options specific to the scanner

        Raises:
            ScannerError: If there is an error during scanning
        """
        pass

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
            self._process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
            )
            stdout, stderr = self._process.communicate()
            if stdout:
                self._output.extend(stdout.splitlines())
            if stderr:
                self._errors.extend(stderr.splitlines())
        except Exception as e:
            raise ScannerError(f"Error running scanner: {str(e)}") from e


class ScannerError(Exception):
    """Exception raised when scanner execution fails."""

    pass
