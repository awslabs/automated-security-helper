"""Module containing the AbstractScanner base class."""

import subprocess
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class AbstractScanner(ABC):
    """Abstract base class for security scanners.

    This class provides common functionality for running security scanners
    and handling their output.
    """

    def __init__(self) -> None:
        """Initialize the scanner."""
        self._process: Optional[subprocess.Popen] = None
        self._output: List[str] = []
        self._errors: List[str] = []

    @abstractmethod
    def scan(self, target: str, options: Dict[str, Any]) -> None:
        """Execute the security scan.

        Args:
            target: The target to scan (file, directory, etc.)
            options: Dictionary of scan options specific to the scanner

        Raises:
            ScannerError: If there is an error during scanning
        """
        pass

    def _run_subprocess(self, command: List[str]) -> None:
        """Run a subprocess with the given command.

        Args:
            command: List of command arguments to execute

        Raises:
            ScannerError: If there is an error running the subprocess
        """
        try:
            result = subprocess.run(command, capture_output=True, check=True)

            if result.stdout:
                self._output.extend(result.stdout.splitlines())
            if result.stderr:
                self._errors.extend(result.stderr.splitlines())

        except subprocess.CalledProcessError as e:
            if e.stdout:
                self._output.extend(e.stdout.splitlines())
            if e.stderr:
                self._errors.extend(e.stderr.splitlines())
            raise ScannerError(f"Scanner failed with return code {e.returncode}")
        except (subprocess.SubprocessError, OSError) as e:
            raise ScannerError(f"Failed to run scanner: {str(e)}")

    @property
    def output(self) -> List[str]:
        """Get the captured output from the scan.

        Returns:
            List of output lines from the scan
        """
        return self._output

    @property
    def errors(self) -> List[str]:
        """Get any error messages from the scan.

        Returns:
            List of error messages from the scan
        """
        return self._errors


class ScannerError(Exception):
    """Exception raised for scanner-related errors."""

    pass
