"""Module containing the ScannerPlugin base class."""

import logging
import queue
import shutil
import subprocess
import threading
from abc import abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional
from typing_extensions import Self

from pydantic import BaseModel, model_validator

from automated_security_helper.models.core import BaseScannerOptions
from automated_security_helper.models.data_interchange import SecurityReport
from automated_security_helper.models.interfaces import IScanner


class ScannerPluginConfig(BaseModel):
    """Base configuration class for scanner plugins."""

    name: str = "base-scanner"
    description: str = "Base scanner configuration."
    enabled: bool = True
    options: Dict[str, Any] = {}
    check_for_updates: bool = False


class ScannerPlugin(IScanner, BaseModel):
    """Base class for all scanner plugins."""

    _default_config: Optional[ScannerPluginConfig] = None
    _config: Optional[ScannerPluginConfig] = None
    _output: List[str] = []
    _errors: List[str] = []
    _work_path: Path | None = None
    _args: List[str] = []

    # Required fields that should be set in child classes
    source_dir: Path | None = None
    output_dir: Path | None = None
    findings: List[Any] = []
    enabled: bool = True
    options: BaseScannerOptions = BaseScannerOptions()
    work_dir: Path | None = None
    results_dir: Path | None = None
    results_file: Path | None = None
    tool_version: str = "0.0.0"
    logger: Any = None

    @model_validator(mode="after")
    def setup_paths(self) -> Self:
        """Set up default paths and initialize plugin configuration."""
        # Use default paths if none provided
        if self.source_dir is None:
            self.source_dir = Path(".")
        if self.output_dir is None:
            self.output_dir = Path("output")

        # Ensure paths are Path objects
        self.source_dir = Path(str(self.source_dir))
        self.output_dir = Path(str(self.output_dir))
        self.work_dir = self.output_dir.joinpath("work")

        # Set up scanner name
        if self._config is None:
            self._config = self._default_config
        scanner_name = (
            getattr(self._config, "name", "unknown") if self._config else "unknown"
        )
        self.logger = logging.getLogger(f"ash.scanners.{scanner_name}")

        self.results_dir = self.output_dir.joinpath("scanners").joinpath(scanner_name)
        if self.results_dir.exists():
            shutil.rmtree(self.results_dir)
        self.results_dir.mkdir(parents=True, exist_ok=True)

        return self

    def _set_config(self, config: ScannerPluginConfig = None) -> None:
        """Set scanner configuration."""
        self._config = config or self._default_config

    @property
    def config(self) -> Optional[ScannerPluginConfig]:
        """Get scanner configuration."""
        return self._config

    @property
    def default_config(self) -> Optional[ScannerPluginConfig]:
        """Get default scanner configuration."""
        return self._default_config

    @property
    def output(self) -> List[str]:
        """Get scanner output."""
        return self._output

    @property
    def output_format(self) -> List[str]:
        """Get output format."""
        return []

    @property
    def errors(self) -> List[str]:
        """Get scanner errors."""
        return self._errors

    def configure(
        self,
        config: ScannerPluginConfig | None = None,
        options: BaseScannerOptions | None = None,
    ):
        """Configure scanner."""
        self._set_config(config)
        if options:
            self.options = options

    @abstractmethod
    def validate(self) -> bool:
        """Validate scanner configuration.

        Returns:
            bool: True if validation passes
        """

    @abstractmethod
    def scan(self, *args, **kwargs) -> SecurityReport:
        """Execute scanner against a target.

        Args:
            *args: Variable length argument list
            **kwargs: Arbitrary keyword arguments

        Returns:
            SecurityReport: Full scan results

        Raises:
            ScannerError: if scanning failed for any reason
        """

    def _build_security_report(self, scan_results: Any) -> SecurityReport:
        """Build security report from scan results.

        Args:
            scan_results: Raw scan results to process

        Returns:
            SecurityReport: Processed scan results
        """
        report = SecurityReport()
        report.scanner_type = self.type
        return report

    def _resolve_arguments(self, target: str) -> List[str]:
        """Resolve any configured options into command line arguments.

        Args:
            target: Target to scan

        Returns:
            List[str]: Arguments to pass to scanner
        """
        return self._args

    def _pre_scan(self, target: Path, options: Optional[Dict[str, Any]] = None) -> None:
        """Perform pre-scan setup.

        Args:
            target: Target to scan
            options: Optional scanner-specific options
        """
        if options:
            self.options.update(options)

        self.work_dir.mkdir(parents=True, exist_ok=True)
        if self.results_dir:
            self.results_dir.mkdir(parents=True, exist_ok=True)

    def _consume_output(self, p: subprocess.Popen, q: queue.Queue) -> None:
        """Consume subprocess output and put it in a queue."""
        for line in iter(p.stdout.readline, b""):
            q.put(line.decode("utf-8").rstrip())

    def _run_subprocess(self, command: List[str]) -> None:
        """Run a subprocess with the given command.

        Args:
            command: Command to run

        Raises:
            ScannerError: If process errors
        """
        q = queue.Queue()
        with subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
            universal_newlines=False,
            encoding=None,
        ) as p:
            t = threading.Thread(target=self._consume_output, args=(p, q))
            t.daemon = True
            t.start()

            output = []
            while True:
                try:
                    line = q.get_nowait()
                    output.append(line)
                    self.logger.debug(line)
                except queue.Empty:
                    if not t.is_alive() and q.empty():
                        break

            t.join()
