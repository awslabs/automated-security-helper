"""Module containing the JupyterScanner implementation."""

import logging
from pathlib import Path
from typing import Dict, Any, Optional

from automated_security_helper.config.config import ScannerPluginConfig
from automated_security_helper.models.data_interchange import ExportFormat
from automated_security_helper.models.scanner_plugin import ScannerPlugin
from automated_security_helper.utils.get_ash_version import get_ash_version


class JupyterScanner(ScannerPlugin):
    """Scanner implementation for Jupyter notebooks security scanning."""

    _default_config = ScannerPluginConfig(
        name="jupyter",
        type="SAST",
        command="self.scan_jupyter_notebooks()",
        invocation_mode="file",
        get_tool_version_command=get_ash_version,
        enabled=True,
        output_format="dict",
    )
    _output_format = ExportFormat.DICT
    tool_version = get_ash_version()

    def __init__(
        self,
        source_dir: Optional[Path] = None,
        output_dir: Optional[Path] = None,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        """Initialize the scanner.

        Args:
            source_dir: Source directory to scan
            output_dir: Output directory for results
            logger: Optional logger instance
        """
        super().__init__(source_dir, output_dir, logger)

    def scan(self, source_path: Path, output_path: Path) -> Dict[str, Any]:
        """Run security scan on Jupyter notebooks.

        Args:
            source_path: Path to source code to scan.
            output_path: Path where to store scan results.

        Returns:
            Dict[str, Any]: Raw scan results.
        """
        # Return empty results for now
        return {"findings": [], "metadata": {}}
