# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Example scanner plugin for ASH."""

from pathlib import Path
from typing import List, Literal, Any

from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.utils.log import ASH_LOGGER


class ExampleScannerConfig(ScannerPluginConfigBase):
    """Configuration for the example scanner."""

    pass


@ash_scanner_plugin
class ExampleScanner(ScannerPluginBase[ExampleScannerConfig]):
    """Example scanner plugin that demonstrates the decorator pattern."""

    def validate(self) -> bool:
        """Validate scanner configuration.

        Returns:
            bool: True if validation passes
        """
        ASH_LOGGER.info("ExampleScanner: Validating configuration")
        return True

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] = [],
        config: Any = None,
        *args,
        **kwargs,
    ) -> dict:
        """Scan a target file/directory.

        This example scanner simply logs the target and returns a mock finding.

        Args:
            target: Target file or directory to scan
            target_type: Type of target (source or converted)
            global_ignore_paths: List of paths to ignore
            config: Scanner configuration

        Returns:
            dict: Scan results
        """
        self._pre_scan(target, target_type, config)

        if self.context is None:
            ASH_LOGGER.warning("ExampleScanner: No context provided!")
            return {"findings": []}

        ASH_LOGGER.info(f"ExampleScanner: Scanning {target} ({target_type})")

        # In a real scanner, you would do some scanning here
        # For this example, we'll just return a mock finding
        result = {
            "findings": [
                {
                    "id": "EXAMPLE-001",
                    "name": "Example Finding",
                    "description": "This is an example finding from the ExampleScanner",
                    "severity": "LOW",
                    "location": {"path": str(target), "line": 1, "column": 1},
                }
            ]
        }

        self._post_scan(target, target_type)
        return result
