#!/usr/bin/env python3
"""Main entry point for ASH multi-scanner execution."""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Annotated, Dict, List, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field

from automated_security_helper.config.config_manager import ConfigurationManager
from automated_security_helper.config.default_config import DEFAULT_ASH_CONFIG
from automated_security_helper.execution_engine import (
    ExecutionStrategy,
    ScanExecutionEngine,
)
from automated_security_helper.models.config import ASHConfig
from automated_security_helper.models.data_interchange import ExportFormat
from automated_security_helper.result_processor import ResultProcessor
from automated_security_helper.scanners.scanner_factory import ScannerFactory


class ASHScanOrchestrator(BaseModel):
    """Orchestrator class for ASH security scanning operations."""

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="allow")

    source_dir: Annotated[Path, Field(..., description="Source directory to scan")]
    output_dir: Annotated[Path, Field(..., description="Output directory for results")]
    config: Annotated[
        ASHConfig, Field(description="The resolved ASH configuration")
    ] = DEFAULT_ASH_CONFIG
    scan_output_format: Annotated[
        List[ExportFormat],
        Field(description="Output format for results", alias="scan_output_formats"),
    ] = [
        ExportFormat.JSON,
        ExportFormat.HTML,
        ExportFormat.CSV,
    ]
    config_path: Annotated[
        Optional[Path], Field(None, description="Path to configuration file")
    ]
    verbose: Annotated[bool, Field(False, description="Enable verbose logging")]
    metadata: Annotated[
        Dict,
        Field(default_factory=dict, description="Additional metadata for the scan"),
    ]

    # Core components
    scanner_factory: Annotated[ScannerFactory, Field(description="Scanner factory")] = (
        ScannerFactory()
    )
    config_manager: Annotated[
        ConfigurationManager, Field(description="Configuration manager")
    ] = ConfigurationManager()
    result_processor: Annotated[
        ResultProcessor, Field(description="Result processor")
    ] = ResultProcessor()
    execution_engine: Annotated[ScanExecutionEngine, Field()] = ScanExecutionEngine(
        ExecutionStrategy.PARALLEL
    )

    def _get_logger(self) -> logging.Logger:
        """Configure and return a logger instance."""
        logger = logging.getLogger("ash-multi")
        log_level = logging.DEBUG if self.verbose else logging.INFO
        logger.setLevel(log_level)

        if not logger.handlers:
            handler = logging.StreamHandler()
            handler.setLevel(log_level)
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def _load_config(self) -> ASHConfig:
        """Load configuration from file or return default configuration."""
        # Default configuration with best practices

        if not self.config_path:
            self._get_logger().info(
                "No configuration file provided, using default configuration"
            )
            return self.config

        try:
            with open(self.config_path, "r") as f:
                if str(self.config_path).endswith(".json"):
                    user_config = json.load(f)
                else:
                    user_config = yaml.safe_load(f)
                # Merge user config with defaults, user config takes precedence
                self.config = self.config_manager.merge_configs(
                    self.config, user_config
                )
                return self.config
        except (yaml.YAMLError, FileNotFoundError) as e:
            raise e
        except Exception as e:
            self.get_logger().warning(
                f"Failed to load configuration from {self.config_path}: {e}. Using default configuration."
            )
            return self.config

    def execute_scan(self) -> Dict:
        """Execute the security scan and return results."""
        logger = self._get_logger()
        logger.info("Starting ASH scan")

        try:
            # Load and process configuration
            config = self._load_config()
            resolved_config = self.config_manager.resolve_configuration(config)

            # Execute scanners
            results = self.execution_engine.execute(resolved_config)

            # Process and return results
            return results

        except Exception as e:
            logger.error(f"Error during scan execution: {e}")
            raise


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="ASH Multi-Scanner")
    parser.add_argument("source", help="Source directory to scan")
    parser.add_argument("-o", "--output", required=True, help="Output file path")
    parser.add_argument("-c", "--config", help="Path to configuration file")
    parser.add_argument(
        "-f", "--format", default="json", help="Output format (default: json)"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )

    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_args()

    try:
        # Create orchestrator instance
        orchestrator = ASHScanOrchestrator(
            source_dir=Path(args.source),
            output_dir=Path(args.output).parent,
            output_format=args.format,
            config_path=Path(args.config) if args.config else None,
            verbose=args.verbose,
        )
        # config = orchestrator.config

        # Execute scan
        results = orchestrator.execute_scan()

        # Write results to output file
        output_file = Path(args.output)
        with open(output_file, "w") as f:
            if args.format == "json":
                json.dump(results, f, indent=2)
            else:
                yaml.dump(results, f)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
