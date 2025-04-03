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
        if not self.config_path:
            self._get_logger().info(
                "No configuration file provided, using default configuration"
            )
            return DEFAULT_ASH_CONFIG

        try:
            with open(self.config_path, "r") as f:
                if str(self.config_path).endswith(".json"):
                    config_data = json.load(f)
                else:
                    config_data = yaml.safe_load(f)

                # Transform loaded data into ASHConfig
                if isinstance(config_data, dict):
                    try:
                        # # If config has sast.scanners, process them into proper scanner objects
                        # if "sast" in config_data and isinstance(config_data["sast"], dict):
                        #     sast_config = config_data["sast"]
                        #     if "scanners" in sast_config:
                        #         scanners = []
                        #         scanner_configs = sast_config["scanners"] if isinstance(sast_config["scanners"], list) else [sast_config["scanners"]]

                        #         for scanner_config in scanner_configs:
                        #             if isinstance(scanner_config, dict):
                        #                 scanner_type = scanner_config.get("type", "").lower().replace("scanner", "")
                        #                 if scanner_type == "bandit":
                        #                     scanners.append(BanditScanner(**scanner_config))
                        #                 elif scanner_type == "cdknag":
                        #                     scanners.append(CDKNagScanner(**scanner_config))

                        #         sast_config["scanners"] = scanners

                        # Validate and create ASHConfig from processed data
                        config = ASHConfig(**config_data)
                        return config

                    except Exception as e:
                        self._get_logger().warning(
                            f"Failed to parse configuration: {e}"
                        )
                        return DEFAULT_ASH_CONFIG
                return DEFAULT_ASH_CONFIG

        except Exception as e:
            self._get_logger().warning(
                f"Failed to load configuration from {self.config_path}: {e}. Using default configuration."
            )
            return DEFAULT_ASH_CONFIG

    def execute_scan(self) -> Dict:
        """Execute the security scan and return results."""
        logger = self._get_logger()
        logger.info("Starting ASH scan")

        try:
            # Load configuration
            config = self._load_config()

            # Ensure we have ASHConfig instance after loading
            if not isinstance(config, ASHConfig):
                self._get_logger().warning(
                    "Invalid configuration format, using default"
                )
                config = DEFAULT_ASH_CONFIG

            # Create execution engine with default scanners
            if not hasattr(self, "execution_engine"):
                self.execution_engine = ScanExecutionEngine(
                    strategy=ExecutionStrategy.SEQUENTIAL
                )

            # Execute scanners with config
            results = self.execution_engine.execute(config)

            # Add empty results if none returned
            results = results or {"scanners": {}}
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
