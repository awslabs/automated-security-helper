#!/usr/bin/env python3
"""Main entry point for ASH multi-scanner execution."""

import argparse
import json
import logging
import shutil
import sys
from pathlib import Path
from typing import Annotated, Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field

from automated_security_helper.config.config_manager import ConfigurationManager
from automated_security_helper.config.default_config import DEFAULT_ASH_CONFIG
from automated_security_helper.execution_engine import (
    ExecutionStrategy,
    ScanExecutionEngine,
)
from automated_security_helper.config.config import ASHConfig
from automated_security_helper.models.data_interchange import ExportFormat
from automated_security_helper.result_processor import ResultProcessor


class ASHScanOrchestrator(BaseModel):
    """Orchestrator class for ASH security scanning operations."""

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="allow")

    source_dir: Annotated[Path, Field(..., description="Source directory to scan")]
    output_dir: Annotated[Path, Field(..., description="Output directory for results")]
    work_dir: Annotated[
        Path, Field(Path("./work"), description="Working directory for scan operations")
    ]
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
    debug: Annotated[bool, Field(False, description="Enable debug logging")]
    offline: Annotated[bool, Field(False, description="Run in offline mode")]
    no_run: Annotated[bool, Field(False, description="Only build container image")]
    build_target: Annotated[
        str, Field("default", description="Build target for container image")
    ]
    oci_runner: Annotated[str, Field("docker", description="OCI runner to use")]
    no_cleanup: Annotated[
        bool, Field(False, description="Keep work directory after scan")
    ]
    metadata: Annotated[
        Dict[str, Any],
        Field(default_factory=dict, description="Additional metadata for the scan"),
    ]

    # Core components
    config_manager: Annotated[
        ConfigurationManager | None, Field(description="Configuration manager")
    ] = None
    result_processor: Annotated[
        ResultProcessor | None, Field(description="Result processor")
    ] = None
    execution_engine: Annotated[ScanExecutionEngine | None, Field()] = None
    logger: Annotated[logging.Logger | None, Field()] = logging.Logger(name=__name__)

    def ensure_directories(self):
        """Ensure required directories exist.

        Creates source_dir if it doesn't exist, work_dir if it doesn't exist or if no_cleanup
        is True, and output_dir if it doesn't exist.
        """
        # Create source directory if it doesn't exist
        if not self.source_dir.exists():
            self.source_dir.mkdir(parents=True, exist_ok=True)

        # Create work directory if it doesn't exist or if no_cleanup is True
        if not self.work_dir.exists() or self.no_cleanup:
            # Remove existing work dir if no_cleanup is True to ensure clean state
            if self.work_dir.exists() and self.no_cleanup:
                shutil.rmtree(self.work_dir)
            self.work_dir.mkdir(parents=True, exist_ok=True)

        # Create output directory if it doesn't exist
        if not self.output_dir.exists():
            self.output_dir.mkdir(parents=True, exist_ok=True)

    def model_post_init(self, context):
        super().model_post_init(context)
        self.logger = self._get_logger()
        self.config_manager = ConfigurationManager()
        self.result_processor = ResultProcessor(
            logger=self.logger,
        )
        self.execution_engine = ScanExecutionEngine(
            source_dir=self.source_dir,
            output_dir=self.output_dir,
            work_dir=self.work_dir,
            strategy=ExecutionStrategy.SEQUENTIAL,
            logger=self.logger,
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
            self.logger.info(
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
            self.logger.warning(
                f"Failed to load configuration from {self.config_path}: {e}. Using default configuration."
            )
            return DEFAULT_ASH_CONFIG

    def execute_scan(self) -> Dict:
        """Execute the security scan and return results."""
        logger = self._get_logger()
        logger.info("Starting ASH scan")

        try:
            # Ensure required directories exist
            self.ensure_directories()
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
                    source_dir=self.source_dir,
                    output_dir=self.output_dir,
                    work_dir=self.work_dir,
                    logger=self.logger,
                    strategy=ExecutionStrategy.SEQUENTIAL,
                )

            # self.execution_engine._scanner_factory

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
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Run in offline mode (skips NPM/PNPM/Yarn Audit checks)",
    )
    parser.add_argument(
        "--no-run",
        action="store_true",
        help="Only build the container image, do not run scans",
    )
    parser.add_argument(
        "--build-target",
        default="default",
        help="Specify build target for container image (e.g. 'ci' for elevated access)",
    )
    parser.add_argument(
        "--oci-runner",
        default="docker",
        help="Specify OCI runner to use (e.g. 'docker', 'finch')",
    )
    parser.add_argument(
        "--no-cleanup",
        action="store_true",
        help="Keep working directory after scan completes",
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
