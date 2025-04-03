#!/usr/bin/env python3
"""
ASH Multi Scanner Entrypoint

This script serves as the main entrypoint for the ASH container, orchestrating the execution
of security scanners and processing their results.
"""

import argparse
import json
import logging
import logging.config
import sys
from typing import Dict

import yaml

from automated_security_helper.config.config_manager import ConfigurationManager
from automated_security_helper.scanners.scanner_factory import ScannerFactory
from automated_security_helper.execution_engine import (
    ScanExecutionEngine,
    ExecutionStrategy,
)
from automated_security_helper.result_processor import ResultProcessor


def parse_args():
    parser = argparse.ArgumentParser(description="ASH Multi-Scanner Execution Tool")
    parser.add_argument(
        "-c",
        "--config",
        help="Path to ASH configuration file (optional - will use default configuration if not provided)",
        required=False,
        default=None,
    )
    parser.add_argument(
        "-o", "--output", help="Output file for scan results", required=True
    )
    parser.add_argument(
        "-v", "--verbose", help="Enable verbose logging", action="store_true"
    )
    return parser.parse_args()


def get_logger(verbose: bool) -> logging.Logger:
    level = logging.DEBUG if verbose else logging.INFO
    logger = logging.Logger("ASH", level=level)
    return logger


def load_config(config_path: str) -> Dict:
    # Default configuration with best practices
    default_config = {
        "scanners": {
            "bandit": {"enabled": True, "config": "bandit.yaml"},
            "cfn": {"enabled": True},
        },
        "output": {"format": "json", "file": "scan_results.json"},
    }

    if not config_path:
        logging.info("No configuration file provided, using default configuration")
        return default_config

    try:
        with open(config_path, "r") as f:
            if config_path.endswith(".json"):
                user_config = json.load(f)
            elif config_path.endswith(".yaml") or config_path.endswith(".yml"):
                user_config = yaml.safe_load(f)
            # Merge user config with defaults, user config takes precedence
            return {**default_config, **user_config}
    except yaml.error.YAMLError as e:
        raise e
    except FileNotFoundError as e:
        raise e
    except Exception as e:
        logging.warning(
            f"Failed to load configuration from {config_path}: {e}. Using default configuration."
        )
        return default_config


def main():
    args = parse_args()
    logger = get_logger(args.verbose)
    logger.info("Starting ASH scan")

    # Load and process configuration
    config = load_config(args.config)
    config_manager = ConfigurationManager()
    resolved_config = config_manager.resolve_configuration(config)

    # Initialize scanner factory and execution engine
    scanner_factory = ScannerFactory()
    engine = ScanExecutionEngine(strategy=ExecutionStrategy.PARALLEL)

    # Create and queue scanners based on configuration
    for scanner_config in resolved_config.get("scanners", []):
        scanner_name = scanner_config.get("name")
        if not scanner_name:
            logging.warning("Skipping scanner with missing name in configuration")
            continue

        try:
            scanner = scanner_factory.create_scanner(scanner_name, scanner_config)
            engine.queue_scanner(scanner)
        except Exception as e:
            logging.error(f"Failed to create scanner {scanner_name}: {e}")
            continue

    # Execute all scanners
    engine.execute()

    # Process results
    result_processor = ResultProcessor()
    results = []

    for scanner in engine.completed_scanners:
        try:
            result = result_processor.process_results(
                scanner.scanner_type, scanner.get_results()
            )
            results.append(result)
        except Exception as e:
            logging.error(f"Failed to process results for {scanner.scanner_type}: {e}")

    # Write final results
    try:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
    except Exception as e:
        logging.error(f"Failed to write results to {args.output}: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
