# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Deprecated module - Use scanner_statistics_calculator instead.

This module is kept for backward compatibility but should not be used in new code.
All functionality has been moved to the scanner_statistics_calculator module.
"""

from typing import Tuple

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)


def calculate_actionable_count(
    critical: int, high: int, medium: int, low: int, info: int, threshold: str
) -> int:
    """Calculate the number of actionable findings based on the threshold.

    DEPRECATED: Use ScannerStatisticsCalculator.calculate_actionable_count instead.

    This function is kept for backward compatibility but should not be used in new code.
    """
    return ScannerStatisticsCalculator.calculate_actionable_count(
        critical, high, medium, low, info, threshold
    )


def extract_sarif_counts_for_scanner(
    asharp_model: AshAggregatedResults, scanner_name: str
) -> Tuple[int, int, int, int, int, int]:
    """Extract severity counts from the final processed SARIF data for a specific scanner.

    DEPRECATED: Use ScannerStatisticsCalculator.extract_sarif_counts_for_scanner instead.

    This function is kept for backward compatibility but should not be used in new code.
    """
    return ScannerStatisticsCalculator.extract_sarif_counts_for_scanner(
        asharp_model, scanner_name
    )


def get_scanner_threshold_info(
    asharp_model: AshAggregatedResults, scanner_name: str
) -> Tuple[str, str]:
    """Get the threshold and threshold source for a scanner.

    DEPRECATED: Use ScannerStatisticsCalculator.get_scanner_threshold_info instead.

    This function is kept for backward compatibility but should not be used in new code.
    """
    return ScannerStatisticsCalculator.get_scanner_threshold_info(
        asharp_model, scanner_name
    )


def get_scanner_status_info(
    asharp_model: AshAggregatedResults, scanner_name: str
) -> Tuple[bool, bool]:
    """Get scanner status information.

    DEPRECATED: Use ScannerStatisticsCalculator.get_scanner_status_info instead.

    This function is kept for backward compatibility but should not be used in new code.
    """
    return ScannerStatisticsCalculator.get_scanner_status_info(
        asharp_model, scanner_name
    )
