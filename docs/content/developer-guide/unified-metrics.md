# Unified Metrics System

The Unified Metrics System provides a centralized implementation for calculating and accessing scanner metrics across all components of ASH. It serves as the single source of truth for scanner statistics, ensuring consistency across all reports and displays.

## Overview

Prior to the implementation of the Unified Metrics System, scanner statistics were calculated inconsistently across different parts of the application. This led to discrepancies in how scanner statistics were displayed in different report formats and in the terminal output.

The Unified Metrics System addresses this issue by providing a centralized implementation for calculating scanner statistics that is used consistently across all components of ASH. This ensures that all reports and displays show the same statistics for each scanner.

## Architecture

The Unified Metrics System follows a layered architecture:

1. **Core Statistics Calculation Layer**: The `ScannerStatisticsCalculator` class is responsible for extracting raw data from the SARIF and scanner results.
2. **Unified Metrics Layer**: The `unified_metrics` module processes the raw data to produce consistent metrics objects.
3. **Presentation Layer**: Various reporters and displays consume the unified metrics to display statistics in different formats.

## Key Components

### ScannerStatisticsCalculator

The `ScannerStatisticsCalculator` class provides static methods for extracting and calculating scanner statistics from the final aggregated SARIF data. It is used by the unified metrics module but can also be used directly if more fine-grained control over the statistics calculation is needed.

#### `extract_scanner_statistics(asharp_model: AshAggregatedResults) -> Dict[str, Dict[str, Any]]`

Extract statistics for all scanners from the final aggregated SARIF file.

#### `extract_sarif_counts_for_scanner(asharp_model: AshAggregatedResults, scanner_name: str) -> Tuple[int, int, int, int, int, int]`

Extract severity counts from the final processed SARIF data for a specific scanner.

#### `calculate_actionable_count(critical: int, high: int, medium: int, low: int, info: int, threshold: str) -> int`

Calculate the number of actionable findings based on the threshold.

#### `get_scanner_threshold_info(asharp_model: AshAggregatedResults, scanner_name: str) -> Tuple[str, str]`

Get the threshold and threshold source for a scanner.

#### `get_scanner_status_info(asharp_model: AshAggregatedResults, scanner_name: str) -> Tuple[bool, bool]`

Get scanner status information.

#### `get_scanner_status(asharp_model: AshAggregatedResults, scanner_name: str) -> str`

Determine the status of a scanner based on its findings and configuration.

#### `get_summary_statistics(asharp_model: AshAggregatedResults) -> Dict[str, Any]`

Calculate summary statistics across all scanners.

### Unified Metrics Module

The `unified_metrics` module provides a higher-level API for accessing scanner metrics. It defines the `ScannerMetrics` data structure and provides functions to generate unified scanner metrics from the final aggregated SARIF data.

#### `ScannerMetrics` Named Tuple

The `ScannerMetrics` named tuple is the single source of truth for scanner metrics that should be used by all table generators and reporters. It contains comprehensive statistics for a single scanner, including counts for different severity levels, suppressed findings, actionable findings, and status information.

#### `get_unified_scanner_metrics(asharp_model: AshAggregatedResults) -> List[ScannerMetrics]`

Generate unified scanner metrics from AshAggregatedResults.

#### `get_summary_metrics(asharp_model: AshAggregatedResults) -> Dict[str, Any]`

Get summary metrics from AshAggregatedResults.

#### `format_duration(duration_seconds: Optional[float]) -> str`

Format duration in seconds to a human-readable string.

## Usage

### For Reporters and Displays

Reporters and displays should use the `get_unified_scanner_metrics` function to get scanner metrics:

```python
from automated_security_helper.core.unified_metrics import get_unified_scanner_metrics

# Get unified metrics for all scanners
scanner_metrics = get_unified_scanner_metrics(asharp_model)

# Access metrics for a specific scanner
for metrics in scanner_metrics:
    if metrics.scanner_name == "bandit":
        print(f"Bandit found {metrics.actionable} actionable findings")
```

### For Summary Statistics

To get summary statistics across all scanners, use the `get_summary_metrics` function:

```python
from automated_security_helper.core.unified_metrics import get_summary_metrics

# Get summary metrics
summary = get_summary_metrics(asharp_model)
print(f"Total findings: {summary['total_findings']}")
print(f"Actionable findings: {summary['total_actionable']}")
```

## Best Practices

1. **Use the Unified Metrics System**: Always use the Unified Metrics System for calculating and displaying scanner statistics. This ensures consistency across all reports and displays.

2. **Avoid Direct SARIF Processing**: Avoid processing SARIF data directly to extract statistics. Instead, use the `ScannerStatisticsCalculator` or the `unified_metrics` module.

3. **Consistent Status Reporting**: Use the status values provided by the Unified Metrics System for consistent status reporting across all reports and displays.

4. **Threshold-Based Actionable Findings**: Use the `actionable` field in the `ScannerMetrics` named tuple to determine if a scanner has actionable findings based on its threshold.

5. **Formatting Durations**: Use the `format_duration` function to format scanner durations consistently across all reports and displays.

## Deprecated Components

The following components are deprecated and should not be used in new code:

- `scanner_metrics_calculator.py`: This module is kept for backward compatibility but should not be used in new code. All functionality has been moved to the `scanner_statistics_calculator.py` module.

## Conclusion

The Unified Metrics System provides a centralized implementation for calculating and accessing scanner metrics across all components of ASH. By using this system consistently, we ensure that all reports and displays show the same statistics for each scanner, improving the user experience and making the application more maintainable.