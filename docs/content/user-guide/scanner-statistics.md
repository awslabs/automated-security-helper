# Scanner Statistics

This document explains how scanner statistics are calculated and displayed in ASH reports and terminal output.

## Overview

ASH provides comprehensive statistics for each scanner that is executed during a scan. These statistics include:

- **Severity Counts**: Number of findings at each severity level (Critical, High, Medium, Low, Info)
- **Suppressed Findings**: Number of findings that have been suppressed
- **Actionable Findings**: Number of findings at or above the threshold severity level
- **Duration**: Time taken by the scanner to complete its execution
- **Status**: Whether the scanner passed, failed, was skipped, or had missing dependencies

These statistics are calculated consistently across all reports and terminal output, ensuring that you see the same numbers regardless of which report format you are viewing.

## Severity Levels

ASH uses the following severity levels for findings:

- **Critical**: Highest severity findings that require immediate attention
- **High**: Serious findings that should be addressed soon
- **Medium**: Moderate risk findings
- **Low**: Lower risk findings
- **Info**: Informational findings with minimal risk

## Suppressed Findings

Suppressed findings are those that have been explicitly marked as suppressed, either through:

1. **Native Scanner Suppressions**: Suppressions applied by the scanner itself
2. **ASH-Applied Suppressions**: Suppressions applied by ASH based on configuration

Suppressed findings are counted separately and do not contribute to the total or actionable finding counts.

## Actionable Findings

Actionable findings are those that are at or above the threshold severity level. The threshold can be set:

1. **Globally**: In the `global_settings.severity_threshold` section of the ASH configuration
2. **Per Scanner**: In the scanner's configuration section

The threshold values and their meanings are:

- **ALL**: All findings are actionable (Critical, High, Medium, Low, Info)
- **LOW**: Findings of low severity or higher are actionable (Critical, High, Medium, Low)
- **MEDIUM**: Findings of medium severity or higher are actionable (Critical, High, Medium)
- **HIGH**: Findings of high severity or higher are actionable (Critical, High)
- **CRITICAL**: Only critical findings are actionable

## Scanner Status

The status of a scanner is determined based on its findings and configuration:

- **PASSED**: The scanner did not find any actionable findings
- **FAILED**: The scanner found actionable findings (at or above the threshold)
- **SKIPPED**: The scanner was explicitly excluded from the scan
- **MISSING**: The scanner has missing dependencies

## Statistics Calculation

All scanner statistics are calculated from the final aggregated SARIF report, ensuring that they reflect the final state of findings after all suppressions and filters have been applied.

The calculation process follows these steps:

1. Extract all findings from the SARIF report
2. Identify which scanner each finding belongs to
3. Count findings by severity level for each scanner
4. Calculate actionable findings based on the threshold
5. Determine scanner status based on actionable findings and configuration

## Terminal Output

The terminal output displays a table with scanner statistics after a scan is completed. The table includes:

- **Scanner**: Name of the scanner
- **Suppressed**: Number of suppressed findings
- **Critical**: Number of critical findings
- **High**: Number of high findings
- **Medium**: Number of medium findings
- **Low**: Number of low findings
- **Info**: Number of informational findings
- **Duration**: Time taken by the scanner
- **Actionable**: Number of actionable findings
- **Result**: Scanner status (PASSED, FAILED, SKIPPED, MISSING)
- **Threshold**: Severity threshold used for this scanner

## Report Formats

ASH provides several report formats, each displaying scanner statistics in a slightly different way:

- **HTML**: Interactive table with color-coded severity levels and status
- **Markdown**: Formatted table with scanner statistics
- **Text**: Plain text table with scanner statistics
- **JSON**: Structured data with scanner statistics

All report formats use the same underlying data, ensuring consistency across different views.

## Interpreting Statistics

When interpreting scanner statistics, keep the following in mind:

1. **Actionable Findings**: Focus on actionable findings, as these are the ones that require attention based on your severity threshold.
2. **Suppressed Findings**: Suppressed findings are not included in the total or actionable counts, as they have been explicitly marked as not requiring attention.
3. **Scanner Status**: A scanner with a FAILED status has actionable findings that need to be addressed.
4. **Threshold Source**: The threshold source indicates where the threshold was defined (global or scanner-specific configuration).

## Example

Here's an example of how to interpret scanner statistics:

```yaml
Scanner: bandit
Suppressed: 5
Critical: 0
High: 2
Medium: 3
Low: 1
Info: 0
Duration: 1.2s
Actionable: 5
Result: FAILED
Threshold: MEDIUM (global)
```

In this example:
- The bandit scanner found 2 high, 3 medium, and 1 low severity findings
- 5 findings were suppressed
- The threshold is MEDIUM, set in the global configuration
- Since the threshold is MEDIUM, the actionable findings include high and medium severity (2 + 3 = 5)
- The scanner status is FAILED because it found actionable findings

## Conclusion

Scanner statistics provide valuable information about the security posture of your codebase. By understanding how these statistics are calculated and displayed, you can better interpret the results of your security scans and prioritize remediation efforts.