# ASH MCP Server - Filtering Guide

## Overview
The `get_scan_results` tool provides comprehensive filtering capabilities to control both response size and content. This guide explains all available filtering options and how to use them effectively.

## Filter Parameters

### 1. `filter_level` - Response Size Control

Controls how much data is returned in the response.

**Options:**
- `"full"` (default) - Complete results including raw_results, validation_checkpoints, etc. (50KB-2MB)
- `"summary"` - Summary data only: metadata, findings counts, scanner summaries (~5-15KB)
- `"minimal"` - Basic status only: scan_id, status, summary_stats (~1-2KB)

**Use when:**
- `full`: Need complete scan data, detailed analysis, comprehensive reporting
- `summary`: Quick status checks, dashboards, CI/CD gates
- `minimal`: Health checks, polling for completion, fast status queries

### 2. `actionable_only` - Exclude Suppressed Findings

Filter out suppressed findings (false positives or accepted risks) to focus only on findings that require action.

**Type:** Boolean (default: `False`)

**When True:**
- Excludes all findings marked as suppressed
- Returns only findings that require attention
- Updates summary stats to reflect only actionable findings
- Sets `suppressed` count to 0 in all statistics

**Use when:**
- CI/CD pipeline gates (fail only on actionable findings)
- Focusing on work that needs to be done
- Excluding known false positives from analysis
- Generating reports for developers (hide accepted risks)

**Examples:**
```python
# Get only actionable findings
actionable = await get_scan_results(
    output_dir=".ash/ash_output",
    actionable_only=True
)

# Combine with severity filter for high-priority actionable findings
high_priority_actionable = await get_scan_results(
    output_dir=".ash/ash_output",
    actionable_only=True,
    severities="critical,high"
)

# Get actionable summary for dashboard
actionable_summary = await get_scan_results(
    output_dir=".ash/ash_output",
    actionable_only=True,
    filter_level="summary"
)
```

### 3. `scanners` - Scanner/Tool Filtering

Filter results to include only specific security scanners.

**Format:** Comma-separated list of scanner names (case-insensitive)

**Available scanners:**
- `bandit` - Python SAST
- `semgrep` - Multi-language SAST
- `opengrep` - Open-source Semgrep rules
- `checkov` - Infrastructure as Code scanner
- `cdk-nag` - AWS CDK security scanner
- `cfn-nag` - CloudFormation security scanner
- `grype` - Vulnerability scanner
- `npm-audit` - NPM dependency scanner
- `detect-secrets` - Secret detection
- `syft` - SBOM generator

**Examples:**
```python
# Single scanner
scanners="bandit"

# Multiple scanners
scanners="bandit,semgrep,checkov"

# SAST tools only
scanners="bandit,semgrep"

# Dependency scanners only
scanners="grype,npm-audit"
```

### 4. `severities` - Severity Level Filtering

Filter results to include only specific severity levels.

**Format:** Comma-separated list of severity levels (case-insensitive)

**Available severities:**
- `critical` - Critical severity findings
- `high` - High severity findings
- `medium` - Medium severity findings
- `low` - Low severity findings
- `info` - Informational findings
- `suppressed` - Suppressed/ignored findings

**Note:** To exclude suppressed findings, use `actionable_only=True` instead of manually listing all non-suppressed severities.

**Examples:**
```python
# Critical only
severities="critical"

# High-priority findings
severities="critical,high"

# Medium and below
severities="medium,low,info"

# Include suppressed findings explicitly
severities="critical,high,suppressed"
```

## Usage Examples

### Basic Filtering

#### Actionable Findings Only
```python
# Get only actionable findings (exclude suppressed)
actionable = await get_scan_results(
    output_dir=".ash/ash_output",
    actionable_only=True
)

# Actionable summary for dashboard
actionable_summary = await get_scan_results(
    output_dir=".ash/ash_output",
    actionable_only=True,
    filter_level="summary"
)

# Fast check for actionable critical findings
actionable_critical = await get_scan_results(
    output_dir=".ash/ash_output",
    actionable_only=True,
    severities="critical",
    filter_level="minimal"
)
```

#### Response Size Only
```python
# Minimal response for fast status check
status = await get_scan_results(
    output_dir=".ash/ash_output",
    filter_level="minimal"
)

# Summary for dashboard
summary = await get_scan_results(
    output_dir=".ash/ash_output",
    filter_level="summary"
)

# Full results (default)
results = await get_scan_results(
    output_dir=".ash/ash_output",
    filter_level="full"
)
```

#### Scanner Filtering
```python
# Only bandit results
bandit_only = await get_scan_results(
    output_dir=".ash/ash_output",
    scanners="bandit"
)

# SAST tools only
sast_results = await get_scan_results(
    output_dir=".ash/ash_output",
    scanners="bandit,semgrep,opengrep"
)

# Infrastructure scanners
iac_results = await get_scan_results(
    output_dir=".ash/ash_output",
    scanners="checkov,cdk-nag,cfn-nag"
)
```

#### Severity Filtering
```python
# Critical findings only
critical = await get_scan_results(
    output_dir=".ash/ash_output",
    severities="critical"
)

# High-priority findings
high_priority = await get_scan_results(
    output_dir=".ash/ash_output",
    severities="critical,high"
)

# Actionable high-priority (exclude suppressed)
actionable_high_priority = await get_scan_results(
    output_dir=".ash/ash_output",
    actionable_only=True,
    severities="critical,high"
)
```

### Combined Filtering

#### Lightweight + Content Filtering
```python
# Fast check for actionable critical findings
critical_status = await get_scan_results(
    output_dir=".ash/ash_output",
    filter_level="minimal",
    actionable_only=True,
    severities="critical"
)

# Summary of actionable high/critical from SAST tools
sast_summary = await get_scan_results(
    output_dir=".ash/ash_output",
    filter_level="summary",
    scanners="bandit,semgrep",
    severities="critical,high",
    actionable_only=True
)
```

#### Full Details with Content Filtering
```python
# Complete bandit actionable results for critical/high findings
bandit_critical = await get_scan_results(
    output_dir=".ash/ash_output",
    filter_level="full",
    scanners="bandit",
    severities="critical,high",
    actionable_only=True
)

# All actionable dependency scanner results (medium+)
dependency_findings = await get_scan_results(
    output_dir=".ash/ash_output",
    filter_level="full",
    scanners="grype,npm-audit",
    severities="critical,high,medium",
    actionable_only=True
)
```

## Common Use Cases

### CI/CD Pipeline Gates

```python
# Fast actionable critical-only check
result = await get_scan_results(
    output_dir=".ash/ash_output",
    filter_level="minimal",
    actionable_only=True,
    severities="critical"
)

if result["summary_stats"]["critical"] > 0:
    print("CRITICAL actionable findings detected!")
    sys.exit(1)

# Check actionable high-priority findings
result = await get_scan_results(
    output_dir=".ash/ash_output",
    filter_level="summary",
    actionable_only=True,
    severities="critical,high"
)

if result["findings_summary"]["by_severity"]["critical"] > 0:
    sys.exit(1)
elif result["findings_summary"]["by_severity"]["high"] > 5:
    print(f"Too many HIGH actionable findings: {result['findings_summary']['by_severity']['high']}")
    sys.exit(1)
```

### Progressive Analysis

```python
# 1. Quick check for any actionable critical findings
status = await get_scan_results(
    output_dir=".ash/ash_output",
    filter_level="minimal",
    actionable_only=True,
    severities="critical"
)

if status["summary_stats"]["critical"] > 0:
    # 2. Get summary to see which scanners found critical issues
    summary = await get_scan_results(
        output_dir=".ash/ash_output",
        filter_level="summary",
        actionable_only=True,
        severities="critical"
    )
    
    # 3. Get full details for the worst scanner
    worst_scanner = max(
        summary["scanner_summary"]["by_scanner"].items(),
        key=lambda x: x[1]["by_severity"]["critical"]
    )[0]
    
    details = await get_scan_results(
        output_dir=".ash/ash_output",
        filter_level="full",
        scanners=worst_scanner,
        severities="critical",
        actionable_only=True
    )
```

### Scanner Comparison

```python
# Compare SAST vs dependency findings
sast = await get_scan_results(
    output_dir=".ash/ash_output",
    filter_level="summary",
    scanners="bandit,semgrep"
)

dependencies = await get_scan_results(
    output_dir=".ash/ash_output",
    filter_level="summary",
    scanners="grype,npm-audit"
)

print(f"SAST findings: {sast['findings_summary']['by_severity']['total']}")
print(f"Dependency findings: {dependencies['findings_summary']['by_severity']['total']}")
```

### Dashboard/Monitoring

```python
# Get summary of all actionable high-priority findings
dashboard_data = await get_scan_results(
    output_dir=".ash/ash_output",
    filter_level="summary",
    actionable_only=True,
    severities="critical,high"
)

# Display by scanner
for scanner, data in dashboard_data["scanner_summary"]["by_scanner"].items():
    critical = data["by_severity"]["critical"]
    high = data["by_severity"]["high"]
    if critical > 0 or high > 0:
        print(f"{scanner}: {critical} critical, {high} high (actionable)")
```

### Debugging Specific Scanner

```python
# Get full details for a specific scanner
scanner_details = await get_scan_results(
    output_dir=".ash/ash_output",
    filter_level="full",
    scanners="bandit"
)

# Analyze all findings from that scanner
for report in scanner_details["scanner_reports"]["bandit"].values():
    print(f"Status: {report['status']}")
    print(f"Findings: {report['finding_count']}")
    print(f"Duration: {report['duration']}s")
```

## Performance Considerations

### Response Size Impact

| Filter Combination | Typical Size | Use Case |
|-------------------|--------------|----------|
| `filter_level="minimal"` | 1-2KB | Fast polling, health checks |
| `filter_level="minimal", actionable_only=True` | <1KB | Actionable status only |
| `filter_level="minimal", severities="critical"` | <1KB | Critical-only status |
| `filter_level="summary"` | 5-15KB | Dashboard, quick analysis |
| `filter_level="summary", actionable_only=True` | 3-10KB | Actionable summary |
| `filter_level="summary", scanners="bandit"` | 2-5KB | Single scanner summary |
| `filter_level="summary", severities="critical,high"` | 3-8KB | High-priority summary |
| `filter_level="full"` | 50KB-2MB | Complete analysis |
| `filter_level="full", actionable_only=True` | 30KB-1.5MB | Actionable findings only |
| `filter_level="full", scanners="bandit"` | 10-200KB | Single scanner details |
| `filter_level="full", severities="critical"` | 5-100KB | Critical findings details |

### Best Practices

1. **Start Small**: Use `filter_level="minimal"` for initial checks, then fetch more data as needed
2. **Use actionable_only**: For CI/CD and developer workflows, focus on actionable findings with `actionable_only=True`
3. **Filter Early**: Apply `severities` filter to reduce data transfer for high-priority checks
4. **Target Scanners**: Use `scanners` filter when debugging or analyzing specific tools
5. **Combine Filters**: Use multiple filters together for maximum efficiency
6. **Cache Results**: Store filtered results locally to avoid repeated API calls

## Filter Metadata

When using content filters (`scanners`, `severities`, or `actionable_only`), the response includes a `_content_filters` field showing which filters were applied:

```json
{
  "_content_filters": {
    "scanners": ["bandit", "semgrep"],
    "severities": ["critical", "high"],
    "actionable_only": true
  }
}
```

This helps track what filters were used to generate the response.

## Backward Compatibility

All filtering parameters are optional. Calling `get_scan_results` without any filter parameters returns the full results, maintaining backward compatibility with existing code:

```python
# This still works exactly as before
results = await get_scan_results(output_dir=".ash/ash_output")
```
