# ASH MCP Server - Tools Reference

## Overview
The ASH MCP server provides multiple tools for accessing scan results with different levels of detail. The `get_scan_results` tool now includes a filter parameter for flexible response sizing, and two new specialized tools provide lightweight alternatives.

## Tool 1: `get_scan_results` (Enhanced with Filter Parameter)

### Purpose
Get scan results with optional filtering to control response size. This is the primary tool for accessing scan data, now with flexible filtering options while maintaining backward compatibility.

### Signature
```python
async def get_scan_results(
    ctx: Context, 
    output_dir: str = ".ash/ash_output",
    filter_level: str = "full",
    scanners: str = None,
    severities: str = None,
    actionable_only: bool = False
) -> Dict[str, Any]
```

### Parameters
- `output_dir` (str): Path to the scan output directory (absolute path recommended)
- `filter_level` (str): Filter level for response data. Options:
  - `"full"` (default): Return all results including raw_results, validation_checkpoints, etc.
  - `"summary"`: Return only summary data (metadata, findings counts, scanner summaries)
  - `"minimal"`: Return only basic scan status and completion info
- `scanners` (str, optional): Comma-separated list of scanner names to include (e.g., "bandit,semgrep"). If not specified, includes all scanners.
- `severities` (str, optional): Comma-separated list of severity levels to include (e.g., "critical,high,medium"). Options: critical, high, medium, low, info, suppressed. If not specified, includes all severities.
- `actionable_only` (bool): If True, exclude suppressed findings from results. This filters out findings that have been marked as false positives or accepted risks. Default is False.

### Returns

#### With `filter="full"` (default - backward compatible)
```json
{
  "success": true,
  "scan_id": "scan-20260228095648",
  "status": "completed",
  "is_complete": true,
  "summary_stats": { ... },
  "scanner_reports": { ... },
  "raw_results": {
    "metadata": { ... },
    "scanner_results": { ... },
    "converter_results": { ... },
    "additional_reports": { ... },
    "validation_checkpoints": [ ... ]
  },
  "validation_checkpoints": [ ... ]
}
```

#### With `filter="summary"`
```json
{
  "success": true,
  "scan_id": "scan-20260228095648",
  "status": "completed",
  "is_complete": true,
  "completion_time": "2026-02-28T09:48:56.544Z",
  "metadata": {
    "generated_at": "2026-02-28T09:48:56.544Z",
    "ash_version": "3.2.2",
    "scan_duration_seconds": 230.5
  },
  "findings_summary": {
    "by_severity": {
      "critical": 0,
      "high": 234,
      "medium": 456,
      "low": 178,
      "info": 28,
      "suppressed": 40,
      "total": 896,
      "actionable": 856
    },
    "scan_stats": {
      "passed": 9,
      "failed": 0,
      "missing": 1,
      "skipped": 0
    }
  },
  "scanner_summary": {
    "by_scanner": {
      "bandit": {
        "status": "PASSED",
        "findings_count": 45,
        "actionable_findings": 40,
        "suppressed_findings": 5,
        "duration": 21.5,
        "by_severity": {
          "critical": 0,
          "high": 12,
          "medium": 23,
          "low": 10,
          "info": 0,
          "suppressed": 5
        }
      }
    },
    "total_scanners": 9,
    "completed_scanners": 9
  },
  "_filter": "summary"
}
```

#### With `filter="minimal"`
```json
{
  "success": true,
  "scan_id": "scan-20260228095648",
  "status": "completed",
  "is_complete": true,
  "completion_time": "2026-02-28T09:48:56.544Z",
  "summary_stats": {
    "total": 896,
    "actionable": 856,
    "critical": 0,
    "high": 234,
    "medium": 456,
    "low": 178,
    "info": 28,
    "suppressed": 40,
    "passed": 9,
    "failed": 0,
    "missing": 1,
    "skipped": 0,
    "duration": 230.5
  },
  "_filter": "minimal"
}
```

### Response Sizes
- `filter="full"`: Variable, typically 50KB-2MB depending on findings
- `filter="summary"`: ~5-15KB (lightweight summary)
- `filter="minimal"`: ~1-2KB (status only)

### Use Cases
- **Full (default)**: Backward compatibility, detailed analysis, comprehensive reporting
- **Summary**: Quick status checks, dashboards, CI/CD gates, monitoring
- **Minimal**: Health checks, polling for completion, simple status displays

### Example Usage
```python
# Get full results (backward compatible - default behavior)
results = await get_scan_results(
    output_dir="/path/to/.ash/ash_output"
)

# Get only actionable findings (exclude suppressed)
actionable_results = await get_scan_results(
    output_dir="/path/to/.ash/ash_output",
    actionable_only=True
)

# Get summary with only actionable findings
actionable_summary = await get_scan_results(
    output_dir="/path/to/.ash/ash_output",
    filter_level="summary",
    actionable_only=True
)

# Filter by specific scanners and severities
filtered_results = await get_scan_results(
    output_dir="/path/to/.ash/ash_output",
    scanners="bandit,semgrep",
    severities="critical,high",
    actionable_only=True
)

# Get summary only (lightweight)
summary = await get_scan_results(
    output_dir="/path/to/.ash/ash_output",
    filter_level="summary"
)

# Check for critical findings
if summary["findings_summary"]["by_severity"]["critical"] > 0:
    print("CRITICAL findings detected!")
    # Now get full results for detailed analysis
    full_results = await get_scan_results(
        output_dir="/path/to/.ash/ash_output",
        filter_level="full"
    )

# Get minimal status (smallest response)
status = await get_scan_results(
    output_dir="/path/to/.ash/ash_output",
    filter_level="minimal"
)
print(f"Scan status: {status['status']}, Total findings: {status['summary_stats']['total']}")
```

---

## Tool 2: `get_scan_summary`

### Purpose
Get a lightweight summary of scan results without detailed findings. Ideal for quick status checks, dashboards, and CI/CD gates.

### Signature
```python
async def get_scan_summary(
    ctx: Context, 
    output_dir: str = ".ash/ash_output"
) -> Dict[str, Any]
```

### Parameters
- `output_dir` (str): Path to the scan output directory (absolute path recommended)

### Returns
```json
{
  "success": true,
  "scan_id": "scan-20260228095648",
  "status": "completed",
  "completion_time": "2026-02-28T09:48:56.544Z",
  "metadata": {
    "generated_at": "2026-02-28T09:48:56.544Z",
    "ash_version": "3.2.2",
    "scan_duration_seconds": 230.5,
    "summary_stats": {
      "total": 896,
      "actionable": 856,
      "critical": 0,
      "high": 234,
      "medium": 456,
      "low": 178,
      "info": 28
    }
  },
  "findings_summary": {
    "by_severity": {
      "critical": 0,
      "high": 234,
      "medium": 456,
      "low": 178,
      "info": 28,
      "total": 896,
      "actionable": 856
    }
  },
  "scanner_summary": {
    "by_scanner": {
      "bandit": {
        "status": "PASSED",
        "findings_count": 45,
        "by_severity": {
          "high": 12,
          "medium": 23,
          "low": 10
        }
      },
      "semgrep": {
        "status": "PASSED",
        "findings_count": 234,
        "by_severity": {
          "high": 89,
          "medium": 123,
          "low": 22
        }
      }
    },
    "total_scanners": 7,
    "completed_scanners": 7
  }
}
```

### Response Size
~5-10KB (vs 100KB+ for full results)

### Use Cases
- Quick status checks after scan completion
- Dashboard displays showing scan statistics
- CI/CD pipeline gates (fail on critical/high findings)
- Monitoring and alerting systems
- Initial assessment before fetching detailed results

### Example Usage
```python
# Get lightweight summary
summary = await get_scan_summary(
    output_dir="/Users/user/project/.ash/ash_output"
)

# Check for critical findings
if summary["findings_summary"]["by_severity"]["critical"] > 0:
    print("CRITICAL findings detected!")
    
# Display scanner results
for scanner, info in summary["scanner_summary"]["by_scanner"].items():
    print(f"{scanner}: {info['findings_count']} findings")
```

---

## Tool 3: `get_scan_result_paths`

### Purpose
Get file paths for all scan result files by type. Allows clients to discover available reports and decide which files to read directly.

### Signature
```python
async def get_scan_result_paths(
    ctx: Context, 
    output_dir: str = ".ash/ash_output"
) -> Dict[str, Any]
```

### Parameters
- `output_dir` (str): Path to the scan output directory (absolute path recommended)

### Returns
```json
{
  "success": true,
  "output_dir": "/Users/user/project/.ash/ash_output",
  "reports_dir": "/Users/user/project/.ash/ash_output/reports",
  "files": {
    "sarif": {
      "path": "/Users/user/project/.ash/ash_output/reports/ash.sarif",
      "exists": true,
      "size_bytes": 2456789
    },
    "flat_json": {
      "path": "/Users/user/project/.ash/ash_output/reports/ash.flat.json",
      "exists": true,
      "size_bytes": 1678234
    },
    "html": {
      "path": "/Users/user/project/.ash/ash_output/reports/ash.html",
      "exists": true,
      "size_bytes": 345678
    },
    "csv": {
      "path": "/Users/user/project/.ash/ash_output/reports/ash.csv",
      "exists": true,
      "size_bytes": 123456
    },
    "markdown": {
      "path": "/Users/user/project/.ash/ash_output/reports/ash.summary.md",
      "exists": true,
      "size_bytes": 12345
    },
    "text": {
      "path": "/Users/user/project/.ash/ash_output/reports/ash.summary.txt",
      "exists": true,
      "size_bytes": 8901
    },
    "ocsf": {
      "path": "/Users/user/project/.ash/ash_output/reports/ash.ocsf.json",
      "exists": true,
      "size_bytes": 1671116
    },
    "cyclonedx": {
      "path": "/Users/user/project/.ash/ash_output/reports/ash.cdx.json",
      "exists": true,
      "size_bytes": 567890
    },
    "junit_xml": {
      "path": "/Users/user/project/.ash/ash_output/reports/ash.junit.xml",
      "exists": true,
      "size_bytes": 234567
    },
    "gitlab_sast": {
      "path": "/Users/user/project/.ash/ash_output/reports/ash.gl-sast-report.json",
      "exists": true,
      "size_bytes": 456789
    },
    "aggregated_results": {
      "path": "/Users/user/project/.ash/ash_output/ash_aggregated_results.json",
      "exists": true,
      "size_bytes": 1890234
    }
  },
  "scanners_dir": "/Users/user/project/.ash/ash_output/scanners",
  "scanner_results": {
    "bandit": {
      "source": {
        "path": "/Users/user/project/.ash/ash_output/scanners/bandit/source/ASH.ScanResults.json",
        "exists": true,
        "size_bytes": 45678
      }
    },
    "semgrep": {
      "source": {
        "path": "/Users/user/project/.ash/ash_output/scanners/semgrep/source/ASH.ScanResults.json",
        "exists": true,
        "size_bytes": 234567
      }
    }
  }
}
```

### Response Size
~2-5KB (just paths and metadata)

### Available Report Types
- `sarif` - SARIF format (industry standard)
- `flat_json` - Flat JSON format (easy to parse)
- `html` - HTML report (human-readable)
- `csv` - CSV format (spreadsheet-friendly)
- `markdown` - Markdown summary
- `text` - Plain text summary
- `ocsf` - OCSF format (Open Cybersecurity Schema Framework)
- `cyclonedx` - CycloneDX SBOM (Software Bill of Materials)
- `junit_xml` - JUnit XML (CI/CD integration)
- `gitlab_sast` - GitLab SAST format
- `aggregated_results` - ASH internal aggregated results

### Use Cases
- Discovering which report formats are available
- Checking file sizes before reading
- Building file download/export features
- Integrating with external tools that need specific formats
- Verifying scan completion (all expected files exist)

### Example Usage
```python
# Get all result file paths
paths = await get_scan_result_paths(
    output_dir="/Users/user/project/.ash/ash_output"
)

# Check if SARIF report exists
if paths["files"]["sarif"]["exists"]:
    sarif_path = paths["files"]["sarif"]["path"]
    print(f"SARIF report: {sarif_path} ({paths['files']['sarif']['size_bytes']} bytes)")
    
    # Read SARIF file directly
    with open(sarif_path) as f:
        sarif_data = json.load(f)

# Find the smallest report for quick viewing
smallest = min(
    paths["files"].items(),
    key=lambda x: x[1]["size_bytes"] if x[1]["exists"] else float('inf')
)
print(f"Smallest report: {smallest[0]} ({smallest[1]['size_bytes']} bytes)")

# List all scanner-specific results
for scanner, targets in paths["scanner_results"].items():
    for target, info in targets.items():
        if info["exists"]:
            print(f"{scanner}/{target}: {info['path']}")
```

---

## Comparison: When to Use Each Tool

| Tool | Response Size | Use Case | Data Included |
|------|---------------|----------|---------------|
| `get_scan_results` (filter_level="minimal") | ~1-2KB | Health checks, polling | Status + summary stats only |
| `get_scan_result_paths` | ~2-5KB | File discovery, integration | File paths, sizes, existence |
| `get_scan_summary` | ~5-10KB | Quick status check, statistics | Metadata, counts by severity/scanner |
| `get_scan_results` (filter_level="summary") | ~5-15KB | Detailed summary | Same as get_scan_summary |
| `get_scan_results` (filter_level="full") | 50KB-2MB | Full analysis | All data including raw results |
| `get_scan_results` (actionable_only=True) | Varies | Actionable findings only | Excludes suppressed findings |
| Direct file read | Varies | Full detail, specific format | Complete data in chosen format |

## Content Filtering Options

### Filter by Actionable Findings
Use `actionable_only=True` to exclude suppressed findings (false positives or accepted risks):

```python
# Get only findings that require action
actionable = await get_scan_results(
    output_dir=".ash/ash_output",
    actionable_only=True
)

# Combine with other filters
critical_actionable = await get_scan_results(
    output_dir=".ash/ash_output",
    severities="critical,high",
    actionable_only=True,
    filter_level="summary"
)
```

### Filter by Scanner
Use `scanners` parameter to include only specific scanners:

```python
# Get results from specific scanners only
sast_results = await get_scan_results(
    output_dir=".ash/ash_output",
    scanners="bandit,semgrep"
)
```

### Filter by Severity
Use `severities` parameter to include only specific severity levels:

```python
# Get only high-priority findings
high_priority = await get_scan_results(
    output_dir=".ash/ash_output",
    severities="critical,high"
)
```

### Combine Multiple Filters
All filters can be combined for precise control:

```python
# Get actionable critical/high findings from SAST scanners only
results = await get_scan_results(
    output_dir=".ash/ash_output",
    scanners="bandit,semgrep",
    severities="critical,high",
    actionable_only=True,
    filter_level="summary"
)
```

## Recommended Workflows

### Workflow 1: Progressive Detail (Recommended)
```python
# 1. Start scan
scan = await run_ash_scan(source_dir="/path/to/code")

# 2. Wait for completion (automatic progress updates)
# Progress updates arrive every 5-15 seconds

# 3. Get minimal status first (1-2KB)
status = await get_scan_results(
    output_dir=scan["output_dir"],
    filter="minimal"
)

# 4. Check if scan completed successfully
if status["status"] == "completed":
    # 5. Get summary for decision making (5-15KB)
    summary = await get_scan_results(
        output_dir=scan["output_dir"],
        filter="summary"
    )
    
    # 6. Decide next steps based on summary
    if summary["findings_summary"]["by_severity"]["critical"] > 0:
        # Critical findings - get full results
        full_results = await get_scan_results(
            output_dir=scan["output_dir"],
            filter="full"
        )
        # Analyze detailed findings...
    else:
        print("Scan passed - no critical findings!")
```

### Workflow 2: Using Specialized Tools
```python
# 1. Start scan
scan = await run_ash_scan(source_dir="/path/to/code")

# 2. Wait for completion

# 3. Get quick summary using dedicated tool
summary = await get_scan_summary(output_dir=scan["output_dir"])

# 4. If detailed analysis needed, get file paths
if summary["findings_summary"]["by_severity"]["high"] > 10:
    paths = await get_scan_result_paths(output_dir=scan["output_dir"])
    
    # Read specific format directly
    with open(paths["files"]["sarif"]["path"]) as f:
        sarif_data = json.load(f)
    
    # Or get full results via MCP
    full_results = await get_scan_results(
        output_dir=scan["output_dir"],
        filter="full"
    )
```

### Workflow 3: CI/CD Pipeline
```python
# Minimal data transfer for fast CI/CD checks
# Get only actionable findings (exclude suppressed)
summary = await get_scan_results(
    output_dir=".ash/ash_output",
    filter_level="summary",
    actionable_only=True
)

# Fail pipeline on critical/high actionable findings
critical = summary["findings_summary"]["by_severity"]["critical"]
high = summary["findings_summary"]["by_severity"]["high"]

if critical > 0 or high > 5:
    print(f"Pipeline failed: {critical} critical, {high} high actionable findings")
    sys.exit(1)
else:
    print("Security scan passed!")
    sys.exit(0)
```

### Workflow 4: Focus on Actionable Findings
```python
# Get only findings that require action (exclude suppressed)
actionable = await get_scan_results(
    output_dir=".ash/ash_output",
    actionable_only=True,
    filter_level="summary"
)

# Check actionable findings count
if actionable["findings_summary"]["by_severity"]["actionable"] > 0:
    # Get full details for actionable findings only
    full_actionable = await get_scan_results(
        output_dir=".ash/ash_output",
        actionable_only=True,
        filter_level="full"
    )
    
    # Process actionable findings...
    for run in full_actionable["raw_results"]["sarif"]["runs"]:
        for result in run["results"]:
            # All results here are actionable (not suppressed)
            print(f"Finding: {result['ruleId']} - {result['message']}")
```

## Benefits

1. **Reduced Network Traffic**: Transfer only the data you need with filter parameter
2. **Faster Response Times**: Smaller payloads = faster responses (1KB vs 1MB+)
3. **Flexible Integration**: Choose the right level of detail for your use case
4. **Better Error Handling**: Less likely to timeout on large results
5. **Client Control**: Clients decide what data to fetch and when
6. **Backward Compatibility**: Default behavior unchanged - existing integrations work as-is
7. **Progressive Enhancement**: Start with minimal data, fetch more as needed

## Migration Guide

### For Existing Users
No changes required! The default behavior of `get_scan_results` is unchanged:
```python
# This still works exactly as before
results = await get_scan_results(output_dir=".ash/ash_output")
```

### To Optimize Performance
Add the filter parameter to reduce response size:
```python
# Before (full results, potentially large)
results = await get_scan_results(output_dir=".ash/ash_output")

# After (summary only, ~5-15KB)
summary = await get_scan_results(
    output_dir=".ash/ash_output",
    filter="summary"
)

# Or use dedicated tool
summary = await get_scan_summary(output_dir=".ash/ash_output")
```

## Tool Selection Guide

**Use `get_scan_results` with `filter="minimal"` when:**
- Polling for scan completion
- Health checks and monitoring
- You only need status and basic counts

**Use `get_scan_results` with `filter="summary"` OR `get_scan_summary` when:**
- Quick status checks after scan completion
- Dashboard displays
- CI/CD pipeline gates
- Initial assessment before detailed analysis

**Use `get_scan_results` with `filter="full"` (default) when:**
- You need complete scan data
- Backward compatibility is required
- Detailed analysis of findings
- Comprehensive reporting

**Use `get_scan_result_paths` when:**
- You need to read specific file formats (SARIF, CSV, etc.)
- Building file download/export features
- Integrating with external tools
- You want to process files directly
