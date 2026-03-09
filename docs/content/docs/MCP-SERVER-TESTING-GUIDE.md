# ASH MCP Server Testing Guide

This guide explains how to test the ASH MCP server locally during development, including configuration, testing procedures, and troubleshooting.

## Prerequisites

- ASH repository cloned locally
- `uv` and `uvx` installed ([installation guide](https://docs.astral.sh/uv/getting-started/installation/))
- Kiro IDE or another MCP-compatible client
- Python 3.10 or later

## Configuration for Local Testing

### 1. Configure MCP Client to Use Local Code

Update your MCP configuration file to point to your local development directory instead of the GitHub repository.

**Location:** `~/.kiro/settings/mcp.json` (for Kiro)

**Configuration:**

```json
{
  "mcpServers": {
    "ash": {
      "command": "uvx",
      "args": [
        "--directory=/path/to/your/automated-security-helper",
        "--with=.",
        "ash",
        "mcp"
      ],
      "autoApprove": [
        "get_scan_progress",
        "get_scan_results",
        "get_scan_summary",
        "get_scan_result_paths",
        "run_ash_scan"
      ],
      "disabled": false,
      "env": {
        "FASTMCP_LOG_LEVEL": "DEBUG"
      }
    }
  }
}
```

**Key Parameters:**
- `--directory=/path/to/your/automated-security-helper` - Points to your local repo
- `--with=.` - Installs the package from the current directory (editable mode)
- `FASTMCP_LOG_LEVEL: DEBUG` - Enables detailed logging for debugging

**Note:** Replace `/path/to/your/automated-security-helper` with your actual path.

### 2. Restart MCP Server

After configuration changes:

**In Kiro:**
1. Open Command Palette (Cmd/Ctrl + Shift + P)
2. Search for "MCP: Reconnect Server"
3. Select the ASH server to reconnect

**Alternative:** Restart your IDE/client completely

### 3. Verify Configuration

You may see a warning like:
```
warning: An executable named `ash` is not provided by package `ash` 
but is available via the dependency `automated-security-helper`.
```

This is safe to ignore - the command will work correctly.

## Testing Procedures

### Test 1: Check Installation

Verify ASH is properly installed and accessible.

```python
# Call the check_installation tool
result = await mcp_ash_check_installation()

# Expected response:
{
  "success": true,
  "installed": true,
  "version": "3.2.2",  # or your current version
  "ash_command_available": true,
  "ash_command_output": "ASH version 3.2.2",
  "timestamp": "2026-02-28T10:10:41.009478"
}
```

**What to verify:**
- `success` is `true`
- `installed` is `true`
- `version` matches your local version
- `ash_command_available` is `true`

### Test 2: Run a Scan

Start a security scan on a test directory.

```python
# Start a scan
result = await mcp_ash_run_ash_scan(
    source_dir="/path/to/test/project",
    severity_threshold="MEDIUM",
    clean_output=true
)

# Expected response:
{
  "success": true,
  "status": "running",
  "scan_id": "2e0cd8d2-132c-4eb1-a822-38dd237067f3",
  "progress": 0.0,
  "message": "Scan started, initializing scanners...",
  "directory_path": "/path/to/test/project"
}
```

**What to verify:**
- `success` is `true`
- `scan_id` is returned (save this for later tests)
- `status` is "running"
- No error messages

**Timing:** Note the start time to verify polling intervals later.

### Test 3: Monitor Scan Progress

Check scan progress using the scan ID from Test 2.

```python
# Check progress (wait 15-20 seconds after starting scan)
result = await mcp_ash_get_scan_progress(
    scan_id="2e0cd8d2-132c-4eb1-a822-38dd237067f3"
)

# Expected response:
{
  "scan_id": "2e0cd8d2-132c-4eb1-a822-38dd237067f3",
  "status": "running",  # or "completed"
  "completed_scanners": 3,
  "total_scanners": 9,
  "scanners": {
    "bandit": {
      "source": {
        "status": "completed",
        "finding_count": 45,
        "severity_counts": {...}
      }
    },
    // ... more scanners
  }
}
```

**What to verify:**
- Progress updates arrive every 5-15 seconds (check timestamps)
- `completed_scanners` increases over time
- Scanner statuses transition from "pending" → "running" → "completed"

**Expected Duration:** 2-5 minutes for typical projects

### Test 4: Get Scan Result Paths (NEW)

Retrieve file paths for all result files.

```python
# Get result file paths
result = await mcp_ash_get_scan_result_paths(
    output_dir="/path/to/test/project/.ash/ash_output"
)

# Expected response:
{
  "success": true,
  "output_dir": "/path/to/test/project/.ash/ash_output",
  "reports_dir": "/path/to/test/project/.ash/ash_output/reports",
  "files": {
    "sarif": {
      "path": "/path/to/.../ash.sarif",
      "exists": true,
      "size_bytes": 4220964
    },
    "flat_json": {...},
    "html": {...},
    // ... more file types
  },
  "scanner_results": {
    "bandit": {
      "source": {
        "path": "/path/to/.../bandit/source/ASH.ScanResults.json",
        "exists": true,
        "size_bytes": 394
      }
    }
  }
}
```

**What to verify:**
- Response size is small (~2-5KB)
- All expected file types are listed
- `exists` is `true` for all files
- `size_bytes` is reasonable (not 0)
- Scanner-specific results are included

### Test 5: Get Scan Summary (NEW)

Retrieve lightweight summary without detailed findings.

```python
# Get summary
result = await mcp_ash_get_scan_summary(
    output_dir="/path/to/test/project/.ash/ash_output"
)

# Expected response:
{
  "success": true,
  "scan_id": "scan-20260228101237",
  "status": "completed",
  "is_complete": true,
  "completion_time": "2026-02-28T15:12:09+00:00",
  "metadata": {
    "generated_at": "2026-02-28T15:10:46+00:00",
    "ash_version": "3.2.2",
    "scan_duration_seconds": 80.6
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
        "findings_count": 128,
        "actionable_findings": 61,
        "duration": 21.04,
        "by_severity": {
          "critical": 0,
          "high": 0,
          "medium": 0,
          "low": 61,
          "suppressed": 67
        }
      }
      // ... more scanners
    },
    "total_scanners": 9,
    "completed_scanners": 9
  }
}
```

**What to verify:**
- Response size is small (~5-10KB)
- NO `raw_results` field with full data
- NO detailed findings arrays
- Only summary statistics and counts
- Scanner-level summaries included

### Test 6: Get Full Scan Results

Retrieve scan results with filtering applied.

```python
# Get full results
result = await mcp_ash_get_scan_results(
    output_dir="/path/to/test/project/.ash/ash_output"
)

# Expected response structure:
{
  "success": true,
  "scan_id": "scan-20260228101237",
  "status": "completed",
  "summary_stats": {...},
  "scanner_reports": {...},
  "raw_results": {
    // Should NOT include:
    // - "sarif" field
    // - "cyclonedx" field
    // - "findings" array
    // - "validation_checkpoints" array
    "metadata": {...},
    "scanner_results": {...}
  },
  "note": "Large data fields removed for MCP transport..."
}
```

**What to verify:**
- Response size is moderate (<100KB, not 1.6MB+)
- Large fields are removed (sarif, cyclonedx, findings)
- Summary data is still present
- Note about data truncation is included

### Test 7: List Active Scans

List all scans in the registry.

```python
# List scans
result = await mcp_ash_list_active_scans()

# Expected response:
{
  "success": true,
  "active_scans": [],  # or list of running scans
  "all_scans": [
    {
      "scan_id": "2e0cd8d2-132c-4eb1-a822-38dd237067f3",
      "status": "completed",
      "directory_path": "/path/to/test/project",
      "start_time": "2026-02-28T10:10:46.026299",
      "end_time": "2026-02-28T10:12:09.962812"
    }
  ],
  "stats": {
    "total_scans": 1,
    "active_scans": 0,
    "status_counts": {
      "completed": 1,
      "running": 0,
      "failed": 0
    }
  }
}
```

**What to verify:**
- All recent scans are listed
- Status counts are accurate
- Timestamps are present

## Performance Verification

### Polling Intervals

Monitor the timestamps in progress updates to verify adaptive polling:

**Expected Intervals:**
- Early phase (0-2 scanners): ~5 seconds
- Mid phase (2-4 scanners): ~8 seconds
- Late phase (4+ scanners): ~10 seconds
- Heartbeat (no progress): ~15 seconds

**How to verify:**
1. Note timestamps from multiple `get_scan_progress` calls
2. Calculate time differences
3. Confirm intervals match expected ranges

### Response Sizes

Compare response sizes across tools:

| Tool | Expected Size | What to Check |
|------|---------------|---------------|
| `get_scan_summary` | 5-10KB | No raw_results, no findings arrays |
| `get_scan_result_paths` | 2-5KB | Only paths and metadata |
| `get_scan_results` | <100KB | Large fields removed |
| Full aggregated file | 5-10MB | On disk, not via MCP |

**How to verify:**
1. Save responses to files
2. Check file sizes: `ls -lh response.json`
3. Inspect content for unexpected large fields

## Error Handling Tests

### Test Connection Resilience

Verify the server handles disconnections gracefully.

**Procedure:**
1. Start a scan
2. Disconnect/kill the MCP client mid-scan
3. Reconnect after scan completes
4. Verify scan completed successfully
5. Retrieve results

**Expected behavior:**
- Scan continues running after disconnect
- Results are saved to disk
- No `ClosedResourceError` in logs
- Can retrieve results after reconnect

### Test Invalid Parameters

Verify error handling for invalid inputs.

```python
# Test with non-existent directory
result = await mcp_ash_get_scan_results(
    output_dir="/non/existent/path"
)

# Expected response:
{
  "success": false,
  "error": "Output directory does not exist: /non/existent/path",
  "error_type": "DirectoryNotFound"
}
```

**What to verify:**
- `success` is `false`
- Clear error message
- Appropriate error_type
- No stack traces in response

## Troubleshooting

### Issue: MCP Server Not Using Local Code

**Symptoms:**
- Changes not reflected after restart
- Old behavior persists

**Solutions:**
1. Clear uvx cache:
   ```bash
   rm -rf ~/.cache/uv/
   ```

2. Force reinstall:
   ```bash
   uvx --force --directory=/path/to/ash --with=. ash mcp
   ```

3. Verify configuration path is correct
4. Restart IDE completely

### Issue: Import Errors

**Symptoms:**
```
ModuleNotFoundError: No module named 'automated_security_helper'
```

**Solutions:**
1. Ensure you're in the correct directory
2. Check `--directory` path in config
3. Verify `--with=.` is present
4. Install dependencies:
   ```bash
   cd /path/to/ash
   pip install -e .
   ```

### Issue: Tools Not Found

**Symptoms:**
```
Tool 'get_scan_summary' not found
```

**Solutions:**
1. Verify tool is registered in `mcp_server.py`
2. Check for syntax errors: `python -m py_compile automated_security_helper/cli/mcp_server.py`
3. Restart MCP server
4. Check MCP logs for registration errors

### Issue: Large Response Sizes

**Symptoms:**
- `get_scan_summary` returns >100KB
- Timeouts or slow responses

**Solutions:**
1. Verify filtering logic in `get_scan_summary`
2. Check that large fields are being removed
3. Compare with `get_scan_result_paths` (should be small)
4. Review code for proper data extraction

## Logging and Debugging

### Enable Debug Logging

Set log level in MCP config:
```json
"env": {
  "FASTMCP_LOG_LEVEL": "DEBUG"
}
```

### View MCP Logs

**In Kiro:**
- Open "MCP Logs" panel
- Filter by server name "ash"
- Look for errors, warnings, or debug messages

**In Terminal:**
```bash
# ASH logs are in the .ash folder of your scan directory
tail -f .ash/ash_output/ash.log
```

### Common Log Messages

**Normal:**
```
INFO: Starting scan for directory: /path/to/project
INFO: Scan started with ID: 2e0cd8d2-132c-4eb1-a822-38dd237067f3
INFO: Scanner bandit completed
```

**Warnings (safe to ignore):**
```
warning: An executable named `ash` is not provided by package `ash`
```

**Errors (need attention):**
```
ERROR: Failed to send progress update: ClosedResourceError
ERROR: Error in get_scan_summary: KeyError
```

## Checklist for Complete Testing

- [ ] Configuration updated to use local code
- [ ] MCP server restarted/reconnected
- [ ] `check_installation` returns success
- [ ] Scan starts successfully
- [ ] Progress updates arrive at correct intervals (5-15s)
- [ ] `get_scan_result_paths` returns small response (~2-5KB)
- [ ] `get_scan_summary` returns small response (~5-10KB)
- [ ] `get_scan_results` has large fields filtered (<100KB)
- [ ] No `ClosedResourceError` in logs
- [ ] Scan completes successfully
- [ ] Can retrieve results after completion
- [ ] Error handling works for invalid inputs
- [ ] Connection resilience verified (disconnect test)

## Next Steps

After successful testing:

1. **Document findings** - Note any issues or improvements
2. **Update tests** - Add automated tests for new features
3. **Performance metrics** - Record actual vs expected timings
4. **Create PR** - Submit changes with test results
5. **Update documentation** - Reflect new tools and capabilities

## Additional Resources

- [MCP Server Guide](mcp-server-guide.md)
- [MCP Tools Reference](MCP-TOOLS-REFERENCE.md)
- [MCP Improvements Summary](MCP-IMPROVEMENTS-SUMMARY.md)
- [ASH Configuration Guide](configuration-guide.md)
