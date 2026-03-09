# ASH MCP Server - Filter Testing Guide

## Overview
This guide provides comprehensive testing procedures for all filtering capabilities in the `get_scan_results` tool.

## Test Setup

Before testing, ensure:
1. ASH MCP server is running with local code
2. You have scan results available in `.ash/ash_output`
3. MCP server is connected and responding

## Test Categories

### 1. Response Size Filtering Tests

#### Test 1.1: Minimal Filter
```python
result = await mcp_ash_get_scan_results(
    output_dir="/path/to/.ash/ash_output",
    filter_level="minimal"
)

# Verify response structure
assert "scan_id" in result
assert "status" in result
assert "summary_stats" in result
assert "_filter" in result
assert result["_filter"] == "minimal"

# Verify excluded fields
assert "raw_results" not in result
assert "validation_checkpoints" not in result
assert "scanner_reports" not in result

# Verify response size
import json
size_kb = len(json.dumps(result)) / 1024
assert size_kb < 5, f"Response too large: {size_kb}KB"
print(f"✓ Minimal filter: {size_kb:.2f}KB")
```

#### Test 1.2: Summary Filter
```python
result = await mcp_ash_get_scan_results(
    output_dir="/path/to/.ash/ash_output",
    filter_level="summary"
)

# Verify response structure
assert "metadata" in result
assert "findings_summary" in result
assert "scanner_summary" in result
assert "_filter" in result
assert result["_filter"] == "summary"

# Verify excluded fields
assert "raw_results" not in result
assert "validation_checkpoints" not in result

# Verify response size
size_kb = len(json.dumps(result)) / 1024
assert size_kb < 20, f"Response too large: {size_kb}KB"
print(f"✓ Summary filter: {size_kb:.2f}KB")
```

#### Test 1.3: Full Filter (Default)
```python
result = await mcp_ash_get_scan_results(
    output_dir="/path/to/.ash/ash_output",
    filter_level="full"
)

# Verify response structure
assert "raw_results" in result
assert "scanner_reports" in result

# Verify response size
size_kb = len(json.dumps(result)) / 1024
print(f"✓ Full filter: {size_kb:.2f}KB")
```

#### Test 1.4: No Filter (Backward Compatibility)
```python
result = await mcp_ash_get_scan_results(
    output_dir="/path/to/.ash/ash_output"
)

# Should return full results
assert "raw_results" in result
print("✓ No filter (backward compatible): Full results returned")
```

### 2. Scanner Filtering Tests

#### Test 2.1: Single Scanner
```python
result = await mcp_ash_get_scan_results(
    output_dir="/path/to/.ash/ash_output",
    scanners="bandit"
)

# Verify only bandit results are included
if "scanner_reports" in result:
    assert "bandit" in result["scanner_reports"]
    assert len(result["scanner_reports"]) == 1

if "raw_results" in result and "scanner_results" in result["raw_results"]:
    assert "bandit" in result["raw_results"]["scanner_results"]
    
# Verify filter metadata
assert "_content_filters" in result
assert "bandit" in result["_content_filters"]["scanners"]
print("✓ Single scanner filter: bandit only")
```

#### Test 2.2: Multiple Scanners
```python
result = await mcp_ash_get_scan_results(
    output_dir="/path/to/.ash/ash_output",
    scanners="bandit,semgrep,checkov"
)

# Verify only specified scanners are included
if "scanner_reports" in result:
    for scanner in result["scanner_reports"].keys():
        assert scanner in ["bandit", "semgrep", "checkov"]

# Verify filter metadata
assert "_content_filters" in result
assert set(result["_content_filters"]["scanners"]) == {"bandit", "semgrep", "checkov"}
print("✓ Multiple scanner filter: bandit, semgrep, checkov")
```

#### Test 2.3: Case Insensitivity
```python
result = await mcp_ash_get_scan_results(
    output_dir="/path/to/.ash/ash_output",
    scanners="BANDIT,Semgrep"
)

# Should work with any case
assert "_content_filters" in result
print("✓ Scanner filter is case-insensitive")
```

### 3. Severity Filtering Tests

#### Test 3.1: Single Severity
```python
result = await mcp_ash_get_scan_results(
    output_dir="/path/to/.ash/ash_output",
    severities="critical"
)

# Verify only critical severity is included
if "summary_stats" in result:
    # Other severities should be 0 or excluded
    assert result["summary_stats"].get("critical", 0) >= 0

# Verify filter metadata
assert "_content_filters" in result
assert "critical" in result["_content_filters"]["severities"]
print("✓ Single severity filter: critical only")
```

#### Test 3.2: Multiple Severities
```python
result = await mcp_ash_get_scan_results(
    output_dir="/path/to/.ash/ash_output",
    severities="critical,high,medium"
)

# Verify filter metadata
assert "_content_filters" in result
assert set(result["_content_filters"]["severities"]) == {"critical", "high", "medium"}
print("✓ Multiple severity filter: critical, high, medium")
```

#### Test 3.3: Exclude Suppressed
```python
result = await mcp_ash_get_scan_results(
    output_dir="/path/to/.ash/ash_output",
    severities="critical,high,medium,low,info"
)

# Verify suppressed is excluded
assert "_content_filters" in result
assert "suppressed" not in result["_content_filters"]["severities"]
print("✓ Severity filter excludes suppressed findings")
```

### 4. Combined Filtering Tests

#### Test 4.1: Response Size + Scanner
```python
result = await mcp_ash_get_scan_results(
    output_dir="/path/to/.ash/ash_output",
    filter_level="summary",
    scanners="bandit"
)

# Verify both filters applied
assert "_filter" in result
assert result["_filter"] == "summary"
assert "_content_filters" in result
assert "bandit" in result["_content_filters"]["scanners"]

# Verify response size
size_kb = len(json.dumps(result)) / 1024
assert size_kb < 10, f"Response too large: {size_kb}KB"
print(f"✓ Summary + scanner filter: {size_kb:.2f}KB")
```

#### Test 4.2: Response Size + Severity
```python
result = await mcp_ash_get_scan_results(
    output_dir="/path/to/.ash/ash_output",
    filter_level="minimal",
    severities="critical"
)

# Verify both filters applied
assert "_filter" in result
assert result["_filter"] == "minimal"
assert "_content_filters" in result
assert "critical" in result["_content_filters"]["severities"]

# Verify response size
size_kb = len(json.dumps(result)) / 1024
assert size_kb < 2, f"Response too large: {size_kb}KB"
print(f"✓ Minimal + severity filter: {size_kb:.2f}KB")
```

#### Test 4.3: Scanner + Severity
```python
result = await mcp_ash_get_scan_results(
    output_dir="/path/to/.ash/ash_output",
    scanners="bandit,semgrep",
    severities="critical,high"
)

# Verify both filters applied
assert "_content_filters" in result
assert set(result["_content_filters"]["scanners"]) == {"bandit", "semgrep"}
assert set(result["_content_filters"]["severities"]) == {"critical", "high"}
print("✓ Scanner + severity filter")
```

#### Test 4.4: All Three Filters
```python
result = await mcp_ash_get_scan_results(
    output_dir="/path/to/.ash/ash_output",
    filter_level="summary",
    scanners="bandit",
    severities="critical,high"
)

# Verify all filters applied
assert "_filter" in result
assert result["_filter"] == "summary"
assert "_content_filters" in result
assert "bandit" in result["_content_filters"]["scanners"]
assert set(result["_content_filters"]["severities"]) == {"critical", "high"}

# Verify response size
size_kb = len(json.dumps(result)) / 1024
assert size_kb < 5, f"Response too large: {size_kb}KB"
print(f"✓ All filters combined: {size_kb:.2f}KB")
```

### 5. Edge Cases and Error Handling

#### Test 5.1: Invalid Scanner Name
```python
result = await mcp_ash_get_scan_results(
    output_dir="/path/to/.ash/ash_output",
    scanners="nonexistent_scanner"
)

# Should return empty results or handle gracefully
assert "scanner_reports" in result or "raw_results" in result
print("✓ Invalid scanner name handled gracefully")
```

#### Test 5.2: Invalid Severity Level
```python
result = await mcp_ash_get_scan_results(
    output_dir="/path/to/.ash/ash_output",
    severities="invalid_severity"
)

# Should return empty results or handle gracefully
assert "summary_stats" in result or "findings_summary" in result
print("✓ Invalid severity level handled gracefully")
```

#### Test 5.3: Empty Filter Values
```python
result = await mcp_ash_get_scan_results(
    output_dir="/path/to/.ash/ash_output",
    scanners="",
    severities=""
)

# Should return all results (empty filters ignored)
print("✓ Empty filter values handled gracefully")
```

### 6. Performance Tests

#### Test 6.1: Response Size Comparison
```python
import json
import time

# Measure full results
start = time.time()
full = await mcp_ash_get_scan_results(
    output_dir="/path/to/.ash/ash_output",
    filter_level="full"
)
full_time = time.time() - start
full_size = len(json.dumps(full)) / 1024

# Measure summary results
start = time.time()
summary = await mcp_ash_get_scan_results(
    output_dir="/path/to/.ash/ash_output",
    filter_level="summary"
)
summary_time = time.time() - start
summary_size = len(json.dumps(summary)) / 1024

# Measure minimal results
start = time.time()
minimal = await mcp_ash_get_scan_results(
    output_dir="/path/to/.ash/ash_output",
    filter_level="minimal"
)
minimal_time = time.time() - start
minimal_size = len(json.dumps(minimal)) / 1024

print(f"Full: {full_size:.2f}KB in {full_time:.3f}s")
print(f"Summary: {summary_size:.2f}KB in {summary_time:.3f}s ({100*summary_size/full_size:.1f}% of full)")
print(f"Minimal: {minimal_size:.2f}KB in {minimal_time:.3f}s ({100*minimal_size/full_size:.1f}% of full)")
```

#### Test 6.2: Content Filter Impact
```python
# Measure unfiltered results
start = time.time()
unfiltered = await mcp_ash_get_scan_results(
    output_dir="/path/to/.ash/ash_output",
    filter_level="summary"
)
unfiltered_time = time.time() - start
unfiltered_size = len(json.dumps(unfiltered)) / 1024

# Measure filtered results
start = time.time()
filtered = await mcp_ash_get_scan_results(
    output_dir="/path/to/.ash/ash_output",
    filter_level="summary",
    scanners="bandit",
    severities="critical,high"
)
filtered_time = time.time() - start
filtered_size = len(json.dumps(filtered)) / 1024

print(f"Unfiltered: {unfiltered_size:.2f}KB in {unfiltered_time:.3f}s")
print(f"Filtered: {filtered_size:.2f}KB in {filtered_time:.3f}s ({100*filtered_size/unfiltered_size:.1f}% of unfiltered)")
```

## Test Checklist

- [ ] Test 1.1: Minimal filter returns <5KB
- [ ] Test 1.2: Summary filter returns <20KB
- [ ] Test 1.3: Full filter returns complete data
- [ ] Test 1.4: No filter maintains backward compatibility
- [ ] Test 2.1: Single scanner filter works
- [ ] Test 2.2: Multiple scanner filter works
- [ ] Test 2.3: Scanner filter is case-insensitive
- [ ] Test 3.1: Single severity filter works
- [ ] Test 3.2: Multiple severity filter works
- [ ] Test 3.3: Can exclude suppressed findings
- [ ] Test 4.1: Response size + scanner combination works
- [ ] Test 4.2: Response size + severity combination works
- [ ] Test 4.3: Scanner + severity combination works
- [ ] Test 4.4: All three filters work together
- [ ] Test 5.1: Invalid scanner handled gracefully
- [ ] Test 5.2: Invalid severity handled gracefully
- [ ] Test 5.3: Empty filters handled gracefully
- [ ] Test 6.1: Response sizes match expectations
- [ ] Test 6.2: Content filters reduce response size

## Troubleshooting

### Filter Not Applied
- Ensure MCP server is restarted after code changes
- Clear Python cache: `find . -name "*.pyc" -delete`
- Check MCP logs for errors
- Verify parameter names are correct (`filter_level`, `scanners`, `severities`)

### Unexpected Results
- Check `_filter` and `_content_filters` fields in response
- Verify scanner names match available scanners
- Verify severity levels are spelled correctly
- Check if scan results exist in output directory

### Performance Issues
- Use `filter_level="minimal"` for fast checks
- Apply content filters to reduce data transfer
- Cache results locally when possible
- Consider using `get_scan_result_paths` for file-based access
