# ASH MCP Server Guide

This guide provides comprehensive documentation for the ASH MCP server implementation, which uses a file-based approach to track scan progress and completion.

## Overview

The Automated Security Helper (ASH) MCP server provides a reliable interface for AI assistants to perform security scans on your codebase. The server implements the Model Context Protocol (MCP) to enable seamless integration with AI assistants.

The MCP server uses a file-based approach to track scan progress and completion, making it more reliable than event-based tracking. This approach ensures that scan progress and results are accurately tracked even in complex threading scenarios.

## Architecture

The ASH MCP server architecture consists of the following components:

1. **MCP Server**: The main server component that registers and exposes MCP tools
2. **Scan Registry**: A thread-safe registry that tracks active scans
3. **File-Based Tracking**: A system that uses file existence to track scan progress
4. **Error Handling**: Comprehensive error handling for various scenarios

### File-Based Tracking Approach

The file-based tracking approach works as follows:

1. When a scan is started, a unique scan ID is generated and registered in the scan registry
2. The scan process is started asynchronously
3. The scan progress is tracked by checking for the existence of result files:
   - `ash_aggregated_results.json`: Indicates the scan has completed
   - Individual scanner result files: Indicate which scanners have completed
4. The scan results are retrieved by parsing these files

This approach is more reliable than event-based tracking because it doesn't depend on in-memory state that could be lost due to threading issues.

### File Structure

The file structure used for tracking is as follows:

```
.ash/ash_output/
├── ash_aggregated_results.json       # Complete scan results
├── scanners/
│   ├── bandit/
│   │   ├── source/
│   │   │   └── ASH.ScanResults.json  # Bandit scanner results
│   ├── detect-secrets/
│   │   ├── source/
│   │   │   └── ASH.ScanResults.json  # Detect-secrets scanner results
│   └── ...
└── reports/
    ├── ash_report.csv                # CSV report
    ├── ash_report.html               # HTML report
    └── ash_report.md                 # Markdown report
```

## MCP Tools

The ASH MCP server provides the following tools:

### scan_directory

Starts a security scan asynchronously and returns a scan ID for tracking.

**Parameters:**
- `directory_path` (required): Path to the directory to scan
- `severity_threshold` (optional): Minimum severity threshold (LOW, MEDIUM, HIGH, CRITICAL)
- `config_path` (optional): Path to ASH configuration file

**Returns:**
A dictionary with scan ID and status information.

**Example:**
```python
result = await mcp_scan_directory(
    directory_path="/path/to/your/code",
    severity_threshold="MEDIUM",
    config_path=None
)
```

**Example Response:**
```json
{
  "success": true,
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "pending",
  "directory_path": "/path/to/your/code",
  "output_directory": "/path/to/your/code/.ash/ash_output",
  "severity_threshold": "MEDIUM",
  "config_path": null,
  "start_time": "2025-07-16T12:34:56.789012",
  "message": "Scan started successfully. Use get_scan_progress to track progress."
}
```

### get_scan_progress

Gets the current progress of a running scan using file-based tracking.

**Parameters:**
- `scan_id` (required): The scan ID returned from scan_directory

**Returns:**
A dictionary with scan progress information.

**Example:**
```python
progress = await mcp_get_scan_progress(
    scan_id="550e8400-e29b-41d4-a716-446655440000"
)
```

**Example Response:**
```json
{
  "success": true,
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "completed_scanners": 2,
  "total_scanners": 5,
  "scanners": {
    "bandit": {
      "status": "completed",
      "target_type": "source",
      "finding_count": 3,
      "severity_counts": {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 0,
        "CRITICAL": 0
      }
    },
    "detect-secrets": {
      "status": "completed",
      "target_type": "source",
      "finding_count": 0,
      "severity_counts": {}
    },
    "semgrep": {
      "status": "running",
      "target_type": "source"
    },
    "checkov": {
      "status": "pending",
      "target_type": "source"
    },
    "cdk-nag": {
      "status": "pending",
      "target_type": "source"
    }
  },
  "start_time": "2025-07-16T12:34:56.789012",
  "current_time": "2025-07-16T12:36:23.456789",
  "duration": 86.667777,
  "timestamp": "2025-07-16T12:36:23.456789"
}
```

### get_scan_results

Gets the final results of a completed scan using file-based tracking.

**Parameters:**
- `scan_id` (required): The scan ID returned from scan_directory

**Returns:**
A dictionary with scan results information.

**Example:**
```python
results = await mcp_get_scan_results(
    scan_id="550e8400-e29b-41d4-a716-446655440000"
)
```

**Example Response:**
```json
{
  "success": true,
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "finding_count": 5,
  "severity_counts": {
    "LOW": 1,
    "MEDIUM": 3,
    "HIGH": 1,
    "CRITICAL": 0
  },
  "findings": [
    {
      "id": "finding-1",
      "title": "Hardcoded password",
      "severity": "HIGH",
      "scanner": "detect-secrets",
      "file_path": "config.py",
      "line_number": 42,
      "description": "Hardcoded password found in configuration file"
    },
    // Additional findings...
  ],
  "scan_duration": 124.567890,
  "start_time": "2025-07-16T12:34:56.789012",
  "end_time": "2025-07-16T12:37:01.356902",
  "timestamp": "2025-07-16T12:37:01.356902"
}
```

### list_active_scans

Lists all active and recent scans with their current status.

**Parameters:**
None

**Returns:**
A dictionary with information about all scans in the registry.

**Example:**
```python
scans = await mcp_list_active_scans()
```

**Example Response:**
```json
{
  "success": true,
  "active_scans": [
    {
      "scan_id": "550e8400-e29b-41d4-a716-446655440000",
      "status": "running",
      "directory_path": "/path/to/your/code",
      "start_time": "2025-07-16T12:34:56.789012"
    }
  ],
  "all_scans": [
    {
      "scan_id": "550e8400-e29b-41d4-a716-446655440000",
      "status": "running",
      "directory_path": "/path/to/your/code",
      "start_time": "2025-07-16T12:34:56.789012"
    },
    {
      "scan_id": "660e8400-e29b-41d4-a716-446655440000",
      "status": "completed",
      "directory_path": "/path/to/another/code",
      "start_time": "2025-07-16T11:22:33.444555",
      "end_time": "2025-07-16T11:25:12.345678"
    }
  ],
  "stats": {
    "total_scans": 2,
    "active_scans": 1,
    "status_counts": {
      "running": 1,
      "completed": 1,
      "failed": 0,
      "cancelled": 0
    }
  },
  "timestamp": "2025-07-16T12:36:23.456789"
}
```

### cancel_scan

Cancels a running scan and cleans up its resources.

**Parameters:**
- `scan_id` (required): The scan ID to cancel

**Returns:**
A dictionary with cancellation result information.

**Example:**
```python
result = await mcp_cancel_scan(
    scan_id="550e8400-e29b-41d4-a716-446655440000"
)
```

**Example Response:**
```json
{
  "success": true,
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "cancelled",
  "message": "Scan cancelled successfully",
  "timestamp": "2025-07-16T12:36:45.123456"
}
```

### check_installation

Checks if ASH is properly installed and ready to use.

**Parameters:**
None

**Returns:**
A dictionary with installation status information.

**Example:**
```python
result = await mcp_check_installation()
```

**Example Response:**
```json
{
  "success": true,
  "installed": true,
  "version": "3.0.0",
  "ash_command_available": true,
  "ash_command_output": "ASH v3.0.0",
  "ash_dir_exists": true,
  "timestamp": "2025-07-16T12:37:12.345678"
}
```

## Error Handling

The ASH MCP server provides comprehensive error handling for various scenarios. Each error response includes:

- `success`: Always `false` for error responses
- `operation`: The operation that was being performed
- `error`: Error message
- `error_type`: Type of error
- `error_category`: Category of error
- `context`: Additional context about the error
- `suggestions`: List of suggestions for resolving the error

### Error Categories

The following error categories are used:

- `file_not_found`: A required file or directory was not found
- `permission_denied`: Permission issues accessing files or directories
- `invalid_format`: File format or structure is invalid
- `invalid_parameter`: Invalid parameter values provided
- `invalid_path`: Path is invalid or improperly formatted
- `resource_exhausted`: System resources are exhausted
- `operation_timeout`: Operation took too long and timed out
- `scan_not_found`: Requested scan ID was not found in the registry
- `scan_incomplete`: Scan has not completed yet
- `unexpected_error`: An unexpected error occurred

### Example Error Response

```json
{
  "success": false,
  "operation": "get_scan_results",
  "error": "Scan 550e8400-e29b-41d4-a716-446655440000 not found",
  "error_type": "MCPResourceError",
  "error_category": "scan_not_found",
  "context": {
    "scan_id": "550e8400-e29b-41d4-a716-446655440000",
    "error_category": "scan_not_found"
  },
  "suggestions": [
    "Check that the scan ID is correct",
    "Verify that the scan exists in the registry",
    "The scan may have been cleaned up if it was completed a long time ago"
  ],
  "timestamp": "2025-07-16T12:37:12.345678"
}
```

## Configuration

The ASH MCP server can be configured using the `mcp-resource-management` section in the ASH configuration file:

```yaml
# .ash/ash.yaml
mcp-resource-management:
  # Concurrent operations
  max_concurrent_scans: 5
  max_concurrent_tasks: 30
  thread_pool_max_workers: 8

  # Timeouts
  scan_timeout_seconds: 2400
  operation_timeout_seconds: 300

  # Resource monitoring
  enable_health_checks: true
  health_check_interval_seconds: 30
  memory_warning_threshold_mb: 1024
  memory_critical_threshold_mb: 2048
  task_count_warning_threshold: 20

  # Message limits
  max_message_size_bytes: 10485760  # 10MB
  max_directory_size_mb: 1024       # 1GB
```

### Configuration Options

- `max_concurrent_scans`: Maximum number of concurrent scans
- `max_concurrent_tasks`: Maximum number of concurrent tasks
- `thread_pool_max_workers`: Maximum number of worker threads
- `scan_timeout_seconds`: Timeout for scans in seconds
- `operation_timeout_seconds`: Timeout for operations in seconds
- `enable_health_checks`: Whether to enable health checks
- `health_check_interval_seconds`: Interval between health checks in seconds
- `memory_warning_threshold_mb`: Memory usage warning threshold in MB
- `memory_critical_threshold_mb`: Memory usage critical threshold in MB
- `task_count_warning_threshold`: Task count warning threshold
- `max_message_size_bytes`: Maximum message size in bytes
- `max_directory_size_mb`: Maximum directory size in MB

## Best Practices

When using the ASH MCP server, follow these best practices:

1. **Store scan IDs**: Always store the scan ID returned by `scan_directory` for later use
2. **Check scan progress**: Periodically check scan progress using `get_scan_progress`
3. **Handle errors gracefully**: Check the `success` field in responses and handle errors appropriately
4. **Clean up resources**: Cancel scans that are no longer needed using `cancel_scan`
5. **Validate parameters**: Ensure all parameters are valid before calling MCP tools
6. **Check installation**: Use `check_installation` to verify ASH is properly installed
7. **Configure appropriately**: Adjust configuration options based on your system resources and usage patterns
8. **Monitor resource usage**: Keep an eye on system resources during scans
9. **Implement timeouts**: Set appropriate timeouts for scans and operations
10. **Handle concurrent scans**: Limit the number of concurrent scans based on your system resources

## Examples

### Basic Scan Workflow

```python
# Start a scan
result = await mcp_scan_directory(
    directory_path="/path/to/your/code",
    severity_threshold="MEDIUM"
)

# Get the scan ID
scan_id = result["scan_id"]

# Check scan progress periodically
while True:
    progress = await mcp_get_scan_progress(scan_id=scan_id)

    if progress["status"] in ["completed", "failed", "cancelled"]:
        break

    # Wait before checking again
    await asyncio.sleep(5)

# Get scan results
if progress["status"] == "completed":
    results = await mcp_get_scan_results(scan_id=scan_id)
    # Process results
else:
    # Handle failure or cancellation
    print(f"Scan {scan_id} {progress['status']}")
```

### Handling Multiple Scans

```python
# Start multiple scans
scan_ids = []
for directory in directories:
    result = await mcp_scan_directory(
        directory_path=directory,
        severity_threshold="MEDIUM"
    )
    scan_ids.append(result["scan_id"])

# Check progress of all scans
completed_scans = set()
while len(completed_scans) < len(scan_ids):
    for scan_id in scan_ids:
        if scan_id in completed_scans:
            continue

        progress = await mcp_get_scan_progress(scan_id=scan_id)

        if progress["status"] in ["completed", "failed", "cancelled"]:
            completed_scans.add(scan_id)

    # Wait before checking again
    await asyncio.sleep(5)

# Get results for all completed scans
for scan_id in scan_ids:
    progress = await mcp_get_scan_progress(scan_id=scan_id)

    if progress["status"] == "completed":
        results = await mcp_get_scan_results(scan_id=scan_id)
        # Process results
    else:
        # Handle failure or cancellation
        print(f"Scan {scan_id} {progress['status']}")
```

### Error Handling Example

```python
# Start a scan with error handling
try:
    result = await mcp_scan_directory(
        directory_path="/path/to/your/code",
        severity_threshold="MEDIUM"
    )

    if not result["success"]:
        # Handle error
        print(f"Error: {result['error']}")
        print(f"Suggestions: {result['suggestions']}")
        return

    scan_id = result["scan_id"]

    # Check scan progress
    while True:
        progress = await mcp_get_scan_progress(scan_id=scan_id)

        if not progress["success"]:
            # Handle error
            print(f"Error: {progress['error']}")
            print(f"Suggestions: {progress['suggestions']}")
            return

        if progress["status"] in ["completed", "failed", "cancelled"]:
            break

        # Wait before checking again
        await asyncio.sleep(5)

    # Get scan results
    if progress["status"] == "completed":
        results = await mcp_get_scan_results(scan_id=scan_id)

        if not results["success"]:
            # Handle error
            print(f"Error: {results['error']}")
            print(f"Suggestions: {results['suggestions']}")
            return

        # Process results
    else:
        # Handle failure or cancellation
        print(f"Scan {scan_id} {progress['status']}")

except Exception as e:
    # Handle unexpected errors
    print(f"Unexpected error: {str(e)}")
```

## Related Documentation

- [MCP Tutorial](../tutorials/using-ash-with-mcp.md)
- [MCP Performance and Scalability](mcp-performance-scalability.md)
- [Configuration Guide](configuration-guide.md)
- [ASH CLI Reference](cli-reference.md)