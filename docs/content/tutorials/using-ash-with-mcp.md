# Using ASH with MCP

This tutorial guides you through using the Automated Security Helper (ASH) with the Model Context Protocol (MCP) server. The MCP server provides a reliable interface for AI assistants to perform security scans on your codebase.

## Overview

ASH's MCP server implementation uses a file-based approach to track scan progress and completion, making it more reliable than event-based tracking. This approach ensures that scan progress and results are accurately tracked even in complex threading scenarios.

## Prerequisites

- ASH v3.0.0 or later installed
- Basic understanding of ASH security scanning
- An AI assistant that supports MCP tools

## MCP Tools Overview

ASH provides the following MCP tools:

1. **scan_directory**: Start a security scan asynchronously
2. **get_scan_progress**: Check the progress of a running scan
3. **get_scan_results**: Get the results of a completed scan
4. **list_active_scans**: List all active and recent scans
5. **cancel_scan**: Cancel a running scan
6. **check_installation**: Check if ASH is properly installed

## Starting a Scan

To start a security scan, use the `scan_directory` tool:

```python
result = await mcp_scan_directory(
    directory_path="/path/to/your/code",
    severity_threshold="MEDIUM",  # Optional, default is "MEDIUM"
    config_path=None  # Optional, path to ASH configuration file
)
```

The tool returns a dictionary with:
- `scan_id`: A unique identifier for tracking the scan
- `status`: Initial status of the scan (usually "pending")
- `directory_path`: Path to the directory being scanned
- `output_directory`: Path where scan results will be stored
- `start_time`: When the scan was started

Example response:
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

## Tracking Scan Progress

To check the progress of a running scan, use the `get_scan_progress` tool:

```python
progress = await mcp_get_scan_progress(
    scan_id="550e8400-e29b-41d4-a716-446655440000"
)
```

The tool returns a dictionary with:
- `status`: Current status of the scan ("pending", "running", "completed", "failed", or "cancelled")
- `completed_scanners`: Number of scanners that have completed
- `total_scanners`: Total number of scanners being run
- `scanners`: Detailed information about each scanner's progress
- `duration`: How long the scan has been running

Example response:
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

## Getting Scan Results

Once a scan is complete, use the `get_scan_results` tool to retrieve the results:

```python
results = await mcp_get_scan_results(
    scan_id="550e8400-e29b-41d4-a716-446655440000"
)
```

The tool returns a dictionary with:
- `status`: Status of the scan (should be "completed")
- `finding_count`: Total number of findings
- `severity_counts`: Counts of findings by severity
- `findings`: Detailed information about each finding
- `scan_duration`: How long the scan took to complete

Example response:
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

## Managing Active Scans

To list all active and recent scans, use the `list_active_scans` tool:

```python
scans = await mcp_list_active_scans()
```

The tool returns a dictionary with:
- `active_scans`: List of currently running scans
- `all_scans`: List of all scans in the registry (including completed ones)
- `stats`: Statistics about scan counts and statuses

Example response:
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

## Cancelling a Scan

To cancel a running scan, use the `cancel_scan` tool:

```python
result = await mcp_cancel_scan(
    scan_id="550e8400-e29b-41d4-a716-446655440000"
)
```

The tool returns a dictionary with:
- `success`: Whether the cancellation was successful
- `scan_id`: ID of the cancelled scan
- `status`: New status of the scan (should be "cancelled")

Example response:
```json
{
  "success": true,
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "cancelled",
  "message": "Scan cancelled successfully",
  "timestamp": "2025-07-16T12:36:45.123456"
}
```

## Checking ASH Installation

To check if ASH is properly installed, use the `check_installation` tool:

```python
result = await mcp_check_installation()
```

The tool returns a dictionary with:
- `installed`: Whether ASH is installed
- `version`: ASH version
- `ash_command_available`: Whether the ASH command is available in the PATH
- `ash_dir_exists`: Whether the ASH directory exists

Example response:
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

## File-Based Tracking Approach

ASH's MCP server uses a file-based approach to track scan progress and completion. This approach is more reliable than event-based tracking because it doesn't depend on in-memory state that could be lost due to threading issues.

The file-based tracking works as follows:

1. When a scan is started, a unique scan ID is generated and registered in the scan registry
2. The scan process is started asynchronously
3. The scan progress is tracked by checking for the existence of result files:
   - `ash_aggregated_results.json`: Indicates the scan has completed
   - Individual scanner result files: Indicate which scanners have completed
4. The scan results are retrieved by parsing these files

This approach ensures that scan progress and results are accurately tracked even if events are missed or not properly received due to threading issues.

## Error Handling

ASH's MCP server provides comprehensive error handling for various scenarios:

- **Invalid parameters**: Validates all input parameters and returns meaningful error messages
- **File not found**: Handles missing files gracefully
- **Permission denied**: Checks for appropriate permissions before accessing files
- **Invalid format**: Validates file formats and provides detailed error messages
- **Scan not found**: Checks if the scan exists in the registry
- **Scan incomplete**: Verifies if the scan has completed before returning results
- **Unexpected errors**: Catches and reports unexpected errors with context

Each error response includes:
- `success`: Always `false` for error responses
- `error`: Error message
- `error_type`: Type of error
- `error_category`: Category of error (e.g., "file_not_found", "permission_denied")
- `suggestions`: List of suggestions for resolving the error

Example error response:
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

## Best Practices

When using ASH with MCP, follow these best practices:

1. **Store scan IDs**: Always store the scan ID returned by `scan_directory` for later use
2. **Check scan progress**: Periodically check scan progress using `get_scan_progress`
3. **Handle errors gracefully**: Check the `success` field in responses and handle errors appropriately
4. **Clean up resources**: Cancel scans that are no longer needed using `cancel_scan`
5. **Validate parameters**: Ensure all parameters are valid before calling MCP tools
6. **Check installation**: Use `check_installation` to verify ASH is properly installed

## Next Steps

- Learn more about [ASH configuration options](../docs/configuration-guide.md)
- Explore [MCP performance and scalability](../docs/mcp-performance-scalability.md)
