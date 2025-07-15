# MCP CLI Integration Tests

This directory contains comprehensive integration tests for the MCP (Model Context Protocol) CLI command functionality in ASH (Automated Security Helper).

## Overview

The integration tests validate end-to-end functionality of the MCP CLI command, covering:

- Complete MCP server startup and tool execution
- Scan workflow through MCP with real ASH integration
- MCP server lifecycle and graceful shutdown
- Functionality parity with original standalone script

## Test Files

### `test_mcp_integration.py`
Main integration test file containing comprehensive end-to-end tests:

- **TestMcpServerLifecycle**: Server startup, shutdown, and error handling
- **TestMcpToolExecution**: MCP tool execution with ASH integration
- **TestMcpResourcesAndPrompts**: MCP resources and prompts functionality
- **TestMcpScanWorkflow**: Complete scan workflow testing
- **TestTemporaryResourceManagement**: Resource cleanup and management
- **TestFunctionalityParity**: Parity with original standalone script

### `test_mcp_integration_simple.py`
Validation tests to ensure integration test structure and coverage:

- Test structure validation
- Requirement coverage verification
- Fixture functionality validation
- Mock environment testing

### `conftest.py`
Pytest configuration and fixtures for integration tests:

- Mock MCP environment setup
- Temporary directory fixtures
- Mock scan results and aggregated data
- Test configuration and markers

### `test_mcp_integration_runner.py`
Simple test runner for executing integration tests with proper configuration.

## Requirements Coverage

The integration tests cover the following requirements from the MCP CLI integration spec:

### Requirement 1.1 - MCP Server Startup
- ✅ `test_mcp_server_startup_success`: Server starts with ASH capabilities
- ✅ `test_mcp_server_name_consistency`: Uses correct server name "ASH Security Scanner"

### Requirement 1.3 - Complete Scan Workflow
- ✅ `test_end_to_end_scan_workflow`: Complete scan through MCP with real ASH integration
- ✅ `test_scan_directory_tool_success`: Successful scan execution

### Requirement 1.4 - Graceful Shutdown
- ✅ `test_mcp_server_graceful_shutdown`: Graceful shutdown on interrupt
- ✅ `test_signal_handler_registration`: Signal handler registration
- ✅ `test_resource_cleanup_on_shutdown`: Resource cleanup on termination

### Requirement 5.1 - MCP Resources
- ✅ `test_ash_status_resource_installed`: ash://status resource functionality
- ✅ `test_ash_status_resource_not_installed`: Error handling for status resource

### Requirement 5.2 - MCP Tools
- ✅ `test_scan_directory_tool_success`: scan_directory tool with identical interface
- ✅ `test_check_installation_tool_success`: check_installation tool functionality
- ✅ `test_scan_directory_tool_validation_error`: Error handling for invalid parameters

### Requirement 5.3 - Help Resource
- ✅ `test_ash_help_resource`: ash://help resource with identical content

### Requirement 5.4 - Security Analysis Prompt
- ✅ `test_analyze_security_findings_prompt`: analyze_security_findings prompt functionality

### Requirement 5.5 - Result Parsing
- ✅ `test_result_parsing_functionality`: Result parsing with identical logic and format
- ✅ `test_parse_ash_results_*`: Various result parsing scenarios

## Test Execution

### Running All Integration Tests

```bash
# Run all MCP integration tests
python -m pytest tests/integration/cli/ -m integration -v

# Run with specific markers
python -m pytest tests/integration/cli/ -m "integration and mcp" -v

# Run slow tests (end-to-end workflows)
python -m pytest tests/integration/cli/ -m "integration and slow" -v
```

### Running Specific Test Classes

```bash
# Test server lifecycle
python -m pytest tests/integration/cli/test_mcp_integration.py::TestMcpServerLifecycle -v

# Test tool execution
python -m pytest tests/integration/cli/test_mcp_integration.py::TestMcpToolExecution -v

# Test scan workflow
python -m pytest tests/integration/cli/test_mcp_integration.py::TestMcpScanWorkflow -v
```

### Running Validation Tests

```bash
# Validate test structure and coverage
python -m pytest tests/integration/cli/test_mcp_integration_simple.py -v

# Or run directly
python tests/integration/cli/test_mcp_integration_runner.py
```

## Test Environment

### Prerequisites

The integration tests require:

- Python 3.10+
- ASH package installed or available in PYTHONPATH
- pytest and testing dependencies
- Mock MCP dependencies (handled by fixtures)

### Mock Environment

The tests use comprehensive mocking to avoid requiring actual MCP package installation:

- **MCP Server**: Mocked FastMCP server with tool/resource registration
- **ASH Integration**: Mocked direct function calls to ASH core functionality
- **File System**: Temporary directories and files for realistic testing
- **Results**: Mock aggregated results and report files

### Fixtures

Key fixtures provided by `conftest.py`:

- `mock_mcp_environment`: Complete MCP environment mock
- `temp_scan_directory`: Temporary directory with sample scannable files
- `mock_ash_scan_results`: Mock ASH scan results structure
- `temp_output_directory`: Temporary output directory with mock results
- `integration_test_config`: Test configuration settings

## Test Data

### Sample Scan Directory Structure
```
temp_scan_dir/
├── sample.py          # Python file with security issues
├── requirements.txt   # Dependencies file
└── Dockerfile        # Container configuration
```

### Mock Aggregated Results Structure
```json
{
  "additional_reports": {
    "bandit": {
      "source": {
        "finding_count": 2,
        "actionable_finding_count": 1,
        "status": "failed"
      }
    },
    "semgrep": {
      "source": {
        "finding_count": 1,
        "actionable_finding_count": 1,
        "status": "failed"
      }
    }
  },
  "metadata": {
    "summary_stats": {
      "total": 3,
      "actionable": 2
    }
  }
}
```

## Error Scenarios Tested

### Server Lifecycle Errors
- Server initialization failures
- Runtime errors during execution
- Signal handling and graceful shutdown
- Resource cleanup on unexpected termination

### Tool Execution Errors
- Invalid scan parameters (directory path, severity threshold)
- File system access errors
- ASH installation/dependency issues
- Scan execution failures

### Validation Errors
- Directory validation (existence, permissions, access)
- Parameter validation (types, values, ranges)
- Structured error response format

## Performance Considerations

### Test Execution Time
- **Fast tests**: Basic validation and mocking (~1-5 seconds each)
- **Medium tests**: Tool execution with file I/O (~5-15 seconds each)
- **Slow tests**: End-to-end workflows with full scan simulation (~15-30 seconds each)

### Resource Usage
- Temporary directories are automatically cleaned up
- Mock objects minimize memory usage
- File I/O is limited to temporary locations

## Debugging

### Common Issues

1. **Import Errors**: Ensure ASH package is in PYTHONPATH
2. **Permission Errors**: Check temporary directory permissions
3. **Mock Failures**: Verify mock environment setup in fixtures

### Debug Output

Enable verbose logging for debugging:

```bash
# Run with debug output
python -m pytest tests/integration/cli/ -v -s --log-cli-level=DEBUG

# Run specific test with full output
python -m pytest tests/integration/cli/test_mcp_integration.py::TestMcpServerLifecycle::test_mcp_server_startup_success -v -s
```

## Contributing

When adding new integration tests:

1. Follow the existing test class structure
2. Use appropriate fixtures from `conftest.py`
3. Add proper requirement references in docstrings
4. Include both success and error scenarios
5. Update this README with new test coverage

## Maintenance

### Regular Updates Needed

- Update mock data structures when ASH output format changes
- Adjust test timeouts for performance changes
- Update requirement coverage when spec changes
- Refresh sample scan files for new security patterns