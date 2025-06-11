# Plugin Best Practices

This guide provides best practices for developing ASH plugins.

## General Best Practices

1. **Follow the Plugin Interface**: Implement all required methods for your plugin type
2. **Use Pydantic Models**: For configuration and data validation
3. **Handle Errors Gracefully**: Use try/except blocks and provide meaningful error messages
4. **Document Your Plugin**: Add docstrings and comments to explain your plugin's functionality
5. **Test Thoroughly**: Create unit tests for your plugins
6. **Version Your Plugins**: Use semantic versioning for your plugins
7. **Respect the Plugin Context**: Use the provided directories for outputs
8. **Clean Up After Yourself**: Remove temporary files when done

## Scanner Plugin Best Practices

1. **Generate SARIF Reports**: SARIF is the standard format for security findings
2. **Handle Ignore Paths**: Skip files that are in the global ignore paths
3. **Use Subprocess Utilities**: Use the provided `_run_subprocess` method for running external commands
4. **Add Metadata**: Add useful metadata to the results container
5. **Support Both File and Directory Scanning**: Handle both individual files and directories

## Reporter Plugin Best Practices

1. **Validate Dependencies**: Implement the `validate` method to check dependencies
2. **Output to Files**: Write reports to the `reports` directory
3. **Return Content**: Return the report content as a string
4. **Use Model Methods**: Use the model's helper methods like `to_simple_dict()` and `to_flat_vulnerabilities()`
5. **Handle Large Reports**: Be mindful of memory usage when generating large reports

## Converter Plugin Best Practices

1. **Preserve Line Numbers**: Try to preserve line numbers for better mapping of findings back to original files
2. **Handle Directories**: Support converting both individual files and directories
3. **Return Paths**: Return the path to the converted file or directory
4. **Skip Unsupported Files**: Only convert files with supported extensions
5. **Maintain File Structure**: Preserve the directory structure when converting directories

## Plugin Dependencies

You can specify dependencies for your plugins:

```python
from automated_security_helper.base.plugin_dependency import PluginDependency, CustomCommand
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.base.scanner_plugin import ScannerPluginBase

@ash_scanner_plugin
class MyCustomScanner(ScannerPluginBase):
    name = "my-custom-scanner"
    description = "My custom security scanner"
    version = "1.0.0"
    dependencies = [
        PluginDependency(
            name="my-scanner-tool",
            commands=[
                CustomCommand(
                    platform="linux",
                    arch="amd64",
                    command=["pip", "install", "my-scanner-tool"]
                ),
                CustomCommand(
                    platform="darwin",
                    arch="amd64",
                    command=["pip", "install", "my-scanner-tool"]
                )
            ]
        )
    ]
```

## Plugin Event Subscribers

ASH supports event subscribers for reacting to events during the scan process. Event subscribers are registered using the `ASH_EVENT_CALLBACKS` dictionary pattern:

```python
# my_ash_plugins/__init__.py
from automated_security_helper.plugins.events import AshEventType

def handle_scan_complete(**kwargs):
    """Handle scan complete event"""
    scanner = kwargs.get('scanner', 'Unknown')
    remaining_count = kwargs.get('remaining_count', 0)
    remaining_scanners = kwargs.get('remaining_scanners', [])
    
    print(f"Scanner '{scanner}' completed!")
    if remaining_count > 0:
        print(f"{remaining_count} scanners remaining: {', '.join(remaining_scanners)}")
    else:
        print("All scanners completed!")
    
    return True

def handle_report_complete(**kwargs):
    """Handle report complete event"""
    phase = kwargs.get('phase', 'Unknown')
    print(f"Report phase '{phase}' completed!")
    return True

# Event callback registry following the same pattern as ASH_SCANNERS, ASH_REPORTERS, etc.
ASH_EVENT_CALLBACKS = {
    AshEventType.SCAN_COMPLETE: [handle_scan_complete],
    AshEventType.REPORT_COMPLETE: [handle_report_complete],
}
```

### Available Event Types

- `AshEventType.SCAN_START`: Fired when the scan phase begins
- `AshEventType.SCAN_COMPLETE`: Fired when each individual scanner completes
- `AshEventType.CONVERT_START`: Fired when the convert phase begins  
- `AshEventType.CONVERT_COMPLETE`: Fired when the convert phase completes
- `AshEventType.REPORT_START`: Fired when the report phase begins
- `AshEventType.REPORT_COMPLETE`: Fired when the report phase completes
- `AshEventType.ERROR`: Fired when errors occur
- `AshEventType.WARNING`: Fired for warning conditions
- `AshEventType.INFO`: Fired for informational events

### Event Data

Event subscribers receive keyword arguments with relevant data. For example, `SCAN_COMPLETE` events include:

- `scanner`: Name of the completed scanner
- `completed_count`: Number of scanners completed so far
- `total_count`: Total number of scanners
- `remaining_count`: Number of scanners still running
- `remaining_scanners`: List of remaining scanner names
- `message`: Human-readable summary message
- `phase`: The phase name ("scan")
- `plugin_context`: The current plugin context

## Common Pitfalls

1. **Not Handling Errors**: Always catch and handle exceptions to prevent the entire scan from failing
2. **Ignoring Configuration**: Always respect the plugin configuration options
3. **Hard-coding Paths**: Use the paths provided in the plugin context
4. **Not Validating Dependencies**: Always check that required dependencies are available
5. **Returning Incorrect Types**: Make sure to return the expected types from plugin methods

## Security Considerations

1. **Validate User Input**: Never trust user input without validation
2. **Avoid Shell Injection**: Use lists for subprocess commands instead of strings
3. **Handle Secrets Securely**: Never log or expose sensitive information
4. **Limit Resource Usage**: Be mindful of memory and CPU usage
5. **Clean Up Temporary Files**: Always clean up temporary files after use