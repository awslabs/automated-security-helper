# ASH Example Plugin Package

This package demonstrates how to create external plugins for the Automated Security Helper (ASH) using the plugin discovery pattern.

## Overview

This example package includes:

1. **ExampleConverter**: A simple converter plugin that logs the target and returns it unchanged
2. **ExampleScanner**: A scanner plugin that returns a mock finding
3. **ExampleReporter**: A reporter plugin that generates a simple text report
4. **Event Subscribers**: Examples of subscribing to ASH events using the `ASH_EVENT_HANDLERS` pattern

## Installation

To install this example plugin package:

```bash
# From the package directory
poetry install
```

## Usage

Once installed, ASH will automatically discover and use these plugins when running scans.

```bash
# Run ASH with the example plugins
ash --source-dir /path/to/code
```

## Plugin Development

This package demonstrates the key components of ASH plugins:

### 1. Plugin Registration

Plugins are registered using discovery constants in the `__init__.py` file:

```python
# Make plugins discoverable
ASH_CONVERTERS = [ExampleConverter]
ASH_SCANNERS = [ExampleScanner]
ASH_REPORTERS = [ExampleReporter]
```

### 2. Interface Implementation

Each plugin implements the required methods from `IConverter`, `IScanner`, or `IReporter` interfaces.

### 3. Event Subscription

Event subscribers are registered using the `ASH_EVENT_HANDLERS` dictionary:

```python
def handle_scan_complete(**kwargs):
    """Example event handler for scan complete event."""
    scanner = kwargs.get('scanner', 'Unknown')
    remaining_count = kwargs.get('remaining_count', 0)
    print(f"Scanner '{scanner}' completed!")
    return True

# Event callback registry
ASH_EVENT_HANDLERS = {
    AshEventType.SCAN_COMPLETE: [handle_scan_complete],
    AshEventType.SCAN_START: [handle_scan_start],
}
```

### Available Event Types

ASH provides several event types you can subscribe to:

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

Event subscribers receive keyword arguments with relevant data:

**SCAN_COMPLETE Event Data:**
- `scanner`: Name of the completed scanner
- `completed_count`: Number of scanners completed so far
- `total_count`: Total number of scanners
- `remaining_count`: Number of scanners still running
- `remaining_scanners`: List of remaining scanner names
- `message`: Human-readable summary message
- `phase`: The phase name ("scan")
- `plugin_context`: The current plugin context

## Plugin Discovery

ASH automatically discovers plugins by:

1. Loading modules specified in the `internal_modules` list (for built-in plugins)
2. Loading additional modules specified in configuration via `ash_plugin_modules`
3. Scanning for `ASH_CONVERTERS`, `ASH_SCANNERS`, `ASH_REPORTERS`, and `ASH_EVENT_HANDLERS` constants
4. Registering discovered plugins and event subscribers with the plugin manager

For more information, see the [ASH Plugin System documentation](https://github.com/awslabs/automated-security-helper/blob/main/AmazonQ.md).
