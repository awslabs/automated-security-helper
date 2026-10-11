# ASH Example Plugin Package

This package demonstrates how to create external plugins for the Automated Security Helper (ASH): a module that lists its plugin classes, which ASH reads when a module list names the module.

## Overview

This example package includes:

1. **ExampleConverter**: A converter plugin meant to log the target and return it unchanged. Its `convert()` takes a `target` argument, which ASH does not pass, so on every scan ASH reports it as not finished with a `TypeError` and converts nothing.
2. **ExampleScanner**: A scanner plugin that returns a mock finding
3. **ExampleReporter**: A reporter plugin that generates a simple text report
4. **Event Subscribers**: Two functions subscribed to ASH events through a dict at module level

## Installation

To install this example plugin package:

<!-- doctest: illustrative reason="needs Poetry and network access" -->
```bash
# From the package directory
poetry install
```

## Usage

ASH loads the package only when a module list names it. The example's `.ash/.ash.yaml`
names it in `ash_plugin_modules`, but ASH ignores a module that a repository's config
names when the module itself is inside a git checkout or the scanned directory, and
`poetry install` installs this package in editable mode, from this directory. Name the
module on the command line instead, which counts as operator configuration:

<!-- doctest: illustrative reason="needs the example package installed" -->
```bash
# Run ASH with the example plugins
ash --source-dir /path/to/code --ash-plugin-modules my_ash_plugins
```

## Plugin Development

This package demonstrates the key components of ASH plugins:

### 1. Plugin Registration

Plugins are registered using discovery constants in the `__init__.py` file:

<!-- doctest: illustrative reason="an excerpt of my_ash_plugins/__init__.py" -->
```python
# Make plugins discoverable
ASH_CONVERTERS = [ExampleConverter]
ASH_SCANNERS = [ExampleScanner]
ASH_REPORTERS = [ExampleReporter]
```

### 2. Interface Implementation

Each plugin subclasses `ConverterPluginBase`, `ScannerPluginBase` or `ReporterPluginBase` and implements its `convert()`, `scan()` or `report()` method.

### 3. Event Subscription

Event subscribers are listed in a dict at module level, which ASH reads when it loads the module:

<!-- doctest: illustrative reason="an excerpt of my_ash_plugins/__init__.py" -->
```python
from automated_security_helper.plugins.events import AshEventType


def handle_scan_complete(**kwargs):
    """Example event handler for scan complete event."""
    scanner = kwargs.get("scanner", "Unknown")
    remaining_count = kwargs.get("remaining_count", 0)
    print(f"Scanner '{scanner}' completed!")
    return True


# Event callback registry
ASH_EVENT_HANDLERS = {
    AshEventType.SCAN_COMPLETE: [handle_scan_complete],
    AshEventType.SCAN_START: [handle_scan_start],
}
```

### Available Event Types

Every event a scan emits, when it fires and the keyword arguments it receives are listed in
[Subscribe to scan events](https://awslabs.github.io/automated-security-helper/plugins/event-subscribers/#events). The two this example uses:

- `AshEventType.SCAN_COMPLETE` fires after each scanner, with `scanner`, `completed_count`,
  `total_count`, `remaining_count`, `remaining_scanners` and `message`, plus `phase` and
  `plugin_context`.
- `AshEventType.SCAN_START` fires before each scanner, and only with
  `ash scan --strategy sequential`. Under the default parallel strategy it is not emitted, so
  `handle_scan_start` does not run.

## Plugin Discovery

ASH has no automatic discovery. It imports a plugin module when a module list names it:
`ash_plugin_modules` in a config file, `--ash-plugin-modules`, or the `ASH_PLUGIN_MODULES`
environment variable. It then reads the module's lists of converters, scanners and reporters
and its dict of event subscribers, shown above, and registers what they name.

For more information, see [Plugins](https://awslabs.github.io/automated-security-helper/plugins/).
