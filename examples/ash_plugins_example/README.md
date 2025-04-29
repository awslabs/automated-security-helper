# ASH Example Plugin Package

This package demonstrates how to create external plugins for the Automated Security Helper (ASH) using the observer pattern.

## Overview

This example package includes:

1. **ExampleConverter**: A simple converter plugin that logs the target and returns it unchanged
2. **ExampleScanner**: A scanner plugin that returns a mock finding
3. **ExampleReporter**: A reporter plugin that generates a simple text report
4. **Event Handlers**: An example of subscribing to ASH events

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

1. **Plugin Registration**: Using the `AshPlugin` metaclass and `implements` attribute
2. **Interface Implementation**: Implementing the required methods from `IConverter`, `IScanner`, or `IReporter`
3. **Event Subscription**: Using the `event_subscriber` decorator to handle ASH events

For more information, see the [ASH Plugin System documentation](https://github.com/awslabs/automated-security-helper/blob/main/AmazonQ.md).
