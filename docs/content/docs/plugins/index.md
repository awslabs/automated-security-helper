# Plugin Development Guide

ASH v3 features a flexible plugin architecture that allows you to extend its functionality through custom plugins. This guide provides an overview of the plugin system and how to develop your own plugins.

## Built-in Plugins

ASH ships with a comprehensive set of built-in plugins that provide core functionality:

- **[Built-in Plugins Overview](./builtin/index.md)**: Complete guide to all built-in plugins
- **[Security Scanners](./builtin/scanners.md)**: 10 built-in security scanners (Bandit, Semgrep, Checkov, etc.)
- **[Report Formats](./builtin/reporters.md)**: 12 output formats (SARIF, HTML, CSV, etc.)
- **[File Converters](./builtin/converters.md)**: Archive extraction and Jupyter notebook processing
- **[Event Handlers](./builtin/event-handlers.md)**: Scan lifecycle event handling

## Plugin Types

ASH supports three types of plugins:

1. **[Scanners](./scanner-plugins.md)**: Perform security scans on files and generate findings
2. **[Reporters](./reporter-plugins.md)**: Generate reports from scan results in various formats
3. **[Converters](./converter-plugins.md)**: Transform files before scanning (e.g., convert Jupyter notebooks to Python)

## Plugin Architecture

ASH plugins are Python classes that inherit from base plugin classes and are registered using decorators. The plugin system is designed to be:

- **Modular**: Each plugin has a specific responsibility
- **Configurable**: Plugins can be configured via YAML configuration
- **Discoverable**: Plugins are automatically discovered and loaded
- **Extensible**: New plugin types can be added in the future

## Getting Started

To create a custom plugin:

1. Create a Python module with your plugin implementation
2. Register your plugin using the appropriate decorator
3. Add your plugin module to the ASH configuration

For detailed instructions and examples, see the specific plugin type documentation:

- [Scanner Plugins](./scanner-plugins.md)
- [Reporter Plugins](./reporter-plugins.md)
- [Converter Plugins](./converter-plugins.md)
- [Plugin Best Practices](./plugin-best-practices.md)

## Plugin Module Structure

A typical plugin module has the following structure:

```
my_ash_plugins/
├── __init__.py
├── converters.py
├── scanners.py
└── reporters.py
```

The `__init__.py` file should register your plugins for discovery:

```python
# my_ash_plugins/__init__.py
from my_ash_plugins.scanners import MyCustomScanner
from my_ash_plugins.reporters import MyCustomReporter
from my_ash_plugins.converters import MyCustomConverter

# Make plugins discoverable
ASH_SCANNERS = [MyCustomScanner]
ASH_REPORTERS = [MyCustomReporter]
ASH_CONVERTERS = [MyCustomConverter]
```

## Using Custom Plugins

Add your custom plugin module to the ASH configuration:

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - my_ash_plugins
```

Or specify it on the command line:

```bash
ash --ash-plugin-modules my_ash_plugins
```

## Real-World Examples

ASH includes several built-in plugins that you can use as examples:

- **Scanner Examples**: Bandit, Semgrep, Checkov
- **Reporter Examples**: Markdown, HTML, JSON, S3, BedrockSummary
- **Converter Examples**: Jupyter, Archive

You can find these plugins in the ASH source code:

- Scanners: `automated_security_helper/plugins/scanners/`
- Reporters: `automated_security_helper/plugins/reporters/`
- Converters: `automated_security_helper/plugins/converters/`

## Next Steps

- Review the [ASH Plugin Architecture](./architecture.md)
- Learn how to create [Scanner Plugins](./scanner-plugins.md)
- Learn how to create [Reporter Plugins](./reporter-plugins.md)
- Learn how to create [Converter Plugins](./converter-plugins.md)
- Review [Plugin Best Practices](./plugin-best-practices.md)