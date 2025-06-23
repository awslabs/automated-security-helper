# Plugin Development Guide

This guide provides comprehensive information on developing custom plugins for ASH. Whether you're creating scanners, reporters, converters, or event subscribers, this document will help you understand the plugin architecture and development process.

## Plugin Architecture Overview

ASH's plugin system is designed to be extensible and modular. Plugins are Python classes that inherit from base plugin classes and implement specific interfaces.

### Plugin Types

ASH supports four main types of plugins:

1. **Scanner Plugins**: Analyze code and infrastructure for security issues
2. **Reporter Plugins**: Generate reports in various formats
3. **Converter Plugins**: Process files before scanning
4. **Event Subscribers**: React to events during the scan lifecycle

### Plugin Lifecycle

All plugins follow a similar lifecycle:

1. **Registration**: Plugins are registered with the plugin manager
2. **Configuration**: Plugin settings are loaded from the ASH configuration
3. **Initialization**: Plugins are initialized with required dependencies
4. **Execution**: Plugins perform their specific tasks
5. **Cleanup**: Plugins clean up resources when done

## Creating a Custom Plugin

### Basic Plugin Structure

All plugins follow a similar structure:

```python
from automated_security_helper.base.scanner_plugin import ScannerPluginBase, ScannerPluginConfigBase

class MyCustomScannerConfig(ScannerPluginConfigBase):
    """Configuration for MyCustomScanner."""

    # Define configuration options
    custom_option: str = "default_value"

class MyCustomScanner(ScannerPluginBase):
    """Custom scanner implementation."""

    def __init__(self, config: MyCustomScannerConfig):
        super().__init__(config)
        # Initialize scanner-specific resources

    def scan(self, target_path: str) -> dict:
        """Perform the scan operation."""
        # Implement scanning logic
        return {
            "findings": [],
            "status": "success"
        }

    def cleanup(self):
        """Clean up resources."""
        # Implement cleanup logic
```

### Plugin Registration

Plugins must be registered with ASH to be discovered:

```python
from automated_security_helper.plugins import ash_plugin_manager

# Register your plugin
ash_plugin_manager.register_scanner(
    name="my-custom-scanner",
    scanner_class=MyCustomScanner,
    config_class=MyCustomScannerConfig
)
```

## Scanner Plugin Development

Scanner plugins analyze code and infrastructure for security issues.

### Scanner Plugin Interface

```python
class ScannerPluginBase(ABC):
    """Base class for all scanner plugins."""

    @abstractmethod
    def scan(self, target_path: str) -> dict:
        """Scan the target path and return findings."""
        pass

    @abstractmethod
    def cleanup(self):
        """Clean up resources."""
        pass
```

### Scanner Plugin Example

```python
from automated_security_helper.base.scanner_plugin import ScannerPluginBase, ScannerPluginConfigBase
from automated_security_helper.core.enums import ScannerStatus

class CustomRegexScannerConfig(ScannerPluginConfigBase):
    """Configuration for CustomRegexScanner."""

    name: str = "custom-regex"
    enabled: bool = True
    patterns: List[str] = ["password\\s*=\\s*['\"]([^'\"]+)['\"]"]

class CustomRegexScanner(ScannerPluginBase):
    """Scanner that uses regex patterns to find security issues."""

    def __init__(self, config: CustomRegexScannerConfig):
        super().__init__(config)
        self.patterns = [re.compile(p) for p in config.patterns]

    def scan(self, target_path: str) -> dict:
        """Scan files for regex patterns."""
        findings = []

        for file_path in self._get_files(target_path):
            with open(file_path, 'r') as f:
                content = f.read()

            for i, line in enumerate(content.splitlines()):
                for pattern in self.patterns:
                    if match := pattern.search(line):
                        findings.append({
                            "file": file_path,
                            "line": i + 1,
                            "pattern": pattern.pattern,
                            "match": match.group(0),
                            "severity": "HIGH"
                        })

        return {
            "findings": findings,
            "status": ScannerStatus.FAILED if findings else ScannerStatus.PASSED
        }

    def cleanup(self):
        """Clean up resources."""
        self.patterns = []

    def _get_files(self, path: str) -> List[str]:
        """Get all files in the path."""
        if os.path.isfile(path):
            return [path]

        files = []
        for root, _, filenames in os.walk(path):
            for filename in filenames:
                files.append(os.path.join(root, filename))

        return files
```

## Reporter Plugin Development

Reporter plugins generate reports in various formats.

### Reporter Plugin Interface

```python
class ReporterPluginBase(ABC):
    """Base class for all reporter plugins."""

    @abstractmethod
    def generate_report(self, results: AshAggregatedResults) -> str:
        """Generate a report from the scan results."""
        pass
```

### Reporter Plugin Example

```python
from automated_security_helper.base.reporter_plugin import ReporterPluginBase, ReporterPluginConfigBase
from automated_security_helper.models.asharp_model import AshAggregatedResults

class CustomJSONReporterConfig(ReporterPluginConfigBase):
    """Configuration for CustomJSONReporter."""

    name: str = "custom-json"
    enabled: bool = True
    pretty_print: bool = True

class CustomJSONReporter(ReporterPluginBase):
    """Reporter that generates a custom JSON report."""

    def __init__(self, config: CustomJSONReporterConfig):
        super().__init__(config)
        self.pretty_print = config.pretty_print

    def generate_report(self, results: AshAggregatedResults) -> str:
        """Generate a custom JSON report."""
        report_data = {
            "project": results.metadata.project_name,
            "timestamp": results.metadata.generated_at,
            "summary": {
                "total": results.metadata.summary_stats.total,
                "critical": results.metadata.summary_stats.critical,
                "high": results.metadata.summary_stats.high,
                "medium": results.metadata.summary_stats.medium,
                "low": results.metadata.summary_stats.low,
                "info": results.metadata.summary_stats.info,
            },
            "findings": []
        }

        # Extract findings from SARIF
        if results.sarif and results.sarif.runs:
            for run in results.sarif.runs:
                if run.results:
                    for result in run.results:
                        finding = {
                            "rule_id": result.ruleId,
                            "level": result.level,
                            "message": result.message.text if result.message else "No message",
                        }
                        report_data["findings"].append(finding)

        # Generate JSON
        indent = 2 if self.pretty_print else None
        return json.dumps(report_data, indent=indent)
```

## Converter Plugin Development

Converter plugins process files before scanning.

### Converter Plugin Interface

```python
class ConverterPluginBase(ABC):
    """Base class for all converter plugins."""

    @abstractmethod
    def convert(self, source_path: str, target_path: str) -> List[str]:
        """Convert files from source_path to target_path."""
        pass
```

### Converter Plugin Example

```python
from automated_security_helper.base.converter_plugin import ConverterPluginBase, ConverterPluginConfigBase

class CustomYAMLConverterConfig(ConverterPluginConfigBase):
    """Configuration for CustomYAMLConverter."""

    name: str = "custom-yaml"
    enabled: bool = True
    file_extensions: List[str] = [".yaml", ".yml"]

class CustomYAMLConverter(ConverterPluginBase):
    """Converter that processes YAML files."""

    def __init__(self, config: CustomYAMLConverterConfig):
        super().__init__(config)
        self.file_extensions = config.file_extensions

    def convert(self, source_path: str, target_path: str) -> List[str]:
        """Convert YAML files to a format suitable for scanning."""
        converted_files = []

        for root, _, files in os.walk(source_path):
            for file in files:
                if any(file.endswith(ext) for ext in self.file_extensions):
                    source_file = os.path.join(root, file)
                    rel_path = os.path.relpath(source_file, source_path)
                    target_file = os.path.join(target_path, rel_path)

                    # Create target directory if it doesn't exist
                    os.makedirs(os.path.dirname(target_file), exist_ok=True)

                    # Process the YAML file
                    with open(source_file, 'r') as f:
                        yaml_content = yaml.safe_load(f)

                    # Write processed content to target file
                    with open(target_file, 'w') as f:
                        yaml.dump(yaml_content, f)

                    converted_files.append(target_file)

        return converted_files
```

## Event Subscriber Development

Event subscribers react to events during the scan lifecycle.

### Event Subscriber Interface

```python
# Event types
class AshEventType(Enum):
    SCAN_START = "scan_start"
    SCAN_COMPLETE = "scan_complete"
    CONVERT_START = "convert_start"
    CONVERT_COMPLETE = "convert_complete"
    REPORT_START = "report_start"
    REPORT_COMPLETE = "report_complete"

# Event subscriber function type
EventSubscriberFunc = Callable[..., bool]
```

### Event Subscriber Example

```python
from automated_security_helper.plugins.events import AshEventType
from automated_security_helper.plugins import ash_plugin_manager

def scan_complete_handler(**kwargs):
    """Handle scan completion events."""
    scanner = kwargs.get('scanner', 'unknown')
    remaining = kwargs.get('remaining_count', 0)

    print(f"Scanner {scanner} completed. {remaining} scanners remaining.")

    # Return True to indicate successful handling
    return True

# Register the event subscriber
ash_plugin_manager.subscribe(AshEventType.SCAN_COMPLETE, scan_complete_handler)
```

## Plugin Configuration

Plugins are configured through the ASH configuration file:

```yaml
# Custom scanner configuration
scanners:
  custom-regex:
    enabled: true
    patterns:
      - "password\\s*=\\s*['\"]([^'\"]+)['\"]"
      - "api_key\\s*=\\s*['\"]([^'\"]+)['\"]"

# Custom reporter configuration
reporters:
  custom-json:
    enabled: true
    pretty_print: true

# Custom converter configuration
converters:
  custom-yaml:
    enabled: true
    file_extensions:
      - ".yaml"
      - ".yml"
```

## Plugin Distribution

### Creating a Plugin Package

To distribute your plugins, create a Python package:

```
my-ash-plugins/
├── setup.py
├── my_ash_plugins/
│   ├── __init__.py
│   ├── scanners.py
│   ├── reporters.py
│   └── converters.py
```

### Plugin Registration in Package

Register your plugins in the `__init__.py` file:

```python
from automated_security_helper.plugins import ash_plugin_manager
from .scanners import CustomRegexScanner, CustomRegexScannerConfig
from .reporters import CustomJSONReporter, CustomJSONReporterConfig

# Register plugins
def register_plugins():
    ash_plugin_manager.register_scanner(
        name="custom-regex",
        scanner_class=CustomRegexScanner,
        config_class=CustomRegexScannerConfig
    )

    ash_plugin_manager.register_reporter(
        name="custom-json",
        reporter_class=CustomJSONReporter,
        config_class=CustomJSONReporterConfig
    )

# Auto-register when imported
register_plugins()
```

### Using Custom Plugin Packages

Configure ASH to use your custom plugin package:

```yaml
# ASH configuration
ash_plugin_modules:
  - "my_ash_plugins"
```

Or specify via command line:

```bash
ash --plugin-modules my_ash_plugins
```

## Best Practices

### Plugin Design

- **Single Responsibility**: Each plugin should do one thing well
- **Configurability**: Make plugins configurable for different use cases
- **Error Handling**: Handle errors gracefully and provide useful error messages
- **Performance**: Optimize for performance, especially for large codebases
- **Documentation**: Document your plugins thoroughly

### Testing Plugins

Create tests for your plugins:

```python
def test_custom_regex_scanner():
    """Test CustomRegexScanner."""
    # Create test files
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = os.path.join(tmpdir, "test.py")
        with open(test_file, "w") as f:
            f.write('password = "secret123"')

        # Configure scanner
        config = CustomRegexScannerConfig(
            patterns=["password\\s*=\\s*['\"]([^'\"]+)['\"]"]
        )
        scanner = CustomRegexScanner(config)

        # Run scan
        result = scanner.scan(tmpdir)

        # Verify results
        assert len(result["findings"]) == 1
        assert result["findings"][0]["file"] == test_file
        assert result["findings"][0]["line"] == 1
        assert result["findings"][0]["severity"] == "HIGH"
```

## Troubleshooting

### Common Issues

- **Plugin Not Found**: Ensure your plugin module is in the Python path
- **Configuration Errors**: Validate your configuration against the plugin's schema
- **Dependency Issues**: Check that all required dependencies are installed
- **Performance Problems**: Profile your plugin to identify bottlenecks

### Debugging Plugins

Enable debug logging to troubleshoot plugin issues:

```bash
ash --debug
```

## Next Steps

- **[Scanner Plugin Guide](scanner-plugins.md)**: Detailed guide for scanner plugins
- **[Reporter Plugin Guide](reporter-plugins.md)**: Detailed guide for reporter plugins
- **[Converter Plugin Guide](converter-plugins.md)**: Detailed guide for converter plugins
- **[Event Subscriber Guide](event-subscribers.md)**: Detailed guide for event subscribers
- **[Plugin Best Practices](plugin-best-practices.md)**: Best practices for plugin development
