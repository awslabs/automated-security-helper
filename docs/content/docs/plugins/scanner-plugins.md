# Scanner Plugins

Scanner plugins perform security scans on files and generate findings. They are the core of ASH's security scanning functionality.

> For detailed visual diagrams of scanner plugin architecture and workflow, see [Scanner Plugin Diagrams](scanner-plugins-diagrams.md).

## Scanner Plugin Interface

`ScannerPluginBase.scan()` is a template method. It runs a fixed sequence —
preamble, tool invocation, read the result file, attach the SARIF invocation,
postamble — and calls into your plugin for the one part that is tool-specific.
That hook is `_execute_scan()`, and it is abstract: every subclass must define
it, even one that does not use the template.

`_execute_scan()` returns a three-tuple of `(argv, results_file, subprocess_env)`.
The template runs `argv`, then reads SARIF from `results_file`, so a plugin that
fits this shape does not implement `scan()` at all:

```python
from pathlib import Path
from typing import List, Literal, Optional, Tuple

from automated_security_helper.base.scanner_plugin import ScannerPluginBase, ScannerPluginConfigBase
from automated_security_helper.plugins.decorators import ash_scanner_plugin

@ash_scanner_plugin
class MyScanner(ScannerPluginBase[MyScannerConfig]):
    """My custom scanner implementation"""

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths,
    ) -> Tuple[List[str], Path, Optional[dict]]:
        """Return the argv to run, where it writes SARIF, and any extra env."""
        results_file = self.results_dir.joinpath(target_type, "results_sarif.sarif")
        results_file.parent.mkdir(parents=True, exist_ok=True)
        argv = ["my-scanner-tool", "--sarif", "--output", str(results_file), str(target)]
        return argv, results_file, None
```

Hooks such as `_process_config_options()`, `_resolve_arguments()`, `_pre_scan()`,
`_post_scan()` and `_post_process_sarif()` let you adjust individual steps
without replacing the template.

### Overriding scan() directly

A scanner whose workflow does not fit the template — one that calls a Python API
instead of a subprocess, for example — overrides `scan()` and returns a
`SarifReport`. Because `_execute_scan()` is abstract, such a plugin still has to
declare it, so give it a stub that says why it is unreachable:

```python
@ash_scanner_plugin
class ApiScanner(ScannerPluginBase[ApiScannerConfig]):
    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    def scan(self, target, target_type, global_ignore_paths=None, config=None):
        ...
```

Omitting the stub makes the class abstract, and it fails at instantiation rather
than at scan time. `examples/ash_plugins_example/my_ash_plugins/scanner.py`
follows this pattern.

## Scanner Plugin Configuration

Define a configuration class for your scanner:

```python
from pydantic import Field

class MyScannerConfig(ScannerPluginConfigBase):
    name: str = "my-scanner"
    enabled: bool = True

    class Options:
        severity_threshold: str = Field(default="MEDIUM", description="Minimum severity level")
        include_tests: bool = Field(default=False, description="Include test files")
```

## Scanner Plugin Example

Here's a complete example of a custom scanner plugin:

```python
import json
import subprocess
from pathlib import Path
from typing import List, Literal

from pydantic import Field

from automated_security_helper.base.scanner_plugin import ScannerPluginBase, ScannerPluginConfigBase
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.models.scan_results_container import ScanResultsContainer

class CustomScannerConfig(ScannerPluginConfigBase):
    """Configuration for CustomScanner"""
    name: str = "custom-scanner"
    enabled: bool = True

    class Options:
        tool_path: str = Field(default="custom-tool", description="Path to the scanning tool")
        severity_threshold: str = Field(default="MEDIUM", description="Minimum severity level")

@ash_scanner_plugin
class CustomScanner(ScannerPluginBase):
    """Custom scanner implementation"""

    def model_post_init(self, context):
        """Initialize the scanner with configuration"""
        if self.config is None:
            self.config = CustomScannerConfig()

        self.command = "custom-tool"
        # Enable UV tool execution if your tool should be managed via UV
        # self.use_uv_tool = True
        self.tool_type = "SAST"  # or "IAC", "SCA", "SECRETS", etc.

        super().model_post_init(context)

    def scan(self, target: Path, target_type: Literal["source", "converted"],
             global_ignore_paths: List = None, config=None):
        """Scan the target using a custom tool"""
        if config is None:
            config = self.config

        # Create results container
        container = ScanResultsContainer()

        try:
            # Run the external tool
            cmd = [config.options.tool_path, "--scan", str(target),
                   "--severity", config.options.severity_threshold]

            result = self._run_subprocess(
                cmd,
                stdout_preference="return",
                stderr_preference="write"
            )

            # Parse the output
            if result.stdout:
                findings = json.loads(result.stdout)

                # Create SARIF report
                sarif_report = {
                    "version": "2.1.0",
                    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
                    "runs": [
                        {
                            "tool": {
                                "driver": {
                                    "name": config.name,
                                    "version": "1.0.0"
                                }
                            },
                            "results": []
                        }
                    ]
                }

                # Convert findings to SARIF format
                for finding in findings:
                    sarif_report["runs"][0]["results"].append({
                        "ruleId": finding["id"],
                        "level": finding["severity"].lower(),
                        "message": {
                            "text": finding["message"]
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": finding["file"]
                                    },
                                    "region": {
                                        "startLine": finding["line"]
                                    }
                                }
                            }
                        ]
                    })

                # Write SARIF report
                sarif_path = self.results_dir / f"{config.name}.sarif"
                with open(sarif_path, "w") as f:
                    json.dump(sarif_report, f, indent=2)

                container.sarif_report = sarif_report

        except Exception as e:
            container.add_error(f"Error running scanner: {str(e)}")

        return container
```

## UV Tool Integration

ASH v3 supports UV tool integration for scanner plugins that use CLI tools. This provides automatic tool isolation and management without requiring users to manually install tools.

### Enabling UV Tool Integration

To enable UV tool integration in your scanner plugin:

```python
@ash_scanner_plugin
class MyScanner(ScannerPluginBase):
    def model_post_init(self, context):
        if self.config is None:
            self.config = MyScannerConfig()

        self.command = "my-tool"
        self.use_uv_tool = True  # Enable UV tool execution
        self.tool_type = "SAST"

        # Get tool version via UV
        self.tool_version = self._get_uv_tool_version("my-tool")

        super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        """Validate scanner dependencies"""
        # UV tool availability is automatically validated
        if not self._validate_uv_tool_availability():
            return False

        # For UV tool-based scanners, dependencies are satisfied if UV is available
        if self.use_uv_tool:
            self.dependencies_satisfied = True
            return True

        return super().validate_plugin_dependencies()
```

### Benefits of UV Tool Integration

- **Automatic Tool Management**: Tools are downloaded and managed automatically
- **Isolation**: Tools run in isolated environments without affecting project dependencies
- **Version Control**: Consistent tool versions across environments
- **Fallback Support**: Automatic fallback to direct execution if UV is unavailable

### Built-in UV Tool Scanners

The following built-in scanners use UV tool integration:
- **Checkov**: Infrastructure-as-Code scanning
- **Semgrep**: Static Application Security Testing

## Scanner Plugin Best Practices

1. **Generate SARIF Reports**: SARIF is the standard format for security findings
2. **Handle Errors Gracefully**: Use try/except blocks to handle errors
3. **Respect Global Ignore Paths**: Skip files that are in the global ignore paths
4. **Use Subprocess Utilities**: Use the provided `_run_subprocess` method for running external commands
5. **Add Metadata**: Add useful metadata to the results container
6. **UV Tool Integration**: For CLI tools that can be managed via UV, set `use_uv_tool = True` in your `model_post_init` method to enable automatic tool isolation and management

## Scanner Plugin Configuration in ASH

Configure your scanner in the ASH configuration file:

```yaml
# .ash/.ash.yaml
scanners:
  custom-scanner:
    enabled: true
    options:
      tool_path: /path/to/custom-tool
      severity_threshold: HIGH
```

## Testing Scanner Plugins

Create unit tests for your scanner:

```python
import pytest
from pathlib import Path

from automated_security_helper.base.plugin_context import PluginContext
from my_ash_plugins.scanners import CustomScanner

def test_custom_scanner():
    # Create a plugin context
    context = PluginContext(
        source_dir=Path("test_data"),
        output_dir=Path("test_output")
    )

    # Create scanner instance
    scanner = CustomScanner(context=context)

    # Run the scanner
    results = scanner.scan(Path("test_data/sample.py"), "source")

    # Assert results
    assert results is not None
    assert results.sarif_report is not None
    assert len(results.sarif_report["runs"][0]["results"]) > 0
```