# Scanner Plugins

Scanner plugins perform security scans on files and generate findings. They are the core of ASH's security scanning functionality.

> For detailed visual diagrams of scanner plugin architecture and workflow, see [Scanner Plugin Diagrams](scanner-plugins-diagrams.md).

## Scanner Plugin Interface

Scanner plugins must implement the `ScannerPluginBase` interface:

```python
from automated_security_helper.base.scanner_plugin import ScannerPluginBase, ScannerPluginConfigBase
from automated_security_helper.plugins.decorators import ash_scanner_plugin

@ash_scanner_plugin
class MyScanner(ScannerPluginBase):
    """My custom scanner implementation"""

    def scan(self, target, target_type, global_ignore_paths=None, config=None):
        """Implement your scanning logic here"""
        # Your code here
```

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

## Scanner Plugin Best Practices

1. **Generate SARIF Reports**: SARIF is the standard format for security findings
2. **Handle Errors Gracefully**: Use try/except blocks to handle errors
3. **Respect Global Ignore Paths**: Skip files that are in the global ignore paths
4. **Use Subprocess Utilities**: Use the provided `_run_subprocess` method for running external commands
5. **Add Metadata**: Add useful metadata to the results container

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