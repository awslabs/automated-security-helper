# Advanced Usage

This guide covers advanced features and usage patterns for ASH v3.

## Execution Modes

ASH v3 supports three execution modes:

### Local Mode

```bash
ash --mode local
```

- Runs entirely in the local Python process
- Only uses Python-based scanners by default
- Fastest execution but limited scanner coverage
- Ideal for quick checks during development

### Container Mode

```bash
ash --mode container
```

- Runs non-Python scanners in a container
- Provides full scanner coverage
- Requires a container runtime (Docker, Podman, etc.)
- Ideal for comprehensive scans

### Precommit Mode

```bash
ash --mode precommit
```

- Runs a subset of fast scanners
- Optimized for pre-commit hooks
- Includes only Python-based scanners + npm audit
- Ideal for git hooks and quick CI checks

## Custom Plugins

ASH v3 supports custom plugins for extending functionality:

### Creating Custom Plugins

1. Create a Python module with your plugins:

```python
# my_ash_plugins/scanners.py
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.base.scanner_plugin import ScannerPluginBase, ScannerPluginConfigBase
from pydantic import Field
from pathlib import Path
from typing import List, Literal

class MyCustomScannerConfig(ScannerPluginConfigBase):
    """Configuration for MyCustomScanner"""
    class Options:
        custom_option: str = Field(default="default", description="Custom option")

@ash_scanner_plugin
class MyCustomScanner(ScannerPluginBase):
    """Custom scanner implementation"""
    name = "my-custom-scanner"
    description = "My custom security scanner"
    version = "1.0.0"

    def scan(self, target: Path, target_type: Literal["source", "converted"],
             global_ignore_paths: List = [], config=None):
        # Implement your scanning logic here
        results = self._run_subprocess(["my-scanner", "--target", str(target)])
        return results
```

2. Add your module to ASH configuration:

```yaml
ash_plugin_modules:
  - my_ash_plugins
```

3. Use your custom scanner:

```bash
ash --ash-plugin-modules my_ash_plugins
```

## Offline Mode

For air-gapped environments:

```bash
# Build an offline image
ash build-image --offline --offline-semgrep-rulesets p/ci

# Run in offline mode
ash --mode container --offline
```

## Customizing Scan Phases

ASH v3 executes scans in phases:

```bash
# Run only specific phases
ash --phases convert,scan

# Skip report generation
ash --phases convert,scan

# Include inspection phase
ash --phases convert,scan,report,inspect
```

## Using Existing Results

You can generate reports from existing scan results:

```bash
# Use existing results file
ash --use-existing --output-dir /path/to/results

# Generate a specific report format
ash report --format html --output-dir /path/to/results
```

## Interactive Findings Explorer

ASH v3 includes an interactive TUI for exploring findings:

```bash
# Launch the findings explorer
ash inspect findings --output-dir /path/to/results
```

## Container Customization

### Using Alternative Container Runtimes

```bash
# Use Podman instead of Docker
ash --mode container --oci-runner podman

# Use Finch
ash --mode container --oci-runner finch
```

### Custom Container Images

```bash
# Specify a custom container image
export ASH_IMAGE_NAME="my-registry/ash:custom"
ash --mode container
```

### Building Custom Images

```bash
# Build a custom image
ash build-image --build-target ci --custom-containerfile ./my-dockerfile
```

## Advanced Configuration Overrides

```bash
# Complex configuration overrides
ash --config-overrides 'scanners.semgrep.options.rules=["p/ci", "p/owasp-top-ten"]'
ash --config-overrides 'global_settings.ignore_paths+=[{"path": "build/", "reason": "Generated files"}]'
```

## Working with Suppressions

### Adding Suppressions via Config Overrides

```bash
# Add a suppression rule
ash --config-overrides 'global_settings.suppressions+=[{"rule_id": "RULE-123", "file_path": "src/example.py", "reason": "False positive"}]'

# Add a suppression with line range and expiration
ash --config-overrides 'global_settings.suppressions+=[{"rule_id": "RULE-456", "file_path": "src/*.js", "line_start": 10, "line_end": 15, "reason": "Known issue", "expiration": "2025-12-31"}]'
```

### Temporarily Ignoring Suppressions

```bash
# Run a scan ignoring all suppression rules
ash --ignore-suppressions

# Useful for verifying if suppressed issues have been fixed
ash --ignore-suppressions --output-dir ./verification-scan
```

## Programmatic Usage

ASH v3 can be used programmatically in Python:

```python
from automated_security_helper.interactions.run_ash_scan import run_ash_scan
from automated_security_helper.core.enums import RunMode, Strategy

# Run a scan
results = run_ash_scan(
    source_dir="/path/to/code",
    output_dir="/path/to/output",
    mode=RunMode.local,
    strategy=Strategy.parallel,
    scanners=["bandit", "semgrep"],
    config_overrides=["scanners.bandit.enabled=true"]
)

# Access scan results
print(f"Found {results.summary_stats.total_findings} findings")
```

## CI/CD Integration

### GitHub Actions

```yaml
name: ASH Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - name: Install ASH
        run: pip install git+https://github.com/awslabs/automated-security-helper.git@v3.0.2
      - name: Run ASH scan
        run: ash --mode local
      - name: Upload scan results
        uses: actions/upload-artifact@v3
        with:
          name: ash-results
          path: .ash/ash_output
```

### GitLab CI

```yaml
ash-scan:
  image: python:3.10
  script:
    - pip install git+https://github.com/awslabs/automated-security-helper.git@v3.0.2
    - ash --mode local
  artifacts:
    paths:
      - .ash/ash_output
```

## Performance Optimization

```bash
# Run scanners in parallel (default)
ash --strategy parallel

# Run scanners sequentially
ash --strategy sequential

# Clean up temporary files after scan
ash --cleanup
```

## Debugging

```bash
# Enable debug logging
ash --debug

# Enable verbose logging
ash --verbose

# Disable progress display
ash --progress false
```

### Scanner Validation

ASH v3 includes comprehensive scanner validation that monitors scanner registration, enablement, and execution throughout the scan process. When debugging scanner issues:

- Check logs for validation warnings about missing or disabled scanners
- Use `--debug` to see detailed validation checkpoint information
- Look for specific reasons why scanners might be disabled (dependencies, configuration, etc.)
- Run the integration verification test: `python verify_integration.py` (if available in your installation)

The validation system includes result completeness validation that ensures all originally registered scanners appear in the final scan results, even if they failed or were disabled. This provides complete visibility into scan coverage and helps identify any scanners that may have been silently dropped during the scan process.

For detailed information about the scanner validation system, see the [Scanner Validation System](../developer-guide/scanner-validation-system.md) developer guide.