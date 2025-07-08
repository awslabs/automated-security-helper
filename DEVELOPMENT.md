# Local Development Setup Guide

This guide will help you set up your local development environment for the Automated Security Helper project.

## Prerequisites

- Python 3.10 or later
- UV (Python package manager) - **Note: Project has migrated from Poetry to UV**

## Setting up UV

1. Install UV on your system

[Official instructions](https://docs.astral.sh/uv/getting-started/installation/)

Linux, macOS, Windows (WSL)

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Windows PowerShell:

```ps1
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

2. Verify UV installation:

```bash
uv --version
```

## Project Setup

### Option 1: Manual Setup

1. Clone the repository:

```bash
git clone https://github.com/awslabs/automated-security-helper.git
cd automated-security-helper
```

2. Install project dependencies:

```bash
uv sync
```

This command will:
- Create a virtual environment
- Install all dependencies from pyproject.toml and uv.lock
- Set up the project in development mode

3. Activate the virtual environment:

```bash
source .venv/bin/activate
```

Or use UV's built-in environment management:

```bash
uv run <command>
```

### Option 2: Using Development Containers

If you're using an IDE that supports devfiles (like Eclipse Che, Red Hat OpenShift Dev Spaces, or other devfile-compatible environments), you can use the provided `devfile.yaml`:

The devfile includes pre-configured commands:
- `install`: Sets up UV and installs dependencies
- `build`: Builds the project using UV
- `test`: Runs the test suite

This provides a consistent development environment across different platforms and IDEs.

## Testing

Run the test suite:

```bash
pytest
```

### Scanner Validation Integration Testing

The project includes a verification script to test the scanner validation system integration:

```bash
# Run the scanner validation integration verification
python verify_integration.py
```

This script validates that:
- The `ScannerValidationManager` is properly initialized in `ScanPhase`
- Validation methods are available and callable
- The integration points are working correctly

### UV Migration Integration Tests

The project includes comprehensive integration tests for the Poetry to UV migration:

```bash
# Run all UV migration integration tests
pytest tests/integration/migration/test_uv_migration_integration.py -v

# Run specific test categories
pytest tests/integration/migration/test_uv_migration_integration.py::TestUVToolScannerExecution -v
pytest tests/integration/migration/test_uv_migration_integration.py::TestUVDependencyResolution -v
pytest tests/integration/migration/test_uv_migration_integration.py::TestUVBuildSystem -v

# Run performance comparison tests (slower)
pytest tests/integration/migration/test_uv_migration_integration.py::TestUVPerformanceComparison -v -m slow

# Run cross-platform compatibility tests
pytest tests/integration/migration/test_uv_migration_integration.py::TestUVCrossPlatformCompatibility -v
```

These tests validate:
- UV tool scanner execution (Checkov, Semgrep)
- UV dependency resolution and installation
- UV build system functionality
- Performance comparisons between Poetry and UV
- Cross-platform compatibility (Windows, macOS, Linux)
- ASH project UV migration validation

## Development Commands

- Format and lint code:

```bash
uv run ruff .
```

- Run a specific script:

```bash
uv run ash
```

## Project Dependencies

The project uses the following key dependencies:

- Python
- UV (package manager)

CLI tools managed via UV tool:

- checkov (Infrastructure as Code scanning)
- semgrep (Static Application Security Testing)

Development dependencies include:

- ruff
- pytest
- pytest-cov

## Troubleshooting

If you encounter any issues:

1. **Validate the migration status first:**

```bash
python -m automated_security_helper.utils.migration_validator
```

2. Verify your Python version matches the required version (3.10+):

```bash
python --version
```

3. Try cleaning and rebuilding the environment:

```bash
rm -rf .venv
uv sync
```

4. Update UV and dependencies:

```bash
uv self update
uv sync --upgrade
```

5. If using a devfile-compatible IDE and encountering issues, try running the devfile commands manually:

```bash
# Install dependencies
curl -LsSf https://astral.sh/uv/install.sh | sh && source $HOME/.cargo/env && uv sync

# Build the project
uv build

# Run tests
uv run pytest
```

### Migration Validation

The project includes a migration validator to help diagnose UV-related issues:

```bash
# Check migration status
python -m automated_security_helper.utils.migration_validator

# Get detailed JSON output for debugging
python -m automated_security_helper.utils.migration_validator --json
```

The validator checks:
- UV installation and version compatibility
- Project configuration (pyproject.toml) structure
- Dependency resolution capability
- CLI tool availability via UV tool run
- Build system configuration

## Scanner Plugin Development

When developing custom scanner plugins for ASH, follow these guidelines:

### Base Scanner Plugin

All scanner plugins should inherit from `ScannerPluginBase` and implement the required methods:

```python
from automated_security_helper.base.scanner_plugin import ScannerPluginBase, ScannerPluginConfigBase
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from typing import Optional

@ash_scanner_plugin
class MyCustomScanner(ScannerPluginBase[MyCustomScannerConfig]):
    def model_post_init(self, context):
        # Initialize scanner properties
        self.command = "my-tool"
        self.use_uv_tool = True  # Enable UV tool management if needed
        self.tool_type = "SAST"  # Scanner type

        # Set up UV tool installation if using UV tool management
        if self.use_uv_tool:
            self._setup_uv_tool_install_commands()
            self.tool_version = self._get_uv_tool_version("my-tool")

        super().model_post_init(context)

    def validate(self) -> bool:
        # Implement validation logic
        return True

    def scan(self, target, target_type, global_ignore_paths=None, config=None):
        # Implement scanning logic
        pass
```

### UV Tool Version Constraints (Optional)

The `_get_tool_version_constraint()` method is **optional** and only needs to be implemented if your scanner requires specific version constraints for UV tool installation:

```python
def _get_tool_version_constraint(self) -> Optional[str]:
    """Get version constraint for tool installation.

    This method is optional - only implement if you need specific version constraints.

    Returns:
        Version constraint string (e.g., ">=1.0.0") or None for latest
    """
    # Optional: specify version constraints for UV tool installation
    return ">=1.0.0"
```

**Key Points:**
- This method is **not abstract** and doesn't require implementation
- If not implemented, ASH will install the latest version of the tool
- Use standard pip version specifiers (e.g., `>=1.0.0`, `==2.1.0`, `>=1.0.0,<2.0.0`)
- Consider tool stability and compatibility when setting constraints

### UV Tool Management

ASH provides automatic tool management via UV's tool isolation system:

- **Automatic Installation**: Tools are installed when needed during scanner validation
- **Version Constraints**: Use `_get_tool_version_constraint()` to specify version requirements
- **Isolation**: Tools run in isolated environments without affecting project dependencies
- **Fallback Support**: ASH falls back to system-installed tools if UV installation fails

### Testing Scanner Plugins

When testing custom scanner plugins:

1. **Unit Tests**: Test scanner logic in isolation
2. **Integration Tests**: Test with actual tool execution
3. **UV Tool Tests**: Verify UV tool installation and execution
4. **Validation Tests**: Ensure proper validation behavior

```bash
# Run scanner-specific tests
pytest tests/unit/plugin_modules/my_custom_scanner/ -v

# Test UV tool integration
pytest tests/integration/migration/test_uv_migration_integration.py -v
```
