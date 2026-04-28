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
uv run pytest
```

Run specific test categories:

```bash
# Unit tests
uv run pytest tests/unit/ -v

# Integration tests
uv run pytest tests/integration/ -v

# Scanner-specific integration tests
uv run pytest tests/integration/scanners/ -v
```

## Development Commands

- Format and lint code:

```bash
uv run ruff check .
uv run ruff format .
```

- Run a specific script:

```bash
uv run ash
```

## Project Dependencies

Dependencies are managed in `pyproject.toml`. Key groups:

- Runtime dependencies: defined under `[project] dependencies`
- Dev dependencies: defined under `[dependency-groups] dev` (includes ruff, pytest, mypy, mkdocs, etc.)

Scanner tools (Bandit, Checkov, Semgrep) are managed via UV tool isolation at runtime — they're not project dependencies.

## Troubleshooting

If you encounter any issues:

1. Verify your Python version matches the required version (3.10+):

```bash
python --version
```

2. Try cleaning and rebuilding the environment:

```bash
rm -rf .venv
uv sync
```

3. Update UV and dependencies:

```bash
uv self update
uv sync --upgrade
```

4. If using a devfile-compatible IDE and encountering issues, try running the devfile commands manually:

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
uv run python -m automated_security_helper.utils.migration_validator

# Get detailed JSON output for debugging
uv run python -m automated_security_helper.utils.migration_validator --json
```

The validator checks:

- UV installation and version compatibility
- Project configuration (pyproject.toml) structure
- Dependency resolution capability
- CLI tool availability via UV tool run
- Build system configuration

## Version Management

ASH uses [Semantic Versioning](https://semver.org/). The version is defined in `pyproject.toml` and propagated to documentation files via a template system.

### How It Works

- `pyproject.toml` is the single source of truth for the version.
- Documentation files that reference the version (README, install guides, etc.) have corresponding `.template` files containing `{{VERSION}}` placeholders.
- The `scripts/version_bump.py` script updates `pyproject.toml` and regenerates all documentation from templates.

### Automated Version Bumping (CI)

Every PR merged to `main` automatically receives a **patch** version bump. To skip the bump (e.g., docs-only or CI-only changes), add the `no-version-bump` label to the PR before merging.

For **minor** or **major** bumps, use the manual workflow dispatch: go to **Actions > ASH - Auto Version Bump > Run workflow** and select the bump type from the dropdown. The commit message includes who triggered it for auditability.

The workflow pushes directly to `main` via a GitHub Actions bypass in the repository ruleset.

### Manual Version Bumping

```bash
# Show current version
uv run python scripts/version_bump.py current

# Bump version (patch, minor, or major)
uv run python scripts/version_bump.py bump patch

# Set a specific version
uv run python scripts/version_bump.py set 4.0.0

# Validate version consistency across files
uv run python scripts/version_bump.py validate
```

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

    def validate_plugin_dependencies(self) -> bool:
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

1. Unit tests: test scanner logic in isolation
2. Integration tests: test with actual tool execution

```bash
# Run scanner-specific unit tests
uv run pytest tests/unit/plugin_modules/ -v

# Run scanner integration tests
uv run pytest tests/integration/scanners/ -v
```
