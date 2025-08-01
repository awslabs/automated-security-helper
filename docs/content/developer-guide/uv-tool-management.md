# UV Tool Management

ASH v3 uses UV's tool isolation system to manage security scanner dependencies automatically. This system provides consistent tool versions, avoids dependency conflicts, and enables seamless tool installation without affecting your project environment.

## Overview

The UV tool management system in ASH provides:

- **Automatic tool installation**: Tools like Checkov, Semgrep, and Bandit are installed automatically when needed
- **Version constraints**: Ensures compatible tool versions with sensible defaults
- **Isolation**: Tools run in isolated environments without dependency conflicts
- **Fallback mechanisms**: Graceful fallback to pre-installed tools when UV is unavailable
- **Offline support**: Respects offline mode settings and uses pre-installed tools
- **Comprehensive logging**: Detailed installation and execution logging for troubleshooting

## Architecture

### Core Components

#### UVToolRunner
The main class responsible for UV tool operations:

```python
from automated_security_helper.utils.uv_tool_runner import get_uv_tool_runner

runner = get_uv_tool_runner()
```

Key methods:
- `is_uv_available()`: Check if UV is available on the system
- `is_tool_installed(tool_name)`: Check if a specific tool is installed
- `install_tool_with_version()`: Install a tool with version constraints
- `run_tool()`: Execute a UV tool with arguments
- `get_tool_version()`: Get version information for installed tools

#### UVToolInstallationStatus
Tracks the complete installation state of UV tools:

```python
from automated_security_helper.models.uv_tool_installation import UVToolInstallationStatus

status = UVToolInstallationStatus(
    tool_name="checkov",
    is_installed=True,
    installed_version="3.2.5",
    preferred_source="uv"
)
```

#### UVToolRetryConfig
Configures retry logic for tool operations:

```python
from automated_security_helper.utils.uv_tool_runner import UVToolRetryConfig

retry_config = UVToolRetryConfig(
    max_retries=3,
    base_delay=1.0,
    max_delay=60.0,
    exponential_base=2.0,
    jitter=True
)
```

## Scanner Integration

### UV-Enabled Scanners

Scanners that use UV tool management:

| Scanner | Default Version Constraint | Installation Method |
|---------|----------------------------|-------------------|
| Bandit | `>=1.7.0` | `uv tool install bandit>=1.7.0` |
| Checkov | `>=3.2.0,<4.0.0` | `uv tool install checkov>=3.2.0,<4.0.0` |
| Semgrep | `>=1.125.0` | `uv tool install semgrep>=1.125.0` |

### Scanner Configuration

Enable UV tool management in scanner plugins:

```python
class MyScanner(ScannerPluginBase):
    def model_post_init(self, context):
        self.use_uv_tool = True  # Enable UV tool execution
        self.command = "my-tool"

        # Set up UV tool installation
        self._setup_uv_tool_install_commands()

        # Get tool version from UV
        self.tool_version = self._get_uv_tool_version("my-tool")
```

### Version Constraints

Override default version constraints:

```python
def _get_tool_version_constraint(self) -> str | None:
    """Get version constraint for tool installation."""
    if self.config and self.config.options.tool_version:
        return self.config.options.tool_version

    # Use tool-specific default constraint
    return ">=2.0.0,<3.0.0"
```

## Installation Process

### Automatic Installation Flow

1. **UV Availability Check**: Verify UV is installed and accessible
2. **Tool Status Check**: Check if tool is already installed via UV
3. **Installation Attempt**: Install tool with version constraints if needed
4. **Retry Logic**: Retry installation with exponential backoff on failure
5. **Fallback**: Use pre-installed tools if UV installation fails

### Installation Logging

The system provides comprehensive logging for troubleshooting:

```
[INSTALLATION_START] Initiating UV tool installation for 'checkov'
[INSTALLATION_PROGRESS] UV availability confirmed in 0.123s
[INSTALLATION_ATTEMPT] Starting installation of UV tool
Tool specification: checkov>=3.2.0,<4.0.0
[INSTALLATION_SUCCESS] Successfully installed UV tool 'checkov'
Installed version: 3.2.5
Total installation time: 45.678s
```

### Error Handling

Common installation scenarios and their handling:

- **UV Not Available**: Falls back to pre-installed tools
- **Network Issues**: Retries with exponential backoff
- **Version Conflicts**: Logs detailed error information
- **Timeout**: Configurable timeout with graceful failure
- **Offline Mode**: Skips installation and uses existing tools

## Configuration

### Environment Variables

Control UV tool behavior with environment variables:

```bash
# Disable automatic tool installation
export ASH_OFFLINE=true

# Custom UV executable path
export UV_EXECUTABLE=/custom/path/to/uv
```

### Scanner Options

Configure UV tool behavior per scanner:

```yaml
scanners:
  checkov:
    enabled: true
    options:
      tool_version: ">=3.2.0,<4.0.0"  # Override version constraint
      install_timeout: 300             # Installation timeout in seconds
```

## Troubleshooting

### Common Issues

#### UV Not Found
```
UV tool execution is required but UV is not available
```

**Solutions:**
- Install UV: `curl -LsSf https://astral.sh/uv/install.sh | sh`
- Use offline mode: `ASH_OFFLINE=true ash --mode local`
- Pre-install tools manually

#### Installation Timeout
```
UV tool install timeout for checkov>=3.2.0,<4.0.0
```

**Solutions:**
- Increase timeout: Configure `install_timeout` in scanner options
- Check network connectivity
- Use pre-installed tools in offline environments

#### Version Conflicts
```
Failed to install UV tool checkov>=3.2.0,<4.0.0 after 3 attempts
```

**Solutions:**
- Check version constraint compatibility
- Install manually: `uv tool install checkov>=3.2.0,<4.0.0`
- Use system-installed version

### Debug Information

Enable verbose logging for detailed UV tool information:

```bash
ash --mode local --verbose
```

This provides:
- UV availability status
- Tool installation attempts and results
- Version detection information
- Fallback mechanism activation
- Execution method selection (UV vs direct)

### Manual Tool Management

Pre-install tools to avoid automatic installation:

```bash
# Install specific versions
uv tool install bandit>=1.7.0
uv tool install checkov>=3.2.0,<4.0.0
uv tool install semgrep>=1.125.0

# List installed tools
uv tool list

# Update tools
uv tool upgrade bandit
```

## Best Practices

### For Users

1. **Install UV**: Ensure UV is available for optimal tool management
2. **Network Access**: Provide internet access for automatic installations
3. **Version Pinning**: Use specific version constraints for reproducible builds
4. **Offline Preparation**: Pre-install tools for air-gapped environments

### For Developers

1. **Graceful Fallbacks**: Always provide fallback to pre-installed tools
2. **Comprehensive Logging**: Log installation attempts and results
3. **Version Constraints**: Use sensible default version constraints
4. **Error Handling**: Handle UV unavailability gracefully
5. **Testing**: Test both UV and direct execution paths

## Integration Examples

### Custom Scanner with UV Support

```python
@ash_scanner_plugin
class CustomScanner(ScannerPluginBase[CustomScannerConfig]):
    def model_post_init(self, context):
        self.command = "custom-tool"
        self.use_uv_tool = True

        # Set up UV tool installation
        self._setup_uv_tool_install_commands()

        # Get version from UV or fallback
        self.tool_version = self._get_uv_tool_version("custom-tool")

        super().model_post_init(context)

    def _get_tool_version_constraint(self) -> str | None:
        return ">=1.0.0,<2.0.0"

    def validate_plugin_dependencies(self) -> bool:
        # Validate UV tool availability
        if not self._validate_uv_tool_availability():
            return False

        # Attempt installation if needed
        if self.use_uv_tool and not self._is_uv_tool_installed():
            if self._install_uv_tool(timeout=300):
                self.dependencies_satisfied = True
                return True

        # Fallback to base validation
        return super().validate_plugin_dependencies()
```

### Testing UV Tool Integration

```python
@patch('automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner')
def test_uv_tool_integration(mock_get_runner):
    mock_runner = Mock()
    mock_get_runner.return_value = mock_runner

    # Configure mock behavior
    mock_runner.is_uv_available.return_value = True
    mock_runner.is_tool_installed.return_value = False
    mock_runner.install_tool_with_version.return_value = True

    # Test scanner initialization
    scanner = CustomScanner(config=config, context=context)
    assert scanner.validate_plugin_dependencies() is True

    # Verify UV tool operations
    mock_runner.install_tool_with_version.assert_called_once()
```

This UV tool management system provides a robust foundation for managing security scanner dependencies while maintaining flexibility and reliability across different environments.