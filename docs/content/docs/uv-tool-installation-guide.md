# UV Tool Installation Guide

This guide covers the enhanced UV tool installation functionality in ASH (Automated Security Helper), which provides explicit tool installation for Python-based security scanners.

## Overview

ASH now supports explicit UV tool installation for Python-based security scanners including:

- **Bandit** - Python source code security analyzer
- **Checkov** - Infrastructure as Code (IaC) security scanner
- **Semgrep** - Static analysis tool for finding bugs and security issues

The enhanced installation system provides:

- **Explicit Installation**: Tools are installed upfront rather than on-demand
- **Version Control**: Specify exact version constraints for reproducible scans
- **Offline Mode Support**: Works with cached tools and pre-installed dependencies
- **Enhanced Error Handling**: Comprehensive logging and fallback mechanisms
- **Performance Optimization**: Leverages UV's caching for faster subsequent installations

## Configuration Options

### Bandit Scanner Configuration

```yaml
scanners:
  bandit:
    enabled: true
    options:
      tool_version: ">=1.7.0,<2.0.0"  # Version constraint for installation
      install_timeout: 300             # Installation timeout in seconds
      confidence_level: "all"
      ignore_nosec: false
```

### Checkov Scanner Configuration

```yaml
scanners:
  checkov:
    enabled: true
    options:
      tool_version: ">=3.2.0,<4.0.0"  # Version constraint for installation
      install_timeout: 300             # Installation timeout in seconds
      frameworks: ["all"]
      offline: false
```

### Semgrep Scanner Configuration

```yaml
scanners:
  semgrep:
    enabled: true
    options:
      tool_version: ">=1.125.0"        # Version constraint for installation
      install_timeout: 300             # Installation timeout in seconds
      config: "auto"
      metrics: "auto"
```

## Installation Workflow

### 1. Explicit Installation Process

When a scanner is initialized, the following workflow occurs:

1. **UV Availability Check**: Verify that UV is available on the system
2. **Tool Status Check**: Check if the tool is already installed via UV
3. **Installation Attempt**: If not installed, attempt explicit installation with version constraints
4. **Validation**: Validate that the installed tool is functional
5. **Fallback**: If installation fails, fall back to pre-installed tools or existing validation

### 2. Installation Commands

The system generates UV tool installation commands automatically:

```bash
# Basic installation
uv tool install bandit

# With version constraint
uv tool install "bandit>=1.7.0,<2.0.0"

# With package extras (for enhanced functionality)
uv tool install "bandit[sarif,toml]>=1.7.0,<2.0.0"

# In offline mode
uv tool install --offline "bandit>=1.7.0,<2.0.0"
```

## Version Constraints

### Supported Version Constraint Formats

```yaml
# Exact version
tool_version: "==1.7.5"

# Minimum version
tool_version: ">=1.7.0"

# Version range
tool_version: ">=1.7.0,<2.0.0"

# Compatible release
tool_version: "~=1.7.0"

# Latest version (default)
tool_version: null
```

### Default Version Constraints

Each scanner has sensible default version constraints:

- **Bandit**: `>=1.7.0,<2.0.0` (SARIF and TOML support)
- **Checkov**: `>=3.2.0,<4.0.0` (Improved stability)
- **Semgrep**: `>=1.125.0` (Enhanced performance)

## Offline Mode Support

### Enabling Offline Mode

Set the `ASH_OFFLINE` environment variable:

```bash
export ASH_OFFLINE=true
ash --mode local
```

Or configure in scanner options:

```yaml
scanners:
  checkov:
    options:
      offline: true
```

### Offline Mode Behavior

In offline mode:

1. **Installation Skipping**: UV tool installation attempts are skipped
2. **Pre-installed Detection**: System searches for pre-installed tools
3. **Cache Usage**: Leverages UV's local cache when available
4. **Clear Error Messages**: Provides helpful guidance for offline limitations

### Offline Mode Environment Variables

```bash
# Enable ASH offline mode
export ASH_OFFLINE=true

# Enable UV offline mode (for tool execution)
export UV_OFFLINE=1

# Specify Semgrep rules cache directory
export SEMGREP_RULES_CACHE_DIR=/path/to/cached/rules
```

### Logging and Diagnostics

The installation system provides structured logging with tags:

- `[INSTALLATION_START]`: Installation initiation
- `[INSTALLATION_PROGRESS]`: Progress updates
- `[INSTALLATION_SUCCESS]`: Successful installation
- `[INSTALLATION_FAILED]`: Installation failure
- `[INSTALLATION_ERROR]`: Unexpected errors
- `[INSTALLATION_SKIP]`: Installation skipped (offline mode, already installed)

Enable debug logging for detailed diagnostics:

```bash
export ASH_LOG_LEVEL=DEBUG
ash --mode local
```

## Performance Optimization

### Caching Benefits

UV's built-in caching provides significant performance improvements:

- **First Installation**: Downloads and caches tool and dependencies
- **Subsequent Installations**: Uses cached artifacts (50-90% faster)
- **Cross-Project Sharing**: Cache shared across different ASH projects

### Cache Management

```bash
# View cache information
uv cache info

# Clean cache if needed
uv cache clean

# Check cache size and location
uv cache dir
```

### Performance Tips

1. **Use Version Ranges**: Allows cache reuse across compatible versions
2. **Pre-install in CI**: Install tools in CI setup phase for faster builds
3. **Shared Cache**: Use shared cache directories in containerized environments
4. **Concurrent Scans**: Installation system handles concurrent scanner initialization

## Advanced Configuration

### Custom Installation Commands

For advanced use cases, you can define custom installation commands:

```python
# In custom scanner implementation
def _get_tool_version_constraint(self) -> str:
    return ">=1.7.0,<2.0.0"

def _get_tool_package_extras(self) -> List[str]:
    return ["sarif", "toml", "yaml"]
```

### Retry Configuration

Configure installation retry behavior:

```python
retry_config = {
    "max_retries": 3,
    "base_delay": 1.0,
    "max_delay": 60.0,
}
```

### Progress Monitoring

For long-running installations, progress monitoring is automatically enabled:

```python
def progress_callback(message: str):
    print(f"Installation progress: {message}")

# Progress updates every 10 seconds for installations > 60 seconds
```

## Migration Guide

### From On-Demand to Explicit Installation

If you're upgrading from a previous version of ASH:

1. **No Configuration Changes Required**: Explicit installation is enabled by default
2. **Optional Version Pinning**: Add `tool_version` to scanner configurations for reproducibility
3. **Timeout Adjustment**: Increase `install_timeout` if you experience timeout issues
4. **Offline Mode**: Configure offline mode if running in air-gapped environments

### Backward Compatibility

The enhanced installation system maintains full backward compatibility:

- **Existing Configurations**: Continue to work without changes
- **Fallback Mechanisms**: Falls back to pre-installed tools if UV installation fails
- **Legacy Behavior**: On-demand installation still available as fallback

## Examples

### Basic Configuration

```yaml
# .ash/ash.yaml
scanners:
  bandit:
    enabled: true
  checkov:
    enabled: true
  semgrep:
    enabled: true
```

### Advanced Configuration with Version Control

```yaml
# .ash/ash.yaml
scanners:
  bandit:
    enabled: true
    options:
      tool_version: ">=1.7.5,<1.8.0"
      install_timeout: 600
      confidence_level: "medium"

  checkov:
    enabled: true
    options:
      tool_version: ">=3.2.5,<3.3.0"
      install_timeout: 300
      frameworks: ["terraform", "cloudformation"]

  semgrep:
    enabled: true
    options:
      tool_version: ">=1.125.0,<2.0.0"
      install_timeout: 450
      config: "p/security-audit"
```

### Offline Mode Configuration

```yaml
# .ash/ash.yaml
scanners:
  checkov:
    enabled: true
    options:
      offline: true
      frameworks: ["terraform"]

  semgrep:
    enabled: true
    options:
      offline: true
      config: "p/ci"  # Use cached rules
```

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Setup UV
  run: |
    curl -LsSf https://astral.sh/uv/install.sh | sh
    echo "$HOME/.cargo/bin" >> $GITHUB_PATH

- name: Pre-install Security Tools
  run: |
    uv tool install "bandit>=1.7.0"
    uv tool install "checkov>=3.2.0"
    uv tool install "semgrep>=1.125.0"

- name: Run ASH Security Scan
  run: |
    ash --mode local
```

## Best Practices

### 1. Version Management

- **Pin Major Versions**: Use ranges like `>=1.7.0,<2.0.0` to avoid breaking changes
- **Regular Updates**: Periodically update version constraints for security patches
- **Testing**: Test version updates in development before production deployment

### 2. Performance Optimization

- **Pre-installation**: Install tools during environment setup rather than scan time
- **Cache Sharing**: Use shared UV cache directories in containerized environments
- **Concurrent Scans**: Leverage concurrent scanner initialization for faster startup

### 3. Error Handling

- **Timeout Configuration**: Set appropriate timeouts based on network conditions
- **Fallback Planning**: Ensure pre-installed tools are available as fallbacks
- **Monitoring**: Monitor installation success rates and adjust configurations

### 4. Security Considerations

- **Version Pinning**: Pin tool versions for reproducible security scans
- **Offline Mode**: Use offline mode in secure environments with limited network access
- **Tool Verification**: Regularly validate that installed tools are functional

## Troubleshooting Checklist

When experiencing installation issues:

1. **Check UV Installation**: `uv --version`
2. **Verify Network Connectivity**: Can reach PyPI and tool repositories
3. **Check Disk Space**: Ensure sufficient space for tool installation and cache
4. **Review Logs**: Enable debug logging for detailed error information
5. **Test Manual Installation**: Try installing tools manually with UV
6. **Check Version Constraints**: Verify version constraint syntax and availability
7. **Consider Offline Mode**: Use offline mode with pre-installed tools if needed
8. **Update Configuration**: Adjust timeouts and retry settings as needed