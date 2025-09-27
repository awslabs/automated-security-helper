# Frequently Asked Questions

## General Questions

### What is ASH?
ASH (Automated Security Helper) is a security scanning tool designed to help you identify potential security issues in your code, infrastructure, and IAM configurations as early as possible in your development process.

### What's new in ASH v3?
ASH v3 has been completely rewritten in Python with significant improvements:
- Python-based CLI with multiple execution modes
- Enhanced configuration system
- Improved reporting formats
- Customizable plugin system
- Better Windows support
- Programmatic API for integration

### Is ASH a replacement for human security reviews?
No. ASH is designed to help identify common security issues early in the development process, but it's not a replacement for human security reviews or team/customer security standards.

## Installation and Setup

### How do I install ASH v3?
You have several options:
```bash
# Using uvx (recommended)
alias ash="uvx git+https://github.com/awslabs/automated-security-helper.git@v3.0.2"

# Using pipx
pipx install git+https://github.com/awslabs/automated-security-helper.git@v3.0.2

# Using pip
pip install git+https://github.com/awslabs/automated-security-helper.git@v3.0.2
```

### What are the prerequisites for ASH v3?
- For local mode: Python 3.10 or later, UV package manager
- For container mode: Any OCI-compatible container runtime (Docker, Podman, Finch, etc.)
- On Windows with container mode: WSL2 is typically required

### How do I run ASH on Windows?
ASH v3 can run directly on Windows in local mode with Python 3.10+. Simply install ASH using pip, pipx, or uvx and run with `--mode local`. For container mode, you'll need WSL2 and a container runtime like Docker Desktop, Rancher Desktop, or Podman Desktop.

## Usage

### What are the different execution modes in ASH v3?
ASH v3 supports three execution modes:
- **Local Mode**: Runs entirely in the local Python process
- **Container Mode**: Runs non-Python scanners in a container
- **Precommit Mode**: Runs a subset of fast scanners optimized for pre-commit hooks

### How do I run a basic scan?
```bash
# Run in local mode (Python-based scanners only)
ash --mode local

# Run in container mode (all scanners)
ash --mode container

# Run in precommit mode (fast subset of scanners)
ash --mode precommit
```

### How do I specify which files to scan?
```bash
# Scan a specific directory
ash --source-dir /path/to/code

# Configure ignore paths in .ash/.ash.yaml
global_settings:
  ignore_paths:
    - path: 'tests/test_data'
      reason: 'Test data only'
```

### How do I exclude files from scanning?
ASH respects `.gitignore` files. You can also configure ignore paths in your `.ash/.ash.yaml` configuration file.

### How do I run specific scanners?
```bash
# Run only specific scanners
ash --scanners bandit,semgrep

# Exclude specific scanners
ash --exclude-scanners cfn-nag,cdk-nag
```

### How do I generate specific report formats?
```bash
# Generate specific report formats
ash --output-formats markdown,html,json

# Generate a report from existing results
ash report --format html --output-dir ./my-scan-results
```

## Configuration

### Where is the ASH configuration file located?
By default, ASH looks for a configuration file in the following locations (in order):
1. `.ash/.ash.yaml`
2. `.ash/.ash.yml`
3. `.ash.yaml`
4. `.ash.yml`

### How do I create a configuration file?
```bash
# Initialize a new configuration file
ash config init
```

### How do I override configuration values at runtime?
```bash
# Enable a specific scanner
ash --config-overrides 'scanners.bandit.enabled=true'

# Change severity threshold
ash --config-overrides 'global_settings.severity_threshold=LOW'
```

## Scanners and Tools

### What security scanners are included in ASH v3?
ASH v3 integrates multiple open-source security tools. Tools like Bandit, Checkov, and Semgrep are managed via UV's tool isolation system, which automatically installs and runs them in isolated environments:
- Bandit (Python SAST) - Managed via UV tool isolation (auto-installed: `bandit>=1.7.0`)
- Semgrep (Multi-language SAST) - Managed via UV tool isolation (auto-installed: `semgrep>=1.125.0`)
- detect-secrets (Secret detection) - Included with ASH
- Checkov (IaC scanning) - Managed via UV tool isolation (auto-installed: `checkov>=3.2.0,<4.0.0`)
- cfn_nag (CloudFormation scanning) - Requires separate installation
- cdk-nag (CloudFormation scanning) - Included with ASH
- npm-audit (JavaScript/Node.js SCA) - Requires Node.js/npm
- Grype (Multi-language SCA) - Requires separate installation
- Syft (SBOM generation) - Requires separate installation

### I am trying to scan a CDK application, but ASH does not show CDK Nag scan results -- why is that?
ASH uses CDK Nag underneath to apply NagPack rules to *CloudFormation templates* via the `CfnInclude` CDK construct. This is purely a mechanism to ingest a bare CloudFormation template and apply CDK NagPacks to it; doing this against a template emitted by another CDK application causes a collision in the `CfnInclude` construct due to the presence of the `BootstrapVersion` parameter on the template added by CDK. For CDK applications, we recommend integrating CDK Nag directly in your CDK code. ASH will still apply other CloudFormation scanners (cfn-nag, checkov) against templates synthesized via CDK, but the CDK Nag scanner will not scan those templates.

### How do I add custom scanners?
You can create custom scanners by implementing the scanner plugin interface and adding your plugin module to the ASH configuration:

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - my_ash_plugins
```

## CI/CD Integration

### How do I run ASH in CI/CD pipelines?
ASH can be run in container mode in any CI/CD environment that supports containers. See the [tutorials](tutorials/running-ash-in-ci.md) for examples.

### How do I use ASH with pre-commit?
Add this to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/awslabs/automated-security-helper
    rev: v3.0.0
    hooks:
      - id: ash-simple-scan
```

### How do I fail CI builds on security findings?
```bash
# Exit with non-zero code if findings are found
ash --mode local --fail-on-findings
```

## Advanced Usage

### How do I run ASH in an offline/air-gapped environment?
Build an offline image with `ash --mode container --offline --offline-semgrep-rulesets p/ci --no-run`, push to your private registry, then use `ash --mode container --offline --no-build` in your air-gapped environment.

### Can I use ASH programmatically?
Yes, ASH v3 can be used programmatically in Python:

```python
from automated_security_helper.interactions.run_ash_scan import run_ash_scan
from automated_security_helper.core.enums import RunMode

results = run_ash_scan(
    source_dir="/path/to/code",
    output_dir="/path/to/output",
    mode=RunMode.local
)
```

### How do I customize the container image?
```bash
# Specify a custom container image
export ASH_IMAGE_NAME="my-registry/ash:custom"
ash --mode container

# Build a custom image
ash build-image --build-target ci --custom-containerfile ./my-dockerfile
```

## Troubleshooting

### ASH is not finding any files to scan
Ensure you're running ASH inside the folder you intend to scan or using the `--source-dir` parameter. If the folder where the files reside is part of a git repository, ensure the files are added (committed) before running ASH.

### I'm getting "command not found" errors for scanners in local mode
Some scanners require external dependencies. Either install the required dependencies locally or use container mode (`--mode container`).

### ASH is running slowly
Try these options:
- Use `--mode precommit` for faster scans
- Use `--scanners` to run only specific scanners
- Use `--strategy parallel` (default) to run scanners in parallel

### Some scanners seem to be missing from my scan results
ASH v3 includes a comprehensive Scanner Validation System that monitors scanner registration, enablement, and execution throughout the scan process. If scanners are missing:

1. Check the scan logs for validation warnings about missing or disabled scanners
2. Verify scanner dependencies are installed (for local mode)
3. Check your configuration for excluded scanners
4. Use `--debug` to see detailed validation information
5. Run the integration verification test: `python verify_integration.py` (if available in your installation)

The validation system will log specific reasons why scanners might be disabled (missing dependencies, configuration exclusions, etc.) and attempt automatic recovery where possible. Additionally, the system ensures all originally registered scanners appear in the final results with appropriate status, even if they failed or were disabled during the scan.

For detailed information about the scanner validation system, see the [Scanner Validation System](developer-guide/scanner-validation-system.md) developer guide.

### How do I debug ASH?
```bash
# Enable debug logging
ash --debug

# Enable verbose logging
ash --verbose
```

## AI Integration and MCP

### What is MCP and how does ASH support it?
Model Context Protocol (MCP) is a standardized way for AI applications to access external tools and data sources. ASH includes an MCP server that allows AI assistants to perform security scans, monitor progress, and analyze results through natural language interactions.

### How do I set up ASH with MCP?
1. **Install UV and Python 3.10+**:
   - Install `uv` from [Astral](https://docs.astral.sh/uv/getting-started/installation/) or the [GitHub README](https://github.com/astral-sh/uv#installation)
   - Install Python 3.10+ using `uv python install 3.10` (or a more recent version)

2. **Configure your AI client** to use the ASH MCP server:

   **Amazon Q Developer CLI** - Add to `~/.aws/amazonq/mcp.json`:
   ```json
   {
     "mcpServers": {
       "ash": {
         "command": "uvx",
         "args": [
           "--from=git+https://github.com/awslabs/automated-security-helper@v3.0.0",
           "ash",
           "mcp"
         ],
         "disabled": false,
         "autoApprove": []
       }
     }
   }
   ```

   **Claude Desktop** - Add to `claude_desktop_config.json`:
   ```json
   {
     "mcpServers": {
       "ash-security": {
         "command": "uvx",
         "args": [
           "--from=git+https://github.com/awslabs/automated-security-helper@v3.0.0",
           "ash",
           "mcp"
         ]
       }
     }
   }
   ```

   **Cline (VS Code)**:
   ```json
   {
     "mcpServers": {
       "ash": {
         "command": "uvx",
         "args": [
           "--from=git+https://github.com/awslabs/automated-security-helper@v3.0.0",
           "ash",
           "mcp"
         ],
         "disabled": false,
         "autoApprove": [
           "get_scan_progress",
           "list_active_scans",
           "get_scan_results"
         ]
       }
     }
   }
   ```

### What can I do with ASH through MCP?
- Start security scans with natural language commands
- Monitor scan progress in real-time
- Analyze and prioritize security findings
- Generate security reports and remediation plans
- Manage multiple concurrent scans
- Configure resource limits and performance settings
- Monitor system resource usage and health

### How do I configure resource management for the MCP server?

ASH v3 includes comprehensive resource management that can be configured through your ASH configuration file:

```yaml
# .ash/ash.yaml
mcp-resource-management:
  max_concurrent_scans: 5          # Limit simultaneous scans
  max_concurrent_tasks: 25         # Limit async tasks
  thread_pool_max_workers: 6       # Thread pool size
  scan_timeout_seconds: 2400       # 40 minute scan timeout
  memory_warning_threshold_mb: 2048 # Memory usage warnings
  enable_health_checks: true       # Enable monitoring
```

This prevents memory leaks, manages system resources, and ensures stable operation under load.

### I'm getting "Maximum concurrent scans exceeded" errors

This is a resource protection feature. You can adjust the limits in your configuration:

```yaml
# .ash/ash.yaml
mcp-resource-management:
  max_concurrent_scans: 10  # Increase from default of 3
  max_concurrent_tasks: 50  # Increase task limit if needed
```

Or wait for existing scans to complete before starting new ones.

### I'm getting MCP dependency errors
MCP dependencies are included by default in ASH v3. If you're still getting errors:

1. **Check UV installation**: Ensure UV is installed and available: `uv --version`
2. **Check Python version**: Ensure Python 3.10+ is available: `uv python list`
3. **Test the MCP server**: Try running the server directly:
   ```bash
   uvx --from=git+https://github.com/awslabs/automated-security-helper@v3.0.0 ash mcp --help
   ```

### How do I test the ASH MCP server?
```bash
# Test MCP server startup
uvx --from=git+https://github.com/awslabs/automated-security-helper@v3.0.0 ash mcp --debug

# Check ASH version
uvx --from=git+https://github.com/awslabs/automated-security-helper@v3.0.0 ash --version
```

### How do I monitor MCP server performance?

Enable resource monitoring in your configuration:

```yaml
# .ash/ash.yaml
mcp-resource-management:
  enable_health_checks: true
  enable_resource_logging: true
  log_resource_operations: true
```

Then ask your AI assistant:
```
"Show me the current resource usage of the MCP server"
"How many scans are currently running?"
"What's the memory usage of the security scanner?"
```

For more details, see the [MCP Tutorial](tutorials/using-ash-with-mcp.md).

## Getting Help

### Where can I find more documentation?
Visit the [ASH Documentation](https://awslabs.github.io/automated-security-helper/).

### How do I report issues or request features?
Create an issue on [GitHub](https://github.com/awslabs/automated-security-helper/issues).

### How do I contribute to ASH?
See the [CONTRIBUTING](contributing.md) guide for contribution guidelines.