# Using ASH with Model Context Protocol (MCP)

This tutorial shows you how to set up and use ASH's Model Context Protocol (MCP) server to integrate security scanning with AI development tools.

## What is MCP?

Model Context Protocol (MCP) is a standardized way for AI applications to access external tools and data sources. ASH's MCP server allows AI assistants to perform security scans, monitor progress, and analyze results through natural language interactions.

## Prerequisites

Before starting, ensure you have:

- **UV Package Manager**: Install `uv` from [Astral](https://docs.astral.sh/uv/getting-started/installation/) or the [GitHub README](https://github.com/astral-sh/uv#installation)
- **Python 3.10+**: Use `uv python install 3.10` (or a more recent version)
- **MCP-compatible AI client**: Cline, Claude Desktop, Amazon Q Developer CLI, etc.

## Installation

ASH's MCP server is included by default and requires no separate installation. The MCP server will be automatically downloaded and run when configured with your AI client using `uvx`.

## Configuration

### Amazon Q Developer CLI

Add to `~/.aws/amazonq/mcp.json`:

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

### Claude Desktop

Add to your Claude Desktop configuration file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

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

### Cline (VS Code Extension)

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

## Basic Usage

### Starting a Security Scan

Once configured, you can interact with ASH through natural language:

```
"Can you scan this project directory for security vulnerabilities?"
"Start a security scan on this directory and show me the progress as it runs"
"Check this code for security issues with HIGH severity threshold"
```

The AI will use ASH's `scan_directory` tool to start a security scan with progress tracking and provide real-time updates.

### Monitoring Scan Progress

All scans now include progress tracking by default:

```
"Show me the progress of my security scan"
"What scanners are currently running?"
"How many security issues have been found so far?"
```

This uses the `scan_directory_with_progress` tool to start a background scan and monitor its progress.

### Analyzing Results

Ask for detailed analysis:

```
"Analyze the security scan results and prioritize the most critical issues"
"What are the top 5 security issues I should fix first?"
"Generate a summary report of the security findings"
```

## Advanced Features

### Custom Configuration

You can specify custom ASH configurations:

```
"Scan this directory with HIGH severity threshold using my custom ASH config"
"Run a security scan but ignore the test directories"
```

### Multiple Scans

Manage multiple concurrent scans:

```
"Start security scans on both the frontend and backend directories"
"Show me the status of all my running scans"
"Cancel the scan on the backend directory"
```

### Specific Scanner Types

Target specific types of security issues:

```
"Run only the secrets detection scanner on this repository"
"Scan for infrastructure security issues in my CloudFormation templates"
"Check for Python security vulnerabilities using Bandit"
```

## Available MCP Tools

The ASH MCP server provides these tools that AI assistants can use:

### Core Scanning Tools

- **`scan_directory`**: Start security scan with progress tracking (returns immediately with scan_id)
- **`get_scan_progress`**: Monitor running scan progress and see all active scanners
- **`get_scan_results`**: Retrieve completed scan results

### Management Tools

- **`list_active_scans`**: Show all active and recent scans
- **`cancel_scan`**: Stop a running scan
- **`check_installation`**: Verify ASH setup and dependencies

## Troubleshooting

### Common Issues

**UV not found:**
```bash
# Install UV if not already installed
curl -LsSf https://astral.sh/uv/install.sh | sh  # Linux/macOS
# or
irm https://astral.sh/uv/install.ps1 | iex       # Windows PowerShell

# Verify UV installation
uv --version
```

**MCP server fails to start:**
```bash
# Test the uvx command directly
uvx --from=git+https://github.com/awslabs/automated-security-helper@v3.0.0 ash mcp --help

# Check if Python 3.10+ is available
uv python list
uv python install 3.10  # Install if needed
```

**Permission errors:**
```bash
# Ensure the directory is readable
chmod -R +r /path/to/scan

# Check disk space
df -h
```

**Network connectivity issues:**
```bash
# Test repository access
git ls-remote https://github.com/awslabs/automated-security-helper.git

# Use offline mode if needed (after initial download)
export ASH_OFFLINE=true
```

### Debug Mode

Test the MCP server directly for detailed logging:

```bash
# Test MCP server startup
uvx --from=git+https://github.com/awslabs/automated-security-helper@v3.0.0 ash mcp --debug
```

This will show:
- UV tool installation status
- MCP dependency status
- Tool registration information
- Detailed error messages
- Resource cleanup operations

### Offline Mode

If you're in an environment without internet access:

```bash
# First, ensure ASH is cached by running once with internet access
uvx --from=git+https://github.com/awslabs/automated-security-helper@v3.0.0 ash --version

# Then set offline mode via environment variable
export ASH_OFFLINE=true

# Or configure in ASH config file (.ash/ash.yaml):
global_settings:
  offline: true
```

Note: The initial `uvx` download requires internet access, but subsequent runs can work offline.

## Best Practices

### 1. Use Progress Tracking for Large Projects

For projects with many files, use progress tracking:

```
"Start a security scan with progress tracking on this large codebase"
```

### 2. Configure Auto-Approval

In your MCP client, auto-approve safe operations:

```json
"autoApprove": [
  "get_scan_progress",
  "list_active_scans",
  "get_scan_results"
]
```

### 3. Set Appropriate Severity Thresholds

Configure severity thresholds based on your needs:

```
"Scan with CRITICAL severity threshold for production code"
"Use MEDIUM threshold for development branches"
```

### 4. Use Configuration Files

Create `.ash/ash.yaml` for consistent settings:

```yaml
project_name: my-project
global_settings:
  severity_threshold: MEDIUM
  ignore_paths:
    - path: 'tests/test_data'
      reason: 'Test data only'
scanners:
  bandit:
    enabled: true
  semgrep:
    enabled: true
```

## Integration Examples

### CI/CD Integration

Use MCP to integrate security scanning into your development workflow:

```
"Set up a security scan that runs on every pull request"
"Create a security report for this release candidate"
```

### Code Review Integration

Enhance code reviews with security insights:

```
"Review this code change for security implications"
"What security issues were introduced in this commit?"
```

### Security Monitoring

Monitor security posture over time:

```
"Compare security scan results from last week to now"
"Track security improvements in this project"
```

## Next Steps

- Explore the [MCP Streaming Guide](mcp-streaming-guide.md) for advanced streaming capabilities
- Learn about [ASH Configuration](../docs/configuration-guide.md) for customizing scans
- Check out [Running ASH in CI](running-ash-in-ci.md) for automation workflows

## Resources

- [Model Context Protocol Specification](https://modelcontextprotocol.io/)
- [ASH Configuration Reference](../docs/configuration-guide.md)
- [ASH CLI Reference](../docs/cli-reference.md)