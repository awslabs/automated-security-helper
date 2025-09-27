# Installation Guide

ASH v3 offers multiple installation methods to fit your workflow. Choose the option that works best for your environment.

## Prerequisites

### For Local Mode
- Python 3.10 or later
- UV package manager (automatically installed with ASH)

ASH v3 uses UV's tool isolation system to automatically manage most scanner dependencies (Bandit, Checkov, Semgrep). For full scanner coverage in local mode, the following additional non-Python tools are recommended:
- Ruby with cfn-nag (`gem install cfn-nag`)
- Node.js/npm (for npm audit support)
- Grype and Syft (for SBOM and vulnerability scanning)

**Note**: Tools like Bandit, Checkov, and Semgrep are automatically installed via UV tool management when needed, so you don't need to install them manually. ASH uses sensible default version constraints with the flexibility to override through configuration.

### For Container Mode
- Any OCI-compatible container runtime (Docker, Podman, Finch, etc.)
- On Windows: WSL2 is typically required for running Linux containers

## Installation Options

### Standard Installation

#### 1. Using `uvx` (Recommended)

[`uvx`](https://github.com/astral-sh/uv) is a fast Python package installer and resolver that allows you to run packages directly without installing them permanently.

#### Linux/macOS
```bash
# Install uv if you don't have it
curl -sSf https://astral.sh/uv/install.sh | sh

# Create an alias for ASH
alias ash="uvx git+https://github.com/awslabs/automated-security-helper.git@v3.0.2"

# Use as normal
ash --help
```

#### Windows
```powershell
# Install uv if you don't have it
irm https://astral.sh/uv/install.ps1 | iex

# Create a function for ASH
function ash { uvx git+https://github.com/awslabs/automated-security-helper.git@v3.0.2 $args }

# Use as normal
ash --help
```

#### 2. Using `pipx`

[`pipx`](https://pypa.github.io/pipx/) installs packages in isolated environments and makes their entry points available globally.

```bash
# Works on Windows, macOS, and Linux
pipx install git+https://github.com/awslabs/automated-security-helper.git@v3.0.2

# Use as normal
ash --help
```

#### 3. Using `pip`

Standard Python package installation:

```bash
# Works on Windows, macOS, and Linux
pip install git+https://github.com/awslabs/automated-security-helper.git@v3.0.2

# Use as normal
ash --help
```

#### 4. Clone the Repository

For development or if you want to modify ASH:

```bash
# Works on Windows, macOS, and Linux
git clone https://github.com/awslabs/automated-security-helper.git --branch v3.0.2
cd automated-security-helper
pip install .

# Use as normal
ash --help
```

### MCP Support

ASH v3 includes built-in Model Context Protocol (MCP) support for AI integration. No additional installation steps are required - MCP dependencies are included as core dependencies.

After installing ASH with any of the methods above, you can immediately use MCP features:

```bash
# Start the MCP server
ash mcp

# Verify MCP support
ash mcp --help
```

## Windows-Specific Installation Notes

ASH v3 provides the same experience on Windows as on other platforms:

- For local mode, ASH runs natively on Windows with Python 3.10+
- For container mode, you'll need:
  1. Windows Subsystem for Linux (WSL2) installed
  2. A container runtime like Docker Desktop, Rancher Desktop, or Podman Desktop with WSL2 integration enabled

## Verifying Your Installation

After installation, verify that ASH is working correctly:

```bash
# Check the version
ash --version

# Run a simple scan in local mode
ash --mode local
```

## Upgrading ASH

To upgrade ASH to the latest version:

### If installed with `uvx`
```bash
# Your alias will use the latest version when specified
alias ash="uvx git+https://github.com/awslabs/automated-security-helper.git@v3.0.2"
```

### If installed with `pipx`
```bash
pipx upgrade automated-security-helper
```

### If installed with `pip`
```bash
pip install --upgrade git+https://github.com/awslabs/automated-security-helper.git@v3.0.2
```

### If installed from repository
```bash
cd automated-security-helper
git pull
pip install .
```

## Next Steps

After installation, you can:

1. [Configure ASH](configuration-guide.md) for your project
2. [Run your first scan](quick-start-guide.md)
3. Learn about [ASH's CLI options](cli-reference.md)