# ASH Built-in Plugins

This directory contains all the built-in plugins that ship with the Automated Security Helper (ASH). These plugins provide core functionality for security scanning, file conversion, result reporting, and event handling.

## Plugin Categories

### 🔍 **Scanners** (`scanners/`)
Security scanners that analyze code and infrastructure for vulnerabilities:

- **Bandit** - Python security linter
- **CDK-Nag** - AWS CDK security checker
- **CFN-Nag** - CloudFormation template security scanner
- **Checkov** - Infrastructure-as-Code security scanner
- **Detect-Secrets** - Secret detection scanner
- **Grype** - Container vulnerability scanner
- **NPM Audit** - Node.js dependency vulnerability scanner
- **OpenGrep** - Code pattern matching scanner
- **Semgrep** - Static analysis scanner
- **Syft** - Software Bill of Materials (SBOM) generator

### 📊 **Reporters** (`reporters/`)
Output formatters that generate scan results in various formats:

- **CSV Reporter** - Comma-separated values format
- **CycloneDX Reporter** - Software Bill of Materials format
- **Flat JSON Reporter** - Simplified JSON format
- **GitLab SAST Reporter** - GitLab Security Dashboard format
- **HTML Reporter** - Interactive web report
- **JUnit XML Reporter** - Test result format
- **Markdown Reporter** - Human-readable markdown format
- **OCSF Reporter** - Open Cybersecurity Schema Framework format
- **SARIF Reporter** - Static Analysis Results Interchange Format
- **SPDX Reporter** - Software Package Data Exchange format
- **Text Reporter** - Plain text summary
- **YAML Reporter** - YAML format

### 🔄 **Converters** (`converters/`)
File processors that prepare source code for scanning:

- **Archive Converter** - Extracts compressed archives (zip, tar, etc.)
- **Jupyter Converter** - Processes Jupyter notebooks

### 📡 **Event Handlers** (`event_handlers/`)
Event handlers that respond to scan lifecycle events:

- **Scan Completion Logger** - Logs remaining scanner information during scan execution

## Usage

These plugins are automatically loaded and available when ASH starts. They can be:

- **Enabled/Disabled** via configuration files
- **Configured** with custom options and thresholds
- **Extended** by creating custom plugins following the same patterns

## Documentation

For detailed information about each plugin, including configuration options, dependencies, and usage examples, see the [Built-in Plugins Documentation](../../../docs/content/docs/plugins/builtin/).

## Plugin Development

These built-in plugins serve as reference implementations for creating custom plugins. Each plugin follows ASH's plugin architecture and demonstrates best practices for:

- Plugin registration and discovery
- Configuration management
- Error handling and logging
- Result formatting and output
- Integration with the ASH execution engine

For plugin development guidance, see the [Plugin Development Guide](../../../docs/content/docs/plugins/development-guide.md).
