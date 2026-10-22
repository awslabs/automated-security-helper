# Community Plugins

This section is dedicated to community-developed plugins for ASH. Community plugins extend ASH's functionality with additional scanners, reporters, converters, and event handlers developed by the community.

## Available Community Plugins

### Security Scanners

- **[Ferret Scan Plugin](ferret-scan-plugin.md)** - Integrates Ferret Scan for comprehensive sensitive data detection (credit cards, passports, SSNs, API keys, secrets, and more)
- **[GuardDog Plugin](guarddog-plugin.md)** - Malicious-package heuristics for PyPI, npm, Go, GitHub Actions, RubyGems and crates packages (pending licensing review)
- **[hadolint Plugin](hadolint-plugin.md)** - Lints Dockerfiles and Containerfiles with hadolint and its ShellCheck integration (pending licensing review)
- **[Snyk Code Plugin](snyk-plugin.md)** - Integrates Snyk Code for static application security testing (SAST) of source code vulnerabilities
- **[Trivy Plugin](trivy-plugin.md)** - Integrates Aquasec's Trivy for vulnerability, misconfiguration, secret, and license scanning

These three ship inside ASH. Each takes part in a scan only when that scan names its
plugin module in `ash_plugin_modules` or `--ash-plugin-modules`, as its page shows.
The MCP `list_scanners` tool reports them either way; listing one does not add it to
any scan.

## Contributing a Community Plugin

We encourage the community to develop and share plugins that extend ASH's capabilities.

To contribute a community plugin:

1. Develop your plugin following the [Plugin Development Guide](../../plugins/development-guide.md)
2. Host your plugin in a public repository
3. Open a pull request to add your plugin to this documentation
4. Include the following information in your PR:
   - Plugin name and description
   - Link to the repository
   - Installation instructions
   - Configuration options
   - Example usage

## Plugin Submission Guidelines

To ensure quality and security, community plugins should:

- Be open source with a compatible license
- Include comprehensive documentation
- Follow ASH's plugin development best practices
- Include tests and examples
- Be actively maintained

## Plugin Review Process

When you submit a PR to add your plugin to this documentation, the ASH team will:

1. Review the plugin code for security and quality
2. Test the plugin functionality
3. Provide feedback on any necessary changes
4. Merge the documentation PR once the plugin meets the guidelines

## Example Plugin Documentation Template

Replace `<my-plugin-package-name>` with the actual name of the plugin package you are creating.

````markdown
## Plugin Name

**Description**: Brief description of what the plugin does and its key features.
\*Description\*\*: Brief description of what the plugin does and its key features.

**Repository**: [Link to GitHub/GitLab/etc. repository](https://github.com/username/plugin-repo)

**Author**: Your Name or Organization

**License**: License type (e.g., Apache 2.0, MIT)

### Installation

```bash
# Installation instructions
pip install <my-plugin-package-name>
```
````

### Configuration

```yaml
# Example configuration in .ash.yaml
plugins:
  my-plugin:
    enabled: true
    options:
      option1: value1
      option2: value2
```

### Features

- Feature 1: Description
- Feature 2: Description

### Example Usage

```bash
# Example command line usage
ash --plugins my-plugin
```

> [!CAUTION] > **Community Plugin Security**: The community plugins listed above ship with ASH, in `automated_security_helper/plugin_modules`, and need no separate package. `ash scan` loads one only when its module is listed in `ash_plugin_modules` or passed with `--ash-plugin-modules`. Each runs an external tool: the container image includes trivy, GuardDog and hadolint, and you install the Snyk CLI and ferret-scan yourself, so check where each tool comes from. A plugin published outside ASH is a third-party package you install separately (for example with `pip install`), and ASH imports it into its own process, so verify its source and trustworthiness before installing it.
