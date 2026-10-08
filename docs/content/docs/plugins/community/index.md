# Community Plugins

This section is dedicated to community-developed plugins for ASH. Community plugins extend ASH's functionality with additional scanners, reporters, converters, and event handlers developed by the community.

## Available Community Plugins

### Security Scanners

- **[actionlint Plugin](actionlint-plugin.md)** (`ash_actionlint_plugins`) - Lints GitHub Actions workflows with actionlint: script injection, expression types, hard-coded credentials
- **[CloudFormation Plugin](cfn-plugin.md)** (`ash_cfn_plugins`) - cfn-lint template validation and cfn-guard policy checks against the AWS Guard Rules Registry
- **[Ferret Scan Plugin](ferret-scan-plugin.md)** - Integrates Ferret Scan for comprehensive sensitive data detection (credit cards, passports, SSNs, API keys, secrets, and more)
- **[Gitleaks Plugin](gitleaks-plugin.md)** (`ash_gitleaks_plugins`) - Finds committed credentials with gitleaks, beside detect-secrets
- **[Snyk Code Plugin](snyk-plugin.md)** - Integrates Snyk Code for static application security testing (SAST) of source code vulnerabilities
- **[Trivy Plugin](trivy-plugin.md)** - Integrates Aquasec's Trivy for vulnerability, misconfiguration, secret, and license scanning (`trivy-repo`), plus the [Trivy filesystem scanner](trivy-fs-plugin.md) (`trivy`, off by default)
- **[zizmor Plugin](zizmor-plugin.md)** (`ash_zizmor_plugins`) - Static analysis of GitHub Actions workflows and composite actions

Each ships with ASH. List a plugin's module in `ash_plugin_modules` (or pass it with `--ash-plugin-modules`) to load it; a scan that does not list a module is unchanged by it.

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

> [!CAUTION] > **Community Plugin Security**: Community plugins are third-party packages that you install separately (e.g., via `pip install`). Always verify the source and trustworthiness of these packages before installation. ASH's built-in plugins are included directly in the ASH repository under `automated_security_helper/plugin_modules` and don't require separate package installation.
