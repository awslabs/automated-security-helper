# Alpha Plugins

This section covers the alpha plugins for ASH: the opt-in scanner packages (`ash_*_plugins`) that ship with ASH but are not built in. Alpha is a maturity label, not a trust level: ASH ships these scanners but does not yet promote them as supported. The `ash_aws_plugins` reporters load the same opt-in way but are not alpha plugins (see [AWS reporters](../../../plugins/aws.md)).

## Available Alpha Plugins

### Security Scanners

- **[Betterleaks Plugin](betterleaks-plugin.md)** (`ash_betterleaks_plugins`) - Secret detection with Betterleaks, the successor to gitleaks written by its author
- **[CredSweeper Plugin](credsweeper-plugin.md)** (`ash_credsweeper_plugins`) - Credential detection with Samsung's CredSweeper
- **[Dependency-Check Plugin](dependency_check-plugin.md)** (`ash_dependency_check_plugins`) - Dependency vulnerability analysis with OWASP Dependency-Check
- **[Ferret Scan Plugin](ferret-scan-plugin.md)** - Integrates Ferret Scan for comprehensive sensitive data detection (credit cards, passports, SSNs, API keys, secrets, and more)
- **[ggshield Plugin](ggshield-plugin.md)** (`ash_ggshield_plugins`) - Secret detection with GitGuardian's ggshield
- **[gosec Plugin](gosec-plugin.md)** (`ash_gosec_plugins`) - Go source security analysis with gosec
- **[GuardDog Plugin](guarddog-plugin.md)** (`ash_guarddog_plugins`) - Malicious-package heuristics for PyPI, npm, Go, GitHub Actions, RubyGems and crates packages (pending licensing review)
- **[hadolint Plugin](hadolint-plugin.md)** (`ash_hadolint_plugins`) - Lints Dockerfiles and Containerfiles with hadolint and its ShellCheck integration (pending licensing review)
- **[KICS Plugin](kics-plugin.md)** (`ash_kics_plugins`) - Infrastructure-as-code misconfiguration scanning with Checkmarx KICS
- **[Kingfisher Plugin](kingfisher-plugin.md)** (`ash_kingfisher_plugins`) - Secret detection with MongoDB's Kingfisher
- **[pip-audit Plugin](pip_audit-plugin.md)** (`ash_pip_audit_plugins`) - Known-vulnerability audit of the pinned dependencies in Python requirements files with PyPA's pip-audit
- **[Polaris Plugin](polaris-plugin.md)** (`ash_polaris_plugins`) - Kubernetes manifest best-practice and security checks with Fairwinds Polaris
- **[Secretlint Plugin](secretlint-plugin.md)** (`ash_secretlint_plugins`) - Secret detection with Secretlint
- **[Snyk Code Plugin](snyk-plugin.md)** - Integrates Snyk Code for static application security testing (SAST) of source code vulnerabilities
- **[Trivy Plugin](trivy-plugin.md)** - Integrates Aquasec's Trivy for vulnerability, misconfiguration, secret, and license scanning

These fifteen ship inside ASH. Each takes part in a scan only when that scan names its
plugin module in `ash_plugin_modules` or `--ash-plugin-modules`, as its page shows.
The MCP `list_scanners` tool reports them either way; listing one does not add it to
any scan.

## Contributing a third-party plugin

We encourage the community to develop and share plugins that extend ASH's capabilities.
A plugin you host yourself is a third-party plugin, not one of the alpha plugins that
ship with ASH.

To contribute a third-party plugin:

1. Develop your plugin following the [Plugin Development Guide](../../../plugins/write-a-scanner.md)
2. Host your plugin in a public repository
3. Open a pull request to add your plugin to this documentation
4. Include the following information in your PR:
   - Plugin name and description
   - Link to the repository
   - Installation instructions
   - Configuration options
   - Example usage

## Plugin Submission Guidelines

To ensure quality and security, a third-party plugin should:

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

**Repository**: [Link to GitHub/GitLab/etc. repository](https://github.com/username/plugin-repo)

**Author**: Your Name or Organization

**License**: License type (e.g., Apache 2.0, MIT)

### Installation

```bash
# Installation instructions
pip install <my-plugin-package-name>
```

### Configuration

```yaml
# Example configuration in your ASH config file (.ash.yaml in a new project)
scanners:
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
ash scan --ash-plugin-modules my_plugin
```
````

> [!CAUTION] > **Alpha Plugin Security**: The alpha plugins listed above ship with ASH, in `automated_security_helper/plugin_modules`, and need no separate package. `ash scan` loads one only when its module is listed in `ash_plugin_modules` or passed with `--ash-plugin-modules`. Each runs an external tool: the container image includes trivy, Betterleaks, GuardDog and hadolint, and you install the Snyk CLI and ferret-scan yourself, so check where each tool comes from. A plugin published outside ASH is a third-party package you install separately (for example with `pip install`), and ASH imports it into its own process, so verify its source and trustworthiness before installing it.
