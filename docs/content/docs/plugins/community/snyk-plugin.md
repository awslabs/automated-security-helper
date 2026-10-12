# ASH Snyk Code Plugin

This plugin integrates [Snyk Code](https://snyk.io/product/snyk-code/) CLI tool with the Automated Security Helper (ASH) to provide comprehensive static application security testing (SAST) for source code vulnerabilities.

## Overview

The Snyk Code plugin enables ASH to leverage Snyk's powerful static analysis capabilities for:

- **Static Application Security Testing (SAST)**: Identifies security vulnerabilities in source code
- **Real-time Analysis**: Fast scanning with minimal false positives
- **Multi-language Support**: Supports JavaScript, TypeScript, Python, Java, C#, PHP, Go, Ruby, Scala, Swift, and mor. See a full list [here](https://docs.snyk.io/supported-languages-package-managers-and-frameworks#supported-languages)
- **Developer-friendly Results**: Provides actionable remediation guidance with code examples

## Prerequisites

### Install Snyk CLI

The plugin requires Snyk CLI to be installed and available in your system PATH.

**npm (Recommended)**:
```bash
npm install -g snyk
```

**Homebrew (macOS)**:
```bash
brew install snyk/tap/snyk
```

**Manual Installation**:
```bash
# Download and install latest release
curl -Lo snyk https://github.com/snyk/cli/releases/latest/download/snyk-linux
chmod +x snyk
sudo mv snyk /usr/local/bin/
```

**Other platforms**: See [Snyk CLI Installation Guide](https://docs.snyk.io/cli-ide-and-ci-cd-integrations/snyk-cli/getting-started-with-the-snyk-cli)

### Authentication

Snyk Code requires authentication to access the scanning service:

**Option 1: Environment Variable**
```bash
export SNYK_TOKEN=your-snyk-token
```

**Option 2: CLI Authentication**
```bash
snyk auth
```

**Option 3: Configuration File**
The plugin will automatically check for credentials at `~/.config/configstore/snyk.json`

### Verify Installation

```bash
snyk --version
snyk code test --help
```

## Quick Start

### Basic Configuration

The Snyk Code plugin is not loaded by default. Its scanner sends the scanned source
to Snyk with your Snyk token, so only the operator running ASH can load it. A config
file inside the scanned tree, such as the repository's own `.ash/.ash.yaml`, cannot:
an `ash_plugin_modules` entry there that names the package, or a module inside it,
is ignored with a warning naming the entry.

Load it with `--ash-plugin-modules`:

```bash
uv run ash --ash-plugin-modules automated_security_helper.plugin_modules.ash_snyk_plugins
```

or with the `ASH_PLUGIN_MODULES` environment variable, which the commands on the
rest of this page assume is set:

```bash
export ASH_PLUGIN_MODULES=automated_security_helper.plugin_modules.ash_snyk_plugins
```

A repository's own config cannot load the package, or select the scanner through
another installed package that lists or imports it: the scanner is selected only
when `--ash-plugin-modules`, `ASH_PLUGIN_MODULES`, `--config-overrides` or a config
file outside the scanned tree loads this package or the package that lists it.

A config file outside the scanned tree, passed with `--config`, can list it too:

```yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_snyk_plugins
```

The scanner's settings, except `honor_tree_exclusions` (see
[Exclusion files in the scanned tree](#exclusion-files-in-the-scanned-tree)),
can stay in the repository's `.ash/.ash.yaml`:

```yaml
scanners:
  snyk-code:
    enabled: true
    severity_threshold: "MEDIUM"
```

### Run Snyk Code Scan

snyk-code does not scan a source directory that holds ASH's output directory (see
[ASH's output directory](#performance-considerations)), so these commands write ASH's
output outside the scanned tree with `--output-dir`. With the default
`.ash/ash_output`, snyk-code reports `ERROR` for the source and names the output
directory.

```bash
# Scan current directory
uv run ash --scanners snyk-code --output-dir ../ash_output

# Scan specific directory
uv run ash --scanners snyk-code --output-dir /path/to/ash_output /path/to/project
```

### Run Snyk Code Scan without an ASH configuration file

If you want to run Snyk code scan without saving a configuration file for ASH, use the following
command to enable the plugin

```bash
# Scan current directory only with snyk-code
uv run ash --scanners snyk-code --output-dir ../ash_output --config-overrides "ash_plugin_modules+=[\"automated_security_helper.plugin_modules.ash_snyk_plugins\"]"

# SCan current directory with all available scanners (including snyk-code)
uv run ash --output-dir ../ash_output --config-overrides "ash_plugin_modules+=[\"automated_security_helper.plugin_modules.ash_snyk_plugins\"]"

```

## Configuration Options

### Severity Filtering

Configure the minimum severity level for reported vulnerabilities:

```yaml
scanners:
  snyk-code:
    enabled: true
    severity_threshold: "HIGH"  # Options: LOW, MEDIUM, HIGH, CRITICAL
```

### Exclusion files in the scanned tree

`snyk code test` reads exclusions from files in the directory it tests, at any
depth, and leaves the files they name out of its analysis: the `exclude.code` and
`exclude.global` entries of a `.snyk` file, and the rules of a `.dcignore` file.
Its legacy implementation also reads any file whose name ends in `.snyk`,
`.dcignore` or `.gitignore`. It has no option that turns this off, and
`snyk code test` takes no `--policy-path`. So when the tree has such a file,
snyk-code does not run, and its error names the files. A `.snyk` file with only
open source `ignore` entries or other `exclude` sections does not count, and
neither does `.gitignore`, which ASH's own scan set honors too.

To accept a repository's exclusions, set `honor_tree_exclusions` with
`--config-overrides`:

```bash
uv run ash --scanners snyk-code --config-overrides 'scanners.snyk-code.options.honor_tree_exclusions=true'
```

or in a config file outside the scanned tree, passed with `--config`:

```yaml
scanners:
  snyk-code:
    enabled: true
    options:
      honor_tree_exclusions: true
```

A config file inside the scanned tree, such as the repository's own
`.ash/.ash.yaml`, or one an MCP client delivered, does not set it.

### Advanced Options

```yaml
scanners:
  snyk-code:
    enabled: true
    severity_threshold: "MEDIUM"
    options:
      # Additional scanner-specific options can be added here
```

## Usage Examples

### High Severity Issues Only

```yaml
scanners:
  snyk-code:
    enabled: true
    severity_threshold: "HIGH"
```

### All Severity Levels

```yaml
scanners:
  snyk-code:
    enabled: true
    severity_threshold: "LOW"
```

### Combined with Other Scanners

```bash
# Use Snyk Code alongside other ASH scanners
uv run ash --scanners snyk-code,bandit,semgrep --output-dir ../ash_output
```

### CI/CD Integration

```bash
# Run in container mode for CI/CD
uv run ash --mode container --scanners snyk-code --output-dir ../ash_output --ash-plugin-modules automated_security_helper.plugin_modules.ash_snyk_plugins
```

## Output Integration

Snyk Code results are integrated into ASH's unified reporting system:

- **SARIF Format**: Machine-readable results for CI/CD integration
- **HTML Reports**: Visual security dashboard with remediation guidance
- **JSON/CSV**: Structured data for analysis and tracking
- **Markdown**: Human-readable summaries for pull requests

## Performance Considerations

- **First Run**: May require initial authentication and setup
- **Network Dependency**: Requires internet connection for cloud-based analysis
- **Large Codebases**: Scanning time scales with codebase size
- **Rate Limits**: Snyk may apply rate limits based on your subscription tier
- **Offline Mode**: Snyk Code needs Snyk's service, so offline it does not run and is reported MISSING (see [Offline Mode](#offline-mode))
- **Links leaving the tree**: `snyk code test` uploads the files it reads and has no option that leaves out one path, so ASH does not run it on a directory holding a link, to a file or to a directory, whose target is outside that directory. snyk-code is then `ERROR`, and the error names the link. Remove the link, or exclude snyk-code for that scan.
- **ASH's output directory**: by default it is inside the scanned tree (`.ash/ash_output`), and it holds an earlier run's reports and logs and the converted files, which `snyk code test` would upload with the source. So snyk-code refuses a source directory that holds ASH's output directory: it is `ERROR`, `snyk code test` is not started, and the error names the output directory. To run snyk-code on the source, pass `--output-dir` with a directory outside the scanned tree. The `.gitignore` ASH writes in an output directory inside the tree is not relied on for this, since that snyk honors it is read from snyk's sources, not measured. The converted files are still scanned, as their own target.
- **Ignored paths**: for the same reason, snyk-code refuses a directory holding a file that `global_settings.ignore_paths` matches, since the file would be uploaded. The files are every file snyk would be given: the source directory for the source, and ASH's directory of converted files, wherever it is, for the converted files. Each is matched as ASH matches the location snyk reports for a finding in it, its path below the directory snyk tests, so snyk-code refuses a file exactly when ASH would drop its findings. A converted file is matched by its path below the directory of converted files, such as `archive/src__bundle__zip/vendor/m.js`; an ignore path naming a source archive or notebook exactly keeps it from being converted at all. `snyk code test` is then not started, snyk-code is `ERROR`, and the error names the first such file and the pattern that matched it, and gives the number of files and the patterns. Narrow `ignore_paths`, or exclude snyk-code with `--exclude-scanners snyk-code`. ASH's own default exclusions, such as `node_modules/`, are not ignore paths and do not stop it, and snyk-code has no exclusion option of its own. This applies to the operator's ignore paths: the ignore paths in a config an MCP client delivered drop their findings but do not stop the upload, so a client that does not want its files sent leaves snyk-code out with the `excluded_scanners` argument of `run_ash_workspace_scan`. `run_ash_scan` has no argument that selects scanners, so a client using it does not deliver the files it does not want sent.

## Troubleshooting

### Common Issues

**Snyk CLI not found**:
```bash
# Check if Snyk is in PATH
which snyk

# Install if missing
npm install -g snyk
```

**Authentication errors**:
```bash
# Check authentication status
snyk auth

# Set token via environment variable
export SNYK_TOKEN=your-token-here
```

**Network connectivity issues**:
```bash
# Test connectivity to Snyk services
snyk test --dry-run
```

**Empty directory warnings**:
The plugin will skip scanning if the target directory is empty or doesn't exist, logging an appropriate warning message.

**No supported files (exit code 3)**:
`snyk code test` exits 3 when the target holds no file Snyk Code supports, for example
a tree of only Terraform or YAML. snyk-code then evaluated nothing and is reported
SKIPPED, not ERROR, so it does not fail the completeness gate. Exit code 2 is a Snyk
failure and is reported ERROR.

### Debug Mode

Enable verbose logging to troubleshoot issues:

```bash
uv run ash --scanners snyk-code --output-dir ../ash_output --log-level DEBUG
```

### Offline Mode

Snyk Code analyzes code on Snyk's service, so it cannot run offline. In offline mode
snyk-code does not run and is reported MISSING, which fails the scan under the default
completeness gate (`fail_on_incomplete_scanners`, exit code 1). To scan offline
without it, leave it out. Both commands assume the plugin is enabled in your
configuration, as shown above:

```bash
# snyk-code is MISSING here, and the scan exits 1
uv run ash --offline --scanners snyk-code

# An offline scan that does not ask for snyk-code
uv run ash --offline --exclude-scanners snyk-code
```

## Integration Examples

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: ash-snyk-code
        name: ASH Snyk Code Security Scan
        entry: uv run ash --scanners snyk-code --mode precommit --output-dir ../ash_output --ash-plugin-modules automated_security_helper.plugin_modules.ash_snyk_plugins
        language: system
        pass_filenames: false
```

### GitHub Actions

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Snyk CLI
        run: npm install -g snyk
      - name: Run ASH with Snyk Code
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
          ASH_PLUGIN_MODULES: automated_security_helper.plugin_modules.ash_snyk_plugins
        # ASH's output outside the checkout, so snyk-code scans the source.
        run: |
          uv run ash --scanners snyk-code --output-format sarif --output-dir "${{ runner.temp }}/ash_output"
      - name: Upload SARIF results
        # Also when ASH exits non-zero on findings: without a status function
        # GitHub skips this step after any failed step.
        if: ${{ !cancelled() }}
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: ${{ runner.temp }}/ash_output/reports/ash.sarif
```

### GitLab CI

```yaml
# .gitlab-ci.yml
snyk-security-scan:
  stage: test
  image: node:18
  before_script:
    - npm install -g snyk
  script:
    # ASH's output outside the checkout, so snyk-code scans the source; the
    # report is copied back in afterwards, since artifacts come from the checkout.
    - uv run ash --scanners snyk-code --output-dir /tmp/ash_output
  after_script:
    - cp /tmp/ash_output/reports/ash.sarif ash.sarif
  variables:
    SNYK_TOKEN: $SNYK_TOKEN
    ASH_PLUGIN_MODULES: automated_security_helper.plugin_modules.ash_snyk_plugins
  artifacts:
    when: always
    paths:
      - ash.sarif
```

## Supported Languages

Snyk Code supports static analysis for:

- **JavaScript/TypeScript**: Node.js, React, Angular, Vue.js
- **Python**: Django, Flask, FastAPI
- **Java**: Spring, Maven, Gradle projects
- **C#/.NET**: .NET Framework, .NET Core
- **PHP**: Laravel, Symfony, WordPress
- **Go**: Standard library and popular frameworks
- **Ruby**: Rails, Sinatra
- **Scala**: Play Framework, Akka
- **Swift**: iOS/macOS applications

Full list of supported languages is available at the [Snyk Website](https://docs.snyk.io/supported-languages-package-managers-and-frameworks#supported-languages)

## Documentation

For comprehensive documentation and advanced configuration options, see:
- [ASH Community Plugins Documentation](index.md)
- [Snyk CLI Documentation](https://docs.snyk.io/cli-ide-and-ci-cd-integrations/snyk-cli)
- [Snyk Code Documentation](https://docs.snyk.io/products/snyk-code)

## Support

- **ASH Issues**: [GitHub Issues](https://github.com/awslabs/automated-security-helper/issues)
- **Snyk Issues**: [Snyk Support](https://support.snyk.io/)
- **Community**: [ASH Discussions](https://github.com/awslabs/automated-security-helper/discussions)