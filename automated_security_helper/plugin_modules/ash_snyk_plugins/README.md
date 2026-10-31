# ASH Snyk Code Plugin

This plugin integrates [Snyk Code](https://snyk.io/product/snyk-code/) CLI tool with the Automated Security Helper (ASH) to provide comprehensive static application security testing (SAST) for source code vulnerabilities.

## Overview

The Snyk Code plugin enables ASH to leverage Snyk's powerful static analysis capabilities for:

- **Static Application Security Testing (SAST)**: Identifies security vulnerabilities in source code
- **Real-time Analysis**: Fast scanning with minimal false positives
- **Multi-language Support**: Supports JavaScript, TypeScript, Python, Java, C#, PHP, Go, Ruby, Scala, Swift, and more. See the full list [here](https://docs.snyk.io/supported-languages-package-managers-and-frameworks#supported-languages)
- **Developer-friendly Results**: Provides actionable remediation guidance with code examples

**Important Note**: This plugin currently supports **Snyk Code (SAST) only**. Other Snyk CLI features such as vulnerability scanning for dependencies, container scanning, or infrastructure as code scanning are not implemented in this plugin.

## Prerequisites

### Install Snyk CLI

The plugin requires Snyk CLI to be installed and available in your system PATH.

**npm (Recommended)**:
<!-- doctest: illustrative reason="installs the Snyk CLI over the network" -->
```bash
npm install -g snyk
```

**Homebrew (macOS)**:
<!-- doctest: illustrative reason="installs the Snyk CLI over the network" -->
```bash
brew install snyk/tap/snyk
```

**Manual Installation**:
<!-- doctest: illustrative reason="installs the Snyk CLI over the network" -->
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
<!-- doctest: illustrative reason="sets a placeholder token for the Snyk CLI" -->
```bash
export SNYK_TOKEN=your-snyk-token
```

**Option 2: CLI Authentication**
<!-- doctest: illustrative reason="needs the Snyk CLI and a Snyk account" -->
```bash
snyk auth
```

**Option 3: Configuration File**
The plugin will automatically check for credentials at `~/.config/configstore/snyk.json`

### Verify Installation

<!-- doctest: illustrative reason="needs the Snyk CLI and a Snyk account" -->
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

<!-- doctest: illustrative reason="runs a scan that needs the Snyk CLI and a Snyk account" -->
```bash
uv run ash --ash-plugin-modules automated_security_helper.plugin_modules.ash_snyk_plugins
```

or with the `ASH_PLUGIN_MODULES` environment variable, which the commands on the
rest of this page assume is set:

<!-- doctest: illustrative reason="a shell outline that needs the Snyk CLI" -->
```bash
export ASH_PLUGIN_MODULES=automated_security_helper.plugin_modules.ash_snyk_plugins
```

A config file outside the scanned tree, passed with `--config`, can list it too:

```yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_snyk_plugins
```

The scanner's settings can stay in the repository's `.ash/.ash.yaml`:

```yaml
scanners:
  snyk-code:
    enabled: true
    options:
      severity_threshold: "MEDIUM"
```

### Run Snyk Code Scan

snyk-code does not scan a source directory that holds ASH's output directory (see
[What snyk-code refuses to run on](#what-snyk-code-refuses-to-run-on)), so these
commands write ASH's output outside the scanned tree with `--output-dir`. When the
output directory is inside the scanned tree, as the default `.ash/ash_output` is,
snyk-code reports `ERROR` for the source and names the output directory.

<!-- doctest: illustrative reason="runs a scan that needs the Snyk CLI and a Snyk account" -->
```bash
# Scan current directory
uv run ash --scanners snyk-code --output-dir ../ash_output

# Scan specific directory
uv run ash --scanners snyk-code --output-dir /path/to/ash_output --source-dir /path/to/project
```

### Run Snyk Code Scan without Configuration File

If you want to run Snyk code scan without saving a configuration file for ASH:

<!-- doctest: illustrative reason="runs a scan that needs the Snyk CLI and a Snyk account" -->
```bash
# Scan current directory only with snyk-code
uv run ash --scanners snyk-code --output-dir ../ash_output --config-overrides "ash_plugin_modules+=[\"automated_security_helper.plugin_modules.ash_snyk_plugins\"]"

# Scan current directory with all available scanners (including snyk-code)
uv run ash --output-dir ../ash_output --config-overrides "ash_plugin_modules+=[\"automated_security_helper.plugin_modules.ash_snyk_plugins\"]"
```

## Configuration Options

### Severity Filtering

Configure the minimum severity level for reported vulnerabilities:

```yaml
scanners:
  snyk-code:
    enabled: true
    options:
      severity_threshold: "HIGH"  # Options: LOW, MEDIUM, HIGH, CRITICAL, ALL
```

### Exclusion files in the scanned tree

`snyk code test` reads exclusions from files in the directory it tests, at any
depth, and leaves the files they name out of its analysis: the `exclude.code` and
`exclude.global` entries of a `.snyk` file, and the rules of a `.dcignore` file.
Its legacy implementation also reads any file whose name ends in `.snyk`,
`.dcignore` or `.gitignore`. It has no option that turns this off, and
`snyk code test` takes no `snyk test --policy-path`. So when the tree has such a file,
snyk-code does not run, and its error names the files. A `.snyk` file with only
open source `ignore` entries or other `exclude` sections does not count, and
neither does `.gitignore`, which ASH's own scan set honors too.

To accept a repository's exclusions, set `honor_tree_exclusions` with
`--config-overrides`:

<!-- doctest: illustrative reason="runs a scan that needs the Snyk CLI and a Snyk account" -->
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
    options:
      severity_threshold: "MEDIUM"
      # Additional scanner-specific options can be added here
```

## Usage Examples

### High Severity Issues Only

```yaml
scanners:
  snyk-code:
    enabled: true
    options:
      severity_threshold: "HIGH"
```

### All Severity Levels

```yaml
scanners:
  snyk-code:
    enabled: true
    options:
      severity_threshold: "ALL"
```

### Combined with Other Scanners

<!-- doctest: illustrative reason="runs a scan that needs the Snyk CLI and a Snyk account" -->
```bash
# Use Snyk Code alongside other ASH scanners
uv run ash --scanners snyk-code,bandit,semgrep --output-dir ../ash_output

# Use with community plugins
uv run ash --scanners snyk-code,trivy-repo --output-dir ../ash_output --config .ash/.ash_community_plugins.yaml --ash-plugin-modules automated_security_helper.plugin_modules.ash_snyk_plugins
```

### CI/CD Integration

<!-- doctest: illustrative reason="needs a container runtime" -->
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

`snyk code test` exits 0 when it finds nothing and 1 when it finds something. ASH treats both as a completed scan and reports the findings from the SARIF file Snyk writes, each at the level Snyk gave it (`error` as CRITICAL, `warning` as MEDIUM, `note` as LOW) and a finding Snyk marks ignored as suppressed. Whether the scan then fails is decided by ASH's severity threshold, as for every scanner. A run that exits 1 but whose SARIF file holds no results, and any other exit code except 3, such as 2 (a failed run), is reported as a snyk-code scanner error. Exit code 3, no supported files found, evaluated nothing and is reported SKIPPED (see Troubleshooting).

## What snyk-code refuses to run on

`snyk code test` uploads the files it reads and has no option that leaves out one path. So snyk-code does not run on a directory that holds any of the following: the scanner is `ERROR`, `snyk code test` is not started, and the error names what it found. The directories are the source directory and ASH's directory of converted files.

- ASH's output directory. By default it is inside the scanned tree (`.ash/ash_output`) and holds an earlier run's reports and logs, so snyk-code refuses the source directory. Pass `--output-dir` with a directory outside the scanned tree to run it. The `.gitignore` ASH writes in an output directory inside the tree is not relied on, since that snyk honors it is read from snyk's sources and not measured. The converted files are still scanned, as their own target.
- A link whose target is outside the directory, to a file or to a directory (`creds -> ~/.aws`). Remove the link, or exclude snyk-code for that scan. The check reads no ignore file, so a link in a directory a `.gitignore` excludes, such as the interpreter link in a virtual environment, counts.
- A file that `global_settings.ignore_paths` matches. Each file is matched as ASH matches the location snyk reports for a finding in it, so snyk-code refuses a file exactly when ASH would drop its findings. The check reads no ignore file either, so an ignore path that matches only files a `.gitignore` excludes still refuses. Narrow `ignore_paths`, or exclude snyk-code with `--exclude-scanners snyk-code`. ASH's own default exclusions for bandit and checkov, such as `node_modules/`, are not ignore paths and do not stop snyk-code. This applies to the operator's ignore paths: the ignore paths in a config an MCP client delivered drop their findings but do not stop the upload, so a client that does not want its files sent leaves snyk-code out with the `excluded_scanners` argument of `run_ash_workspace_scan`.

## What ASH sends to Snyk

`snyk code test` uploads the files of the directory it tests, and it has no option that leaves a path out. For the source directory, once it holds none of what snyk-code refuses above, ASH therefore runs it on a copy of the scan set. The copy is made in a new directory under the system temporary directory (`TMPDIR`), outside both the scanned directory and the output directory, and is removed when the scan of that directory ends; snyk-code reports an error rather than run when `TMPDIR` is inside either of them. A run that is killed (with SIGKILL, or SIGTERM) leaves its copy behind. On Linux and macOS, each later snyk-code run removes such copies: the user's own `ash-snyk-code-*` directories that no running scan holds and that were last modified longer ago than the scan timeout (`scanners.snyk-code.options.scan_timeout`, 1800 seconds by default, or an hour when it is null). On Windows, remove them yourself. Under the scanner sandbox, the Snyk CLI is given read access to that directory for its run. The copy leaves out:

- files under `global_settings.ignore_paths`, matched the way ASH matches findings against ignore paths;
- files that a `.gitignore` or `.ignore` file excludes from the scan set, and ASH's own output directory, apart from the files git tracks there;
- symlinks, files with more than one hard link, paths outside the scanned directory, and files ASH cannot read, which ASH counts in a warning.

If ASH cannot write the copy, because the disk is full for example, snyk-code reports a scanner error instead of testing part of the tree. It reports one too when it leaves out every file it would have sent, so a tree of links is not reported as a clean scan. When the scan set holds no file to send, nothing is sent, snyk-code does not run, and the log says so. Files the converters wrote are tested where ASH wrote them. Making the copy takes time and disk space in proportion to the scan set. As for every scanner, a finding in a file under an ignore path is also left out of the reports.

Ignores managed in the Snyk app belong to a Snyk project, and Snyk may rely on the tested directory's git remote to find that project. The copy ASH sends carries no `.git` directory, so Snyk may not match it to that project, and those ignores may not apply: a finding ignored in the Snyk app can be reported again. To keep a finding out of ASH's results, suppress it in ASH's configuration.

## Performance Considerations

- **First Run**: May require initial authentication and setup
- **Network Dependency**: Requires internet connection for cloud-based analysis
- **Large Codebases**: Scanning time scales with codebase size
- **Rate Limits**: Snyk may apply rate limits based on your subscription tier
- **Offline Mode**: Snyk Code needs Snyk's service, so offline it does not run and is reported MISSING (see [Offline Mode](#offline-mode))

## Troubleshooting

### Common Issues

**Snyk CLI not found**:
<!-- doctest: illustrative reason="installs the Snyk CLI over the network" -->
```bash
# Check if Snyk is in PATH
which snyk

# Install if missing
npm install -g snyk
```

**Authentication errors**:
<!-- doctest: illustrative reason="needs the Snyk CLI and a Snyk account" -->
```bash
# Check authentication status
snyk auth

# Set token via environment variable
export SNYK_TOKEN=your-token-here
```

**Network connectivity issues**:
<!-- doctest: illustrative reason="needs the Snyk CLI and a Snyk account" -->
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

<!-- doctest: illustrative reason="runs a scan that needs the Snyk CLI and a Snyk account" -->
```bash
uv run ash --scanners snyk-code --output-dir ../ash_output --log-level DEBUG
```

### Offline Mode

Snyk Code analyzes code on Snyk's service, so it cannot run offline. In offline mode
snyk-code does not run and is reported MISSING, which fails the scan under the default
completeness gate (`fail_on_incomplete_scanners`, exit code 1). To scan offline
without it, leave it out. Both commands assume the plugin is enabled in your
configuration, as shown above:

<!-- doctest: illustrative reason="runs a scan that needs the Snyk CLI and a Snyk account" -->
```bash
# snyk-code is MISSING here, and the scan exits 1
uv run ash --offline --scanners snyk-code

# An offline scan that does not ask for snyk-code
uv run ash --offline --exclude-scanners snyk-code
```

## Integration Examples

### Pre-commit Hook

<!-- doctest: config kind=pre-commit -->
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

<!-- doctest: config kind=github-actions runner=none reason="a workflow for the reader's own repository, which needs a Snyk token" -->
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

<!-- doctest: config kind=gitlab-ci runner=none reason="a pipeline for the reader's own project, which needs a Snyk token" -->
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

Full list of supported languages is available at the [Snyk Documentation](https://docs.snyk.io/supported-languages-package-managers-and-frameworks#supported-languages).

## Documentation

For comprehensive documentation and advanced configuration options, see:
- [ASH Community Plugins Documentation](../../../docs/content/docs/plugins/community/snyk-plugin.md)
- [Snyk CLI Documentation](https://docs.snyk.io/cli-ide-and-ci-cd-integrations/snyk-cli)
- [Snyk Code Documentation](https://docs.snyk.io/products/snyk-code)

## Support

- **ASH Issues**: [GitHub Issues](https://github.com/awslabs/automated-security-helper/issues)
- **Snyk Issues**: [Snyk Support](https://support.snyk.io/)
- **Community**: [ASH Discussions](https://github.com/awslabs/automated-security-helper/discussions)
