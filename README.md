<a id="overview"></a>

# Automated Security Helper (ASH)

Open-source orchestration for code, infrastructure, secret, and dependency scanners.

[![Unified CI](https://github.com/awslabs/automated-security-helper/actions/workflows/ash-unified-ci.yml/badge.svg)](https://github.com/awslabs/automated-security-helper/actions/workflows/ash-unified-ci.yml)
[![Install methods](https://github.com/awslabs/automated-security-helper/actions/workflows/ash-install-methods.yml/badge.svg)](https://github.com/awslabs/automated-security-helper/actions/workflows/ash-install-methods.yml)

[Quick start](#quick-start) · [Reports](#reports) · [Integrations](#integrations) · [Configuration](#configuration) · [Documentation](https://awslabs.github.io/automated-security-helper/)

<a id="installation-options"></a>
<a id="basic-usage"></a>
<a id="prerequisites"></a>

<a id="your-first-scan"></a>

## Quick start

## Built-In Scanners

ASH v3 integrates multiple open-source security tools as scanners. Tools like Bandit, Checkov, and Semgrep are managed via UV's tool isolation system, which automatically installs and runs them in isolated environments without affecting your project dependencies:

| Scanner                                                       | Type      | Languages/Frameworks                                                                         | Installation (Local Mode)                                               |
|---------------------------------------------------------------|-----------|----------------------------------------------------------------------------------------------|-------------------------------------------------------------------------|
| [Bandit](https://github.com/PyCQA/bandit)                     | SAST      | Python                                                                                       | Managed via UV tool isolation (auto-installed: `bandit>=1.7.0,<2.0.0`)        |
| [Semgrep](https://github.com/semgrep/semgrep)                 | SAST      | Python, JavaScript, TypeScript, Java, Go, C#, Ruby, PHP, Kotlin, Swift, Bash, and more       | Managed via UV tool isolation (auto-installed: `semgrep>=1.125.0,<2.0.0`)     |
| [Opengrep](https://github.com/opengrep/opengrep)               | SAST      | Same rule surface as Semgrep (open-source fork)                                               | Managed via UV tool isolation                                           |
| [detect-secrets](https://github.com/Yelp/detect-secrets)      | Secrets   | All text files                                                                               | Included with ASH                                                       |
| [Checkov](https://github.com/bridgecrewio/checkov)            | IaC, SAST | Terraform, CloudFormation, Kubernetes, Dockerfile, ARM Templates, Serverless, Helm, and more | Managed via UV tool isolation (auto-installed: `checkov>=3.2.0,<4.0.0`) |
| [cfn_nag](https://github.com/stelligent/cfn_nag)              | IaC       | CloudFormation                                                                               | `gem install cfn-nag`                                                   |
| [cdk-nag](https://github.com/cdklabs/cdk-nag)                 | IaC       | CloudFormation                                                                               | ASH's `cdk` extra, and Node.js                                          |
| [npm-audit](https://docs.npmjs.com/cli/v8/commands/npm-audit) | SCA       | JavaScript/Node.js                                                                           | Install Node.js/npm                                                     |
| [Grype](https://github.com/anchore/grype)                     | SCA       | Python, JavaScript/Node.js, Java, Go, Ruby, and more                                         | See [Grype Installation](https://github.com/anchore/grype#installation) |
| [Syft](https://github.com/anchore/syft)                       | SBOM      | Python, JavaScript/Node.js, Java, Go, Ruby, and more                                         | See [Syft Installation](https://github.com/anchore/syft#installation)   |
| [gitleaks](https://github.com/gitleaks/gitleaks)              | Secrets   | All text files                                                                               | `ash dependencies install` (pinned release binary)                      |
| [cfn-lint](https://github.com/aws-cloudformation/cfn-lint)    | IaC       | CloudFormation                                                                               | Managed via UV tool isolation (auto-installed: `cfn-lint[sarif]>=1.43.3,<2.0.0`) |
| [cfn-guard](https://github.com/aws-cloudformation/cloudformation-guard) | IaC | CloudFormation (AWS Guard Rules Registry rules)                                        | `ash dependencies install` (pinned binary and rules)                    |
| [Trivy](https://github.com/aquasecurity/trivy) (`trivy fs`)   | SCA       | Python, JavaScript/Node.js, Java, Go, Ruby, Rust, PHP, .NET, and more                        | `ash dependencies install` (pinned release binary)                      |
| [actionlint](https://github.com/rhysd/actionlint)             | IaC       | GitHub Actions workflows                                                                     | `ash dependencies install` (pinned release binary)                      |
| [zizmor](https://github.com/zizmorcore/zizmor)                | SAST      | GitHub Actions workflows and composite actions                                               | Managed via UV tool isolation (auto-installed: `zizmor>=1.29.0,<2.0.0`) |

## Community Scanner Plugins

These ship with ASH and run when their plugin module is listed in `ash_plugin_modules` (or passed with `--ash-plugin-modules`); a scan that does not list a module is unchanged by it. The container image includes every tool below. See [Community Plugins](docs/content/docs/plugins/community/index.md).

| Scanner(s) | Module | Type | Targets |
|------------|--------|------|---------|
| [actionlint](https://github.com/rhysd/actionlint) | `ash_actionlint_plugins` | IaC | GitHub Actions workflows |
| [cfn-lint](https://github.com/aws-cloudformation/cfn-lint), [cfn-guard](https://github.com/aws-cloudformation/cloudformation-guard) | `ash_cfn_plugins` | IaC | CloudFormation |
| [Ferret Scan](https://github.com/awslabs/ferret-scan) | `ash_ferret_plugins` | Sensitive data | All text files |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | `ash_gitleaks_plugins` | Secrets | All text files |
| [Snyk Code](https://snyk.io/product/snyk-code/) | `ash_snyk_plugins` | SAST | Source code |
| [Trivy](https://github.com/aquasecurity/trivy) (`trivy-repo`, and `trivy`, off by default) | `ash_trivy_plugins` | SCA | Dependency manifests and lockfiles |
| [zizmor](https://github.com/zizmorcore/zizmor) | `ash_zizmor_plugins` | SAST | GitHub Actions workflows and composite actions |

## Prerequisites

### Runtime Requirements

| Mode      | Requirements                                                                                                                                                         | Notes                                                    |
|-----------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------|
| Local     | Python 3.10+, UV package manager                                                                                                                                     | Some scanners require additional tools (see table above) |
| Container | Any OCI-compatible container runtime ([Finch](https://github.com/runfinch/finch), [Docker](https://docs.docker.com/get-docker/), [Podman](https://podman.io/), etc.) | On Windows: WSL2 is typically required                   |
| Precommit | Python 3.10+, UV package manager                                                                                                                                     | Subset of scanners, optimized for speed                  |

## Installation Options

### Quick Install (Recommended)

<!-- doctest: illustrative reason="installs ASH from GitHub over the network and starts a container scan" -->
```bash
pipx install git+https://github.com/awslabs/automated-security-helper.git@v3.7.0

# Run from the project you want to scan
ash --mode container
```

The first container run builds the image and prepares scanner dependencies.
Open `.ash/ash_output/reports/ash.html` or run `ash inspect findings`.

### Execution modes

| Mode | Command | Requirements |
| --- | --- | --- |
| Container | `ash --mode container` | OCI-compatible runtime |
| Local | `ash --mode local` | Local scanner dependencies |
| Pre-commit | `ash --mode precommit` | Python-based scanners with simplified output |

Local and pre-commit workflows use [uv](https://docs.astral.sh/uv/getting-started/installation/)
for managed tool installation. The [installation guide](docs/content/how-to/install.md)
covers platform prerequisites and dependency setup.

<details>
<summary>Other installation methods</summary>

Run with uv:

<!-- doctest: illustrative reason="runs ASH from GitHub over the network" -->
```bash
uvx --from git+https://github.com/awslabs/automated-security-helper.git@v3.7.0 ash --help
uvx --from git+https://github.com/awslabs/automated-security-helper.git@v3.7.0 ash --mode container
```

Install in a Python environment:

<!-- doctest: illustrative reason="installs ASH from GitHub over the network" -->
```bash
pip install git+https://github.com/awslabs/automated-security-helper.git@v3.7.0
```

Install with Homebrew:

<!-- doctest: illustrative reason="installs ASH with Homebrew over the network" -->
```bash
brew tap awslabs/automated-security-helper https://github.com/awslabs/automated-security-helper.git
brew trust awslabs/automated-security-helper
brew install ash
```

Homebrew refuses to load a formula by its short name, as in `brew install ash`, from a tap you have not trusted, so the second line trusts this one; on a Homebrew without `brew trust`, skip that line. Naming the formula in full needs no `brew trust`: `brew install awslabs/automated-security-helper/ash` trusts that one formula as it installs it. The formula builds the tagged release on Homebrew's Python 3.12, with ASH's `cdk` extra, and installs the dependency versions locked in that release's `uv.lock`. It downloads them from PyPI during the install, so the install needs network access, and building with `HOMEBREW_FORMULA_BUILD_NETWORK=deny` is not supported. The formula also installs Node.js, which cdk-nag and npm-audit run on. grype, syft, opengrep and cfn-nag are separate programs that the formula does not install: `ash dependencies install` adds grype, syft and opengrep, and cfn-nag needs Ruby (`gem install cfn-nag`). Until they are installed, a default scan reports them MISSING and exits 1. In container mode, a Homebrew install builds its image from the commit the formula built, or, when Homebrew built it from a source tarball with no git metadata, from the release tag of its version, with a warning that this is a guess.

#### Using `pipx`

<!-- doctest: illustrative reason="clones this repository and installs it over the network" -->
```bash
git clone --branch v3.7.0 https://github.com/awslabs/automated-security-helper.git
cd automated-security-helper
pip install .
```

Pin `@v3.7.0` for a reproducible install. The floating `@v3` tag follows
stable v3 releases. See the [installation guide](docs/content/how-to/install.md)
for Windows and offline environments.

</details>

<a id="review-the-results"></a>

## Reports

- Check the outcome and scanner coverage.
- Review findings by severity.
- Inspect rule IDs, locations, and evidence.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/readme/report-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="docs/assets/readme/report-light.png">
  <img alt="ASH offline report with the scan outcome, finding counts, and explicit coverage notices." src="docs/assets/readme/report-light.png" width="1200">
</picture>

Example scan results.

Offline HTML reports include search, filters, finding details, and printing.

<!-- doctest: illustrative reason="opens an interactive explorer on the results of an earlier scan" -->
```bash
# Run a scan in local mode (the scanner tools installed on this machine)
ash --mode local

# Run a scan in container mode (all tools)
ash --mode container

# Run a scan in precommit mode (fast subset of tools)
ash --mode precommit
```

<details>
<summary>Terminal findings explorer</summary>

![ASH terminal explorer with severity-first findings, scanner and suppression filters, selected finding context, and keyboard shortcuts.](docs/assets/readme/findings-terminal.png)

Use the footer shortcuts to search, filter, inspect, and suppress.

</details>

=== ASH Exit Codes ===
  0: success
  1: scan errors / scanner failures
  2: actionable findings at or above threshold (fail_on_findings is true; default true)
  3: invalid config or refused input
  4: workspace definition or policy error
  5: usage error
ERROR (2) Exiting due to 122 actionable findings found in ASH scan
```

### Output files

Default output lives in `.ash/ash_output/`. Enabled reporters write into `reports/`.

| Artifact | Use it for |
| --- | --- |
| `reports/ash.html` | Offline review, filtering, and printing |
| `reports/ash.summary.md` | Pull request comments and Actions summaries |
| `reports/ash.summary.txt` | A readable summary in a file or terminal |
| `reports/ash.sarif` | IDE annotations and SARIF consumers |
| `reports/ash.flat.json` | Scripts and dashboards |
| `reports/ash.csv` | Spreadsheet analysis |
| `ash_aggregated_results.json` | The complete scan record and validation data |

ASH also supports JUnit XML, CycloneDX, SPDX, OCSF, GitLab, YAML, and AWS
reporting destinations. See the [complete format guide](docs/content/reference/output-files.md).

Exit status: `0` means no actionable findings, or findings are allowed by
policy; `1` means execution needs attention; `2` means actionable findings with
failure-on-findings enabled. A scan with incomplete coverage needs follow-up.
Filters change the view; configured thresholds determine the scan gate.

<a id="bring-ash-into-your-workflow"></a>

## Integrations

| Your workflow | Next step |
| --- | --- |
| CI and pull requests | [Run ASH in CI](docs/content/getting-started/ci.md) |
| Before a commit | [Set up pre-commit](docs/content/how-to/pre-commit.md) |
| AI coding assistant | [Install an editor or agent integration](ash-agent-plugins/README.md) |
| MCP client | [Connect a client](docs/content/getting-started/agents.md) |
| Multiple projects | [Scan a workspace over MCP](docs/content/how-to/scale-large-repos.md) |
| AWS reporting | [Choose an AWS destination](docs/content/plugins/aws.md) |
| A custom scanner or report | [Build an ASH plugin](docs/content/plugins/index.md) |

See [integration options](docs/content/integrations.md).

<a id="ai-integration-with-mcp"></a>
<a id="installing-ash-into-an-ai-coding-agent"></a>
<a id="client-configuration"></a>

### Connect an AI assistant

After installing ASH, add this server to your MCP client's configuration:

```json
{
  "mcpServers": {
    "ash": {
      "command": "ash",
      "args": ["mcp"]
    }
  }
}
```

Stop polling on `completed`, `incomplete`, `failed`, or `cancelled`.
Check scanner coverage before reviewing findings.

For agent instructions, install the `ash-mcp` skill:

<!-- doctest: illustrative reason="installs an agent skill over the network" -->
```bash
npx skills add awslabs/automated-security-helper
```

The skill supplies workflow guidance. Configure the MCP server as above, or use
a [platform integration](ash-agent-plugins/README.md) that includes server wiring.
The [MCP server guide](docs/content/how-to/mcp-server.md) covers client-specific
setup. The [HTTP transport guide](docs/content/how-to/mcp-server.md) covers
remote source delivery, session handling, and deployment configuration.

<details>
<summary>MCP tools</summary>

| Tool | Action |
| --- | --- |
| `get_scan_progress` | Read scan status and partial results |
| `get_scan_results` | Read results after a completed or incomplete scan |
| `list_active_scans` | List active and recent scans |
| `cancel_scan` | Stop a running scan |
| `check_installation` | Check ASH and scanner dependencies |
| `run_ash_scan` | Run a synchronous scan |
| `get_scan_summary` | Read counts, severity, and scan status |
| `get_scan_result_paths` | Locate generated report files |
| `explain_finding` | Look up one finding by ID |
| `get_config` | Read the resolved configuration |
| `diff_scan_results` | Compare two aggregated result files |
| `suggest_suppression` | Draft a suppression for review |
| `resolve_ash_workspace` | Preview a workspace scan plan |
| `run_ash_workspace_scan` | Scan workspace projects with their configurations |
| `list_scanners` | List registered scanners and metadata |
| `validate_config` | Check a configuration against the schema |
| `list_profiles` | List registered configuration profiles |
| `select_profile` | Apply a profile to the session |
| `set_source_git` | Clone a repository as the scan target |
| `set_source_zip_chunk` | Upload a source archive chunk, up to 1 MiB |
| `set_source_zip_finalize` | Verify and extract the uploaded archive |
| `clear_source` | Delete the delivered source tree |

See the [tool reference](docs/content/reference/mcp-tools.md) for complete
inputs and outputs. Source-delivery tools use transport sessions on a network
connection; a local stdio client can name local paths directly.

</details>

### Add a pre-commit check

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/awslabs/automated-security-helper
    rev: v3.7.0
    hooks:
      - id: ash-simple-scan
```

Run `pre-commit run ash-simple-scan --all-files` to check the project.

<a id="configuration"></a>

<a id="make-it-fit-your-project"></a>

## Configuration

Create `.ashrc.yaml` at the project root to name the project, set the severity
gate, and choose scanner and reporter options (existing configs under the older
`.ash/.ash.yaml` name keep loading). The schema provides editor validation.

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/main/automated_security_helper/schemas/AshConfig.json
project_name: my-project
global_settings:
  severity_threshold: MEDIUM
scanners:
  bandit:
    enabled: true
    options:
      confidence_level: high
reporters:
  markdown:
    enabled: true
    options:
      include_detailed_findings: true
```

Use the [configuration guide](docs/content/how-to/configure.md) for
settings and overrides, the [suppression guide](docs/content/how-to/suppress-findings.md)
for an accepted finding with a recorded reason, and [plugin development](docs/content/plugins/index.md)
for new capabilities.

Add this to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/awslabs/automated-security-helper
    rev: v3.7.0
    hooks:
      - id: ash
```

Run with:

```bash
pre-commit run ash --all-files
```

The `ash` hook runs precommit mode (bandit, detect-secrets, checkov, cdk-nag and npm-audit) and installs the `cdk` extra into its environment. It needs pre-commit running on Python 3.10 to 3.14, and Node.js and npm on `PATH` for cdk-nag and npm-audit. `ash-simple-scan` is the same hook under its earlier id, and `ash-full-scan` scans in the ASH container image instead. See [Using ASH with pre-commit](docs/content/tutorials/using-ash-with-pre-commit.md) for running without Node.js and for the container hook.

## Output Files

ASH v3 produces several output files in the `.ash/ash_output/` directory:

- `ash_aggregated_results.json`: Complete machine-readable results including validation checkpoints
- `reports/ash.flat.json`: Flattened JSON array of findings for scripts and dashboards
- `reports/ash.sarif`: SARIF 2.1.0 report for IDE and CI/CD integration
- `reports/ash.summary.txt`: Human-readable text summary
- `reports/ash.summary.md`: Markdown summary for GitHub PRs and other platforms
- `reports/ash.html`: Interactive HTML report
- `reports/ash.csv`: CSV report for filtering and sorting findings

ASH also supports CycloneDX, SPDX, OCSF, GitLab SAST, JUnit XML, and YAML output. Enable any combination of reporters in your `.ash/ash.yaml` configuration. For the complete schema reference, consumption examples, and format details, see [Output Formats](https://awslabs.github.io/automated-security-helper/docs/output-formats/).

The `ash_aggregated_results.json` file includes comprehensive validation information that tracks scanner registration, enablement, execution, and result inclusion throughout the scan process. The Scanner Validation System can also generate detailed validation reports that provide comprehensive analysis of scanner states, validation checkpoints, dependency issues, and actionable recommendations for troubleshooting scan issues.

## FAQ

<details>
<summary>Scanner coverage and local setup</summary>

| Scanner | Coverage | Local setup |
| --- | --- | --- |
| [Bandit](https://github.com/PyCQA/bandit) | Python code | Managed through uv tool isolation |
| [Semgrep](https://github.com/semgrep/semgrep) | Application code across multiple languages | Managed through uv tool isolation |
| [Opengrep](https://github.com/opengrep/opengrep) | Application code with Semgrep-compatible rules | Managed through uv tool isolation |
| [detect-secrets](https://github.com/Yelp/detect-secrets) | Secrets in text files | Included with ASH |
| [Checkov](https://github.com/bridgecrewio/checkov) | Infrastructure and configuration | Managed through uv tool isolation |
| [cfn-nag](https://github.com/stelligent/cfn_nag) | CloudFormation | Ruby and cfn-nag |
| [cdk-nag](https://github.com/cdklabs/cdk-nag) | CloudFormation | Included with ASH |
| [npm-audit](https://docs.npmjs.com/cli/commands/npm-audit) | Node.js dependencies | Node.js and npm |
| [Grype](https://github.com/anchore/grype) | Dependency vulnerabilities | Grype |
| [Syft](https://github.com/anchore/syft) | Software bill of materials | Syft |

Enabled scanners depend on your execution mode and configuration. Check the
[scanner catalog](docs/content/reference/scanners.md) for capabilities
and the [language guide](docs/content/reference/coverage.md) for coverage.

</details>

<details>
<summary>How do I run ASH in CI/CD pipelines?</summary>

ASH can be run in container mode in any CI/CD environment that supports containers. See the [tutorials](docs/content/tutorials/running-ash-in-ci.md) for examples.
</details>

<details>
<summary>How do I exclude files from scanning?</summary>

ASH respects `.gitignore` files. You can also configure ignore paths in your `.ash/ash.yaml` configuration file.
</details>

<details>
<summary>Does ASH scan its own output, or the templates in cdk.out?</summary>

ASH leaves its own output out of the scan, whether or not `.gitignore` lists it: the output directory of the current scan, and `.ash/ash_output` under the scanned directory and under the directory ASH runs from. In a git checkout, regular files committed to one of those directories are still scanned (a committed link is not), and ASH warns that its output directory holds committed files. Outside a git checkout, or when git cannot list the repository, only the current scan's output directory is left out: an earlier run's `.ash/ash_output` is scanned like the rest of the tree, and ASH warns once per scan while the scan set still holds files in it, naming it and saying how to leave it out: delete it, or list it in an ignore file such as `.gitignore`. Adding it to `global_settings.ignore_paths` leaves its findings out, but the scan still reads it, so the warning repeats until the directory is deleted or an ignore file lists it. The output directory is recognized when it or the scanned directory is given through a link above the tree, as `/var` is on macOS. A scan does not delete or overwrite a committed file: when git tracks one where a scan writes its output (`ash_aggregated_results.json`, `ash-ignore-report.txt`, `ash-scan-set-files-list.txt`, `ash-scan-set-run.json`, `ash.log`, `ash.log.jsonl`, `.ash_previous_results_restored`, or anything under `analysis/`, `reports/`, `scanners/`, `converted/`, `.ash_previous_results/` or `.ash_previous_results.partial/`), the scan exits 3 before it deletes or writes anything, in every mode and from the MCP server. When git cannot list the repository the output directory is in (git is not installed, or it fails on the repository), any file at one of those paths stops the scan the same way, and the message names git's error and says to let git read the repository or remove the old results. A report over existing results (`--use-existing`) is stopped only where it writes: the results file, the logs, `reports/`, and `analysis/` with `--inspect` or `converted/` with `--cleanup`. A `.ash/ash_output` that is a link, or that a link inside the scanned directory leads to, is not taken as ASH's output, however the path to it is spelled, and a scan into an output directory git tracks as a link exits 3. The trivy-repo plugin still reads those directories, and ASH drops the findings it reports there, except in committed files. Any other directory is scanned, even one holding an earlier run's or another shard's results; ASH warns when a directory holds `ash_aggregated_results.json`, or both `ash-ignore-report.txt` and `ash-scan-set-files-list.txt`. Write shard output outside the scanned directory, or list it in `.gitignore`. CloudFormation templates that `cdk synth` writes (`*.template.json`) are scanned even when `.gitignore` excludes `cdk.out`, so cdk-nag and cfn-nag check them; the rest of the `cdk.out` directory stays excluded.
</details>

<details>
<summary>How do I run ASH in an offline/air-gapped environment?</summary>

Build an offline image with `ash --mode container --offline --offline-semgrep-rulesets p/ci --no-run`, push to your private registry, then use `ash --mode container --offline --no-build` in your air-gapped environment.
</details>

<details>
<summary>I am trying to scan a CDK application, but ASH does not show CDK Nag scan results -- why is that?</summary>

ASH uses CDK Nag underneath to apply NagPack rules to *CloudFormation templates* via the `CfnInclude` CDK construct. This is purely a mechanism to ingest a bare CloudFormation template and apply CDK NagPacks to it; doing this against a template emitted by another CDK application causes a collision in the `CfnInclude` construct due to the presence of the `BootstrapVersion` parameter on the template added by CDK. For CDK applications, we recommend integrating CDK Nag directly in your CDK code. ASH will still apply other CloudFormation scanners (cfn-nag, checkov) against templates synthesized via CDK, but the CDK Nag scanner will not scan those templates.
</details>

<details>
<summary>Why is ASH trying to install tools automatically? Can I use my own tool installations?</summary>

ASH v3 uses UV's tool isolation system to automatically manage scanner dependencies like Bandit, Checkov, and Semgrep. This ensures consistent tool versions and avoids dependency conflicts. If you prefer to use your own tool installations:

1. **Pre-install tools**: Install tools manually using `uv tool install <tool>` or your preferred method
2. **Offline mode**: Set `ASH_OFFLINE=true` to skip automatic installations and use system-installed tools
3. **Fallback behavior**: ASH automatically falls back to system-installed tools if UV tool installation fails

The automatic installation uses sensible default version constraints to ensure compatibility:
- **Bandit**: `>=1.7.0` (enhanced SARIF support and security fixes)
- **Checkov**: `>=3.2.0,<4.0.0` (improved stability, avoiding potential breaking changes in 4.x)
- **Semgrep**: `>=1.125.0` (comprehensive rule support and performance improvements)

These constraints can be overridden through scanner configuration when needed.
</details>

<details>
<summary>ASH is failing with UV tool installation errors. How do I fix this?</summary>

If you're experiencing UV tool installation issues:

1. **Check UV installation**: Ensure UV is installed and available: `uv --version`
2. **Network connectivity**: UV tool installation requires internet access
3. **Use offline mode**: Set `ASH_OFFLINE=true` to skip downloads and use pre-installed tools
4. **Manual installation**: Pre-install tools manually:
   ```bash
   uv tool install bandit>=1.7.0,<2.0.0
   uv tool install checkov>=3.2.0,<4.0.0
   uv tool install semgrep>=1.125.0,<2.0.0
   ```
5. **Check logs**: Run ASH with `--verbose` to see detailed error messages including:
   - UV availability status
   - Tool installation attempts and retry logic
   - Version detection information
   - Fallback mechanism activation
6. **Fallback to system tools**: ASH will automatically try to use system-installed tools if UV installation fails
7. **Installation timeout**: Increase timeout in scanner configuration if needed:
   ```yaml
   scanners:
     checkov:
       options:
         install_timeout: 600  # 10 minutes
   ```
</details>

## Documentation

| Task | Reference |
| --- | --- |
| Understand a command | [CLI reference](docs/content/reference/cli.md) |
| Recover from a setup or scan issue | [Troubleshooting](docs/content/how-to/troubleshoot.md) |
| Understand scanner coverage | [Languages and frameworks](docs/content/reference/coverage.md) |
| Read common answers | [FAQ](docs/content/faq.md) |
| Contribute a change | [Contributing](CONTRIBUTING.md) and [development setup](DEVELOPMENT.md) |
| Review the interfaces | [Design system](docs/content/developer-guide/interface-design.md) and [all-surface review](docs/content/developer-guide/high-end-design-review.md) |

<a id="security"></a>

Report bugs and feature requests through [GitHub issues](https://github.com/awslabs/automated-security-helper/issues).
For security concerns, follow [Security issue notifications](CONTRIBUTING.md#security-issue-notifications).

<a id="license"></a>

Licensed under [Apache 2.0](LICENSE). Bundled fonts and icons retain their
respective licenses alongside their assets.

Build with <3 at Amazon Web Services
