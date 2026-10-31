---
template: home.html
title: Overview
description: Security scanning for code, infrastructure, secrets, and dependencies.
ash_version: "3.7.1"
hide:
  - navigation
  - toc
  - footer
---

# Automated Security Helper

ASH runs open-source security scanners and aggregates their findings. AWS Labs project. Apache 2.0 license.

## Scanning

- Application code, infrastructure, secrets, and dependencies
- Severity thresholds and suppressions
- SARIF, HTML, JSON, Markdown, and CSV reports

## Quickstart

Install ASH with Python 3.10+ and pipx:

<!-- doctest: illustrative reason="installs ASH from GitHub over the network" -->
```bash
pipx install git+https://github.com/awslabs/automated-security-helper.git@v3.7.1
```

From your project directory, choose an execution mode:

<!-- doctest: illustrative reason="container mode needs a container runtime, and every mode runs a scan with all scanner tools" -->
```bash
# Linux/macOS
curl -LsSf https://astral.sh/uv/install.sh | sh
alias ash="uvx git+https://github.com/awslabs/automated-security-helper.git@v3.7.1"

# Windows PowerShell
irm https://astral.sh/uv/install.ps1 | iex
function ash { uvx git+https://github.com/awslabs/automated-security-helper.git@v3.7.1 $args }
```

#### Using `pip`

<!-- doctest: illustrative reason="installs ASH from GitHub over the network" -->
```bash
pip install git+https://github.com/awslabs/automated-security-helper.git@v3.7.1
```

#### Clone the Repository

<!-- doctest: illustrative reason="clones the ASH repository and installs it over the network" -->
```bash
git clone https://github.com/awslabs/automated-security-helper.git --branch v3.7.1
cd automated-security-helper
pip install .
```
</details>

## Basic Usage

<!-- doctest: illustrative reason="container mode needs a container runtime, and every mode runs a scan with all scanner tools" -->
```bash
# Run a scan in local mode (the scanner tools installed on this machine)
ash --mode local

# Run a scan in container mode (all tools)
ash --mode container
ash --mode local
ash --mode precommit
```

| Mode | Requirements |
| --- | --- |
| `container` | OCI-compatible runtime |
| `local` | Local scanner dependencies |
| `precommit` | Dependencies for the enabled subset |

[Installation](how-to/install.md) · [Quickstart](getting-started/local.md)

## Scanners

- Code: Bandit, Semgrep, Opengrep
- Infrastructure: Checkov, CDK-Nag, CFN-Nag
- Secrets: detect-secrets
- Dependencies and software inventory: Grype, npm audit, Syft

A scan ends by printing the exit codes and the one it exits with:

```text
=== ASH Exit Codes ===
  0: success
  1: scan errors / scanner failures
  2: actionable findings at or above threshold (fail_on_findings is true; default true)
  3: invalid config or refused input
  4: workspace definition or policy error
  5: usage error
ERROR (2) Exiting due to 122 actionable findings found in ASH scan
```

## Configuration

Configure scanners, severity thresholds, ignore paths, and suppressions in your [ASH configuration](how-to/configure.md). Add your own [scanner, reporter, and converter plugins](plugins/index.md).

## Integrations

Run [locally](getting-started/local.md), integrate with [CI/CD](getting-started/ci.md), or connect your AI tools through the [Model Context Protocol](how-to/mcp-server.md).

## Reports and next steps

<!-- doctest: config kind=pre-commit -->
```yaml
repos:
  - repo: https://github.com/awslabs/automated-security-helper
    rev: v3.7.1
    hooks:
      - id: ash
```

## Help

<!-- doctest: illustrative reason="runs the ash hook through pre-commit, which needs a .pre-commit-config.yaml and the network to fetch the hook repository" -->
```bash
pre-commit run ash --all-files
```

The `ash` hook runs bandit, detect-secrets, checkov, cdk-nag and npm-audit. It needs pre-commit running on Python 3.10 to 3.14, and Node.js and npm on `PATH` for cdk-nag and npm-audit. `ash-simple-scan` is the same hook under its earlier id. See [Using ASH with pre-commit](how-to/pre-commit.md) for running without Node.js and for the container hook, `ash-full-scan`.

## Output Files

ASH v3 produces several output files in the `.ash/ash_output/` directory:

- `ash_aggregated_results.json`: Complete machine-readable results
- `reports/ash.summary.txt`: Human-readable text summary
- `reports/ash.summary.md`: Markdown summary for GitHub PRs and other platforms
- `reports/ash.html`: Interactive HTML report
- `reports/ash.csv`: CSV report for filtering and sorting findings

## FAQ

<details>
<summary>How do I run ASH on Windows?</summary>

ASH v3 can run directly on Windows in local mode with Python 3.10+. Simply install ASH using pip, pipx, or uvx and run with `--mode local`. For container mode, you'll need WSL2 and a container runtime like Docker Desktop, Rancher Desktop, or Podman Desktop.
</details>

<details>
<summary>How do I run ASH in CI/CD pipelines?</summary>

ASH can be run in container mode in any CI/CD environment that supports containers. See the [tutorials](getting-started/ci.md) for examples.
</details>

<details>
<summary>How do I exclude files from scanning?</summary>

ASH leaves out of its scan set every file a `.gitignore` or `.ignore` file in the scanned tree matches. You can also configure ignore paths in your `.ash/.ash.yaml` configuration file. The summaries record how many files the ignore files excluded, and `--no-honor-ignore-files` (or `honor_ignore_files: false` in a config file outside the scanned tree) scans those files too. See [Ignore files and the scan set](reference/coverage.md#what-decides-the-files).
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

## Feedback and Contributing

- Create an issue [in the GitHub repository](https://github.com/awslabs/automated-security-helper/issues)
- See [CONTRIBUTING](contributing/index.md) for contribution guidelines

## Security

See [CONTRIBUTING](contributing/index.md) for security issue reporting information.

## License

This library is licensed under the Apache 2.0 License. See the [LICENSE](https://github.com/awslabs/automated-security-helper/blob/main/LICENSE) file.
