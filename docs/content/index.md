---
template: home.html
title: Overview
description: Security scanning for code, infrastructure, secrets, and dependencies.
ash_version: "3.7.0"
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
pipx install git+https://github.com/awslabs/automated-security-helper.git@v3.7.0
```

From your project directory, choose an execution mode:

<!-- doctest: illustrative reason="container mode needs a container runtime, and every mode runs a scan with all scanner tools" -->
```bash
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

Explore [built-in scanners](reference/scanners.md). Scanner coverage varies by language, file type, and configuration.

## Configuration

Configure scanners, severity thresholds, ignore paths, and suppressions in your [ASH configuration](how-to/configure.md). Add your own [scanner, reporter, and converter plugins](plugins/index.md).

## Integrations

Run [locally](getting-started/local.md), integrate with [CI/CD](getting-started/ci.md), or connect your AI tools through the [Model Context Protocol](how-to/mcp-server.md).

## Reports and next steps

Reports are written to `.ash/ash_output/` by default. See [output formats](reference/output-files.md) for the available reports and [CLI reference](reference/cli.md) for commands.

## Help

- Core scanning: no AWS account required.
- Security Hub and S3 integrations: AWS account required.
- Coverage: depends on enabled scanners, languages, file types, and configuration.

Read the [FAQ](faq.md), [contribute](contributing/index.md), or [open an issue](https://github.com/awslabs/automated-security-helper/issues).
