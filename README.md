# ASH: Automated Security Helper

[![ASH - Core Pipeline](https://github.com/awslabs/automated-security-helper/actions/workflows/ash-repo-scan.yml/badge.svg)](https://github.com/awslabs/automated-security-helper/actions/workflows/ash-repo-scan.yml)
[![ASH - Unified CI](https://github.com/awslabs/automated-security-helper/actions/workflows/ash-unified-ci.yml/badge.svg)](https://github.com/awslabs/automated-security-helper/actions/workflows/ash-unified-ci.yml)

ASH runs a set of open-source security scanners over a directory and combines what they
find into one set of reports and one exit code. One config file controls all of them:
which scanners run, the severity that fails a scan, the paths to ignore, and the findings
you suppress, each with a reason. You can run ASH on your machine, in CI, in a container,
or from an AI coding agent over MCP.

ASH scans the files in a directory, not built container images. It does not deduplicate
findings, so a problem that two scanners detect appears twice.

## What it runs

ASH has 16 built-in scanners, all enabled by default (semgrep and opengrep are off on
Windows):

- Source code: bandit, semgrep, opengrep
- Secrets: detect-secrets, gitleaks
- Infrastructure as code: checkov, cfn-lint, cfn-guard, cfn-nag, cdk-nag
- Dependencies: grype, trivy, npm-audit, and syft for a software bill of materials
- GitHub Actions workflows: actionlint, zizmor

Community scanners add more when you load them. The
[scanners reference](https://awslabs.github.io/automated-security-helper/reference/scanners/)
lists every scanner and its options.

## Install

You need curl and git. ASH installs from GitHub with [uv](https://docs.astral.sh/uv/),
which also provides the Python that ASH runs on. Install uv:

<!-- doctest: illustrative reason="downloads and runs the uv installer from the network" -->
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Open a new terminal, so that `uv` is on your PATH, and install ASH:

<!-- doctest: illustrative reason="installs ASH from GitHub over the network" -->
```bash
uv tool install --python 3.12 'automated-security-helper[cdk] @ git+https://github.com/awslabs/automated-security-helper.git@v3.7.0'
```

Keep `--python 3.12`: on a machine without Python 3.10 to 3.14, uv would otherwise
download Python 3.15, and v3.7.0 does not install on it. The `cdk` extra adds the
packages the cdk-nag scanner needs. ASH is not published on PyPI; a package named
`automated-security-helper` there belongs to someone else, so always install from GitHub.

Check the install:

```bash
ash --version
```

```text
awslabs/automated-security-helper v3.7.0
```

This README and the documentation describe the `main` branch, which has changes that are
not in v3.7.0 yet. To use them now,
[install from `main`](https://awslabs.github.io/automated-security-helper/how-to/install/#install-from-main).
[Install ASH](https://awslabs.github.io/automated-security-helper/how-to/install/) also
covers pipx, pip, Windows, and the other install methods.

## Run your first scan

ASH runs other projects' scanners, so install their tools first. `ash dependencies install`
cannot install two things: Node.js, which npm-audit and cdk-nag use, and Ruby with a C
compiler, which cfn-nag needs. Install those first if you want every scanner to run.

<!-- doctest: illustrative reason="downloads scanner tools from GitHub releases and PyPI" -->
```bash
ash dependencies install
```

ASH writes its results to `.ash/ash_output/` in the directory it scans, and those files
can contain the secrets that scanners found, copied from your code. Add
`.ash/ash_output/` to the project's `.gitignore` before you scan. Then run `ash` in the
project. With no arguments, it scans the current directory with every enabled scanner:

<!-- doctest: illustrative reason="a full scan downloads rules and vulnerability databases; the docs job has no network" -->
```bash
cd path/to/your/project
ash
```

The first scan takes a minute or two, most of it downloading rules and a vulnerability
database. ASH prints a table with one row per scanner and its result: PASSED, FAILED (it
has actionable findings), SKIPPED (it did not run, for example because the project has no
files of the kind it checks), MISSING (its tool is not installed), or ERROR.

A MISSING or ERROR scanner makes the scan incomplete, and an incomplete scan exits 1 even
when it also found something. Without `ash dependencies install`, most scanners are
MISSING. To scan without a tool you cannot install, leave its scanner out:

<!-- doctest: illustrative reason="a full scan downloads rules and vulnerability databases; the docs job has no network" -->
```bash
ash --exclude-scanners cdk-nag,npm-audit
```

## What you get

The reports are in `.ash/ash_output/reports/`: an HTML report, Markdown and text
summaries, SARIF, JUnit XML, CSV, and formats for GitHub code scanning, GitLab, CycloneDX,
and OCSF. `ash report` prints the findings in the terminal with their rule IDs, and
`ash inspect findings` lets you browse them.
[Read scan results](https://awslabs.github.io/automated-security-helper/how-to/read-results/)
explains each file.

The exit code is the verdict: `0` when nothing is actionable, `2` for actionable findings,
`1` when the scan was incomplete or failed (checked before findings), `3` for an invalid
configuration, and `4` for a workspace definition or policy error. See
[Exit codes](https://awslabs.github.io/automated-security-helper/reference/exit-codes/).

## Next steps

Pick the guide for what you want to do next:

- [Add ASH to a GitHub Actions pipeline](https://awslabs.github.io/automated-security-helper/getting-started/ci/):
  scan every pull request and fail the check on findings; the guide links to GitLab CI and
  other CI systems. For CI owners.
- [Run your first scan](https://awslabs.github.io/automated-security-helper/getting-started/local/):
  the local workflow in full, from reading a finding to suppressing a false positive and
  fixing a real issue. For developers.
- [Roll out ASH across repositories](https://awslabs.github.io/automated-security-helper/getting-started/platform-teams/):
  your own image, one operator config that repositories cannot change, and results sent
  where your team reads them. For security and platform teams.
- [Connect an AI agent to ASH](https://awslabs.github.io/automated-security-helper/getting-started/agents/):
  let a coding agent or IDE run scans over MCP and explain the findings. For AI agent and
  IDE users.

The full documentation is at <https://awslabs.github.io/automated-security-helper/>.

## Contributing

Bug reports, fixes, and new scanners are welcome. [CONTRIBUTING.md](CONTRIBUTING.md)
explains how to report an issue and open a pull request.

## Security

If you find a security issue in ASH, do not open a public issue. Email
aws-security@amazon.com, as [SECURITY.md](SECURITY.md) describes.

## License

ASH is licensed under the Apache License 2.0. See [LICENSE](LICENSE).
