# ASH with AWS CodeBuild

This example demonstrates how to integrate Automated Security Helper (ASH) into your AWS CodeBuild projects.

## Overview

The provided `buildspec.yml` configures AWS CodeBuild to:

1. Install an ASH release from GitHub
2. Run an ASH scan in container mode, writing its results to `.ash/ash_output`
3. Print the scan's summary in the post-build phase
4. Collect the results as an artifact and the JUnit report as a CodeBuild report group

## Usage

1. Add the `buildspec.yml` to your repository
2. Create a CodeBuild project that references this buildspec
3. **Enable privileged mode** in the CodeBuild project settings (required for Docker operations)
4. Configure the CodeBuild environment with appropriate permissions

## Configuration

The buildspec's `env.variables` block sets four variables:

- the ASH release tag (or commit) to install. It names the release this example
  ships in.
- `ASH_MODE`, the execution mode for ASH, `container`.
- `ASH_REPO_CLONE_URL`, the repository to install ASH from,
  `https://github.com/awslabs/automated-security-helper.git`.
- the terminal width for the build log, 140 columns.

## Phases

### Pre-Build
- Installs that ASH release from `ASH_REPO_CLONE_URL` with pip

### Build
- Runs the scan in `ASH_MODE` with progress display disabled, writing results to `.ash/ash_output`
- The scan writes every report format, including `reports/ash.junit.xml`, during this phase
- ASH exits non-zero when it finds actionable findings, which fails the build

### Post-Build
- Prints the Markdown summary of the scan's results to the build log with `ash report`. CodeBuild runs this phase even when the build phase failed.

## Artifacts

The buildspec collects everything in `.ash/ash_output` as the build artifact, with a date-stamped name.

## Reports

`.ash/ash_output/reports/ash.junit.xml` is collected into the `junit-security-findings` report group, so you can track security findings across builds in the CodeBuild test reports section.

## Requirements

- AWS CodeBuild environment with Docker support
- **Privileged mode enabled** in the CodeBuild project settings (required for container operations)
- Python 3.10 to 3.14
- Internet access to download ASH and its dependencies

## Customization

You can customize the ASH execution by modifying the `ash` command in the build phase. If you change `--output-dir`, change the artifact and report `base-directory` paths to match. For example:

<!-- doctest: config kind=buildspec runner=none reason="an excerpt of examples/AWSCodeBuild/buildspec.yml; container mode needs a privileged CodeBuild project" -->
```yaml
version: 0.2
phases:
  build:
    commands:
      - ash --mode container --no-progress --output-dir .ash/ash_output --scanners bandit,semgrep
```