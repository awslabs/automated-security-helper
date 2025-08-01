# ASH with AWS CodeBuild

This example demonstrates how to integrate Automated Security Helper (ASH) into your AWS CodeBuild projects.

## Overview

The provided `buildspec.yml` configures AWS CodeBuild to:

1. Install ASH from a specified GitHub repository branch
2. Run ASH in container mode
3. Generate reports in the post-build phase
4. Collect artifacts and test reports as custom CodeBuild Report Group

## Usage

1. Add the `buildspec.yml` to your repository
2. Create a CodeBuild project that references this buildspec
3. **Enable privileged mode** in the CodeBuild project settings (required for Docker operations)
4. Configure the CodeBuild environment with appropriate permissions

## Configuration

The buildspec includes the following environment variables:

| Variable             | Description                          | Default                                                    |
|----------------------|--------------------------------------|------------------------------------------------------------|
| `ASH_REPO_BRANCH`    | The branch or tag of ASH to install  | `v3.0.0-beta`                                              |
| `ASH_MODE`           | The execution mode for ASH           | `container`                                                |
| `ASH_REPO_CLONE_URL` | The URL to clone the ASH repository  | `https://github.com/awslabs/automated-security-helper.git` |
| `COLUMNS`            | Terminal width for better formatting | `140`                                                      |

## Phases

### Pre-Build
- Installs ASH from the specified GitHub repository

### Build
- Runs ASH in container mode with progress display disabled

### Post-Build
- Generates ASH reports

## Artifacts

The buildspec collects all files in the `ash_output` directory as artifacts, with a date-stamped name format.

## Reports

JUnit XML reports are collected and made available in the CodeBuild test reports section, allowing you to track security findings across builds.

## Requirements

- AWS CodeBuild environment with Docker support
- **Privileged mode enabled** in the CodeBuild project settings (required for container operations)
- Python 3.8 or later
- Internet access to download ASH and its dependencies

## Customization

You can customize the ASH execution by modifying the `ash` command in the build phase. For example:

```yaml
build:
  commands:
    - ash --mode container --no-progress --scanners bandit,semgrep
```