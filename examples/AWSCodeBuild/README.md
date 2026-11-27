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

| Name                 | Description                                | Set to                                                     |
|----------------------|--------------------------------------------|------------------------------------------------------------|
| `RELEASE_TAG`        | The ASH release tag (or commit) to install | `v3.8.0`                                                   |
| `ASH_MODE`           | The execution mode for ASH                 | `container`                                                |
| `ASH_REPO_CLONE_URL` | The URL to clone the ASH repository        | `https://github.com/awslabs/automated-security-helper.git` |
| `COLUMNS`            | Terminal width for better formatting       | `140`                                                      |

## Phases

### Pre-Build
- Installs the ASH release that the buildspec's version variable names, from the clone URL, with pip

### Build
- Runs the scan in `ASH_MODE` with progress display disabled, writing results to `.ash/ash_output`
- The scan writes every report format, including `reports/ash.junit.xml`, during this phase
- ASH exits non-zero when it finds actionable findings, which fails the build
- Asks the installed ASH whether it has `ash scan fs`, ASH 3.9's spelling, and runs the older `ash --mode ...` form when `RELEASE_TAG` names an older release
- Picks the older form only from an answer: a help that does not name `scan fs`, or a usage error that refuses the word `fs`. A probe that fails any other way, such as a crash or an out-of-memory kill, fails the build with status 70 and the end of its output instead of being read as an older ASH. 70 is not a status ASH gives, so it cannot be read as the scan's verdict
- Prints the spelling it chose and why to the build log

### Post-Build
- Prints the Markdown summary of the scan's results to the build log with `ash results report`, or `ash report` on a release older than 3.9, chosen the same way. CodeBuild runs this phase even when the build phase failed.

## Artifacts

The buildspec collects everything in `.ash/ash_output` as the build artifact, with a date-stamped name.

## Reports

`.ash/ash_output/reports/ash.junit.xml` is collected into the `junit-security-findings` report group, so you can track security findings across builds in the CodeBuild test reports section.

## Requirements

- AWS CodeBuild environment with Docker support
- **Privileged mode enabled** in the CodeBuild project settings (required for container operations)
- Python 3.11 or later
- Internet access to download ASH and its dependencies

## Customization

You can customize the ASH execution by modifying the `ash` commands in the build phase. If you change `--output-dir`, change the artifact and report `base-directory` paths to match. For example, the lines of the build command that follow its probe, with `--scanners` added to both spellings:

<!-- doctest: config kind=buildspec runner=none reason="an excerpt of examples/AWSCodeBuild/buildspec.yml, the lines after its probe; container mode needs a privileged CodeBuild project" -->
```yaml
build:
  commands:
    - |
      # The probe above these lines, as in buildspec.yml, sets ASH_SCAN_FS.
      if [ "$ASH_SCAN_FS" = yes ]; then
        ash scan fs --mode container --build-target ci --no-progress --output-dir .ash/ash_output --scanners bandit,semgrep
      else
        ash --mode container --build-target ci --no-progress --output-dir .ash/ash_output --scanners bandit,semgrep
      fi
```

With a `RELEASE_TAG` of 3.9 or later the `else` branch never runs, so the probe and the
`if` can go and the `ash scan fs` line can stand on its own.

CodeBuild runs the build as root, so the example asks for the `ci` image stage, which
runs as root. The default `non-root` stage would give its user UID 0, and ASH refuses
that build before it starts.
