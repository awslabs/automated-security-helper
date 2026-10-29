# Run ASH in Jenkins, CodeBuild, Azure Pipelines, CircleCI, and other CI systems

Every CI integration does the same things: install ASH outside the checkout, install the
scanner tools, run the scan, keep the reports whatever the exit code, and let the exit code
fail the build. This page gives that recipe as plain shell, then shows it in Jenkins, AWS
CodeBuild, Azure Pipelines, and CircleCI. GitHub Actions and GitLab CI have their own pages:
[Run ASH in GitHub Actions](github-actions.md) and [Run ASH in GitLab CI](gitlab-ci.md).

## The recipe {#recipe}

<!-- doctest: illustrative reason="installs ASH and scanner tools from the network" -->
```bash
python3 -m venv "$HOME/ash-venv"
"$HOME/ash-venv/bin/pip" install --quiet \
  "automated-security-helper[cdk] @ git+https://github.com/awslabs/automated-security-helper.git@v3.7.1"
export PATH="$HOME/ash-venv/bin:$PATH"
(cd "$(mktemp -d)" && ash dependencies install \
  --tool grype --tool syft --tool opengrep --tool cfn-nag \
  --tool actionlint --tool cfn-guard --tool gitleaks --tool trivy)
ash scan --mode local --no-progress \
  --fail-on-findings --fail-on-incomplete-scanners --no-allow-stale-content-db
```

Run it from the root of the checkout. The reports land in `.ash/ash_output/reports/`.

- Keep the virtual environment outside the checkout. ASH does not run tools it finds inside
  the directory it scans, and the virtual environment's `bin` holds the `uv` that ASH uses to
  install bandit, checkov, semgrep, cfn-lint, and zizmor during the scan; see
  [Tools inside the scanned directory](../../docs/advanced-usage.md#tools-inside-the-scanned-directory).
- Run `ash dependencies install` outside the checkout too, as the empty directory does here,
  so a config in the repository cannot change what it installs. It downloads the tool
  versions that this ASH version pins, checks each against its pinned SHA256, and installs
  it into `~/.ash/bin`, where the scan finds it. A binary that is already there and matches
  is not downloaded again, so `~/.ash/bin` is safe to cache between builds. Cache it and
  nothing else under `~/.ash`: the cfn-guard rules in `~/.ash/share/cfn-guard-rules` are
  downloaded again on each run, and `~/.ash/install-receipts` holds the install records.
  Restore the cache with the files' execute bits: `ash dependencies install`
  downloads a binary there again if it has lost its execute bit, and a scan run without
  that step skips it. cfn-nag is the exception: it is a Ruby gem, not a pinned binary, and
  it is installed again on every run.
- Install ASH from a git URL as shown. The `automated-security-helper` name on PyPI belongs to
  an unrelated project; see [Install ASH](../install.md).
- The three gate flags keep a pull request's or merge request's own config from turning off
  the gate for findings, incomplete scans, and stale content databases. A branch's config can
  still raise thresholds, add suppressions, and turn scanners off; to keep those yours, pass
  `--config` with a file outside the checkout. See
  [Who can change the gate](../set-the-gate.md#who).

### What the build host needs {#host}

| Scanners | Needs on the host |
|---|---|
| detect-secrets | Nothing; it is part of ASH |
| bandit, checkov, semgrep, cfn-lint, zizmor | Access to PyPI during the scan |
| grype, syft, opengrep, actionlint, cfn-guard, gitleaks, trivy | The binary, from `ash dependencies install` |
| cfn-nag | Ruby, with the headers and a C compiler to build gems, so that `ash dependencies install` can install it |
| cdk-nag | The `cdk` extra, which the recipe installs, and Node.js |
| npm-audit | Node.js and npm |

A scanner whose requirements are missing is reported MISSING when the repository has files
it scans, and the scan exits 1. With none, it is SKIPPED, whether or not its tool is
installed. In a repository with no npm lockfile, npm-audit is SKIPPED, and this scan exits
2 for the hardcoded password that detect-secrets finds in `app.py`:

<!-- doctest: run expect-exit=2 -->
```bash
ash scan --mode local --no-progress --offline --scanners detect-secrets --scanners npm-audit
```

To run without a scanner, name it in `--exclude-scanners`, for example
`ash scan --mode local --no-progress --exclude-scanners cfn-nag`. Several scanners also use
the network during the scan, for their vulnerability databases, rules, or registries;
[What each scanner does offline](../run-offline.md#scanners) lists them.

## Local mode or container mode {#modes}

The recipe uses local mode: the scanners run on the build host, which needs the tools above.

Container mode (`--mode container`) runs the scan inside ASH's container image instead, so
the host needs only ASH and a container runtime. In CI that costs time on every build: ASH
publishes no image, so each container-mode run on a fresh host builds one, downloading every
tool. Two more things differ in CI:

- A job that runs as root, as AWS CodeBuild and container-based jobs do, needs
  `--build-target ci`: ASH refuses to build the non-root image, whose user would get
  UID 0.
- `--changed-files-only` is not supported in container mode: the scan stops with exit code 5
  before anything is built or run, also when `ASH_CHANGED_FILES_ONLY` sets it.

For many repositories, build the image once, push it to your registry, and use it as the
build image, running `ash scan --mode local` inside it. Nothing is installed per build. See
[Run ASH in a container](../run-in-a-container.md) and
[Roll out ASH across repositories](../../getting-started/platform-teams.md).

## Use the exit code as the gate {#exit-codes}

ASH exits 0 when nothing actionable was found or `fail_on_findings` is off, 1 when the scan
did not complete or was refused, 2 for actionable findings, 3 for a configuration it cannot use or an input it refuses before scanning, such as a linked output directory,
4 for a workspace error, and 5 for a command-line usage error, such as an unknown option or
an unknown `--output-formats` value. When a scan is both incomplete and has findings, it
exits 1. [Exit codes](../../reference/exit-codes.md) lists every condition behind each
code.

A usage error stops ASH before it scans anything, so a mistyped value cannot pass as a
finding or as a clean scan:

<!-- doctest: run expect-exit=5 -->
```bash
ash scan --mode local --no-progress --offline --scanners detect-secrets --min-severity hihg
```

Fail the build on any non-zero code, and keep the reports when it fails: the build tools
below all have a way to do that. The scan itself decides which findings count, from the
severity threshold and suppressions; see [Set the gate](../set-the-gate.md).

## Jenkins {#jenkins}

A declarative pipeline for an agent that has Python 3.10 or later, git, Node.js, npm, and
Ruby:

<!-- doctest: config kind=jenkinsfile -->
```groovy
pipeline {
  agent { label 'linux' }
  environment {
    INSTALL_SPEC = 'automated-security-helper[cdk] @ git+https://github.com/awslabs/automated-security-helper.git@v3.7.1'
  }
  stages {
    stage('ASH') {
      steps {
        sh '''
          mkdir -p "$WORKSPACE_TMP/tools"
          python3 -m venv "$WORKSPACE_TMP/ash"
          "$WORKSPACE_TMP/ash/bin/pip" install --quiet "$INSTALL_SPEC"
          export PATH="$WORKSPACE_TMP/ash/bin:$PATH"
          (cd "$WORKSPACE_TMP/tools" && ash dependencies install --tool grype --tool syft --tool opengrep --tool cfn-nag --tool actionlint --tool cfn-guard --tool gitleaks --tool trivy)
          ash scan --mode local --no-progress --fail-on-findings --fail-on-incomplete-scanners --no-allow-stale-content-db
        '''
      }
    }
  }
  post {
    always {
      junit allowEmptyResults: true, testResults: '.ash/ash_output/reports/ash.junit.xml'
      archiveArtifacts allowEmptyArchive: true, artifacts: '.ash/ash_output/reports/**, .ash/ash_output/ash_aggregated_results.json'
    }
  }
}
```

`WORKSPACE_TMP` is a directory next to the workspace, so the virtual environment stays out
of the checkout. A non-zero exit from `sh` fails the stage, and `post { always { ... } }`
publishes the JUnit file and archives the reports anyway. The `junit` step marks the build
unstable when any test failed, and every actionable finding is a failed test.

If you run the stage in a container with `agent { docker { ... } }`, Jenkins starts the
container as the agent's user, not root, so the image has to have the tools already, or the
recipe has to install everything under a directory that user can write. Your own ASH image
from [Build and host your own image](../run-in-a-container.md#own-image) has the tools.

## AWS CodeBuild {#codebuild}

A `buildspec.yml` for a standard Linux image, for example
`aws/codebuild/amazonlinux-x86_64-standard:5.0`, the image ASH's own CDK templates use:

<!-- doctest: config kind=buildspec -->
```yaml
version: 0.2
env:
  variables:
    INSTALL_SPEC: "automated-security-helper[cdk] @ git+https://github.com/awslabs/automated-security-helper.git@v3.7.1"
phases:
  install:
    runtime-versions:
      python: 3.12
      nodejs: 22
      ruby: 3.3
    commands:
      - python -m venv /opt/ash
      - /opt/ash/bin/pip install --quiet "$INSTALL_SPEC"
      - export PATH="/opt/ash/bin:$PATH"
      - (cd "$(mktemp -d)" && ash dependencies install --tool grype --tool syft --tool opengrep --tool cfn-nag --tool actionlint --tool cfn-guard --tool gitleaks --tool trivy)
  build:
    commands:
      - ash scan --mode local --no-progress --fail-on-findings --fail-on-incomplete-scanners --no-allow-stale-content-db
reports:
  ash-findings:
    base-directory: .ash/ash_output/reports
    files:
      - ash.junit.xml
    file-format: JUNITXML
artifacts:
  base-directory: .ash/ash_output
  files:
    - "**/*"
```

Name all three runtimes: when `runtime-versions` lists any, CodeBuild provides only those.
Buildspec version 0.2 runs every command in one shell, so the `PATH` change carries into the
build phase. CodeBuild attempts to upload the artifacts even when the build phase fails.

Container mode needs privileged mode on the CodeBuild project, because it runs Docker. Local
mode, as above, does not.

## Azure Pipelines {#azure}

An `azure-pipelines.yml` for a Microsoft-hosted Ubuntu agent:

<!-- doctest: config kind=azure-pipelines -->
```yaml
pool:
  vmImage: ubuntu-latest
variables:
  INSTALL_SPEC: "automated-security-helper[cdk] @ git+https://github.com/awslabs/automated-security-helper.git@v3.7.1"
steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: "3.12"
  - script: |
      sudo apt-get update && sudo apt-get install -y --no-install-recommends ruby-dev libyaml-dev
      python -m venv "$(Agent.TempDirectory)/ash"
      "$(Agent.TempDirectory)/ash/bin/pip" install --quiet "$INSTALL_SPEC"
      echo "##vso[task.prependpath]$(Agent.TempDirectory)/ash/bin"
    displayName: Install ASH
  - script: ash dependencies install --tool grype --tool syft --tool opengrep --tool cfn-nag --tool actionlint --tool cfn-guard --tool gitleaks --tool trivy
    workingDirectory: $(Agent.TempDirectory)
    displayName: Install scanner tools
  - script: ash scan --mode local --no-progress --fail-on-findings --fail-on-incomplete-scanners --no-allow-stale-content-db
    displayName: Run ASH
  - task: PublishTestResults@2
    condition: succeededOrFailed()
    inputs:
      testResultsFormat: JUnit
      testResultsFiles: .ash/ash_output/reports/ash.junit.xml
  - script: |
      mkdir -p "$(Build.ArtifactStagingDirectory)/sarif"
      cp .ash/ash_output/reports/ash.sarif "$(Build.ArtifactStagingDirectory)/sarif/"
    condition: succeededOrFailed()
    displayName: Stage the SARIF report
  - task: PublishPipelineArtifact@1
    condition: succeededOrFailed()
    inputs:
      targetPath: $(Build.ArtifactStagingDirectory)/sarif
      artifact: CodeAnalysisLogs
  - task: PublishPipelineArtifact@1
    condition: succeededOrFailed()
    inputs:
      targetPath: .ash/ash_output
      artifact: ash-output
```

- `succeededOrFailed()` runs the publishing steps after a failed scan, and skips them when
  the run is canceled.
- `workingDirectory` runs `ash dependencies install` outside the checkout.
- The JUnit file appears in the run's **Tests** tab.
- The artifact named `CodeAnalysisLogs` is the one the free SARIF SAST Scans Tab extension
  from Microsoft DevLabs reads. With the extension installed in your organization, the run
  shows the SARIF findings in a tab of its own.
- The `apt-get` line adds the Ruby headers and libyaml that building cfn-nag's gems needs.

## CircleCI {#circleci}

A `.circleci/config.yml` for CircleCI's Docker executor:

<!-- doctest: config kind=circleci -->
```yaml
version: 2.1
jobs:
  ash-scan:
    docker:
      - image: cimg/python:3.12-node
    environment:
      INSTALL_SPEC: "automated-security-helper[cdk] @ git+https://github.com/awslabs/automated-security-helper.git@v3.7.1"
    steps:
      - checkout
      - run:
          name: Install ASH
          command: |
            sudo apt-get update && sudo apt-get install -y --no-install-recommends ruby ruby-dev libyaml-dev
            python3 -m venv "$HOME/ash-venv"
            "$HOME/ash-venv/bin/pip" install --quiet "$INSTALL_SPEC"
            echo 'export PATH="$HOME/ash-venv/bin:$PATH"' >> "$BASH_ENV"
      - restore_cache:
          key: ash-tools-v3.7.1-{{ arch }}
      - run:
          name: Install scanner tools
          command: (cd "$(mktemp -d)" && ash dependencies install --tool grype --tool syft --tool opengrep --tool cfn-nag --tool actionlint --tool cfn-guard --tool gitleaks --tool trivy)
      - save_cache:
          key: ash-tools-v3.7.1-{{ arch }}
          paths:
            - ~/.ash/bin
      - run:
          name: Run ASH
          command: ash scan --mode local --no-progress --fail-on-findings --fail-on-incomplete-scanners --no-allow-stale-content-db
      - run:
          name: Copy the JUnit file out of .ash
          when: always
          command: |
            mkdir -p /tmp/ash-test-results
            if [ -f .ash/ash_output/reports/ash.junit.xml ]; then cp .ash/ash_output/reports/ash.junit.xml /tmp/ash-test-results/; fi
      - store_test_results:
          path: /tmp/ash-test-results
      - store_artifacts:
          path: .ash/ash_output/reports
          destination: ash-output/reports
      - store_artifacts:
          path: .ash/ash_output/ash_aggregated_results.json
          destination: ash-output/ash_aggregated_results.json
workflows:
  ash:
    jobs:
      - ash-scan
```

- `cimg/python:3.12-node` is CircleCI's Python image with Node.js added. The `apt-get`
  line adds Ruby, its headers, and libyaml, which building cfn-nag's gems needs. The image
  already has a C compiler.
- Each `run` step starts a new shell. The line that appends to `$BASH_ENV` puts the
  virtual environment's `bin` on `PATH` for every later step. The virtual environment is
  in the home directory, outside the checkout in `~/project`.
- `save_cache` comes before the scan because, by default, it runs only when every step
  before it succeeded, and a scan with findings fails its step. CircleCI never overwrites
  a saved key, so key the cache on the ASH version, as above: each version pins its own
  tool versions.
- Keep `ash dependencies install` after `restore_cache`. Pull requests from a fork share
  a cache with the repository's own builds, so a restored cache may have been written by
  another branch. `ash dependencies install` checks each binary against its pinned
  SHA256 and installs again any that does not match, so a restored cache cannot
  substitute a different tool. Because that check needs no install record, the cache
  holds `~/.ash/bin` and nothing else: the records in `~/.ash/install-receipts` hold the
  SHA256 each installed tool is checked against, so a cache a fork's pull request can
  write must not carry them. cfn-nag, and the cfn-guard rules in
  `~/.ash/share/cfn-guard-rules`, are installed again on every run.
- A non-zero exit from `ash scan` fails its step and the job. `store_test_results` and
  `store_artifacts` run after a failed step, so the JUnit file appears in the job's
  **Tests** tab, one failed test per actionable finding, and `.ash/ash_output/reports/` and
  `.ash/ash_output/ash_aggregated_results.json` are kept as the job's artifacts. Neither runs when the job is canceled or times out.
- CircleCI's test results `path` must not be a hidden directory, and `.ash` is one, so
  the step before `store_test_results` copies the JUnit file out of it. Its
  `when: always` runs it after a failed scan.

## Generic shell {#shell}

Any other CI service, or a cron job, runs the [recipe](#recipe) as a shell step. Make the
step that archives `.ash/ash_output/` run after a failed scan, and pass the scan's exit code
through to the build result:

<!-- doctest: illustrative reason="runs a full scan with every scanner, which needs the network" -->
```bash
ash_exit=0
ash scan --mode local --no-progress \
  --fail-on-findings --fail-on-incomplete-scanners --no-allow-stale-content-db \
  || ash_exit=$?
tar -czf ash-output.tar.gz .ash/ash_output
exit "$ash_exit"
```

The same step with one scanner that needs no network runs anywhere. In a project whose
`app.py` holds a hardcoded password, detect-secrets reports it, the archive is written,
and the step exits 2:

<!-- doctest: run expect-exit=2 -->
```bash
ash_exit=0
ash scan --mode local --no-progress --offline --scanners detect-secrets \
  --fail-on-findings --fail-on-incomplete-scanners --no-allow-stale-content-db \
  || ash_exit=$?
tar -czf ash-output.tar.gz .ash/ash_output
exit "$ash_exit"
```

## Examples in the repository {#examples}

- [.github/workflows/ash-repo-scan.yml](https://github.com/awslabs/automated-security-helper/blob/main/.github/workflows/ash-repo-scan.yml)
  is how ASH scans itself with its reusable workflows, and uses their current inputs. Its
  `sarif` job's `if:` has no status function, so that job is skipped when the scan fails;
  [Upload SARIF](github-actions.md#sarif) shows the condition to use instead.
- [examples/GitHubActions/ash-repo-scan.yml](https://github.com/awslabs/automated-security-helper/blob/main/examples/GitHubActions/ash-repo-scan.yml)
  calls the reusable workflow at the floating `v3` tag, with `ash-version: v3`, and uploads
  SARIF from the scan job on pull requests only. To pin a release, upload SARIF on every
  event, and install every default scanner's tool, follow
  [Run ASH in GitHub Actions](github-actions.md).
- [examples/AWSCodeBuild/](https://github.com/awslabs/automated-security-helper/tree/main/examples/AWSCodeBuild)
  installs the ASH release it ships in and scans in container mode, which needs
  privileged mode on the CodeBuild project. The [buildspec above](#codebuild) scans in
  local mode instead.
