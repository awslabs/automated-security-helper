# Add ASH to a GitHub Actions pipeline

In this tutorial you add a workflow that scans every pull request with ASH, fails the check
when ASH finds something, and shows the findings on the pull request and in GitHub code
scanning. It uses the reusable workflows that ASH ships, pinned to `v3.7.1`.

## Before you start

- A GitHub repository with Actions enabled, where you can push a branch and open a pull
  request.
- For step 4, code scanning: any public repository, or a private one with a GitHub Code
  Security license. Without it, skip step 4; the other steps work the same.
- git, to look up the commit of `v3.7.1` in step 1.

Nothing else has to be installed on your machine. Using another CI service? See
[Run ASH in GitLab CI](../how-to/ci/gitlab-ci.md) or
[Run ASH in Jenkins, CodeBuild, Azure Pipelines, CircleCI, and other CI systems](../how-to/ci/other-ci.md),
whose [CircleCI section](../how-to/ci/other-ci.md#circleci) has a `.circleci/config.yml`.

## 1. Add the workflow

Create `.github/workflows/ash.yml` on a new branch:

<!-- doctest: config kind=github-actions save-as=.github/workflows/ash.yml -->
```yaml
name: ASH
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  ash:
    uses: awslabs/automated-security-helper/.github/workflows/run-ash-security-scan.yml@v3.7.1
    permissions:
      contents: read
      checks: write
      pull-requests: write
    with:
      ash-version: v3.7.1
      collect-sarif-report: false
```

What the parts do:

- `uses: ...@v3.7.1` selects the workflow file, and `ash-version: v3.7.1` selects the ASH
  it installs. Without `ash-version`, the workflow installs ASH from `main`, so give both
  the same release to run the ASH that the workflow's steps were written for.
- The three permissions let the job read the code, publish a check run, and comment on the
  pull request.
- The workflow installs the tools that scanners on by default need from the runner:
  grype, syft, opengrep, cfn-nag, actionlint, cfn-guard, gitleaks, and trivy. Each has an
  `install-*` input that defaults to `true`.
- `collect-sarif-report: false` because step 4 uploads the SARIF report from a separate
  job, on every event. The workflow's own upload works on pull requests from branches of
  this repository only, and left on, it would upload the report a second time on those.
- The `push` trigger scans `main` after each merge. Code scanning compares a pull request
  with the analysis of its base branch, and the workflow saves its tool and database caches
  only from these runs.

If your default branch is not `main`, change the branch name.

Now pin the `uses:` line to a commit. ASH's zizmor scanner reports a `uses:` line that names
a tag as `zizmor/unpinned-uses` at HIGH, because a tag can be moved and a commit cannot, so
until you pin it every scan of this repository fails on this file. Look up the commit that
`v3.7.1` points to:

<!-- doctest: illustrative reason="queries GitHub over the network" -->
```bash
git ls-remote https://github.com/awslabs/automated-security-helper refs/tags/v3.7.1
```

In the `uses:` line, replace the `v3.7.1` after the `@` with the 40-character SHA that
the command prints, and add the comment `# v3.7.1` at the end of the line. Set
`ash-version` to the same SHA, so the workflow file and the ASH it installs both come from
the commit of the `v3.7.1` release.

## 2. Open a pull request and watch the scan

Commit the file, push the branch, and open a pull request. Under **Checks**, the job
**ash / SAST, SCA, and IaC Scan** starts. It downloads the scanner tools and the
vulnerability databases first, so expect it to take several minutes. Once the scan has
written its reports, whether it passed or failed, a second job,
**ash / Report ASH results**, posts them on the pull request.

When both finish, you see:

- A comment on the pull request with the ASH summary: one row per scanner, with its finding
  counts and a result of PASSED, FAILED, MISSING, SKIPPED, or ERROR. SKIPPED means the
  scanner was turned off or found nothing in the repository to scan.
- The same summary in the scan job's summary page.
- A check run named **ASH Scan JUnit Test Report**, which lists each actionable finding as a
  failed test.
- An artifact named `ash_output` with every report, including `ash.html`.

If the job fails, the end of its log says why:

- A line such as `ERROR (2) Exiting due to 3 actionable findings found in ASH scan` means
  ASH found something in your code. The comment and the JUnit check list what.
- `ERROR (1) Exiting because the scan was incomplete`, followed by scanners marked
  `MISSING`, means a scanner's tool is not on the runner, for example because its
  `install-*` input is `false`.
- Exit code 5 means ASH refused its command line, for example a mistyped option in
  `ash-args`. The log names the option.
- An error such as `the ash-args input holds a line break, another control character or the legacy command marker, so it is refused without being printed. A block scalar of one line is fine; more than one line is refused.`
  means the input it names holds more than one line, another control character, a Unicode
  line or paragraph separator, or `##[`, and the job stopped before it installed anything. Write `ash-args` on one line; see
  [How the workflow checks its inputs](../how-to/ci/github-actions.md#input-checks).

[Exit codes](../reference/exit-codes.md) lists the rest.

## 3. Choose what fails the build

By default the job fails when a scanner reports a finding at severity MEDIUM or above that
is not suppressed, when a scanner did not run, or when a vulnerability database is past its
age bound.

To fail only on HIGH and CRITICAL findings, add `.ashrc.yaml` at the root of the branch:

```yaml
global_settings:
  severity_threshold: HIGH
```

Other choices, each set under `with:` in the workflow:

- `fail-on-findings: false` reports findings without failing the job. A scan that did not
  complete still fails.
- `ash-args: --exclude-scanners cfn-nag` leaves a scanner out. Set its tool's `install-*`
  input to `false` too, here `install-cfn-nag: false`, so the job does not install it. For
  trivy, `install-trivy: false` saves its download of about 180 MB per run. An input set to
  `false` while its scanner is still on makes that scanner MISSING when the repository
  has files it scans, and the job fails with exit code 1.

To accept one finding instead, suppress it with a reason and an expiration date; see
[Suppress findings](../how-to/suppress-findings.md).

That config file is part of the repository, so a pull request that edits it changes the rules
it is judged by: it can raise the threshold, add suppressions, or turn scanners off. To hold
repositories to a gate that their own pull requests cannot change, see
[Roll out ASH across repositories](platform-teams.md).
[Set the gate](../how-to/set-the-gate.md) covers every option.

## 4. Upload results to code scanning

Add a second job under `jobs:`, at the same indentation as `ash`:

<!-- doctest: config kind=github-actions extends=.github/workflows/ash.yml -->
```yaml
  sarif:
    needs: ash
    if: ${{ !cancelled() && needs.ash.outputs.artifact-id != '' }}
    uses: awslabs/automated-security-helper/.github/workflows/upload-ash-sarif.yml@v3.7.1
    permissions:
      contents: read
      security-events: write
```

Pin its `uses:` line to the same commit as the first one, with the same `# v3.7.1`
comment.

This job downloads the `ash_output` artifact and uploads `ash.ghas.sarif` to code scanning.
It needs `security-events: write`, which the scan job cannot hold: a called workflow can
only narrow the permissions its caller grants, and the scan workflow does not ask for this
one. The scan sets its `artifact-id` output once it has uploaded its reports, which it does
when it fails on findings too, so the `if:` uploads after such a scan and skips the upload
after a scan that stopped before ASH wrote its reports. Without `!cancelled()` in it,
GitHub skips the job whenever the scan job fails.

Push the change, then merge the pull request. The merge starts the workflow on `main`, and
when that run finishes, the repository's **Security and quality** tab lists ASH's findings
under **Code scanning**, with the tool name `ASH - Automated Security Helper`. That analysis
of `main` is what code scanning compares later pull requests with.

## 5. See a finding on a pull request

Create a new branch from `main` and add a file with a known problem, for example
`ash_demo.py`:

<!-- doctest: run save-as=ash_demo.py -->
```python
import subprocess


def run(command):
    return subprocess.call(command, shell=True)
```

Push it and open a pull request. This time:

- The scan job fails with exit code 2: bandit reports the `subprocess` call with
  `shell=True`.
- The pull request comment shows bandit as FAILED, with its findings counted by severity.
- The **ASH Scan JUnit Test Report** check is red and names the finding.
- The **Code scanning results** check annotates the line in **Files changed**. Code scanning
  shows a pull request only the alerts on lines that the pull request changes.

Delete the file and push again, and the checks pass, provided `main` itself had no
actionable findings.

## Next steps

- [Run ASH in GitHub Actions](../how-to/ci/github-actions.md): every input of the reusable
  workflow, writing the steps yourself, caching, and changed-files scans.
- [Read scan results](../how-to/read-results.md): what each report file is for.
- [Choose scanners](../how-to/choose-scanners.md): turn scanners on and off.
- [Scale to large repositories](../how-to/scale-large-repos.md): split a scan across runners.
