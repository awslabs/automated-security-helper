# Frequently asked questions

Short answers, each with a link to the page that has the details. The config examples are
keys to add to `.ash/.ash.yaml` in the directory you scan. `ash config init` writes that
file with a `project_name`, which `ash config lint` and `ash config validate` require: on a
file without it they report an error and exit 1, although a scan accepts the file.

## Why does my first scan exit 1?

At least one scanner is MISSING: its tool is not installed, or ASH found the tool only
inside the scanned directory, such as in the project's `.venv`, and did not run it (see
[Tools inside the scanned directory](docs/advanced-usage.md#tools-inside-the-scanned-directory)).
A scan with a MISSING scanner is incomplete, and an incomplete scan exits 1 even when it
also found something. Run `ash dependencies install` to install the tools it can install.
npm-audit and cdk-nag also need Node.js, and cfn-nag needs Ruby with a C compiler. To scan
without a tool you cannot install, leave its scanner out with
`ash --exclude-scanners cdk-nag,npm-audit`. See
[A scanner shows MISSING](how-to/troubleshoot.md#a-scanner-shows-missing) and
[Exit codes](reference/exit-codes.md).

## How do I install ASH, and which version should I pin?

Install from GitHub with a git URL; [Install ASH](how-to/install.md) shows each method. ASH
is not published on PyPI, and a package named `automated-security-helper` there belongs to
someone else, so do not install ASH by that name. Pin an exact release tag or a commit.
The floating `v3` tag moves to every new 3.x release, including releases with breaking
changes. A pin fixes ASH's own code, not every dependency: uv, pipx, and pip resolve ASH's
dependencies again when they install it.

## Is there a container image?

ASH publishes no image. `ash build-image` builds one from a release tag, and
`ash --mode container` builds one and runs the scan in it. ASH uses the first of finch,
docker, nerdctl, and podman that it finds on your `PATH`, or the one you name with
`--oci-runner`. The default image runs as a non-root user whose UID and GID you can set.
When any of the variables `CI`, `IsCI`, `ISCI`, or `CODEBUILD_BUILD_ID` is set, to any
value, ASH builds the image that runs as root instead, whatever build target you ask for.
See [Run ASH in a container](how-to/run-in-a-container.md).

## Which scanners run on my code?

In local and container mode, every enabled scanner runs on every scan. A scanner that
finds nothing of its kind to check, such as actionlint in a repository without GitHub
Actions workflows, shows as SKIPPED. [Scanner coverage](reference/coverage.md) lists the
languages and file types each scanner checks, and the
[scanners reference](reference/scanners.md) lists each scanner's options.

## Does ASH scan my CDK app?

It scans the CloudFormation templates the app synthesizes, not the CDK source. Run
`cdk synth` before the scan, so that the templates exist under `cdk.out`. If a
`.gitignore` inside your CDK app's directory excludes `cdk.out`, ASH still scans the
`*.template.json` files in it. If the `.gitignore` at the root of the scanned directory
excludes `cdk.out`, ASH does not look inside it; scan it on its own with
`ash --source-dir cdk.out`. cdk-nag, cfn-nag, cfn-lint, and the other CloudFormation
scanners then evaluate the templates.

## A scanner hangs. What can I do?

ASH stops a scanner's tool after its `scan_timeout`, 1800 seconds by default. Set a lower
value under that scanner's options, `scanners.<name>.options.scan_timeout`, and see
[A scanner hangs](how-to/troubleshoot.md#a-scanner-hangs) for common causes.

## How do I suppress a finding?

Add a suppression with the finding's rule ID, its path, and your reason:

```yaml
global_settings:
  suppressions:
    - rule_id: B602
      path: src/build.py
      reason: The command is a constant string; no user input reaches it.
```

`ash report` shows each finding's rule ID. You can add `expiration` with a date in quotes,
such as `"2027-06-30"`; from that date the suppression stops applying, and
`ash config lint` reports it as expired. ASH also honors inline `ash-ignore` comments, and
scanners honor their own, such as bandit's `# nosec`. See
[Suppress findings](how-to/suppress-findings.md).

## How do I keep files or directories out of the results?

Add them to `global_settings.ignore_paths`, each with a reason:

```yaml
global_settings:
  ignore_paths:
    - path: tests/fixtures/**
      reason: Test data with deliberate findings.
```

ASH passes the ignore paths to every scanner. Some scanners skip those files and others
scan them, and either way ASH drops every finding located in an ignored path. ASH also
reads `.gitignore`, so directories it excludes, such as `.venv/` and `node_modules/` in
most projects, are not scanned. If they are not in `.gitignore`, add them to
`ignore_paths`. See
[Suppressions, ignore paths, and scanner exclusions](concepts/suppressions.md).

## How do I fail only on high-severity findings, or never fail on findings?

Set the threshold under `global_settings`, and `fail_on_findings` at the top level of the
file, not under `global_settings`:

```yaml
fail_on_findings: true
global_settings:
  severity_threshold: HIGH
```

With `fail_on_findings: false`, or `--no-fail-on-findings` on the command line, findings
never fail the scan. An incomplete scan, or one with a vulnerability database or offline
ruleset past its age bound, still exits 1. See [Set the gate](how-to/set-the-gate.md).

## Why do two scanners report the same problem?

ASH runs scanners whose checks overlap and does not deduplicate their findings: semgrep and
opengrep run the same ruleset, grype and trivy both check dependencies, and detect-secrets
and gitleaks both look for secrets. Each finding carries its scanner's own rule ID, so a
suppression for one does not cover the other. To keep one of a pair, turn the other off
by setting `scanners.opengrep.enabled` to `false` in the config or by passing
`--exclude-scanners opengrep`. See
[Choose scanners](how-to/choose-scanners.md).

## Does ASH work on Windows?

Local mode installs and runs on Windows, but semgrep and opengrep are off there and show as
SKIPPED, and there is no scanner sandbox. If another program named `ash` comes first on
your `PATH` (Git for Windows and MSYS2 ship a shell by that name), run ASH as `ashv3`, which
is the same command. Container mode is not tested on Windows. See
[Install ASH](how-to/install.md).

## Which GitHub Actions permissions does ASH need?

The job that calls the reusable workflow
[`run-ash-security-scan.yml`](https://github.com/awslabs/automated-security-helper/blob/main/.github/workflows/run-ash-security-scan.yml)
must grant `contents: read`, `checks: write` for its JUnit check, and `pull-requests: write`
for its pull request comment. GitHub refuses to start a call that grants fewer. Uploading results to code scanning outside same-repository pull requests
needs `security-events: write`, granted to a separate job that calls
[`upload-ash-sarif.yml`](https://github.com/awslabs/automated-security-helper/blob/main/.github/workflows/upload-ash-sarif.yml).
See [Run ASH in GitHub Actions](how-to/ci/github-actions.md).

## Can ASH run offline or in an air-gapped network?

Yes. With `--offline`, ASH runs every scanner in its offline mode and installs nothing.
Some scanners still make requests; only the scanner sandbox, or container mode with
`--offline`, removes the network itself. The rules and vulnerability databases must be in
place first; an image built with `ash build-image --offline` contains them. Each database
has an age bound, from a day to a month, and by default a scan fails when one is past it
(an image built with `OFFLINE=YES` only warns for trivy's database), so plan to rebuild
offline images often. See [Run ASH offline](how-to/run-offline.md) and
[Content databases](concepts/content-databases.md).

## What does a scan send over the network?

ASH itself sends no telemetry. The scanners download rules and vulnerability databases, and
some send data to their own services: for example, semgrep sends usage metrics to Semgrep
when it uses registry rules, and npm-audit sends your dependency tree to the npm registry.
See [what leaves the machine during a scan](concepts/scanning-untrusted-code.md#what-leaves-the-machine-during-a-scan).
