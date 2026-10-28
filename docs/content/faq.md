# Frequently asked questions

Short answers, each with a link to the page that has the details. The config examples are
keys to add to your ASH config file. `ash config init` writes one, `.ashrc.yaml`, in the
current directory.

## Why does my first scan exit 1?

At least one scanner is MISSING: its tool is not installed, or ASH found the tool only
inside the scanned directory, such as in the project's `.venv`, and did not run it (see
[Tools inside the scanned directory](docs/advanced-usage.md#tools-inside-the-scanned-directory)).
A scan with a MISSING scanner is incomplete, and an incomplete scan exits 1 even when it
also found something. Run `ash dependencies install` to install the tools it can install.
A scanner with nothing to scan shows as SKIPPED whether or not its tool is installed, so
npm-audit and cdk-nag need Node.js, and cfn-nag needs Ruby with a C compiler, only in a
project they have something to scan in: CloudFormation templates for cdk-nag and cfn-nag,
and a lockfile beside a `package.json` for npm-audit. To scan without a tool you cannot install, leave its scanner out with
`ash --exclude-scanners cdk-nag,npm-audit`. See
[A scanner shows MISSING](how-to/troubleshoot.md#a-scanner-shows-missing) and
[Exit codes](reference/exit-codes.md).

In a project without CloudFormation templates, cdk-nag shows as SKIPPED in this scan,
with or without Node.js, so the exit code is detect-secrets' verdict alone:

<!-- doctest: run expect-exit=2 -->
```bash
ash --scanners cdk-nag,detect-secrets --no-progress
```

## How do I install ASH, and which version should I pin?

Install from GitHub, with a git URL or with Homebrew from the repository's tap;
[Install ASH](how-to/install.md) shows each method. ASH is not published on PyPI. The
PyPI project named `automated-security-helper` is not published by this project, so do not
install ASH by that name. Pin an exact release tag or a commit. The floating `v3` tag moves to
every new 3.x release, including releases with breaking changes. A pin fixes ASH's own
code, not every dependency: uv, pipx, and pip resolve ASH's dependencies again when they
install it. Homebrew installs the release its formula names, the latest one, with the
dependency versions locked in that release's `uv.lock`.

## Is there a container image?

ASH publishes no image. `ash build-image` builds one from a release tag, and
`ash --mode container` builds one and runs the scan in it. ASH uses the first of finch,
docker, nerdctl, and podman that it finds on your `PATH`, or the one you name with
`--oci-runner`. The default image runs as a non-root user whose UID and GID you can set;
`--build-target ci` builds the image that runs as root, which a job running as root
needs. See [Run ASH in a container](how-to/run-in-a-container.md#build-target).

## Which scanners run on my code?

In local and container mode, every enabled scanner runs on every scan. A scanner that
finds nothing of its kind to check, such as actionlint in a repository without GitHub
Actions workflows, shows as SKIPPED, whether or not its tool is installed. [Scanner coverage](reference/coverage.md) lists the
languages and file types each scanner checks, and the
[scanners reference](reference/scanners.md) lists each scanner's options.

## Does ASH scan my CDK app?

It scans the CloudFormation templates the app synthesizes, not the CDK source. Run
`cdk synth` before the scan, so that the templates exist under `cdk.out`. ASH scans the
`*.template.json` files there even when a `.gitignore` excludes `cdk.out`, at the root of
the scanned directory or inside your CDK app's directory, and the rest of `cdk.out`
stays out of the scan. The same holds for an assembly that `cdk synth -o` writes to
another directory. cdk-nag, cfn-nag, cfn-lint, and the other CloudFormation scanners then
evaluate the templates. To check, look for a template in the list of files the scan
read:

<!-- doctest: run expect-exit=2 -->
```bash
mkdir -p cdk.out
echo '{"Resources": {"Bucket": {"Type": "AWS::S3::Bucket"}}}' > cdk.out/App.template.json
echo cdk.out >> .gitignore
ash --scanners detect-secrets --offline --no-progress
```

```bash
grep cdk.out/App.template.json .ash/ash_output/ash-scan-set-files-list.txt
```

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

### Does ASH scan its own output, or the templates in cdk.out?
ASH leaves its own output out of the scan, whether or not `.gitignore` lists it: the output directory of the current scan, and `.ash/ash_output` under the scanned directory and under the directory ASH runs from. In a git checkout, regular files committed to one of those directories are still scanned (a committed link is not), and ASH warns that its output directory holds committed files. Outside a git checkout, or when git cannot list the repository, only the current scan's output directory is left out: an earlier run's `.ash/ash_output` is scanned like the rest of the tree, and ASH warns once per scan while the scan set still holds files in it, naming it and saying how to leave it out: delete it, or list it in an ignore file such as `.gitignore`. Adding it to `global_settings.ignore_paths` leaves its findings out, but the scan still reads it, so the warning repeats until the directory is deleted or an ignore file lists it. The output directory is recognized when it or the scanned directory is given through a link above the tree, as `/var` is on macOS. A scan does not delete or overwrite a committed file: when git tracks one where a scan writes its output (`ash_aggregated_results.json`, `ash-ignore-report.txt`, `ash-scan-set-files-list.txt`, `ash-scan-set-run.json`, `ash.log`, `ash.log.jsonl`, `.ash_previous_results_restored`, or anything under `analysis/`, `reports/`, `scanners/`, `converted/`, `.ash_previous_results/` or `.ash_previous_results.partial/`), the scan exits 3 before it deletes or writes anything, in every mode and from the MCP server. When git cannot list the repository the output directory is in (git is not installed, or it fails on the repository), any file at one of those paths stops the scan the same way, and the message names git's error and says to let git read the repository or remove the old results. A report over existing results (`--use-existing`) is stopped only where it writes: the results file, the logs, `reports/`, and `analysis/` with `--inspect` or `converted/` with `--cleanup`. A `.ash/ash_output` that is a link, or that a link inside the scanned directory leads to, is not taken as ASH's output, however the path to it is spelled, and a scan into an output directory git tracks as a link exits 3. The trivy-repo plugin still reads those directories, and ASH drops the findings it reports there, except in committed files. Any other directory is scanned, even one holding an earlier run's or another shard's results; ASH warns when a directory holds `ash_aggregated_results.json`, or both `ash-ignore-report.txt` and `ash-scan-set-files-list.txt`. Write shard output outside the scanned directory, or list it in `.gitignore`. CloudFormation templates that `cdk synth` writes (`*.template.json`) are scanned even when `.gitignore` excludes `cdk.out`, so cdk-nag and cfn-nag check them; the rest of the `cdk.out` directory stays excluded. The snyk-code plugin first refuses a run when a file in the directory it would test matches an ignore path, then tests a temporary copy of the source scan set with the ignore paths left out; converted outputs are tested in place.

### How do I scan files that a `.gitignore` excludes?
Pass `--no-honor-ignore-files`, or set `honor_ignore_files: false` in a config file outside the scanned tree. A config file inside the repository being scanned cannot change this setting. See [Ignore files and the scan set](reference/coverage.md#what-decides-the-files).

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

Yes. With `--offline`, ASH runs every scanner in its offline mode and installs nothing,
except npm-audit, which does not run offline. Some scanners still make requests; only the
scanner sandbox, or container mode with `--offline`, removes the network itself. The rules and vulnerability databases must be in
place first; an image built with `ash build-image --offline` contains them. Each database
has an age bound, from a day to a month, and by default a scan fails when one is past it
(an image built with `OFFLINE=YES` only warns for trivy's database), so plan to rebuild
offline images often. See [Run ASH offline](how-to/run-offline.md) and
[Content databases](concepts/content-databases.md).

npm, yarn, and pnpm audit a lockfile by asking the registry, so in an offline scan
npm-audit is MISSING, and the scan exits 1, for a project with a lockfile beside a
`package.json`. For a project without one it is SKIPPED. To scan such a project offline,
add `--exclude-scanners npm-audit`:

<!-- doctest: run expect-exit=1 -->
```bash
echo '{"name": "demo", "version": "1.0.0"}' > package.json
echo '{"name": "demo", "version": "1.0.0", "lockfileVersion": 3, "packages": {}}' > package-lock.json
ash --offline --scanners npm-audit,detect-secrets --no-progress
```

## What does a scan send over the network?

ASH itself sends no telemetry. The scanners download rules and vulnerability databases, and
some send data to their own services: for example, semgrep sends usage metrics to Semgrep
when it uses registry rules, and npm-audit sends your dependency tree to the npm registry.
See [what leaves the machine during a scan](concepts/scanning-untrusted-code.md#what-leaves-the-machine-during-a-scan).

## Can I use ASH programmatically?

Yes. `run_ash_scan` runs a scan from Python:

<!-- doctest: illustrative reason="scans a placeholder path; reference/python-api.md has runnable examples" -->
```python
from automated_security_helper.core.enums import RunMode
from automated_security_helper.interactions.run_ash_scan import run_ash_scan

results = run_ash_scan(
    source_dir="/path/to/code",
    output_dir="/path/to/output",
    mode=RunMode.local,
    # Return the results even when there are actionable findings
    fail_on_findings=False,
)
print(f"{results.metadata.summary_stats.actionable} actionable findings")
```

It returns the results only when the scan's exit code is 0. Otherwise it raises
`SystemExit` with that code, as `ash scan` exits with it, which is why the example passes
`fail_on_findings=False`. An incomplete scan still raises. A keyword that `run_ash_scan`
does not take raises `TypeError`. See [Python API](reference/python-api.md).
