# Troubleshoot

Find the symptom, then read its cause and fix. Two places hold most of what you need:
the console output of the scan, and `ash.log` in the output directory
(`.ash/ash_output/ash.log` by default), which has every warning, including the ones the
console summary leaves out.

## Scanners that do not run

### A scanner shows MISSING {#a-scanner-shows-missing}

Symptom: a row in the summary table has the result MISSING, and the scan ends with:

```text
ERROR (1) Exiting because the scan was incomplete: 1 selected scanner(s) did not
evaluate everything they were given
  grype: MISSING
```

Cause: ASH could not find the scanner's tool, or could not install it. Earlier in the
output, and in `ash.log`, a warning names what is missing, for example
`Grype executable not found in PATH. Please ensure grype is installed.` For bandit,
checkov, semgrep, cfn-lint and zizmor, the warning
`UV tool validation failed - UV is not available but required` means the `uv` command
is not on your `PATH`, so ASH cannot install them during the scan. A scanner whose
tool is missing shows MISSING even when the project has nothing for it to scan.

Fix: install the tool, usually with `ash dependencies install --tool grype` (using the
scanner's name). [When a scanner shows MISSING](../docs/advanced-usage.md#when-a-scanner-shows-missing)
lists the exceptions: cdk-nag, npm-audit, cfn-nag and the uv-installed scanners. If you
do not need the scanner, leave it out with `ash --exclude-scanners grype`, which records
it as SKIPPED.

### A tool inside the scanned directory is not run {#a-scanner-is-missing-because-it-was-found-only-inside-the-scanned-tree}

Symptom: a scanner shows MISSING although its tool is installed, and the scan prints:

```text
Not running grype from inside the scanned tree /home/me/repo: /home/me/repo/.venv/bin/grype. To use it, install it outside the scanned tree, or set ASH_ALLOW_IN_TREE_TOOLS=1 or pass --allow-in-tree-tools to allow tools from the tree.
```

The scanner's `missing_reason` in `ash_aggregated_results.json` says the same. The
message at the end of the scan gives only the general advice to install the missing
tools.

Cause: during a scan, ASH does not run programs found inside the directory it scans.
The usual case is a scanner installed in the project's virtual environment or
`node_modules`, which `uv run` or `npm run` put first on `PATH`.

Fix: install the tool outside the repository, for example with
`ash dependencies install` or `uv tool install`. To use the in-tree copies for one
scan, pass `--allow-in-tree-tools` or set `ASH_ALLOW_IN_TREE_TOOLS=1`. `ash mcp`
ignores both. See
[Tools inside the scanned directory](../docs/advanced-usage.md#tools-inside-the-scanned-directory).

### semgrep and opengrep show SKIPPED on Windows

Cause: both are off by default on Windows, and semgrep publishes no Windows build, so
it is SKIPPED even when you turn it on. A SKIPPED scanner does not fail the scan, so
the scan passes without them.

Fix: to run them, scan from WSL or in a container. See
[Platform limits](../docs/advanced-usage.md#platform-limits).

## Exit codes

ASH exits 0 when nothing is actionable, 1 when the scan is incomplete or failed, 2 when
it has actionable findings, 3 for an invalid configuration, and 4 for a workspace
error. When a scan is both incomplete and has findings, it exits 1. See
[Exit codes](../reference/exit-codes.md).

### The scan exits 1 with no findings

Cause: the scan is incomplete, or it stopped before running. The last lines say which:

- `Exiting because the scan was incomplete`, followed by the scanners: a scanner is
  MISSING, or it ran and failed (ERROR), or it could not read some of its inputs. For
  ERROR, the scanner's own messages are in `ash.log` and in its stderr log under
  `scanners/` in the output directory.
- `Exiting because conversion was incomplete`: see the next entry.
- `Exiting because N content database(s) are past their declared age bound`: see
  [A content database is stale](#a-content-database-is-stale).
- `Scan ran no scanners`: every scanner was SKIPPED, so the scan shows nothing about
  the code. The scan then also prints `Exiting due to exception during ASH scan`,
  although no exception occurred. Check `--scanners`, `--exclude-scanners` and the
  `enabled` settings in your configuration.
- `None of the requested scanners exist`: a name in `--scanners` is misspelled. Names
  use hyphens, as `ash plugin list` shows them.

Fix: fix the cause named in the message. To accept a partial scan, pass
`--no-fail-on-incomplete-scanners`, or set `fail_on_incomplete_scanners: false` at the
top level of your configuration. The scan's own advice says to drop
`--fail-on-incomplete-scanners`, but the check is on by default, so dropping the flag
changes nothing. Excluding the scanner is usually better, because the reports then say
it did not run.

### The scan exits 1 because conversion was incomplete {#the-scan-exits-1-because-conversion-was-incomplete}

Symptom:

```text
ERROR (1) Exiting because conversion was incomplete: 1 converter(s) did not process the files they were given
```

Cause: ASH converts Jupyter notebooks to Python, and extracts `.zip`, `.tar` and `.gz`
archives, before it scans them. A notebook that `nbconvert` could not convert, or an
archive that cannot be read, fails the scan so that its content is not silently left
unscanned. The lines after the message name each file and the reason.

Fix: for notebooks, make sure `uv` is on your `PATH` so ASH can run `nbconvert`, or
install it ahead of time with `ash dependencies install --tool jupyter`. For a corrupt
archive, fix or remove the file. To skip a file, add it to `global_settings.ignore_paths`
with a reason; see [Suppress findings](suppress-findings.md).

### The scan exits 2

Cause: the scan found at least one finding at or above the severity threshold, which
is MEDIUM unless you change it. The scan ends with
`ERROR (2) Exiting due to 2 actionable findings found in ASH scan`.

Fix: fix or suppress the findings ([Suppress findings](suppress-findings.md)). To
report findings without failing, pass `--no-fail-on-findings`, or set
`fail_on_findings: false` at the top level of your configuration, not under
`global_settings`. To fail only on more severe findings, set
`global_settings.severity_threshold`. See [Set the gate](set-the-gate.md).

### The scan exits 3

Symptom:

```text
ERROR (3) Invalid configuration: Configuration validation failed for '/home/me/repo/.ash/.ash.yaml': 1 validation error for AshConfig
global_settings.fail_on_findings
  Extra inputs are not permitted
```

Cause: the configuration file has a key ASH does not know, or a value of the wrong type,
below the top level. A common case is an unquoted `expiration` date in a suppression:
YAML reads it as a date, and ASH expects text. Quote it, as in `"2027-04-30"`.

Fix: correct the key or value that the message names. `ash config get` loads and checks
the file the way a scan does. The message suggests `ash config lint`, but `lint` does
not report these errors. See [Configure ASH](configure.md).

### Your configuration has no effect

Symptom: the scan behaves as if your configuration file were not there: suppressions
do not apply, or a setting is ignored. The scan does not exit 3.

Cause: one of these:

- The file is not valid YAML. ASH logs
  `Failed to load configuration file: ... Using default configuration — suppressions and custom settings are NOT active.`
  and scans with the defaults.
- A top-level key is misspelled, such as `fail_on_finding`. ASH ignores unknown keys at
  the top level.
- ASH found a different file first. `ash config get` prints the configuration a scan
  would use.
- A suppression's `expiration` date has passed. ASH accepts a past date, and the
  suppression then matches nothing.
- The setting is one a repository's file may not set; see the next entry.

Fix: run `ash config validate`, which reports YAML errors and unknown top-level keys,
and `ash config get`, which reports errors below the top level.

### A setting in the repository's config file is ignored

Symptom: a warning such as:

```text
Ignoring sandbox.network_scanners from .ash/.ash.yaml: ...
```

Cause: some settings decide what ASH may run, read, or send: sandbox grants, plugin
modules, reporter destinations and credentials, and options that name a scanner's own
configuration or ignore file. A config file inside the scanned directory, or inside any git checkout, could have been
written by someone other than you, so ASH ignores those settings from it. The warning
names each setting and says why.

Fix: pass the setting with `--config-overrides`, or put it in a config file outside the
scanned directory and outside every git checkout and name that file with `--config`.
A scanner configuration or ignore file that such an option names must also be outside
the scanned directory. See [Trust model](../concepts/trust-model.md).

### The scan exits 4

Cause: a workspace scan (`--workspace`) could not start: the workspace file is missing
or is not valid JSON, a project path contains `..`, or a project directory does not
exist. The message names the problem.

Fix: correct the workspace file, or pass `--allow-missing-projects` to skip projects
that do not exist. See [Scale to large repositories](scale-large-repos.md).

## Output directory

### The scan stops because the output directory is a symlink {#the-scan-stops-because-something-in-the-output-directory-is-a-symlink}

Symptom: the scan exits 1 before writing anything, with one of:

```text
ERROR (1) The output directory /home/me/out is a symlink. ASH does not write to, clear or mount its output directory through a link, whatever the sandbox mode. Pass --output-dir with a directory that is not a link, or replace the link with a directory.
ERROR (1) /home/me/repo/.ash is a symlink, on the way to the output directory /home/me/repo/.ash/ash_output. ...
ERROR (1) /home/me/out/reports is a symlink. ...
```

Cause: the output directory, a directory on the way to it inside the scanned
directory, or something ASH writes inside it, such as `reports`, is a symbolic link.
ASH clears and writes its output directory, so it does not do that through a link. This
check applies whether or not the sandbox is on.

Fix: pass `--output-dir` with a real directory, which can be outside the project, or
replace the link with a directory. Turning the sandbox off does not change this.

## Content databases

### A content database is stale {#a-content-database-is-stale}

Symptom:

```text
ERROR (1) Exiting because 1 content database(s) are past their declared age bound
  Content database semgrep-offline-rules (semgrep) is stale: downloaded 2026-08-31T22:43:12Z, 40d 0h old, past its 720h bound ...
```

Cause: grype, trivy, and offline semgrep and opengrep read databases that go out of
date. ASH fails a scan whose database is older than its bound, or whose age it cannot
read: 120 hours for grype's database, 24 hours for trivy's, and 30 days for the offline
rulesets. Online scans keep grype's and trivy's databases current, so this usually
happens offline or with an old image.

Fix: refresh the database. For an offline image, rebuild it with
`ash build-image --offline`. For offline rules on your machine, download them again
([Seeding the semgrep and opengrep rule cache](../docs/advanced-usage.md#seeding-the-semgrep-and-opengrep-rule-cache)).
To scan with the old database anyway, pass `--allow-stale-content-db` or set
`content_db_staleness: warn`: the scan then passes, and every report names the stale
database. With `warn`, a scan passes even when a database is missing, so its
vulnerability results can be incomplete. See
[Content databases](../concepts/content-databases.md) and
[Run ASH offline](run-offline.md).

## Slow or stuck scans

### The first scan is slow

Cause: the first scan downloads grype's vulnerability database, which can take a
minute or more, and installs any uv-based scanner that is not installed yet. Later
scans reuse both.

Fix: run `ash dependencies install` ahead of time. In CI, cache the scanners' cache
directories, such as `~/.cache/grype` and `~/.cache/trivy`, between runs.

### A scanner hangs

Symptom: the scan stops making progress. Every 60 seconds the log shows which scanners
are still running:

```text
bandit still running on source (60s elapsed)
```

Cause: each scanner has a time limit, `scan_timeout`, which defaults to 1800 seconds
(30 minutes). A scanner that reaches it is stopped and shows as ERROR. With
`scan_timeout` set to 65, for example:

```text
(bandit @ source) timed out after 65.0s and was killed. Raise scanners.bandit.options.scan_timeout if this target legitimately needs longer.
```

There is no limit on the scan as a whole.

Fix: find the scanner in the "still running" lines or in `ash.log`, and look at its
stderr log under `scanners/<scanner>/` in the output directory. Then do one of these:

- Exclude it for now: `ash --exclude-scanners bandit`.
- Lower or raise its limit: `ash --config-overrides 'scanners.bandit.options.scan_timeout=600'`.
- Run scanners one at a time to see where time goes: `ash --strategy sequential`.
- Get more detail with `ash --verbose` or `ash --debug`.

## Installing and running ASH

### The install fails while building `rtoml`

Symptom: `uvx` or `uv tool install` fails with
`Failed to build rtoml` and a message that the Python version (3.15) is newer than
PyO3's maximum supported version.

Cause: uv chose Python 3.15, which some of ASH's dependencies do not support yet.

Fix: pass a supported Python version, as in `uv tool install --python 3.12`. See
[Install ASH](install.md).

### The install fails because git is missing

Symptom: uv stops with an error whose causes end in:

```text
  cause: Git operation failed
  cause: Git executable not found. Ensure that Git is installed and available.
```

Cause: uv and pip fetch ASH from its git repository, which needs git.

Fix: install git and run the command again.

### `ash` is not found after installing

Cause: the directory where uv or pipx puts commands is not on your `PATH` in the
current shell.

Fix: open a new terminal. If that does not help, run `uv tool update-shell` (for uv)
or `pipx ensurepath` (for pipx), then open a new terminal.

### `ash` runs a different program on Windows

Symptom: in Git Bash or an MSYS2 shell, `ash --version` prints an error such as
`ash: 0: Illegal option --`, and `ash dependencies install` reports
`cannot open dependencies`.

Cause: Git for Windows and MSYS2 ship an unrelated shell named `ash`, and it comes first
on your `PATH`.

Fix: use `ashv3` or `automated-security-helper`, which are the same program as ASH's
`ash`.

### Results differ between your machine and CI

Cause: the two runs differ in something ASH does not control:

- Scanner versions. A scanner on your `PATH` is used if its version is in range, so
  your machine and CI can run different versions.
- Database age. grype's and trivy's databases change daily.
- Platform. On Windows, semgrep and opengrep are SKIPPED.
- Diff scans. With `--changed-files-only`, ASH scans everything when the diff against
  `--base-ref` fails, which happens in shallow clones. The log then says
  `falling back to full scan`.
- Mode. `ash --mode precommit` runs a smaller set of scanners.

Fix: run the same scanner versions in both places, for example with the same container
image, and fetch enough history in CI for the diff.

## Container mode

### The container image does not build

Container mode builds ASH's image on your machine before it scans. Common causes:

- No container runtime. The scan exits 1 with `Unable to resolve an OCI runner`. ASH
  tries finch, docker, nerdctl and podman, in that order. Install one, or name it with
  `--oci-runner`.
- A non-numeric user or group ID: `Container UID must be a numeric value`. Pass numbers
  to `--container-uid` and `--container-gid`.
- An install with no version in its git URL. The image build clones ASH at the version
  you installed, and without a tag that clone fails, so later build steps fail. Install
  ASH with a tag, or pass `--ash-revision-to-install` with one.
- No access to the base image registry or the internet. The build pulls a Python base
  image and downloads ASH and its scanners. To use a mirror of the base image, set
  `ASH_BASE_IMAGE_OVERRIDE`.

Run container mode from a directory other than the project you scan, and name the
project with `--source-dir`.

If any of `CI`, `IsCI`, `ISCI` or `CODEBUILD_BUILD_ID` is set, to any value, ASH builds
the `ci` target, which runs as root, even if you pass
`ash --mode container --build-target non-root`. On
Windows, `ash build-image` always builds the `ci` target.

See [Run ASH in a container](run-in-a-container.md).
