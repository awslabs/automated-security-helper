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
    its tool grype was not found on PATH or in /home/me/.ash/bin, /home/me/.local/share/uv/tools/automated-security-helper/bin, /usr/local/bin; install it with `ash dependencies install` or exclude grype with --exclude-scanners
```

Cause: ASH could not find the scanner's tool, or could not install it. The line under
each MISSING scanner gives the reason, and so does its `missing_reason` in
`ash_aggregated_results.json`. A warning in `ash.log` names what is missing too, for
example `Grype executable not found in PATH. Please ensure grype is installed.` The
console shows it when the progress display is off (`--no-progress`). For the scanners
ASH installs with uv, one or both of these warnings mean ASH found no `uv`, neither the
copy installed with ASH, beside the Python interpreter that runs it, nor one on your
`PATH`, so it cannot install them during the scan:

```text
UV tool validation failed - UV is not available but required
UV tool execution is required but UV is not available for checkov
```

A scanner with nothing to scan in the project, such as cdk-nag with no CloudFormation
template, npm-audit with no lockfile beside a `package.json`, or actionlint with no
workflows, shows SKIPPED instead, whether or not its tool is installed. Scanners that
have no such check, such as grype and semgrep, show MISSING whenever their tool is
missing.

Fix: install the tool, usually with `ash dependencies install --tool grype` (using the
scanner's name). [When a scanner shows MISSING](../docs/advanced-usage.md#when-a-scanner-shows-missing)
lists the exceptions: detect-secrets, cdk-nag, npm-audit, and cfn-nag. If you do not need the scanner,
leave it out with `ash --exclude-scanners grype`, which records it as SKIPPED.

### A tool inside the scanned directory is not run {#a-scanner-is-missing-because-it-was-found-only-inside-the-scanned-tree}

Symptom: a scanner shows MISSING although its tool is installed, and after the list of
incomplete scanners the scan names each tool it found only inside the scanned
directory:

```text
Found only inside the scanned tree, so not run: grype (/home/me/repo/.venv/bin/grype). To use them, install it outside the scanned tree, or set ASH_ALLOW_IN_TREE_TOOLS=1 or pass --allow-in-tree-tools to allow tools from the tree.
```

`ash.log` has a warning for each one (the console shows it too when the progress display
is off):

```text
Not running grype from inside the scanned tree /home/me/repo: /home/me/repo/.venv/bin/grype. To use it, install it outside the scanned tree, or set ASH_ALLOW_IN_TREE_TOOLS=1 or pass --allow-in-tree-tools to allow tools from the tree.
```

The scanner's `missing_reason` in `ash_aggregated_results.json` records the reason, as
"grype was found only inside the scanned tree, at ...".

Cause: during a scan, ASH does not run programs found inside the directory it scans.
The usual case is a scanner installed in the project's virtual environment or
`node_modules`, which `uv run` or `npm run` put first on `PATH`.

Fix: install the tool outside the repository, for example with
`ash dependencies install` or `uv tool install`. To use the in-tree copies for one
scan, pass `--allow-in-tree-tools` or set `ASH_ALLOW_IN_TREE_TOOLS=1`. `ash mcp`
ignores both. See
[Tools inside the scanned directory](../docs/advanced-usage.md#tools-inside-the-scanned-directory).

### A scanner is ERROR with an exit code it does not accept {#a-scanner-is-error-with-an-exit-code-it-does-not-accept}

Symptom: a scanner's row is `ERROR`, and its error names the tool's exit code:

```text
Failed to execute semgrep scanner on source: SemgrepScanner scan failed: its tool exited with code 7, which this scanner does not accept as a completed run, so its results file is not graded (exit code 7: not an accepted exit code; success_exit_codes=[0, 1]). No stderr captured; checked .ash/ash_output/scanners/semgrep/source/SemgrepScanner.stderr.log, which the tool did not write. .ash/ash_output/scanners/semgrep/source/results_sarif.sarif reports: Invalid YAML file ...
```

Cause: the tool reported that it failed. Each scanner accepts the exit codes its tool uses
for a run that completed, with or without findings, and nothing else. A failed tool
can still leave a results file (semgrep exits 7 and writes SARIF holding only error
notifications when it cannot read a rule configuration; grype exits 1 and writes a
zero-byte report when it cannot load its database), so ASH does not read the file of
a run with any other code: an empty or error-only file would otherwise be graded
`PASSED` with no findings. A tool ended by a signal shows as `128 + N` (129 for
SIGHUP, 130 for SIGINT, 137 for SIGKILL). 127 is a tool the OS could not start, or
a run ASH itself failed to carry out (the scanner's errors name ASH's error).

| Scanner | Accepted exit codes | What the tool uses other codes for |
|---|---|---|
| bandit | 0, 1 (issues found) | 2: any error (`bandit/cli/main.py`) |
| checkov | 0, 1 (failed checks) | 2: the run crashed (`checkov/main.py`) |
| grype | 0, 2 (a match at or above `grype --fail-on`) | 1: any error, such as a database it cannot load (`cmd/grype/cli/cli.go`) |
| semgrep | 0, 1 (findings) | 2: fatal; 3 and up: specific failures, 7 for a rule configuration it cannot read (`semgrep/error.py`) |
| opengrep | 0, 1 | the same values as semgrep (`src/osemgrep/core/Exit_code.ml`) |
| trivy, trivy-repo | 0 | 1: any error (`cmd/trivy/main.go`) |
| syft | 0 | 1: any error (`cmd/syft/main.go`) |
| ferret-scan | 0, 3 (coverage cut short under `fail_on_incomplete`: the findings are reported and the row is `ERROR`, as its target counts as failed) | 1: any error |
| snyk-code | 0, 1 (issues found) | 2: an error; 3: no supported project (`src/cli/exit-codes.ts`) |
| gitleaks | 0, 2 (leaks found: ASH runs `gitleaks --exit-code=2`) | 1: any error, such as an unreadable config; gitleaks exits 1 for leaks too unless told otherwise, which is why ASH moves the leaks code |
| zizmor | 0, 3 (nothing it could audit; findings never set the status because ASH runs `zizmor --no-exit-codes`) | any other status |
| hadolint | 0 (ASH runs `hadolint --no-fail`) | any other status |
| actionlint | 0, 1 (problems found) | 2: a bad command line; 3: a fatal error, such as an unreadable file |
| cfn-lint | 0 and the even values up to 14: 2 error, 4 warning and 8 informational, added together for a run with more than one level (`cfnlint/runner/cli.py`) | 1: a fatal error, so any odd status; anything above 15 |
| cfn-guard | 0, 19 (at least one rule failed) | any other status, such as 255 for a parse error or a missing rules path |
| guarddog | 0, with output on stdout | any other status |

trivy exits 0 for a run with findings unless its `exit-code` setting names another
code. ASH runs trivy and trivy-repo with `trivy --exit-code=0`, which outranks an
`exit-code` in the operator's trivy config and `TRIVY_EXIT_CODE` (measured with trivy
0.75.0), and neither scanner reads a `trivy.yaml` from the scanned directory, so a
run with findings exits 0 and a nonzero exit only ever means trivy failed. ASH
decides the scan's exit code from the findings itself.

cfn-nag, npm audit, detect-secrets and cdk-nag are not in this table. cfn-nag exits
with its count of failing violations and is judged per template; npm audit exits 1
both for advisories and for errors and is judged by whether it wrote a report;
detect-secrets and cdk-nag run in ASH's own worker processes.

Fix: read what the message quotes, and fix what the tool reported: its stderr, or, when
it wrote none (semgrep and opengrep report a rule file they cannot read only in
their SARIF), the error-level notifications from its results file, which the
message names. The full text is in the `<Scanner>.stderr.log`, the
`<Scanner>.stdout.log` and the results file under `scanners/<name>/<target>/` in the
output directory; the message names the ones the tool wrote.
For semgrep and opengrep under `--offline`, see
[Seeding the semgrep and opengrep rule cache](../docs/advanced-usage.md#seeding-the-semgrep-and-opengrep-rule-cache).
For grype, see [What each scanner does offline](run-offline.md#scanners).

The scan exits 1 for an `ERROR` scanner while `fail_on_incomplete_scanners` is on,
which is the default. With it off, the exit code comes from the findings alone, so a
scan whose only problem is the failed scanner exits 0; see
[Incomplete scans](set-the-gate.md#incomplete).

### semgrep and opengrep show SKIPPED on Windows

Cause: both are off by default on Windows, and semgrep publishes no Windows build, so
it is SKIPPED even when you turn it on. A SKIPPED scanner does not fail the scan, so
the scan passes without them, as long as another selected scanner runs.

Fix: to run them, scan from WSL or in a container. See
[Platform limits](../docs/advanced-usage.md#platform-limits).

## Exit codes

ASH exits 0 when nothing is actionable, 1 when the scan is incomplete or failed, 2 when
it has actionable findings at or above the threshold, 3 for a configuration it cannot use
or an input it refuses before scanning, such as a linked output directory, 4 for a
workspace error, and 5 for a usage error. When a scan is both incomplete and has
findings, it exits 1 (a workspace scan exits 2). See
[Exit codes](../reference/exit-codes.md).

### The scan exits 1 with no findings {#the-scan-exits-1-with-no-findings}

Cause: the scan is incomplete, or it stopped before running. The last lines say which:

- `Exiting because the scan was incomplete`, followed by the scanners: a scanner is
  MISSING, or it ran and failed (ERROR), or it could not read some of its inputs. For
  ERROR, the scanner's own messages are in `ash.log` and in its stderr log under
  `scanners/` in the output directory.
- `Exiting because conversion was incomplete`: see the next entry.
- `Exiting because N content database(s) are past their declared age bound`: see
  [A content database is stale](#a-content-database-is-stale).
- `Exiting because no scanner ran`: every scanner was SKIPPED, so the scan shows
  nothing about the code. Each scanner's `skipped_reason` in
  `ash_aggregated_results.json` says why. Check `--scanners`, `--exclude-scanners`, and
  the `enabled` settings in your configuration.
- A message that no selected scanner had a file to scan: see
  [No selected scanner had a file to scan](#no-selected-scanner-had-a-file-to-scan).
- `Exiting because N rule(s) could not be evaluated`: cdk-nag rules failed with an
  error on your templates, so the scan says nothing about them. Fix the template the
  rule fails on, or suppress that rule's findings for the template.

Fix: fix the cause named in the message. To accept an incomplete scan, pass
`--no-fail-on-incomplete-scanners`, as the scan's message says, or set
`fail_on_incomplete_scanners: false` at the top level of your configuration. Excluding
the scanner is usually better, because the reports then say it did not run.

### No selected scanner had a file to scan {#no-selected-scanner-had-a-file-to-scan}

Symptom: the scan exits 1 with no findings, every selected scanner is SKIPPED, and the
error names the scanners that had nothing to scan:

```text
No selected scanner had a file to scan: bandit was SKIPPED with nothing to scan, so this run has shown the target to be neither clean nor dirty. To accept a run that scanned nothing, set fail_on_incomplete_scanners: false or pass --no-fail-on-incomplete-scanners.
```

When the config sets `global_settings.ignore_paths`, the error also shows its first three
patterns, with a count of any others, and suggests narrowing them:

```text
No selected scanner had a file to scan: detect-secrets was SKIPPED with nothing to scan, so this run has shown the target to be neither clean nor dirty. The config's global_settings.ignore_paths ('**') leaves every path it matches out of what the scanners read, which can leave them nothing to scan; narrow it to have those files scanned. To accept a run that scanned nothing, set fail_on_incomplete_scanners: false or pass --no-fail-on-incomplete-scanners.
```

A run whose scanners were all SKIPPED for another reason, such as a `--scanners` name
that matches no scanner on this platform, or every selected scanner turned off in the
configuration, reports `Scan ran no scanners:` instead, with each scanner and its status;
see [The scan exits 1 with no findings](#the-scan-exits-1-with-no-findings).

Cause: each selected scanner had nothing to read, so the scan shows nothing about the
code. A scanner that reads only some files, such as cfn-nag with no CloudFormation
template or bandit with no Python file, has nothing to read in a project without them,
and no scanner has anything to read when the scan set is empty. Two cases are ERROR
instead, and the error gives a count. semgrep and opengrep are ERROR when their own
exclusions, rather than `ignore_paths`, left out every file they found. bandit is ERROR
when it scanned no file although Python files that nothing excludes are there; when
`ignore_paths` or bandit's own `excluded_paths` leave out every Python file, bandit is
SKIPPED.

Fix: check that `--source-dir` names the project, that `ignore_paths`, and the
repository's `.gitignore` and `.ignore` files, leave the files you mean to scan, and that
the scanners you selected read them; [Scanner coverage](../reference/coverage.md) lists
what each scanner reads. To accept such a scan, pass `--no-fail-on-incomplete-scanners`
or set `fail_on_incomplete_scanners: false`; it then exits 0. `ash merge` gives the same
verdict over the shards.

### The scan exits 1 because conversion was incomplete {#the-scan-exits-1-because-conversion-was-incomplete}

Symptom:

```text
ERROR (1) Exiting because conversion was incomplete: 1 converter(s) did not process the files they were given
```

Cause: ASH converts Jupyter notebooks to Python, and extracts `.zip`, `.tar`, and `.gz`
archives, before it scans them. A notebook that `nbconvert` could not convert, or an
archive that cannot be read, fails the scan so that its content is not silently left
unscanned. The lines after the message name each converter and up to five of the files
it could not convert, or, for a converter that crashed, its error as `<Type>: <message>`.
`ash.log` has a line for each file with the reason, `Could not convert '<file>': <reason>`
(the console shows it too when the progress display is off), and each converter's
`failed_inputs` in `ash_aggregated_results.json` records the same reason. A reason that
comes from an unexpected error is the error's type and message, such as
`BadZipFile: Bad CRC-32 for file 'app.py'`. For a notebook, the reason says that nbconvert
exited with a non-zero code, did not finish within 60 seconds, or wrote no output, or that
uv could not run nbconvert and no `jupyter-nbconvert` was found.

A notebook in an offline scan with no nbconvert installed gives
`jupyter: dependencies unavailable, so it never ran`, because ASH does not install
nbconvert offline.

Fix: for notebooks, install nbconvert ahead of time with
`ash dependencies install --tool jupyter`, or let ASH install it during an online scan.
To see nbconvert's own error output, run the scan again with `--debug`. For a corrupt
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

### The command exits 5 {#the-command-exits-5}

Symptom: the command stops before anything runs and writes no report. A mistyped option
prints an `Error` box:

```text
Usage: ash scan [OPTIONS]
Try 'ash scan --help' for help.
╭─ Error ──────────────────────────────────────────────────────────────────────╮
│ No such option: --fail-on-finding (Possible options: --fail-on-findings,     │
│ --no-fail-on-findings)                                                       │
╰──────────────────────────────────────────────────────────────────────────────╯
```

Cause: a usage error. Every `ash` command exits 5 when its command line is wrong: an
option or argument the command does not take, a value an option does not accept (such
as an invalid `--output-formats`, `--mode`, `--strategy`, or `--min-severity`), a
`--scanners` list that names no scanner, a `--source-dir` that does not exist or
cannot be entered, an `--output-dir` that ASH cannot create, enter, or write in,
`--use-existing` with no results to use, or an `ash report --format` that no reporter
answers to. The code is not 2, so a CI gate does not read a mistyped flag as a scan
with findings. Two selections exit 2 instead: an `ash dependencies install --tool` name
that it has no plugin for, and a `--plugin-type` other than `converter`, `scanner`, or
`reporter` ([Exit codes](../reference/exit-codes.md#other)).

<!-- doctest: run expect-exit=5 -->
```bash
ash scan --output-formats nosuch
```

`ash report` with a format no reporter answers to lists the ones it has, whether or not
there are results to report:

<!-- doctest: run expect-exit=5 -->
```bash
ash report --format nosuch
```

```text
Error: Reporter plugin 'nosuch' not found.
Available reporter formats:
  - csv
  - cyclonedx
  - github-ghas
  ...
```

Fix: correct the command line; `ash <command> --help` lists each command's options.
Scanner and reporter names use hyphens, as `ash plugin list` shows them. A single
misspelled name among valid ones in `--scanners` is not a usage error: ASH logs
`No registered scanner matches ...` and runs the others.

### The scan exits 3

Symptom:

```text
ERROR (3) Invalid configuration: Configuration validation failed for '/home/me/repo/.ashrc.yaml': Invalid value at 'global_settings.fail_on_findings': Extra inputs are not permitted. Run: ash config lint --config /home/me/repo/.ashrc.yaml
```

Cause: the configuration file has a key ASH does not know below the top level, or a
value of the wrong type anywhere, top level included. A suppression, an ignore path, or
a plugin's options with a key ASH does not know is refused too, and the message lists
the keys it accepts:

<!-- doctest: run expect-exit=3 -->
```bash
cat > .ashrc.yaml <<'EOF'
global_settings:
  suppressions:
    - rule_id: B602
      path: app.py
      reason: Commands come from a fixed allowlist
      expires: "2027-04-30"
EOF
ash config validate
```

```text
❌ 1 error(s); a scan refuses the configuration because of these:
  1. Invalid value at 'global_settings.suppressions[0]': Value error, Unknown key 'expires' (did you mean 'expiration'?) in a suppression. Accepted keys: expiration, line_end, line_start, package_name, package_path, package_version, path, reason, rule_id, symbol.
```

A common case is an unquoted `expiration` date in a suppression: YAML reads it as a
date, and ASH expects text. Quote it, as in `"2027-04-30"`.

Fix: correct the key or value that the message names. `ash config validate` and
`ash config lint` check the file the way a scan does and report the same errors, with
exit code 3; `lint` marks each one `[blocks the scan]`. See
[Configure ASH](configure.md).

### Your configuration has no effect

Symptom: the scan behaves as if your configuration file were not there: suppressions
do not apply, or a setting is ignored. The scan does not exit 3.

Cause: one of these. A file that does not exist or does not parse is not one of them:
the scan refuses it with exit 3.

- A top-level key is misspelled, such as `fail_on_finding`. ASH ignores unknown keys at
  the top level.
- ASH found a different file first. `ash config get` prints the configuration a scan
  would use.
- A suppression's or an ignore path's `expiration` date has passed. The entry then
  stops applying, and the scan starts with a warning that names it (see below).
- The setting is one a repository's file may not set; see the next entry.

An ignore path that expired lets its files back into the scan, so the finding in `app.py`
counts again here:

<!-- doctest: run expect-exit=2 -->
```bash
cat > .ashrc.yaml <<'EOF'
global_settings:
  ignore_paths:
    - path: app.py
      reason: Generated file, scanned upstream
      expiration: "2026-01-31"
EOF
ash scan --scanners detect-secrets --no-progress
```

```text
The following ignore paths and suppressions have expired and no longer apply:
  - Ignore path 'app.py' expired on 2026-01-31. Reason: Generated file, scanned upstream
Remove them, or move their expiration dates, in your ASH configuration file.
```

Fix: run `ash config validate`, which checks the file the way a scan does and warns
about unknown top-level keys and a missing `project_name`, and `ash config get`, which
prints the configuration a scan would use. `ash config lint` also lists expired
suppressions and ignore paths.

### A setting in the repository's config file is ignored

Symptom: a warning such as:

```text
Ignoring sandbox.network_scanners from /home/me/repo/.ash/.ash.yaml: that config is inside a git checkout or the scanned tree, or was delivered by an MCP client. ...
```

Cause: some settings decide what ASH may run, read, or send, or whether a stale database
fails the scan: sandbox grants, plugin modules, reporter destinations and credentials,
options that name a scanner's own configuration or ignore file, `tool_version`, trivy-repo's
`disable_telemetry: false`, and a relaxed `content_db_staleness`. A config file inside the scanned directory, or inside any git
checkout, could have been written by someone other than you, so ASH ignores those settings
from it, even from a config you keep in an ops repository of its own. These settings count
as yours only from `--config-overrides` or a config file outside every git checkout and the
scanned directory. The warning names each
setting and the file, says why, and says how to keep the setting. For a plugin module
found inside a git checkout or the scanned directory, it also gives where Python found the
module and which checkout or directory that is. For other modules, it says that the module
is not importable, or what ASH's AWS or Snyk plugin package would send off the host.

Under `ash mcp`, a config file that an MCP client names as a scan's `config_path`, outside
the directories `ASH_MCP_ALLOWED_CONFIG_ROOTS` names, is held to the same limits. Under the
default policy, a config file an MCP client delivered is refused instead when its own `sandbox`
section gives a scanner a network or an `extra_read_paths` entry the server's settings do
not, or changes a sandbox mode other than `off` that the server sets, or when its own
`ash_plugin_modules` list adds a module this check would drop; see
[What a delivered config cannot set](mcp-server.md#what-a-delivered-config-cannot-set).

Fix: pass the setting with `--config-overrides`, or move the file outside every git
checkout, such as under `/etc/ash`, and name it with `--config`. A file inside the scanned
directory has to move out of it as well. Name a plugin module with `--ash-plugin-modules`, or install it outside
every git checkout and the scanned directory. A config inside a checkout cannot add ASH's
AWS or Snyk plugin package at all, so name those with `--ash-plugin-modules` or one of the
two ways above.
For some scanners, the file such an option names must also be outside the scanned
tree; [Options only the operator can set](choose-scanners.md#operator-only) says
which. See [Configuration trust model](../concepts/trust-model.md).

### The scan exits 4

Cause: a workspace scan (`--workspace`) could not start, or a workspace option was used
without one. The message names the problem. The causes are:

- the workspace file is missing or is not valid JSON;
- `--workspace auto` finds more than one workspace file;
- a project path contains `..`, or a project directory does not exist;
- `--source-dir` is given with `--workspace`;
- `--dry-run`, `--allow-missing-projects`, or `--workspace-config` is given without
  `--workspace`.

Fix: correct the workspace file or the command line, or pass `--allow-missing-projects`
to skip projects that do not exist. See [Scale to large repositories](scale-large-repos.md).

## Output directory

### The scan stops because the output directory is a symlink {#the-scan-stops-because-something-in-the-output-directory-is-a-symlink}

Symptom: the scan exits 3 before writing anything, with one of:

```text
ERROR (3) The output directory /home/me/out is a symlink. ASH does not write to, clear or mount its output directory through a link, whatever the sandbox mode. Pass --output-dir with a directory that is not a link, or replace the link with a directory.
ERROR (3) /home/me/repo/.ash is a symlink, on the way to the output directory /home/me/repo/.ash/ash_output. ...
ERROR (3) /home/me/out/reports is a symlink. ...
```

Cause: the output directory, a directory on the way to it inside the scanned
directory, or something ASH writes inside it, such as `reports`, is a symbolic link.
ASH clears and writes its output directory, so it does not do that through a link. This
check applies whether or not the sandbox is on. In an `ash --workspace` scan, a link at
`projects/<project>` fails only that project, and a link at `projects` or
`.workspace-spool` stops the whole run. [Output files](../reference/output-files.md#links)
lists every path ASH checks.

Fix: pass `--output-dir` with a real directory, which can be outside the project, or
replace the link with a directory. Turning the sandbox off does not change this.

### The scan stops because a report file is a link

Symptom: the run exits 1 before any reporter writes, with this message (`ash merge`
prints the same text after `Refusing to write reports:`):

```text
ERROR (1) /home/me/out/reports/ash.sarif is a symlink. ASH does not write a report through a link. Remove the link and run ASH again.
```

Cause: a file a reporter is about to write in `reports/` is a symbolic link or a
directory junction. A scan clears `reports/` first, so this usually comes from
`ash scan --use-existing` or `ash merge` writing into an output directory that already
holds the link.

Fix: remove the link and run the command again, or write to a new output directory.

## Content databases

### A content database is stale {#a-content-database-is-stale}

Symptom:

```text
ERROR (1) Exiting because 1 content database(s) are past their declared age bound
  Content database semgrep-offline-rules (semgrep) is stale: downloaded 2026-08-31T22:43:12Z, 40d 0h old, past its 720h bound ...
```

Cause: grype, trivy, and offline semgrep and opengrep read databases that go out of
date. ASH fails a scan whose database is past its age bound, or whose age it cannot
read; [Content databases](../concepts/content-databases.md) lists the bounds. Online
scans keep grype's and trivy's databases current, so this usually happens offline or
with an old image.

Fix: refresh the database. For an offline image, rebuild it with
`ash build-image --offline`. For offline rules on your machine, download them again
([Seeding the semgrep and opengrep rule cache](../docs/advanced-usage.md#seeding-the-semgrep-and-opengrep-rule-cache)).
To scan with the old database anyway, pass `--allow-stale-content-db` or set
`content_db_staleness: warn`: the stale database then no longer fails the scan, and
every report names it. With `warn`, a scan passes even when a database is missing, so its
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
- Diff scans. With `--changed-files-only`, ASH reports findings in every file when git
  cannot list the changes: the base ref does not exist, as in a shallow clone, the
  directory is not in a git repository, or git is not installed. The log says which,
  such as `git diff against origin/main failed (rc=128); falling back to full scan`.
- Mode. `ash --mode precommit` runs a smaller set of scanners.

Fix: run the same scanner versions in both places, for example with the same container
image, and fetch enough history in CI for the diff.

## Container mode

### The container image does not build

Container mode builds ASH's image on your machine before it scans. Common causes:

- No container runtime. The scan exits 1 with `Unable to resolve an OCI runner`. ASH
  tries finch, docker, nerdctl, and podman, in that order. Install one, or name it with
  `--oci-runner`.
- A non-numeric user or group ID: `Container UID must be a numeric value`. Pass numbers
  to `--container-uid` and `--container-gid`.
- No revision to install. A package that recorded no commit, such as one built from a
  source tarball, installs the release tag of its version, and a development or
  pre-release version has none, so the build stops and asks for
  `--ash-revision-to-install`. Pass a tag, a branch, or a full commit ID.
  [Which ASH goes into the image](run-in-a-container.md#revision) lists where the
  revision comes from for each kind of install.
- No access to the base image registry or the internet. The build pulls a Python base
  image and downloads ASH and its scanners. To use a mirror of the base image, set
  `ASH_BASE_IMAGE_OVERRIDE`.

Run container mode from a directory other than the project you scan, and name the
project with `--source-dir`.

To scan offline with an image you already built, add `--no-build`, as in
`ash scan --mode container --offline --no-build`. Without it, container mode builds the
image first, and the first offline build of a UTC day downloads the databases again,
which needs network access. See [Run ASH offline](run-offline.md).

With `--custom-containerfile`, ASH builds the `ci` target, which runs as root, even if you
pass `--build-target non-root`. On Windows, ASH builds `ci` unless you name a target. A
`non-root` build that would give its user UID 0 or GID 0, as a job running as root does,
stops with exit code 3 before anything is built: pass `--build-target ci` there.

See [Run ASH in a container](run-in-a-container.md).
