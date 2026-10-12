# Configuration Guide

ASH v3 uses a YAML configuration file to control its behavior. This guide explains how to configure ASH for your project.

## Configuration File Location

ASH reads its configuration from one source. When `--config` (or the
`ASH_CONFIG` environment variable) names a file, that file is used. Otherwise
ASH looks in the source directory in this order and uses the first source it
finds:

1. `.ash.yml`
2. `.ash/.ash.yml`
3. `.ash.yaml`
4. `.ash/.ash.yaml`
5. `.ash.json`
6. `.ash/.ash.json`
7. `ash.yml`
8. `.ash/ash.yml`
9. `ash.yaml`
10. `.ash/ash.yaml`
11. `ash.json`
12. `.ash/ash.json`
13. `.ashrc.toml`
14. `.ashrc.yaml`
15. `.ashrc.yml`
16. `.ashrc.json`
17. `ashrc.toml`
18. `ashrc.yaml`
19. `ashrc.yml`
20. `ashrc.json`
21. `pyproject.toml`

Items 1-12 are checked per filename, not per directory: for each name ASH checks
the source directory and then its `.ash/` subdirectory, so `.ash.yml` in the
source directory beats `.ash/.ash.yaml`. Items 13-21 are checked in the source
directory only. A `pyproject.toml` counts only when it has a `[tool.ash]` table;
one without that table is not a config source. The lists come from
`ASH_CONFIG_FILE_NAMES`, `ASH_RC_FILE_NAMES` and `ASH_PYPROJECT_FILE_NAME` in
`automated_security_helper/core/constants.py`.

Sources are never merged. If more than one exists, ASH logs which one it used
and logs a warning naming each one it ignored, once. The scan repeats each of
those warnings under "CONFIGURATION WARNING" in its summary and records it in the
results as a `config_warning` entry of `validation_checkpoints`, because the
settings in an ignored source are not applied; `ash merge` keeps one copy of a
warning every shard recorded. The names in items 1-12 are
deprecated in favor of an `ashrc` file or `[tool.ash]`, and the warning says so
when one of them shadows a newer source. They still take precedence, so adding a
`[tool.ash]` table to a repository that already has `.ash/.ash.yaml` does not
change which settings a scan uses until the older file is removed.

Scan results are written to `.ash/ash_output` whichever source is used.

You can also specify a custom configuration file path using the `--config` option:

```bash
ash --config /path/to/my-config.yaml
```

In a single-directory scan, that file replaces discovery, so the repository's own
config is not read. In workspace mode (`ash --workspace`) it is layered over each
project's own config instead: every field it sets is final for every project, and
a project's config fills only the fields it leaves unset. See
[The operator's config](cli-reference.md#the-operators-config).

### A config file that cannot be loaded stops the scan

ASH uses its built-in default configuration only when there is no config file at
all: none named and none found in the source directory. A config file that is
named or found and cannot be loaded stops the scan with exit code 3 before any
scanner runs, and the message names the file. That covers:

- a file named by `--config`, `ASH_CONFIG`, the `config` argument of
  `run_ash_scan()` or an MCP tool's `config_path` that does not exist, and an
  empty `--config ""`. An empty `ASH_CONFIG` counts as unset;
- a named or discovered file that is not valid YAML, JSON or TOML, is not UTF-8,
  cannot be read, is larger than 1 MiB, uses a YAML alias (`*name`), or is a
  directory, FIFO, device or other non-regular file. A syntax error, and an
  alias, names its line. A file that is not a regular file is refused without
  being read, so a FIFO or `/dev/zero` at a config name does not stall the scan.
  A leading UTF-8 byte order mark is accepted in YAML, JSON and TOML alike.
  Aliases are refused in every YAML ASH reads as configuration (config files,
  `extends` bases, workspace policy files, MCP profiles and a client's
  `override_yaml`), because a few hundred bytes of nested aliases expand to
  gigabytes when the config is written into the results; an anchor (`&name`)
  that nothing refers to is accepted;
- a dangling symbolic link at one of the names above, for example
  `.ash/.ash.yaml` linked to a shared file that is not checked out. It is not
  treated as "no config";
- a `pyproject.toml` that cannot be read at all, when it would be the source ASH
  uses: ASH cannot tell whether it holds a `[tool.ash]` table;
- a config name ASH cannot look for, such as one inside an `.ash/` directory
  that cannot be searched: ASH cannot tell whether the file is there.

Scanning with the defaults instead would run without the file's suppressions,
ignore paths, thresholds and sandbox settings, and report the scan as completed.
The same applies to `ash report`, `ash plugin list`, `ash dependencies install`,
`ash config get` and `ash config wizard` (each exits 3; the wizard leaves the
file as it was rather than rewriting it from the defaults), to workspace mode (see
[Workspace mode](cli-reference.md#workspace-mode)), and to the MCP server:
`scan_directory` refuses such a file, and an empty `config_path`, before it
starts a scan, a workspace scan's session profile that does not load is reported
as an invalid configuration (exit code 3), and `get_config` (with or without `raw`)
returns an error instead of the default configuration, with `error_category` `file_not_found` for a file
that does not exist and `invalid_format` for one that does not load. A config
file outside the session's allowed config roots is refused as outside them
before anything reads it, so the response says nothing about its contents. That
includes a config source found in the scanned directory: a `pyproject.toml`, a
config file or an `.ash/` directory that is a symbolic link out of the roots is
refused before discovery opens it, with the same response whether its target is
missing, unreadable or readable.

### Configuring ASH in pyproject.toml

`[tool.ash]` holds the same settings as `.ash.yaml`, written as TOML, and is
validated by the same schema:

```toml
[tool.ash]
project_name = "my-service"
fail_on_findings = true

[tool.ash.global_settings]
severity_threshold = "MEDIUM"
ignore_paths = [{ path = "tests/fixtures/**", reason = "Test fixtures" }]

[[tool.ash.global_settings.suppressions]]
rule_id = "B101"
path = "tests/**"
reason = "assert is expected in tests"

[tool.ash.scanners.bandit]
enabled = true
```

A validation error names the table and its line, for example
`pyproject.toml [tool.ash] (line 12)`. String values beginning with `${` are
resolved from the environment by the same rule as in YAML, including the limit
on which variable names may be read; see the `!ENV` notes in
[Configuration Overrides](config-overrides.md).
`ash config update`, `ash config wizard`, `ash config lint --fix` and the
suppression dialog in `ash inspect` edit YAML, so they refuse a TOML file rather
than rewrite it; edit `[tool.ash]` by hand.

A `pyproject.toml` that is not valid TOML is skipped, unless its text declares a
`[tool.ash]` table, in which case the scan fails instead of running with the
default configuration. One that cannot be read at all (a dangling link, no
permission) fails the scan when it would be the source ASH uses; behind a
higher-precedence file it is only logged.

## Creating a Configuration File

The easiest way to create a configuration file is to use the `config init` command:

```bash
ash config init
```

This creates a default configuration file at `.ash/.ash.yaml` with recommended settings.

## Configuration Structure

The ASH configuration file has the following main sections:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/main/automated_security_helper/schemas/AshConfig.json
project_name: my-project
global_settings:
  severity_threshold: MEDIUM
  ignore_paths: []
fail_on_incomplete_scanners: true
converters:
  # Converter plugins configuration
scanners:
  # Scanner plugins configuration
reporters:
  # Reporter plugins configuration
ash_plugin_modules: []
```

### Failing on an incomplete scan

`fail_on_incomplete_scanners` is a top-level key, and it is on by default. ASH exits
1 when a scanner you selected did not complete — status `ERROR` (it ran and failed)
or `MISSING` (its dependencies were unavailable, so it never ran) — and prints which
ones.

It is on rather than off because a scanner recorded `ERROR` or `MISSING` produces no
findings, so with the gate off that scan reports the exit code of a clean one. That is
the one failure a reader cannot see: the crash is visible in the log, the false
all-clear is not. A host that genuinely cannot provide a scanner's tool says so once,
with the key below or `--no-fail-on-incomplete-scanners`, and keeps its old exit codes.

It selects on status, so it covers a failure only once that failure has reached the
status. A tool's own failure does reach it: a scanner whose tool exits with a code
outside the codes that scanner accepts for a completed run is `ERROR`, whatever its
results file holds, and the row records the exit code and the tool's stderr. A failed
tool can still leave a results file behind (semgrep writes SARIF holding only error
notifications when it cannot read its rules, grype a zero-byte report when it cannot
load its database), and "found nothing" and "never scanned" look the same in it, so
that file is not read. The accepted codes per scanner are in
[Scanner exit codes](troubleshooting.md#a-scanner-is-error-with-an-exit-code-it-does-not-accept).
A results file ASH cannot read as SARIF is `ERROR` too, whatever the exit code, as is
an empty results file, SARIF with no run, and a scanner result that carries nothing
to grade (a dict with no `status`, `severity_counts` or `findings`, a dict whose
`status` does not say its tool completed, or a list or string from a scanner's own
`scan()`); none of them can show that the target is clean. The scanners ASH ships
write SARIF with one run even when there is nothing for them to scan. So is a scanner whose tool reports that its content database does not exist;
see [Failing on a stale content database](#failing-on-a-stale-content-database).

With the key off, an `ERROR` scanner no longer fails the scan: the exit code comes from
the findings alone, so a scan whose only problem is a failed scanner exits 0, the same
code as a clean scan. That is what turning the gate off means, and the summary table
still shows the `ERROR` row.

It covers converters too: a converter that crashed, one that could not convert some of
its inputs (`converter_results.<name>.failed_inputs`), and one whose tool is missing
while it had inputs make the scan exit 1, as an incomplete scanner does, in `ash merge`
and per project in workspace mode as well.

`SKIPPED` scanners are ones you did not select and never trip it, which is what
keeps a sharded scan working: each shard excludes the scanners its siblings own,
and those are recorded as `SKIPPED`. Narrowing a run with `--scanners` or
`--exclude-scanners` also records the scanners you left out as `SKIPPED`, so
selecting a subset does not fail the gate.

To accept a partial scan's exit code, set it to `false`:

```yaml
fail_on_incomplete_scanners: false
```

Prefer excluding the scanner whose tool you do not have. `false` makes ASH exit 0
for a scan where nothing ran, which is the same code as a scan where everything
ran and found nothing; excluding the scanner records it as `SKIPPED` and says so
in the report, so the next reader can see what was and was not measured.

It is independent of `fail_on_findings` in both directions. `fail_on_findings:
false` still reports an incomplete scan, and when both would fail the exit code is
1 rather than 2, because clearing the findings that were reported would not make
the scan complete. See
[An incomplete scan is not a clean scan](cli-reference.md#an-incomplete-scan-is-not-a-clean-scan).

### Failing on a stale content database

`content_db_staleness` is a top-level key, and it defaults to `fail`. After each
scanner that matches against a content database, ASH reads that database's own
build time and compares it to the bound declared for it in
`automated_security_helper/utils/content_databases.py`. Past the bound, the scan
exits 1 and names the database, when it was built, how old it is, the bound, and
how to refresh it. This happens in online and offline mode alike.

| Database | Scanner | Bound | Where the bound comes from | Age read from |
| --- | --- | --- | --- | --- |
| `grype-db` | grype | 120h (5 days) | grype's own default, `db.max-allowed-built-age` | `built` in `grype db status -o json` |
| `trivy-db` | trivy-repo, unless its `scanners` list leaves out `vuln`, and trivy | 24h | trivy's own rule: a database is current until its `NextUpdate`, which the published database sets 24h after `UpdatedAt` | `VulnerabilityDB.UpdatedAt` in `trivy version --format json` |
| `semgrep-offline-rules` | semgrep (offline only) | 720h (30 days) | ASH's own choice; semgrep has no staleness notion for local rules | `.ash-rules-fetched-at` in `$SEMGREP_RULES_CACHE_DIR`, else the oldest rules file's mtime |
| `opengrep-offline-rules` | opengrep (offline only) | 720h (30 days) | ASH's own choice; opengrep has no staleness notion for local rules | `.ash-rules-fetched-at` in `$OPENGREP_RULES_CACHE_DIR`, else the oldest rules file's mtime |

A database whose build time cannot be read is treated as stale, because an
unmeasurable database is not evidence of a fresh one. So is a database whose build
time is more than 15 minutes ahead of the host's clock: its age cannot be measured,
and the message says so.

A database the tool reports does not exist at all (grype's `database does not
exist`, no `VulnerabilityDB` from trivy, no rules files in the offline rules
directory) also makes that scanner `ERROR`, under `fail` and `warn` alike: the scan had
nothing to match against, so its zero findings are not a result. `warn` relaxes the
age bound for a database that exists.

To let one scan run against a stale database, pass `--allow-stale-content-db`, or
set:

```yaml
content_db_staleness: warn
```

Under `warn` the scan proceeds, and the warning is written to the log and into the
reports: a `### Stale content databases` section in `ash.summary.md`, a `STALE
CONTENT DATABASES` section in `ash.summary.txt`, a `toolConfigurationNotifications`
entry with descriptor id `ASH-CONTENT-DB-STALE` on the scanner's invocation in
`ash.sarif`, and a `content_databases` list in `ash.flat.json` with `stale: true`
and `enforced: false`. A reader of any of those can see the scan ran against an
out-of-date database.

To relax one database without relaxing the others, for example while an upstream
publisher is not publishing, name it in `content_db_staleness_overrides`:

```yaml
content_db_staleness: fail
content_db_staleness_overrides:
  - database: trivy-db        # a name from the table above
    policy: warn
    expiration: "2026-10-11"  # YYYY-MM-DD; required
    reason: "Upstream trivy-db publishing is failing"  # required
```

The entry applies only to the database it names, so every other database is
still held to `content_db_staleness`. It stops applying at 00:00 UTC on its
expiration date: from then on it is ignored, with a warning in the log, and the
database is held to the policy it has without the entry. That is
`content_db_staleness`, except for `trivy-db` in an image built with
`OFFLINE=YES`, which returns to that image's `warn` default described below. A
stale database relaxed this way is reported the same as under `warn`, and the
message names the entry and its expiry. Each database can appear in at most one
entry, and an unknown database name is a config error. The list is empty by
default.

An image built with `OFFLINE=YES` (`ash build-image --offline`) holds `trivy-db` to
`warn` rather than to `content_db_staleness: fail`. The image carries the trivy
database it was built with, and the 24h bound would otherwise fail every scan in it
from a day after the build. So those scans pass, and each report records the stale
database as it does under `warn`, with a message saying the offline image's default
let the scan pass. Only `trivy-db` is relaxed: `grype-db` and the offline rulesets
still fail the scan once they are past their bounds. What turns this on is
`ASH_OFFLINE_AT_BUILD_TIME=YES` in ASH's environment, which the image sets from its
`OFFLINE` build argument and nothing else in ASH sets; the config cannot turn it on,
and a process given that variable some other way gets the same default. To hold
`trivy-db` to `content_db_staleness` in the image as well:

```yaml
content_db_staleness_offline_image_default: false  # default true
```

A `content_db_staleness_overrides` entry for `trivy-db` outranks this default, and
once the entry expires the database returns to it.

The CLI flag takes precedence over the config value in both directions:
`--no-allow-stale-content-db` restores `fail` for one scan even when the config
says `warn`, and either form of the flag also clears
`content_db_staleness_overrides` and sets `content_db_staleness_offline_image_default`
to false for that scan, so it decides for every database, `trivy-db` in an offline
image included. Like `fail_on_incomplete_scanners`, none of these keys can be
changed by an MCP runtime patch.

Relaxing the check is the operator's choice. Set `warn`, or an entry with
`policy: warn`, with the flag, `--config-overrides` or a config file outside the
scanned tree. From a config file inside the tree (a repository's
`.ash/.ash.yaml`, or a workspace project's own config) they are ignored with a
warning naming the key, unless they equal the operator's value. `fail`, and an
entry with `policy: fail`, only make the check stricter, so they apply from any
config. See [Settings a repository's config cannot choose](#settings-a-repositorys-config-cannot-choose).

This gate is independent of `fail_on_incomplete_scanners` and does not need it
turned on. When the scan also has actionable findings, the exit code is 1 rather
than 2: clearing the reported findings would not make a scan against a stale
database trustworthy.

### Ignore files and the scan set

Before the scanners run, ASH builds a scan set: the list of files in the source
directory that detect-secrets, cfn-nag, cdk-nag, npm-audit and the archive and
Jupyter converters read. By default every file a `.gitignore` or `.ignore` in the
scanned tree matches is left out of it, as git would leave it out. A nested ignore
file applies to the directory it sits in, a later negation (`!keep.log`) puts a file
back, and a directory the root `.gitignore` excludes is not entered at all, so the
ignore files inside it are not read. ASH also leaves out files on its own: `.git`,
CDK assets under `cdk.out/asset.*`, its bundled aws-cdk tree, and its own output
directory when that is inside the source directory. A CloudFormation
template (`*.template.json`) an ignore file matches is kept, unless it sits in a
directory the root `.gitignore` excludes. bandit, semgrep, opengrep, checkov, grype
and syft walk the source directory themselves, with their own ignore rules, so this
setting does not change what they read: in a git checkout, semgrep and opengrep
still skip the files git ignores. snyk-code passes the source directory to the Snyk
CLI as it is.

A link to a file is in the scan set only when its target, with every link on the way
resolved, is inside the source directory. A link that leaves the tree (to an absolute
path elsewhere, up through `..`, or through a link to a directory outside) is not
scanned: a warning names it, as `Not scanning 'vendor/config.py': link leaves the
scanned tree`, and names only the link, not where it points. Each one is also listed
as an input not scanned, under `ASH`: in `ash_aggregated_results.json` under
`metadata.inputs_not_scanned` (`path` and `reason`), in the console summary, and in
the "Inputs not scanned" section of `ash.summary.md` and `ash.summary.txt`; in a
workspace scan, in that project's `inputs_not_scanned` entry. A link to a file inside
the tree stays in the scan set, and a source directory that is itself reached through
a link is scanned as given. This applies to the readers of the scan set listed above.

The scanners that walk the directory they scan themselves do not read the scan set.
So ASH tells each of them to skip every link to a file whose target leaves that
directory, or does not run it on that directory:

- bandit reads a link to a file wherever it points (measured with bandit 1.9.4). ASH
  adds each such link to bandit's `--exclude`, as the link's own path.
- checkov reads a link to a file wherever it points, whether the target is relative
  or absolute, and does not enter a link to a directory (measured with checkov
  3.3.26). ASH passes one `--skip-path` for each such link, escaped and anchored so
  that it matches that path and no other: skipping `a/main.tf` does not skip
  `a/main.tf.json`. These values are ASH's own; the `skip_path` values in your
  config are passed as they are.
- ferret-scan is given each such link in its `--exclude`, relative to the directory
  it scans. How ferret-scan treats links has not been measured.
- grype and syft follow neither a link to a file nor a link to a directory whose
  target leaves the directory they scan (measured with grype 0.120.1 and syft
  1.54.1). Each such link is still passed in their `--exclude`, as `./` and its
  path with the glob characters escaped, which leaves out that path and no other.
- trivy (the `trivy-repo` scanner) skips every link, inside the tree or not
  (measured with trivy 0.75.0). Each such link is still passed in `--skip-files`,
  glob characters escaped, unless its path holds a comma, a double quote or a line
  break, which trivy's option cannot carry. Such a link is named in a debug log
  line (`--log-level DEBUG`).
- semgrep and opengrep skip every link, inside the tree or not (measured with
  semgrep 1.180.0 and opengrep 1.30.2), and get no exclusion for one. Their
  `--exclude` cannot name one path: semgrep matches a pattern against paths below
  the git checkout's root when the scanned directory is inside one, and opengrep
  matches a top-level name at every depth. A link's name passed in `--exclude` could
  be one of the scanned directory's own names, and then semgrep left out every file
  in it.
- snyk-code uploads the files it reads to Snyk, `snyk code test` has no option that
  leaves out one path, and how it treats links has not been measured by running it.
  So ASH does not run it on a directory holding such a link, or a link to a
  directory whose target is outside it (`creds -> ~/.aws`). Snyk's sources list
  files without walking into a link to a directory, but that has been read, not
  measured.

ASH finds these links the way the tools walk: it does not read ignore files, so a
link in a directory a `.gitignore` excludes is skipped too, and it does not enter a
link to a directory. When bandit, checkov or ferret-scan cannot be given a link's
path, ASH does not run that tool on that directory, rather than let it read the file
the link points at; the same goes for snyk-code and any such link. The scanner's
status is `ERROR`, and the error names the link, as `Not running bandit on /src:
'a,b.py': link leaves the scanned tree, and bandit's --exclude cannot leave out that
file alone, ... (bandit was not started)`. It carries no exit code, since the tool
did not run. bandit cannot be given a path with a comma or one of `*`, `?` and
`[`, or a path that another file's path contains, because it also leaves out every
path an entry is part of. ferret-scan cannot be given a path with a comma or any of
`*?[]{}\`. checkov cannot be given any on Windows, where it joins the paths it walks
with `\`. For the scanners that follow no such link, a path their option cannot
carry is only left out of it, and on Windows none is passed.

`honor_ignore_files` is a top-level key, and it defaults to `true`. To scan the files
the repository's ignore files match as well, set it to `false` in a config file
outside the scanned tree, or for one scan:

```bash
ash --source-dir . --no-honor-ignore-files
ash --source-dir . --config-overrides 'honor_ignore_files=false'
```

ASH's own exclusions still apply then. `--honor-ignore-files` sets it back to `true`
for one scan. Either form of the flag takes precedence over the config value, and
in container mode the flag reaches the scan inside the container. In workspace mode
it applies to every project.

Whether the repository's ignore files hide its own files is the operator's decision,
so a config file inside the scanned tree cannot set this key in either direction;
see [Settings a repository's config cannot choose](#settings-a-repositorys-config-cannot-choose).
An MCP client cannot set it either: a client's config file is treated the same way,
and `/honor_ignore_files` is in the default `runtime_overrides.denied_paths`.

Every scan records the outcome in `ash_aggregated_results.json`, under
`metadata.ignore_file_exclusions`:

```json
"ignore_file_exclusions": {
  "honored": true,
  "excluded_file_count": 7,
  "by_ignore_file": {
    ".gitignore": 3,
    ".ignore": 1,
    "vendor/.gitignore": 2,
    "sub/.ignore": 1,
    "sub/deep/.gitignore": 0
  },
  "output_dir_file_count": 0
}
```

`excluded_file_count` is the number of files the ignore files removed, counted from
the scan set itself: every file the walk found that is not in it, less the ones ASH
leaves out on its own. `by_ignore_file` says which ignore file removed each one. Each
ignore file is listed by its path relative to the source directory, with 0 when it
removed nothing. A line that starts with `#` is a comment, as in git, and is not
copied into `ash-ignore-report.txt`. The files under a
directory the root `.gitignore` excludes count for the root `.gitignore`. A symlink
(or junction) to a directory is never followed, so the files behind it are in no scan
set and are not counted. With `honor_ignore_files: false` the record reads
`"honored": false` with a count of 0.

ASH's own output directory is left out whatever `honor_ignore_files` says. It is
recognized as the same directory however its path is spelled (through a link in the
source path, or as `/src/.ash/ash_output` and `/out` in container mode), not by its
name; on a file system that reports no inode numbers, its absolute path decides
instead. Files that are already in it when the scan set is built, this run's
`ash.log` and `ash.log.jsonl` aside, are counted in `output_dir_file_count`, also when
it sits under a directory the root `.gitignore` excludes, and the summaries say
they were left out, and a warning names the directory. They are an earlier run's
output, or repository files that sit where ASH writes; to scan repository files
there, write ASH's output outside the scanned tree with `--output-dir`.

When the output directory is inside the source directory, ASH also writes a
`.gitignore` there holding `*` before any scanner starts, unless something is
already at that name. A tool that reads the tree itself and honors `.gitignore`
files then leaves ASH's output out too, and so does git. An existing `.gitignore`
there is left as it is, nothing is written for an output directory outside the tree,
and a link at that name stops the scan with exit code 3, as one at `ash.log` does.
snyk-code does not rely on the file: `snyk code test` uploads what it reads, and that
it honors a `.gitignore` is read from snyk's sources, not measured, so snyk-code
refuses a source directory that holds ASH's output directory. Pass `--output-dir`
with a directory outside the scanned tree to run snyk-code on the source.

`ash.summary.txt` and `ash.summary.md` print the total in their scan metadata, for
example `Ignore files: the scanned repository's .gitignore and .ignore files
excluded 7 files from ASH's scan set`, or say that the ignore files were not
honored.
`ash report --format text` and `--format markdown` print the same line from the
stored results. The MCP `get_scan_summary` tool returns the record under
`metadata.ignore_file_exclusions`. In a workspace scan, each project's record is in
`workspace.projects[].ignore_file_exclusions`, and the merged results and summaries
carry the workspace total, with each ignore file keyed by its path relative to the
workspace root. When the merged scans disagree (some projects, or some `ash merge`
shards, honored the ignore files and some did not), the record also carries
`honored_scan_count` and `scan_count`, `honored` is false, and the summaries say,
for example, `honored by 1 of 2 merged scans and not by the other 1
(honor_ignore_files: false); the ignore files that were applied excluded 7 files from
ASH's scan sets`. A project or shard that recorded no ignore-file record (it built no
scan set, or an older ASH wrote its results) is not counted in `scan_count`. A record
whose counts contradict each other or `honored` prints `recorded inconsistently`
instead of either sentence. The log names every ignore file and its count at INFO
level, and
`ash-ignore-report.txt` in the output directory holds the rules that were applied.

### Global Settings

The `global_settings` section controls general behavior:

```yaml
global_settings:
  # Minimum severity level to consider findings actionable
  # Options: CRITICAL, HIGH, MEDIUM, LOW, INFO
  severity_threshold: MEDIUM

  # Paths to ignore during scanning
  ignore_paths:
    - path: 'tests/test_data/'
      reason: 'Test data only'
    - path: '**/vendor/'
      reason: 'Vendored third-party code'

  # Findings to suppress based on rule ID, file path, and line numbers
  suppressions:
    - rule_id: 'RULE-123'  # Scanner-specific rule ID
      path: 'src/example.py'  # File path (supports glob patterns)
      line_start: 10  # Optional starting line number
      line_end: 15  # Optional ending line number
      reason: 'False positive due to test mock'  # Reason for suppression
      expiration: '2025-12-31'  # Optional expiration date (YYYY-MM-DD)
```

An ignore path's `path` is a glob matched against a file's path below the source
directory, anchored at both ends, with `**` for any number of directories. One
ending in `/` names a directory and ignores what is inside it, as `<dir>/*/**`
does, never a file of that name: `tests/test_data/` is what is inside the
top-level `tests/test_data` directory, and `**/vendor/` what is inside a `vendor`
directory at any depth. So `**/.*/` ignores the files in dot-directories such as
`.git/` and `.cache/`, and not dotfiles such as `.env`. An ignore path drops every
finding below it, a dependency scanner's included, so `**/node_modules/` hides
the vulnerabilities npm-audit reports. A path naming a
directory without the slash, such as `tests/test_data`, matches no file in it, and
`ash config lint` warns about one. A suppression's `path` is read differently: one
ending in `/` matches no file, and ASH warns after the scan about each such
suppression that matched nothing, naming the `<dir>/**/*` that would. bandit and
checkov also skip `node_modules`, `.venv` and `venv` directories on their own; ASH
does not drop findings there, since the dependency scanners report theirs there
(npm-audit at `node_modules/<package>/package.json`).

An ignore path is a suppression. ASH does not convert a file under one or include
it in the file lists it hands scanners, and leaves a finding any scanner reports
there out of the results. The scanners that walk the directory themselves are also
told to leave out the files an ignore path matches, matched the same way: each
ignored file, or once for a directory whose every file is ignored.

- bandit: in its `--exclude`;
- grype and syft: `--exclude ./<path>`, and `./<dir>/**` for a directory;
- trivy-repo: `--skip-files` and `--skip-dirs`;
- checkov: one `--skip-path` each, anchored so it matches that path alone;
- semgrep and opengrep: `--exclude=<name>`, only for a name that nothing else
  below the scanned directory, and nothing in that directory's own path, has.

A path a tool's option cannot carry (one with a comma for bandit and trivy, or a
name that is not unique for semgrep and opengrep) is still read by that tool, and
ASH drops what it finds there. snyk-code has no option that leaves out a path and
uploads the files it reads, so it refuses a directory holding a file an ignore path
matches, whether the source directory or ASH's directory of converted files,
wherever that is. Each file is matched as ASH matches the location snyk reports for
a finding in it, its path below the directory snyk tests, so a file is refused
exactly when the operator's ignore paths would have ASH drop its findings: a
converted file by its path below the directory of converted files, such as
`archive/src__bundle__zip/vendor/m.js`. An
ignore path naming a source archive or notebook exactly keeps it from being
converted at all. It is `ERROR`,
`snyk code test` is not started, and the error names the first such file and the
pattern that matched it, gives the number of files and the patterns, and suggests
narrowing `ignore_paths` or `--exclude-scanners snyk-code`. On Windows the other
tools are given none of these.
`--ignore-suppressions` lifts ignore paths along with
suppressions: every scanner reads those files and their findings are reported. See
[Temporarily Disabling Suppressions](suppressions.md#temporarily-disabling-suppressions).

Omitting `line_end` does **not** suppress only `line_start`. A suppression with
`line_start` and no `line_end` matches every finding from that line to the end of
the file, including findings introduced later. To suppress a single line, set
`line_end` to the same value as `line_start`. To follow a function or class
when lines move, use `symbol` instead; see
[Suppressing by symbol](suppressions.md#suppressing-by-symbol).

```yaml
    - rule_id: 'RULE-123'
      path: 'src/example.py'
      line_start: 10
      line_end: 10  # Without this, lines 10 onwards are all suppressed
      reason: 'False positive due to test mock'
    - rule_id: 'RULE-456'
      path: 'src/*.js'  # Glob pattern matching all JS files in src/
      reason: 'Known issue, planned for fix in v2.0'
    - rule_id: 'B602'
      path: 'src/deploy.py'
      symbol: 'Deployer.run_hook'  # Only findings inside this method; needs the [symbols] extra
      reason: 'Hook command comes from the signed manifest'

  # Whether to fail with non-zero exit code if actionable findings are found
  fail_on_findings: true
```

### Converters Configuration

The `converters` section configures file converters that transform files before scanning:

```yaml
converters:
  jupyter:
    enabled: true
    options:
      tool_version: null      # Version constraint for the conversion tool
      install_timeout: 300    # Seconds allowed for tool installation
  archive:
    enabled: true
    options:                  # Extraction limits; a config in the scanned tree can only lower them
      max_members: 100000
      max_member_bytes: 268435456
      max_total_bytes: 1073741824
      max_compression_ratio: 100
```

The archive converter's options bound what extracting one archive may write; see
[Extraction limits](plugins/builtin/converters.md#extraction-limits).

### Scanners Configuration

The `scanners` section configures security scanners:

```yaml
scanners:
  bandit:
    enabled: true
    options:
      confidence_level: high     # all | low | medium | high (lowercase)
      severity_threshold: MEDIUM # ALL | LOW | MEDIUM | HIGH | CRITICAL (uppercase)

  semgrep:
    enabled: true
    options:
      config: 'p/ci'        # Ruleset, directory, or URL passed to --config
      exclude_rule: []      # Rule IDs to skip
      tool_version: null    # Version constraint (e.g., '>=1.125.0')
      install_timeout: 300  # Timeout in seconds for tool installation

  detect-secrets:
    enabled: true
    options:
      baseline_file: null   # Path to a detect-secrets baseline, relative to the config file that sets it

  checkov:
    enabled: true
    options:
      frameworks: ['all']   # Note the plural; 'framework' is not a field
      skip_path: []         # Paths to skip, matched as regular expressions
      tool_version: null    # Version constraint (e.g., '>=3.2.0,<4.0.0')
      install_timeout: 300  # Timeout in seconds for tool installation

  cfn-nag:
    enabled: true
    options:
      severity_threshold: MEDIUM

  cdk-nag:
    enabled: true
    options:
      nag_packs:            # An object of per-pack booleans, not a list
        AwsSolutionsChecks: true
        HIPAASecurityChecks: false

  npm-audit:
    enabled: true
    options:
      severity_threshold: MEDIUM

  grype:
    enabled: true
    options:
      severity_threshold: MEDIUM

  syft:
    enabled: true
    options:
      exclude: []           # Paths to skip, as globs starting ./, */ or **/
```

Two conventions differ between fields, and both are enforced: `severity_threshold`
accepts only uppercase (`ALL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), while bandit's
`confidence_level` accepts only lowercase (`all`, `low`, `medium`, `high`). The wrong
case is rejected with a validation error rather than coerced.

#### An unrecognized option is accepted and ignored

Scanner option models allow extra keys, so a misspelled or invented option does not
raise an error -- it is stored and never read. `severity_level: medium` on bandit
validates cleanly and changes nothing, because bandit reads `severity_threshold`.
When a setting appears to have no effect, check the option name against
[the built-in scanner reference](plugins/builtin/scanners.md) before assuming the
scanner ignored the value.

#### Bounding how long a scanner may run

Every scanner accepts `scan_timeout`, the number of seconds its tool invocation may
run before it is killed. The default is `1800` (30 minutes). Set it to `null` to leave
a scanner unbounded:

```yaml
scanners:
  semgrep:
    options:
      scan_timeout: 3600  # An hour for a large repository
  syft:
    options:
      scan_timeout: null  # No limit
```

A scanner killed by its timeout produces no results file, so the scan fails with an
error naming the scanner and the limit (`<scanner> timed out after 1800.0s`) rather
than silently reporting zero findings for it. Whatever the tool wrote before it was
killed is kept in `scanners/<name>/<target>/<Scanner>.stderr.log` under the output
directory. While a scanner runs, ASH logs `<scanner> still running on <target>
(<N>s elapsed)` at INFO once a minute, so a hung scanner is named in a CI log without
any extra flag. `scan_timeout` bounds the scan itself; `install_timeout` separately
bounds tool installation and defaults to `300`.

### Reporters Configuration

The `reporters` section configures output report formats:

```yaml
reporters:
  markdown:
    enabled: true
    options:
      include_detailed_findings: true

  html:
    enabled: true             # The HTML reporter exposes no options

  flat-json:                  # Note the hyphen; there is no 'json' reporter
    enabled: true
    options:
      include_metadata: true
      include_scanner_metrics: true

  csv:
    enabled: true             # The CSV reporter exposes no options

  sarif:
    enabled: true             # The SARIF reporter exposes no options

  github-ghas:
    enabled: true
    options:
      exclude_suppressed: true  # Exclude ASH-suppressed findings (default)
```

### Custom Plugin Modules

The `ash_plugin_modules` section allows you to specify custom Python modules containing ASH plugins:

```yaml
ash_plugin_modules:
  - my_custom_ash_plugins
  - another_ash_plugins
```

Each entry must be a dotted path of Python identifiers inside ASH's plugin namespace:
under `automated_security_helper.` or `ash_plugins`, or a top-level package named
`ash_plugins` or ending in `_ash_plugins` (`my_ash_plugins`, but not `myash_plugins`).
ASH's plugin root `automated_security_helper.plugin_modules` holds every plugin package
ASH ships and names none of them, so name the package below it (for example
`automated_security_helper.plugin_modules.ash_trivy_plugins`). A namespace package (a
directory with no `__init__.py`, which can gather packages from several distributions)
declares no plugins either, so name the packages it holds. One entry may name several
modules separated by commas, and spaces around each name are ignored, whether the entry
comes from a config file, `--config-overrides`, `--ash-plugin-modules` or
`ASH_PLUGIN_MODULES`. Any other entry, such as `another_plugin_module`, the plugin root,
a namespace package, or a name with a space inside it, refuses the scan with exit code 3
(invalid configuration) before any module is imported, from any of those sources. The
same name refuses `ash plugin list`, `ash dependencies install`, `ash report` and `ash
merge` with exit code 3. A module that is named correctly but does not import, because
it is not installed or its import raises an error, refuses a scan with exit code 3 too,
before any scanner runs, and refuses `ash plugin list`, `ash dependencies install` and
`ash report` the same way; the message names the module and the error. `ash config
validate` and the MCP `validate_config` tool report a name a scan refuses as a
validation error; they import nothing, so they do not check whether an accepted name
imports. When the list comes from
a config file inside the scanned tree, only installed modules are imported; see
[Settings a repository's config cannot choose](#settings-a-repositorys-config-cannot-choose).

A scan uses ASH's built-in plugins (those defined in
`automated_security_helper.plugin_modules.ash_builtin`) plus the converters, scanners,
reporters and event handlers of the modules its own `ash_plugin_modules` (from its config and
`--ash-plugin-modules`) names. A module's plugins are those it defines itself, imports
into its namespace, or lists in its `ASH_*` declarations; naming a package does not
select a plugin that only one of its subpackages defines, so name that subpackage. This holds when one process runs several scans, as the
MCP server does: a module that an earlier scan named, or that the MCP `list_scanners`
tool loaded to describe the community scanners, takes no part in a scan that does not
name it, and a module that only a later scan names takes part in that scan. An event
handler defined outside ASH's plugin namespace, such as one a program that calls
`run_ash_scan` subscribes with `ash_plugin_manager.subscribe`, is notified in every
scan that program runs.

## Settings a repository's config cannot choose

ASH reads its configuration from the repository it scans unless `--config` names a
file elsewhere. A few settings decide what ASH installs, imports or hands a scanner
as its own configuration, so they are limited when someone other than the operator
could have written them. Two terms are used below:

- **Repository-written**: inside any git checkout, or inside the source directory
  when that is outside every checkout. A checkout is something other people can push
  to, so this includes a checkout of your own, such as an ops or dotfiles
  repository. Under the MCP server, a file any MCP client delivered counts too:
  everything under the MCP workspace root (`$ASH_MCP_WORKSPACE_ROOT`, by default
  `~/.cache/ash-mcp/`) except the profile files the server writes in each session's
  `config/` directory: `ash.yaml`, the profile `select_profile` binds, and a workspace
  tool's per-call profile, one file per profile named `call-profile-` followed by 16
  lowercase hex digits and `.yaml` (or `call-profile.yaml`). Only a file directly in
  `config/` with one of those names is the server's. Any other file there is the
  client's, and neither `config/` nor `client-config/` may be a scan target or an
  output directory. A profile a client patched with `select_profile` is written to
  the session's `client-config/` directory instead, so it counts as the client's.
- **The scanned tree**: the source directory, or the outermost git checkout holding
  it.

A file is judged by the path as written, relative to the source directory, by the
file it resolves to, and by every symlink resolving it follows, so a symlink the
scanned repository planted counts where it sits and where it points, and so does a
path of your own that leads through one.

A config is limited when any file it was built from is repository-written: a
discovered `.ash/.ash.yaml`, a `--config` path, an `extends` base, or the file
`ASH_CONFIG` names. Under the MCP server, a config file a client delivered (an upload
or a file in a delivered tree, named as `config_path`) is limited the same way,
wherever it is. Pass `ash_plugin_modules` and the sandbox settings with
`--ash-plugin-modules` or `--config-overrides` instead, or keep the config file
outside every checkout.

A file that one of the path settings below names is judged by who named it:

- **Named by the operator**, with `--config-overrides`, in a config file that is not
  repository-written (outside every git checkout and the source directory), or
  through an environment variable such as `TRIVY_IGNOREFILE`: it is passed to the
  tool unless it is inside the scanned tree or an MCP client delivered it. A tool
  config or ignore file kept in an ops repository works.
- **Named by a repository-written config or one an MCP client delivered**, or found
  by name in the source directory: it is passed only when the file is not
  repository-written, so the repository cannot point a tool at a file in someone's
  checkout. A config file kept in an ops checkout is repository-written too, as it
  is for the other settings here, so the paths it names follow this rule, a tool
  config in that same checkout included. The warning says how to keep the setting:
  move the config file outside every git checkout, or pass the setting with
  `--config-overrides`.

When the operator's config file extends a repository-written one, only the paths the
operator's file writes itself count as the operator's. An MCP client's
`config_overrides`, and a session profile its `select_profile` `patch_ops` or
`override_yaml` changed, count as the client's.

| Setting | Limit |
|---|---|
| `scanners.<name>.options.tool_version`, `converters.<name>.options.tool_version` | Taken from the defaults, `--config-overrides` or a config file outside the tree, for every scanner and converter, including those a plugin module adds. It chooses which release of the tool ASH installs and which one already on `PATH` it accepts. A value equal to the operator's applies; any other is ignored with a warning, and the operator's value or the tool's default constraint applies. From every source, including `--config-overrides`, it must also be a PEP 440 version specifier set such as `>=1.2,<2` or `==1.4.1`; any other value is replaced by the default constraint. |
| `scanners.opengrep.options.version` | Must be a release tag such as `v1.15.1`, from every source. Any other value is replaced by the pinned version. |
| `content_db_staleness`, `content_db_staleness_overrides`, `content_db_staleness_offline_image_default` | `warn`, an overrides entry with `policy: warn`, and an offline image default of `true` where the operator's is `false`, are taken from the defaults, `--allow-stale-content-db`, `--config-overrides` or a config file outside the tree. From the tree's config such a value is ignored with a warning unless it equals the operator's, and the scan fails on a stale database as by default. `fail`, an entry with `policy: fail`, and an offline image default of `false` apply from every config. See [Failing on a stale content database](#failing-on-a-stale-content-database). |
| `ash_plugin_modules` | From a repository-written config, an entry is imported only if it names an installed module that Python finds in a location that is not repository-written. An entry in the plugin namespace that is not importable, or that would be imported from such a location, is skipped. A virtualenv inside a git checkout counts as inside it, so a module installed there is skipped too; the warning gives the module's location and the checkout. So are `automated_security_helper.plugin_modules.ash_aws_plugins` and `automated_security_helper.plugin_modules.ash_snyk_plugins`, and any module inside either: the AWS reporters send findings to AWS with the operator's credentials, and the Snyk Code scanner sends the scanned source to Snyk with the operator's Snyk token, so only `--ash-plugin-modules` (or `ASH_PLUGIN_MODULES`), `--config-overrides` or a config file that is not repository-written can add them. The same holds for their classes when another package a repository-written config loads lists or imports them: a scanner or reporter defined in either package is selected only when one of those operator sources loads that package, a module inside it, or the package that lists the class, and each one dropped is named in a warning. Where one process runs several scans, under the MCP server and in a workspace run, a later scan that does not load the module itself is not offered the classes such an entry's import registered, and the same holds for a module an operator source names: each scan uses only the modules it names. An entry outside the namespace refuses the scan with exit code 3, as it does from any config source (see [Custom Plugin Modules](#custom-plugin-modules)). |
| `scanners.checkov.options.config_file`, `scanners.ferret-scan.options.config_file` | Passed to the tool by the rule above. The same applies to the `.checkov.yaml` and `ferret.yaml` files these scanners look for by name. ferret-scan then uses its bundled config. checkov and ferret-scan also read such a file from their working directory on their own, so ASH runs both from the filesystem root and always passes ferret-scan a `--config`; finding paths are unchanged. |
| `scanners.detect-secrets.options.scan_settings` plugins and filters | An entry that names a file (`file://...`) is kept by the rule above. Entries read from a baseline file count as named inside the scanned tree. detect-secrets' built-in plugins and filters are unaffected. |
| `scanners.detect-secrets.options.baseline_file` | Taken from the defaults, `--config-overrides` or a config file that is not repository-written. A baseline an MCP client delivered is not read. Under a sandbox, a baseline outside the source tree is read only when `sandbox.read_path_scanners` names detect-secrets and the file is inside a `sandbox.extra_read_paths` entry. |
| trivy's and trivy-repo's ignore file and secret config | Both always get `--ignorefile` and `--secret-config`, so trivy does not read a `.trivyignore` or `trivy-secret.yaml` from the scanned repository. `scanners.trivy.options.ignore_file` and `secret_config_file` (and trivy-repo's), set by `--config-overrides` or a config file outside the scanned tree, or else `TRIVY_IGNOREFILE` and `TRIVY_SECRET_CONFIG`, name the files to use; each is passed only when it is outside the scanned tree, and not reached through a symbolic link in the tree, and otherwise trivy gets a file that sets nothing, which ASH writes outside the scanned tree. |
| `scanners.trivy.options.config_file`, `scanners.trivy-repo.options.config_file` and `module_dir`, `scanners.cfn-lint.options.config_file` | Ignored with a warning. Honored only from `--config-overrides` or a config file outside the scanned tree, and only for a path outside the tree that no symbolic link in the tree leads to, because these files can make the tool load code (trivy modules, cfn-lint `append_rules`). Without them the tool gets an empty config of ASH's. |
| `scanners.actionlint.options.config_file`, `scanners.gitleaks.options.config_file` and `baseline_path`, `scanners.zizmor.options.config_file`, `scanners.cfn-guard.options.rules_paths` | Ignored with a warning, and the tool runs without it: on ASH's own empty or default-rules config, or for cfn-guard on the bundled rule sets. Honored from `--config-overrides` or a config file outside the scanned tree, where the file named may also be inside the tree, unless it leads out of the tree through a symbolic link there: then the scanner reports `ERROR` (cfn-guard `MISSING`) and the tool is not run. |
| `scanners.actionlint.options.shellcheck` and `pyflakes` | Only the option's own name (`shellcheck`, `pyflakes`), looked up on `PATH`. Another program, or a path, only from the operator. A program that resolves inside the scanned tree, or that a path in the tree reaches through a symbolic link there, is refused whoever set it. |
| `scanners.trivy.options.scanners` | Ignored with a warning unless it is the default, `[vuln]`: a repository could otherwise turn vulnerability scanning off. Another set only from `--config-overrides` or a config file outside the scanned tree. |
| `scanners.zizmor.options.online_audits` | Ignored with a warning: zizmor runs `--offline` without GitHub tokens. Only the operator turns online audits on. |
| `sandbox.network_scanners`, `sandbox.extra_read_paths`, `sandbox.read_path_scanners`, `sandbox.env_scanners` | Not used from a repository-written config: these grant sandbox access. A `network_scanners` list still removes network from the scanners it does not name. See [Scanner sandbox](scanner-sandbox.md). |
| `sandbox.mode` | From a repository-written config, applies only when nothing the operator set turns the sandbox on. When `--sandbox`, `ASH_CONFIG` or the operator's config file turns it on, this cannot turn it off or switch backends. |
| `honor_ignore_files` | Not honored in either direction. The value comes from a config file that is not repository-written, `--config-overrides`, `--no-honor-ignore-files` / `--honor-ignore-files`, or the default `true`. See [Ignore files and the scan set](#ignore-files-and-the-scan-set). |
| `scanners.bandit.options.config_file`, `scanners.grype.options.config_file`, `scanners.syft.options.config_file` | Taken from the defaults, `--config-overrides` or a config file outside the tree; a file named that way is used even inside the tree. ASH does not look for `.bandit`, `bandit.yaml`, `bandit.toml`, `.grype.yaml`, `.grype/config.yaml`, `.syft.yaml` or their `.ash/` copies by name, and otherwise passes each tool an empty config (`--ini` for bandit, `--config` for grype and syft), so the tool does not read one from the tree on its own. ASH writes that file, the empty ones it passes ferret-scan, trivy, trivy-repo, actionlint and cfn-lint, and gitleaks' default-rules config, in a new directory outside the scanned tree, one per scanner run, and removes the directory when the run ends. When neither the temporary directory nor the output directory is outside the tree (a scan of a whole filesystem), the directory is made inside it and a warning says so. It does not use a `TMPDIR` that another account owns or that other accounts can write without the sticky bit; the output directory is used instead, and if it is no better the scanner fails and says to set `TMPDIR` to a directory only you can write. An ASH process killed by SIGTERM or SIGKILL leaves its `ash-tool-config-*` directory in the temporary directory; it is readable only by you and holds only those empty files. |
| `scanners.opengrep.options.config`, `scanners.semgrep.options.config`, `scanners.opengrep.options.patterns`, `scanners.opengrep.options.metrics`, `scanners.semgrep.options.metrics` | Taken from the defaults (`p/ci`, no patterns and `auto`), `--config-overrides` or a config file outside the tree. `config` chooses the rules, from the registry, a URL the tool fetches or a path it reads; opengrep's `patterns` runs the patterns in place of every rule config; and `metrics` chooses whether the tool sends usage data. `metrics: off`, which only stops it sending any, applies from every config. To run a repository's own rules, name them with `--config-overrides`. |
| `scanners.trivy-repo.options.disable_telemetry` | `false`, which lets trivy send anonymous usage data to its vendor on an online scan, is taken from `--config-overrides` or a config file outside every git checkout and the scanned directory. `true`, the default, which only stops it, applies from every config. A config file that leaves the option out keeps the operator's value. |
| A `.semgrepignore` in the scanned tree | Not honored by semgrep or opengrep: ASH passes `--x-ignore-semgrepignore-files` with the tools' default exclusions, so the same paths are scanned as with no `.semgrepignore`, and the file is named in the results as a `config_warning` validation checkpoint. In a tree an MCP client delivered, the checkpoint names the file as client-supplied. List the files to leave out in `global_settings.ignore_paths`. |
| `scanners.ferret-scan.options.profile`, `scanners.ferret-scan.options.use_default_config` | Taken from the defaults, `--config-overrides` or a config file outside the tree. A profile chooses which checks ferret-scan runs and the lowest confidence it reports, and the bundled `redaction` and `secure-redaction` profiles also have it write redacted copies of the files it scans. `use_default_config: false` replaces the bundled config with an empty one, which drops the bundled validators' patterns. ferret-scan's other options, `checks` and `confidence_levels` among them, still apply. |
| `scanners.snyk-code.options.honor_tree_exclusions` | Taken from the defaults, `--config-overrides` or a config file outside the tree. `snyk code test` leaves out the files that the `.snyk` and `.dcignore` files in the tree it tests exclude, and has no option to stop it, so while this is `false` (the default) snyk-code does not run on a tree that has one, and its error names the files. See [Exclusion files in the scanned tree](plugins/community/snyk-plugin.md#exclusion-files-in-the-scanned-tree). |
| `reporters.<name>.extension` | Must be a filename suffix such as `json`, from every source, including `--config-overrides`: the report is written to `ash.<extension>` in the reports directory. A value containing `/`, `\`, `..` or NUL is replaced by the reporter's default. ASH also writes a report, and the files some reporters write beside it, only when the resolved file is directly inside the reports directory. When the reports directory, or a file an enabled reporter writes there, is already a symlink or a directory junction, the run exits 1 before any reporter writes, and the error names the link. |
| Reporter destinations and credentials: `aws_region` and `aws_profile` of `aws-security-hub`, `bedrock-summary-reporter` and `s3`; `aws-security-hub`'s `account_id`, and its `findings_scope` and `archive_resolved_findings`, which choose which findings it imports and whether it archives the ones that are resolved; `bedrock-summary-reporter`'s `model_id`, `output_file`, `output_executive_file` and `output_technical_file`, and its `include_code_snippets`, `custom_prompt`, `industry_context`, `compliance_frameworks`, `custom_context`, `exclude_scanner_types`, `actionable_only`, `max_findings_to_analyze`, `max_findings_per_severity`, `summarize_findings`, `batch_processing`, `enable_fallback_models`, `add_section_headers`, `output_markdown`, `include_sections`, `exclude_sections` and `group_by_severity`, which choose what is sent to the model with the findings, which findings and how many, whether another model may receive them, and which of the reporter's calls are made; `max_retries`, `base_delay` and `max_delay` of `bedrock-summary-reporter`, `cloudwatch-logs` and `s3`, which choose how long each keeps calling its service when it is refused (capped at 10 retries and 60 seconds from every source); `s3`'s `bucket_name` and `key_prefix`; `cloudwatch-logs`' `aws_region`, `log_group_name` and `log_stream_name` (all under `reporters.<name>.options`) | Taken from the defaults, `--config-overrides` or a config file outside the tree, whichever spelling of the reporter's section the file uses (`BedrockSummary` is read as `bedrock-summary-reporter`, for example) and of the option (`-` or `_`). A value equal to the trusted one is no change. These options choose where findings are sent or written and which credentials send them. The same holds for the options a reporter from a plugin module declares in `destination_options`, once the scan has imported the module; see [Declaring destination options](plugins/reporter-plugins.md#declaring-destination-options). The reporters' other options still apply. |
| `reporters.<name>.enabled` of `aws-security-hub`, `bedrock-summary-reporter`, `cloudwatch-logs` and `s3`, and of a reporter from a plugin module that declares `destination_options` | Taken from the defaults, `--config-overrides` or a config file outside the tree, in both directions: the tree's config neither turns one of these reporters on nor turns one off. Its `enabled: true` or `enabled: false` is ignored with a warning where the operator's value differs, and leaving the section out, which would return the reporter to its own default, leaves it as the operator has it. Each of these reporters sends findings off the host when it runs, and which destinations get them is the operator's choice. To turn one off for a scan, use `--config-overrides`, such as `--config-overrides reporters.s3.enabled=false`. |

Each setting that is not honored is named in a warning when the config is
resolved.

A repository's config may still choose opengrep's `version`, within the limits
above: a tag of opengrep's own releases, whose binary ASH installs only when it
matches its SHA-256 digest. It does not choose a scanner's `tool_version`, so a
workspace project does not pin a scanner version either; the operator's value
applies to every project.

To set any of these for a repository you trust, use `--config-overrides`,
`--ash-plugin-modules`, or a config file outside every checkout and the scanned
directory. A tool config path set that way follows the operator's rule above: it
may be in a checkout of your own, but not inside the scanned tree, except a bandit,
grype or syft config file and the findings configs above (actionlint's, gitleaks'
and zizmor's `config_file`, gitleaks' `baseline_path` and cfn-guard's
`rules_paths`). Under `--sandbox`,
a file outside the system paths the sandbox already reads also has to be listed in
`sandbox.extra_read_paths`, or the tool cannot open it and the scanner reports an
error.

`ash merge` holds the configuration each shard recorded in its results to every
row of the table above except `content_db_staleness` and its overrides, which it
takes from the shards with the other settings its verdict reads, against the
operator's defaults, `--config` and `--config-overrides` at merge time, `enabled`
of the reporters in the `enabled` row included. It imports only the
`ash_plugin_modules` entries the operator's configuration names; see
[Settings a shard's recorded configuration cannot choose](cli-reference.md#settings-a-shards-recorded-configuration-cannot-choose).

### Configs an MCP client delivered

ASH's configuration can come from three places, and how far it is trusted depends
on which:

- **The operator**: ASH's defaults, a config file outside the scanned tree (named
  by `--config` or `ASH_CONFIG`), `--config-overrides`, `--ash-plugin-modules`, and, under the MCP
  server, the profiles the server registers. Everything applies.
- **The repository being scanned**: a config file inside the scanned tree, or a
  file a symlink inside the tree reaches, wherever that file is. The table above
  applies.
- **An MCP client**: a file the client delivered, such as an upload named as
  `config_path`, a delivered tree's own `.ash/.ash.yaml`, or a project config in
  a delivered workspace. So is any other config path a client names, unless it
  is in a directory `ASH_MCP_ALLOWED_CONFIG_ROOTS` names or is a profile file the
  server writes in the session's own `config/` directory: a config in another checkout the server may scan is that
  checkout's, not the operator's. A path is judged where it sits, at each
  symlink on the way, and by the file it reaches, so a link a client delivered is
  the client's wherever it points, and so is a file reached through a linked
  directory such as `.ash`. A file under the MCP workspace root is a client's whoever names it: a
  `--config` or `ASH_CONFIG` naming one, on the CLI as well, gets the limits of a
  config inside the scanned tree, and the server's runtime-override policy is
  never read from it (the built-in defaults apply instead). A profile after the
  client's `select_profile` `patch_ops` or `override_yaml` is the client's too,
  held to the registered profile as its trusted base, and so are the MCP
  workspace tools' `config_overrides`, even for keys the runtime-override
  allowlist lets the client change. The table above applies, and so does the
  session's runtime-override policy, `global_settings.mcp.runtime_overrides`:

  - The file may not change a field that `denied_paths` or
    `denied_value_patterns` denies. Entries match either `-` or `_`, every
    spelling of a plugin's section, and globs such as
    `/scanners/trivy-*/options/ignore_file`. A value equal to the server's is
    accepted, so a file `ash config init` wrote scans. A file that changes a
    denied field is refused with `error_type: config_field_denied`, naming each
    field. When the policy cannot be established, a scan that reads such a file is
    refused with `error_type: config_policy_unreadable`.
  - It may restrict the server's `sandbox` and `ash_plugin_modules` settings but
    not ask for more than they give: a `network_scanners` entry for a scanner the
    server's config gives no network, an `extra_read_paths` entry the server's
    config does not grant, a `mode` other than the server's when the server sets
    one, or a module the server's config does not load that is inside the scanned
    tree or sends findings off the host. A file that does is refused the same
    way, naming the setting; an equal or tighter value scans.
  - What chooses a scanner's own config, which version of a tool ASH installs, or
    where findings go is in the default `denied_paths` too, so a file that sets
    one is refused rather than scanned without it: each scanner's own config file
    (`config_file` for actionlint, bandit, cfn-lint, checkov, ferret-scan,
    gitleaks, grype, syft, trivy, trivy-repo and zizmor, and trivy's and
    trivy-repo's `secret_config_file`), trivy-repo's `module_dir`, cfn-guard's
    `rules_paths`, the programs actionlint runs (`shellcheck`, `pyflakes`),
    zizmor's `online_audits` (which lets the GitHub token reach zizmor),
    snyk-code's `honor_tree_exclusions`, the `honor_inline_ignores` of cfn-lint,
    gitleaks and zizmor (which honor the ignore comments in the scanned files),
    every scanner's and the jupyter converter's
    `tool_version`, opengrep's `version` and `sha256`, opengrep's and semgrep's
    `metrics` (their `config` is in the table below), the AWS reporters'
    destinations and credentials listed in the table above, whether
    `aws-security-hub`, `s3`, `cloudwatch-logs` and `bedrock-summary-reporter` run
    (`enabled`; `false` is not refused, here or in a client's runtime overrides,
    but it takes no effect: the server's `enabled` applies, as in the `enabled`
    row above, and a warning names the client's value. A `patch` op that writes
    `enabled` is refused whatever its value, as is any `patch` op on a denied
    path. A reporter that writes only local files is not covered), every other
    `aws-security-hub`, `s3` and
    `bedrock-summary-reporter`
    setting (each section is a whole-section entry, as `cloudwatch-logs` is),
    and the GitLab SAST reporter's
    `exclude_suppressed`, which would leave the findings a client's
    suppressions are marked on out of that report. The options a reporter from a
    plugin module declares in `destination_options` are not default entries,
    because the file is checked before the module is imported: a file that sets
    one is scanned with the server's value, as a config inside the scanned tree
    is.
  - Its own `global_settings.suppressions` and `global_settings.ignore_paths`
    apply. Each entry the operator did not supply is marked `client_supplied: true`,
    the files under a client-supplied ignore path are still scanned, and a finding
    either one hides is reported suppressed and marked rather than dropped. See
    [Suppressions an MCP client's config supplied](suppressions.md#suppressions-an-mcp-clients-config-supplied).
  - An exclusion it adds to one of the scanner options below is not passed to
    the scanner. Each finding of that scanner the entry would have left out is
    reported suppressed and marked in the same way. The operator's own entries
    apply as before.

    | Option | Matched as |
    |---|---|
    | `scanners.bandit.options.excluded_paths` | The `**/<path>/**` glob ASH passes bandit, against the file's absolute path |
    | `scanners.checkov.options.skip_path` | As checkov's own filter reads it: a regular expression found in, or a substring of, the absolute path of the file or of a directory above it |
    | `scanners.opengrep.options.exclude`, `scanners.semgrep.options.exclude`, `scanners.ferret-scan.options.exclude_patterns` | A glob matching the file's path or any directory in it |
    | `scanners.syft.options.exclude` | The same glob; each SBOM component it would have dropped carries an `ash:clientSuppliedExclusion` property |
    | `scanners.trivy.options.ignore_file`, `scanners.trivy-repo.options.ignore_file` | Each unexpired ID in the file, against the rule ID of that scanner's finding, when the file is a regular file inside the scanned tree (not a link); any other file is not read |

  - The scanner options below drop findings by rule ID, by a baseline, or by a
    whole category (a framework, a severity, a rule set, a detector, a confidence
    level, a cap on how many are reported) rather than by path. They are in the
    default `denied_paths`, so a delivered file that changes one is refused, and
    one that leaves it at its default scans. All are under `scanners.<name>.options`:

    | Scanner | Options |
    |---|---|
    | bandit | `confidence_level` |
    | cdk-nag | `nag_packs.AwsSolutionsChecks` (turning on another pack reports more, and is allowed) |
    | cfn-guard | `rule_sets` |
    | cfn-lint | `ignore_checks`, `regions` (a finding one region raises is dropped by validating for another) |
    | checkov | `frameworks`, `skip_frameworks` |
    | detect-secrets | `baseline_file`, `scan_settings` |
    | ferret-scan | `checks`, `confidence_levels`, `disable_ip_types`, `enable_preprocessors`, `finding_limit`, `max_live_bytes` (which bounds how much extracted content it holds), `profile`, `recursive`, `respect_gitignore`, `use_default_config`, `validator_budget` |
    | gitleaks | `baseline_path`, `max_target_megabytes` (files larger than it are skipped) |
    | opengrep | `config`, `exclude_rule`, `patterns`, `severity` |
    | semgrep | `config`, `exclude_rule`, `severity` |
    | trivy | `scanners`, `ignore_unfixed` |
    | trivy-repo | `license_full`, `scanners` |
    | every scanner | `offline`: a scanner set offline runs on cached data, and npm audit, which keeps no advisory data, checks none offline |

    Options that only tune output or performance, or whose default already
    reports the least they can (trivy-repo's `ignore_unfixed`, bandit's
    `ignore_nosec`, detect-secrets' `skip_generated_lockfiles`, trivy's
    `license_full`, zizmor's `persona`, cfn-lint's `include_checks`), are not
    listed.
    `scan_timeout` and `install_timeout` are not either: a scanner that runs out
    of time or cannot be installed is reported as not completing.

See [Config files in delivered source](mcp/streamable-http.md#config-files-in-delivered-source)
for the details, including which profile the policy comes from.

## Validating Configuration

To validate your configuration file:

```bash
ash config validate
```

## Viewing Current Configuration

To view the current configuration:

```bash
ash config get
```

## Updating Configuration

To update configuration values:

```bash
ash config update --set 'scanners.bandit.enabled=true'
ash config update --set 'global_settings.severity_threshold=LOW'
```

## Configuration Overrides

You can override configuration values at runtime using the `--config-overrides` option:

```bash
# Enable a specific scanner
ash --config-overrides 'scanners.bandit.enabled=true'

# Change severity threshold
ash --config-overrides 'global_settings.severity_threshold=LOW'

# Append to a list
ash --config-overrides 'ash_plugin_modules+=["my_ash_plugins"]'

# Add a complex value
ash --config-overrides 'global_settings.ignore_paths+=[{"path": "build/", "reason": "Generated files"}]'
```

## Relative paths in the operator's settings

A relative path in one of the operator's settings is taken from where it was set,
not from the source directory being scanned:

- in a config file outside the tree (`--config`, `ASH_CONFIG`, a workspace's
  `--config`, an MCP profile), from that file's directory; in an `extends` base,
  from the base's directory; and in a `patch` operation, from the directory of the
  file that holds it;
- in `--config-overrides`, in a CLI flag, and in `TRIVY_IGNOREFILE`,
  `TRIVY_SECRET_CONFIG` or `TRIVY_CONFIG`, from the working directory ASH runs in.

This covers `config_file` of bandit, checkov, ferret-scan, grype and syft,
detect-secrets' `baseline_file` and the `file://` entries of its `scan_settings`,
trivy-repo's `ignore_file` and `secret_config_file`, opengrep's and semgrep's
`config` when a file or directory is there (otherwise it is a registry entry such
as `p/ci`), and `sandbox.extra_read_paths`. A path that starts with `~`, or is
absolute, is used as written. In `TRIVY_IGNOREFILE`, `TRIVY_SECRET_CONFIG` and
`TRIVY_CONFIG`, any other value is taken from the working directory exactly as
written, a `$` or `://` in it included, and a `..` after a symbolic link goes up
from where the link points. A config file inside the scanned tree does not set
these options (see
[Settings a repository's config cannot choose](#settings-a-repositorys-config-cannot-choose)).
To name a file in the scanned repository, give its absolute path, or a path
relative to where you run ASH with `--config-overrides`.

## Extending another configuration

A config can build on one or more base configs with `extends`, and adjust the
result with RFC 6902 JSON-Patch operations under `patch`:

```yaml
# .ash/.ash.yaml
extends: ../shared/ash-base.yaml     # or a list: [org.yaml, team.yaml]
project_name: my-service
global_settings:
  severity_threshold: HIGH
patch:
  - op: add
    path: /global_settings/suppressions/-
    value:
      rule_id: B101
      path: "tests/**"
      reason: "assert is expected in tests"
```

The same keys work in `[tool.ash]` (`extends = "ash-base.yaml"`,
`patch = [{op = "add", path = "/fail_on_findings", value = false}]`) and in an
`ashrc` file. A base can be YAML, JSON, TOML, or a `pyproject.toml`, whose
`[tool.ash]` table is used.

How a config is resolved:

1. Each base is resolved the same way, so bases can extend other bases.
2. The bases are merged in the order listed, a later base winning over an
   earlier one.
3. The file's own settings are merged over the bases. The file always wins.
4. The file's `patch` operations run, in order, on the result.
5. `--config-overrides` apply last, on top of everything above.

Merge rules:

- Mappings merge key by key, at every level. A base's `scanners.bandit.options`
  and a child's `scanners.bandit.enabled` both survive.
- Lists, scalars and `null` replace. A child that sets
  `global_settings.suppressions` replaces the base's list. To keep the base's
  entries and add more, use `patch` with `op: add` and a path ending in `/-`.
- To delete something a base set, use `patch` with `op: remove`.
- A setting is merged as ASH reads it. Where ASH reads one setting under two
  spellings (`cdk-nag` and `cdk_nag`), both are the one setting: the child's
  value wins over the base's whichever spelling either file uses, and the
  result is kept under one spelling. A spelling ASH does not read
  (`global-settings` for `global_settings`) in a base is left alone, so it
  cannot keep a child's value from applying; one in a child still reaches the
  base's spelling of the setting, unless the child also uses a spelling ASH
  reads, which wins. Two spellings of a plugin's section that ASH reads for the
  same plugin (`BedrockSummary` and `bedrock-summary-reporter`) are one
  section, under the child's spelling. In `patch` paths, a key spelled with `-`
  and the same key spelled with `_` are one key.
- `patch` accepts `add`, `remove`, `replace` and `test`. `move` and `copy` are
  refused. A failing operation, including a failing `test`, fails the load.

Where a base may live:

- A relative path is relative to the file that names it. An absolute path is
  also accepted.
- Every base must be inside the scan's source directory (or, for a `--config`
  file kept outside it, inside that file's own directory, or the parent of
  `.ash/` for a file in `.ash/`). `..` is fine while it stays inside. A path, or
  a symlink, that resolves outside is an error. In workspace mode each project
  is scanned with its own directory as the source directory, so a project's
  bases must be inside that project.
- URLs are refused. ASH never downloads a base config; copy the file into the
  repository instead.

Errors stop the scan rather than falling back to the default configuration: a
missing or unreadable base, a cycle (the error prints the chain, for example
`.ash.yaml -> b.yaml -> c.yaml -> b.yaml`), a chain more than 10 levels deep,
or more than 50 files read in total. `${VAR}` references in every file of the
chain are resolved under the same allowlist as a single file.

`ash config validate` and `ash config lint` follow the chain, report extends
errors, and print the files the config was built from, lowest precedence first.
`ash config update`, `ash config wizard` and the `ash inspect` suppression dialog
refuse to rewrite a file in a way that would copy its bases into it or drop their
suppressions.

## Scanner-Specific Configuration

Each scanner has its own configuration options. Here are some examples:

### Bandit

```yaml
scanners:
  bandit:
    enabled: true
    options:
      confidence_level: high      # all | low | medium | high -- lowercase only
      severity_threshold: MEDIUM  # ALL | LOW | MEDIUM | HIGH | CRITICAL -- uppercase only
      ignore_nosec: false         # true scans lines carrying a '# nosec' comment anyway
      excluded_paths: []          # Paths to exclude, each with a reason
      config_file: null           # The operator's bandit config file; see below
      scan_timeout: 1800          # Seconds before the bandit invocation is killed
      # Bandit is installed via UV tool management with the constraint
      # '>=1.7.0,<2.0.0' for SARIF support.
```

Selecting individual bandit tests is done in a bandit configuration file rather than
through ASH options. ASH does not look for one by name in the scanned tree. Name it
with `config_file`, set with `--config-overrides` or in a config file outside the
tree; a config file inside the tree does not set it (see
[Settings a repository's config cannot choose](#settings-a-repositorys-config-cannot-choose)). A relative
path is taken from where it was set, as for the operator's other paths
([Relative paths in the operator's settings](#relative-paths-in-the-operators-settings)).
A file named exactly `.bandit` is passed with `bandit --ini`,
and any other file with `bandit --configfile`. Unless `config_file` names a `.bandit`
file that exists, ASH passes bandit an empty config file with `bandit --ini`, so
bandit does not read a `.bandit` file from the tree either. A path that is not a file
is logged as a warning and ignored.
For the file's format, refer to
the Bandit [documentation](https://bandit.readthedocs.io/en/latest/config.html).

### Semgrep

```yaml
scanners:
  semgrep:
    enabled: true
    options:
      config: 'p/ci'        # Ruleset, directory of YAML rules, or URL, passed to --config (operator only)
      exclude: ['*-converted.py', '*_report_result.txt']  # Paths to skip
      exclude_rule: []      # Rule IDs to skip (singular; 'exclude_rules' is not a field)
      severity: []          # Report only findings from rules of these severities
      metrics: 'auto'       # How usage metrics are sent to the Semgrep server ('off' from any config)
      offline: false        # Use locally cached rules only
      scan_timeout: 1800    # Seconds before the semgrep invocation is killed
      tool_version: null    # Version constraint (e.g., '>=1.125.0')
      install_timeout: 300  # Timeout in seconds for tool installation
```

### Detect-Secrets

```yaml
scanners:
  detect-secrets:
    enabled: true
    options:
      baseline_file: null   # Explicit .secrets.baseline path, relative to the config file that sets it
      scan_timeout: 1800    # Seconds before the detect-secrets invocation is killed
```

Which plugins and filters run, and which findings are already accepted, live in the
detect-secrets baseline rather than in ASH options. Point `baseline_file` at one, or
rely on the discovery described below. The `scan_settings` option takes the same
structure as a baseline's own settings block if you would rather inline it.

If you have been using detect-secrets separately and have an existing baseline file
you would like to use with ASH, ASH can use it automatically. It looks for
`.ash/.secrets.baseline`, then `.secrets.baseline`, in the source directory
(`--source-dir`), wherever ASH is run from, and takes a relative `baseline_file` from
the source directory too. A baseline in the directory ASH runs from does not apply to
a scan of another directory. For more details on baseline files, refer to the
detect-secrets [documentation](https://github.com/Yelp/detect-secrets/tree/master).

#### Secret verification

detect-secrets can verify a candidate secret by sending it to the service that issued
it, and drop the candidates the service rejects. The filter that does this is
`detect_secrets.filters.common.is_ignored_due_to_verification_policies`, and
`detect-secrets scan` writes it into every baseline it generates. For an AWS access
key the request goes to `sts.amazonaws.com`, signed with the key pair found in the
scanned file, so verification makes the host running ASH contact the issuer with
credentials taken from the scanned tree. ASH therefore verifies only when the operator
asks for it, and never in offline mode:

- The filter counts when the operator's own configuration names it: a config file
  outside the scanned directory and every git checkout (`--config` or `ASH_CONFIG`),
  `--config-overrides`, or for the MCP server the profile the session is bound to. An
  MCP client's runtime overrides cannot set these detect-secrets settings: they are
  always in `runtime_overrides.denied_paths`, whatever `allowed_paths` says. A profile
  that sets its own `denied_paths` adds to them and cannot remove them, as for the
  scanner sandbox, `ash_plugin_modules` and the archive extraction limits. It
  can be in `scan_settings.filters_used`, or in a `baseline_file` the operator names
  that is outside the scanned tree and outside the git checkout holding it, including
  through `--config-overrides` beside a repository's own config. A baseline in another
  checkout counts: scanning `repo/service` with a baseline from a separate
  `shared-baselines` checkout verifies, while one in `repo/ops` does not.
- When `scan_settings` sets `plugins_used` or `version`, it replaces the baseline's
  plugins and filters. Otherwise the baseline's are used, and a verification filter
  the operator's `scan_settings.filters_used` names is kept beside them.
- A `.secrets.baseline` inside the scanned tree or its checkout, a config file the scanned repository
  holds (`.ash/.ash.yaml` and the other discovered names, including a workspace
  project's own config), and a config an MCP client supplied cannot turn verification
  on, whatever baseline they name. ASH removes the filter, keeps the rest of the
  settings, and logs a warning that names the source.
- Under `--offline` (or `ASH_OFFLINE`) nothing turns it on.

To verify, name the filter with its `min_level` in your own config. detect-secrets reads
`min_level` for this filter, and without it the scan fails:

```yaml
scanners:
  detect-secrets:
    options:
      scan_settings:
        filters_used:
          - path: detect_secrets.filters.common.is_ignored_due_to_verification_policies
            min_level: 2
```

The same sources decide which plugin and filter files detect-secrets may import. A
`plugins_used` or `filters_used` entry named by `file://` path is a Python file the
detect-secrets worker loads, so only the operator's own configuration, or a baseline
outside the scanned tree and its checkout that the operator names, may name one. The
file itself must also be outside the scanned tree and every git checkout. A `file://` entry in a
repository's config or `.secrets.baseline`, or in a baseline such a config names, is
removed with a warning, wherever the file is; the built-in detectors it lists by name
still run.

When verification is off, candidates the filter would have dropped are reported, so a
repository whose own baseline used to verify can show more findings. The
detect-secrets worker also refuses every HTTP request in that case, so a filter or
plugin that verifies under another name sends nothing either. Under `--sandbox`,
verification also needs `sandbox.network_scanners` to name detect-secrets; see
[Scanner sandbox](scanner-sandbox.md).

### Checkov

```yaml
scanners:
  checkov:
    enabled: true
    options:
      frameworks: ['all']  # Frameworks to scan (plural; 'framework' is not a field)
      skip_frameworks: []  # Frameworks to exclude
      skip_path: []  # Paths to skip, matched as regular expressions
      skip_ash_output_dir: true  # Skip ASH's output directory when it is inside the source (not on Windows)
      offline: false  # Run in offline mode
      additional_formats: ['cyclonedx_json']  # Additional output formats
      tool_version: null  # Version constraint (e.g., '>=3.2.0,<4.0.0')
      install_timeout: 300  # Timeout in seconds for tool installation
      # Note: Checkov is automatically downloaded and run via UV tool management
      # with version constraint >=3.2.0,<4.0.0 for enhanced stability
```

A Checkov configuration file is passed to checkov only when it is outside the
scanned tree: name it with `config_file`, set with `--config-overrides` or in a
config file outside the tree (see [Settings a repository's config cannot choose](#settings-a-repositorys-config-cannot-choose)).
A `.checkov.yaml` or `.checkov.yml` in the scanned tree, or in its `.ash`
directory, is not used, and checkov runs from outside the tree so it does not
read one on its own. For the file's format, refer to the Checkov
[documentation](https://github.com/bridgecrewio/checkov?tab=readme-ov-file#configuration-using-a-config-file).

### Grype

```yaml
scanners:
  grype:
    enabled: true
    options:
      config_file: null # The operator's grype config file; see below
      severity_threshold: MEDIUM # Options: ALL, LOW, MEDIUM, HIGH, CRITICAL
      offline: false # Run in offline mode
```

ASH does not look for a Grype configuration file by name in the scanned tree. Name
one with `config_file`, set with `--config-overrides` or in a config file outside
the tree (see [Settings a repository's config cannot choose](#settings-a-repositorys-config-cannot-choose)). Without
one, grype gets an empty config, so it does not read a `.grype.yaml` from the tree
either. For the file's format, refer to the Grype
[documentation](https://github.com/anchore/grype?tab=readme-ov-file#configuration).

One setting is not used: `db.cache-dir`. ASH reads grype's database from the directory grype uses by default (`$XDG_CACHE_HOME/grype/db` when `XDG_CACHE_HOME` is an absolute path, else `~/.cache/grype/db` on Linux, `~/Library/Caches/grype/db` on macOS and `%LOCALAPPDATA%\cache\grype\db` on Windows), passed to the scan as `GRYPE_DB_CACHE_DIR`, so that the scan, the database update and ASH's check of the database's age all read the same one. To keep the database somewhere else, set `GRYPE_DB_CACHE_DIR`; ASH logs a warning naming the file when a grype config sets `db.cache-dir`.

### Syft

```yaml
scanners:
  syft:
    enabled: true
    options:
      config_file: null # The operator's syft config file; see below
      exclude:                # Each entry needs a path and a reason
        - path: 'tests'
          reason: 'Test fixtures are not shipped'
      additional_outputs: ["syft-json"] # List of additional output formats for Syft. Options:
      # "cyclonedx-json", "cyclonedx-xml","github-json", "spdx-json",
      # "spdx-tag-value", "syft-json", "syft-table", "syft-text"
```

ASH does not look for a Syft configuration file by name in the scanned tree. Name
one with `config_file`, set with `--config-overrides` or in a config file outside
the tree (see [Settings a repository's config cannot choose](#settings-a-repositorys-config-cannot-choose)). Without
one, syft gets an empty config, so it does not read a `.syft.yaml` from the tree
either. For the file's format, refer to the Syft
[documentation](https://github.com/anchore/syft/wiki/Configuration).

### actionlint

```yaml
scanners:
  actionlint:
    enabled: true
    options:
      config_file: null  # an actionlint config; operator-only, may be inside the tree
      shellcheck: null   # "shellcheck" to enable it; another program or a path is operator-only
      pyflakes: null     # "pyflakes" to enable it; same rule as shellcheck
```

actionlint lints the workflows in `.github/workflows`. The scanned repository's own `.github/actionlint.yaml` is not read. See [actionlint](plugins/builtin/actionlint.md).

### cfn-lint

```yaml
scanners:
  cfn-lint:
    enabled: true
    options:
      config_file: null      # a .cfnlintrc; operator-only, outside the scanned tree
      regions: []            # e.g. [us-east-1, eu-west-1] or [ALL_REGIONS]
      ignore_checks: []      # rule ids or prefixes to skip
      include_checks: []     # e.g. [I] for informational rules
      honor_inline_ignores: false # a template's own Metadata ignore_checks and configure_rules; operator-only
      tool_version: ">=1.43.3,<2.0.0"
      install_timeout: 300
```

A `.cfnlintrc` in the scanned repository or the home directory is not read. See [cfn-lint and cfn-guard](plugins/builtin/cfn-lint-and-cfn-guard.md).

### cfn-guard

```yaml
scanners:
  cfn-guard:
    enabled: true
    options:
      rule_sets: [wa-Security-Pillar]  # bundled Guard Rules Registry sets, by name
      rules_paths: []                  # your own .guard files or directories; operator-only
```

See [cfn-lint and cfn-guard](plugins/builtin/cfn-lint-and-cfn-guard.md) for the bundled rule sets and how a rules directory is read.

### gitleaks

```yaml
scanners:
  gitleaks:
    enabled: true
    options:
      config_file: null           # a gitleaks TOML config; operator-only, may be inside the tree
      baseline_path: null         # a gitleaks report whose findings are ignored; same rule
      honor_inline_ignores: false # honor gitleaks:allow comments; operator-only
      max_target_megabytes: null  # skip files larger than this; operator-only
```

A `.gitleaks.toml` in the scanned repository is not read, and findings a root `.gitleaksignore` drops are reported anyway. See [Gitleaks](plugins/builtin/gitleaks.md).

### trivy

```yaml
scanners:
  trivy:
    enabled: true
    options:
      scanners: [vuln]           # vuln, misconfig, secret, license; operator-only
      ignore_unfixed: false
      license_full: false
      disable_telemetry: true
      config_file: null          # a trivy.yaml; operator-only, outside the scanned tree
      ignore_file: null          # a .trivyignore; same rule
      secret_config_file: null   # a trivy-secret.yaml; same rule
      offline: false
      severity_threshold: null   # gates the verdict, as for every scanner
```

A scanner-level `severity_threshold` gates the verdict as it does for every other scanner: findings below it are reported and do not fail the scan. ASH does not pass it as `trivy --severity`. See [Trivy filesystem scanner](plugins/builtin/trivy.md).

### zizmor

```yaml
scanners:
  zizmor:
    enabled: true
    options:
      persona: regular       # regular, pedantic or auditor
      config_file: null      # a zizmor config; operator-only, may be inside the tree
      online_audits: false   # operator-only; GitHub API audits with the token from the environment
      tool_version: ">=1.29.0,<2.0.0"
      install_timeout: 300
```

ASH runs `zizmor --no-config` and `zizmor --offline` unless the operator sets these. See [zizmor](plugins/builtin/zizmor.md).

## UV Tool Management

ASH v3 uses UV's tool isolation system to automatically manage scanner dependencies. This provides several benefits:

- **Automatic Installation**: Tools like Bandit, Checkov, and Semgrep are automatically installed when needed
- **Version Constraints**: ASH ensures compatible tool versions with sensible defaults:
  - **Bandit**: `>=1.7.0` (enhanced SARIF support and security fixes)
  - **Checkov**: `>=3.2.0,<4.0.0` (improved stability, avoiding potential breaking changes)
  - **Semgrep**: `>=1.125.0` (comprehensive rule support and performance improvements)
- **Isolation**: Tools run in isolated environments without affecting your project dependencies
- **Retry Logic**: Automatic retry with exponential backoff for network issues
- **Comprehensive Logging**: Detailed installation and execution logging for troubleshooting
- **Fallback Support**: If UV tool installation fails, ASH falls back to system-installed tools when available

### UV Tool Configuration Options

Each UV-managed scanner supports these configuration options:

```yaml
scanners:
  checkov:  # or bandit, semgrep
    enabled: true
    options:
      tool_version: ">=3.2.0,<4.0.0"  # Override default version constraint
      install_timeout: 300             # Installation timeout in seconds (default: 300)
```

### Environment Variables

Control UV tool behavior globally:

```bash
# Disable automatic tool installation (use pre-installed tools)
export ASH_OFFLINE=true

# Custom UV executable path (if needed)
export UV_EXECUTABLE=/custom/path/to/uv
```

### Troubleshooting UV Tool Issues

If you encounter UV tool installation issues:

1. **Check UV availability**: `uv --version`
2. **Enable verbose logging**: `ash --verbose` for detailed installation logs
3. **Use offline mode**: `ASH_OFFLINE=true` to skip installations
4. **Pre-install tools manually**:
   ```bash
   uv tool install bandit>=1.7.0,<2.0.0
   uv tool install checkov>=3.2.0,<4.0.0
   uv tool install semgrep>=1.125.0,<2.0.0
   ```
5. **Increase timeout** for slow networks:
   ```yaml
   scanners:
     checkov:
       options:
         install_timeout: 600  # 10 minutes
   ```

For more detailed information about UV tool management, see the [UV Tool Management Developer Guide](../developer-guide/uv-tool-management.md).
- **Flexible Version Management**: Scanners can optionally specify version constraints, with sensible defaults provided

### UV Tool Behavior

- **Bandit**: Automatically installed via `uv tool install bandit>=1.7.0,<2.0.0` (default version constraint)
- **Checkov**: Automatically installed via `uv tool install checkov>=3.2.0,<4.0.0` (default version constraint) with fallback to `uv tool run`
- **Semgrep**: Automatically installed via `uv tool install semgrep>=1.125.0,<2.0.0` (default version constraint) with fallback to `uv tool run`

### Version Constraint Configuration

Each UV-managed scanner can specify version constraints in two ways:

1. **Default Constraints**: Built-in version constraints ensure compatibility and stability
2. **Custom Constraints**: Override defaults via configuration options (where supported)

For scanners that support custom version constraints (like Semgrep and Checkov), you can specify them in a config file outside the scanned tree, or with `--config-overrides`. A repository's own config does not choose them; see [Settings a repository's config cannot choose](#settings-a-repositorys-config-cannot-choose).

```yaml
scanners:
  semgrep:
    options:
      tool_version: ">=1.130.0,<2.0.0"  # Custom version constraint
  checkov:
    options:
      tool_version: ">=3.3.0"  # Custom version constraint
```

### Troubleshooting UV Tool Issues

If you encounter issues with UV tool management:

1. **Check UV Installation**: Ensure UV is installed and available in your PATH
2. **Network Connectivity**: UV tool installation requires internet access
3. **Offline Mode**: Use `ASH_OFFLINE=true` to skip tool downloads and rely on pre-installed tools
4. **Manual Installation**: You can pre-install tools manually if needed:
   ```bash
   uv tool install bandit>=1.7.0,<2.0.0
   uv tool install checkov>=3.2.0,<4.0.0
   uv tool install semgrep>=1.125.0,<2.0.0
   ```

## Advanced Configuration

For advanced configuration options, refer to the [JSON Schema](https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/main/automated_security_helper/schemas/AshConfig.json) that defines all available configuration options.

You can add this schema reference to your configuration file for editor autocompletion:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/main/automated_security_helper/schemas/AshConfig.json
```
