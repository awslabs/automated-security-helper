# Output files

What a scan writes to its output directory. The output directory is
`<source-dir>/.ash/ash_output` unless you pass `--output-dir`; see
[Read scan results](../how-to/read-results.md) for which file to open for what.

## Layout

A scan of a project with Python, a CloudFormation template, and a GitHub Actions workflow,
with every built-in scanner installed:

```text
.ash/ash_output/
├── ash.log
├── ash_aggregated_results.json
├── ash-ignore-report.txt
├── ash-scan-set-files-list.txt
├── analysis/
├── converted/
├── reports/
│   ├── ash.cdx.json
│   ├── ash.csv
│   ├── ash.flat.json
│   ├── ash.ghas.sarif
│   ├── ash.gl-dependency-scanning-report.cdx.json
│   ├── ash.gl-sast-report.json
│   ├── ash.html
│   ├── ash.junit.xml
│   ├── ash.ocsf.json
│   ├── ash.sarif
│   ├── ash.summary.md
│   ├── ash.summary.txt
│   ├── ash.unused-suppressions.json
│   └── ash.unused-suppressions.md
└── scanners/
    ├── bandit/
    │   └── source/
    │       ├── ASH.ScanResults.json
    │       ├── BanditScanner.stderr.log
    │       └── bandit.sarif
    ├── checkov/
    │   └── source/
    │       ├── ASH.ScanResults.json
    │       ├── CheckovScanner.stdout.log
    │       ├── results_cyclonedx.json
    │       └── results_sarif.sarif
    └── ...one directory for every scanner
```

| Path | Written by | Contents |
|---|---|---|
| `ash.log` | ASH's logger | The run's log, INFO and above by default, one tab-separated line per record: time, level, source location, and message. Lines from a scanner have a field before the message naming the scanner and target, such as `([yellow]bandit[/yellow] @ [magenta]source[/magenta])`, and messages can contain the same Rich markup. |
| `ash_aggregated_results.json` | the scan engine | Every result of the scan in one document. See [below](#aggregated-results). |
| `ash-ignore-report.txt` | the scan set step | The ignore rules that shaped the scan set: the text of each `.gitignore` and `.ignore` ASH found, and ASH's built-in rules (`.git` and `**/cdk.out/asset.*` left out, `**/*.template.json` kept). |
| `ash-scan-set-files-list.txt` | the scan set step | The files ASH selected, one absolute path per line. Scanners that walk the source directory themselves can read more; see [Coverage](coverage.md#what-decides-the-files). |
| `analysis/` | `ash scan --inspect` | The SARIF field analysis. Empty otherwise. |
| `converted/` | the converters | `archive/` holds a directory per `.zip`, `.tar`, or `.gz` file with the members ASH extracted; `jupyter/` holds each notebook converted to a script, named after the notebook's path and ending in `-converted.py` for a Python notebook (see [Converted files](coverage.md#converted-files)). Empty when there was nothing to convert. |
| `reports/` | the reporters | One file per enabled reporter, named `ash.<extension>`. See [below](#reports). |
| `scanners/<name>/<target>/` | each scanner | `ASH.ScanResults.json` and the tool's own output for one target: `source` for the source directory, `converted` for `converted/`. See [below](#per-scanner-results). |

In workspace mode the workspace's output directory holds the combined
`ash_aggregated_results.json`, and each project's own output tree is under
`projects/<project>/`. The workspace's `reports/` holds the reports that combine every
project, and `workspace-reports.json`, which lists where each project's own reports are.
The reporters that write one file per project, `cyclonedx`, `spdx`, `github-ghas`,
`gitlab-sast`, and `gitlab-cyclonedx`, write nothing at the workspace level; their files
are in each project's `reports/`. See
[Scale to large repositories](../how-to/scale-large-repos.md).

## Each scan replaces the last

Before a scan writes anything, ASH removes and recreates `analysis/`, `reports/`,
`scanners/`, and `converted/`, and deletes `ash_aggregated_results.json`,
`ash-ignore-report.txt`, and `ash-scan-set-files-list.txt`. `ash.log` is truncated
when the logger opens it.

So a scan that fails leaves only what it wrote before it failed: gate CI on ASH's exit
code, not on whether `reports/` exists. Container mode and Nix mode delete the same
entries before they start the scan.

In local mode, ASH clears the output directory only after it has accepted the command
line and the configuration. A scan refused before that leaves the earlier results in
place: an unknown option or scanner name, or a selection that excludes every scanner it
names (exit 5), or a configuration that does not validate (exit 3). Only `ash.log` is
rewritten. For example, after a scan of the sample project:

<!-- doctest: run expect-exit=2 -->
```bash
ash scan --scanners detect-secrets
```

a scan that names a scanner ASH does not have is refused:

<!-- doctest: run expect-exit=5 -->
```bash
ash scan --scanners not-a-scanner
```

and the first scan's results are still there:

<!-- doctest: run -->
```bash
test -f .ash/ash_output/ash_aggregated_results.json
```

A scan started over MCP keeps the previous results until it has its own. When it
starts, the server moves the previous `reports/`, `scanners/`, `analysis/`,
`converted/`, `ash_aggregated_results.json`, `ash-ignore-report.txt`, and
`ash-scan-set-files-list.txt` into `.ash_previous_results/` in the output directory.
When the scan finishes with results, they are deleted. When it fails or is canceled,
the server removes what the scan wrote, puts them back, and writes
`.ash_previous_results_restored` beside them. The next scan removes that file, and the
next `ash scan` also deletes a held `.ash_previous_results/`. For a scan whose previous
results were put back, `get_scan_progress` returns `output_holds_previous_results: true`,
and the tools that read results from the directory, such as `get_scan_results`, answer
that the scan is not complete.

`ash scan --use-existing` runs only the report phase: it writes `reports/` again from the
`ash_aggregated_results.json` already in the output directory, rewrites
`metadata.summary_stats` in that file, leaves `scanners/` and the other files in place,
and exits with the verdict of the stored results.

## Links are refused {#links}

ASH refuses to write through a symbolic link or a Windows directory junction at any of
these:

- the output directory itself, or a directory on the way to it below the source
  directory (the default `.ash/ash_output` is below it, so a repository can commit such
  a link);
- `analysis`, `reports`, `scanners`, or `converted` in the output directory;
- the files ASH writes there by a fixed name: `ash_aggregated_results.json`,
  `ash-ignore-report.txt`, `ash-scan-set-files-list.txt`, `ash.log`, and
  `ash.log.jsonl`;
- in workspace mode, `projects` and `.workspace-spool` in the workspace's output
  directory, and each project's `projects/<project>` directory.

It also refuses an output directory below the source directory whose real path, with
every link resolved, is outside the source directory.

The check runs before anything is written or deleted, in every run mode and whatever
the sandbox mode, and also in `ash report` and `ash merge`. The command exits 3:

```text
ERROR (3) The output directory /work/out-link is a symlink. ASH does not write to, clear or
mount its output directory through a link, whatever the sandbox mode. Pass --output-dir with
a directory that is not a link, or replace the link with a directory.
```

In an `ash --workspace` scan, a link at `projects` or `.workspace-spool` stops the whole
run this way before any project starts. A link at `projects/<project>` fails only that
project, logged as `Project '<project>' was not scanned:` and the same refusal. The other
projects still run, and the run exits 1, or 2 when another project has actionable
findings (see [Workspace mode](exit-codes.md#workspace)). Over MCP,
`run_ash_workspace_scan` refuses the whole call when any of these is a link.

Directories above an output directory that is outside the source directory are not
examined, so `--output-dir /tmp/ash` works on a system where `/tmp` is a link.

Reports are checked again before any reporter writes. If `reports/`, or a file that one
of the reporters about to run writes there, such as `reports/ash.sarif`, is a link, the
run stops with exit 1:

```text
ERROR (1) /work/out/reports/ash.sarif is a symlink. ASH does not write a report through a link.
Remove the link and run ASH again.
```

This applies to scans in every run mode, including `--use-existing` and workspace scans,
and to `ash merge`. `ash merge` prints the same text after `Refusing to write reports:`.
`ash report` prints its report instead of writing it, and refuses a link only at a file
the reporter writes beside it.

## `ash_aggregated_results.json` {#aggregated-results}

The scan engine writes this file, not a reporter, and every reporter and `ash report`
reads it. Its JSON schema is
[`AshAggregatedResults.json`](https://github.com/awslabs/automated-security-helper/blob/main/automated_security_helper/schemas/AshAggregatedResults.json).

| Top-level name | Contents |
|---|---|
| `name`, `description` | A label with the scan's start time, and a fixed description. |
| `metadata` | About the run. See below. |
| `ash_config` | The configuration the scan resolved, after overrides and trust rules. A value or key a config file read from the environment is recorded as the reference the file wrote, here and in `metadata.expected_scanners` ([Read values from the environment](../how-to/configure.md#environment)). |
| `scanner_results` | One row per scanner, keyed by scanner name. See below. |
| `converter_results` | One row per converter, keyed by converter name. See below. |
| `sarif` | The aggregated SARIF report. See [SARIF](#sarif). |
| `cyclonedx` | The CycloneDX software bill of materials syft produced; with no components when syft did not run. |
| `additional_reports` | Each scanner's per-target record, keyed by scanner and then target (`source`, `converted`). The same records as `scanners/<name>/<target>/ASH.ScanResults.json`. |
| `validation_checkpoints` | The checks ASH ran on its own execution (were all selected scanners queued, did each finish), and configuration warnings, which have `type` set to `config_warning`. |
| `used_suppressions` | The ids of the `global_settings.suppressions` entries that matched a finding (format below). Inline `ash-ignore` comments are not listed. |
| `workspace` | The workspace plan and per-project outcomes in workspace mode; `null` otherwise. |

A suppression's ID is its path, rule ID, first line, and last line joined with `|`, with
`*` for a part the entry does not set, so an entry for rule `B602` in `app.py` with no
lines is `app.py|B602|*|*`. Entries that set package or symbol fields have more parts.

`metadata` holds `report_id`, `generated_at`, `project_name` (the config's
`project_name`, else the `ASH_PROJECT_NAME` environment variable, else `ash-scan`),
`tool_version` (the ASH version), `summary_stats`, `validation_summary`,
`execution_discrepancy_report`, `shard` (set by `--shard-index`), `expected_scanners`,
`requested_scanners_not_run` (the names in `--scanners` or `ASH_SCANNERS` that matched no
scanner, or `null` when every name matched or no list was given; `ash merge` records the
names of all the shards), `plugin_load_errors` (plugin groups that failed to import), and
`changed_files_only`
(`true` when `--changed-files-only` filtered the findings, `false` on a full scan,
including one that fell back to a full scan).

`report_id` is unique to each scan: `ASH-`, the scan's start as a UTC date and time, and
12 random hexadecimal digits, such as `ASH-20261011180835-deff7bedfe39`. Reports rendered
again from saved results, by `ash report` or `--use-existing`, keep it. `ash merge` gives
the merged results an id of the same shape, computed from the shards' ids, so merging the
same shards again gives the same id. A workspace scan's combined results have an id of
the form `ASH-WORKSPACE-<workspace file name>-<date and time>-<hex digits>`.

`summary_stats` totals the scan: `severity_counts` (`suppressed`, `critical`, `high`,
`medium`, `low`, `info`), `total` (unsuppressed findings), `actionable`, the count of
scanners in each status (`passed`, `failed`, `missing`, `skipped`, `error`), and
`start`, `end`, and `duration`.

### Scanner rows

Each `scanner_results` row has:

| Name | Meaning |
|---|---|
| `status` | `PASSED`, `FAILED`, `ERROR`, `MISSING`, or `SKIPPED`; see [the summary table](../how-to/read-results.md#read-the-summary-table). |
| `severity_counts`, `finding_count`, `actionable_finding_count`, `suppressed_finding_count` | The counts the summary table shows. |
| `duration` | How long the scanner ran, in seconds. |
| `dependencies_satisfied` | `false` on a `MISSING` row. |
| `excluded` | `true` when the run left the scanner out: `--scanners`, `--exclude-scanners`, `enabled: false`, `--python-only`, the shard split, or a platform it does not support. |
| `exit_code` | The tool's exit code, the highest over the targets it ran on, or `null` when no tool ran: a `MISSING` or excluded scanner, one that had nothing to scan, or one that started no tool for its targets. |
| `missing_reason` | On a `MISSING` row, why: the tool that was not found and where ASH looked, what the scanner's own dependency check reported, that the tool was found only inside the scanned directory, which ASH does not run unless you allow it (see [Tools inside the scanned directory](../docs/advanced-usage.md#tools-inside-the-scanned-directory)), or that the scanner could not be sandboxed. `null` otherwise. |
| `skipped_reason` | On a `SKIPPED` row, why: the option that left it out, such as `not named by --scanners`, or what it had nothing to scan, such as `no CloudFormation template in the scanned files`. `null` otherwise. |

<!-- doctest: config kind=ash-output model=automated_security_helper.models.asharp_model.AshAggregatedResults.scanner_results -->
```json
{
  "grype": {
    "status": "MISSING",
    "dependencies_satisfied": false,
    "excluded": false,
    "severity_counts": {"suppressed": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
    "finding_count": 0,
    "actionable_finding_count": 0,
    "suppressed_finding_count": 0,
    "exit_code": null,
    "duration": 0.0,
    "missing_reason": "its tool grype was not found on PATH or in /home/me/.ash/bin, /home/me/.local/share/uv/tools/automated-security-helper/bin, /usr/local/bin; install it with `ash dependencies install` or exclude grype with --exclude-scanners",
    "skipped_reason": null
  }
}
```

### Converter rows

Each `converter_results` row (`archive`, `jupyter`) has:

| Name | Meaning |
|---|---|
| `dependencies_satisfied` | `false` when the converter's tool was missing. |
| `excluded` | `true` when the converter was turned off. |
| `failure` | The error, as `<Type>: <message>`, when the converter itself crashed or could not be created, or a note that it was dropped although its dependency check passed. |
| `candidate_inputs` | How many inputs it set out to convert, when it counts them. |
| `refused_inputs` | Inputs it declined to read, each with `path`, `member` (for an archive member) and `reason`, such as links, special files, and archive members with absolute names or names that would land outside the extraction directory. These never fail the scan. |
| `failed_inputs` | Inputs it tried and could not convert, each with `path` and `reason`, such as a corrupt archive or a notebook nbconvert could not read. A reason that comes from an unexpected error is the error's type and message, such as `BadZipFile: Bad CRC-32 for file 'app.py'`. |
| `converted_paths` | The files it wrote under `converted/`. |

A converter with a `failure`, any `failed_inputs`, or a missing tool while it had inputs
makes the conversion incomplete. Under the default `fail_on_incomplete_scanners` the scan
then exits 1, because the scanners were given fewer files than the repository has. The
console line for each such converter, and its entry in `incomplete_converters` in the MCP
scan results, give its `failure`, the number of failed inputs and up to five of their
paths, or `dependencies unavailable, so it never ran`.

<!-- doctest: config kind=ash-output model=automated_security_helper.models.asharp_model.AshAggregatedResults.converter_results -->
```json
{
  "archive": {
    "dependencies_satisfied": true,
    "excluded": false,
    "failure": null,
    "candidate_inputs": null,
    "refused_inputs": [],
    "failed_inputs": [
      {"path": "bundle.zip", "reason": "it is not a zip or tar archive Python can read"}
    ],
    "converted_paths": []
  }
}
```

### Suppressions and ignore paths in `ash_config`

Each entry under `ash_config.global_settings.suppressions` and
`ash_config.global_settings.ignore_paths` has a `client_supplied` flag. ASH sets it to
`true` on entries that came from the config file of a tree an MCP client delivered, and
marks the findings they hide in the SARIF (below). Treat the flag as a label for reading
results, not as an access control. See
[Configuration trust model](../concepts/trust-model.md#client-supplied).

## SARIF {#sarif}

`reports/ash.sarif` and the `sarif` member of `ash_aggregated_results.json` hold the same
SARIF 2.1.0 run, written two ways. The member writes every field of every result,
defaults included, so its results show `"ruleIndex": -1`, and `"rule": null` unless the
scanner gave one. `reports/ash.sarif` leaves out the fields ASH did not set, `ruleIndex`
among them, and the empty ones, and adds each result's `rule` reference (below). After a
scan of the sample project:

<!-- doctest: run expect-exit=2 -->
```bash
ash --scanners detect-secrets --no-progress
```

```python
import json

with open(".ash/ash_output/ash_aggregated_results.json", encoding="utf-8") as f:
    member = json.load(f)["sarif"]["runs"][0]["results"][0]
with open(".ash/ash_output/reports/ash.sarif", encoding="utf-8") as f:
    report = json.load(f)["runs"][0]["results"][0]
for name, result in (("sarif member", member), ("reports/ash.sarif", report)):
    print(name, result.get("ruleIndex", "no ruleIndex"), result.get("rule", "no rule"))
```

<!-- doctest: output -->
```text
sarif member -1 None
reports/ash.sarif no ruleIndex no rule
```

The run:

- `tool.driver` is ASH itself (`AWS Labs - Automated Security Helper`, with ASH's
  version).
- `tool.extensions` has one entry per scanner that produced SARIF, named after the
  scanner, carrying that scanner's rules and, as `version`, the version the scanner's
  own run reported. Some extensions also carry `semanticVersion`. When ASH does not know
  a scanner's version, `version` is left out. A scanner that produces only an SBOM, such
  as syft, has no entry.
- `results` holds every scanner's results, appended without merging duplicates. Every
  result has a `level`; ASH fills in the level of a result that stated none, as
  [How ASH counts findings](../how-to/read-results.md#counting) describes.
- In `reports/ash.sarif`, a result whose rule its scanner's extension defines carries
  `rule`, as SARIF asks for rules defined in an extension: `rule.toolComponent` gives
  the extension's `name` and its `index` in `tool.extensions`, and `rule.index` is the
  rule's position in that extension's `rules`. A result whose rule no extension defines,
  such as a detect-secrets result, has no `rule`.
- `invocations` has one entry per scanner run, with its command line, working
  directory, exit code, and times. The command lines contain absolute paths from the
  machine that ran the scan.

Each result's `properties` carries `scanner_name`, `tags`, `scanner_details`
(`tool_name`, `tool_version`, and the run's start and end times), and `issue_severity`
when the scanner integration assigned one. `scanner_version` and
`scanner_details.tool_version` hold the scanner's own version, and are left out when
ASH does not know it. Locations in the source directory are relative to it, wherever
ASH runs from. Findings in `converted/` point into the output directory.

<!-- doctest: config kind=ash-output model=automated_security_helper.schemas.sarif_schema_model.Result -->
```json
{
  "ruleId": "B602",
  "rule": {"id": "B602", "index": 2, "toolComponent": {"name": "bandit", "index": 0}},
  "level": "error",
  "message": {"text": "subprocess call with shell=True identified, security issue."},
  "locations": [
    {"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 7, "endLine": 7}}}
  ],
  "suppressions": [
    {
      "kind": "inSource",
      "justification": "(ASH) Suppressing finding for rule 'B602' in 'app.py' with reason: Commands come from a fixed allowlist in this demo"
    }
  ],
  "properties": {
    "tags": ["bandit"],
    "issue_confidence": "HIGH",
    "issue_severity": "HIGH",
    "scanner_name": "bandit",
    "scanner_version": "bandit 1.9.4",
    "scanner_details": {
      "tool_name": "bandit",
      "tool_version": "bandit 1.9.4",
      "tool_invocation": {
        "start_time": "2026-10-11T18:11:00.025599+00:00",
        "end_time": "2026-10-11T18:11:00.954843+00:00"
      }
    }
  }
}
```

A suppressed finding stays in `results` with a `suppressions` entry:

| Source of the suppression | `kind` | `justification` starts with |
|---|---|---|
| A `global_settings.suppressions` entry | `inSource` | `(ASH) Suppressing finding for rule ...` |
| An inline `ash-ignore` comment | `inSource` | `(ASH inline)` |
| An entry from the config of a tree an MCP client delivered | `inSource` | `(ASH, client-supplied config)` |
| An ignore path or scanner exclusion from such a config | `external` | `(ASH, client-supplied config)` |

Client-supplied entries also carry `properties.clientSupplied: true`. A finding under
one of your own `global_settings.ignore_paths` is removed from the results, not
suppressed. See [Suppressions, ignore paths, and scanner exclusions](../concepts/suppressions.md).

In workspace mode the document has one run per project. Each run declares its
project's root in `originalUriBaseIds`, keeps its URIs relative to that root, and gives
the workspace-relative path in `properties.workspace_uri`.

`reports/ash.ghas.sarif` is a smaller variant for GitHub code scanning; see
[`github-ghas`](reporters.md#github-ghas).

## Reports {#reports}

`reports/` holds one file per enabled reporter, named `ash.<extension>`, or `ash.txt`
for a reporter that declares no extension. The table lists the reporters ASH ships and
whether each is enabled by default; [Reporters](reporters.md) gives each one's format
and options.

A reporter's `extension` must be a file name suffix. A configured `extension` that
contains `/`, `\`, `:`, `..`, or a NUL character is ignored with a warning, and the
reporter's default is used. If a reporter's report file name is still not a single file
name, one that is not empty, `.`, or `..`, contains no `/`, `\`, `:`, or NUL, and does
not name a Windows device (`nul.json`, `con`, `com1.txt`), the run stops with exit 1
before any reporter writes. The colon is refused on every platform because on NTFS
`ash.json:stream` names an alternate data stream of `ash.json`, another reporter's file.
A file a reporter writes beside its report through `write_report_file` follows the same
rule, and a symbolic link at that name, or a `reports/` directory that has become a
symbolic link or a directory junction by the time of the write, is refused and the
refusal raised (`OutputLinkRefused` for a symbolic link, `OutputDirLinkRefused` for a
junction), as for any other output file ([Links are refused](#links)), instead of being
skipped with a warning.

| File | Reporter | Enabled |
|---|---|---|
| `ash.cdx.json` | [`cyclonedx`](reporters.md#cyclonedx) | yes |
| `ash.csv` | [`csv`](reporters.md#csv) | yes |
| `ash.flat.json` | [`flat-json`](reporters.md#flat-json) | yes |
| `ash.ghas.sarif` | [`github-ghas`](reporters.md#github-ghas) | yes |
| `ash.gl-dependency-scanning-report.cdx.json` | [`gitlab-cyclonedx`](reporters.md#gitlab-cyclonedx) | yes |
| `ash.gl-sast-report.json` | [`gitlab-sast`](reporters.md#gitlab-sast) | yes |
| `ash.html` | [`html`](reporters.md#html) | yes |
| `ash.junit.xml` | [`junitxml`](reporters.md#junitxml) | yes |
| `ash.ocsf.json` | [`ocsf`](reporters.md#ocsf) | yes |
| `ash.sarif` | [`sarif`](reporters.md#sarif) | yes |
| `ash.summary.md` | [`markdown`](reporters.md#markdown) | yes |
| `ash.summary.txt` | [`text`](reporters.md#text) | yes |
| `ash.unused-suppressions.json`, `ash.unused-suppressions.md` | [`unused-suppressions`](reporters.md#unused-suppressions) | yes |
| `ash.spdx.json` | [`spdx`](reporters.md#spdx) | no |
| `ash.yaml` | [`yaml`](reporters.md#yaml) | no |

Reporters from plugin modules, such as the AWS reporters, write their files here too. A
reporter that fails logs an error and leaves its file out; it does not change the exit
code.

`ash.flat.json` holds `metadata` (the project name, the scan and report times, and ASH's
version), `scanner_metrics` (one row per scanner with its counts, `status`, `excluded`,
`dependencies_missing`, `missing_reason`, and `skipped_reason`), `content_databases`,
`top_hotspots`, and `findings`, one record per finding. A finding's `id` is
`<scanner>-<rule>-<12 hex digits>`, such as `bandit-B602-426afbe0ae52`, and no two
findings in a scan share one. The digits are a hash of what identifies the finding: the
SARIF fingerprints its scanner gives, when they tell findings apart, or else its file
and its start and end lines, plus the package for a dependency finding and the project
in a workspace scan. A file a converter wrote is identified by its path under
`converted/`. Findings that share all of that, such as two secrets on one line, are told
apart by their column and message. So a finding keeps its id from one scan to the next,
unless it has no fingerprints and an edit above it moves it to other lines.

## Per-scanner results {#per-scanner-results}

`scanners/<name>/` is where each scanner writes, and under the sandbox it is the only
directory a scanner can write to. Each target's directory below it holds the tool's raw
output (SARIF, JSON, `<Class>.stdout.log`, and `<Class>.stderr.log`), the configuration
files ASH generated for the tool, and `ASH.ScanResults.json`, ASH's record of that run.
Some scanners keep the files ASH generated in `scanners/<name>/` itself. Every scanner
gets a directory; one that did not run holds only a short `ASH.ScanResults.json` with
its status.

`ASH.ScanResults.json` has:

| Name | Meaning |
|---|---|
| `scanner_name`, `target`, `target_type` | Which scanner ran, on which directory, and whether it was `source` or `converted`. |
| `exit_code` | The tool's exit code. |
| `start_time`, `end_time`, `duration` | When it ran. |
| `finding_count`, `severity_counts` | How many results the run produced, suppressed ones included, and their split by severity, with suppressed results under `suppressed`. |
| `status` | The status of this run. It can differ from the scanner's row in `scanner_results`, which is the verdict the summary table shows. |
| `targets_attempted`, `targets_failed` | For scanners that count their inputs, how many they tried and how many they could not evaluate. |
| `raw_results` | For a failed run, `errors`, `exception`, and `stack_trace`. |
