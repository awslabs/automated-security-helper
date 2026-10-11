# Read scan results

Every scan prints a summary table and writes its results to an output directory. This
page shows where the results go, how to read the table, and which file to open for each
job. [Output files](../reference/output-files.md) describes every file in detail.

## Where results land

ASH writes to `.ash/ash_output` under the directory it scans. Run from your project root,
that is `.ash/ash_output` in the current directory:

<!-- doctest: run expect-exit=2 -->
```bash
ash --scanners detect-secrets --no-progress
```

```bash
ls .ash/ash_output
```

```text
analysis
ash-ignore-report.txt
ash-scan-set-files-list.txt
ash.log
ash_aggregated_results.json
converted
reports
scanners
```

With `--source-dir`, the default moves with it: `ash --source-dir ../service` writes to
`../service/.ash/ash_output`. To write somewhere else, pass `--output-dir`, or set
`ASH_OUTPUT_DIR`. If you give the source directory itself as the output directory, ASH
writes to `.ash/ash_output` inside it instead.

<!-- doctest: run expect-exit=2 -->
```bash
ash --scanners detect-secrets --no-progress --output-dir build/ash-results
```

Things to know about the output directory:

- Each scan replaces the previous results. ASH empties `reports/`, `scanners/`,
  `converted/` and `analysis/`, and removes the top-level results files, before it
  writes. Copy anything you want to keep.
- The default location is inside the scanned tree. Keep it out of version control:
  `ash config init` writes a `.ash/.gitignore` that ignores `ash_output*`.
- ASH refuses an output directory that is reached through a symbolic link or a Windows
  junction, or that has one at `reports/`, `scanners/`, `converted/` or `analysis/`. The
  scan stops with exit code 1 before it writes anything. See
  [Output files](../reference/output-files.md#links).
- Reports contain source text. ASH masks secrets in finding messages, but the code
  snippets attached to findings are copied as they are, secrets included. Treat the
  output directory like the code it came from.

## Read the summary table

After the scan, ASH prints one row per scanner. In this scan of a small project, one
scanner failed, one scanner's tool was missing, and most scanners were not selected
(trimmed to four rows):

```text
                                                 ASH Scan Results Summary
┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━┳━━━━━━━━┳━━━━━┳━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━┓
┃ Scanner        ┃ Suppressed ┃ Critical ┃ High ┃ Medium ┃ Low ┃ Info ┃ Duration ┃ Actionable ┃ Result  ┃ Threshold       ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━╇━━━━━━━━╇━━━━━╇━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━┩
│ actionlint     │ 0          │ 0        │ 0    │ 0      │ 0   │ 0    │ 3ms      │ 0          │ ERROR   │ MEDIUM (global) │
│ bandit         │ 0          │ 0        │ 1    │ 1      │ 2   │ 0    │ 528ms    │ 2          │ FAILED  │ MEDIUM (global) │
│ cdk-nag        │ 0          │ 0        │ 0    │ 0      │ 0   │ 0    │ <1ms     │ 0          │ SKIPPED │ MEDIUM (global) │
│ gitleaks       │ 0          │ 0        │ 0    │ 0      │ 0   │ 0    │ <1ms     │ 0          │ MISSING │ MEDIUM (global) │
└────────────────┴────────────┴──────────┴──────┴────────┴─────┴──────┴──────────┴────────────┴─────────┴─────────────────┘

Incomplete coverage: actionlint evaluated 0 of 1 target(s); 1 could not be evaluated and
contributed no findings. See the scanner's exitCodeDescription in its SARIF report for the
reason per target.
Scan incomplete: actionlint (ERROR), gitleaks (MISSING)
```

When the terminal is narrower than 100 columns, or the output goes to a file, the headers
are shortened to S, C, H, M, L, I, Time, Action, Result and Thresh, and the threshold
reads `MED (g)`.

| Column | Meaning |
|---|---|
| Suppressed | Findings a suppression matched. They are not in the severity columns and never count as actionable. |
| Critical to Info | Unsuppressed findings at each severity (see [How ASH counts findings](#counting)). |
| Duration | How long the scanner ran. |
| Actionable | Unsuppressed findings at or above the scanner's threshold. These decide whether the scan fails. |
| Result | The scanner's status, below. |
| Threshold | The threshold and where it came from: `global` is `global_settings.severity_threshold` (default `MEDIUM`), `config` is the scanner's own `scanners.<name>.options.severity_threshold`. |

The Result column has five values. A row takes the first one that applies, in this order:

| Result | What happened | What to do |
|---|---|---|
| `ERROR` | The scanner started and produced no usable result for any of its targets. | Read the error in the scan output or in `ash.log`; the full record is in `scanners/<name>/source/ASH.ScanResults.json`. |
| `FAILED` | The scanner ran and reported at least one actionable finding. It says nothing about the tool crashing. | Fix or suppress the findings. |
| `SKIPPED` | The scanner was not selected (`--scanners`, `--exclude-scanners`, `enabled: false`, `--python-only`), its platform is not supported, or it had nothing to read, such as actionlint in a repository with no workflows. | Nothing, unless you expected it to run. |
| `MISSING` | The scanner never ran: its tool was not found, was found only inside the scanned directory, or the scanner could not be sandboxed as requested. | Install the tool (`ash dependencies install`), or see [Troubleshoot](troubleshoot.md). |
| `PASSED` | The scanner ran and nothing reached its threshold. Findings below the threshold still show in the severity columns. | Nothing. |

Lines under the table add what the status cannot say: `Incomplete coverage` names a
scanner that could not read some of its inputs, `Scan incomplete` lists the scanners
that did not finish, and a stale content database is reported there too.

The exit code follows the table. By default an `ERROR` or `MISSING` row, a scan where
every scanner was `SKIPPED`, or a file a converter could not convert makes the scan exit
1, and an actionable finding makes it exit 2. [Set the gate](set-the-gate.md) changes
these rules, and [Exit codes](../reference/exit-codes.md) lists them all.

The markdown, text and HTML reports carry the same table, and `ash.flat.json` has the
same counts under `scanner_metrics`.

## How ASH counts findings {#counting}

The counts come from the aggregated SARIF after suppressions are applied, so the table,
the reports and the exit code agree on which findings are actionable.

A finding counts as suppressed when its SARIF result carries a suppression: one ASH
applied from a `global_settings.suppressions` entry or an inline `ash-ignore` comment,
or one the scanner recorded itself. A finding under `global_settings.ignore_paths` is
removed, not counted. See [Suppress findings](suppress-findings.md).

ASH gives each unsuppressed finding one severity, from the first of these that exists:

1. The severity the scanner integration assigned (the result's `issue_severity`
   property: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` or `INFO`).
2. The rule's CVSS base score (its `security-severity` property): 9 or more is
   critical, 7 or more high, 4 or more medium, above 0 low. A score of 0, or one that
   is not a number from 0 to 10, counts as no score.
3. The SARIF level: `error` is critical, `warning` medium, `note` low, anything else
   info.

So a rule's CVSS score wins over the scanner's level, in either direction: an `error`
advisory with a score of 5.0 counts as medium.

A finding is actionable when its severity is at or above the threshold:

| Threshold | Actionable severities |
|---|---|
| `ALL` | critical, high, medium, low, info |
| `LOW` | critical, high, medium, low |
| `MEDIUM` | critical, high, medium |
| `HIGH` | critical, high |
| `CRITICAL` | critical |

Two things make counts differ between outputs:

- `ash.flat.json`, `ash.csv` and `ash inspect findings` map a SARIF `error` with no
  severity of its own to high, not critical. A checkov finding that the table counts as
  critical shows as `HIGH` in `ash.flat.json`.
- ASH does not merge findings across scanners. When two scanners report the same issue,
  such as grype and trivy finding one vulnerable package, it is counted twice. See
  [How ASH works](../concepts/how-ash-works.md#findings-are-merged-not-deduplicated).

## Pick the file to open

All paths are relative to the output directory.

| To | Open |
|---|---|
| Read the findings in a browser | `reports/ash.html` |
| Paste a summary into a pull request | `reports/ash.summary.md` (`--compact-report` shortens it) |
| Read a plain-text summary | `reports/ash.summary.txt` |
| Upload to GitHub code scanning or another SARIF tool | `reports/ash.ghas.sarif` or `reports/ash.sarif`; see [Export reports](export-reports.md) |
| Open the findings in a spreadsheet | `reports/ash.csv` |
| Process the results in a script | `ash_aggregated_results.json`, or `reports/ash.flat.json` for one record per finding |
| Find out why a scanner is `ERROR` or `MISSING` | the scan output, `ash.log`, and `scanners/<name>/source/ASH.ScanResults.json` |
| See a scanner's own output | `scanners/<name>/source/` |
| Check which files were selected for scanning | `ash-scan-set-files-list.txt`, and `ash-ignore-report.txt` for the ignore rules |
| Clean up stale suppressions | `reports/ash.unused-suppressions.md` |

A row's `missing_reason` in `ash_aggregated_results.json` says why a scanner is
`MISSING` when ASH knows more than "not installed", for example that its tool was found
only inside the scanned directory. In that file, read a scanner's `status`; its
`dependencies_satisfied`, `excluded` and `exit_code` fields keep their defaults in this
release. The tool's own exit code is in `scanners/<name>/source/ASH.ScanResults.json`.

To read the results from a script:

```python
import json
from pathlib import Path

results = json.loads(
    Path(".ash/ash_output/ash_aggregated_results.json").read_text(encoding="utf-8")
)
for name, row in sorted(results["scanner_results"].items()):
    if row["status"] != "SKIPPED":
        print(name, row["status"], row["actionable_finding_count"])
```

```text
detect-secrets FAILED 1
```

## Print a report in the terminal with `ash report`

`ash report` renders a report of the last scan and prints it. It reads
`ash_aggregated_results.json` from `.ash/ash_output` under the current directory, and
does not write a report file:

```bash
ash report
```

The default format is `markdown`. `--format` takes any reporter name, including reporters
a scan does not run by default, such as `yaml`:

```bash
ash report --format text
```

To read another output directory, pass `--output-dir`. ASH looks for the results file in
`.ash/ash_output` and then `ash_output` under that directory, and then in the directory
itself:

```bash
ash report --output-dir build/ash-results --format sarif
```

`ash report` styles its output for the terminal and wraps it at the terminal's width,
even when you redirect it. To keep a report in a file, use the copy in `reports/`.
A missing results file prints `Error loading results file` and exits 1. An unknown
format lists the reporter names and exits 1. The reporters are listed in
[Reporters](../reference/reporters.md).

## Explore findings with `ash inspect findings`

`ash inspect findings` opens an interactive browser of the findings in the terminal. It
reads `ash_aggregated_results.json` from `.ash/ash_output`, or from `--output-dir`:

<!-- doctest: illustrative reason="opens an interactive terminal application" -->
```bash
ash inspect findings --output-dir build/ash-results
```

| Press | To |
|---|---|
| `j`, `k` | Move to the next or previous finding |
| `v` | Show the selected finding, with its code snippet when the scanner gave one |
| `s` or `/` | Search; `Escape` leaves the search |
| `f` | Show or hide the filters |
| `h` | Show or hide suppressed findings (hidden at start) |
| `x` | Suppress the selected finding |
| `q` | Quit |

The Severity column is the SARIF level alone (`error` is high, `warning` medium, `note`
low), so it can differ from the summary table.

`x` asks for a reason and an optional expiration date, then adds a suppression for that
rule, file and line to a config file: the one `--config` or `ASH_CONFIG` names, else the
config file a scan of the current directory would use, else `.ash.yaml` in the current
directory. It refuses a TOML file, and a file that `extends` another and has no
suppressions list of its own, because writing one there would replace the base file's
list. The suppression applies from the next scan. See
[Suppress findings](suppress-findings.md) before you suppress from here.

## Check which SARIF fields survive with `ash inspect sarif-fields`

`ash inspect sarif-fields` is for plugin authors and for debugging a scanner integration.
It reads every scanner's own SARIF under `scanners/` and the reports' SARIF under
`reports/`, and shows which fields each scanner fills in and whether they reach the
aggregated report:

```bash
ash inspect sarif-fields --sarif-dir .ash/ash_output --output-dir build/sarif-fields
```

It prints a summary and writes `sarif_fields.json`, `sarif_fields.csv`,
`sarif_excluded_fields.json`, `sarif_excluded_fields.csv` and
`sarif_validation_report.html` to the output directory, which defaults to
`.ash/ash_output/inspect` under the current directory. It exits 1 when it finds no SARIF
files.

`ash scan --inspect` runs the same analysis at the end of a scan and writes the files to
`analysis/` in the output directory. It reads the SARIF files under `.ash/ash_output` in
the current directory whatever `--output-dir` says, so use it from the scanned directory
with the default output directory.
