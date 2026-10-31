# Read scan results

A scan that runs to the end prints a summary table and writes its results to an output
directory. This page shows where the results go, how to read the table, and which file to
open for each task. [Output files](../reference/output-files.md) describes every file in detail.

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

<!-- doctest: output -->
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
  `converted/`, and `analysis/`, and removes the top-level results files, before it
  writes. Copy anything you want to keep. In local mode it does this only once it has
  accepted the command line and the configuration, so a scan refused with exit 5 or 3
  leaves the earlier results in place
  ([Output files](../reference/output-files.md#each-scan-replaces-the-last)).
- The default location is inside the scanned tree. Keep it out of version control:
  `ash config init` writes a `.ash/.gitignore` that ignores `ash_output*`.
- ASH refuses an output directory that is itself a symbolic link or a Windows junction,
  that is reached through one below the scanned directory (such as a linked `.ash`), or
  that has one at `reports/`, `scanners/`, `converted/`, `analysis/`, or a file ASH writes
  there, such as `ash.log`. The scan stops with exit code 3 before it writes anything.
  See [Output files](../reference/output-files.md#links).
- Reports contain source text. ASH masks secrets in finding messages, but the code
  snippets attached to findings are copied as they are, secrets included. Treat the
  output directory like the code it came from.

## Read the summary table

After the scan, ASH prints one row per scanner. This scan of a small project ran with
`--scanners bandit,cdk-nag,detect-secrets,grype` on a machine without grype: bandit
found an actionable finding, grype's tool was missing, cdk-nag had no CloudFormation
template to read, and semgrep was not selected (trimmed to four rows):

```text
                                                 ASH Scan Results Summary
┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━┳━━━━━━━━┳━━━━━┳━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━┓
┃ Scanner        ┃ Suppressed ┃ Critical ┃ High ┃ Medium ┃ Low ┃ Info ┃ Duration ┃ Actionable ┃ Result  ┃ Threshold       ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━╇━━━━━━━━╇━━━━━╇━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━┩
│ bandit         │ 0          │ 0        │ 1    │ 0      │ 2   │ 0    │ 889ms    │ 1          │ FAILED  │ MEDIUM (global) │
│ cdk-nag        │ 0          │ 0        │ 0    │ 0      │ 0   │ 0    │ <1ms     │ 0          │ SKIPPED │ MEDIUM (global) │
│ grype          │ 0          │ 0        │ 0    │ 0      │ 0   │ 0    │ <1ms     │ 0          │ MISSING │ MEDIUM (global) │
│ semgrep        │ 0          │ 0        │ 0    │ 0      │ 0   │ 0    │ <1ms     │ 0          │ SKIPPED │ MEDIUM (global) │
└────────────────┴────────────┴──────────┴──────┴────────┴─────┴──────┴──────────┴────────────┴─────────┴─────────────────┘
                                                      source-dir: '.'
                                               output-dir: '.ash/ash_output'

Scan incomplete: grype (MISSING)
```

When the terminal is narrower than 100 columns, or the output is not a terminal (as when
you redirect it to a file), the headers are shortened to S, C, H, M, L, I, Time, Action,
Result, and Thresh, and the threshold reads `MED (g)`.

| Column | Meaning |
|---|---|
| Suppressed | Findings a suppression matched. They are not in the severity columns and never count as actionable. |
| Critical to Info | Unsuppressed findings at each severity (see [How ASH counts findings](#counting)). |
| Duration | How long the scanner ran. |
| Actionable | Unsuppressed findings at or above the scanner's threshold. These decide whether the scan fails. |
| Result | The scanner's status, below. |
| Threshold | The threshold and where it came from: `global` is `global_settings.severity_threshold` (default `MEDIUM`), `config` is the scanner's own `scanners.<name>.options.severity_threshold`. |

The Result column has five values. A row takes the first one that applies, in this
order: `ERROR`; `FAILED`; `SKIPPED` because the scanner was not selected or its platform
is not supported; `MISSING`; `SKIPPED` because it had nothing to read; `PASSED`.

| Result | What happened | What to do |
|---|---|---|
| `ERROR` | The scanner produced no usable result for a target: its tool failed, or never started as asked, recorded with the start-failure code 127 (a sandbox the configuration asks for that ASH cannot provide, for example). One good target does not outweigh another, so the row is `ERROR` when any target failed or was never evaluated. On Linux and macOS, a tool ended by a signal ASH did not send, such as an out-of-memory kill, is `ERROR` whatever exit codes the scanner accepts, with an error that names the signal and an exit code of 128 plus the signal's number. How a sandbox backend's own exit code is read back is the note under the table. | Read the error in the scan output or in `ash.log`; the full record is in `scanners/<name>/source/ASH.ScanResults.json`. |
| `FAILED` | The scanner ran and reported at least one actionable finding. It says nothing about the tool crashing. | Fix or suppress the findings. |
| `SKIPPED` (not selected) | The scanner was not selected (`--scanners`, `--exclude-scanners`, `enabled: false`, or `--python-only`), or its platform is not supported. | Nothing, unless you expected it to run. |
| `MISSING` | The scanner never ran: its tool was not found, or was found only inside the scanned directory. | Install the tool (`ash dependencies install`), or see [Troubleshoot](troubleshoot.md). |
| `SKIPPED` (nothing to read) | The scanner had nothing to read, such as cdk-nag with no CloudFormation template, npm-audit with no lockfile beside a `package.json`, or actionlint with no workflows. These are `SKIPPED` whether or not their tools are installed. | Nothing, unless you expected it to find files. |
| `PASSED` | The scanner ran and nothing reached its threshold. Findings below the threshold still show in the severity columns. | Nothing. |

Under a sandbox backend that reports a signal death as its own exit (bwrap and firejail; ASH knows which backends report this way), a scanner exit of 128+N is read back as a likely death by signal N: the scanner's row is ERROR with a reason that says 'likely' and names the exit code it came from, and the run's exit reflects it. This is an inference from the shell convention. A scanner that declares its tool's exit code a count of findings (cfn_nag) opts out, and such an exit grades by the findings the tool rendered; a native signal death still reads as one for every scanner. Unsandboxed runs and backends without the behavior keep such an exit as the tool's own answer.

The read-back takes only exits 129 through 192 (N of 1 to 64); 128, 255 and codes above the range stay the tool's own answer. Its fail-closed direction is deliberate: a tool that itself exits with such a code under such a backend reads as a signal death, which errs toward never reporting a killed scan as passed. The count opt-out trades that direction away for its scanner: under such a backend a count-declaring scanner's death by signal arrives only as the backend's own 128+N exit, indistinguishable by the exit code alone from a count, so it grades by the findings the tool rendered.

Lines under the table add what the status cannot say: `Incomplete coverage` names a
scanner that could not read some of its inputs, `Scan incomplete` lists the scanners
that did not finish, and a stale content database is reported there too.

The exit code follows the table. By default an `ERROR` or `MISSING` row, a scan where
every scanner was `SKIPPED`, including one in which no selected scanner had a file to
scan, or a file a converter could not convert makes the scan exit 1, and an actionable finding makes it exit 2. [Set the gate](set-the-gate.md) changes
these rules, and [Exit codes](../reference/exit-codes.md) lists them all.

The Markdown, text, and HTML reports carry the same table, and `ash.flat.json` has the
same counts under `scanner_metrics`.

## How ASH counts findings {#counting}

The counts come from the aggregated SARIF after suppressions are applied, so the table,
the reports, and the exit code agree on which findings are actionable.

A finding counts as suppressed when its SARIF result carries a suppression: one ASH
applied from a `global_settings.suppressions` entry or an inline `ash-ignore` comment,
or one the scanner recorded itself. A finding under `global_settings.ignore_paths` is
removed, not counted. See [Suppress findings](suppress-findings.md).

ASH gives each unsuppressed finding one severity, from the first of these that exists:

1. The severity the scanner integration assigned (the result's `issue_severity`
   property: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`).
2. The rule's CVSS base score (its `security-severity` property): 9 or more is
   critical, 7 or more high, 4 or more medium, above 0 low. A score of 0, or one that
   is not a number from 0 to 10, counts as no score.
3. The SARIF level: `error` is critical, `warning` medium, `note` low, and `none`
   info. A result that states no level takes `none` when its `kind` is not `fail`,
   else its rule's `defaultConfiguration.level`, else `warning`. A level that is not
   one of the four also counts as `warning`.

So a rule's CVSS score wins over the scanner's level, in either direction: an `error`
advisory with a score of 5.0 counts as medium.

A finding is actionable when its severity is at or above the threshold;
[Severity thresholds](set-the-gate.md#thresholds) lists the severities each threshold
includes.

The table, the exit code, `ash inspect findings`, and every report except
`ash.ghas.sarif` give a finding this same severity. Formats with a scale of their own
carry it in that scale: GitLab SAST as `Critical` to `Info`, and OCSF as `severity_id` 5
to 1.

`ash.ghas.sarif` gives each rule one `security-severity` score, which GitHub code
scanning reads as the severity of that rule's alerts. The score is the first of these
that exists:

1. The score the rule's scanner gives it, unchanged.
2. The score for the most severe of the rule's findings, suppressed findings included,
   from the table below. A finding's severity here is its `issue_severity`, else its
   SARIF level, as in the list above.
3. The score for the rule's `defaultConfiguration.level`, read the same way.
4. 6.0.

| ASH severity | `security-severity` | GitHub shows |
|--------------|---------------------|--------------|
| CRITICAL | 9.5 | Critical |
| HIGH | 8.0 | High |
| MEDIUM | 6.0 | Medium |
| LOW | 3.0 | Low |
| INFO | 1.0 | Low |

So every alert from one rule shows the same severity, and a rule that its scanner scores
can show a severity other than ASH's: a finding with `issue_severity` `HIGH` under a rule
scored 5.0 is high for ASH and medium on GitHub. GitHub reads a score of 0.0, or one
outside 0.1 to 10.0, as no security severity.

ASH does not merge findings across scanners. When two scanners report the same issue,
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

In `ash_aggregated_results.json`, a scanner's row says why it did not run.
`missing_reason` on a `MISSING` row gives the reason: the tool that was not found and
where ASH looked, what the scanner's own check reported (semgrep offline with no rule
cache, for example), or that the tool was found only inside the scanned directory.
`skipped_reason` on a `SKIPPED` row names the option
that left the scanner out, or what it had nothing to scan, as in
`no CloudFormation template in the scanned files`. The row's `exit_code` is the tool's
exit code, the highest over its targets, the start-failure code 127 for a tool that
could not start as asked, or `null` when no tool ran.

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

<!-- doctest: output -->
```text
detect-secrets FAILED 1
```

## Print a report in the terminal with `ash report`

`ash report` renders a report of the last scan and prints it to standard output. It reads
`ash_aggregated_results.json` only from `.ash/ash_output` under the current directory, and
does not write a report file:

```bash
ash report
```

The default format is `markdown`. `--format` takes any reporter name, including reporters
a scan does not run by default, such as `yaml`:

```bash
ash report --format text
```

To read another output directory, pass `--output-dir`, or set `ASH_OUTPUT_DIR`. ASH looks
for the results file in `.ash/ash_output` and `ash_output` under that directory, and in the
directory itself, and reports on the one it finds:

```bash
ash report --output-dir build/ash-results --format sarif > build/ash-report.sarif
```

When more than one of the three holds a results file, ASH prints
`More than one scan results file found:` with each path, reports on none, and exits 5.
Point `--output-dir` at the directory that holds the one to report on.

`ash report` writes its log to standard error, so standard output holds the report
alone. To get the report exactly as the reporter wrote it, command lines included,
redirect standard output to a file, as in the command above: ASH then writes the
reporter's output unchanged, so the command above writes a SARIF file.

On a pipe, ASH changes every line of the report that a CI system (GitHub Actions, Azure
Pipelines, or TeamCity) would read as a command, so that none of them runs, whether or
not a CI variable is set. A JSON report has the `#` of a `##name[` form written as JSON's
own escape for it, so it parses to the same document. On a terminal it changes those
lines when `GITHUB_ACTIONS`, `TF_BUILD`, or `TEAMCITY_VERSION` is set. Apart from that,
the output on a pipe is the reporter's output as the reporter wrote it, not wrapped or
styled. On a terminal with color, JSON is indented and Markdown is rendered. On a
terminal, with or without color, no character a terminal acts on is written as it is: it
is shown as an escape, such as `\x1b` for an escape character in a file name, or in a
JSON report as JSON's own escape, such as `\u001b`. Rendered Markdown leaves such
characters out. ASH's own messages, such as a refusal that quotes a path, have their CI
command lines changed the same way even when they go to a file; only the report itself
is written to a file as is.

A missing results file prints `No scan results found:` with the paths it checked, and
exits 1. With `--output-dir` or `ASH_OUTPUT_DIR` the message names the three paths ASH
looked in (`none of … exists`); otherwise it names
`.ash/ash_output/ash_aggregated_results.json` under the current directory, in full
(`… does not exist`). `ash report` creates nothing then, and an output directory under a
directory it cannot search counts as missing. An output directory that exists but cannot
be entered is refused with exit 5, `Output directory cannot be entered:` and the path as
given. So is an output directory that is a file, `Output directory is not a directory:`,
and a path the system cannot look up, such as one holding a NUL character,
`Output directory is not a valid path:`. None of these refusals creates anything. An
unknown format is refused before the results are read: ASH
prints `Error: Reporter plugin '<name>' not found.` and the reporter names, and exits 5.

<!-- doctest: run expect-exit=5 -->
```bash
ash report --format nosuch
```

The reporters are listed in [Reporters](../reference/reporters.md).

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

The Severity column uses the same severity as the summary table (see
[How ASH counts findings](#counting)).

`x` asks for a reason and an optional expiration date, then adds a suppression for that
rule, file, and line to a config file: the one `--config` or `ASH_CONFIG` names, else the
config file a scan of the current directory would use, else `.ashrc.yaml` in the current
directory. It writes YAML, or JSON to a `.json` file. It refuses a TOML file, and a file
that `extends` another and has no suppressions list of its own, because writing one there
would replace the base file's list. If the file already has the same suppression, `x`
writes nothing; one that differs, such as another line range for the same rule and file,
is added. The suppression applies from the next scan. See
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
`sarif_excluded_fields.json`, `sarif_excluded_fields.csv`, and
`sarif_validation_report.html` to the output directory, which defaults to
`.ash/ash_output/inspect` under the current directory. It exits 1 when it finds no SARIF
files.

`ash scan --inspect` runs the same analysis at the end of a scan, on that scan's output
directory, and writes the files to its `analysis/` directory.
