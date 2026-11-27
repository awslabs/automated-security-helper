# Track findings over time

[`ash results diff`](../reference/cli.md#results-diff) compares two scans.
[`ash results trend`](../reference/cli.md#results-trend) reads a series of them and shows,
for each run after the first, how many findings per scanner and severity are new, carried
over, fixed, and unobserved; which findings have been open longest; and where a carried
finding's severity or suppression changed. It runs no scan and writes nothing.

The top-level spelling `ash trend` still works and prints a deprecation warning; see
[The `ash results` command group](read-results.md#results-group).

ASH keeps one run in its output directory: the next scan replaces it. A series therefore
needs one saved record per run. There are two ways to keep them, and a single
`ash results trend` call reads one of them, never both.

## Option 1: archive the results file of each run {#archive}

Save `ash_aggregated_results.json` from every scan under a name that is unique to the run,
for example as a CI artifact, then pass the files to `ash results trend`. When every file
records one of ASH's timestamped report IDs, the files are put in chronological order by
it, so the order on the command line does not matter. When one does not, the order given
is kept, and the output says so.

<!-- doctest: illustrative reason="requires saved ASH scan results files from earlier runs" -->
```bash
ash results trend runs/1/ash_aggregated_results.json runs/2/ash_aggregated_results.json runs/3/ash_aggregated_results.json
ash results trend runs/*/ash_aggregated_results.json --format json
```

In CI this is one extra upload step after the scan, with a step condition that keeps it
running when the scan exits non-zero, as it does with findings (exit code 2). Download
the earlier runs' artifacts in the job that runs `ash results trend`.

This route needs no ASH configuration, and the archived files are the same ones
`ash results diff` and `--baseline` read.

## Option 2: let ASH record a compact history {#history}

Turn on `global_settings.history`. ASH then adds one small record to `history/` in the
output directory for each recorded run, and `ash results trend --history` reads them.
Recording is off by default because it adds a file to the output directory on every scan.

<!-- doctest: config kind=ash -->
```yaml
global_settings:
  history:
    enabled: true
    keep_runs: 50
```

`--history` takes the scan's output directory, not `history/` itself:

<!-- doctest: illustrative reason="requires an output directory with recorded run history" -->
```bash
ash results trend --history .ash/ash_output
```

For history to build up in CI, the output directory (or just its `history/` directory)
has to be restored before the scan and saved after it, for example with your CI system's
cache. A fresh checkout and an empty output directory start a new history.

### Which runs are recorded {#recorded}

These runs add a record:

- a scan that runs to the end, whatever its findings and exit code. A scan with incomplete
  scanner coverage is recorded too, including one that exits 1 because
  `fail_on_incomplete_scanners` is on, and its record notes the gap, so the boundaries on
  either side of it are marked as not like for like;
- `ash results merge`, described below.

These runs add none:

- a scan stopped before it finished: cancelled or timed out over MCP, or stopped by a
  SIGTERM to `ash scan`. A record already written for it is removed, unless git tracks
  it or `history/` is in a git repository whose index git cannot list;
- a scan that fails after its scan phase, which leaves its results file but no record;
- `ash scan --use-existing`, which runs only the report phase;
- the runs a comparison would refuse: an un-merged shard, the combined results of an
  `ash --workspace` scan, a `--changed-files-only` run, and a run filtered by `--baseline`.
  With the history on, a shard or a filtered scan logs a warning that starts
  `This run is not recorded in the history:`.

With `global_settings.history.enabled` on in the merged configuration (the shards'
recorded configuration, with any `--config-overrides` applied),
[`ash results merge`](../reference/cli.md#results-merge) records the merged run in its own
`--output-dir`, under the merged report's ID, once it has written the merged results file.
Merging the same shards again replaces that record rather than adding a run. To turn
recording on at the merge alone, pass
`--config-overrides global_settings.history.enabled=true`. A sharded CI therefore keeps
its history in the merge job's output directory.

### How long records are kept {#retention}

Each time ASH writes a record, it prunes `history/` to the newest `keep_runs` records
(default 50, from 1 to 10,000), ordered by the start time in their report IDs. Lowering
`keep_runs` takes effect at the next recorded run, all at once: with 50 records kept and
`keep_runs` lowered to 10, the next run's write leaves the newest 10. Pruning never
removes the record it has just written, a record git tracks (ASH keeps it and logs a
warning), a link, or a file whose name is not a run record's. When `history/` is in a git
repository whose index git cannot list, nothing is pruned that time. Each removal is
logged.

No scan removes or clears `history/`. Turning `enabled` off stops new records and pruning
and leaves the directory and its records where they are, so `ash results trend --history`
can still read them. To start a new history, delete the directory.

### What a record holds {#record}

A record is not a copy of the results file. It holds its format version, the run's
metadata (report ID, `generated_at`, project, and ASH version), the coverage markers a
comparison checks, and one row per finding: its ID, scanner, rule, severity, suppression
state, and location, plus the fields ASH pairs it by with the same finding in the next
run, which can include the finding's message. It leaves out code snippets, the scanners'
raw output, the SARIF document, and the resolved configuration.

Each row also holds `result_kind`, the SARIF kind of its result, and `is_finding`,
whether that result states a finding. A result states no finding when its kind is `pass`,
`notApplicable`, or `informational` and nothing in it reports a problem: its level is
`none` or not stated, and no `issue_severity` it declares is above INFO. The trend reads
`is_finding` and counts a row that states no finding in no total. A record written before
ASH stored `is_finding` falls back to the row's kind and severity, so a row of one of
those kinds with severity INFO counts in no total. A record written before ASH stored the
kind has neither, so the trend reads every row of it as a finding.

A record ASH cannot read is skipped: a corrupt file, one in a record format this version
of ASH does not read, or one whose report ID is not its file name. The output says how
many were skipped. A record from another project cuts the series: `ash results trend`
keeps the records newer than it, names the ones it left out, and refuses only when fewer
than two remain.

## Read the output {#read}

The text output lists the runs in order, then for each run after the first a line with
its new, carried, fixed, and unobserved totals and the boundary's warnings; a table by
run, scanner, and severity; the findings carried longest, up to ten, with the suppressed
ones in a table of their own; and the first ten changes of severity or suppression while
a finding was carried. `--format json` returns the same data, with every entry rather
than the first ten, for dashboards:

| JSON key | Holds |
|---|---|
| `trend_version` | The schema version, currently `2`. |
| `runs` | The runs in order, each with its label, report ID, `generated_at`, ASH version, and number of findings. |
| `boundaries` | For each run after the first: the labels of its two runs, `like_for_like`, the coverage warnings, and the scanners added or removed. |
| `series` | Counts per run, scanner, severity, status (`new`, `carried`, `fixed`, `unobserved`), and suppression state. |
| `streaks` | Each finding unsuppressed in the last run that was also open in the run before it: how many runs it has been open, since which run, and `left_censored`. |
| `suppressed_streaks` | The same, for findings suppressed in the last run. |
| `changes` | Each change of severity or suppression of a carried finding, with the run it changed in. |
| `ordered_by` | `report_id` when the runs were put in order by their report IDs (always so with `--history`), `given` when the order given was kept. |
| `unreadable_records` | With `--history`, how many records were skipped as unreadable; otherwise 0. |
| `history_cut` | With `--history`, the report IDs of the older records left out of the series; otherwise empty. |

A few readings to keep in mind:

- `fixed` means the finding's scanner ran in the later run and did not report it.
  `unobserved` means its scanner did not run there, so nothing looked. Neither confirms a
  fix.
- A finding that moves to different lines is paired with its earlier self and stays one
  streak. One that disappears and returns starts a new streak.
- A streak is marked `left_censored` (shown as "or earlier") when the finding may have
  been open before the streak's first run: the streak begins in the first run of the
  series, or in a run whose predecessor did not run the finding's scanner.
- A boundary is marked as not like for like when its two runs did not cover the same
  ground: the scanners expected or run differ, the recorded ignore-file exclusions differ,
  either run has incomplete scanner coverage or records too little to tell, or either
  records inputs that were not scanned. Its fixed and new counts do not measure progress,
  and the output says so.

## What `ash results trend` refuses {#refusals}

`ash results trend` exits 1 with a message on standard error, and prints nothing on
standard output, when:

- fewer than two runs are given, or the same run is given twice;
- the runs come from different projects;
- a run is a workspace aggregate, an un-merged shard, a `--changed-files-only` run, or a
  baseline-filtered run (the rules `ash results diff` applies);
- a results file cannot be read as ASH scan results, or holds duplicate finding IDs;
- results files and `--history` are given together;
- `--history` finds no run records, none that ASH can read, or fewer than two that form
  one series.

It exits 0 after a successful computation whether or not findings changed. It is a report,
not a CI gate; use [`--baseline`](ci/github-actions.md#baseline) to gate on new findings.
