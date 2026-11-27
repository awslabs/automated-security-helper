# Deduplicate findings across scanners

Two scanners often report the same problem: grype and trivy on one vulnerable package,
two code scanners on one line. ASH keeps both findings, because each scanner's findings
belong to that scanner's counts, baselines and suppressions. Two opt-in switches let the
reports say which findings are the same problem, without changing any of that.

| Switch | CLI flag | What it changes |
|---|---|---|
| `global_settings.deduplication.annotate` | `--annotate-duplicates` | The CSV and flat JSON reports gain three columns that name each finding's duplicate cluster. No row is added or removed. |
| `global_settings.deduplication.fold` | `--fold-duplicates` | The human-readable reports (HTML, Markdown, text, and the Bedrock summary) show one row per cluster, with a note naming the other scanners, and print deduplicated counts beside the per-scanner counts. |

Both are off by default, and they are independent: `fold` does not need `annotate`. They
are off because both change what a CI job may read. `annotate` adds three columns to the
CSV header, and `fold` changes the number of rows in the human reports.

## Turn it on

Pass a flag to `ash scan fs` or to `ash results report`:

<!-- doctest: illustrative reason="needs two scanners that report the same finding, such as grype and trivy" -->
```bash
ash scan fs --only-scanners grype,trivy --annotate-duplicates --fold-duplicates
```

`ash results report` applies the same flags to the results of an earlier scan. It only ever turns
a switch on: a scan that recorded the setting keeps it.

<!-- doctest: illustrative reason="needs the output of an earlier scan with findings from two scanners" -->
```bash
ash results report --format csv --annotate-duplicates
```

Or set the keys in your configuration:

```yaml
global_settings:
  deduplication:
    annotate: true
    fold: true
```

## What counts as the same finding

A finding joins at most one cluster, by the first class below whose fields it carries.
A class with only one matching finding makes no cluster.

| Class | Findings are in one cluster when they share | Folds |
|---|---|---|
| Package | The CVE, the package name and the package's install path. The package version is not part of the key, so a scanner that reads `1.0.0` and one that reads `1.0.1` still match. | Yes |
| Location | The file, overlapping lines and at least one CWE. A finding with no CWE never joins a location cluster. | Yes |
| IaC resource | The resource id, the resource type, the file and the same set of CWEs. | No: annotated only |

The same CVE in a different package path is not a duplicate, and neither is the same
line with a different CWE. Secrets findings carry no CWE and never cluster.

IaC clusters are annotated and never folded, because the resource ids two scanners
report are not yet known to use one vocabulary.

Each cluster has one primary finding. When the members disagree about suppression, the
primary is chosen among the unsuppressed members, so a suppressed finding never stands
in for a live one. After that, the highest severity wins, then a finding with a
fingerprint over one identified by its line numbers, then the scanner name, then the
finding id. The choice does not depend on the order of the input.

## The three columns

With `annotate` on, the CSV and flat JSON reports add these after every other column:

| Column | On a finding in a cluster | On a finding in no cluster |
|---|---|---|
| `cluster_id` | The id shared by every member | empty |
| `duplicate_of` | The primary's finding id, on every member except the primary | empty |
| `duplicate_sources` | On the primary: the other members' scanner, rule, id and severity | empty |

In flat JSON a finding in no cluster carries none of the three keys. Every other cell in
every row is the same as without the annotation.

## What the fold shows

With `fold` on, the human-readable reports (HTML, Markdown, text, and the Bedrock
summary) show one row per foldable cluster in their findings tables, detailed findings,
finding cards and hotspots, with a note such as
`Also reported by trivy CVE-2024-0001 (MEDIUM)`. The row that stands for a cluster is
an actionable member when the view holds one (the gate is per scanner, so a cluster can
mix dispositions), else the cluster's severity-ranked primary. Line-overlap clusters
chain: two findings can fold through a third that overlaps both. The summary adds
deduplicated counts next to the per-scanner counts when anything folded, labeled as
deduplicated and counting live (unsuppressed) rows. They never replace the per-scanner
counts.

## What never changes

Both switches act only when a report is written. These stay the same with them on or off:

- Finding ids. A finding's id still includes its scanner, so the two copies of a
  duplicate have two ids.
- The SARIF reports and `ash_aggregated_results.json`.
- Per-scanner metrics, the summary table's per-scanner counts and the exit code.
- Suppressions. Suppressing a finding suppresses that scanner's copy only.
- Baselines. `--baseline` matches findings by their scanner-inclusive identity, so a
  baseline that holds one scanner's copy of a duplicate does not remove the other
  scanner's copy.
- The CSV, flat JSON and JUnit reports under `fold`. Only the human reports fold.

[Read scan results](read-results.md) describes the summary table, and the
[configuration reference](../reference/configuration.md#global_settings.deduplication)
lists both keys.
