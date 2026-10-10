# Set when a scan fails

A scan's exit code is its verdict: 0 passes, 2 means findings failed it, 1 means the scan did not produce a result you can rely on, and 3 means the config is invalid. This page shows which settings decide the verdict, in what order ASH checks them, and how to set them for CI. Every code, for every command, is in [Exit codes](../reference/exit-codes.md).

## What decides the exit code {#order}

ASH decides the exit code from these conditions, in order, and stops at the first one that holds:

| Order | Condition | Exit | Controlled by |
|---|---|---|---|
| 1 | The config does not validate | 3 | The config itself; ASH stops before scanning |
| 2 | A selected scanner did not complete (ERROR, MISSING, or some targets not scanned), no scanner ran, or a converter failed | 1 | `fail_on_incomplete_scanners`, on by default |
| 3 | A rule could not be evaluated, such as a cdk-nag rule that raised an error on a template | 1 | Always checked |
| 4 | A content database is past its age bound | 1 | `content_db_staleness`, `fail` by default |
| 5 | `fail_on_findings` is off | 0 | `fail_on_findings`, on by default |
| 6 | An unsuppressed finding is at or above its scanner's severity threshold, and an unsuppressed finding is at or above `--min-severity` | 2 | The thresholds and `--min-severity` |
| 7 | None of the above | 0 | |

Two consequences of the order: a scan with findings and a MISSING scanner exits 1, not 2, and turning off `fail_on_findings` does not hide an incomplete scan or a stale database.

Suppressed findings and findings under an ignore path never count in row 6. See [Suppress a finding](suppress-findings.md).

## Severity thresholds {#thresholds}

The threshold names the least severe finding that still fails the scan. A higher threshold is a looser gate:

| Threshold | Findings that fail the scan |
|---|---|
| `ALL` | CRITICAL, HIGH, MEDIUM, LOW and INFO |
| `LOW` | CRITICAL, HIGH, MEDIUM and LOW |
| `MEDIUM` (default) | CRITICAL, HIGH and MEDIUM |
| `HIGH` | CRITICAL and HIGH |
| `CRITICAL` | CRITICAL |

Set it for the whole scan in `global_settings`, and for one scanner in its options. A scanner's own threshold replaces the global one for that scanner, in either direction; `null` (the default) uses the global one.

```yaml
global_settings:
  severity_threshold: HIGH
scanners:
  detect-secrets:
    options:
      severity_threshold: ALL
  grype:
    options:
      severity_threshold: CRITICAL
```

The values are uppercase and case-sensitive. `high`, `INFO` and `NONE` are not thresholds, and a config that uses them is refused:

<!-- doctest: run expect-exit=3 -->
```bash
ash --source-dir . --scanners detect-secrets --offline --no-progress \
  --config-overrides global_settings.severity_threshold=high
```

When no config sets the global threshold, the `ASH_DEFAULT_SEVERITY_LEVEL` environment variable does, with the same values; an unrecognized value falls back to `MEDIUM` with a warning.

A finding's severity is the one its scanner reports. A scanner that reports none is graded from its SARIF level: `error` is CRITICAL, `warning` is MEDIUM and `note` is LOW. detect-secrets and gitleaks findings are graded CRITICAL this way, although `ash.flat.json` and `ash.csv` show them as HIGH, so a `CRITICAL` threshold still fails on them. For trivy, ASH also passes the threshold to trivy itself (`trivy --severity`), so trivy does not report findings below it at all.

### `--min-severity`

`--min-severity` (`critical`, `high`, `medium`, `low` or `none`; default `low`) is a second, scan-wide condition on the command line. A scan that fails its thresholds exits 2 only when at least one unsuppressed finding is at or above this severity; otherwise it exits 0. `critical` and `high` are equivalent. `none` turns the condition off.

## Report findings without failing {#fail-on-findings}

`fail_on_findings: false` in the config, or `--no-fail-on-findings` on the command line, makes findings never fail the scan:

```bash
ash --source-dir . --scanners detect-secrets --offline --no-progress --no-fail-on-findings
```

The flag takes precedence over the config, and `--fail-on-findings` turns the gate back on whatever the config says. The scan still exits 1 when it is incomplete or a database is stale.

## Incomplete scans {#incomplete}

With `fail_on_incomplete_scanners` on, the default, a scan exits 1 when a scanner it selected did not finish: ERROR (it ran and failed), MISSING (its tool is not installed, or the sandbox could not confine it) or a scanner that lost some of its targets. It also exits 1 when no scanner ran or a converter failed. The message names each scanner and its status.

Turn a scanner you cannot run off, or exclude it, rather than turning this gate off: a SKIPPED scanner is recorded as not measured, and the gate stays on for the others. `fail_on_incomplete_scanners: false` or `--no-fail-on-incomplete-scanners` accepts a partial scan; with it off, a scan in which no scanner ran exits 0.

## Stale content databases {#content-databases}

grype, trivy and the offline semgrep and opengrep rule sets read databases that age. ASH measures each one after the scanner runs and treats a database it cannot date as stale:

| Database | Bound |
|---|---|
| `grype-db` | 120 hours |
| `trivy-db` | 24 hours |
| `semgrep-offline-rules`, `opengrep-offline-rules` | 30 days |

With `content_db_staleness: fail`, the default, a stale database fails the scan with exit 1, before `fail_on_findings` is considered, and the message says how to refresh it. With `warn`, the scan continues and the reports carry the warning. To relax one database for a limited time, add an override; it applies until 00:00 UTC on its expiration date and is then ignored with a warning:

```yaml
content_db_staleness: fail
content_db_staleness_overrides:
  - database: grype-db
    policy: warn
    expiration: "2027-03-31"
    reason: Offline runners get a new image every week
```

`--allow-stale-content-db` sets `warn` for one scan, and `--no-allow-stale-content-db` sets `fail`. Either flag replaces the config's policy and clears its overrides. [Content databases](../concepts/content-databases.md) explains the bounds, and [Run offline](run-offline.md) covers keeping the databases fresh.

## Who can change the gate {#who}

On the command line, a repository's own config is honored for every setting on this page. A repository you scan can set `fail_on_findings: false`, raise thresholds, turn scanners off, set `content_db_staleness: warn` and add suppressions, and none of it is marked in the results.

When the repository is not yours to trust, keep these settings yours:

- Pass your own config with `--config`, from a file the repository's authors cannot change. ASH then does not read the repository's config at all.
- Pass the gate flags explicitly. `--fail-on-findings`, `--fail-on-incomplete-scanners` and `--no-allow-stale-content-db` take precedence over any config file, and `--config-overrides` beats the file for the global threshold. A per-scanner threshold in the repository's config still replaces the global one for its scanner, which is why the first point matters.
- Pass `--ignore-suppressions` to report findings that suppressions and `ash-ignore` comments would hide. It lifts yours as well as the repository's.

A config file that an MCP client delivers to the ASH MCP server cannot set `fail_on_findings`, `fail_on_incomplete_scanners`, `content_db_staleness` or `content_db_staleness_overrides` to a value other than the server's own: the server refuses the whole file. Under the server's default policy such a file can still raise thresholds and turn scanners off. [Configuration trust model](../concepts/trust-model.md#denied-settings) covers both tiers.

## CI recipes {#ci}

Report findings, but fail when the scan is incomplete or a database is stale:

<!-- doctest: illustrative reason="runs every default scanner, which needs each scanner's tool installed" -->
```bash
ash --source-dir . --no-fail-on-findings
```

Fail on HIGH and CRITICAL findings, with the gate set by the pipeline rather than by the repository:

<!-- doctest: illustrative reason="names a pipeline config file outside the sample project" -->
```bash
ash --source-dir . --config "$RUNNER_TEMP/ash-gate.yaml" \
  --fail-on-findings --fail-on-incomplete-scanners --no-allow-stale-content-db
```

where the pipeline writes `ash-gate.yaml` outside the checkout (here, in the GitHub Actions runner's temporary directory):

```yaml
project_name: payments-api
global_settings:
  severity_threshold: HIGH
```

To fail on HIGH and above while still using the repository's config, override the threshold instead: `ash --source-dir . --config-overrides global_settings.severity_threshold=HIGH`.

In a sharded scan, gate on `ash merge`, which recomputes the verdict over all shards; see [Scale to large repositories](scale-large-repos.md).
