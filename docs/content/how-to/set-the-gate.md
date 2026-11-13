# Set the gate

A scan's exit code is its verdict: 0 passes, 2 means findings failed it, 1 means the scan did not produce a result you can rely on, and 3 means the config is invalid. 5 is a usage error: the command line was wrong, as with an unknown option or a `--scanners` list that names no scanner. This page shows which settings decide the verdict, in what order ASH checks them, and how to set them for CI. Every code, for every command, is in [Exit codes](../reference/exit-codes.md).

## What decides the exit code {#order}

ASH decides the exit code from these conditions, in order, and stops at the first one that holds. A usage error (5) comes before all of them, except a `--scanners` list that names no scanner, which ASH refuses after the config check, when the scan phase starts; [Exit codes](../reference/exit-codes.md#scan-precedence) gives the whole order:

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

Suppressed findings and findings under an ignore path never count in row 6. See [Suppress findings](suppress-findings.md).

## Severity thresholds {#thresholds}

The threshold names the least severe finding that still fails the scan. A higher threshold is a looser gate:

| Threshold | Findings that fail the scan |
|---|---|
| `ALL` | CRITICAL, HIGH, MEDIUM, LOW, and INFO |
| `LOW` | CRITICAL, HIGH, MEDIUM, and LOW |
| `MEDIUM` (default) | CRITICAL, HIGH, and MEDIUM |
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

The values are uppercase and case-sensitive. `high`, `INFO`, and `NONE` are not thresholds, and a config that uses them is refused:

<!-- doctest: run expect-exit=3 -->
```bash
ash --source-dir . --scanners detect-secrets --offline --no-progress \
  --config-overrides global_settings.severity_threshold=high
```

When no config sets the global threshold, the `ASH_DEFAULT_SEVERITY_LEVEL` environment variable does. It takes the same five names in any case (`high` works there), and an unrecognized value falls back to `MEDIUM` with a warning.

A finding's severity is the one its scanner reports. A finding with none is graded from its rule's `security-severity` score when the rule has one (9 and above is CRITICAL, 7 HIGH, 4 MEDIUM, and above 0 LOW), and otherwise from its SARIF level: `error` is CRITICAL, `warning` is MEDIUM, and `note` is LOW. detect-secrets and gitleaks findings are graded CRITICAL this way, in the gate and in every report that carries ASH's severity, so a `CRITICAL` threshold fails on them. `ash.ghas.sarif` scores rules rather than findings, so GitHub can show these alerts at another severity; [Read the results](read-results.md#counting) explains how.

ASH does not pass a threshold to trivy, so trivy reports every finding it makes, for the built-in `trivy` scanner and for `trivy-repo` alike. ASH applies the threshold after the scan, as for every scanner, to the severity trivy gave each finding: a finding below it stays in the reports and in the summary table's severity columns, is not counted as actionable, and does not fail the scan.

### `--min-severity`

`--min-severity` (`critical`, `high`, `medium`, `low`, or `none`, in any case; default `low`) is a second, scan-wide condition on the command line. A scan that fails its thresholds exits 2 only when at least one unsuppressed finding is at or above this severity; otherwise it exits 0. `critical` and `high` are equivalent, and `none` turns the condition off. Any other value is a usage error (exit 5).

## Report findings without failing {#fail-on-findings}

`fail_on_findings: false` in the config, or `--no-fail-on-findings` on the command line, makes findings never fail the scan:

```bash
ash --source-dir . --scanners detect-secrets --offline --no-progress --no-fail-on-findings
```

The flag takes precedence over the config, and `--fail-on-findings` turns the gate back on whatever the config says. The scan still exits 1 when it is incomplete or a database is stale.

## Incomplete scans {#incomplete}

With `fail_on_incomplete_scanners` on, the default, a scan exits 1 when a scanner it selected did not finish: ERROR (it failed, or its tool could not start, as when a sandbox the configuration asks for cannot be provided), MISSING (its tool is not installed), or a scanner that lost some of its targets. It also exits 1 when no scanner ran or a converter failed. The message names each scanner and its status.

Turn a scanner you cannot run off, or exclude it, rather than turning this gate off: a SKIPPED scanner is recorded as not measured, and the gate stays on for the others. `fail_on_incomplete_scanners: false` or `--no-fail-on-incomplete-scanners` accepts an incomplete scan; with it off, a scan in which no scanner ran, or in which no selected scanner had a file to scan, exits 0.

## Stale content databases {#content-databases}

grype, trivy, and the offline semgrep and opengrep rulesets read databases that age. ASH measures each one after the scanner runs, treats a database it cannot date as stale, and fails the scan when one is past its age bound; [Content databases](../concepts/content-databases.md#which-scanners-use-one) lists the databases and their bounds.

With `content_db_staleness: fail`, the default, a stale database fails the scan with exit 1, before `fail_on_findings` is considered, and the message says how to refresh it. A scanner that passed against the stale database is recorded ERROR, with the database named, and one that failed its threshold stays FAILED. The scan reports the stale database once, as the cause of the exit code, and does not list the scanner as incomplete as well. With `warn`, the scan continues and the reports carry the warning. To relax one database for a limited time, add an override; it applies until 00:00 UTC on its expiration date and is then ignored with a warning:

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

On the command line, a repository's own config is honored for every setting on this page except the stale content database policy, which it can only make stricter ([Configuration trust model](../concepts/trust-model.md#what-each-tier-may-set)). A repository you scan can set `fail_on_findings: false`, raise thresholds, turn scanners off, and add suppressions, and none of it is marked in the results.

When the repository is not yours to trust, keep these settings yours:

- Pass your own config with `--config`, from a file the repository's authors cannot change. In a scan of one directory, ASH then does not read the repository's config at all. In workspace mode, every setting your `--config` makes is final for every project ([Scan a multi-project workspace](scale-large-repos.md#workspaces)).
- Pass the gate flags explicitly. `--fail-on-findings`, `--fail-on-incomplete-scanners`, and `--no-allow-stale-content-db` take precedence over any config file, and `--config-overrides` beats the file for the global threshold. A per-scanner threshold in the repository's config still replaces the global one for its scanner, which is why the first point matters.
- Pass `--ignore-suppressions` to report findings that suppressions, ignore paths, and `ash-ignore` comments would hide. It lifts yours as well as the repository's, and every scanner reads the files under an ignore path. In container mode it reaches the scan inside the container and works there as in a local scan. To drop only the repository's ignore paths, pass `--config-overrides 'global_settings.ignore_paths=[]'` instead.

The repository still affects the results in other ways. Its inline suppressions apply: ASH's `ash-ignore` comments unless you pass `--ignore-suppressions`, and the scanners' own comments, such as bandit's `# nosec` (set `scanners.bandit.options.ignore_nosec: true` in your config to ignore those). Its `.gitignore` and `.ignore` files also remove files from the set that several scanners read, with or without `--ignore-suppressions`; [Coverage](../reference/coverage.md#what-decides-the-files) lists which scanners use that set. [Configuration trust model](../concepts/trust-model.md#not-protected) lists the rest.

A config file that an MCP client delivers to the ASH MCP server cannot set `fail_on_findings`, `fail_on_incomplete_scanners`, `content_db_staleness`, or `content_db_staleness_overrides` to a value other than the server's own: the server refuses the whole file. Under the server's default policy such a file can still raise thresholds and turn scanners off. [Configuration trust model](../concepts/trust-model.md#denied-settings) covers both tiers.

## CI recipes {#ci}

Report findings, but fail when the scan is incomplete or a database is stale:

<!-- doctest: illustrative reason="runs every default scanner, which needs each scanner's tool installed" -->
```bash
ash --source-dir . --no-fail-on-findings
```

To try it without every scanner's tool, run detect-secrets alone. Its finding is reported, and the scan exits 0:

<!-- doctest: run expect-exit=0 -->
```bash
ash --source-dir . --scanners detect-secrets --offline --no-progress --no-fail-on-findings
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
