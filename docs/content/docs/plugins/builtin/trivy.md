# Trivy scanner (opt-in)

[trivy](https://github.com/aquasecurity/trivy) matches the packages in your dependency manifests and lockfiles against its vulnerability database. ASH runs it as `trivy fs` over each scan target.

trivy is opt-in. A default `ash scan` does not run it and does not mention it: there is no trivy row in the summary, the reports or the SARIF until you enable it.

## Enabling it

Any one of these turns it on:

```yaml
# .ash/.ash.yaml
scanners:
  trivy:
    enabled: true
```

```bash
# For one run, alongside the default scanners
ash scan --config-overrides 'scanners.trivy.enabled=true'

# For one run, on its own
ash scan --scanners trivy
```

Naming trivy in `--scanners` runs it even when the config says `enabled: false`. `--exclude-scanners trivy` wins over both.

Once enabled it behaves like every other scanner. If the `trivy` binary is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate).

## Installing trivy

- Container image: included. The image installs the pinned release (currently v0.69.3).
- Local mode: `ash dependencies install` downloads the pinned release asset from GitHub and checks it against the SHA256 recorded in `automated_security_helper/utils/tool_downloads.py` before installing it.
- Nix mode: the flake supplies nixpkgs' `trivy`. Nix mode runs offline, so see [Offline and air-gapped use](#offline-and-air-gapped-use).
- A `trivy` already on `PATH` is used as is. ASH is tested against the pinned version.

## What it scans by default, and why

trivy has four scanners. The builtin runs one of them unless you ask for more:

| trivy scanner | Default | Why |
|---------------|---------|-----|
| `vuln` | on | Known vulnerabilities in dependencies, from trivy's own database. grype answers the same question from a different database; a second database is the reason to enable trivy. |
| `secret` | off | detect-secrets runs by default. Both would report the same credential under different rule ids, and a suppression for one does not cover the other. |
| `misconfig` | off | checkov, cfn-nag and cdk-nag cover IaC by default. |
| `license` | off | License findings are a compliance question and depend on a license policy ASH does not hold. |

```yaml
scanners:
  trivy:
    enabled: true
    options:
      # Any of vuln, secret, misconfig, license. At least one.
      scanners: ["vuln"]
      # Report only vulnerabilities with a fixed version. Off: an unfixed
      # vulnerability is still a vulnerability. ASH logs a warning when it is on.
      ignore_unfixed: false
      # Look for licenses in source headers too. Only used with `license`.
      license_full: false
      disable_telemetry: true
      # A trivy.yaml, a .trivyignore and a trivy-secret.yaml, relative to the
      # source directory. Unset, the ones in the scanned repository are NOT read;
      # see below.
      config_file: null
      ignore_file: null
      secret_config_file: null
      # Defaults to ASH's offline mode (ASH_OFFLINE / --offline).
      offline: false
      # Passed to trivy as --severity (this level and above).
      severity_threshold: null
      # Seconds before the trivy process is killed; also passed as trivy --timeout.
      # null leaves both unbounded (trivy --timeout=0s; trivy's own default is 5m).
      scan_timeout: 1800
```

## trivy configuration in the scanned repository

trivy reads `trivy.yaml`, `.trivyignore` and, for the `secret` scanner, `trivy-secret.yaml` from its working directory, which is the repository being scanned. Any of them can remove findings without the report saying so: a `severity: [CRITICAL]` or `scan.skip-files` entry in `trivy.yaml` removes every lower-rated or skipped finding, each `.trivyignore` line removes an advisory, and `trivy-secret.yaml` can disable secret rules. So the builtin scanner passes `--config`, `--ignorefile` and `--secret-config` pointing at files of its own that set nothing, and a repository's own files are not read. To use them, name them:

```yaml
scanners:
  trivy:
    options:
      config_file: trivy.yaml
      ignore_file: .trivyignore
      secret_config_file: trivy-secret.yaml
```

A relative path is anchored on the source directory. A configured file that does not exist fails the scan rather than running without it.

To accept a finding, prefer an ASH suppression, which is recorded in the reports. The community `trivy-repo` plugin still reads the repository's files, as it always has.

## Severity

Each finding is reported at trivy's own severity for it (CRITICAL, HIGH, MEDIUM, LOW). That is the severity trivy's `--severity` filter uses, which is how `severity_threshold` reaches trivy, so a finding cannot pass the filter as HIGH and be reported as MEDIUM. A finding trivy rates UNKNOWN falls back to ASH's usual SARIF mapping: the rule's CVSS score (`security-severity`), then the SARIF level.

## Suppressions

ASH suppressions apply as for any scanner:

- `rule_id` is the advisory id (`CVE-2021-23337`, `GHSA-...`), or the check id (`DS-0002`) for misconfiguration findings.
- `path` and `line_start`/`line_end` match the manifest and the line trivy reports for the package.
- `package_name`, `package_version` and `package_path` match one package copy. For npm lockfiles, a result covering two installed copies of the same version is split into one result per copy, so a suppression can cover one copy and not the other.

Symbol-scoped suppressions (function or class) do not apply: a dependency finding points at a manifest entry, not at code.

## Vulnerability database and staleness

The database is declared as `trivy-db` in `automated_security_helper/utils/content_databases.py`, with a 24h bound measured from its `UpdatedAt`, which is trivy's own rule for its published database. After the scan, ASH reads `UpdatedAt` from `trivy version --format json` and fails the scan when the database is older than that (`content_db_staleness: warn` or `--allow-stale-content-db` turns the failure into a warning carried in every report). This is the same check grype's database gets.

- Online, trivy refreshes a database past its `NextUpdate` itself before scanning, and fails if it cannot download one.
- Offline, ASH passes `--skip-db-update --skip-java-db-update --offline-scan --skip-check-update`, so trivy uses whatever database is in its cache, and the post-scan check holds it to the bound.

The database is only read by the `vuln` scanner; with `vuln` off nothing is measured.

## Offline and air-gapped use

trivy needs a database in its cache to scan offline. With none, ASH reports trivy `MISSING` with the reason and the scan exits 1; trivy is not run. To provide one, on a machine with network access:

```bash
TRIVY_CACHE_DIR=/path/to/cache trivy image --download-db-only
```

and point the offline scan at the same `TRIVY_CACHE_DIR`. The container image built with `--offline` does not bake a trivy database in; set `TRIVY_CACHE_DIR` to a mounted cache, or run trivy online.

## Running it alongside the trivy-repo community plugin

The community `trivy-repo` plugin (enabled through `ash_plugin_modules`) is unchanged: same name, same defaults (all four trivy scanners, unfixed vulnerabilities dropped), same findings and outputs. The two share their implementation but are separate scanners.

If both are enabled, trivy runs twice and each finding is reported once per scanner, under that scanner's name. Both read the same database, which is measured once for each. The rule ids are the same, so one suppression by `rule_id` and `path` covers both. To avoid the duplicate, enable one of them.
