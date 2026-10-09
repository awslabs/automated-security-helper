# Trivy filesystem scanner (`trivy`)

[trivy](https://github.com/aquasecurity/trivy) matches the packages in your dependency manifests and lockfiles against its vulnerability database. ASH runs it as `trivy fs` over each scan target.

## Enabling it

The `trivy` scanner is a builtin scanner, enabled by default: a default scan runs it. `scanners.trivy.enabled: false` in the ASH config turns it off, and `--scanners` and `--exclude-scanners` select it as they select any scanner. If the tool is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate), as for every builtin scanner; `ash dependencies install` and the container image provide it.

## Installing trivy

- Container image: included. The image installs the pinned release (currently v0.75.0).
- Local mode: `ash dependencies install` downloads the pinned release asset from GitHub and checks it against the SHA256 recorded in `automated_security_helper/utils/tool_downloads.py` before installing it.
- Nix mode: the flake supplies nixpkgs' `trivy`, and the nix shell keeps its vulnerability database in `TRIVY_CACHE_DIR` (default `~/.cache/ash/trivy`), updating it on every entry; trivy returns at once when the database is current. Nix mode scans offline, so when the shell had no network and nothing is cached, trivy is reported `MISSING` with the reason; see [Offline and air-gapped use](#offline-and-air-gapped-use).
- A `trivy` already on `PATH` is used as is. ASH is tested against the pinned version.

## What it scans by default, and why

trivy has four scanners. This scanner runs one of them unless you ask for more:

| trivy scanner | Default | Why |
|---------------|---------|-----|
| `vuln` | on | Known vulnerabilities in dependencies, from trivy's own database. grype answers the same question from a different database; a second database is the reason to enable trivy. ASH does not deduplicate across scanners, so a vulnerability both find is reported by each, trivy usually under the CVE id and grype under the GHSA id, and one suppression by `rule_id` does not cover both. |
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
      # A trivy.yaml, a .trivyignore and a trivy-secret.yaml outside the scanned
      # tree, set by the operator. Unset, the ones in the scanned repository are
      # NOT read; see below.
      config_file: null
      ignore_file: null
      secret_config_file: null
      # false follows ASH (--offline / ASH_OFFLINE); true forces trivy offline.
      offline: false
      # Passed to trivy as --severity (this level and above).
      severity_threshold: null
      # Seconds before the trivy process is killed; also passed as trivy --timeout.
      # null leaves both unbounded (trivy --timeout=0s; trivy's own default is 5m).
      scan_timeout: 1800
```

## trivy configuration in the scanned repository

trivy reads `trivy.yaml`, `.trivyignore` and, for the `secret` scanner, `trivy-secret.yaml` from its working directory, which is the repository being scanned. Any of them can remove findings without the report saying so: a `severity: [CRITICAL]` or `scan.skip-files` entry in `trivy.yaml` removes every lower-rated or skipped finding, an `ignore-policy` it names (a Rego file) drops whatever the policy matches, each `.trivyignore` line removes an advisory, and `trivy-secret.yaml` can disable secret rules. A `trivy.yaml` can also point trivy at a directory of WASM modules (`module.dir`) and enable them, which runs them during the scan. So the builtin scanner passes `--config`, `--ignorefile` and `--secret-config` pointing at files of its own that set nothing, and a repository's own files are not read. trivy reads no other file from a default location: `--ignore-policy` has no default.

To use your own, name them as the operator, through `--config-overrides` or an ASH config file outside the scanned tree, for files outside the scanned tree:

```bash
ash scan --config-overrides 'scanners.trivy.options.ignore_file=/etc/ash/trivyignore'
```

Each of `config_file`, `ignore_file` and `secret_config_file` set by an ASH config inside the scanned tree, or naming a file inside it, is ignored with a warning, and trivy gets ASH's empty one. A configured file that does not exist fails the scan rather than running without it.

To accept a finding, prefer an ASH suppression, which is recorded in the reports and counted. The community `trivy-repo` plugin passes its own config file, modules directory and secret config the same way; see its `config_file`, `module_dir` and `secret_config_file` options.

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

and point the offline scan at the same `TRIVY_CACHE_DIR`. In nix mode, export `TRIVY_CACHE_DIR` before running `ash scan --mode nix`; the variable is passed through to the scan. The container image built with `--offline` does not bake a trivy database in; set `TRIVY_CACHE_DIR` to a mounted cache, or run trivy online.

## Running it alongside the trivy-repo community plugin

The community `trivy-repo` plugin (enabled through `ash_plugin_modules`) keeps its name and its defaults (all four trivy scanners, unfixed vulnerabilities dropped). It names its own config file and modules directory, so a `trivy.yaml` in the scanned repository is not loaded, and settings that file made no longer apply. The two share their implementation but are separate scanners.

`trivy` is on by default, so listing the Trivy plugin for `trivy-repo` runs trivy twice, and each finding is reported once per scanner, under that scanner's name. Both read the same database, which is measured once for each. The rule ids are the same, so one suppression by `rule_id` and `path` covers both. To avoid the duplicate, keep one: set `scanners.trivy.enabled: false`, or stop listing the plugin.
