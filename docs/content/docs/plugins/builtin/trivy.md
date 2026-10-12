# Trivy filesystem scanner (`trivy`)

[trivy](https://github.com/aquasecurity/trivy) matches the packages in your dependency manifests and lockfiles against its vulnerability database. ASH runs it as `trivy fs` over each scan target.

## Enabling it

The `trivy` scanner is a builtin scanner, enabled by default: a default scan runs it. `scanners.trivy.enabled: false` in the ASH config turns it off, and `--scanners` and `--exclude-scanners` select it as they select any scanner. If the tool is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate), as for every builtin scanner; `ash dependencies install` and the container image provide it.

trivy is a native binary, so `--python-only` does not run it.

## Installing trivy

- Container image: included. The image installs the pinned release (currently v0.75.0).
- Local mode: `ash dependencies install` downloads the pinned release asset from GitHub and checks it against the SHA256 recorded in `automated_security_helper/utils/tool_downloads.py` before installing it. trivy publishes no Windows arm64 asset, so there it has to be installed another way.
- Nix mode: the flake supplies nixpkgs' `trivy`, and the nix shell keeps its vulnerability database in `TRIVY_CACHE_DIR` (default `~/.cache/ash/trivy`), updating it on every entry; trivy returns at once when the database is current. Nix mode scans offline, so when the shell had no network and nothing is cached, trivy is reported `MISSING` with the reason; see [Offline and air-gapped use](#offline-and-air-gapped-use).
- A `trivy` already on `PATH` is used as is. ASH is tested against the pinned version.

## What it scans by default, and why

trivy has four scanners. This scanner runs one of them unless you, as the operator, ask for more:

| trivy scanner | By default | Why |
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
      # Any of vuln, secret, misconfig, license. At least one. Honored only from
      # the operator (--config-overrides or a config file outside every git
      # checkout and the scanned directory); set by a config inside one, it is
      # ignored with a warning.
      scanners: ["vuln"]
      # Report only vulnerabilities with a fixed version. Off: an unfixed
      # vulnerability is still a vulnerability. ASH logs a warning when it is on.
      ignore_unfixed: false
      # Look for licenses in source headers too. Only used with `license`.
      license_full: false
      disable_telemetry: true
      # A trivy.yaml (from the operator), a .trivyignore and a trivy-secret.yaml,
      # each outside the scanned tree. Unset, the ones in the scanned repository
      # are NOT read; see below.
      config_file: null
      ignore_file: null
      secret_config_file: null
      # false follows ASH (--offline / ASH_OFFLINE); true forces trivy offline.
      offline: false
      # Gates the verdict, as for every scanner. Findings below it are still
      # reported. ASH does not pass it as trivy --severity.
      severity_threshold: null
      # Seconds before the trivy process is killed; also passed as trivy --timeout.
      # null leaves both unbounded: ASH passes trivy --timeout=2562047h (about 292
      # years), since it reads 0s as a deadline already passed. Its default is 5m.
      scan_timeout: 1800
```

## trivy configuration in the scanned repository

trivy reads `trivy.yaml`, `.trivyignore` and, for the `secret` scanner, `trivy-secret.yaml` from its working directory, which is the repository being scanned. Any of them can remove findings without the report saying so: a `severity: [CRITICAL]` or `scan.skip-files` entry in `trivy.yaml` removes every lower-rated or skipped finding, an `ignore-policy` it names (a Rego file) drops whatever the policy matches, each `.trivyignore` line removes an advisory, and `trivy-secret.yaml` can disable secret rules. A `trivy.yaml` can also point trivy at a directory of WASM modules (`module.dir`) and enable them, which runs them during the scan, and turn on a VEX repository download or client/server mode, which reach the network. So the builtin scanner passes `trivy --config`, `trivy --ignorefile` and `trivy --secret-config` pointing at files that set nothing (the empty config ASH ships, and an empty ignore file and secret config ASH writes outside the scanned tree), and a repository's own files are not read. trivy reads no other file from a default location: `trivy --ignore-policy` has no default.

To use your own:

- `config_file`: set it as the operator, through `--config-overrides` or an ASH config file outside every git checkout and the scanned directory (one that is not [repository-written](../../configuration-guide.md#settings-a-repositorys-config-cannot-choose)), for a file outside the scanned tree. Set by an ASH config inside a git checkout or the scanned directory, or naming a file inside the tree, it is ignored with a warning, and an MCP client cannot set it at all: `/scanners/trivy/**` is denied to every client, as for each scanner that can send data off the host. So is a path inside the tree that leads out of it through a symbolic link there: the link chose the file, not the operator. A relative path is taken from the directory of the ASH config file that sets it, or from the working directory for `--config-overrides`, not from the source directory (see [Relative paths in the operator's settings](../../configuration-guide.md#relative-paths-in-the-operators-settings)). Unset or ignored, trivy gets `TRIVY_CONFIG` from the environment, for a file outside the scanned tree, and otherwise ASH's empty config.
- `ignore_file` and `secret_config_file`: under the same rule as `config_file`, a relative path included. Otherwise `TRIVY_IGNOREFILE` and `TRIVY_SECRET_CONFIG` from the environment, for a file outside the scanned tree; a relative path in either is taken from the working directory ASH runs in. A file inside the tree is ignored with a warning, and trivy gets ASH's empty one, which ASH writes outside the scanned tree and removes when the scan ends. trivy-repo takes all three the same way.

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
ash scan --config-overrides 'scanners.trivy.options.ignore_file=/etc/ash/trivyignore'
```

A configured file that does not exist fails the scan rather than running without it.

ASH always passes `trivy --exit-code=0`, which outranks `TRIVY_EXIT_CODE` and an `exit-code` set in your `config_file`. trivy then exits nonzero only when it fails, and its report is read whatever it found. trivy-repo gets the same flag.

To accept a finding, prefer an ASH suppression, which is recorded in the reports and counted. The community `trivy-repo` plugin passes its own config file, modules directory, ignore file and secret config the same way; see its `config_file`, `module_dir`, `ignore_file` and `secret_config_file` options.

## Severity

Each finding is reported at trivy's own severity for it (CRITICAL, HIGH, MEDIUM, LOW), not at a band of its CVSS score, so a finding trivy rates HIGH is reported HIGH whatever its score. A finding trivy rates UNKNOWN falls back to ASH's usual SARIF mapping: the rule's CVSS score (`security-severity`), then the SARIF level.

`severity_threshold` works as for every other scanner: ASH applies it after the scan, to that severity, so a finding below it is still reported and does not fail the scan. ASH does not pass it as `trivy --severity`, which would drop those findings before ASH saw them.

The severity is read per finding, from the `Severity:` line trivy writes in each result's message, not from the result's SARIF rule. trivy writes one rule per advisory, and one advisory can be rated differently for two packages in the same scan (Debian, for example, rates some binutils advisories CRITICAL for `binutils` and LOW for `gdb`); the rule carries only one of those ratings.

## Suppressions

ASH suppressions apply as for any scanner:

- `rule_id` is the advisory id (`CVE-2021-23337`, `GHSA-...`), or the check id (`DS-0002`) for misconfiguration findings.
- `path` and `line_start`/`line_end` match the manifest and the line trivy reports for the package.
- `package_name`, `package_version` and `package_path` match one package copy. For npm lockfiles, a result covering two installed copies of the same version is split into one result per copy, so a suppression can cover one copy and not the other.

Symbol-scoped suppressions (function or class) do not apply: a dependency finding points at a manifest entry, not at code.

## Vulnerability database and staleness

The database is declared as `trivy-db` in `automated_security_helper/utils/content_databases.py`, with a 24h bound measured from its `UpdatedAt`, which is trivy's own rule for its published database. After the scan, ASH reads `UpdatedAt` from `trivy version --format json` and fails the scan when the database is older than that (`content_db_staleness: warn` or `--allow-stale-content-db` turns the failure into a warning carried in every report). This is the same check grype's database gets. In an image built with `OFFLINE=YES` the stale database warns instead of failing; see [Offline and air-gapped use](#offline-and-air-gapped-use).

- Online, ASH updates the database once per scan before trivy and trivy-repo run (`trivy image --download-db-only`, outside the scanner sandbox and under a lock in trivy's cache, so the two never write it at the same time), and fails the scan if it cannot download one. The update runs from a directory outside the scanned tree with an explicit `trivy --config`: your config file when the scan uses one (`config_file`, or `TRIVY_CONFIG`), so a database mirror it names applies, and otherwise the empty one ASH ships. Both scanners then run with `trivy --skip-db-update --skip-java-db-update`, `trivy --skip-check-update` when `misconfig` is on, and `trivy --cache-dir` naming the cache the update wrote, so the scan only reads the cache. `fs` and `repository` scans never read the Java database.
- If you turn trivy's own update off, with `TRIVY_SKIP_DB_UPDATE=true` or `db.skip-update: true` in your config file, ASH does not run its update either: trivy refuses to download a database under that setting, and you set it to keep trivy off the database registry, for example in CI that restores a cached database. ASH logs a warning naming the setting, and trivy and trivy-repo read the database already in the cache. The post-scan check still holds it to the 24h bound, so a cache you do not keep current fails the scan (or warns, under `content_db_staleness: warn`).
- Offline, ASH passes `trivy --skip-db-update --skip-java-db-update --skip-check-update`, so trivy uses whatever database is in its cache (named with `trivy --cache-dir`, as below), and the post-scan check holds it to the bound.
- Online or offline, trivy scans never contact package registries: ASH passes `trivy --offline-scan` on every scan, and the database refresh is the separate step above. trivy then resolves Maven dependencies from the `pom.xml` files in the scanned tree and the local Maven repository (`~/.m2/repository`), not from the repositories a `pom.xml` declares or Maven Central. trivy does not check for new versions or announcements either: online every scan gets `trivy --skip-version-check`, and offline `TRIVY_SKIP_VERSION_CHECK=true` in trivy's environment turns the same check off (see [What offline mode turns off](../../advanced-usage.md#what-offline-mode-turns-off)), since a trivy too old to know the flag refuses the command over it and ignores the variable. trivy-repo gets the same.
- Where the database is kept: where trivy itself keeps it on the host. That is `TRIVY_CACHE_DIR` when it is set, else `$XDG_CACHE_HOME/trivy` on Linux when that is set, else `~/.cache/trivy` (`~/Library/Caches/trivy` on macOS, `%LocalAppData%\trivy` on Windows). ASH names that directory to the update, to every scan (`trivy --cache-dir`), online and offline, and to the post-scan check, so all three read one database, sandboxed or not: the sandbox does not pass `XDG_CACHE_HOME`, and trivy left to its own default there would read another cache. A `cache.dir` in a trivy.yaml does not move it; set `TRIVY_CACHE_DIR` instead.

The database is only read by the `vuln` scanner; with `vuln` off nothing is measured.

## Offline and air-gapped use

trivy needs a database in its cache to scan offline. With none, ASH reports trivy `MISSING` with the reason and the scan exits 1; trivy is not run. To provide one, on a machine with network access:

<!-- doctest: illustrative reason="needs trivy and the network" -->
```bash
TRIVY_CACHE_DIR=/path/to/cache trivy image --download-db-only
```

and point the offline scan at the same `TRIVY_CACHE_DIR`.

With `misconfig` added to `scanners`, trivy's Terraform checks do not run offline: trivy downloads the source of every `module` block a `.tf` file names (from the Terraform registry, with the host's `git`, or over HTTPS) whatever offline flags it is given. ASH passes `trivy --misconfig-scanners` with the installed trivy's own default list minus `terraform`, read from `trivy fs --help`, and logs a warning; when that list cannot be read, `misconfig` is left out of the offline scan. checkov still checks Terraform. trivy-repo does the same. In nix mode, export `TRIVY_CACHE_DIR` before running `ash scan --mode nix`; the variable is passed through to the scan. The container image built with `--offline` ships a trivy database (in `/deps/.trivy`, its `TRIVY_CACHE_DIR`), downloaded at build time; the build fails if that download fails or leaves the cache empty. Once that database is older than the 24h bound, scans in that image still pass: the image holds `trivy-db` to `warn` rather than `fail`, so every report records the stale database and its age. Its findings still lack advisories published since the build, so refresh it anyway: rebuild the image, or mount a fresher cache as `TRIVY_CACHE_DIR`. To make the stale database fail the scan instead, set `content_db_staleness_offline_image_default: false` (see [Stale content databases](../../../how-to/set-the-gate.md#content-databases)). This default follows `ASH_OFFLINE_AT_BUILD_TIME=YES`, which the offline image sets; without it, a stale database in a `TRIVY_CACHE_DIR` you provide is held to `content_db_staleness`.

## Running it alongside the trivy-repo community plugin

The community `trivy-repo` plugin (enabled through `ash_plugin_modules`) keeps its name and its defaults (all four trivy scanners, unfixed vulnerabilities dropped, `license_full: true`), and has a `module_dir` option `trivy` does not. It names its own config file and modules directory, so a `trivy.yaml` in the scanned repository is not loaded, and settings that file made no longer apply. The two share their implementation (the database update, the cache and the treatment of trivy's input files) but are separate scanners. trivy-repo keeps its own scan path: it gets no `trivy --timeout` (trivy's 5-minute default applies), no `trivy --skip-dirs` for ASH's output directory, no offline check for a missing database, and its findings are rated by ASH's usual SARIF mapping rather than at trivy's own severity (see [Severity](#severity)), so one finding can carry different ASH severities in the two scanners.

`trivy` is on by default, so listing the Trivy plugin for `trivy-repo` runs trivy twice, and each finding is reported once per scanner, under that scanner's name. Both read the same database, which is measured once for each: a stale database is reported, and fails the scan, under each scanner's name. The rule ids are the same, so one suppression by `rule_id` and `path` covers both. To avoid the duplicate, keep one: set `scanners.trivy.enabled: false`, or stop listing the plugin.
