# OSV-Scanner Plugin

[OSV-Scanner](https://github.com/google/osv-scanner) (Apache-2.0) finds known-vulnerable dependencies. ASH runs it as `osv-scanner scan source --recursive` over the scan target. It reads the lockfiles and manifests it recognizes (npm, yarn, pnpm, Python lockfiles and `requirements.txt`, Go, Rust, Ruby, PHP, .NET, Java and others) and reports each package that matches an advisory in the [OSV database](https://osv.dev).

## Enabling it

OSV-Scanner is an alpha plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF. There is no license or service gate.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_osv_scanner_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_osv_scanner_plugins
```

With the module listed, `osv-scanner` runs by default, like every other scanner. `scanners.osv-scanner.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners osv-scanner` without the module listed is refused, with a message naming the module to add. If the tool is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate).

OSV-Scanner runs beside the builtin `grype` and `trivy-repo` scanners, not instead of them, so an advisory more than one of them finds is reported by each.

## Installing OSV-Scanner

ASH pins OSV-Scanner v2.7.1 in the plugin's own install module (`ash_osv_scanner_plugins/osv_scanner_install.py`: the version, one release executable per platform and architecture, and the SHA256 of each, taken from the release's `osv-scanner_SHA256SUMS`). Install it with:

<!-- doctest: illustrative reason="downloads a release binary" -->
```bash
ash dependencies install --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_osv_scanner_plugins"]' --tool osv-scanner
```

A download that does not hash to its pin is refused. If `osv-scanner` is already on `PATH`, ASH uses it. The ASH container image installs it the same way.

## What is scanned

OSV-Scanner is handed the whole target and walks it recursively for lockfiles. A finding is one vulnerable package and one advisory, reported at the lockfile that names the package. A tree with no file OSV-Scanner reads makes it exit 128 ("no packages found"); ASH reads that as a scan with nothing to report, not as a failure.

Source scans read lockfiles best. A manifest that is not fully pinned gives best-effort versions, which can differ from what is installed.

## Configuration

```yaml
scanners:
  osv-scanner:
    enabled: true
    options:
      # true skips this scanner even when ASH runs online, as ASH's own
      # --offline mode does (see "Offline use" below).
      offline: false
      # Seconds for the whole OSV-Scanner run (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override: ALL, LOW, MEDIUM, HIGH,
      # CRITICAL, or null for the global threshold.
      severity_threshold: null
```

The plugin has no option that points OSV-Scanner at a config file. OSV-Scanner reads an `osv-scanner.toml` from the directory of each lockfile, and that file can ignore advisories or whole packages. ASH passes `osv-scanner --config` with an empty file kept outside the scanned tree, which the OSV-Scanner documentation says applies to every file parsed and replaces the `osv-scanner.toml` in every directory. The scanned repository therefore cannot hide findings from ASH. Use [ASH suppressions](../../../concepts/suppressions.md) instead: they are reported and counted.

## Severity

OSV-Scanner's SARIF holds one result per vulnerable package and advisory. ASH rates each result and sets the SARIF level to agree with the ASH severity:

| Source | Value | ASH severity | SARIF level |
|---|---|---|---|
| Rule `security-severity` score (CVSS base score) | 9.0 and up | CRITICAL | `error` |
| | 7.0 to 8.9 | HIGH | `error` |
| | 4.0 to 6.9 | MEDIUM | `warning` |
| | above 0 to 3.9 | LOW | `note` |
| | 0 | INFO | `none` |
| Result level, when the rule has no readable score | `error` | HIGH | `error` |
| | `warning` | MEDIUM | `warning` |
| | `note` | LOW | `note` |
| | `none` | INFO | `none` |
| No score and no level | | MEDIUM | `warning` |

The OSV-Scanner documentation shows `warning` on its sample result and does not say how it rates other advisories, so a result with no usable score is rated in the middle, not the quietest. With ASH's default `severity_threshold` of `MEDIUM`, a MEDIUM finding fails the scan. Every result is `kind: fail` and tagged `sca` and `security`.

## Exit codes

| Exit code | Meaning | ASH |
|---|---|---|
| 0 | packages found, no vulnerabilities | scan succeeds |
| 1 | packages found, with vulnerabilities | scan succeeds, findings reported |
| 128 | no packages found | scan succeeds with no findings |
| anything else | error (127 is a general error) | the scan fails, even if a report was written |

OSV-Scanner's stderr is not copied into the scan's errors, because it can quote paths from the scanned tree. The failure message names its log file instead.

## Suppressions

ASH suppressions by rule and path work as for any scanner. The rule is the advisory id OSV-Scanner reports, and the path is the lockfile:

```yaml
global_settings:
  suppressions:
    - rule_id: CVE-2022-24713
      path: Cargo.lock
      reason: the affected function is not reachable in this service
```

Leave out `line_start` and `line_end`. An OSV-Scanner finding has a file and no line, and a suppression with a line range never matches a finding that has no line, so such an entry suppresses nothing.

Package-scoped and symbol-scoped suppressions do not apply: the result location is the lockfile, not a package.

## Offline use

Online, OSV-Scanner sends the names and versions of the packages it found to the OSV API, and the transitive resolution of Maven and Python requirements manifests calls deps.dev. Under `ash scan --offline`, or `scanners.osv-scanner.options.offline: true` for this scanner alone, the scanner does not run: it is reported `MISSING`, with the reason that it needs the OSV API. OSV-Scanner's own offline mode reads a local database (`<dir>/osv-scalibr/<ecosystem>/all.zip`) that it holds to no age, and ASH provisions no such database, so ASH does not use it.

## License

OSV-Scanner is Apache-2.0 licensed. The ASH container image redistributes the pinned release binary, so it carries the repository `LICENSE` at the pinned commit beside it (the `osv-scanner` entry in `THIRD_PARTY_LICENSES`). Nothing of OSV-Scanner is shipped in the ASH Python package itself.
