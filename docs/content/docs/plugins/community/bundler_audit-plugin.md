# bundler-audit (community plugin)

[bundler-audit](https://github.com/rubysec/bundler-audit) finds gems with known vulnerabilities in a Ruby project. ASH runs `bundler-audit check` over the `Gemfile.lock` at the root of the scan target, which matches every locked gem version against the [ruby-advisory-db](https://github.com/rubysec/ruby-advisory-db) advisories, and also reports a gem source fetched over `git://` or `http://`. ASH installs bundler-audit 0.9.3.

## Enabling it

bundler-audit is a community plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_bundler_audit_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_bundler_audit_plugins
```

With the module listed, `bundler_audit` runs by default, like every other scanner. `scanners.bundler_audit.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners bundler_audit` without the module listed is refused, with a message naming the module to add. If the tool is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate).

There is no gate beyond listing the module: bundler-audit needs no account, token or license acceptance.

## Installing bundler-audit

bundler-audit is a Ruby gem. Ruby and RubyGems must already be installed: ASH does not install them, and on a machine without `gem` the scanner declares no install command and is reported as having no install path.

- **Container mode:** the ASH image does not include bundler-audit or Ruby. Build an image that does, or install it at run time.
- **Local mode:** `ash dependencies install --tool bundler_audit`, with the module listed in `ash_plugin_modules` (or added with `--config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_bundler_audit_plugins"]'`), runs `gem install bundler-audit -v 0.9.3 --user-install` and places the executable in ASH's bin directory.
- **Nix mode:** the flake does not supply bundler-audit. Install it with `ash dependencies install`, or have it on `PATH`.
- Any `bundler-audit` already on `PATH` is also used.

## What is scanned

bundler-audit reads one file: `Gemfile.lock` at the root of the scan target. A target without it is skipped (the row reads SKIPPED, not PASSED). A lockfile in a subdirectory is not found, and a `Gemfile.lock` that is a symbolic link is not read. To audit a nested project, scan that directory as the target.

Findings are reported on the line of the lockfile that names the gem (`    rack (2.0.1)`), or the `remote:` line of an insecure source, and carry the package name and version so [package-scoped suppressions](../../../concepts/suppressions.md) can match.

ASH runs `bundler-audit check --format=json`, writes the report to a file and converts it to SARIF. bundler-audit exits 1 both when it finds vulnerabilities and when it fails (a failed download, a missing lockfile), so ASH decides by the report: a run that exits 1 and wrote no report, or whose report lists nothing, fails the scan.

## Configuration

```yaml
scanners:
  bundler_audit:
    enabled: true
    options:
      # Pull the advisory database before each check (default true). Turn it off
      # to use the database as it is, for a read-only cache or a database prepared
      # before the scan. A missing database is downloaded either way.
      update_database: true
      # Seconds for the whole scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override: ALL, LOW, MEDIUM, HIGH,
      # CRITICAL, or null for the global threshold.
      severity_threshold: null
```

A `.bundler-audit.yml` in the scanned repository lists advisories for bundler-audit to ignore, which would drop them before ASH sees them. ASH therefore always passes `--config` with a file of its own that ignores nothing, and never passes `--ignore`. Move such entries to [ASH suppressions](../../../concepts/suppressions.md), which are reported and counted.

## Severity

Each advisory result is rated from the `criticality` bundler-audit derives from the advisory's CVSS score (v4 or v3 first, else v2). `HIGH` and `CRITICAL` share the SARIF level `error`, since SARIF has no level between `error` and `warning`; ASH's severity keeps them apart.

| bundler-audit criticality | ASH severity | SARIF level |
|---|---|---|
| critical (CVSS 9.0 to 10.0) | CRITICAL | error |
| high (7.0 to 8.9) | HIGH | error |
| medium (4.0 to 6.9) | MEDIUM | warning |
| low (0.1 to 3.9) | LOW | note |
| none (0.0) | INFO | none |
| no score | MEDIUM | warning |
| insecure gem source | MEDIUM | warning |

An advisory with no CVSS score is MEDIUM: it is a known vulnerable version, so it should not fall below the default `MEDIUM` threshold, and without a score there is no ground to rate it higher. Newer advisories are often unscored; in the run that measured this plugin, 10 of 56 results were.

## Suppressions

ASH suppressions by rule, path and line work as for any scanner, and package-scoped suppressions apply because each result names its gem:

```yaml
global_settings:
  suppressions:
    - rule_id: CVE-2020-8164
      path: Gemfile.lock
      line_start: 5
      line_end: 5
      reason: the affected code path is not reachable in this application
```

## Offline and air-gapped use

bundler-audit downloads its advisory database from GitHub (a `git clone`, and a `git pull` with `update_database` on). Offline mode therefore skips the scanner: it is reported `MISSING` with the reason, because an empty or old database would report nothing. To scan in an air-gapped environment, prepare `~/.local/share/ruby-advisory-db` before going offline and run bundler-audit on a host that has network access, or accept that the scanner does not run offline.

In the scanner sandbox the scanner is granted a network and the advisory database directory as a cache path. Where the sandbox backend mounts that directory read-only, set `update_database: false` and prepare the database beforehand.

## License

bundler-audit is licensed GPL-3.0-or-later. ASH runs it as a separate process and does not include, modify or redistribute it: it is installed on the user's side with `gem install`, and ASH imports none of its code.
