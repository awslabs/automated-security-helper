# Psalm (community plugin)

[Psalm](https://psalm.dev) is a static analyzer for PHP. ASH runs `psalm --taint-analysis` over the scan target and reports the tainted data flows it finds: user input that reaches a SQL query, an HTML response, a shell command or another sink without being sanitized. Each finding carries Psalm's CWE tag and its trace from source to sink. ASH pins the 6.x line (6.20.13).

## Enabling it

Psalm is a community plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_psalm_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_psalm_plugins
```

With the module listed, `psalm` runs by default, like every other scanner. `scanners.psalm.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners psalm` without the module listed is refused, with a message naming the module to add.

There is no license gate and no account: Psalm is MIT licensed and runs on your machine. Unlike `snyk-code`, which needs an opt-in because it sends code to a service, nothing here leaves the host, so there is no opt-in option.

If Psalm or PHP is not installed the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate). If the target holds no PHP file the scanner is `SKIPPED`.

## Installing Psalm

Psalm is a PHP program. It needs PHP 8.2 or newer on `PATH`; ASH does not install PHP.

- **Container mode:** the ASH image installs the pinned Psalm release and a PHP runtime.
- **Local mode:** `ash dependencies install --tool psalm`, with the module listed in `ash_plugin_modules` (or added with `--config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_psalm_plugins"]'`), downloads the pinned `psalm.phar` from the Psalm release page, verifies its SHA256 digest and installs it as `psalm`. Linux and macOS on x86_64 and arm64 are supported. Windows is not: the phar is started through its `#!/usr/bin/env php` line.
- **Nix mode:** the flake does not supply Psalm. Install it with `ash dependencies install`, or have it on `PATH`.
- Any `psalm` already on `PATH` is also used.

## What is scanned

Psalm analyzes the PHP files (`.php`, `.phtml`, `.inc`) under the scan target. ASH generates the Psalm config: the target is the project directory, `vendor/` and ASH's own output directory are not analyzed, taint analysis is on, and the cache is off. The config is written outside the scanned tree and passed with `--config`, with `--root` pointing at the same empty directory.

A `psalm.xml`, a `vendor/autoload.php` or a Psalm plugin in the scanned repository is therefore not read or run. To tune findings, use ASH suppressions.

## Configuration

```yaml
scanners:
  psalm:
    enabled: true
    options:
      # Also report Psalm's non-security (type) issues. Off: only taint findings.
      include_type_issues: false
      # Seconds for the whole Psalm run (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

`include_type_issues` only adds results, so a repository may set it.

## Severity

Psalm's SARIF has two levels, `error` and `note`, and tags each rule `security` (issue types starting `Tainted`) or `maintainability`. ASH maps them so the SARIF level and ASH's severity agree:

| Result | ASH severity | SARIF level |
|---|---|---|
| taint, `error` | HIGH | `error` |
| taint, `note` | LOW | `note` |
| type issue, `error` (`include_type_issues`) | MEDIUM | `warning` |
| type issue, `note` (`include_type_issues`) | INFO | `none` |

A taint finding is HIGH, not CRITICAL: Psalm reports a possible flow from a source to a sink, not a confirmed exploit. A result with no level, or a level Psalm does not write, is rated as an `error` of its kind, the more severe choice.

## Exit status

Psalm exits 0 when it finds nothing, 2 when it finds issues, and 1 when it could not run. ASH accepts 0 and 2. Any other exit code fails the scan even when a report was written.

## Suppressions

[ASH suppressions](../../../concepts/suppressions.md) by rule, path and line work as for any scanner:

```yaml
global_settings:
  suppressions:
    - rule_id: "201"
      path: "src/legacy/export.php"
      line_start: 12
      line_end: 12
      reason: "The value is checked by the caller."
```

The rule id is the numeric shortcode Psalm writes in `ruleId`; the rule's name (for example `TaintedSql`) is in the report. Package-scoped and symbol-scoped suppressions do not apply.

## Offline and air-gapped use

Psalm makes no network call while it analyzes, so it runs offline once installed. Installing the pinned phar needs access to the release page, or a mirror with the same digest.

## License

Psalm is MIT licensed. See [third-party licenses](../../../how-to/run-in-a-container.md#third-party-licenses).
