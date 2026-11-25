# DevSkim (community plugin)

[DevSkim](https://github.com/microsoft/DevSkim) is Microsoft's MIT-licensed security linter for many languages. ASH runs `devskim analyze` over the scan target and reads the SARIF it writes. The plugin pins the `Microsoft.CST.DevSkim.CLI` 1.0.103 release.

## Enabling it

DevSkim is a community plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_devskim_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_devskim_plugins
```

With the module listed, `devskim` runs by default, like every other scanner. `scanners.devskim.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners devskim` without the module listed is refused, with a message naming the module to add. If the tool is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate). There is no license or service gate.

## Installing DevSkim

DevSkim is a .NET tool, so a .NET SDK is a prerequisite ASH does not install.

- **Local mode:** with `dotnet` on `PATH`, `ash dependencies install --tool devskim` (with the module listed in `ash_plugin_modules`, or added with `--config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_devskim_plugins"]'`) runs `dotnet tool install Microsoft.CST.DevSkim.CLI --version 1.0.103 --tool-path <ASH bin directory>`. Without `dotnet`, the scanner is reported as having no install path.
- **Container and Nix modes:** the image and the flake do not supply DevSkim. Put `devskim` on `PATH`.
- Any `devskim` already on `PATH` is also used.

## What is scanned

ASH runs `devskim analyze --source-code=<path> --output-file=<results> --file-format=sarif --disable-supression` from the source directory, with the source target given as `.` so reported paths are source-relative. DevSkim walks the target and picks files by its own language rules; its rules are compiled into the release. ASH's own output directory is inside the source tree by default, so DevSkim reads it, and ASH drops every result under it except for a file the repository committed there.

The plugin does not pass `--options-json`, custom rule files (`-r`), `--rule-ids`, `--ignore-default-rules`, `--crawl-archives` or `-E`, so nothing in the scanned tree changes the rules.

## Configuration

```yaml
scanners:
  devskim:
    enabled: true
    options:
      # Seconds for the whole DevSkim scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override: ALL, LOW, MEDIUM, HIGH,
      # CRITICAL, or null for the global threshold.
      severity_threshold: null
```

The plugin has no DevSkim-specific options.

## Inline suppressions

DevSkim reads `DevSkim: ignore` comments in the scanned files. The tree writes those comments, so honoring them would hide findings before ASH counts them. ASH passes `--disable-supression` (DevSkim's spelling), so every finding reaches ASH. Use ASH suppressions instead.

## Severity

DevSkim's SARIF writer sets each result's level from the rule severity and records the exact severity in the `DevSkimSeverity` property. ASH uses that property:

| DevSkim | ASH | SARIF level |
|---|---|---|
| Critical | CRITICAL | error |
| Important | HIGH | error |
| Moderate | MEDIUM | warning |
| BestPractice | LOW | note |
| ManualReview | INFO | none |

A result without the property is rated from its SARIF level: error is HIGH, warning is MEDIUM, note is LOW, and a missing level or `none` is MEDIUM. The SARIF level and the ASH severity always agree. These are lint findings, so only DevSkim's own Critical is CRITICAL.

## Exit status

A run that finishes exits 0 whether or not it found anything, because ASH does not pass `-E`. Any other exit code fails the scan, even when a report is on disk, as does a timeout, a missing report and a report that is not valid SARIF.

## Suppressions

ASH suppressions by rule, path and line work as for any scanner:

```yaml
global_settings:
  suppressions:
    - rule_id: DS126858
      path: tests/fixtures/example.py
      line_start: 4
      line_end: 4
      reason: a documented example, not production code
```

Package-scoped and symbol-scoped suppressions do not apply: no DevSkim finding names a package or a symbol.

## Offline and air-gapped use

DevSkim's rules are compiled into the release and `analyze` makes no network calls, so it behaves the same offline. Install it before going offline.

## License

DevSkim is MIT-licensed. ASH does not redistribute it: it is installed from NuGet at install time, or comes from your own `PATH`.
