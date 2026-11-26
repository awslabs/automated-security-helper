# DevSkim Plugin

Runs [DevSkim](https://github.com/microsoft/DevSkim) (MIT), Microsoft's security linter, over the scan target. Its rules are compiled into the release and flag insecure API use and risky patterns across many languages: weak hash algorithms, banned C functions, `eval`, plain-HTTP URLs, suspicious comments and more. ASH runs `devskim analyze` and reads the SARIF it writes.

## Enabling

The scanner is on once its module is listed:

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_devskim_plugins
```

With the module listed, `devskim` runs by default. `scanners.devskim.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. If the tool or a .NET runtime is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate).

## Installing DevSkim

DevSkim is a .NET program. A .NET runtime, version 8 or later, with `dotnet` on `PATH`, is a prerequisite that ASH does not install.

ASH pins DevSkim 1.0.103 in the plugin's own install module (`ash_devskim_plugins/devskim_install.py`: the version and the SHA256 of the `Microsoft.CST.DevSkim.CLI` package nuget.org serves for it). Install it with:

<!-- doctest: illustrative reason="downloads a release package" -->
```bash
ash dependencies install --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_devskim_plugins"]' --tool devskim
```

A package that does not hash to its pin is refused. The install unpacks the package's net8.0 build into a `.devskim` directory inside ASH's bin directory and writes a `devskim` launcher beside the other tools, which runs the build with `dotnet --roll-forward Major`, so it runs on .NET 8 and on any later .NET. Linux and macOS (amd64 and arm64) are installed this way. On Windows, install DevSkim yourself (`dotnet tool install Microsoft.CST.DevSkim.CLI --version 1.0.103`) so that `devskim` is on `PATH`. A `devskim` already on `PATH` is used on every platform.

The ASH container image does not carry DevSkim, because the image has no .NET runtime. Install DevSkim and a .NET runtime yourself to use it there.

## What is scanned

ASH runs `devskim analyze --source-code=. --output-file=<results> --file-format=sarif --disable-supression` from the source directory, so reported paths are source-relative. DevSkim walks the target and picks files by its own language rules. Two of its defaults stay in place: files under any `bin` directory (and `.git`) are not analyzed, and a low-confidence rule match is not reported. ASH's own output directory is inside the source tree by default, so DevSkim reads it, and ASH drops every result under it except for a file the repository committed there.

The plugin does not pass `--options-json`, custom rule files (`-r`), `--rule-ids`, `--ignore-rule-ids`, `--ignore-default-rules`, `--crawl-archives` or `-E`, so nothing in the scanned tree changes the rules.

## Configuration

The plugin has no options of its own, only the shared ones (`severity_threshold`, `scan_timeout`, `offline`).

## Inline suppressions

DevSkim reads `DevSkim: ignore DSnnnnnn` comments in the scanned files. The tree writes those comments, so honoring them would hide findings before ASH counts them. ASH passes `--disable-supression` (DevSkim's spelling), so every finding reaches ASH. Use ASH suppressions instead:

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

## Severity

DevSkim's SARIF records each result's severity in the `DevSkimSeverity` property. ASH maps it and sets the SARIF level to agree:

| DevSkim | ASH | SARIF level |
|---|---|---|
| Critical | CRITICAL | error |
| Important | HIGH | error |
| Moderate | MEDIUM | warning |
| BestPractice | LOW | note |
| ManualReview | INFO | none |

A result without the property is rated from its SARIF level: error is HIGH, warning is MEDIUM, note is LOW, and a missing level or `none` is MEDIUM. These are lint findings, so only DevSkim's own Critical is CRITICAL.

## Exit status

A run that finishes exits 0 whether or not it found anything, because ASH does not pass `-E`. Any other exit code fails the scan, even when a report is on disk, as does a timeout, a missing report and a report that is not valid SARIF.

## Offline use

DevSkim's rules are compiled into the release and `analyze` makes no network calls, so a scan behaves the same offline. Install the tool before going offline.

## License

DevSkim is MIT-licensed. ASH does not redistribute it: the install downloads the pinned package from nuget.org, and nothing of DevSkim is shipped in the ASH Python package or the ASH container image.
