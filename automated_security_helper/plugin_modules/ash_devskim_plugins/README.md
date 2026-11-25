# ASH DevSkim Plugin

[DevSkim](https://github.com/microsoft/DevSkim) is Microsoft's MIT-licensed security linter. Its built-in rules flag insecure API use and risky patterns across many languages. ASH runs `devskim analyze` over the scan target and reads the SARIF it writes.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_devskim_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_devskim_plugins
```

With the module listed, `devskim` runs by default. `scanners.devskim.enabled: false` turns it off again. There is no license or service gate: DevSkim is MIT-licensed and runs locally.

## Installing the tool

DevSkim is a .NET tool, so a .NET SDK is a prerequisite that ASH does not install. With `dotnet` on `PATH`:

<!-- doctest: illustrative reason="downloads and installs the scanner's tool" -->
```bash
ash dependencies install --config-overrides "ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_devskim_plugins]" --tool devskim
```

This runs `dotnet tool install Microsoft.CST.DevSkim.CLI --version 1.0.103 --tool-path <ASH bin directory>`. Without `dotnet` the scanner is reported as having no install path, and a `devskim` already on `PATH` is used.

## Configuration

```yaml
scanners:
  devskim:
    enabled: true
    options:
      # Seconds for the whole DevSkim scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

DevSkim's own inline `DevSkim: ignore` comments are switched off (`--disable-supression`), so the scanned tree cannot hide findings; use ASH suppressions.

## Severity

| DevSkim | ASH | SARIF level |
|---|---|---|
| Critical | CRITICAL | error |
| Important | HIGH | error |
| Moderate | MEDIUM | warning |
| BestPractice | LOW | note |
| ManualReview | INFO | none |

## Documentation

Flags, severity, suppressions and offline use: [the DevSkim plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/community/devskim-plugin/).
