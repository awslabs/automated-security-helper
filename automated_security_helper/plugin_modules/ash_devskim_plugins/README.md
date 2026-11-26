# DevSkim alpha scanner plugin

Runs [DevSkim](https://github.com/microsoft/DevSkim) (MIT), Microsoft's security linter, over the scan target. Its built-in rules flag insecure API use and risky patterns across many languages. ASH runs `devskim analyze` and reads the SARIF it writes.

## Enabling

The scanner is on once its module is listed:

```yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_devskim_plugins
```

A scan that does not list the module is unchanged. There is no license or service gate.

## Installing

DevSkim is a .NET program, so a .NET runtime (8 or later, with `dotnet` on `PATH`) is a prerequisite that ASH does not install. Then:

```bash
ash dependencies install --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_devskim_plugins"]' --tool devskim
```

This downloads the pinned `Microsoft.CST.DevSkim.CLI` 1.0.103 package from nuget.org, refuses it unless it hashes to the SHA256 pinned in `devskim_install.py`, unpacks its net8.0 build into ASH's bin directory and writes a `devskim` launcher there that runs it with `dotnet --roll-forward Major`. Linux and macOS are installed this way. On Windows, install DevSkim yourself (`dotnet tool install Microsoft.CST.DevSkim.CLI --version 1.0.103`) so that `devskim` is on `PATH`. A `devskim` already on `PATH` is used on every platform.

The ASH container image does not carry DevSkim: it has no .NET runtime.

## Configuration

The plugin has no options of its own, only the shared ones (`severity_threshold`, `scan_timeout`, `offline`). DevSkim's inline `DevSkim: ignore` comments are switched off (`--disable-supression`), so the scanned tree cannot hide findings; use ASH suppressions instead.

## Severity

| DevSkim | ASH | SARIF level |
|---|---|---|
| Critical | CRITICAL | error |
| Important | HIGH | error |
| Moderate | MEDIUM | warning |
| BestPractice | LOW | note |
| ManualReview | INFO | none |

## Documentation

See <https://awslabs.github.io/automated-security-helper/docs/plugins/alpha/devskim-plugin/>.
