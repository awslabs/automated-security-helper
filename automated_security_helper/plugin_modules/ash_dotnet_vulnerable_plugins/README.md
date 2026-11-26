# dotnet-vulnerable alpha scanner plugin

`dotnet-vulnerable` reports NuGet packages with known vulnerabilities. ASH runs `dotnet list <project> package --vulnerable --include-transitive` once for each `.csproj`, `.fsproj` and `.vbproj` file in the scan set and turns the JSON report into findings. The `dotnet` command is the one the .NET SDK ships (SDK 7.0.200 or later): `dotnet list package` is built into the SDK, so ASH downloads nothing for this scanner.

## Enabling

This alpha plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_dotnet_vulnerable_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_dotnet_vulnerable_plugins
```

With the module listed, `dotnet-vulnerable` runs by default. `scanners.dotnet-vulnerable.enabled: false` turns it off again.

## Requirements

- The .NET SDK on `PATH`. ASH has nothing to install for this scanner; if `dotnet` is missing the scanner is reported `MISSING`.
- Each project restored (`dotnet restore`) before the scan. The command reads `obj/project.assets.json`. ASH does not pass `--no-restore` (it exists only from SDK 10; SDK 7 to 9 reject it). On SDK 7 to 9 a project that was never restored is reported as an unevaluated project that fails the scan, not as a clean one. From SDK 10 the command restores the project itself, which writes `obj/` into the scanned tree and fetches packages.
- A network. The advisory data comes from the NuGet sources the project's configuration names. The scanner is skipped under `--offline`.
- A tree you would build: `dotnet` evaluates the project file with MSBuild to read its package references.

A tree with no .NET project file is skipped (nothing was scanned), not reported as passing.

## Configuration

```yaml
scanners:
  dotnet-vulnerable:
    enabled: true
    options:
      # Seconds for the whole scan, every project together (default 1800;
      # null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

## Severity

NuGet's severity names map to ASH severities and SARIF levels as follows: Critical is CRITICAL and `error`, High is HIGH and `error`, Moderate is MEDIUM and `warning`, Low is LOW and `note`. An advisory with no stated severity is MEDIUM, and a name ASH does not know is HIGH.

## Documentation

Findings, restore, the network, the sandbox and suppressions: [the dotnet-vulnerable plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/alpha/dotnet_vulnerable-plugin/).
