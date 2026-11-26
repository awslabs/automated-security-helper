# ASH BinSkim Plugin

[BinSkim](https://github.com/microsoft/binskim) (Microsoft, MIT license) checks compiled Windows PE, Linux ELF and macOS Mach-O binaries for missing hardening such as ASLR, DEP, stack protection and control-flow guard. ASH runs `BinSkim analyze` over the scan target and reads its SARIF output.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_binskim_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_binskim_plugins
```

With the module listed, `binskim` runs by default. `scanners.binskim.enabled: false` turns it off again. A tree with no PE, ELF or Mach-O file is reported `SKIPPED`. BinSkim needs no account, token or license acceptance, so there is no opt-in gate beyond listing the module.

## Installing the tool

<!-- doctest: illustrative reason="downloads a release package" -->
```bash
ash dependencies install --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_binskim_plugins"]' --tool binskim
```

This installs BinSkim 4.4.9.14 from the `Microsoft.CodeAnalysis.BinSkim` NuGet package, pinned in `binskim_install.py` (the package's SHA256 and a digest of every file of each build). The package holds a self-contained build per platform (`linux-x64`, `linux-arm64`, `osx-x64`, `win-x64`), so no .NET install is needed. The host's build goes into `binskim-4.4.9.14-<rid>/` in ASH's bin directory, with a `BinSkim` link beside it on Linux and macOS. BinSkim publishes no build for Apple silicon (`osx-arm64`), so ASH installs nothing there. If `BinSkim` is already on `PATH`, ASH uses it.

## Configuration

```yaml
scanners:
  binskim:
    enabled: true
    options:
      # Seconds for the whole BinSkim scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

## Severity

SARIF `error` is HIGH, `warning` is MEDIUM, `note` is LOW. A result with no level is MEDIUM. Results that are not failures (`pass`, `notApplicable`) are dropped.

## Globalization

Every run sets `DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1`: the .NET runtime inside BinSkim stops at startup on a host with no ICU library otherwise (the ASH container image has none). The findings are the same either way.

## Documentation

Suppressions, offline use and the details: [the BinSkim plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/alpha/binskim-plugin/).

Sources for the flags used: `AnalyzeOptions.cs` in microsoft/binskim and `AnalyzeOptionsBase.cs` in microsoft/sarif-sdk.
