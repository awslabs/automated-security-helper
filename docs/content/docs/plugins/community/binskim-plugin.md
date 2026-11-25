# BinSkim (community plugin)

[BinSkim](https://github.com/microsoft/binskim) is Microsoft's binary analyzer. It checks compiled Windows PE, Linux ELF and macOS Mach-O files for missing hardening such as ASLR, DEP, stack protection, RELRO and control-flow guard. ASH runs `BinSkim analyze` over the scan target and reads the SARIF it writes.

## Enabling it

BinSkim is a community plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_binskim_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_binskim_plugins
```

With the module listed, `binskim` runs by default, like every other scanner. `scanners.binskim.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners binskim` without the module listed is refused, with a message naming the module to add. If the tool is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate).

BinSkim is MIT-licensed and needs no account, token or license acceptance, so listing the module is the only opt-in. (Compare the Snyk scanners, which also need a `SNYK_TOKEN`.)

## Installing BinSkim

- **Local mode:** ASH pins no BinSkim release yet, so `ash dependencies install` installs nothing for it. Download the `Microsoft.CodeAnalysis.BinSkim` NuGet package, extract the `tools/<rid>` folder for your platform (`linux-x64`, `linux-arm64`, `osx-x64`, `win-x64`), mark `BinSkim` executable and put it on `PATH`. The build is self-contained, so no .NET install is needed.
- **Container mode:** the ASH image does not include BinSkim.
- The executable name is case-sensitive on Linux and macOS.

## What is scanned

BinSkim is handed the whole target with `--recurse=true` and picks out the PE, ELF and Mach-O files itself. It also opens archives (ZIP and similar) by default. A tree that holds no such file is reported `SKIPPED`, not `PASSED`: ASH looks for the files' magic numbers before deciding.

ASH passes `--level=Error;Warning;Note` and `--kind=Fail`, so passing and not-applicable results are not written. It passes no `--config`, so a policy file in the scanned tree is not read, and no `--sympath`, so no symbol server is contacted. Debug symbols (PDB files) found beside a binary are still used; a PDB that cannot be loaded does not end the run.

## Configuration

```yaml
scanners:
  binskim:
    enabled: true
    options:
      # Seconds for the whole BinSkim scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override: ALL, LOW, MEDIUM, HIGH,
      # CRITICAL, or null for the global threshold.
      severity_threshold: null
```

The plugin has no options of its own. BinSkim's policy file and symbol path would let the scanned tree or the network change what is reported, so ASH does not expose them.

## Severity

| BinSkim SARIF level | ASH severity |
|---|---|
| `error` | HIGH |
| `warning` | MEDIUM |
| `note` | LOW |
| none | MEDIUM |

A missing mitigation is a hardening gap and not a vulnerability by itself, so no result is CRITICAL. The SARIF level and ASH's severity agree on every result.

## Suppressions

ASH suppressions by rule, path and line work as for any scanner. BinSkim rule ids look like `BA2001`:

```yaml
global_settings:
  suppressions:
    - rule_id: BA2021
      path: vendor/prebuilt/tool.exe
      reason: a vendor binary we do not build
```

Package-scoped and symbol-scoped suppressions do not apply.

## Offline and air-gapped use

BinSkim's rules are compiled into the tool and ASH configures no symbol server, so it behaves the same offline. Install it before going offline.

## License

BinSkim is MIT-licensed. See [Third-party license files](../../../how-to/run-in-a-container.md#third-party-licenses) for how bundled tools' licenses ship.
