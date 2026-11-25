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

BinSkim is distributed as the NuGet package `Microsoft.CodeAnalysis.BinSkim`; the executable (`BinSkim` on Linux and macOS, `BinSkim.exe` on Windows) is taken from the `tools/<rid>` folder for the platform. Locally:

<!-- doctest: illustrative reason="downloads and installs the scanner's tool" -->
```bash
ash dependencies install --config-overrides "ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_binskim_plugins]" --tool binskim
```

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

## Central registration owed

This module is self-contained; three shared-file edits belong to the integration lane and are deliberately not made here:

1. `utils/tool_downloads.py`: a `binskim` entry in `TOOL_VERSIONS` and `_ASSET_TABLES` (the pinned `Microsoft.CodeAnalysis.BinSkim` NuGet package and its digest). Until it lands the scanner constructs with no install commands and reports the tool `MISSING`; when it lands, `pinned_tool_install_commands("binskim")` fills them and the register row's runtime becomes `PINNED_BINARY`.
2. `utils/scanner_names.py`: `"binskim": "sast"` in `SCANNER_TOOL_TYPES`.
3. `tests/unit/walked_package.py`: `"plugin_modules/ash_binskim_plugins"` in `PACKAGE_DIRS` (a whole-tree `pytest --collect-only` errors without it: "not named in PACKAGE_DIRS").
4. The two universe counts (22) in `tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py` and `test_scanner_facets_registry_totality.py`, and the corpus table in `test_scanner_facets_corpus_consistency.py`: a `binskim` entry once a real BinSkim log is committed under `tests/test_data/scanners/binskim/captured/`, at which point the scanner's `rule_id`, `severity`, `file_path` and `message` cells become MAPPED. `tests/test_data/scanners/binskim/reference.sarif` is hand-written, not a capture, and is not a corpus.

## Documentation

Suppressions, offline use and the details: [the BinSkim plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/community/binskim-plugin/).

Sources for the flags used: `AnalyzeOptions.cs` in microsoft/binskim and `AnalyzeOptionsBase.cs` in microsoft/sarif-sdk.
