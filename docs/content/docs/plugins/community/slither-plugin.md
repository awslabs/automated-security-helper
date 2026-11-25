# Slither (community plugin)

[Slither](https://github.com/crytic/slither) is a static analyzer for Solidity smart contracts, written by Trail of Bits. ASH runs it as `slither` over the scan target and reports its detector findings, with the severity ASH assigns from each detector's impact.

## Enabling it

Slither is a community plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_slither_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_slither_plugins
```

With the module listed, `slither` runs by default, like every other scanner. `scanners.slither.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners slither` without the module listed is refused, with a message naming the module to add. If the tool is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate).

## Installing Slither

Slither is licensed under the AGPL-3.0. ASH does not install it, bundle it or download it: the plugin declares no install command, `ash dependencies install` does nothing for it, and the container image does not include it. You install it, and accept its license, yourself:

<!-- doctest: illustrative reason="installs a third-party tool" -->
```bash
uv tool install slither-analyzer
```

`pip install slither-analyzer` and `brew install slither-analyzer` also work. Slither needs Python 3.10 or later and either a Solidity compiler (`solc`, for example managed with `solc-select`) or the project's own build tool. Any `slither` on `PATH` is used. In container mode, build an image that adds it. Nix mode: the flake does not supply Slither.

## What is scanned

ASH hands Slither the whole target: `slither --json=<report> --fail-none --exclude-dependencies -- <target>`, run from the source directory so paths in the report are source-relative. `--fail-none` keeps the finding count out of Slither's exit code, so exit 0 means Slither finished, and any other code fails the scan. `--exclude-dependencies` leaves out findings in dependency code such as `node_modules`.

A tree with no `.sol` file is a no-op: the scanner is reported SKIPPED with the reason "no Solidity (.sol) file in the scan target" and Slither is not started. A `.sol` file that exists only under `node_modules` or `.git`, or only as a link, does not count.

Given a directory, Slither builds the project with its framework (Hardhat, Foundry and similar), and that runs the repository's own build configuration. List this module only for trees you are willing to build. The scanner uses the strict sandbox default, which has no network, so a build that downloads a compiler or npm packages fails; a failed run is a failed scan, never a clean one.

Slither's own SARIF writer (`--sarif`) marks every result `warning`, so ASH does not use it. It reads Slither's JSON (`--json`) and builds the SARIF itself, which lets the SARIF level and ASH's severity agree for every finding.

## Configuration

```yaml
scanners:
  slither:
    enabled: true
    options:
      # Seconds for the whole Slither scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override: ALL, LOW, MEDIUM, HIGH,
      # CRITICAL, or null for the global threshold.
      severity_threshold: null
```

The plugin has no option the scanned repository could use to hide a finding.

## Severity

| Slither impact | ASH severity | SARIF level |
|---|---|---|
| High | HIGH | error |
| Medium | MEDIUM | warning |
| Low | LOW | note |
| Informational | INFO | none |
| Optimization | INFO | none |

High is HIGH and not CRITICAL: Slither's High detectors (reentrancy, unprotected selfdestruct and similar) flag patterns the tool believes are exploitable, not confirmed exploits. A result with no impact is MEDIUM, and an impact ASH does not recognize is HIGH, the more severe reading. Slither's confidence rating (High, Medium, Low) is kept on each result as the `slither_confidence` property and does not change the severity.

A Slither finding whose first element has no source location cannot be placed in a file. ASH counts it and logs a warning, and leaves it out of the report.

## Suppressions

ASH suppressions by rule, path and line work as for any scanner. The rule is the Slither detector name:

```yaml
global_settings:
  suppressions:
    - rule_id: reentrancy-eth
      path: contracts/Vault.sol
      line_start: 10
      line_end: 12
      reason: the call is to a trusted contract, reviewed in the audit
```

Package-scoped and symbol-scoped suppressions do not apply.

## Offline and air-gapped use

Slither's detectors are part of the package, so analysis needs no network once the project compiles. Compiling can need one (a `solc` download, npm packages), and the sandbox grants none: have the compiler and the project's dependencies in place before an air-gapped scan.

## License

Slither is AGPL-3.0 licensed and is not distributed with ASH. The plugin only runs a `slither` you installed, as a separate process.
