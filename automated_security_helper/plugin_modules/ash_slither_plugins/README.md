# ASH Slither Plugin

[Slither](https://github.com/crytic/slither) is a static analyzer for Solidity smart contracts. ASH runs `slither` over the scan target and reports its detector findings as SARIF.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_slither_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_slither_plugins
```

With the module listed, `slither` runs by default. `scanners.slither.enabled: false` turns it off again. A tree with no `.sol` file is a no-op: the scanner is reported SKIPPED and Slither is not started.

## Installing the tool (license gate)

Slither is licensed AGPL-3.0, so ASH never installs it: the plugin declares no install command, `ash dependencies install` does nothing for it, and the container image does not include it. If `slither` is not on `PATH`, the scanner is reported `MISSING` with the install line, and the scan exits 1 (the incomplete-scan gate). Install it yourself, accepting its license, for example:

<!-- doctest: illustrative reason="installs a third-party tool" -->
```bash
uv tool install slither-analyzer
```

Slither needs Python 3.10 or later, and a Solidity compiler (`solc`, for example through `solc-select`) or the project's own build tool.

## What it runs

`slither --json=<report> --config-file=<empty file> --triage-database=<missing file> --fail-none --exclude-dependencies -- <target>`, with the source directory as the working directory. `--fail-none` keeps findings out of the exit code, so exit 0 is a finished run and any other code fails the scan. The JSON is converted to SARIF by the plugin because Slither's own SARIF writer marks every result `warning`. The config and triage database paths keep the scanned tree's `slither.config.json` and `slither.db.json` from hiding findings. A run that analyzes 0 contracts (a directory with no supported project and no `.sol` file at its root) fails the scan, because Slither's JSON reads the same for it as for a clean run.

Given a directory, Slither builds the project with its framework (Hardhat, Foundry and so on), which runs the repository's own build configuration. List this module only for trees you are willing to build. The scanner declares the strict sandbox default (no network), so a build that needs the network fails.

## Severity

| Slither impact | ASH severity | SARIF level |
|---|---|---|
| High | HIGH | error |
| Medium | MEDIUM | warning |
| Low | LOW | note |
| Informational, Optimization | INFO | none |

No impact is MEDIUM; an impact ASH does not know is HIGH. Slither's confidence is kept in the result properties as `slither_confidence`.

## Configuration

```yaml
scanners:
  slither:
    enabled: true
    options:
      # Seconds for the whole Slither scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

## Documentation

Severity, suppressions, offline use and limits: [the Slither plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/community/slither-plugin/).
