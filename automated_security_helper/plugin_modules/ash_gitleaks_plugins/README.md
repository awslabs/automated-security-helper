# ASH Gitleaks Plugin

[gitleaks](https://github.com/gitleaks/gitleaks) finds credentials (API keys, tokens, private keys) by matching its rule set against file contents. ASH runs it as `gitleaks dir` over the files in the scan target. It does not scan git history.

detect-secrets stays on by default and is unaffected; the two can run side by side. ASH does not deduplicate across scanners, so a secret both of them find is reported twice, once under each scanner's name and rule id; suppress it for each scanner, or enable only one.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. A scan that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_gitleaks_plugins
```

or, for one run:

```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_gitleaks_plugins
```

With the module listed, `gitleaks` runs by default. `scanners.gitleaks.enabled: false` turns it off again.

## Installing the tool

The ASH container image includes it. Locally:

```bash
ash dependencies install --config-overrides "ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_gitleaks_plugins]" --tool gitleaks
```

## Configuration

```yaml
scanners:
  gitleaks:
    enabled: true
    options:
      # A gitleaks TOML config, relative to the source directory.
      config_file: null
      # A gitleaks JSON report whose findings gitleaks ignores (--baseline-path).
      baseline_path: null
      # Skip files larger than this many megabytes.
      max_target_megabytes: null
      # Seconds before the gitleaks process is killed. Inherited by every scanner.
      scan_timeout: 1800
```

## Documentation

Severity mapping, suppressions, offline use and every option: [docs/content/docs/plugins/community/gitleaks-plugin.md](../../../docs/content/docs/plugins/community/gitleaks-plugin.md).
