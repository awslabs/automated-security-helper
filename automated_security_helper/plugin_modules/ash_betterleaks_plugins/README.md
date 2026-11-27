# ASH Betterleaks Plugin

[Betterleaks](https://github.com/betterleaks/betterleaks) finds secrets in files. It is the successor to gitleaks, written by gitleaks' author, and ASH runs it as `betterleaks dir` over the scan target: the files as they are on disk, not git history. ASH pins the 1.x line.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. A scan that does not list it is unchanged.

```yaml
# .ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_betterleaks_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan fs --ash-plugin-modules automated_security_helper.plugin_modules.ash_betterleaks_plugins
```

With the module listed, `betterleaks` runs by default. `scanners.betterleaks.enabled: false` turns it off again. It runs beside the builtin `gitleaks` scanner, so a secret both find is reported by each.

## Installing the tool

The ASH container image includes it. Locally:

<!-- doctest: illustrative reason="downloads and installs the scanner's tool" -->
```bash
ash dependencies install --config-overrides "ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_betterleaks_plugins]" --tool betterleaks
```

## Configuration

```yaml
scanners:
  betterleaks:
    enabled: true
    options:
      # A Betterleaks TOML config, honored only when set with --config-overrides
      # or an ASH config file outside every git checkout and the scanned tree.
      # Unset, Betterleaks uses its built-in rules: a .betterleaks.toml or
      # .gitleaks.toml in the scanned repository is not read.
      config_file: null
      # Honor betterleaks:allow and gitleaks:allow comments in the scanned files
      # (operator only; off, every finding reaches ASH).
      honor_inline_ignores: false
      # Run over a tree that holds a .betterleaksignore or .gitleaksignore, which
      # drop findings before ASH sees them (operator only; off, such a tree fails
      # the scan).
      honor_tree_ignore_files: false
      # Seconds for the whole Betterleaks scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

## Documentation

How it differs from gitleaks, suppressions, ignore files, offline use and every option: [the Betterleaks plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/alpha/betterleaks-plugin/).
