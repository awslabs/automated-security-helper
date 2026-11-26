# ASH Kingfisher Plugin

[Kingfisher](https://github.com/mongodb/kingfisher) finds secrets in files. It is maintained by MongoDB and licensed Apache-2.0. ASH runs it as `kingfisher scan` over the scan target: the files as they are on disk, not git history. The flags ASH passes were checked against v2.19.1.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_kingfisher_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_kingfisher_plugins
```

With the module listed, `kingfisher` runs by default. `scanners.kingfisher.enabled: false` turns it off again. It runs beside the builtin secret scanners, so a secret more than one finds is reported by each.

## Installing the tool

ASH has no pinned release of Kingfisher and its container image does not include it. Install the binary from the [Kingfisher releases](https://github.com/mongodb/kingfisher/releases) and put `kingfisher` on `PATH`. Without it the scanner is reported `MISSING`.

## Configuration

```yaml
scanners:
  kingfisher:
    enabled: true
    options:
      # Validate findings against each provider's live API (operator only; off,
      # ASH passes --no-validate and no credential leaves the host).
      validate_credentials: false
      # Seconds for the whole Kingfisher scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

## Documentation

Live validation, severity, exit codes, suppressions and offline use: [the Kingfisher plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/community/kingfisher-plugin/).
