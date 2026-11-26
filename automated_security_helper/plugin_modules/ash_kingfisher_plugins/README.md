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

ASH pins Kingfisher v2.19.1 in `utils/tool_downloads.py`: `ash dependencies install --tool kingfisher` downloads the release archive for the current platform, refuses a digest mismatch (archive and executable both), and puts `kingfisher` on `PATH`; the container image installs it the same way. A `kingfisher` already on `PATH` is left alone. Without either, the scanner is reported `MISSING`.

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
