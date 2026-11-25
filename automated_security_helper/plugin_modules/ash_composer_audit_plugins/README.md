# ASH Composer Audit Plugin

[Composer](https://getcomposer.org/) is the PHP dependency manager. Its `composer audit` command checks the packages in a `composer.lock` against published security advisories and reports abandoned packages. ASH runs `composer audit --locked --format=json` once for every `composer.lock` in the scan target and reports each advisory as a finding on the lock file, on the line that names the package.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_composer_audit_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_composer_audit_plugins
```

With the module listed, `composer_audit` runs by default. `scanners.composer_audit.enabled: false` turns it off again.

## Installing the tool

ASH does not install Composer. Install Composer 2.8 or later (the first release with `composer audit --abandoned`), and the PHP it needs, from <https://getcomposer.org/download/>, so that `composer` is on `PATH`. If it is not, the scanner is reported `MISSING`.

## Network

The advisories are fetched from Packagist (or the repositories the project's `composer.json` lists) when the audit runs. There is no offline mode: with `--offline` the scanner is skipped. A repository Composer cannot reach fails the scan; it is never reported as a clean result.

## Configuration

```yaml
scanners:
  composer_audit:
    enabled: true
    options:
      # Seconds for the whole scan, every lock file included (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

## Documentation

Severity mapping, what is and is not scanned, and the limits: [the Composer Audit plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/community/composer_audit-plugin/).
