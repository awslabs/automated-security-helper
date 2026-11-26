# Composer Audit alpha scanner plugin

[Composer](https://getcomposer.org/) (MIT) is the PHP dependency manager. Its `composer audit` command checks the packages in a `composer.lock` against published security advisories, reports abandoned packages, and reports locked versions that match a filter list such as the `malware` list. ASH runs `composer audit --locked --format=json` once for every `composer.lock` in the scan target and reports each advisory and each filter-list match as a finding on the lock file, on the line that names the package.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged.

```yaml
# .ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_composer_audit_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_composer_audit_plugins
```

With the module listed, `composer-audit` runs by default. `scanners.composer-audit.enabled: false` turns it off again.

## Installing

<!-- doctest: illustrative reason="downloads a release asset" -->
```bash
ash dependencies install --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_composer_audit_plugins"]' --tool composer-audit
```

This installs the pinned Composer 2.11.3 phar, checked against the SHA-256 Composer publishes for it: as `composer` on Linux and macOS, and on Windows as `composer.phar` with a `composer.bat` launcher beside it, the layout of Composer's own manual Windows install. On Windows the scanner runs that phar with `php` itself rather than through the launcher. ASH does not install PHP: Composer needs PHP 7.2.5 or later on `PATH`. If `composer` is already on `PATH`, ASH uses it. Without `php` or `composer` the scanner is reported `MISSING`. The ASH container image includes neither.

## Network

The advisories are fetched from Packagist (or the repositories the project's `composer.json` lists) when the audit runs. There is no offline mode: with `--offline` the scanner is skipped. A repository Composer cannot reach fails the scan; it is never reported as a clean result.

## Configuration

```yaml
scanners:
  composer-audit:
    enabled: true
    options:
      # Seconds for the whole scan, every lock file included (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

## Documentation

Severity mapping, what is and is not scanned, and the limits: [the Composer Audit plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/alpha/composer-audit-plugin/).
