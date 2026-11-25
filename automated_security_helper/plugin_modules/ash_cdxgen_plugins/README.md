# ASH cdxgen plugin

Generates a CycloneDX software bill of materials (SBOM) for the scanned directory
with [cdxgen](https://github.com/CycloneDX/cdxgen). It reports inventory, not
findings, so every component is informational, as with the builtin syft scanner.

## Enabling

```yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_cdxgen_plugins
```

There is no license or service gate: cdxgen is Apache-2.0 and ASH runs it locally.

## Installing

cdxgen needs Node.js (20 or later). `ash dependencies install` installs the pinned
release with `npm install -g @cyclonedx/cdxgen@12.9.2`.

## Configuration

```yaml
scanners:
  cdxgen:
    options:
      project_type: [] # cdxgen --type values; empty means auto-detect
      exclude: [] # glob patterns passed as --exclude
```

ASH always passes `--spec-version=1.6` and `--no-install-deps`. The second keeps
cdxgen from running the scanned project's package manager.

## Documentation

See https://awslabs.github.io/automated-security-helper/docs/plugins/community/cdxgen-plugin/
