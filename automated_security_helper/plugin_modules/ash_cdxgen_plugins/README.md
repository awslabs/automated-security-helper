# cdxgen alpha scanner plugin

Generates a CycloneDX software bill of materials (SBOM) for the scanned directory
with [cdxgen](https://github.com/cdxgen/cdxgen). It reports inventory, not
findings, so every component is informational, as with the builtin syft scanner.

## Enabling

```yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_cdxgen_plugins
```

There is no license or service gate: cdxgen is Apache-2.0 and ASH runs it locally.

## Installing

cdxgen needs Node.js (the 12.9.2 release declares 20, 22, 24, 25 or 26).
`ash dependencies install` installs the pinned release with
`npm install -g @cyclonedx/cdxgen@12.9.2`. The ASH container image does not
include it.

## Configuration

```yaml
scanners:
  cdxgen:
    options:
      project_type: [] # cdxgen --type values; empty means auto-detect
      exclude: [] # entries of path (a glob passed as --exclude) and reason
```

ASH always passes `--spec-version=1.6` and `--no-install-deps`. The second keeps
cdxgen from running the scanned project's package manager.

## Documentation

See <https://awslabs.github.io/automated-security-helper/docs/plugins/alpha/cdxgen-plugin/>.
