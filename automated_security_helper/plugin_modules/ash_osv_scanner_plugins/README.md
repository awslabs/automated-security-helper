# ASH OSV-Scanner Plugin

[OSV-Scanner](https://github.com/google/osv-scanner) finds known-vulnerable dependencies. ASH runs it as `osv-scanner scan source --recursive` over the scan target: it reads the lockfiles and manifests it recognizes and reports the advisories in the [OSV database](https://osv.dev) that match the packages it finds.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_osv_scanner_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_osv_scanner_plugins
```

With the module listed, `osv_scanner` runs by default. `scanners.osv_scanner.enabled: false` turns it off again. It runs beside the builtin `grype` and `trivy-repo` scanners, so an advisory more than one of them finds is reported by each.

## Installing the tool

ASH does not install OSV-Scanner. Put an `osv-scanner` release from [github.com/google/osv-scanner](https://github.com/google/osv-scanner/releases) on `PATH`; without one the scanner reports the tool as missing.

## Configuration

```yaml
scanners:
  osv_scanner:
    enabled: true
    options:
      # Run this scanner with osv-scanner --offline: no network, and a database
      # downloaded earlier is required. ASH's own --offline mode does the same.
      offline: false
      # Seconds for the whole OSV-Scanner run (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

## Network use

Online, OSV-Scanner sends the names and versions of the packages it found to the OSV API (and to deps.dev for Maven transitive resolution). Use `offline: true` or `ash scan --offline` to keep a scan off the network.

## Documentation

Severity mapping, suppressions, offline use and the exit codes: [the OSV-Scanner plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/community/osv_scanner-plugin/).
