# OSV-Scanner alpha scanner plugin

[OSV-Scanner](https://github.com/google/osv-scanner) (Apache-2.0) finds known-vulnerable dependencies. ASH runs it as `osv-scanner scan source --recursive` over the scan target: it reads the lockfiles and manifests it recognizes and reports the advisories in the [OSV database](https://osv.dev) that match the packages it finds.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged. There is no license or service gate.

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

With the module listed, `osv-scanner` runs by default. `scanners.osv-scanner.enabled: false` turns it off again. It runs beside the builtin `grype` and `trivy-repo` scanners, so an advisory more than one of them finds is reported by each.

## Installing

<!-- doctest: illustrative reason="downloads and installs the pinned OSV-Scanner release" -->
```bash
ash dependencies install --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_osv_scanner_plugins"]' --tool osv-scanner
```

This installs the pinned OSV-Scanner release (v2.7.1, checked against the SHA256 the release publishes). If `osv-scanner` is already on `PATH`, ASH uses it.

## Configuration

```yaml
scanners:
  osv-scanner:
    enabled: true
    options:
      # true skips this scanner, as ASH's own --offline mode does: OSV-Scanner
      # matches packages against the OSV API, and ASH provisions no offline
      # database for it.
      offline: false
      # Seconds for the whole OSV-Scanner run (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

## Network use

Online, OSV-Scanner sends the names and versions of the packages it found to the OSV API (and to deps.dev for the transitive resolution of Maven and Python requirements manifests). Under `offline: true` or `ash scan --offline` the scanner does not run, so nothing is sent.

## Documentation

Severity mapping, suppressions, offline behavior and the exit codes: [the OSV-Scanner plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/alpha/osv-scanner-plugin/).
