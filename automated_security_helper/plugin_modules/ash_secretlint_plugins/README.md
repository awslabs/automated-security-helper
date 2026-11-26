# ASH Secretlint Plugin

[Secretlint](https://github.com/secretlint/secretlint) finds credentials in files. ASH runs it over the scan target with its recommended rule preset and reads the SARIF it writes. Secretlint is a Node.js tool: Node.js 22 or later is required.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_secretlint_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_secretlint_plugins
```

With the module listed, `secretlint` runs by default. `scanners.secretlint.enabled: false` turns it off again. If Node.js or Secretlint is not installed, the scanner is reported `MISSING`.

## Installing the tool

Locally, with Node.js 22 or later and `npm` on `PATH`:

<!-- doctest: illustrative reason="downloads and installs the scanner's tool" -->
```bash
ash dependencies install --config-overrides "ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_secretlint_plugins]" --tool secretlint
```

This runs `npm install -g secretlint@14.0.1` and `npm install -g @secretlint/secretlint-formatter-sarif@14.0.1`.

## Configuration

```yaml
scanners:
  secretlint:
    enabled: true
    options:
      # Seconds for the whole Secretlint scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

## Documentation

Severity, ignore files, suppressions and offline use: [the Secretlint plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/community/secretlint-plugin/).
