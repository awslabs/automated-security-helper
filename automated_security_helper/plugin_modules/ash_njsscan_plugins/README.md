# ASH njsscan Plugin

[njsscan](https://github.com/ajinabraham/njsscan) (LGPL-3.0) is a static security
scanner for Node.js applications. It runs a curated rule pack over JavaScript and
server-side template files and maps each finding to an OWASP category and a CWE.
The rules ship inside the package, so a scan needs no network. ASH runs it as a
separate process; nothing in ASH imports it.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_njsscan_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_njsscan_plugins
```

With the module listed, `njsscan` runs by default. `scanners.njsscan.enabled: false` turns it off again. There is no license or service gate.

## Installing the tool

ASH installs it through `uv`, pinned to `njsscan==1.0.2`. Locally:

<!-- doctest: illustrative reason="downloads and installs the scanner's tool" -->
```bash
ash dependencies install --config-overrides "ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_njsscan_plugins]" --tool njsscan
```

Linux and macOS only; on Windows an enabled scanner is skipped.

## Configuration

```yaml
scanners:
  njsscan:
    enabled: true               # once the module is listed; false turns it off
    options:
      scan_timeout: 1800        # seconds for the whole scan
      tool_version: null        # default "==1.0.2"
      install_timeout: 300
```

ASH passes njsscan a config of its own so a `.njsscan` file in the scanned tree is not read. njsscan always honors `// njsscan-ignore:` comments; ASH cannot turn that off.

## Severity

ERROR is HIGH, WARNING is MEDIUM, INFO is LOW, anything else is INFO; the SARIF level is set to match.

## Documentation

See the [njsscan plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/community/njsscan-plugin/).
