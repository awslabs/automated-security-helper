# ASH ScanCode Plugin

[ScanCode Toolkit](https://github.com/aboutcode-org/scancode-toolkit) (Apache-2.0) matches
file text against its bundled license index and reports which licenses a file carries.
This plugin reports each match as an `INFO` finding. It is license and provenance
information: a license that is not OSI-approved is not a security severity.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. ScanCode reads
every file in the tree and matches it against thousands of license rules, so it is slow on
a large tree. Listing the module is therefore the opt-in; once it is listed the scanner
runs with the others.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_scancode_plugins
```

To run only ScanCode, for one run:

```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_scancode_plugins --scanners scancode
```

## Installing the tool

ASH installs `scancode-toolkit` with `uv tool install` on an online scan. Locally:

```bash
ash dependencies install --config-overrides "ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_scancode_plugins]" --tool scancode
```

ScanCode's documentation says its pip install does not work on ARM CPUs (Apple Silicon)
and needs system libraries on Linux; see its installation guide.

## Configuration

```yaml
scanners:
  scancode:
    enabled: true           # set false to skip it while the module is listed
    options:
      license_score: 0      # drop matches scoring below this (0-100)
      tool_version: null    # default "==32.5.0"
      scan_timeout: 1800    # seconds per target
      install_timeout: 1200
```

## Documentation

Severity, exit status, offline use and every option: [the ScanCode plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/community/scancode-plugin/).
