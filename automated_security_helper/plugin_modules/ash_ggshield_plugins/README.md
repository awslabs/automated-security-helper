# ASH ggshield Plugin

[ggshield](https://github.com/GitGuardian/ggshield) is GitGuardian's command line client. ASH runs `ggshield secret scan path` over the scan target and reads the SARIF it writes.

**ggshield sends the files it scans to the GitGuardian API.** The detection runs on GitGuardian's servers, so this scanner needs the network and a GitGuardian API key, is off by default, and does not run without the key.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. Listing it makes the scanner available; turning it on is a second, explicit step, because the scan uploads your files.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_ggshield_plugins

scanners:
  ggshield:
    enabled: true
```

Export the key before the scan:

<!-- doctest: illustrative reason="needs a GitGuardian API key" -->
```bash
export GITGUARDIAN_API_KEY=<your key>
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_ggshield_plugins
```

Without `GITGUARDIAN_API_KEY` the scanner is reported as unavailable, with a message naming the variable. ASH does not read the credentials `ggshield auth login` stores. Under `ASH_OFFLINE` the scanner is skipped. ASH refuses to run it when ASH's own output directory is inside the scanned tree or when `global_settings.ignore_paths` is set, because ggshield would upload those files.

## Installing the tool

ggshield is a Python package that ASH runs through `uv`. ASH pins the release it was written against (1.56.1; `options.tool_version` overrides it).

<!-- doctest: illustrative reason="downloads and installs the scanner's tool" -->
```bash
ash dependencies install --config-overrides "ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_ggshield_plugins]" --tool ggshield
```

## Configuration

```yaml
scanners:
  ggshield:
    enabled: false # true to opt in
    options:
      # Version constraint for the ggshield install, in pip requirement syntax.
      tool_version: null
      # Seconds allowed for the install.
      install_timeout: 300
      # Seconds for the whole ggshield scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

## Documentation

Severity, the opt-in gate, what is uploaded, suppressions and every option: [the ggshield plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/community/ggshield-plugin/).
