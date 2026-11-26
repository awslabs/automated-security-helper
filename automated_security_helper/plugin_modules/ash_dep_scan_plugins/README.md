# dep-scan alpha scanner plugin

[OWASP dep-scan](https://github.com/owasp-dep-scan/dep-scan) (MIT) reports known vulnerabilities in the dependencies of a source tree. It builds a bill of materials with cdxgen, looks each component up in a local vulnerability database, and writes a CycloneDX Vulnerability Disclosure Report that ASH converts to findings. ASH runs it over the scan target and pins release 6.3.2.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged.

```yaml
# .ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_dep_scan_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_dep_scan_plugins
```

With the module listed, `dep-scan` runs by default. `scanners.dep-scan.enabled: false` turns it off again. It needs no account, API key or license acceptance, so there is no opt-in beyond listing the module.

## Installing the tools

dep-scan needs two tools:

- `depscan`, installed by ASH as a uv tool from PyPI (`owasp-depscan==6.3.2`):

<!-- doctest: illustrative reason="downloads and installs the scanner's tool" -->
```bash
ash dependencies install --config-overrides "ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_dep_scan_plugins]" --tool dep-scan
```

- `cdxgen`, which reads the manifests. ASH does not install it: if it is not on `PATH` the scanner is reported `MISSING`.

<!-- doctest: illustrative reason="installs a global npm package" -->
```bash
npm install -g @cyclonedx/cdxgen
```

The ASH container image installs the pinned `depscan` the same way and carries its license file, but not cdxgen.

The first scan downloads dep-scan's vulnerability database, so the scanner is skipped under `--offline`.

## Configuration

```yaml
scanners:
  dep-scan:
    enabled: true
    options:
      # FrameworkReachability (dep-scan's default) adds a "reachable" tag to findings
      # dep-scan could trace to the project's code; "off" skips that analysis. It
      # never removes a finding.
      reachability_analyzer: FrameworkReachability
      # Version constraint for the owasp-depscan install (default ==6.3.2).
      tool_version: null
      # Seconds to allow for installing the tool.
      install_timeout: 300
      # Seconds for the whole dep-scan run (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

A `.config/depscan.toml` in the scanned tree is never read: ASH passes `depscan --config` with an empty file outside the tree.

## Documentation

Severity mapping, exit status, suppressions and offline use: [the dep-scan plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/alpha/dep-scan-plugin/).
