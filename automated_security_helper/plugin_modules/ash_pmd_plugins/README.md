# ASH PMD Plugin

[PMD](https://pmd.github.io/) is a source code analyzer for Java and several other languages. ASH runs it as `pmd check` over the scan target with PMD's security rule category and reads the SARIF PMD writes. PMD needs a Java runtime (11 or later) on `PATH`.

PMD's other rule categories (best practices, code style, design, performance, error-prone) are code-quality rules, not vulnerabilities. ASH runs only the `security` category by default, so a default scan reports security-relevant findings. Adding other categories reports quality findings.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_pmd_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_pmd_plugins
```

With the module listed, `pmd` runs by default. `scanners.pmd.enabled: false` turns it off again. The plugin has no service gate. PMD's BSD-style license carries an acknowledgement clause, so ASH does not bundle PMD: the pinned release is installed only by `ash dependencies install`.

## Installing

PMD is a multi-file distribution (a launcher script and jars), not a single executable. Locally:

<!-- doctest: illustrative reason="downloads and installs the scanner's tool" -->
```bash
ash dependencies install --config-overrides "ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_pmd_plugins]" --tool pmd
```

This downloads the pinned PMD 7.29.0 release archive over HTTPS, checks it against the SHA256 digest pinned in the plugin, unpacks it into ASH's bin directory and writes a `pmd` launcher there. A `pmd` already on `PATH` is also used. A Java runtime is not installed by ASH.

## Configuration

```yaml
scanners:
  pmd:
    enabled: true
    options:
      # PMD built-in categories, each category/<language>/<name>.xml. A ruleset
      # file path or URL is refused (the scanned repository would pick the rules).
      rulesets:
        - category/java/security.xml
      # PMD's own priority filter, 1 (highest) to 5. 5 reports everything.
      minimum_priority: 5
      # Seconds for the whole PMD scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

## Documentation

Severity mapping, suppressions, offline use and every option: [the PMD plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/community/pmd-plugin/).
