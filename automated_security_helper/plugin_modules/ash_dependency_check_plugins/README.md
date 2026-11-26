# ASH Dependency-Check Plugin

[OWASP Dependency-Check](https://github.com/dependency-check/DependencyCheck) identifies third-party libraries in a tree (Java, .NET, JavaScript, Python, Ruby, Go and others) and reports the known vulnerabilities, mostly from the NVD, that match them. ASH runs it over the scan target and reads the SARIF report it writes.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_dependency_check_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_dependency_check_plugins
```

With the module listed, `dependency-check` runs by default. `scanners.dependency-check.enabled: false` turns it off again.

## Requirements

- A Java runtime on `PATH`. Without one the scanner is reported `MISSING`.
- Network access. The tool downloads its vulnerability database from the NVD on the first run, which is slow without an API key. Set `NVD_API_KEY` to use one; ASH writes it to a private properties file and never puts it on the command line. Under `--offline` the scanner is skipped.

## Installing the tool

<!-- doctest: illustrative reason="downloads and installs the scanner's tool" -->
```bash
ash dependencies install --config-overrides "ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_dependency_check_plugins]" --tool dependency-check
```

This downloads the pinned v13.0.0 release zip, verifies its SHA-256 digest, unpacks it beside ASH's bin directory and writes a `dependency-check` launcher there. Linux and macOS only; a `dependency-check` already on `PATH` is also used.

## Configuration

```yaml
scanners:
  dependency-check:
    enabled: true
    options:
      # Seconds for the whole scan (default 1800; null for no limit). The first run
      # downloads the database, so raise this for a first scan without an API key.
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

## Severity

Dependency-Check writes every result as `warning`. ASH rates each result from its rule's CVSS score: 9.0 and up is CRITICAL, 7.0 and up HIGH, 4.0 and up MEDIUM, above 0 LOW, 0 INFO. A rule with only a CVSS v2 severity uses that word, and a rule with neither is MEDIUM. The SARIF level is set to match.

## Documentation

Flags, severity, exit status, offline use and suppressions: [the Dependency-Check plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/community/dependency_check-plugin/).
