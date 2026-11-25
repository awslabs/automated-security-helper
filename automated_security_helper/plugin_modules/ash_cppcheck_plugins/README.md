# ASH cppcheck Plugin

[Cppcheck](https://cppcheck.sourceforge.io/) is a static analyzer for C and C++. It
finds undefined behavior, memory and resource leaks, out-of-bounds access, and (with
the style groups ASH enables) unused code, portability and performance problems. It
needs no build.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_cppcheck_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_cppcheck_plugins
```

With the module listed, `cppcheck` runs by default. `scanners.cppcheck.enabled: false` turns it off again. If the tool is not installed, the scanner is reported `MISSING`.

## Installing the tool

Cppcheck is licensed GPL-3.0-or-later and ASH only runs it as a separate program; ASH does not bundle or redistribute it. The project publishes no Linux or macOS binary, so ASH installs it from the system package manager (apt on Linux, Homebrew on macOS). It needs a Cppcheck release that supports `--output-format=sarif`.

<!-- doctest: illustrative reason="installs the scanner's tool with the system package manager" -->
```bash
ash dependencies install --config-overrides "ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_cppcheck_plugins]" --tool cppcheck
```

## Configuration

```yaml
scanners:
  cppcheck:
    enabled: true
    options:
      # Seconds for the whole cppcheck scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

Cppcheck has no operator-only options: nothing in the scanned tree can change what it runs, and `// cppcheck-suppress` comments are not honored (use ASH suppressions).

## Severity

A rule whose `security-severity` is 7.0 or more is HIGH. Otherwise the level decides:

| Cppcheck SARIF level | ASH severity |
| --- | --- |
| error (not written by 2.17.1) | HIGH |
| warning | MEDIUM |
| note | LOW |

## Documentation

<https://awslabs.github.io/automated-security-helper/docs/plugins/community/cppcheck-plugin/>
