# ASH SpotBugs Plugin

[SpotBugs](https://spotbugs.github.io/) with the [Find Security Bugs](https://find-sec-bugs.github.io/) plugin finds security defects in JVM bytecode. ASH runs `spotbugs -textui` over the compiled classes and archives (`.class`, `.jar`, `.war`, `.ear`) in the scan target. A tree with no compiled code is skipped with an INFO message; ASH does not compile anything. ASH pins SpotBugs 4.10.5 and Find Security Bugs 1.14.0.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_spotbugs_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_spotbugs_plugins
```

With the module listed, `spotbugs` runs by default. `scanners.spotbugs.enabled: false` turns it off again. There is no license or service gate.

## Installing the tool

SpotBugs needs a Java runtime (`JAVA_HOME` or `java` on `PATH`), which ASH does not install.

<!-- doctest: illustrative reason="downloads and installs the scanner's tool" -->
```bash
ash dependencies install --config-overrides "ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_spotbugs_plugins]" --tool spotbugs
```

That downloads the pinned SpotBugs release and the Find Security Bugs jar, verifies both against pinned SHA256 digests, and installs them under the ASH bin directory (Linux and macOS only).

## Configuration

```yaml
scanners:
  spotbugs:
    enabled: true
    options:
      # Lowest confidence reported: high, medium or low.
      confidence: medium
      # Analysis effort: min, less, default, more or max.
      effort: default
      # Keep only results from SpotBugs's SECURITY category.
      security_only: true
      # Seconds for the whole SpotBugs scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

## Documentation

Inputs, severity mapping, exit status, suppressions and offline use: [the SpotBugs plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/community/spotbugs-plugin/).
