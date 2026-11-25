# ASH Bearer Plugin

[Bearer](https://github.com/Bearer/bearer) is a static application security testing (SAST) scanner that follows sensitive data through code. ASH runs it as `bearer scan --scanner=sast` over the scan target.

Bearer is licensed under the Elastic License 2.0 (ELv2). ASH never installs or redistributes it: you install it yourself, and ASH runs the `bearer` found on `PATH`.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged. Listing the module is the opt-in to running Bearer; installing Bearer is yours.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_bearer_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_bearer_plugins
```

With the module listed, `bearer` runs by default. `scanners.bearer.enabled: false` turns it off again.

## Installing the tool

ASH does not install Bearer, because of its license, and `ash dependencies install` has nothing to run for it. Install it from [the Bearer project](https://github.com/Bearer/bearer) and put `bearer` on `PATH`. If it is missing, the scanner is reported `MISSING`.

## Configuration

```yaml
scanners:
  bearer:
    enabled: true
    options:
      scan_timeout: 1800
      severity_threshold: null
```

A `bearer.yml` or `bearer.ignore` in the scanned repository is never read: ASH passes empty ones from outside the tree.

## Severity

Bearer's severity is kept: critical is CRITICAL (`error`), high is HIGH (`error`), medium is MEDIUM (`warning`), low is LOW (`note`), warning is INFO (`none`).

## Documentation

Full documentation: <https://awslabs.github.io/automated-security-helper/docs/plugins/community/bearer-plugin/>
