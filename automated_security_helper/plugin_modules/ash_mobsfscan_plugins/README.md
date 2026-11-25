# ASH mobsfscan Plugin

[mobsfscan](https://github.com/MobSF/mobsfscan) is a static analysis tool for
Android (Java, Kotlin), iOS (Swift, Objective-C) and mobile JavaScript source. It
reports insecure code patterns with rule sets written for mobile apps. It overlaps
ASH's builtin semgrep and opengrep scanners where rules coincide; the mobile rule
sets are the reason to add it.

mobsfscan is LGPL-3.0-or-later licensed. ASH runs it as a separate process and does
not import it or ship it in the container image. It needs no account or license key.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_mobsfscan_plugins
```

or, for one run:

```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_mobsfscan_plugins
```

With the module listed, `mobsfscan` runs by default. `scanners.mobsfscan.enabled: false` turns it off again.

## Installing the tool

mobsfscan is a Python package that ASH installs as a uv tool:

```bash
ash dependencies install --config-overrides "ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_mobsfscan_plugins]" --tool mobsfscan
```

## Configuration

```yaml
scanners:
  mobsfscan:
    enabled: true
    options:
      # pip version constraint for the install; unset uses the pinned release.
      tool_version: null
      # Seconds allowed for installing the tool.
      install_timeout: 300
      # Seconds for the whole scan (default 1800).
      scan_timeout: 1800
      severity_threshold: null
```

A `.mobsf` file in the scanned repository is not read: ASH passes mobsfscan an empty
config so the tree cannot ignore rules or paths. Inline `mobsf-ignore` comments in
source are still honored by mobsfscan, which has no option to turn that off.

## semgrep

mobsfscan runs its Java, Kotlin and Swift rules through `semgrep`, which it expects on
`PATH`. It is a dependency of the mobsfscan package, so a uv install brings it. If it is
missing mobsfscan exits 0 with a report that holds no Java, Kotlin or Swift finding and
no error, so ASH refuses to run a pre-installed mobsfscan whose environment has no
semgrep. Per-file semgrep errors are not visible in mobsfscan's SARIF.

## Documentation

Severity mapping, offline use and every option: [the mobsfscan plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/community/mobsfscan-plugin/).
