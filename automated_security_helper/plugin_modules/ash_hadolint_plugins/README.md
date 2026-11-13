# ASH hadolint Plugin

> **Pending licensing review.** The hadolint plugin, and the hadolint binary (GPL-3.0) the ASH container image ships for it, are pending licensing review.

[hadolint](https://github.com/hadolint/hadolint) lints Dockerfiles. It checks
each instruction against its own `DL` rules (unpinned base images, `apt-get`
without pinned versions, `ADD` where `COPY` would do, a final `USER root`, and
so on) and runs [ShellCheck](https://www.shellcheck.net/) over the shell in every
`RUN` instruction, reported as `SC` rules.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_hadolint_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_hadolint_plugins
```

With the module listed, `hadolint` runs by default. `scanners.hadolint.enabled: false` turns it off again.

## Installing the tool

The ASH container image includes it. Locally:

<!-- doctest: illustrative reason="downloads and installs the scanner's tool" -->
```bash
ash dependencies install --config-overrides "ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_hadolint_plugins]" --tool hadolint
```

## Configuration

```yaml
scanners:
  hadolint:
    enabled: true
    options:
      # A hadolint config file outside the scanned tree, honored only when set
      # with --config-overrides or an ASH config file outside the tree. Unset,
      # hadolint gets an empty config: a .hadolint.yaml in the scanned repository
      # is not read. A path that is honored but missing fails the scan instead of
      # silently running with hadolint's defaults.
      config_file: null
      # Seconds for the whole hadolint scan (default 1800; null for no limit).
      # Every hadolint process the scan starts shares this one budget.
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

## Documentation

Severity mapping, suppressions, offline use and every option: [the hadolint plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/community/hadolint-plugin/).
