# ASH hadolint Plugin

[hadolint](https://github.com/hadolint/hadolint) lints Dockerfiles. It checks
each instruction against its own `DL` rules (unpinned base images, `apt-get`
without pinned versions, `ADD` where `COPY` would do, a final `USER root`, and
so on) and runs [ShellCheck](https://www.shellcheck.net/) over the shell in every
`RUN` instruction, reported as `SC` rules.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. A scan that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_hadolint_plugins
```

or, for one run:

```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_hadolint_plugins
```

With the module listed, `hadolint` runs by default. `scanners.hadolint.enabled: false` turns it off again.

## Installing the tool

The ASH container image includes it. Locally:

```bash
ash dependencies install --config-overrides "ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_hadolint_plugins]" --tool hadolint
```

## Configuration

```yaml
scanners:
  hadolint:
    enabled: true
    options:
      # A hadolint config file, relative to the source directory. When unset,
      # ASH uses the first of .hadolint.yaml, .hadolint.yml, .ash/.hadolint.yaml
      # and .ash/hadolint.yaml that exists. A path that is set but missing fails
      # the scan instead of silently running with hadolint's defaults.
      config_file: null
      # Seconds for the whole hadolint scan (default 1800; null for no limit).
      # Every hadolint process the scan starts shares this one budget.
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

## Documentation

Severity mapping, suppressions, offline use and every option: [docs/content/docs/plugins/community/hadolint-plugin.md](../../../docs/content/docs/plugins/community/hadolint-plugin.md).
