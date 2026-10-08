# ASH actionlint Plugin

[actionlint](https://github.com/rhysd/actionlint) checks GitHub Actions workflow files: workflow syntax, `${{ }}` expression types, script injection from untrusted event data, hard-coded container credentials, `if:` conditions that are always true, undefined `needs:` jobs, unknown runner labels, and more. It is a single Go binary, MIT licensed. zizmor, also a community plugin, flags template injection too; ASH does not deduplicate across scanners, so with both enabled such a step is reported by each, under its own rule id.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. A scan that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_actionlint_plugins
```

or, for one run:

```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_actionlint_plugins
```

With the module listed, `actionlint` runs by default. `scanners.actionlint.enabled: false` turns it off again.

## Installing the tool

The ASH container image includes it. Locally:

```bash
ash dependencies install --config-overrides "ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_actionlint_plugins]" --tool actionlint
```

## Configuration

```yaml
scanners:
  actionlint:
    enabled: true           # once the module is listed; false turns it off
    options:
      config_file: null     # actionlint config, relative to the source directory
      shellcheck: null      # command name or path; null disables the integration
      pyflakes: null        # command name or path; null disables the integration
      severity_threshold: null
      scan_timeout: 1800
```

## Documentation

Severity mapping, suppressions, offline use and every option: [docs/content/docs/plugins/community/actionlint-plugin.md](../../../docs/content/docs/plugins/community/actionlint-plugin.md).
