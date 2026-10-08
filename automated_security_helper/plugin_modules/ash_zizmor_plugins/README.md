# ASH zizmor Plugin

[zizmor](https://docs.zizmor.sh) is a static analyzer for GitHub Actions. ASH runs it
over a repository's workflows and composite actions and reports template
injection, dangerous triggers, credential persistence, unpinned actions,
excessive permissions and the rest of zizmor's
[audits](https://docs.zizmor.sh/audits/).

actionlint, also a community plugin, flags template injection from untrusted event data too.
ASH does not deduplicate across scanners, so with both enabled such a step is
reported by each, under its own rule id.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. A scan that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_zizmor_plugins
```

or, for one run:

```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_zizmor_plugins
```

With the module listed, `zizmor` runs by default. `scanners.zizmor.enabled: false` turns it off again.

## Installing the tool

The ASH container image includes it. Locally:

```bash
ash dependencies install --config-overrides "ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_zizmor_plugins]" --tool zizmor
```

## Configuration

```yaml
scanners:
  zizmor:
    enabled: true
    options:
      persona: regular        # regular, pedantic or auditor
      config_file: null       # zizmor config; relative to the source dir, or absolute
      online_audits: false    # see "Network access and tokens"
      tool_version: ">=1.29.0,<2.0.0"
      install_timeout: 300
      scan_timeout: 1800
      severity_threshold: null
```

## Documentation

Severity mapping, suppressions, offline use and every option: [docs/content/docs/plugins/community/zizmor-plugin.md](../../../docs/content/docs/plugins/community/zizmor-plugin.md).
