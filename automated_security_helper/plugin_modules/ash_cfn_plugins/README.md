# ASH CloudFormation (cfn-lint and cfn-guard) Plugin

`ash_cfn_plugins` holds two CloudFormation scanners. Both read the same templates cfn-nag reads, and neither needs network access to scan.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. A scan that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_cfn_plugins
```

or, for one run:

```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_cfn_plugins
```

With the module listed, `cfn-lint`, `cfn-guard` run by default. `scanners.cfn-lint.enabled: false` turns one off again.

## Installing the tool

The ASH container image includes it. Locally:

```bash
ash dependencies install --config-overrides "ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_cfn_plugins]" --tool cfn-lint --tool cfn-guard
```

## Configuration

```yaml
scanners:
  cfn-lint:
    enabled: true
    options:
      # A .cfnlintrc to use, relative to the source directory. When unset, ASH
      # gives cfn-lint an empty configuration (see "Configuration files" below).
      config_file: .cfnlintrc
      # Regions to validate against. Defaults to cfn-lint's own default (us-east-1).
      regions: [us-east-1, eu-west-1]
      # Rule ids or prefixes to skip everywhere, or to enable (e.g. "I" for
      # informational rules, which cfn-lint does not run by default).
      ignore_checks: [W3005]
      include_checks: [I]
      # Version constraint for the installed tool.
      tool_version: ">=1.43.3,<2.0.0"
      # Seconds before cfn-lint is killed.
      scan_timeout: 1800
```

## Documentation

Severity mapping, suppressions, offline use and every option: [docs/content/docs/plugins/community/cfn-plugin.md](../../../docs/content/docs/plugins/community/cfn-plugin.md).
