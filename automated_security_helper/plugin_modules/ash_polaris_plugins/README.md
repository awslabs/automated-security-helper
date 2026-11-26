# Polaris alpha scanner plugin

Runs [Polaris](https://github.com/FairwindsOps/polaris) (Apache-2.0) over the Kubernetes
YAML files in the scanned directory, using the checks built into the binary. It does not
talk to a cluster.

## Enabling

The scanner is on once its module is listed:

```yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_polaris_plugins
```

A scan that does not list the module is unchanged. There is no license or service gate.

## Installing

```bash
ash dependencies install --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_polaris_plugins"]' --tool polaris
```

This installs the pinned Polaris release. If `polaris` is already on `PATH`, ASH uses it.

## Configuration

The plugin has no options of its own, only the shared ones (`severity_threshold`,
`scan_timeout`, `offline`). It passes no Polaris config file, and it turns Polaris
exemptions off (`--disallow-exemptions`), so the scanned tree cannot hide findings with
`polaris.fairwinds.com/<check>-exempt` annotations. Use ASH suppressions instead.

## Severity

Polaris `danger` is HIGH (SARIF level `error`); `warning` is MEDIUM (level `warning`).

## Documentation

See <https://awslabs.github.io/automated-security-helper/docs/plugins/alpha/polaris-plugin/>.
