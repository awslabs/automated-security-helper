# Titus alpha scanner plugin

Secret detection over the scan target's files with
[Titus](https://github.com/praetorian-inc/titus) (Apache-2.0), Praetorian's Go port of
Nosey Parker. Where a builtin secret scanner finds the same secret, both report it.

## Enabling

The scanner is on once its module is listed:

```yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_titus_plugins
```

A scan that does not list the module is unchanged. There is no license or service gate:
Titus is a local binary, and the plugin passes no flag that validates a secret or calls
an outside API.

## Installing

```bash
ash dependencies install --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_titus_plugins"]' --tool titus
```

This installs the pinned Titus release (v1.3.0, pinned in this package's
`titus_install.py`: one release executable per platform and its SHA256, from the
release's `checksums.txt`). If `titus` is already on `PATH`, ASH uses it.

## What it runs

`titus scan --format=sarif --output=:memory: --accessibility=private --context-lines=0 -- <path>`

- SARIF 2.1.0 is read from Titus' standard output.
- Titus' rules apply as built in. Rules marked noisy stay off.
- Matched text is replaced with `REDACTED` in every snippet.
- Only exit code 0 is accepted as a finished run.

## Configuration

The plugin has no options of its own, only the shared ones (`severity_threshold`,
`scan_timeout`, `offline`).

## Severity

Severity comes from Titus' own 0-100 score: 80 and up CRITICAL, 60 up HIGH, 40 up
MEDIUM, 20 up LOW, below 20 INFO.

## Documentation

See <https://awslabs.github.io/automated-security-helper/docs/plugins/alpha/titus-plugin/>.
