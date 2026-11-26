# Spectral alpha scanner plugin

[Spectral](https://github.com/stoplightio/spectral) (Apache-2.0) lints OpenAPI, Swagger and AsyncAPI descriptions. It reports a missing `operationId`, an undefined path parameter, a broken `$ref`, no `servers`, and the rest of its recommended rules. ASH runs it as `spectral lint` over the JSON and YAML files in the scan target and reads the SARIF it writes.

## Enabling

The scanner is on once its module is listed:

```yaml
# .ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_spectral_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_spectral_plugins
```

A scan that does not list the module is unchanged. `scanners.spectral.enabled: false` turns it off again. It needs no account, token or service.

## Installing

```bash
ash dependencies install --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_spectral_plugins"]' --tool spectral
```

This installs the pinned Spectral release (v6.17.1, one executable per platform, each checked against its SHA256 in `spectral_install.py`). If `spectral` is already on `PATH`, ASH uses it. Spectral publishes no Windows arm64 build. Nothing in this module vendors Spectral code.

## Configuration

```yaml
scanners:
  spectral:
    enabled: true
    options:
      # A Spectral ruleset to use instead of the default (spectral:oas and
      # spectral:asyncapi, recommended). Operator only: set it with
      # --config-overrides or a config file outside every git checkout and the
      # scanned directory. A .spectral.yaml in the scanned tree is never read.
      ruleset_file: null
      scan_timeout: 1800
```

## Severity

Spectral writes `error`, `warning` and `note` (its info and hint both). ASH rates them HIGH, MEDIUM and LOW, with the SARIF level to match.

## Documentation

See <https://awslabs.github.io/automated-security-helper/docs/plugins/alpha/spectral-plugin/>.
