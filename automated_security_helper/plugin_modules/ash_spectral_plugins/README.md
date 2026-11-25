# ASH Spectral Plugin

[Spectral](https://github.com/stoplightio/spectral) lints OpenAPI, Swagger and AsyncAPI descriptions. It reports a missing `operationId`, an undefined path parameter, a broken `$ref`, no `servers`, and the rest of its recommended rules. ASH runs it as `spectral lint` over the JSON and YAML files in the scan target and reads the SARIF it writes.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_spectral_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_spectral_plugins
```

With the module listed, `spectral` runs by default. `scanners.spectral.enabled: false` turns it off again. It needs no account, token or service.

## Installing the tool

ASH does not download Spectral yet: `utils/tool_downloads.py` has no `spectral` row, so install the binary yourself from the [release page](https://github.com/stoplightio/spectral/releases) (the scanner was measured on 6.17.1, linux x64) and put it on `PATH`. Without it the scan reports the scanner as missing its dependency and does not run it. Once the pinned row lands, `ash dependencies install --tool spectral` downloads the release binary and verifies its digest. Nothing in this module vendors Spectral code.

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

See [the plugin's page](https://awslabs.github.io/automated-security-helper/docs/plugins/community/spectral-plugin/).
