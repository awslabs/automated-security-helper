# ASH Snyk Code plugin

This module adds the `snyk-code` scanner, which runs `snyk code test`, the static analysis of [Snyk Code](https://snyk.io/product/snyk-code/), on the source directory and reads its SARIF. Snyk Code analyzes the code on Snyk's servers, so the scan uploads the scanned source to Snyk with your Snyk credentials. It is a community plugin: it ships with ASH, a scan runs it only when the module is loaded, and only the operator running ASH can load it. The full documentation is the [Snyk Code plugin](https://awslabs.github.io/automated-security-helper/docs/plugins/community/snyk-plugin/) page.

The plugin runs Snyk Code only. Snyk's dependency, container and infrastructure-as-code scans are not part of it.

## Before you start

- Install the Snyk CLI so that `snyk` is on `PATH`, for example with `npm install -g snyk` ([Snyk CLI](https://github.com/snyk/cli)). ASH does not install it, and the ASH container image does not include it.
- Authenticate it, with a `SNYK_TOKEN` environment variable or with `snyk auth`, which stores the credential in `~/.config/configstore/snyk.json`. If ASH finds neither, it logs a warning and runs the Snyk CLI anyway.
- Make sure that your organization's rules and your Snyk plan let you send this source code to Snyk.

## Load the plugin

A config file that the scanned repository could have written cannot load this module. ASH ignores, with a warning, an `ash_plugin_modules` entry for `ash_snyk_plugins` in a config file inside a git checkout or the scanned directory, such as the repository's own `.ash/.ash.yaml`. Load it from the command line instead:

<!-- doctest: illustrative reason="needs the Snyk CLI and a Snyk account" -->
```bash
ash scan \
  --ash-plugin-modules automated_security_helper.plugin_modules.ash_snyk_plugins \
  --scanners snyk-code
```

The `ASH_PLUGIN_MODULES` environment variable and `--config-overrides` work too, as does a config file outside every git checkout and the scanned directory, passed with `--config`:

```yaml
project_name: my-service
ash_plugin_modules: [automated_security_helper.plugin_modules.ash_snyk_plugins]
scanners:
  snyk-code:
    options:
      severity_threshold: HIGH
```

Snyk's SARIF is written to `.ash/ash_output/scanners/snyk-code/source/results_sarif.sarif`, and its findings are in every ASH report.

## Options

`snyk-code` has the two options every scanner has, `severity_threshold` and `scan_timeout` ([scanner reference](https://awslabs.github.io/automated-security-helper/reference/scanners/#snyk-code)). ASH also passes `severity_threshold` to the Snyk CLI as `snyk code test --severity-threshold`, so Snyk does not report findings below it at all; `CRITICAL` is sent as `high`, Snyk Code's highest level.

## Limits

- When Snyk Code reports an issue, `snyk` exits with code 1, and in this release ASH treats that as a failure: snyk-code is recorded as ERROR with no findings, and the scan exits with code 1. See [Known defect](https://awslabs.github.io/automated-security-helper/docs/plugins/community/snyk-plugin/#known-defect).
- ASH applies `global_settings.ignore_paths` to Snyk's results after the scan and does not pass them to the Snyk CLI, so ignored directories are uploaded too.
- In offline mode the scanner is reported MISSING, which fails the scan. The ASH container image has no Snyk CLI, and ASH does not pass `SNYK_TOKEN` into the container.
