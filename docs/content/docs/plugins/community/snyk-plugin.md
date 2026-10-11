# Snyk Code plugin (`snyk-code`)

The `snyk-code` scanner runs `snyk code test`, the static analysis of [Snyk Code](https://snyk.io/product/snyk-code/), on the source directory and reads its SARIF. Snyk Code analyzes the code on Snyk's servers, so the scan uploads the scanned source to Snyk. It is a [community plugin](index.md): it ships with ASH, `ash scan` runs it only when its module is loaded, and only the operator can load it.

## Before you start

- Install the Snyk CLI so that `snyk` is on `PATH`, for example with `npm install -g snyk` ([Snyk CLI](https://github.com/snyk/cli)). ASH does not install it, and the ASH container image does not include it.
- Authenticate it, either with a `SNYK_TOKEN` environment variable or with `snyk auth`, which stores the credential in `~/.config/configstore/snyk.json`. If ASH finds neither, it logs a warning and runs the Snyk CLI anyway.
- Make sure you may send this source code to Snyk under your organization's rules and your Snyk plan. Do not install or authenticate the Snyk CLI on a host that runs ASH unless every scan there may send source to Snyk.

## Load the plugin

The scanner sends source off the host with your Snyk credentials, so a config file that the scanned repository could have written cannot load it. ASH ignores, with a warning, an `ash_plugin_modules` entry for `ash_snyk_plugins`, or for a module inside it, in a config file inside a git checkout or the scanned directory, and under its default policy the MCP server refuses a config an MCP client delivered whose `ash_plugin_modules` list names one, and otherwise drops the entry ([Who may load a module](../../../plugins/index.md#who-may-load-a-module)). Load it from an operator source instead. With `SNYK_TOKEN` set, or after `snyk auth`:

<!-- doctest: illustrative reason="needs the Snyk CLI and a Snyk account" -->
```bash
ash scan \
  --ash-plugin-modules automated_security_helper.plugin_modules.ash_snyk_plugins \
  --scanners snyk-code
```

The `ASH_PLUGIN_MODULES` environment variable, `--config-overrides 'ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_snyk_plugins]'`, or a config file outside every git checkout and the scanned directory, passed with `--config`, work too:

```yaml
project_name: my-service
ash_plugin_modules: [automated_security_helper.plugin_modules.ash_snyk_plugins]
scanners:
  snyk-code:
    options:
      severity_threshold: HIGH
```

Once you load the module, the repository's own `.ash/.ash.yaml` can still set the `snyk-code` options.

Snyk's SARIF is in `.ash/ash_output/scanners/snyk-code/source/results_sarif.sarif`, and its findings are in the finding reports under `.ash/ash_output/reports/`, such as `ash.sarif`, `ash.html`, and `ash.csv`.

## Options

`snyk-code` has the two options every scanner has, `severity_threshold` and `scan_timeout` ([scanner reference](../../../reference/scanners.md#snyk-code)). ASH also passes `severity_threshold` to Snyk as `snyk code test --severity-threshold`, so Snyk does not report findings below it at all; `CRITICAL` is sent as `high`, Snyk Code's highest level.

## What is sent to Snyk

`snyk code test` uploads the source files it supports from the source directory. ASH applies `global_settings.ignore_paths` to Snyk's results after the scan and does not pass them to the Snyk CLI, so ignored directories are uploaded too.

## Known defect

When Snyk Code reports any issue, `snyk` exits with code 1. In this release ASH treats that exit code as a failure: `snyk-code` is recorded as ERROR with no findings, and the scan exits with code 1. A Snyk Code run that finds nothing is recorded as PASSED.

## Offline, container, and sandboxed scans

- Offline mode (`--offline` or `ASH_OFFLINE`): the scanner is reported MISSING, which fails the scan, so do not load the module in offline scans.
- Container mode (`--mode container`): the image has no Snyk CLI, and ASH does not pass `SNYK_TOKEN` into the container.
- Under `--sandbox`, the scanner gets network access, the `SNYK_*` environment variables, and read access to `~/.config/configstore/snyk.json`, beyond the sandbox's defaults ([Enable the scanner sandbox](../../scanner-sandbox.md)).

[Snyk plugin in ASH's CI](snyk-plugin-setup.md) describes how the ASH repository's own CI handles the plugin.
