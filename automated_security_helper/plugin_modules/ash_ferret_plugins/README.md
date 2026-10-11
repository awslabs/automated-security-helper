# ASH Ferret Scan plugin

This module adds the `ferret-scan` scanner, which runs [Ferret Scan](https://github.com/awslabs/ferret-scan) to find sensitive data in files: credit card numbers, passport and Social Security numbers, API keys and other secrets, email addresses, phone numbers and more. It is a community plugin: it ships with ASH, and a scan runs it only when the module is loaded. The full documentation is the [Ferret Scan plugin](https://awslabs.github.io/automated-security-helper/docs/plugins/community/ferret-scan-plugin/) page.

## Install Ferret Scan

The plugin runs the `ferret-scan` command it finds on `PATH`, and supports ferret-scan `>=2.4.5,<2.6.0` (`DEFAULT_VERSION_CONSTRAINT` in `ferret_scanner.py`). ASH does not install it during a scan, and the ASH container image does not include it. Install it with ASH, which runs `pip install` with the supported range in the Python environment that runs ASH, and so fails if that environment has no pip, as in one that uv created:

<!-- doctest: illustrative reason="installs ferret-scan from PyPI" -->
```bash
ash dependencies install \
  --config-overrides 'ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_ferret_plugins]' \
  --tool ferret-scan
```

Or install it yourself, with the range: without it you get the newest release, which may be outside it.

<!-- doctest: illustrative reason="installs ferret-scan from PyPI" -->
```bash
pipx install 'ferret-scan>=2.4.5,<2.6.0'
```

If `ferret-scan` is not on `PATH`, the scanner is reported MISSING and the scan exits with code 1.

## Load the plugin

Name the module in an ASH config. A repository's own `.ash/.ash.yaml` may load this module:

```yaml
project_name: my-service
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_ferret_plugins
scanners:
  ferret-scan:
    options:
      confidence_levels: "high,medium"
      checks: "CREDIT_CARD,SECRETS,SSN,PASSPORT"
```

Or name it on the command line with `--ash-plugin-modules`. This lists `ferret-scan` among the scanners:

```bash
ash plugin list --ash-plugin-modules automated_security_helper.plugin_modules.ash_ferret_plugins
```

ferret-scan's SARIF is written to `.ash/ash_output/scanners/ferret-scan/source/ferret-scan.sarif`, and its findings are in every ASH report.

## Options

Every option, with its type and default, is in the [scanner reference](https://awslabs.github.io/automated-security-helper/reference/scanners/#ferret-scan). ferret-scan options that conflict with how ASH runs the tool, such as `format`, `debug`, `verbose` and `suppressions_file`, are refused: a config that sets one makes the scanner fail to start. The [plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/community/ferret-scan-plugin/#options) lists them.

For ferret-scan's own debug or verbose output, set `ferret_debug` or `ferret_verbose`:

<!-- doctest: illustrative reason="needs ferret-scan installed" -->
```bash
ash scan \
  --ash-plugin-modules automated_security_helper.plugin_modules.ash_ferret_plugins \
  --scanners ferret-scan \
  --config-overrides 'scanners.ferret-scan.options.ferret_debug=true'
```

Leave `show_match` off where reports or logs are shared. With it on, ferret-scan puts the matched values, such as a card number or a key, into its findings, and from there into the SARIF files, every report and the logs. Some profiles in the bundled `ferret-config.yaml` turn it on; the plugin page names them.

## The ferret-scan config file

ASH passes ferret-scan one config file: the file that `config_file` names, when that file is outside every git checkout and the scanned directory, and otherwise the `ferret-config.yaml` bundled with this plugin. With `use_default_config: false` and no usable `config_file`, ferret-scan uses its built-in defaults instead.

A ferret-scan config file inside the scanned repository is never used, whether `config_file` names it or ASH finds it by name (`ferret.yaml`, `.ferret.yaml`, `.ash/ferret.yaml` and the like); ASH logs a warning and goes on as if it were not there. To use your own config, keep it outside the repository and name it with `config_file`.

## False positives from the SECRETS check

ferret-scan's `SECRETS` check includes a detector, `API_KEY_OR_SECRET`, that matches the name of an assignment when the name is a secret keyword such as `session`, `token` or `api_key`, whatever the value, so a model field or a local variable named `session` can be reported at HIGH confidence although it holds no credential. ferret-scan's config cannot turn this detector off (its `disabled_types` setting works only for the `INTELLECTUAL_PROPERTY` check), so the plugin keeps it on and you handle its false positives with ASH:

```yaml
project_name: my-service
global_settings:
  suppressions:
    - path: src/models/generated_model.py
      rule_id: API_KEY_OR_SECRET
      reason: "A field name that matches the secret-keyword rule, not a credential"
```

You can also skip whole directories with the `exclude_patterns` option, or leave `SECRETS` out of `checks` if you do not need secret detection. [DEVELOPMENT.md](DEVELOPMENT.md#design-decision-api_key_or_secret-stays-enabled-false-positives-are-suppressed) records why the plugin does not filter these findings itself.
