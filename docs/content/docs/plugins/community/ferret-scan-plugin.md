# Ferret Scan plugin (`ferret-scan`)

The `ferret-scan` scanner runs [Ferret Scan](https://github.com/awslabs/ferret-scan), which looks for sensitive data in files: credit card numbers, passport numbers, Social Security numbers, API keys and other secrets, email addresses, phone numbers and more. With its preprocessors on (the default), it also extracts text from documents such as PDF and Office files and scans that. It complements detect-secrets, which looks only for credentials. It is a [community plugin](index.md): it ships with ASH and runs only when its module is loaded.

## Install Ferret Scan

The plugin supports ferret-scan `>=2.4.5,<2.6.0` and runs the `ferret-scan` command it finds on `PATH`. ASH does not install it during a scan, and the container image does not include it.

To install it with ASH, run the command below. It runs `pip install 'ferret-scan>=2.4.5,<2.6.0'` with the Python that runs ASH, so it fails if that Python environment has no pip, as in an environment that uv created.

<!-- doctest: illustrative reason="installs ferret-scan from PyPI" -->
```bash
ash dependencies install \
  --config-overrides 'ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_ferret_plugins]' \
  --tool ferret-scan
```

Or install it with pip or pipx into any environment whose commands are on `PATH`. Pass the supported range: without it, you get the newest release, which may be outside it.

<!-- doctest: illustrative reason="installs ferret-scan from PyPI" -->
```bash
pipx install 'ferret-scan>=2.4.5,<2.6.0'
```

If `ferret-scan` is not found, the scanner is MISSING and the scan exits with code 1. If the installed version is outside the supported range, ASH logs a warning and runs it anyway.

## Run it

Load the module and select the scanner:

<!-- doctest: illustrative reason="needs ferret-scan installed" -->
```bash
ash scan \
  --ash-plugin-modules automated_security_helper.plugin_modules.ash_ferret_plugins \
  --scanners ferret-scan
```

Or load it from a config file, which a repository's own `.ash/.ash.yaml` may do:

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

ferret-scan's SARIF is in `.ash/ash_output/scanners/ferret-scan/source/ferret-scan.sarif`, and its findings are in every ASH report.

## Options

The full list, with types and defaults, is in the [scanner reference](../../../reference/scanners.md#ferret-scan). The ones that change what is reported:

- `confidence_levels`: `all` (default), `high`, `medium`, `low`, or a pair such as `high,medium`.
- `checks`: `all` (default), or a comma-separated list of ferret-scan's checks, such as `CREDIT_CARD,SECRETS`. `ferret-scan --help checks` lists the checks of the installed version.
- `exclude_patterns`: glob patterns ferret-scan skips. ASH's `ignore_paths` are passed to ferret-scan as excludes too.
- `profile`: a profile from the ferret-scan config, such as `quick`, `ci` or `security-audit`.
- `finding_limit`: the most findings ferret-scan reports. The default, 0, means no limit; ferret-scan's own default of 200 would cut off large scans.
- `respect_gitignore`: off by default, because `.gitignore` often lists files, such as `.env` and key files, that a sensitive-data scan should see.
- `ferret_debug` and `ferret_verbose`: ferret-scan's own debug and verbose output.

Some option names are refused because they conflict with how ASH runs the tool: `format`, `output_format`, `debug`, `verbose`, `web`, `port`, `enable_redaction`, `redaction_output_dir`, `redaction_strategy`, `redaction_audit_log`, `memory_scrub`, `generate_suppressions`, `show_suppressed`, `suppressions_file`, `extract_text`, `preprocess_only`, `pre_commit_mode` and `list_profiles`. A config that sets one makes the scanner fail to start: it is reported ERROR, with the reason in the log, and the scan exits with code 1. Use ASH's own [suppressions](../../../how-to/suppress-findings.md) and [reports](../../../how-to/export-reports.md) for what those options do in ferret-scan.

## The ferret-scan config file

ASH passes ferret-scan one config file: the file `config_file` names, when that file is outside every git checkout and the scanned directory; otherwise the `ferret-config.yaml` bundled with the plugin. With `use_default_config: false` and no usable `config_file`, ferret-scan uses its built-in defaults instead.

A config file in the scanned repository is never passed to ferret-scan, whether `config_file` names it or ASH finds it by name (`ferret.yaml`, `ferret.yml`, `.ferret.yaml`, `.ferret.yml`, `.ash/ferret.yaml` or `.ash/ferret-scan.yaml`). ASH logs a warning and uses the bundled config. To use your own, keep it outside the repository and name it with `config_file`.

## Matched values in the output

With `show_match: true`, ferret-scan includes the matched text (the card number, the key) in its findings, so it reaches the SARIF files, the other reports and the logs; ASH logs a warning when the option is on. It is off by default. Several profiles in the bundled config set `show_match: true`: `comprehensive`, `debug`, `enhanced-metadata`, `json-api`, `person-name` and `social-media`. Treat a scan with one of those profiles as one with `show_match: true`, and do not use them where the reports are uploaded or shared.

## Network

None. ferret-scan reads only the files it is given, and works the same in offline mode.
