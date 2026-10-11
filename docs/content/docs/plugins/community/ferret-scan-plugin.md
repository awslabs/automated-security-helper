# Ferret Scan plugin (`ferret-scan`)

The `ferret-scan` scanner runs [Ferret Scan](https://github.com/awslabs/ferret-scan), which looks for sensitive data in files: credit card numbers, passport numbers, Social Security numbers, API keys and other secrets, email addresses, phone numbers, and more. With its preprocessors on (the default), it also extracts text from documents such as PDF and Office files and scans that. It complements detect-secrets, which looks only for credentials. It is a [community plugin](index.md): it ships with ASH, and `ash scan` runs it only when its module is loaded.

## Install Ferret Scan

The plugin supports ferret-scan `>=2.4.5,<2.6.0` and runs the first `ferret-scan` command it finds: on `PATH`, then in ASH's bin directory (`~/.ash/bin`, or the directory `ASH_BIN_PATH` names), then in `/usr/local/bin`. ASH does not install it during a scan, and the container image does not include it.

To install it with ASH, run the command below. It runs `pip install 'ferret-scan>=2.4.5,<2.6.0'` with the Python that runs ASH. That fails when the environment has no pip, as in one uv created. ASH also finds the installed `ferret-scan` only when that environment's bin directory is on `PATH`, as in an activated virtual environment.

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

ferret-scan's SARIF is in `.ash/ash_output/scanners/ferret-scan/source/ferret-scan.sarif`, and its findings are in the finding reports under `.ash/ash_output/reports/`, such as `ash.sarif`, `ash.html`, and `ash.csv`.

## Options

The full list, with types and defaults, is in the [scanner reference](../../../reference/scanners.md#ferret-scan). The ones you are most likely to set:

<!-- doctest: options of=scanners.ferret-scan -->
| Option | Default | Effect |
|---|---|---|
| `confidence_levels` | `all` | the confidence levels to report: `high`, `medium`, `low`, a pair such as `high,medium`, or `all` |
| `checks` | `all` | a comma-separated list of ferret-scan's checks, such as `CREDIT_CARD,SECRETS`; `ferret-scan --help checks` lists the checks of the installed version |
| `exclude_patterns` | `[]` | glob patterns ferret-scan skips; ASH's `ignore_paths` are passed to ferret-scan as excludes too |
| `profile` | `null` | a profile from the ferret-scan config, such as `quick`, `ci`, or `security-audit` |
| `finding_limit` | `0` | the most findings ferret-scan reports; 0 means no limit, where ferret-scan's own default of 200 would cut off large scans |
| `respect_gitignore` | `false` | skip what `.gitignore` lists; off because `.gitignore` often lists files, such as `.env` and key files, that a sensitive-data scan should see |
| `show_match` | `false` | include the matched text in findings ([below](#matched-values-in-the-output)) |
| `config_file` | `null` | a ferret-scan config file ([below](#the-ferret-scan-config-file)) |
| `use_default_config` | `true` | use the config bundled with the plugin when `config_file` is unset |
| `ferret_debug` | `false` | ferret-scan's own debug output |
| `ferret_verbose` | `false` | ferret-scan's own verbose output |

Some option names are refused because they conflict with how ASH runs the tool: `format`, `output_format`, `debug`, `verbose`, `web`, `port`, `enable_redaction`, `redaction_output_dir`, `redaction_strategy`, `redaction_audit_log`, `memory_scrub`, `generate_suppressions`, `show_suppressed`, `suppressions_file`, `extract_text`, `preprocess_only`, `pre_commit_mode`, and `list_profiles`. A config that sets one makes the scanner fail to start: it is reported ERROR, with the reason in the log, and the scan exits with code 1. Use ASH's own [suppressions](../../../how-to/suppress-findings.md) and [reports](../../../how-to/export-reports.md) for what those options do in ferret-scan.

## The ferret-scan config file

ASH passes ferret-scan one config file. With `config_file` unset, that is the `ferret-config.yaml` bundled with the plugin. If `config_file` names a file outside every git checkout and the scanned directory, ASH passes that file. If it names a file inside one, ASH logs a warning and passes the bundled config. If it names a file that does not exist, ASH logs a warning and passes an empty config, so ferret-scan uses its built-in defaults. With `use_default_config: false`, an empty config takes the place of the bundled one.

A config file that the scanned repository carries under one of the names ferret-scan looks for (`ferret.yaml`, `ferret.yml`, `.ferret.yaml`, `.ferret.yml`, `.ash/ferret.yaml`, or `.ash/ferret-scan.yaml`) is not passed to ferret-scan either; ASH logs a warning and uses the bundled config. To use your own config, keep it outside the repository and name it with `config_file`.

## Matched values in the output

With `show_match: true`, ferret-scan includes the matched text (the card number, the key) in its findings, so it reaches the SARIF files, the other reports, and the logs; ASH logs a warning when the option is on. It is off by default. Several profiles in the bundled config set `show_match: true`: `comprehensive`, `debug`, `enhanced-metadata`, `json-api`, `person-name`, and `social-media`. Treat a scan with one of those profiles as one with `show_match: true`, and do not use them where the reports are uploaded or shared.

## Network

None. ferret-scan reads only the files it is given, and works the same in offline mode.
