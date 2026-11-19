# CredSweeper plugin

Runs [CredSweeper](https://github.com/Samsung/CredSweeper) (MIT) over the scan target and reports the credentials it finds. CredSweeper matches candidates with rules and scores each one with a small machine-learning model, so every finding carries a confidence and an ML probability.

## Enabling it

The module is an opt-in. List it in `ash_plugin_modules`; a scan that does not list it is unchanged.

```yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_credsweeper_plugins
```

Once listed, the scanner is enabled. To turn it off while keeping the module listed, set `scanners.credsweeper.enabled: false`.

## Installing CredSweeper

CredSweeper is a Python tool and ASH installs it with uv:

```bash
ash dependencies install --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_credsweeper_plugins"]' --tool credsweeper
```

The default constraint is `>=1.19.6,<2.0.0`, installed into Python `>=3.11,<3.14`. Set `scanners.credsweeper.options.tool_version` to change the constraint. The scanner needs uv, or a `credsweeper` already on `PATH`.

## Configuration

```yaml
scanners:
  credsweeper:
    enabled: true
    options:
      tool_version: ">=1.19.6,<2.0.0"
      install_timeout: 300
      scan_timeout: 1800
```

CredSweeper's own config, rules, ML threshold and ignore handling are not exposed: each reads from, or can hide findings in, the scanned tree. Tune findings with ASH suppressions.

## Severity

| CredSweeper confidence | ASH severity | SARIF level |
|---|---|---|
| strong | HIGH | error |
| moderate | MEDIUM | warning |
| weak | LOW | note |

An unreadable or unknown confidence is rated HIGH. The rule's own severity and the ML probability are kept as result properties. The credential text is never copied into the report.

## Documentation

See <https://awslabs.github.io/automated-security-helper/docs/plugins/community/credsweeper-plugin/>.
