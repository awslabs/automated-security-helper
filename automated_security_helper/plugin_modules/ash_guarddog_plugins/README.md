# ASH GuardDog Plugin

[GuardDog](https://github.com/DataDog/guarddog) (Apache-2.0, by Datadog) looks for the
shapes malicious packages take: an install hook that downloads and runs a script,
`exec` of a base64-decoded payload, obfuscated JavaScript, exfiltration to a raw IP
address, and similar. Its YARA rules ship inside the GuardDog package, so scanning
local source needs no network.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. A scan that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_guarddog_plugins
```

or, for one run:

```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_guarddog_plugins
```

With the module listed, `guarddog` runs by default. `scanners.guarddog.enabled: false` turns it off again.

## Installing the tool

The ASH container image includes it. Locally:

```bash
ash dependencies install --config-overrides "ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_guarddog_plugins]" --tool guarddog
```

## Configuration

```yaml
scanners:
  guarddog:
    enabled: true               # once the module is listed; false turns it off
    options:
      ecosystems: [pypi, npm, go, github_action, rubygems, crates]
      verify: false             # downloads dependencies; refused offline
      verify_timeout: 600       # seconds per manifest
      verify_parallelism: 8     # GUARDDOG_PARALLELISM for verify
      sandbox: auto             # auto | required | disabled
      rules: []                 # run only these rules
      exclude_rules: []         # or skip these
      include_capabilities: false
      excluded_paths: []        # [{path: "vendor/**", reason: "..."}]
      scan_timeout: 1800        # seconds per package root
      tool_version: null        # default "==3.2.0"
      install_timeout: 300
```

## Documentation

Severity mapping, suppressions, offline use and every option: [docs/content/docs/plugins/community/guarddog-plugin.md](../../../docs/content/docs/plugins/community/guarddog-plugin.md).
