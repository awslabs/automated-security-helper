# capa (community plugin)

[capa](https://github.com/mandiant/capa) (Apache-2.0) detects what a compiled
program is able to do: "create a process", "encrypt data using RC4", "persist via a
Run key". The plugin runs it over the PE and ELF files in the scan and reports each
capability as a result.

These are capabilities, not vulnerabilities. Most legitimate programs have many.
Every result is therefore `LOW` (SARIF `note`) when capa maps the rule to an ATT&CK
or MBC technique, and `INFO` (SARIF `none`) when it does not. Nothing is rated higher.

## Enabling

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_capa_plugins
```

With the module listed, `capa` runs by default. `scanners.capa.enabled: false` turns it
off. A scan that does not list the module is unchanged.

## Installing

`ash dependencies install --tool capa` (with the module listed) downloads the pinned
capa v10.0.0 standalone release and verifies its digest. Any `capa` already on `PATH`
is also used.

## What is scanned

Files whose first bytes are a PE (`MZ`) or ELF (`\x7fELF`) header, from ASH's scan
set, one capa run per file. Shellcode and sandbox reports, which capa also accepts, are
not selected. A file capa cannot analyze (corrupt, packed, unsupported architecture) is
a failed target, not a finding, and the scan is reported incomplete.

capa uses its embedded rules and signatures, so no network is needed and no rule file
in the scanned tree is read.

## Configuration

capa has no options of its own. `scan_timeout` (default 1800 seconds, for the whole
scan) comes from the base options.

## Documentation

<https://awslabs.github.io/automated-security-helper/docs/plugins/community/capa-plugin/>
