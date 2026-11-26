# capa alpha scanner plugin

[capa](https://github.com/mandiant/capa) (Apache-2.0) detects what a compiled
program is able to do: "create a process", "encrypt data using RC4", "persist via a
Run key". The plugin runs it over the PE and ELF files in the scan and reports each
capability as a result.

These are capabilities, not vulnerabilities. Most legitimate programs have many.
Every result is therefore `LOW` (SARIF `note`) when capa maps the rule to an ATT&CK
or MBC technique, and `INFO` (SARIF `none`) when it does not. Nothing is rated higher.

## Enabling

The scanner is on once its module is listed:

```yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_capa_plugins
```

`scanners.capa.enabled: false` turns it off again. A scan that does not list the
module is unchanged. There is no license or service gate.

## Installing

```bash
ash dependencies install --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_capa_plugins"]' --tool capa
```

This installs the pinned capa v10.0.0 standalone release and verifies the SHA256 of
the archive and of the executable inside it. Linux (x86_64 and arm64), macOS (x86_64
and arm64) and Windows x86_64 are covered. The Linux builds need glibc 2.38 or newer,
so the ASH container image (Debian bookworm, glibc 2.36) does not carry capa. Any
`capa` already on `PATH` is also used; a capa installed from PyPI has no embedded
rules and exits 10 on every file.

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

See <https://awslabs.github.io/automated-security-helper/docs/plugins/alpha/capa-plugin/>.
