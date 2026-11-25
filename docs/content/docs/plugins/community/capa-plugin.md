# capa (community plugin)

[capa](https://github.com/mandiant/capa) detects what a compiled program is able to do. It matches a rule set against the functions of a PE or ELF file and reports capabilities such as "create a process", "encrypt data using RC4" or "persist via a Run key", with the MITRE ATT&CK and Malware Behavior Catalog (MBC) techniques each one maps to. capa is licensed under Apache-2.0.

## Enabling it

capa is a community plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_capa_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_capa_plugins
```

With the module listed, `capa` runs by default, like every other scanner. `scanners.capa.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners capa` without the module listed is refused, with a message naming the module to add. If the tool is not installed, the scanner is reported `MISSING` and the scan exits 1.

## Installing capa

- **Container mode:** the ASH image includes capa v10.0.0.
- **Local mode:** `ash dependencies install --tool capa`, with the module listed in `ash_plugin_modules`, downloads the pinned v10.0.0 standalone release from GitHub and verifies its SHA256 digest before installing it. Linux (x86_64 and arm64), macOS (x86_64 and arm64) and Windows x86_64 are supported.
- **Nix mode:** the flake does not supply capa.
- Any `capa` already on `PATH` is also used.

## What is scanned

Files whose first bytes are a PE (`MZ`) or ELF (`\x7fELF`) header, taken from ASH's scan set, so `.gitignore`, `.ignore` and `global_settings.ignore_paths` apply first. capa analyzes one file per run, so ASH starts one `capa -q -j -- <file>` process per executable. A file over 256 MiB is skipped with a warning, and a link that resolves outside the source directory is skipped.

Shellcode and sandbox reports, which capa can also read, are not selected: neither has a header ASH can recognize. If the tree has no PE or ELF file, capa is not run and the scanner reports `SKIPPED`.

A file capa could not analyze (corrupt, packed, an unsupported architecture or OS) is reported as an unevaluated target, not as a finding, and the scan is incomplete. capa's own messages are kept in its log and are not copied into the scan's errors, because they can quote the analyzed file.

capa runs with its embedded rules and signatures. ASH passes no rule or signature path, so a rule file in the scanned tree is never read.

## Configuration

capa has no options of its own.

<!-- doctest: config kind=other reason="shows the scanner section; only the base options apply" -->
```yaml
scanners:
  capa:
    enabled: true
    options:
      # Seconds for the whole capa scan (default 1800; null for no limit).
      scan_timeout: 1800
```

## Severity

capa reports capabilities, not defects. A program that can create a process, read the registry or open a socket is ordinary; the report tells you what to look at, not what is wrong. So the plugin never rates a result above `LOW`:

| capa rule | ASH severity | SARIF level |
|---|---|---|
| maps to an ATT&CK or MBC technique | `LOW` | `note` |
| has no ATT&CK or MBC mapping | `INFO` | `none` |

The result's rule id and message carry the capability name, its namespace, the number of matches and the technique ids; the first few match addresses are in the result properties. Because a binary has no source line, each result is located at line 1 of the file. capa's library rules and sub-scope rules are building blocks for other rules and are not reported.

Use [ASH suppressions](../../../concepts/suppressions.md) by rule id (the capability name) and path to silence a capability you expect.

## Offline and air-gapped use

capa's rules and signatures are embedded in the standalone release, so a scan makes no network call.

## License

capa is Apache-2.0. The container image's third-party notices are described in [Third-party licenses](../../../how-to/run-in-a-container.md#third-party-licenses).
