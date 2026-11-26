# capa Plugin

[capa](https://github.com/mandiant/capa) detects what a compiled program is able to do. It matches a rule set against the functions of a PE or ELF file and reports capabilities such as "create a process", "encrypt data using RC4" or "persist via a Run key", with the MITRE ATT&CK and Malware Behavior Catalog (MBC) techniques each one maps to. capa is licensed under Apache-2.0.

## Enabling

capa is an alpha plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_capa_plugins
```

With the module listed, `capa` runs by default. `scanners.capa.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. If the tool is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate).

## Installing capa

ASH pins capa v10.0.0 in the plugin's own install module (`ash_capa_plugins/capa_install.py`: the version, one standalone release asset per platform, a SHA256 for each archive and for the executable inside it). Install it with:

<!-- doctest: illustrative reason="downloads a release binary" -->
```bash
ash dependencies install --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_capa_plugins"]' --tool capa
```

A download that does not hash to its pin is refused. Linux (x86_64 and arm64), macOS (x86_64 and arm64) and Windows x86_64 are covered.

- **Linux needs glibc 2.38 or newer.** Every Linux build of the v10.0.0 release unpacks a Python library that requires glibc 2.38, so on an older glibc (Amazon Linux 2023 has 2.34 and Debian 12 has 2.36) the executable exits 255 naming `GLIBC_2.38` and every file is reported as not analyzed. `ash dependencies install` warns when it installs capa on such a host.
- **Container and Nix modes do not supply capa.** The ASH container image is built on Debian bookworm, whose glibc is 2.36, so the image does not carry it.
- Any `capa` already on `PATH` is also used. A capa installed from PyPI (`flare-capa`) has no embedded rules: it exits 10 ("default embedded rules not found") on every file, and ASH passes no rule path, so use the standalone release.

## What is scanned

Files whose first bytes are a PE (`MZ`) or ELF (`\x7fELF`) header, taken from ASH's scan set, so `.gitignore`, `.ignore` and `global_settings.ignore_paths` apply first. capa analyzes one file per run, so ASH starts one `capa -q -j -- <file>` process per executable. A file over 256 MiB is skipped with a warning, and a link that resolves outside the source directory is skipped.

Shellcode and sandbox reports, which capa can also read, are not selected: neither has a header ASH can recognize. If the tree has no PE or ELF file, capa is not run.

A file capa could not analyze (corrupt, packed, an unsupported architecture or OS) is reported as an unevaluated target, not as a finding, and the scan is incomplete. capa's own messages are kept in its log and are not copied into the scan's errors, because they can quote the analyzed file.

capa runs with its embedded rules and signatures. ASH passes no rule or signature path, so a rule file in the scanned tree is never read.

## Configuration

capa has no options of its own, only the shared ones (`severity_threshold`, `scan_timeout`, `offline`).

<!-- doctest: config kind=other reason="alpha plugin options, valid only with the module listed" -->
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

## Offline use

capa's rules and signatures are embedded in the standalone release, so a scan makes no network call. Install the tool before going offline.

## License

capa is Apache-2.0 licensed. ASH downloads the release when you install it and never vendors it; nothing of capa is shipped in the ASH Python package or the ASH container image.
