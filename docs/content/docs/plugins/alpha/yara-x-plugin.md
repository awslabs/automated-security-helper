# YARA-X Plugin

[YARA-X](https://virustotal.github.io/yara-x/) is VirusTotal's Rust rewrite of YARA, a pattern matching engine for files. ASH runs it as `yr scan` over the scan target with a rule set you supply, and reports each rule that matches a file. YARA-X ships no rules of its own, so this plugin is bring-your-own-rules: until you configure a rules path it does nothing. ASH pins v1.23.0. The scanner's name is `yara-x`.

## Enabling it

YARA-X is an alpha plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_yara_x_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_yara_x_plugins
```

With the module listed, `yara-x` is on by default, like every other scanner, but it only scans once `rules_path` is set (see below). `scanners.yara-x.enabled: false` turns it off, and `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners yara-x` without the module listed is refused, with a message naming the module to add. If the tool is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate).

## Installing YARA-X

ASH pins YARA-X v1.23.0 in the plugin's own install module (`ash_yara_x_plugins/yara_x_install.py`: the version, one release asset per platform, a SHA256 for each archive and for the `yr` executable inside it). Linux and macOS on x86_64 and arm64, and Windows on x86_64, are supported; the release publishes no Windows arm64 build. Install it with:

<!-- doctest: illustrative reason="downloads a release binary" -->
```bash
ash dependencies install --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_yara_x_plugins"]' --tool yara-x
```

A download that does not hash to its pin is refused. If `yr` is already on `PATH`, ASH uses it. The ASH container image installs it the same way.

## The rules gate

YARA-X has no built-in rules, so the scanner needs yours:

```yaml
scanners:
  yara-x:
    options:
      rules_path: /etc/ash/yara-rules
```

`rules_path` is one `.yar` or `.yara` file, or a directory searched recursively for them. It is an operator-only option: it is used only when you set it with `--config-overrides` or in an ASH config file outside every git checkout and the scanned directory. Set from a config inside the scanned tree it is ignored with a warning. The rules may sit inside the scanned tree if you set the path yourself.

With no usable `rules_path`, ASH does not start `yr`. It logs at INFO that no rule set is configured, and the scanner reports that nothing was scanned instead of a pass. A `rules_path` you set that does not exist fails the scan, because a run with no rules would report a scan that checked nothing. A path that contains a colon (other than a Windows drive letter) is refused, because `yr` reads `NAME:PATH` as a namespace and a path.

## What is scanned

`yr scan --recursive` walks the target and reads every file. A match is reported at the file: ASH does not pass `yr scan --print-strings`, so no match offset or matched bytes are in the report, and a finding has no line number. ASH's own output directory sits inside the source tree by default; ASH drops every result under it, and drops results under `ignore_paths`. Ignoring a path does not stop `yr` from reading it.

`yr` reads no configuration from the scanned tree and makes no network call. ASH never passes `yr scan --scan-list`, `yr scan --module-data`, `yr scan --compiled-rules` or `yr scan --include-dir`.

`yr scan --recursive` follows no symbolic link. A link to a file is not read and a link to a directory is not descended, wherever the link points, so nothing outside the scanned directory is read through a link, and a file reached only through a link inside the tree is not scanned either.

## Configuration

```yaml
scanners:
  yara-x:
    enabled: true
    options:
      # A .yar/.yara file or a directory of them. Operator only. Unset, the scanner
      # is a no-op that logs at INFO.
      rules_path: null
      # Seconds for the whole scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override: ALL, LOW, MEDIUM, HIGH,
      # CRITICAL, or null for the global threshold.
      severity_threshold: null
```

## Severity

YARA has no severity of its own, so ASH reads the rule's `severity` metadata, case-insensitively:

```text
rule suspicious_loader {
    meta:
        severity = "high"
        description = "Matches the loader stub"
    strings:
        $a = "FAKE_MARKER_VALUE"
    condition:
        $a
}
```

| `severity` metadata | ASH severity | SARIF level |
|---|---|---|
| `critical` | CRITICAL | `error` |
| `high` | HIGH | `error` |
| `medium` | MEDIUM | `warning` |
| `low` | LOW | `note` |
| `info` | INFO | `none` |
| none | INFO | `none` |
| any other value | MEDIUM | `warning` |

A rule that does not say it matters is INFO. A value the scanner does not recognize is MEDIUM, so a rule author's intent is reported rather than rated as informational. The rule's `description` metadata is the finding's message, and the rule's tags are carried on the result. With ASH's default `severity_threshold` of `MEDIUM`, only rules that say `medium` or above fail the scan.

## Suppressions

ASH suppressions by rule, path and line work as for any scanner:

```yaml
global_settings:
  suppressions:
    - rule_id: suspicious_loader
      path: tests/fixtures/loader.bin
      reason: a test fixture, not a real loader
```

Package-scoped and symbol-scoped suppressions do not apply: no YARA-X finding names a package or a symbol. A finding has no line, so a `line_start` does not match it.

## Exit status and failures

`yr scan` exits 0 whether or not a rule matched, and 1 when it cannot go on (a rules path that does not open, a rule that does not compile). So 0 is the only accepted code, and any other fails the scan. Output that is not newline-delimited JSON of the expected shape fails the scan rather than reading as clean. A file `yr` could not read is reported on its standard error and the scan continues with exit 0; ASH does not see it.

## Offline and air-gapped use

Rules are read from disk and `yr scan` makes no network call, so it behaves the same offline. Install it before going offline.

## License

YARA-X is BSD-3-Clause licensed. The ASH container image redistributes the pinned release binary, so it carries the repository `LICENSE` at the pinned commit beside it (the `yara-x` entry in `THIRD_PARTY_LICENSES`; the release archives hold the executable alone). Nothing of YARA-X is shipped in the ASH Python package itself.
