# YARA-X (community plugin)

[YARA-X](https://virustotal.github.io/yara-x/) is VirusTotal's Rust rewrite of YARA, a pattern matching engine for files. ASH runs it as `yr scan` over the scan target with a rule set you supply, and reports each rule that matches a file. YARA-X ships no rules of its own, so this plugin is bring-your-own-rules: until you configure a rules path it does nothing. ASH pins v1.23.0.

## Enabling it

YARA-X is a community plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

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

With the module listed, `yara_x` is on by default, like every other scanner, but it only scans once `rules_path` is set (see below). `scanners.yara_x.enabled: false` turns it off, and `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners yara_x` without the module listed is refused, with a message naming the module to add. If the tool is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate).

## Installing YARA-X

- **Container mode:** the ASH image includes YARA-X v1.23.0.
- **Local mode:** `ash dependencies install --tool yara_x`, with the module listed in `ash_plugin_modules` (or added with `--config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_yara_x_plugins"]'`), downloads the pinned v1.23.0 release archive from GitHub and verifies it against the SHA256 digest pinned in ASH, and the `yr` executable inside it against a second pinned digest, before installing it. Linux and macOS on x86_64 and arm64, and Windows on x86_64, are supported.
- Any `yr` already on `PATH` is also used.

## The rules gate

YARA-X has no built-in rules, so the scanner needs yours:

```yaml
scanners:
  yara_x:
    options:
      rules_path: /etc/ash/yara-rules
```

`rules_path` is one `.yar` or `.yara` file, or a directory searched recursively for them. It is an operator-only option: it is used only when you set it with `--config-overrides` or in an ASH config file outside every git checkout and the scanned directory. Set from a config inside the scanned tree it is ignored with a warning. The rules may sit inside the scanned tree if you set the path yourself.

With no usable `rules_path`, ASH does not start `yr`. It logs at INFO that no rule set is configured, and the scanner reports that nothing was scanned instead of a pass. A `rules_path` you set that does not exist fails the scan, because a run with no rules would report a scan that checked nothing. A path that contains a colon (other than a Windows drive letter) is refused, because `yr` reads `NAME:PATH` as a namespace and a path.

## What is scanned

`yr scan --recursive` walks the target and reads every file. A match is reported at the file: ASH does not pass `--print-strings`, so no match offset or matched bytes are in the report, and a finding has no line number. ASH's own output directory sits inside the source tree by default; ASH drops every result under it, and drops results under `ignore_paths`. Ignoring a path does not stop `yr` from reading it.

`yr` reads no configuration from the scanned tree and makes no network call. ASH never passes `--scan-list`, `--module-data`, `--compiled-rules` or `--include-dir`.

## Configuration

```yaml
scanners:
  yara_x:
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

YARA-X is BSD-3-Clause licensed. The ASH container image includes the unmodified binary, and its license is in the image at `/usr/share/doc/ash/third-party/yara_x/`, installed the same way as every other bundled tool's (see [Third-party license files](../../../how-to/run-in-a-container.md#third-party-licenses)).
