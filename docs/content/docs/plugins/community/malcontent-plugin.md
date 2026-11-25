# Malcontent (community plugin)

[Malcontent](https://github.com/chainguard-dev/malcontent) discovers supply-chain compromise in programs, scripts and archives. ASH runs `mal analyze` over the scan target. It matches more than 14,500 embedded YARA-X rules and reports each capability it finds with a risk level. Its authors say `CRITICAL` findings "should be considered malicious" and that `analyze` is paranoid, so expect false positives. Malcontent is Apache-2.0 licensed.

## Enabling it

Malcontent is a community plugin that ships with ASH. Its module is loaded only when you list it, so an `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_malcontent_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_malcontent_plugins
```

With the module listed, `malcontent` runs by default. `scanners.malcontent.enabled: false` turns it off, and `--scanners` and `--exclude-scanners` select it like any scanner. `--scanners malcontent` without the module listed is refused with a message naming the module to add. If the binary is not installed, the scanner is reported `MISSING`.

## Installing Malcontent

Malcontent publishes no release binaries. Its GitHub releases (v1.28.2 and earlier) have no assets, so ASH has nothing to pin and checksum, and `ash dependencies install` has nothing to install for it. Put `mal` (or `malcontent`) on `PATH` yourself:

- build it from source, which needs Go and Rust: `make install-yara-x`, then `make out/mal`; or
- base your scan image on `cgr.dev/chainguard/malcontent:latest`.

The ASH container image does not include Malcontent.

## What is scanned

ASH runs this from the source directory, so paths in the report are source-relative:

<!-- doctest: illustrative reason="shows the argv ASH builds; the placeholders are not runnable" -->
```text
mal --format=json --output=<results>/<target>/malcontent.json --min-risk=low --third-party=false --ignore-self analyze -- .
```

Malcontent walks the path itself and decides which files are programs. ASH converts the JSON report to SARIF: one result per behavior, located at its file with no line number, because Malcontent reports no line numbers, so findings are file-level. The text Malcontent matched in your files is never copied into the report. ASH drops results under its own output directory.

Always passed: `--third-party=false`. Malcontent includes its third-party rules, which may have licensing restrictions, unless the flag is turned off, so ASH turns it off and only Malcontent's own rules run.

Never passed: `--image`, `--processes`, `--oci-auth`, `--exit-first-hit` and `--exit-first-miss`. The scan makes no network calls.

Malcontent exits 0 when it ran. Any other exit status fails the scan, even if a report was written, as does a report that is not a JSON object.

## Configuration

```yaml
scanners:
  malcontent:
    enabled: true
    options:
      # Seconds for the whole Malcontent scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override: ALL, LOW, MEDIUM, HIGH,
      # CRITICAL, or null for the global threshold.
      severity_threshold: null
```

Malcontent has no options of its own in ASH, and nothing in the scanned tree can change what it runs.

## Severity

Malcontent lists capabilities, which legitimate programs have too, so the low end is informational, as with capa. `issue_severity` and the SARIF level agree.

| Malcontent risk | ASH severity | SARIF level |
|---|---|---|
| critical | CRITICAL | error |
| high | HIGH | error |
| medium | MEDIUM | warning |
| low, harmless | INFO | none |
| any other value | HIGH | error |

An unrecognized level is rated HIGH so it is not hidden under the default threshold.

## Suppressions

ASH suppressions by rule and path work as for any scanner. Findings are file-level, so a suppression with a line range never matches a Malcontent finding; leave `line_start` and `line_end` out. The rule ID is the Malcontent behavior ID.

```yaml
global_settings:
  suppressions:
    - rule_id: net/socket/connect
      path: tools/healthcheck.py
      reason: a documented health check, not a callback
```

Package-scoped and symbol-scoped suppressions do not apply.

## Offline and air-gapped use

The rules are embedded in the binary, so Malcontent behaves the same offline.

## License

Malcontent is Apache-2.0 licensed. ASH does not redistribute it.
