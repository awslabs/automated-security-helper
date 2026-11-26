# gosec (community plugin)

[gosec](https://github.com/securego/gosec) inspects Go source for security problems:
hard-coded credentials, unhandled errors, weak cryptography, file and command
injection patterns, unsafe use of `net`, `os` and `unsafe`, and similar. Each issue
carries a gosec rule id (`G101`, `G104`, `G304` and so on), a severity and a CWE.

## Enabling it

gosec is a community plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_gosec_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_gosec_plugins
```

With the module listed, `gosec` runs by default, like every other scanner. `scanners.gosec.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners gosec` without the module listed is refused, with a message naming the module to add. If gosec or the Go toolchain is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate).

There is no license or service gate. gosec is Apache-2.0 and runs on the host, and the plugin sends nothing off it.

## Installing gosec

gosec needs the `gosec` binary and the Go toolchain (`go`) on `PATH`. gosec loads packages through `go`, and it fails without it.

- **Local mode:** `ash dependencies install --tool gosec`, with the module listed in `ash_plugin_modules` (or added with `--config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_gosec_plugins"]'`), downloads the pinned gosec v2.30.0 release archive from GitHub and verifies it against the SHA256 digest pinned in ASH. Linux, macOS and Windows on x86_64 and arm64 are supported. It does not install Go.
- **Container mode:** the image includes gosec only when the image build installs it; install the Go toolchain in a derived image, or use local mode.
- Any `gosec` already on `PATH` is also used.

## What is scanned

gosec is run from the source directory over `./...`, so it scans the Go packages of the module there. The project needs a `go.mod`, and its module dependencies must already be in the local module cache or a `vendor/` directory: ASH does not run `go mod download`, and gosec makes no network call of its own. If packages fail to load, gosec exits 1 with no findings, and ASH fails the scan with a message saying so; it is never reported as a clean scan.

Test files (`_test.go`) are skipped unless `include_tests` is on. ASH's ignore files and `global_settings.ignore_paths` apply to the findings after the scan, and results under ASH's own output directory are dropped.

## Configuration

<!-- doctest: config kind=other reason="community plugin options, valid only with the module listed" -->
```yaml
scanners:
  gosec:
    enabled: true
    options:
      include_tests: false   # also scan _test.go files (gosec -tests)
```

ASH runs `gosec -fmt=sarif -out=<report> -nosec=true -- ./...`. `-nosec=true` makes gosec ignore `#nosec` comments, so every finding reaches ASH and suppressions are reported and counted there. gosec's own config file (`-conf`) is never passed.

## Severity

gosec rates each issue LOW, MEDIUM or HIGH. ASH reports the same rating and sets the SARIF level to match:

| gosec severity | ASH severity | SARIF level |
|---|---|---|
| HIGH | HIGH | error |
| MEDIUM | MEDIUM | warning |
| LOW | LOW | note |

gosec writes the SARIF level `error` for both MEDIUM and HIGH and `warning` for LOW, and puts the severity word on the rule's tags. ASH reads that tag to separate MEDIUM from HIGH. Where gosec's `error` cannot be resolved (the rule's tag says LOW), ASH rates the result HIGH, the more severe reading. gosec's confidence does not change the severity. The rating is HIGH and not CRITICAL because these are static-analysis findings whose impact depends on context.

## Suppressions

Suppress a finding with an ASH suppression by rule id, path and line:

<!-- doctest: config kind=other reason="community plugin suppression example" -->
```yaml
global_settings:
  suppressions:
    - rule_id: G304
      path: pkg/util.go
      line_start: 20
      line_end: 20
      reason: The path comes from a trusted, validated configuration value.
```

`#nosec` comments in the code do not hide findings from ASH, because the scan runs with `-nosec=true`. Package-scoped and symbol-scoped suppressions do not apply.

## Offline and air-gapped use

gosec itself needs no network. Go module resolution does: with a cold module cache and no network the packages do not load and the scan fails. Populate the module cache or a `vendor/` directory before an offline scan.

## License

gosec is Apache-2.0. See [third-party licenses](../../../how-to/run-in-a-container.md#third-party-licenses).
