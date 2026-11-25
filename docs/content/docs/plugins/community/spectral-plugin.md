# Spectral (community plugin)

[Spectral](https://github.com/stoplightio/spectral) lints OpenAPI, Swagger and AsyncAPI descriptions. ASH runs it as `spectral lint` over the JSON and YAML files in the scan target, with Spectral's recommended rulesets, and reads the SARIF it writes. It finds defects in an API description: a missing `operationId`, a path parameter the operation does not define, a `$ref` that does not resolve, no `servers`. ASH pins Spectral v6.17.1.

## Enabling it

Spectral is a community plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_spectral_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_spectral_plugins
```

With the module listed, `spectral` runs by default, like every other scanner. `scanners.spectral.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners spectral` without the module listed is refused, with a message naming the module to add. If the tool is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate).

Spectral needs no account, license key or network service, so there is no opt-in beyond listing the module.

## Installing Spectral

ASH does not download or bundle Spectral yet: `utils/tool_downloads.py` has no `spectral` row. Install the binary from the [Spectral releases](https://github.com/stoplightio/spectral/releases) (the scanner was measured on v6.17.1, linux x64) and put it on `PATH`. Spectral publishes linux and macOS binaries for x86_64 and arm64 and Windows for x86_64, none for Windows arm64. Without the binary the scanner is reported `MISSING`. Once a pinned row lands, `ash dependencies install --tool spectral` will download the release binary and verify its SHA256 digest.

## What is scanned

ASH hands Spectral the glob `**/*.{json,yaml,yml}` under the scan target. Spectral skips a file that is not an OpenAPI, Swagger or AsyncAPI description (`spectral lint --ignore-unknown-format`), so ordinary JSON and YAML files produce nothing. The glob does not descend into dot-directories. A target with no JSON or YAML file at all is reported as skipped, not failed.

ASH's own rules for the run:

- It always passes `--ruleset`. Without it Spectral would read a `.spectral.yaml`, `.spectral.json` or `.spectral.js` from the scanned tree, and a JavaScript ruleset is code. A ruleset in the tree is never read.
- The default ruleset extends `spectral:oas` and `spectral:asyncapi`, Spectral's recommended rulesets.
- It passes `--fail-severity=hint`, so Spectral exits 1 whenever it reports anything, and uses its SARIF levels, not its exit status, for severity.
- It does not pass the documents after `--`: Spectral then lints nothing and reads standard input.

Spectral resolves `$ref` pointers while it lints and has no flag that turns this off. A description in the scanned tree can point at a remote URL or at a file outside the tree. Under `--sandbox` the scanner has no network and cannot read outside the tree, so such a reference is reported as an unresolved reference (`invalid-ref`); without the sandbox Spectral fetches or reads it.

## Configuration

```yaml
scanners:
  spectral:
    enabled: true
    options:
      # A Spectral ruleset (YAML, JSON or JavaScript) used in place of ASH's
      # default. Operator only: honored when set with --config-overrides or an ASH
      # config file outside every git checkout and the scanned tree, and naming a
      # file outside the scanned tree (a JavaScript ruleset is code). Set by such a
      # config, or naming a file inside the tree, it is ignored with a warning. A
      # path that does not exist fails the scan.
      ruleset_file: null
      # Seconds for the whole Spectral scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override: ALL, LOW, MEDIUM, HIGH,
      # CRITICAL, or null for the global threshold.
      severity_threshold: null
```

<!-- doctest: config kind=other reason="a Spectral ruleset file, not an ASH config" -->
```yaml
# my-ruleset.yaml, given to scanners.spectral.options.ruleset_file
extends: ["spectral:oas"]
rules:
  info-contact: off
```

## Severity

Spectral's SARIF has three levels: `error`, `warning`, and `note` (its info and hint severities both). Every result is rated by its level, and the SARIF level is set to agree:

| Spectral level | ASH severity | SARIF level |
|---|---|---|
| `error` | HIGH | `error` |
| `warning` | MEDIUM | `warning` |
| `note` | LOW | `note` |

These are lint findings about an API description, not exploitable vulnerabilities, so `error` is HIGH and not the CRITICAL that ASH's generic `error` level would mean. A level Spectral does not write (`none`, or an unknown value) is HIGH, the more severe reading. Every result also carries the tags `lint` and `api-description`.

## Suppressions

ASH suppressions by rule, path and line work as for any scanner:

```yaml
global_settings:
  suppressions:
    - rule_id: info-contact
      path: api/openapi.yaml
      line_start: 2
      line_end: 4
      reason: the contact object is added by the publishing pipeline
```

Package-scoped and symbol-scoped suppressions do not apply: no Spectral finding names a package or a symbol. To turn a rule off for every file, use a ruleset in `ruleset_file`.

## Offline and air-gapped use

Spectral's rulesets are compiled into the binary, so a run behaves the same offline except for a remote `$ref`, which cannot be fetched. Install the binary before going offline.

## License

ASH does not bundle or redistribute Spectral. It runs the binary you install, under that binary's own license.
