# govulncheck Plugin

[govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) finds known vulnerabilities in the Go modules a project uses, from the Go vulnerability database, and reports whether the vulnerable function is reachable from the project's code. It ships with the Go project and is licensed BSD-3-Clause.

## Enabling it

govulncheck is an alpha plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_govulncheck_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_govulncheck_plugins
```

With the module listed, `govulncheck` runs by default, like every other scanner. `scanners.govulncheck.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners govulncheck` without the module listed is refused, with a message naming the module to add. If the tool is not installed, or the Go toolchain it runs is not on `PATH`, the scanner is reported `MISSING` with the reason and the scan exits 1 (the incomplete-scan gate).

There is no license gate and no opt-in beyond listing the module: the tool is BSD-3-Clause and the database is public and needs no account.

## Installing govulncheck

- **Local mode:** with a Go toolchain on `PATH`, `ash dependencies install --tool govulncheck` (with the module listed in `ash_plugin_modules`, or added with `--config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_govulncheck_plugins"]'`) runs `go install golang.org/x/vuln/cmd/govulncheck@v1.9.0` with `GOBIN` set to ASH's bin directory. `go install` checks the module it fetches against the Go checksum database unless your Go environment turns that check off. ASH does not install Go itself; without it the scanner reports no install path on this machine. Linux and macOS (x86_64 and arm64) are covered, Windows is not.
- **Container and Nix modes:** the image and the flake do not supply govulncheck. The image carries no Go toolchain, and govulncheck needs one both to be built and to load packages when it scans.
- Any `govulncheck` already on `PATH` is also used, with `go` on `PATH` beside it.

## What is scanned

One govulncheck run is made for each directory under the source that holds a `go.mod`, with that directory as the working directory and `./...` as the package pattern. `vendor`, `node_modules`, `testdata` and `.git` are not searched, symlinks are not followed, and `global_settings.ignore_paths` entries matching a module's `go.mod` skip that module. A tree with no `go.mod` is not scanned and the scanner reports `SKIPPED`. A tree with more than 200 modules fails the scan rather than reporting a partial result.

Each finding points at the module's `go.mod`, at line 1, which is the one location govulncheck reports. Its rule links to the advisory on pkg.go.dev, and its message names the packages the code calls or imports.

## Configuration

<!-- doctest: config kind=other reason="shows every option of a plugin that is not in the default config" -->
```yaml
scanners:
  govulncheck:
    enabled: true
    options:
      # govulncheck -scan level: symbol (default), package or module.
      scan_level: symbol
      # Also analyze _test.go files (govulncheck -test).
      include_tests: false
      # Seconds for the whole scan, shared by every module (default 1800;
      # null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

ASH never passes `-db`, so the database is always the tool's default, vuln.go.dev, and a scanned tree cannot point the tool at another one.

## Severity

govulncheck writes one SARIF level per finding, by how precisely it could place the vulnerability. ASH sets the severity and the SARIF level together:

| govulncheck level | Meaning | ASH severity | SARIF level |
|---|---|---|---|
| `error` | the vulnerable function is called | HIGH | error |
| `warning` | the vulnerable package is imported, the function is not called | MEDIUM | warning |
| `note` | only the module is required | LOW | note |

No finding is CRITICAL: the report carries no CVSS score, and a reachable function shows exposure, not exploitability. A result with no level is MEDIUM. A level of `none` is INFO, and any other level is HIGH, so an unexpected value is never under-reported.

## Exit status

With `-format sarif` govulncheck exits 0 whether or not it found anything, so the exit code says nothing about findings and ASH reads the report instead. Exit 0 is the only accepted code: any other code, a timeout, or output that is empty, not JSON, or not a SARIF report fails the scan, even if some output was written.

## Suppressions

Suppress a finding by its OSV id in the ASH config:

<!-- doctest: config kind=other reason="shows a suppression for a plugin that is not in the default config" -->
```yaml
global_settings:
  suppressions:
    - rule_id: GO-2023-0001
      path: go.mod
      line_start: 1
      line_end: 1
      reason: The affected function is behind a build tag we do not set.
```

Package-scoped and symbol-scoped suppressions do not apply: govulncheck's location is the `go.mod` file, not a source line, and ASH writes no package fields for its findings.

## Offline and air-gapped use

govulncheck fetches the vulnerability database from vuln.go.dev on every run, and Go may fetch modules, so the scan needs a network. Under `--offline` the scanner is skipped with a warning. Its sandbox declaration grants a network; the Go module and build caches are mounted read-only.

## License

govulncheck is BSD-3-Clause: the `LICENSE` file of the `golang.org/x/vuln` v1.9.0 module, the same file as at the v1.9.0 tag. ASH does not redistribute it: it is built from the module on request, and the container image does not carry it. See [third-party licenses](../../../how-to/run-in-a-container.md#third-party-licenses) for the tools the image ships.
