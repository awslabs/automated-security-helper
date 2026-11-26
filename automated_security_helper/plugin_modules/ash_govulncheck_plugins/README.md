# govulncheck alpha scanner plugin

[govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) (BSD-3-Clause) finds known vulnerabilities in the Go modules a project uses and reports whether the vulnerable function is actually reachable from the project's code. A vulnerable dependency whose affected function is never called is reported at a lower severity than one the code calls.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_govulncheck_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_govulncheck_plugins
```

With the module listed, `govulncheck` runs by default. `scanners.govulncheck.enabled: false` turns it off again. There is no license or service gate and no account is needed.

## Installing the tool

It needs a Go toolchain on the machine, which ASH does not install: govulncheck builds with it and runs `go` to load packages at scan time. With `go` on `PATH`, ASH runs `go install golang.org/x/vuln/cmd/govulncheck@v1.9.0` into its bin directory:

<!-- doctest: illustrative reason="downloads and installs the scanner's tool" -->
```bash
ash dependencies install --config-overrides "ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_govulncheck_plugins]" --tool govulncheck
```

Any `govulncheck` already on `PATH` is also used. The install command covers Linux, macOS and Windows (x86_64 and arm64): ASH sets `GOBIN` in the environment it starts `go` with, so no shell is involved. The ASH container image does not carry govulncheck, because it carries no Go toolchain.

## Configuration

```yaml
scanners:
  govulncheck:
    enabled: true
    options:
      # govulncheck -scan level: symbol (default), package or module.
      scan_level: symbol
      # Also analyze _test.go files (govulncheck -test).
      include_tests: false
      # Seconds for the whole scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

## Notes

- One govulncheck run is made for each directory under the source that holds a `go.mod`. `vendor`, `node_modules` and `testdata` are not searched.
- govulncheck exits 0 with `-format sarif` whatever it finds, so ASH reads the report and treats any non-zero exit as a failed scan.
- The vulnerability database is fetched from vuln.go.dev at scan time, so the scan needs a network and is skipped with `--offline`.

## Documentation

Severity mapping, suppressions, offline use and every option: [the govulncheck plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/alpha/govulncheck-plugin/).
