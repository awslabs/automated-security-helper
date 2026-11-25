# Capslock (community plugin)

[Capslock](https://github.com/google/capslock) (BSD-3-Clause) reports which
privileged operations a Go package can reach by following its transitive calls
into the standard library: file system, network, program execution, system calls,
`unsafe`, cgo and reflection. The ASH plugin runs it on each Go module in the
source directory and reports one INFO result per package and capability.

Capslock tells you what code *can* do. A web server reaching the network is
expected, so the results are an inventory for review and never fail a scan on
their own.

## Enabling it

Capslock is a community plugin that ships with ASH. Its module is loaded only when you list it, so an `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_capslock_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_capslock_plugins
```

With the module listed, `capslock` runs by default. `scanners.capslock.enabled: false` turns it off, and `--scanners` and `--exclude-scanners` select it as they select any scanner. There is no license or service gate. If the tool is not installed, the scanner is reported `MISSING`.

## Installing Capslock

Capslock publishes no releases, so ASH neither bundles nor installs it. Install it yourself with Go 1.21 or later and make sure the Go bin directory is on `PATH`:

<!-- doctest: illustrative reason="installs a program from the network" -->
```bash
go install github.com/google/capslock/cmd/capslock@latest
```

`ash dependencies install` has nothing to install for this scanner. When the binary is missing, the scan log prints the command above.

## What is scanned

Every directory under the source directory that holds a `go.mod` is analyzed, except under `vendor`, `node_modules`, `.git` and `testdata`. Capslock runs once per module, in the module's directory:

<!-- doctest: illustrative reason="the argv the plugin builds" -->
```bash
capslock -packages=./... -output=json -force_local_module
```

- `-output=json` is Capslock's JSON mode. The plugin reads the report from stdout.
- `-force_local_module` stops Capslock from building a temporary module and running `go get` when it cannot load the packages. That fallback reaches the network and analyzes something other than your tree. With the flag Capslock exits 2 instead.
- `GOFLAGS=-mod=readonly` is set so the run never rewrites `go.mod`.

A tree with no `go.mod` is skipped, and the scanner reports `SKIPPED`, not a clean pass. The plugin passes no capability map, so nothing in the scanned tree can change what is reported.

## Configuration

Capslock has no options of its own; the shared options apply.

```yaml
scanners:
  capslock:
    enabled: true
    options:
      scan_timeout: 1800
```

There are no options a scanned tree could use to hide findings, so no option is operator-only.

## Severity

Every capability is INFO, SARIF level `none`, kind `informational`. The rule id is `CAPSLOCK-<CAPABILITY>`, for example `CAPSLOCK-NETWORK`. The message names the package, the capability, whether it is direct or transitive, and one example call path. The location is the first call site Capslock gives for that path; when it gives none, or the site is outside the source directory, the module's `go.mod`.

## Exit status

Capslock exits 0 on success, 1 only for a comparison difference (never requested here) and 2 for any error, such as packages that cannot be loaded. The plugin accepts 0 only. Any other status, a timeout, or output that is not a Capslock JSON report fails the scan.

## Suppressions

Suppress a result by rule id, path or line in the ASH configuration, as for any scanner:

```yaml
global_settings:
  suppressions:
    - rule_id: CAPSLOCK-EXEC
      path: tools/build/main.go
      reason: Build helper that runs the compiler on purpose.
```

Package-scoped and symbol-scoped suppressions do not apply.

## Offline and air-gapped use

The analysis is local, but loading Go packages needs their modules in the module cache or a `vendor` directory. The scanner sandbox has no network, so a module that is not cached makes Capslock exit 2 and the scan fails. Run `go mod download` or `go mod vendor` first.

## License

Capslock is BSD-3-Clause. ASH does not redistribute it; you install it yourself.
