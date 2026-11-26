# Capslock Plugin

[Capslock](https://github.com/google/capslock) (BSD-3-Clause) reports which privileged operations a Go package can reach by following its transitive calls into the standard library: file system, network, program execution, system calls, `unsafe`, cgo and reflection. The ASH plugin runs it on each Go module in the source directory and reports one INFO result per function and capability.

Capslock tells you what code *can* do. A web server reaching the network is expected, so the results are an inventory for review and never fail a scan on their own.

## Enabling

The scanner is on once its module is listed:

```yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_capslock_plugins
```

With the module listed, `capslock` runs by default. `scanners.capslock.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. There is no license or service gate. If the tool is not installed, the scanner is reported `MISSING`.

## Installing Capslock

Capslock publishes no release binaries, so ASH neither bundles nor installs it, and the ASH container image does not carry it. The plugin is written against Capslock's `v0.3.4` module tag. Install that version with Go 1.26 or later and make sure the Go bin directory is on `PATH`:

<!-- doctest: illustrative reason="installs a program from the network" -->
```bash
go install github.com/google/capslock/cmd/capslock@v0.3.4
```

Capslock runs the `go` command to load your packages, so Go has to be on `PATH` when ASH scans too. `ash dependencies install` has nothing to install for this scanner. When the binary is missing, the scan log prints the command above.

ASH does not check which Capslock version you installed. A later version runs as is, and if its flags or its report format changed, the scan fails rather than reporting different findings without saying so. `capslock -version` prints the version you have.

## What is scanned

Every directory under the source directory that holds a `go.mod` is analyzed, except under `vendor`, `node_modules`, `.git` and `testdata`, and except modules under an ignore path. Capslock runs once per module, in the module's directory:

<!-- doctest: illustrative reason="needs a capslock binary, a Go toolchain and a Go module" -->
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

Every capability is INFO, SARIF level `none`, kind `informational`. The rule id is `CAPSLOCK-<CAPABILITY>`, for example `CAPSLOCK-NETWORK`. The message names the package by its import path, the capability, whether it is direct or transitive, and one example call path.

The location is the call the reporting function makes on that path: the file and line Capslock gives for it, in the package's own directory. When Capslock gives no such call, or the package is not under the module path the module's `go.mod` declares, the location is the module's `go.mod`.

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

Capslock is BSD-3-Clause: the `LICENSE` file at the commit the `v0.3.4` tag points to (`29ad626`). ASH does not redistribute it; you install it yourself.
