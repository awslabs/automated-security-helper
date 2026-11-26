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

Capslock publishes no release binaries, so ASH builds it from source. The plugin is written against Capslock's `v0.3.4` module tag, and `ash dependencies install` builds that version with the Go toolchain on `PATH` (Go 1.26 or later) and puts the executable in ASH's bin directory:

<!-- doctest: illustrative reason="downloads and builds a Go module" -->
```bash
ash dependencies install --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_capslock_plugins"]' --tool capslock
```

Before it builds, ASH has the go command download the module and refuses it unless the digest the go command reports is the pinned one (`h1:eS3/PLl++R96+Ub8b7uIDgCWzQh8CsY1CzVQbnt+Vhs=`, the Go checksum database's record for `v0.3.4`). The module's own `go.sum` pins its dependencies, and after the build the executable's embedded build information has to name the pinned module and this machine's platform. The build uses your toolchain as it is (`GOTOOLCHAIN=local`): an older Go is refused with its version named, not upgraded behind your back. Your `GOPROXY`, `GOPRIVATE` and module cache settings are used, so a mirror works. Offline, nothing is built.

The same build by hand is:

<!-- doctest: illustrative reason="installs a program from the network" -->
```bash
go install github.com/google/capslock/cmd/capslock@v0.3.4
```

Capslock runs the `go` command to load your packages, so Go has to be on `PATH` when ASH scans too. The ASH container image carries neither Capslock nor Go, so this scanner runs in local mode. When the binary is missing, the scan log prints both commands.

A `capslock` already on `PATH` is used as it is, and ASH does not check its version. A later version runs as is, and if its flags or its report format changed, the scan fails rather than reporting different findings without saying so. `capslock -version` prints the version you have.

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

The analysis is local, but loading Go packages needs their modules in the module cache or a `vendor` directory, and a module that is not there makes Capslock exit 2 and the scan fails. Run `go mod download` (or `go mod vendor`) first: the loader reads the `.info` record `go mod download` writes beside each cached module.

## Sandboxed scans

Under `--sandbox`, Capslock gets the strict default (no network, the baseline environment) and one grant: it runs the `go` command, so the directory of the `go` on `PATH` and its installation (GOROOT) are mounted read-only. The go command's build cache is written in the sandbox's private home and thrown away. Measured with bubblewrap and Landlock on Linux: a module that uses only the standard library, or vendors its dependencies, scans as it does unsandboxed.

The module cache is not mounted, because its location comes from your environment. A module whose dependencies are only in the module cache exits 2 under the sandbox. Vendor the dependencies, or grant the cache from a config file outside every git checkout (see [Give a scanner more access](../../scanner-sandbox.md#grants)):

```yaml
sandbox:
  mode: bwrap
  extra_read_paths:
    - /home/me/go/pkg/mod
  environment:
    - GOMODCACHE=/home/me/go/pkg/mod
```

`go env GOMODCACHE` prints the directory. A `sandbox.environment` list replaces the default one, so add back the proxy and certificate variables you need ([Pass other variables](../../scanner-sandbox.md#environment)). firejail and macOS `sandbox-exec` have not been measured with this scanner.

## License

Capslock is BSD-3-Clause: the `LICENSE` file at the commit the `v0.3.4` tag points to (`29ad626`). ASH builds the pinned module on your machine when you run `ash dependencies install` and does not redistribute it.
