# Capslock alpha scanner plugin

Reports the capabilities (files, network, exec, unsafe, cgo, and so on) that the
Go packages in your tree can reach, using Google's
[Capslock](https://github.com/google/capslock) (BSD-3-Clause). Every capability is
reported as INFO: it is an inventory for review, not a vulnerability.

## Enabling

The scanner is on once its module is listed:

```yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_capslock_plugins
```

A scan that does not list the module is unchanged. There is no license or service gate.

## Installing Capslock

Capslock publishes no release binaries, so ASH builds it from source. The plugin is
written against the module's `v0.3.4` tag, and `ash dependencies install --tool
capslock` (with the module listed) builds that version with the Go toolchain on
`PATH` (Go 1.26 or later) into ASH's bin directory. It refuses the module unless the
go command reports the pinned digest before the build, and refuses an executable
whose build information names another module or platform after it
(`capslock_install.py`). The same build by hand:

```bash
go install github.com/google/capslock/cmd/capslock@v0.3.4
```

Capslock runs the `go` command to load your packages, so Go has to be on `PATH`
when ASH scans too. The ASH container image carries neither. Without the binary
the scanner is skipped and the log prints both routes. A `capslock` already on
`PATH` is used as is; `capslock -version` prints its version.

## What is scanned

Each directory that holds a `go.mod` (not under `vendor`, `node_modules`, `.git`
or `testdata`) is analyzed with `capslock -packages=./... -output=json
-force_local_module`. A tree with no `go.mod` is skipped, not reported as clean.
`-force_local_module` keeps Capslock from building a temporary module and running
`go get`. Go modules that are not already in the module cache (written by `go mod
download`) or `vendor` cannot be loaded offline, and Capslock then exits 2, which
fails the scan.

Under `--sandbox` the `go` on `PATH` and its GOROOT are mounted read-only, so a
standard-library or vendored module scans as it does unsandboxed (measured with
bubblewrap and Landlock). The module cache is mounted only when the operator grants
it (`sandbox.extra_read_paths` with `GOMODCACHE` in `sandbox.environment`); see the
documentation page.

## Configuration

Capslock has no options of its own; the shared `scan_timeout` and `offline`
options apply.

```yaml
scanners:
  capslock:
    options:
      scan_timeout: 1800
```

## Severity

Every result is INFO, SARIF level `none`, kind `informational`.

## Documentation

See <https://awslabs.github.io/automated-security-helper/docs/plugins/alpha/capslock-plugin/>.
