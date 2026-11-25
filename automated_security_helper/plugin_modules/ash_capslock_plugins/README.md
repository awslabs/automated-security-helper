# Capslock (community plugin)

Reports the capabilities (files, network, exec, unsafe, cgo, and so on) that the
Go packages in your tree can reach, using Google's
[Capslock](https://github.com/google/capslock) (BSD-3-Clause). Every capability is
reported as INFO: it is an inventory for review, not a vulnerability.

A scan that does not list this module is unchanged.

## Enabling

```yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_capslock_plugins
```

Once the module is listed the scanner is on. There is no license or service gate.

## Installing Capslock

Capslock publishes no releases, so ASH does not install it. Install it yourself
and put the Go bin directory on `PATH`:

```bash
go install github.com/google/capslock/cmd/capslock@latest
```

Without the binary the scanner is skipped and the log prints that command.

## What is scanned

Each directory that holds a `go.mod` (not under `vendor`, `node_modules`, `.git`
or `testdata`) is analyzed with `capslock -packages=./... -output=json
-force_local_module`. A tree with no `go.mod` is skipped, not reported as clean.
`-force_local_module` keeps Capslock from building a temporary module and running
`go get`. Go modules that are not already in the module cache or `vendor` cannot
be loaded in the network-free sandbox, and Capslock then exits 2, which fails the
scan.

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

See <https://awslabs.github.io/automated-security-helper/docs/plugins/community/capslock-plugin/>.
