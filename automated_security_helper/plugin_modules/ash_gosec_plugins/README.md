# gosec scanner plugin

Go source security analysis for ASH, using [gosec](https://github.com/securego/gosec)
(Apache-2.0). A scan that does not list this module is unchanged.

## Enabling

```yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_gosec_plugins
```

Listing the module is the opt-in. There is no license or service gate: gosec runs
locally and sends nothing off the host.

## Installing

gosec needs two things on `PATH`: the `gosec` binary and the Go toolchain (`go`),
because gosec loads packages through it.

```bash
ash dependencies install \
  --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_gosec_plugins"]' \
  --tool gosec
```

This installs the pinned gosec release. It does not install Go. gosec also needs the
project's module dependencies in the local module cache (or a `vendor/` directory);
ASH does not run `go mod download`, and a scan whose packages fail to load fails
instead of passing as clean.

## Configuration

```yaml
scanners:
  gosec:
    enabled: true
    options:
      include_tests: false   # scan _test.go files too (gosec -tests)
```

## What it runs

`gosec -fmt=sarif -out=<report> -nosec=true -- ./...` from the source directory.
`-nosec=true` makes gosec ignore `#nosec` comments so every finding reaches ASH, where
suppressions are reported and counted.

## Severity

LOW is LOW (SARIF `note`), MEDIUM is MEDIUM (`warning`), HIGH is HIGH (`error`). gosec
itself writes `error` for both MEDIUM and HIGH; ASH reads the rule's severity tag to tell
them apart and, where that is not enough, rates the result HIGH.

## Documentation

https://awslabs.github.io/automated-security-helper/docs/plugins/community/gosec-plugin/
