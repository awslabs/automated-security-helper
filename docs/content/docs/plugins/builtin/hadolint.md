# hadolint (opt-in)

[hadolint](https://github.com/hadolint/hadolint) lints Dockerfiles. It checks
each instruction against its own `DL` rules (unpinned base images, `apt-get`
without pinned versions, `ADD` where `COPY` would do, a final `USER root`, and
so on) and runs [ShellCheck](https://www.shellcheck.net/) over the shell in every
`RUN` instruction, reported as `SC` rules.

hadolint is an **opt-in** scanner. A scan that has not enabled it does not run
it and does not mention it: it has no row in the results, the summary, the
reports or the SARIF output. Existing configurations produce the same output
they did before hadolint was added.

## Enabling it

Any one of these enables it:

```yaml
# .ash/.ash.yaml
scanners:
  hadolint:
    enabled: true
```

```bash
# For one run, without editing the config
ash scan --config-overrides 'scanners.hadolint.enabled=true'

# Run only hadolint
ash scan --scanners hadolint
```

Naming hadolint in `--scanners` (or the MCP `scanners` argument) runs it even if
the config says `enabled: false`. `--exclude-scanners hadolint` wins over both.

Once enabled it behaves like every other built-in scanner. If the `hadolint`
binary is not installed the scanner is reported `MISSING` and, because
`fail_on_incomplete_scanners` defaults to true, the scan exits 1.

## Installing hadolint

- **Container mode:** the ASH image includes hadolint v2.15.1.
- **Local mode:** `ash dependencies install` (or `ash dependencies install --tool hadolint`)
  downloads the pinned v2.15.1 release binary from GitHub and verifies it against
  the SHA256 digest pinned in ASH before installing it. Linux and macOS (x86_64
  and arm64) and Windows x86_64 are supported; hadolint publishes no Windows arm64
  build.
- **Nix mode:** the flake supplies `hadolint` from nixpkgs.
- Any `hadolint` already on `PATH` is also used.

## Which files are scanned

Files named `Dockerfile`, `Containerfile`, `*.Dockerfile` or `Dockerfile.*`
anywhere under the source directory, matched case-sensitively: a lowercase
`app.dockerfile` or `dockerfile` is not linted. BuildKit ignore files
(`Dockerfile.dockerignore`, `*.Dockerfile.dockerignore`) are not linted either.

ASH's ignore files (`.gitignore`, `.ashignore`) and `global_settings.ignore_paths`
apply before hadolint sees anything. ASH's own output directory is never scanned,
and a symlinked Dockerfile that points outside the source directory is skipped
with a warning. If there are no Dockerfiles, hadolint is not run and the scanner
reports `SKIPPED`. A tree with more Dockerfiles than fit on one command line is
linted in several hadolint runs whose results are merged.

A Dockerfile hadolint cannot parse (a template such as `Dockerfile.j2`, for
example) is reported as rule `DL1000` at HIGH severity. Add it to
`ignore_paths` if it is not meant to be a Dockerfile.

## Configuration

```yaml
scanners:
  hadolint:
    enabled: true
    options:
      # A hadolint config file, relative to the source directory. When unset,
      # ASH uses the first of .hadolint.yaml, .hadolint.yml, .ash/.hadolint.yaml
      # and .ash/hadolint.yaml that exists. A path that is set but missing fails
      # the scan instead of silently running with hadolint's defaults.
      config_file: null
      # Seconds for the whole hadolint scan (default 1800; null for no limit).
      # Every hadolint process the scan starts shares this one budget.
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

Everything hadolint's own [configuration file](https://github.com/hadolint/hadolint#configure)
supports works: `ignored`, `override`, `trustedRegistries`, `label-schema`,
`strict-labels` and `disable-ignore-pragma`. For example:

```yaml
# .hadolint.yaml
ignored:
  - DL3008
override:
  error:
    - DL3002
trustedRegistries:
  - docker.io
  - my-registry.example.com
```

If hadolint cannot parse its config file it reports that on stderr and carries
on with its defaults. ASH treats that as a scanner error, because the report
would otherwise silently drop the ignores and overrides you configured.

hadolint's rule-policy environment variables (`HADOLINT_IGNORE`,
`HADOLINT_OVERRIDE_ERROR` and the other `HADOLINT_OVERRIDE_*`,
`HADOLINT_TRUSTED_REGISTRIES`, `HADOLINT_REQUIRE_LABELS`,
`HADOLINT_STRICT_LABELS`, `HADOLINT_DISABLE_IGNORE_PRAGMA`) are passed through.
`HADOLINT_FORMAT`, `HADOLINT_NOFAIL`, `HADOLINT_FAILURE_THRESHOLD` and
`HADOLINT_VERBOSE` are removed from hadolint's environment, because they would
change how ASH has to read its output (`HADOLINT_FORMAT` overrides the
`--format` flag ASH passes).

## Severity mapping

| hadolint level | ASH severity | SARIF level |
|----------------|--------------|-------------|
| `error`        | HIGH         | `error`     |
| `warning`      | MEDIUM       | `warning`   |
| `info`         | LOW          | `note`      |
| `style`        | INFO         | `none`      |

hadolint's `error` maps to HIGH rather than CRITICAL: its errors are build
correctness and deprecation problems, not exploitable vulnerabilities. Severity
overrides in your hadolint config change the level hadolint reports, and the
mapping applies to the overridden level.

hadolint's SARIF output writes both `info` and `style` as `note`. To tell them
apart ASH runs hadolint a second time with `--format json`, only when the SARIF
report contains a `note`, and reads each rule's level from it. If that second run
fails, every `note` is reported as LOW, never lower.

With ASH's default `severity_threshold` of `MEDIUM`, hadolint warnings and errors
fail the scan; info and style findings are reported but do not.

## Suppressions

- **hadolint's inline pragmas** (`# hadolint ignore=DL3008,SC2086` on the line
  above an instruction) are honored by hadolint itself, unless your hadolint config
  sets `disable-ignore-pragma`.
- **ASH suppressions** by rule, path and line work as for any scanner:

  ```yaml
  global_settings:
    suppressions:
      - rule_id: DL3008
        path: docker/base.Dockerfile
        line_start: 12
        line_end: 12
        reason: apt package versions are pinned by the base image snapshot
  ```

- Package-scoped suppressions do not apply: no hadolint finding names a package.
  Symbol-scoped suppressions do not apply either: a Dockerfile has no functions
  or classes.

## Offline and air-gapped use

hadolint reads only the files it is given and never uses the network, so it
behaves the same offline. Install it before going offline (the container image
already has it).

## License

hadolint is licensed under GPL-3.0. ASH runs it as a separate program and does
not link to it. The ASH container image includes the unmodified hadolint
binary; its license, upstream third-party notices and the location of its
corresponding source are in the image at `/usr/share/doc/hadolint/`.
