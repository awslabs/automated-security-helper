# hadolint (community plugin)

[hadolint](https://github.com/hadolint/hadolint) lints Dockerfiles. It checks
each instruction against its own `DL` rules (unpinned base images, `apt-get`
without pinned versions, `ADD` where `COPY` would do, a final `USER root`, and
so on) and runs [ShellCheck](https://www.shellcheck.net/) over the shell in every
`RUN` instruction, reported as `SC` rules.

## Enabling it

hadolint is a community plugin that ships with ASH. Its plugin module is loaded only when you list it, so a scan that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_hadolint_plugins
```

```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_hadolint_plugins
```

With the module listed, `hadolint` runs by default, like every other scanner. `scanners.hadolint.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners hadolint` without the module listed is refused, with a message naming the module to add. If the tool is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate).

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
example) was not evaluated: hadolint applies none of its rules to it. ASH reports
it as an unevaluated target, not as a finding. The file is named in the scan log
and the scanner's errors, the summary shows hadolint with that many targets
unevaluated, and the scan is incomplete, so it exits 1 (unless you pass
`--no-fail-on-incomplete-scanners`). hadolint's own `DL1000` parse-error result
is dropped, so no finding stands in for a file nothing was checked in. If every
Dockerfile fails to parse, hadolint's status is `ERROR`. Add a file to
`ignore_paths` if it is not meant to be a Dockerfile.

## Configuration

```yaml
scanners:
  hadolint:
    enabled: true
    options:
      # A hadolint config file outside the scanned tree, honored only when set
      # with --config-overrides or an ASH config file outside the tree. Unset,
      # hadolint gets an empty config: a .hadolint.yaml in the scanned repository
      # is not read. A path that is honored but missing fails the scan instead of
      # silently running with hadolint's defaults.
      config_file: null
      # Seconds for the whole hadolint scan (default 1800; null for no limit).
      # Every hadolint process the scan starts shares this one budget.
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

hadolint reads `.hadolint.yaml` or `.hadolint.yml` from its working directory,
which is the source directory, and that file belongs to the scanned repository: it
can ignore rules or lower their severity with nothing in the report saying so. So
ASH always passes `--config`, your `config_file` when it is honored, or otherwise an
empty config, and a `.hadolint.yaml` in the tree is noted in the scan log and not
read. Tune findings with ASH suppressions, which are reported and counted, or
hadolint's inline `# hadolint ignore=` pragmas. An explicit `--config` also means
hadolint does not read a user-level config under `$XDG_CONFIG_HOME` or `$HOME`;
name that file in `config_file` to use it.

Everything hadolint's own [configuration file](https://github.com/hadolint/hadolint#configure)
supports works in your `config_file`: `ignored`, `override`, `trustedRegistries`,
`label-schema`, `strict-labels` and `disable-ignore-pragma`. For example:

```yaml
# /etc/ash/hadolint.yaml, passed with
# --config-overrides 'scanners.hadolint.options.config_file=/etc/ash/hadolint.yaml'
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
binary; its license, upstream third-party notices (`ThirdPartyNotices.txt`) and a
`SOURCE` file naming the repository, tag and commit of its corresponding source are
in the image at `/usr/share/doc/ash/third-party/hadolint/`, installed the same way as
every other bundled tool's (see
[Building your own image](../../building-your-own-image.md#third-party-license-files-in-the-image)).
