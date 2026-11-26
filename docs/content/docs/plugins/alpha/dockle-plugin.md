# Dockle Plugin

[Dockle](https://github.com/goodwithtech/dockle) is a container image linter. It checks an image against the CIS Docker Benchmark (checkpoints `CIS-DI-0001` to `CIS-DI-0011`) and Dockle's own Docker and Linux checkpoints (`DKL-DI-*`, `DKL-LI-*`): the last user is root, the image uses the `latest` tag, a file in a layer looks like a credential. It complements the [hadolint plugin](hadolint-plugin.md), which lints the Dockerfile, where Dockle lints the image that was built from it. Dockle is Apache-2.0 licensed.

Dockle reads one image, not a directory of files. ASH runs it on the image of an image scan, or, in a directory scan, on an image you name in its options, and does nothing otherwise.

## Enabling it

Dockle is an alpha plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_dockle_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_dockle_plugins
```

With the module listed, `dockle` is enabled by default, like every other scanner, and `scanners.dockle.enabled: false` turns it off again. `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners dockle` without the module listed is refused, with a message naming the module to add. If the tool is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate).

## Scanning an image

An image scan names its image on the command line, and Dockle is one of the scanners that read it:

<!-- doctest: illustrative reason="pulls a container image from a registry" -->
```bash
ash scan --image registry.example.com/team/app:1.2.3 --ash-plugin-modules automated_security_helper.plugin_modules.ash_dockle_plugins
```

or, for a saved image (`docker save`), with no network:

<!-- doctest: illustrative reason="needs a saved container image tarball" -->
```bash
ash scan --image-archive build/app-image.tar --ash-plugin-modules automated_security_helper.plugin_modules.ash_dockle_plugins
```

A reference is passed to Dockle after `--`, so it is never read as a flag, and a saved archive with `dockle --input`, which reads a `docker save` archive only. An `--image-layout` directory, or an OCI-layout tarball that holds no `manifest.json`, is therefore reported `SKIPPED` for Dockle with the reason, while the other image scanners still read it.

## Naming the image in a directory scan

In a directory scan Dockle needs an image named by the operator. It is gated on an option, the way `snyk-code` is gated on credentials, with one difference: with no image set the scanner does not fail. It logs an INFO line ("dockle needs a container image"), records that nothing was scanned, and returns without starting Dockle.

<!-- doctest: config kind=other reason="alpha plugin options, valid only with the module listed" -->
```yaml
scanners:
  dockle:
    options:
      image: registry.example.com/team/app:1.2.3
```

or, for a saved image, with no network:

<!-- doctest: config kind=other reason="alpha plugin options, valid only with the module listed" -->
```yaml
scanners:
  dockle:
    options:
      image_tarball: build/app-image.tar
```

Both are operator-only. A value written in a config file inside the scanned repository, or sent by an MCP client, is ignored with a warning, because it would let the scanned repository choose which image ASH pulls from which registry. Set them with `--config-overrides` or in a config file outside every git checkout and the scanned tree. Setting both fails the scan, and an `image` that is not a plain reference (it starts with a dash, or holds a space) is refused before Dockle runs.

Dockle runs once, on the source target. The converted target is the same image and is not scanned again.

## Installing Dockle

- **Local mode:** `ash dependencies install --tool dockle`, with the module listed in `ash_plugin_modules` (or added with `--config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_dockle_plugins"]'`), downloads the pinned Dockle v0.4.15 release archive from GitHub and verifies it, and the executable inside it, against the SHA256 digests pinned in ASH before installing it. Linux and macOS on x86_64 and arm64 are supported; Dockle publishes no Windows build.
- **Container mode:** the ASH container image includes Dockle, installed the same way.
- Any `dockle` already on `PATH` is also used.

## What is scanned

One image, or one saved image tarball. By name, Dockle fetches the image from its registry, or reads it from a Docker daemon, so that scan needs network access. A saved image read with `dockle --input` needs none. Dockle reads the image's configuration (user, health check, exposed ports, environment) and its filesystem layers.

ASH runs Dockle from the scan's results directory, not from the scanned tree, so a `.dockleignore` in the repository is not read. ASH does not pass `dockle --ignore`, the `--accept-*` and `--sensitive-*` flags, or `dockle --exit-code`; tune findings with ASH suppressions. Dockle has no option to leave paths unread, so ASH applies the scan's ignore paths to its findings after the scan. Dockle's own `DOCKLE_*` environment variables (not credentials) reach it when the scan runs under `--sandbox`.

## Severity

Dockle writes the SARIF level itself, and ASH rates each result to match:

| Dockle level | SARIF level | ASH severity |
|---|---|---|
| FATAL | `error` | HIGH |
| WARN | `warning` | MEDIUM |
| INFO | `note` | LOW |
| PASS, SKIP, IGNORE | `none` | INFO |

`error` is HIGH rather than CRITICAL because the checkpoints are configuration lint, as for hadolint, and not exploitable vulnerabilities. A result with no level is MEDIUM; a level not in the table is HIGH, so nothing is under-reported. With ASH's default `severity_threshold` of `MEDIUM`, FATAL and WARN findings fail the scan.

## Suppressions

ASH suppressions by rule, path and line work as for any scanner. A finding's location is the image reference or a path inside the image:

<!-- doctest: config kind=other reason="alpha plugin suppression example" -->
```yaml
global_settings:
  suppressions:
    - rule_id: CIS-DI-0001
      path: registry.example.com/team/app:1.2.3
      reason: the image runs a root-only init system by design
```

Package-scoped and symbol-scoped suppressions do not apply: no Dockle finding names a package or a symbol.

## Exit status

Dockle exits 0 whether or not it found anything, unless it is run as `dockle --exit-code`, which ASH does not pass. Any non-zero exit (an image that cannot be pulled, a daemon that cannot be reached) therefore fails the scan, even when a report is on disk. A report that is not JSON, not SARIF, or holds no SARIF run fails the scan as well; a run with zero results is a clean image. A timeout fails the scan with a message naming `scanners.dockle.options.scan_timeout`.

## Offline and air-gapped use

A scan by image name needs a registry or a Docker daemon, so an `--offline` scan does not run Dockle, a saved image included. Reading a saved image (`--image-archive`, or `scanners.dockle.options.image_tarball`) needs no network of its own.

## License

Dockle is Apache-2.0 licensed. The ASH container image redistributes the pinned release binary, so it carries the release archive's `LICENSE` beside it (the `dockle` entry in `THIRD_PARTY_LICENSES`). See [third-party licenses](../../../how-to/run-in-a-container.md#third-party-licenses).
