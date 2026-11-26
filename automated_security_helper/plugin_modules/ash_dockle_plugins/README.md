# ASH Dockle Plugin

[Dockle](https://github.com/goodwithtech/dockle) is a container image linter. It checks one image against the CIS Docker Benchmark and Dockle's own checkpoints (a root user, a `latest` tag, a sensitive-looking file in a layer) and complements the hadolint plugin, which lints Dockerfiles. ASH runs it as `dockle --format=sarif` over one image, never over the scan target's files: the image of an image scan, or, in a directory scan, an image you name in its options.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_dockle_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_dockle_plugins
```

With the module listed, `dockle` is on by default and scans the image of an image scan (`ash scan --image <reference>`, or `--image-archive <docker save tarball>`). In a directory scan it needs an image named by the operator: until `scanners.dockle.options.image` or `scanners.dockle.options.image_tarball` is set, it logs an INFO line and scans nothing.

## Installing the tool

<!-- doctest: illustrative reason="downloads and installs the scanner's tool" -->
```bash
ash dependencies install --config-overrides "ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_dockle_plugins]" --tool dockle
```

ASH pins Dockle v0.4.15 (Linux and macOS, on amd64 and arm64; the release has no Windows build) and verifies the release archive and the executable inside it against their pinned SHA256 digests before installing it. The ASH container image includes it.

## Configuration

```yaml
scanners:
  dockle:
    enabled: true
    options:
      # The image to scan, by registry reference. Operator only: set it with
      # --config-overrides or a config file outside every git checkout and the
      # scanned tree. Needs a network (or a Docker daemon) to fetch the image.
      image: null
      # Or a saved image (docker save), scanned with dockle --input. Operator only.
      # Needs no network. Set one of image and image_tarball, not both.
      image_tarball: null
      # Seconds for the whole Dockle scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

## Documentation

Severity mapping, suppressions, offline use and every option: [the Dockle plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/alpha/dockle-plugin/).
