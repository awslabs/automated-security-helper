# cdxgen Plugin

[cdxgen](https://github.com/cdxgen/cdxgen) (CycloneDX Generator, Apache-2.0) builds a software bill of materials (SBOM) for the scanned directory. It reads manifests and lock files for many ecosystems (JavaScript, Python, Java, Go, Rust and others) and writes a CycloneDX document. It reports an inventory of components, not vulnerabilities.

## Enabling

The scanner is on once its module is listed:

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_cdxgen_plugins
```

With the module listed, `cdxgen` runs by default. `scanners.cdxgen.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. If the tool is not installed, the scanner is reported `MISSING`.

## Installing cdxgen

cdxgen is a Node.js program: the 12.9.2 release declares Node.js 20, 22, 24, 25 or 26. ASH pins `@cyclonedx/cdxgen` 12.9.2. With `node` and `npm` on `PATH`, install it with:

<!-- doctest: illustrative reason="installs a package from the npm registry" -->
```bash
ash dependencies install --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_cdxgen_plugins"]' --tool cdxgen
```

That runs `npm install -g @cyclonedx/cdxgen@12.9.2`, which installs cdxgen's dependencies too, its optional prebuilt platform plugins among them. If `cdxgen` is already on `PATH`, ASH uses it. The ASH container image does not include cdxgen.

## What is scanned

The whole source directory, recursively. If the directory is empty or missing, cdxgen is not run. ASH's own output directories inside the source are excluded.

ASH runs cdxgen from a working directory outside the scanned tree, so a `.cdxgenrc` or a cdxgen section in the repository's `package.json` does not change what is reported.

## Configuration

<!-- doctest: config kind=other reason="options of an alpha plugin that is not loaded by default" -->
```yaml
scanners:
  cdxgen:
    enabled: true
    options:
      project_type: [] # cdxgen --type values, such as python or js; empty detects them
      exclude: [] # entries of path (a glob passed to cdxgen as --exclude) and reason
      scan_timeout: 1800
```

ASH always passes these flags, and the configuration cannot change them:

- `--spec-version=1.6`: ASH reads CycloneDX 1.6. cdxgen's default is newer.
- `--no-install-deps`: cdxgen installs the dependencies of some project types by default, which runs the scanned project's package manager. ASH does not allow that.

## Severity

cdxgen reports no findings, so there is no SARIF level and no severity to rate. The components are inventory, as for the builtin syft scanner. The SBOM is written to the scan's results directory as `cdxgen.cdx.json`.

## Suppressions

Because there are no findings, there is nothing for a suppression to match. Use `exclude` to keep a path out of the inventory.

## Exit status

cdxgen exits 0 when it wrote a report. Any other exit code, a timeout, or a report that is not valid CycloneDX 1.6 fails the scan.

## Offline use

ASH passes `--no-install-deps`, and the scanner runs under the strict sandbox, which grants it no network, so the scan reaches no package registry. Install the npm package before going offline.

## License

cdxgen is Apache-2.0 licensed. ASH does not redistribute it: `ash dependencies install` installs it from the npm registry, and neither the ASH Python package nor the ASH container image carries it.
