# cdxgen (community plugin)

[cdxgen](https://github.com/CycloneDX/cdxgen) (CycloneDX Generator) builds a software
bill of materials (SBOM) for a source tree. It reads manifests and lock files for many
ecosystems (JavaScript, Python, Java, Go, Rust, and others) and writes a CycloneDX
document. It reports an inventory of components, not vulnerabilities.

## Enabling it

cdxgen is a community plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_cdxgen_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_cdxgen_plugins
```

With the module listed, `cdxgen` runs by default, like every other scanner.
`scanners.cdxgen.enabled: false` turns it off again. cdxgen has no license or service
gate: it is Apache-2.0 and runs locally. If the tool is not installed, the scanner is
reported `MISSING`.

## Installing cdxgen

cdxgen is a Node.js program (Node.js 20 or later). `ash dependencies install --tool cdxgen`,
with the module listed in `ash_plugin_modules`, runs
`npm install -g @cyclonedx/cdxgen@12.9.2`. Any `cdxgen` already on `PATH` is also
used.

## What is scanned

The whole source directory, recursively. If the directory is empty or missing,
cdxgen is not run. ASH's own output directory inside the source is excluded.

ASH runs cdxgen from a working directory outside the scanned tree, so a `.cdxgenrc`
or a cdxgen section in the repository's `package.json` does not change what is
reported.

## Configuration

<!-- doctest: config kind=other reason="options of a community plugin that is not loaded by default" -->
```yaml
scanners:
  cdxgen:
    enabled: true
    options:
      project_type: [] # cdxgen --type values, such as python or js; empty detects them
      exclude: [] # glob patterns passed to cdxgen as --exclude
      scan_timeout: 1800
```

ASH always passes these flags, and the configuration cannot change them:

- `--spec-version=1.6`: ASH reads CycloneDX 1.6. cdxgen's default is newer.
- `--no-install-deps`: cdxgen installs the dependencies of some project types by
  default, which runs the scanned project's package manager. ASH does not allow that.

## Severity

cdxgen reports no findings, so there is no SARIF level and no severity to rate. The
components are inventory (INFO), as for the builtin syft scanner. The SBOM is written
to the scan's results directory as `cdxgen.cdx.json`.

## Suppressions

Because there are no findings, there is nothing for a suppression to match. Use
`exclude` to keep a path out of the inventory.

## Exit status

cdxgen exits 0 when it wrote a report. Any other exit code, a timeout, or a report that
is not valid CycloneDX 1.6 fails the scan.

## Offline and air-gapped use

ASH passes `--no-install-deps` and the scanner runs under the strict sandbox with no
network, so it makes no registry calls for the scan. Install the npm package ahead of
time in an air-gapped environment.

## License

cdxgen is licensed under Apache-2.0. ASH does not redistribute it; it is installed from
npm.
