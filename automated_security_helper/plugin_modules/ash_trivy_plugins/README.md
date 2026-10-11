# ASH Trivy repository plugin

This module adds the `trivy-repo` scanner, which runs [trivy](https://github.com/aquasecurity/trivy)'s `trivy repository` command on the source directory with all four of trivy's scanners: vulnerable dependencies (`vuln`), misconfigurations in infrastructure-as-code and Dockerfiles (`misconfig`), secrets (`secret`) and licenses (`license`). It is a community plugin: it ships with ASH, and a scan runs it only when the module is loaded. The full documentation is the [Trivy repository plugin](https://awslabs.github.io/automated-security-helper/docs/plugins/community/trivy-plugin/) page.

ASH also has a built-in `trivy` scanner, on by default, which runs `trivy fs` with only the vulnerability scanner. With both on, trivy runs twice and every vulnerability both find is reported twice. For a new setup, use the built-in scanner and turn on the trivy scanners you want with its `scanners` option; [trivy-repo and the built-in trivy scanner](https://awslabs.github.io/automated-security-helper/docs/plugins/community/#trivy-repo-and-the-built-in-trivy-scanner) compares the two.

## Install trivy

trivy-repo runs the same trivy binary as the built-in scanner. `ash dependencies install` installs the release ASH pins, after checking its SHA256, and trivy-repo uses that copy. The ASH container image includes it, and a `trivy` already on `PATH` is used as it is.

## Load the plugin

Name the module in an ASH config, which a repository's own `.ash/.ash.yaml` may do, and turn the built-in scanner off:

```yaml
project_name: my-service
ash_plugin_modules: [automated_security_helper.plugin_modules.ash_trivy_plugins]
scanners:
  trivy:
    enabled: false
  trivy-repo:
    options:
      scanners: [vuln, misconfig, secret]
```

Or name it on the command line with `--ash-plugin-modules`. This lists `trivy-repo` among the scanners:

```bash
ash plugin list --ash-plugin-modules automated_security_helper.plugin_modules.ash_trivy_plugins
```

trivy's SARIF is written to `.ash/ash_output/scanners/trivy-repo/source/results_sarif.sarif`, and its findings are in every ASH report.

## Options

Every option, with its type and default, is in the [scanner reference](https://awslabs.github.io/automated-security-helper/reference/scanners/#trivy-repo). trivy-repo's defaults differ from the built-in scanner's: it reports only vulnerabilities that have a fix (`ignore_unfixed: true`) and looks for licenses in file headers too (`license_full: true`).

## Files that trivy reads

Left to itself, trivy reads a `trivy.yaml`, a `.trivyignore` and a `trivy-secret.yaml` from the directory it scans, so a scanned repository could use them to drop its own findings. ASH therefore always passes trivy its config file, module directory, ignore file and secret config, and those files in the scanned repository are never read. The options `config_file`, `module_dir`, `ignore_file` and `secret_config_file` name files of your own, and ASH uses them only when the operator sets them (with `--config-overrides`, or in a config file outside every git checkout and the scanned directory) for a path outside those directories. Under `--sandbox`, trivy can read such a file only when the sandbox already lets it read that directory or the path is listed in `sandbox.extra_read_paths`. To ignore a finding, use an [ASH suppression](https://awslabs.github.io/automated-security-helper/how-to/suppress-findings/).

## The vulnerability database

trivy-repo and the built-in scanner share one trivy cache. Before an online scan ASH updates the vulnerability database in it; offline, trivy uses the database already there. Either way, by default ASH fails the scan when the database was built more than 24 hours earlier (`ash scan --allow-stale-content-db` relaxes that). [The vulnerability database and offline scans](https://awslabs.github.io/automated-security-helper/docs/plugins/community/trivy-plugin/#the-vulnerability-database-and-offline-scans) has the details.
