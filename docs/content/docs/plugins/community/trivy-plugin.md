# Trivy repository plugin (`trivy-repo`)

The `trivy-repo` scanner runs [trivy](https://github.com/aquasecurity/trivy)'s `trivy repository` command on the source directory with all four of trivy's scanners: vulnerable dependencies (`vuln`), misconfigurations in infrastructure-as-code and Dockerfiles (`misconfig`), secrets (`secret`), and licenses (`license`). It is a [community plugin](index.md): it ships with ASH, and `ash scan` runs it only when its module is loaded.

ASH also has a built-in `trivy` scanner, on by default, which runs `trivy fs` with only the vulnerability scanner ([Trivy filesystem scanner](../builtin/trivy.md)). With both on, trivy runs twice and every vulnerability both find is reported twice. For a new setup, use the built-in scanner; [trivy-repo and the built-in trivy scanner](index.md#trivy-repo-and-the-built-in-trivy-scanner) compares the two.

## Install trivy

trivy-repo runs the first `trivy` it finds: on `PATH`, then in ASH's bin directory (`~/.ash/bin`, or the directory `ASH_BIN_PATH` names), then in `/usr/local/bin`. `ash dependencies install` puts the pinned trivy release, v0.75.0, checked against the SHA256 recorded in ASH, in ASH's bin directory, for the built-in scanner; trivy-repo uses the same binary. A different `trivy` on `PATH` runs instead of it. The ASH container image includes the pinned release. If no `trivy` is found, trivy-repo is MISSING and the scan exits with code 1.

## Run it

Load the module, and turn the built-in scanner off so that vulnerabilities are not reported twice:

<!-- doctest: illustrative reason="needs trivy and its vulnerability database" -->
```bash
ash scan \
  --ash-plugin-modules automated_security_helper.plugin_modules.ash_trivy_plugins \
  --config-overrides 'scanners.trivy.enabled=false'
```

Or in a config file, which a repository's own `.ash/.ash.yaml` may do:

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

trivy's SARIF is in `.ash/ash_output/scanners/trivy-repo/source/results_sarif.sarif`, and its findings are in the finding reports under `.ash/ash_output/reports/`, such as `ash.sarif`, `ash.html`, and `ash.csv`.

## What ASH runs

```text
trivy repository <online update flags> --cache-dir=<trivy cache> --cache-backend=memory
  --ignorefile=<file> --secret-config=<file> --config=<file> --module-dir=<dir>
  --format sarif --scanners vuln,secret,misconfig,license
  --license-full --ignore-unfixed --disable-telemetry <severity flag> <offline flags>
  <source directory> --output .ash/ash_output/scanners/trivy-repo/source/results_sarif.sarif

online update flags, online only:  --skip-db-update --skip-java-db-update,
                                   and --skip-check-update when the misconfig scanner is on
severity flag:                     --severity <severities>, when severity_threshold is set
offline flags, offline only:       --skip-db-update --skip-java-db-update --offline-scan --skip-check-update
```

The scanner list and the license and unfixed flags follow the options below. The four file and directory flags are always passed; how ASH chooses them is under [Files that trivy reads](#files-that-trivy-reads). The update and offline flags tell trivy not to update anything itself, because ASH has already done so or the scan is offline ([The vulnerability database and offline scans](#the-vulnerability-database-and-offline-scans)).

ASH does not pass `trivy repository --timeout`, so trivy's own default timeout of 5 minutes applies to trivy-repo, inside ASH's `scan_timeout`.

## Options

All options, with types and defaults, are in the [scanner reference](../../../reference/scanners.md#trivy-repo).

<!-- doctest: options of=scanners.trivy-repo -->
| Option | Default | Effect |
|---|---|---|
| `scanners` | `[vuln, secret, misconfig, license]` | which trivy scanners run |
| `ignore_unfixed` | `true` | report only vulnerabilities that have a fixed version |
| `license_full` | `true` | look for licenses in source file headers and license files too |
| `severity_threshold` | `null` | the threshold for this scanner's actionable findings; `null` uses the global threshold. ASH also passes it to trivy (`trivy repository --severity`), so trivy does not report findings it rates below it. `ALL` passes no severity flag. |
| `offline` | `false` | run this scanner offline even when the scan is online |
| `disable_telemetry` | `true` | pass `trivy repository --disable-telemetry` |
| `scan_timeout` | `1800` | seconds before ASH stops trivy |
| `config_file` | `null` | a trivy config file, passed as `trivy repository --config`; see below |
| `module_dir` | `null` | a directory of trivy modules, passed as `trivy repository --module-dir`; see below |
| `ignore_file` | `null` | a trivy ignore file, passed as `trivy repository --ignorefile`; see below |
| `secret_config_file` | `null` | a trivy secret-scanning config, passed as `trivy repository --secret-config`; see below |

## Files that trivy reads

trivy runs in the source directory and, without flags that say otherwise, reads a `trivy.yaml`, a `.trivyignore`, and a `trivy-secret.yaml` from there; a `trivy.yaml` can also point trivy at a directory of modules to load. A scanned repository could use those files to remove its own findings or make trivy load code. So ASH always passes trivy's config, module directory, ignore file, and secret config flags:

- `config_file`, `module_dir`, `ignore_file`, and `secret_config_file` are used only when the operator set them, with `--config-overrides` or in a config file outside every git checkout and the scanned directory, and only for a path outside every git checkout and the scanned directory. Otherwise ASH logs a warning and ignores the value. A path that does not exist fails the scan.
- With `ignore_file` or `secret_config_file` unset or ignored, ASH uses the file that `TRIVY_IGNOREFILE` or `TRIVY_SECRET_CONFIG` names, under the same path rule.
- Otherwise ASH passes an empty file, or an empty module directory, that it creates in the scanner's results directory.

A `.trivyignore`, `trivy.yaml`, or `trivy-secret.yaml` in the scanned repository is therefore never read. When neither the option nor the environment variable supplies an ignore file or a secret config, and the repository has a `.trivyignore` or `trivy-secret.yaml`, ASH logs a warning that it is not used. To ignore findings, use ASH suppressions ([Suppress findings](../../../how-to/suppress-findings.md)):

```yaml
project_name: my-service
ash_plugin_modules: [automated_security_helper.plugin_modules.ash_trivy_plugins]
global_settings:
  suppressions:
    - rule_id: CVE-2018-18074
      path: requirements.txt
      reason: "Only used by the build scripts, which never send credentials"
      expiration: "2027-01-31"
```

Or, as the operator, a trivy ignore file kept outside the repository:

<!-- doctest: illustrative reason="needs trivy and its vulnerability database" -->
```bash
ash scan \
  --ash-plugin-modules automated_security_helper.plugin_modules.ash_trivy_plugins \
  --scanners trivy-repo \
  --config-overrides 'scanners.trivy-repo.options.ignore_file=/etc/ash/trivyignore'
```

## The vulnerability database and offline scans

trivy-repo and the built-in `trivy` scanner use one trivy cache: the directory `TRIVY_CACHE_DIR` names, or else `trivy` under your user cache directory (`$XDG_CACHE_HOME` or `~/.cache` on Linux, `~/Library/Caches` on macOS).

- Online, before the scan, ASH updates the vulnerability database in that cache with `trivy image --download-db-only`, outside the scanner sandbox. When the `misconfig` scanner is on, it also fetches trivy's checks bundle. trivy then scans without updating anything itself.
- Offline (`--offline`, `ASH_OFFLINE=YES`, or the scanner's `offline: true`), ASH updates nothing and passes trivy the offline flags, so trivy uses whatever database is in the cache. `TRIVY_OFFLINE_SCAN` on its own does not stop ASH's update before an online scan.
- Either way, ASH holds the database to its age bound, 24 hours from the time it was built (trivy's own bound), and by default fails the scan when it is older. A container image built with `--offline` contains a database, so its trivy scans fail one day after the database was built unless you rebuild the image or allow stale databases. [Content databases](../../../concepts/content-databases.md) explains the bound and how to relax it.

## Sandbox

Under `--sandbox`, trivy-repo gets network access when the scan is online, read access to the trivy caches, and the `TRIVY_*` environment variables ([Enable the scanner sandbox](../../scanner-sandbox.md)). The database update before the scan runs outside the sandbox.
