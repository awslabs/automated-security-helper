# Community scanner plugins

These scanners ship inside ASH, under `automated_security_helper.plugin_modules`, but `ash scan` loads one only when a module list names its module ([Load a plugin module](index.md#load-a-plugin-module)). Once the module is loaded, its scanner is enabled. Every option of every scanner on this page, with its type and default, is in the [scanner reference](../reference/scanners.md).

| Scanner | Module | Finds | Tool and how you get it | Network | In the container image |
|---|---|---|---|---|---|
| [`ferret-scan`](#ferret-scan) | `ash_ferret_plugins` | sensitive data and secrets | ferret-scan from PyPI, by `ash dependencies install` | none | no |
| [`snyk-code`](#snyk-code) | `ash_snyk_plugins` | code vulnerabilities (SAST) | the Snyk CLI, which you install | sends the source to Snyk | no |
| [`trivy-repo`](#trivy-repo) | `ash_trivy_plugins` | vulnerable dependencies, secrets, misconfigurations, licenses | trivy, by `ash dependencies install` | downloads trivy's database | yes |
| [`hadolint`](#hadolint) | `ash_hadolint_plugins` | Dockerfile problems | hadolint, by `ash dependencies install` | none | yes |
| [`guarddog`](#guarddog) | `ash_guarddog_plugins` | malicious-package patterns | GuardDog from PyPI, by `ash dependencies install` or at scan time | none, unless `verify` is on | yes |

Module names in this table are short: the full name is `automated_security_helper.plugin_modules.` followed by the module.

`ash dependencies install` installs a community scanner's tool only while its module is loaded, and the command has no `--ash-plugin-modules` option, so name the module with a config override:

<!-- doctest: illustrative reason="downloads the tool from its release page" -->
```bash
ash dependencies install \
  --config-overrides 'ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_hadolint_plugins]' \
  --tool hadolint
```

Without the override, `--tool hadolint` fails with "Unknown tool(s): hadolint", and a bare `ash dependencies install` skips the community tools. See [Manage scanner tools](../docs/advanced-usage.md) for where ASH looks for tools.

## ferret-scan

Finds sensitive data, such as credit card numbers, passport numbers, Social Security numbers and API keys, in source files and in documents (PDF and Office files) that ferret-scan extracts text from.

- Tool: the `ferret-scan` command from PyPI, version `>=2.4.5,<2.6.0`. `ash dependencies install` runs `pip install` into the Python environment that runs ASH, which fails when that environment has no pip, as in an environment that uv created. You can instead install `ferret-scan` into any environment whose `ferret-scan` command is on `PATH`. It is not in the container image.
- Options: `confidence_levels`, `checks`, `profile` and `exclude_patterns` choose what is reported; `finding_limit` (default 0, no limit) caps the number of findings; `fail_on_incomplete` records a file that ferret-scan could not scan completely as an incomplete run; `config_file` names a ferret-scan config. [All options](../reference/scanners.md#ferret-scan).
- Network: none.
- Restrictions: a ferret-scan config file inside a git checkout or the scanned directory is never passed to the tool, whether `config_file` names it or ASH finds it by name (`ferret.yaml`, `.ferret.yaml`); the config bundled with the plugin is used instead.

```yaml
project_name: my-service
ash_plugin_modules: [automated_security_helper.plugin_modules.ash_ferret_plugins]
scanners:
  ferret-scan:
    enabled: true
    options:
      confidence_levels: "high,medium"
```

## snyk-code

Runs `snyk code test` on the source directory.

- Tool: the Snyk CLI (`snyk`) on `PATH`, authenticated with `SNYK_TOKEN` or `snyk auth`. ASH never installs it, and the container image does not include it.
- Options: `severity_threshold`, which ASH also passes to Snyk (`snyk code test --severity-threshold`), so findings below it are not reported at all. [All options](../reference/scanners.md#snyk-code).
- Network: required. Snyk Code uploads the scanned source to Snyk for analysis. ASH applies `ignore_paths` to Snyk's results after the scan and does not pass them to the Snyk CLI, so ignored directories are uploaded too. In offline mode the scanner is reported MISSING, which fails the scan.
- Restrictions: operator-only. A config file inside a git checkout or the scanned directory, or one an MCP client delivered, cannot load `ash_snyk_plugins`. Name it with `--ash-plugin-modules`, `ASH_PLUGIN_MODULES`, `--config-overrides` or a config file outside every git checkout and the scanned directory.
- Known defect: when Snyk reports any issue, the `snyk` command exits with code 1, and this release records snyk-code as ERROR with no findings and fails the scan with exit 1. A Snyk run that finds nothing is reported as PASSED.

This config is meant for a file outside every git checkout, passed with `--config`:

```yaml
project_name: my-service
ash_plugin_modules: [automated_security_helper.plugin_modules.ash_snyk_plugins]
scanners:
  snyk-code:
    options:
      severity_threshold: HIGH
```

## trivy-repo

Runs `trivy repository` on the source directory with trivy's vulnerability, secret, misconfiguration and license scanners, reporting only vulnerabilities that have a fix.

- Tool: trivy, the same pinned, checksum-verified release that the built-in `trivy` scanner uses, installed by `ash dependencies install`. The container image includes it.
- Options: `scanners` (default `[vuln, secret, misconfig, license]`), `ignore_unfixed` (default `true`), `license_full` (default `true`), `severity_threshold`, which is also passed to trivy and so removes lower findings from the report. [All options](../reference/scanners.md#trivy-repo).
- Network: online, trivy downloads its vulnerability database before the scan. Offline, it uses the database already in its cache. Either way ASH holds that database to a 24-hour age bound and, by default, fails the scan when it is older ([Content databases](../concepts/content-databases.md)).
- Restrictions: `config_file`, `module_dir`, `ignore_file` and `secret_config_file` are used only when the operator set them and they are outside every git checkout and the scanned directory. A `trivy.yaml`, `.trivyignore` or `trivy-secret.yaml` in the repository is not read.

### trivy-repo and the built-in trivy scanner

ASH also has a built-in `trivy` scanner, enabled by default, which runs `trivy fs` on the same directory with only the vulnerability scanner. Both read the same trivy database. If you load `ash_trivy_plugins` and leave the built-in scanner on, trivy runs twice, and every vulnerability both find is reported once by each scanner, because ASH does not deduplicate findings.

For a new setup, use the built-in `trivy` scanner and set its `scanners` option to get the coverage trivy-repo has:

```yaml
project_name: my-service
scanners:
  trivy:
    options:
      scanners: [vuln, secret, misconfig, license]
```

If you already use trivy-repo, turn the built-in scanner off:

```yaml
project_name: my-service
ash_plugin_modules: [automated_security_helper.plugin_modules.ash_trivy_plugins]
scanners:
  trivy:
    enabled: false
  trivy-repo:
    options:
      scanners: [vuln, secret, misconfig]
```

The two scanners do not have the same defaults: trivy-repo reports only vulnerabilities that have a fix and looks for licenses in file headers, and the built-in scanner does neither unless you set `ignore_unfixed` and `license_full`.

## hadolint

Status: pending licensing review. The review covers the third-party components that ASH's container image would redistribute for this plugin: the hadolint binary and the libraries statically linked into it.

Lints Dockerfiles, with hadolint's own rules (DL codes) and ShellCheck's rules for `RUN` commands (SC codes). It scans files named `Dockerfile`, `Containerfile`, `*.Dockerfile` and `Dockerfile.*`, matched case-sensitively. A tree with none is reported SKIPPED. A Dockerfile that hadolint cannot parse is counted as not evaluated, which makes the scan incomplete (exit 1).

- Tool: hadolint 2.15.1, a pinned, checksum-verified release binary, installed by `ash dependencies install` with the module loaded (above). The container image includes it. ASH does not install it during a scan; a `hadolint` already on `PATH` is used whatever its version. Nix mode uses the hadolint that nixpkgs provides.
- Options: `config_file`, a hadolint config. [All options](../reference/scanners.md#hadolint).
- Network: none.
- Restrictions: hadolint always gets an explicit `--config`. `config_file` is used only when the operator set it and the file is outside every git checkout and the scanned directory; otherwise hadolint gets an empty config, so a `.hadolint.yaml` in the repository is not read.

```yaml
project_name: my-service
ash_plugin_modules: [automated_security_helper.plugin_modules.ash_hadolint_plugins]
scanners:
  hadolint:
    enabled: true
```

## GuardDog

Status: pending licensing review. The review covers the third-party components that ASH's container image would redistribute for this plugin: GuardDog and its pygit2 dependency, with the libgit2 library bundled in pygit2's package.

Looks for the patterns malicious packages use, such as an install hook that downloads and runs code, in each package in the repository. A package is a directory holding a manifest of one of GuardDog's ecosystems: `setup.py`, `setup.cfg` or `pyproject.toml` (pypi); `package.json` (npm); `go.mod` (go); `action.yml` or `action.yaml` (github_action); a `*.gemspec` (rubygems); `Cargo.toml` (crates).

- Tool: GuardDog 3.2.0 from PyPI, installed with `uv tool install` for Python `>=3.10,<3.14`. `ash dependencies install` installs it with the module loaded, and an online scan installs it if it is missing. The container image includes it. It is SKIPPED on Windows, where it cannot be installed, and it is not available in nix mode.
- Options: `ecosystems` (all six by default); `rules` or `exclude_rules`; `excluded_paths`; `sandbox` (`auto`, `required` or `disabled`), which controls GuardDog's own kernel sandbox; `verify`. [All options](../reference/scanners.md#guarddog).
- Network: none for the default scan, which reads only the repository's files. With `verify: true`, GuardDog also downloads every dependency the manifests declare, from their registries, and scans each one; this is refused in offline mode, and it fails under ASH's `--sandbox`, which gives the scanner no network.
- Restrictions: GuardDog has no path options, and a repository's own config can set all of its options, including `verify` (which makes the scan download the repository's declared dependencies) and `tool_version` (which chooses the GuardDog release that ASH installs). To keep these choices yours, pass your own config with `--config`, so that the repository's config is not read.

```yaml
project_name: my-service
ash_plugin_modules: [automated_security_helper.plugin_modules.ash_guarddog_plugins]
scanners:
  guarddog:
    enabled: true
    options:
      ecosystems: [pypi, npm]
      excluded_paths:
        - path: "vendor/**"
          reason: "Vendored third-party code"
```
