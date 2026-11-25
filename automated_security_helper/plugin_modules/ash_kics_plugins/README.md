# ASH KICS Plugin

[KICS](https://github.com/Checkmarx/kics) (Keeping Infrastructure as Code Secure) finds misconfigurations in infrastructure-as-code. ASH runs it as `kics scan` over the scan target: Terraform, CloudFormation, Kubernetes, Ansible, OpenAPI, Pulumi, Azure Resource Manager, Google Deployment Manager, Dockerfile, Docker Compose and the other platforms KICS reads. ASH pins KICS v2.1.20.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_kics_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_kics_plugins
```

With the module listed, `kics` runs by default. `scanners.kics.enabled: false` turns it off again. It runs beside the builtin IaC scanners, so a misconfiguration more than one of them finds is reported by each.

## Installing the tool

The KICS release archive holds the `kics` binary only. The queries and libraries come from the same release's assets, which ASH looks for in `assets` beside the binary or in `../share/kics/assets`. Installing the module's tool puts both in place:

<!-- doctest: illustrative reason="downloads and installs the scanner's tool" -->
```bash
ash dependencies install --config-overrides "ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_kics_plugins]" --tool kics
```

## Configuration

```yaml
scanners:
  kics:
    enabled: true
    options:
      # Seconds for the whole KICS scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

KICS has no other options here: ASH fixes the queries, the config and the ignore handling so the scanned repository does not choose them.

## Central registration still owed

This module touches nothing outside its directory and its tests. Until an integration change adds the rows below, the scanner builds and scans (with a `kics` and its `assets` already on the machine) but `ash dependencies install --tool kics` has nothing to install:

- `utils/tool_downloads.py`: a `kics` entry in `TOOL_VERSIONS` (`v2.1.20`), `_ASSET_TABLES` (the six `kics_2.1.20_<os>_<arch>` archives; the release names them `linux_amd64`, `darwin_arm64`, `windows_amd64` and so on) and the digest tables, plus the pinned `assets` (queries and libraries) download that unpacks beside the binary, and a `THIRD_PARTY_LICENSES["kics"]` row (Apache-2.0).
- `utils/scanner_names.py`: `"kics": "IAC"` in `SCANNER_TOOL_TYPES`.
- `core/scanner_inventory.py`: the module in the community plugin list.
- `tests/unit/walked_package.py`: `"plugin_modules/ash_kics_plugins"` in `PACKAGE_DIRS` (until it is there, whole-tree collection stops with "not named in PACKAGE_DIRS").
- The shared register tests keep one row per scanner, and each fails until its row exists: `CORPORA["kics"]` in `test_scanner_facets_corpus_consistency.py` (`CorpusSpec("kics", sarif=("captured/*.sarif",))`); `_NATIVE_FIXTURES["kics"]` in `test_scanner_operational_facets_consistency.py` (`("kics/captured/positive.sarif", opsf.OutputFormat.SARIF)`); `_DROPPED_FIXTURES["KicsScanner"]` in `test_scanner_facets_resource_id_conformance.py` (`("kics/captured/positive.json", "search_key", "aws_s3_bucket[b].acl=public-read")`); and the scanner count, 22 to 23, in `test_scanner_facets_registry_totality.py` and `test_scanner_operational_facets_consistency.py`. With `CORPORA["kics"]` added, the corpus check reads every `kics` cell `ok` (measured over the committed captures).

## Documentation

Severity, what the scanned tree can and cannot hide, suppressions, offline use and the license: [the KICS plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/community/kics-plugin/).
