## fix(facets): observe snyk-code, grype and ferret-scan in the corpus gate

### What

The facets corpus gate joins each scanner's declared cells with what its committed fixtures show in the flat row. Three scanners had no corpus (snyk-code, grype, ferret-scan), so #1054 declared their unread cells n/a. The gate could not distinguish drift from never-measured on them.

This adds a corpus and a prep for each, then flips the cells to the states the gate observes:

- snyk-code: an authored, sanitized SARIF in the shape `snyk code test --sarif` writes (`tests/test_data/scanners/snyk/authored/`, with a README that says it is authored, not captured). The prep applies the adapter's own `normalize_rule_cwe_into_tags`. Seven cells move from n/a to mapped: rule_id, severity, file_path, line_range, message, taxonomy_cwe, fingerprints.
- grype: a real `grype -o sarif` capture, grype 0.122.1 (the pinned release, sha256 checked) over the committed syft SBOM (`captured/grype-0.122.1-from-syft-sbom.sarif`, 21 results). The prep runs the adapter's `_post_process_sarif`. Nine cells move to mapped (rule_id, severity, file_path, line_range, message, package_name, package_version, fingerprints, fix_available), plus column. taxonomy_cwe's reason now states what the capture shows.
- ferret-scan: a real `ferret-scan --format sarif` capture, 2.5.3, over the committed `sample.txt` (108 results). The prep applies the adapter's base-relative URI resolution. Five cells move to mapped; fingerprints stays n/a with the observed reason (no result carries fingerprints).

Three operational cells are settled from reads:

- ferret-scan identity: positional only (no fingerprints in the capture).
- grype identity: `partialFingerprints.primaryLocationLineHash`, a per-manifest-line hash (6 distinct values over 21 results), so findings on one line share it.
- opengrep prerequisite: a copy of `opengrep/fixture_repo` with no `.git` scanned with opengrep 2.0.0 (sha256 checked) exits 0 with the same one finding as a git copy. The prerequisite is `none`; the git ls-files / safe.directory behavior is kept as a note.

snyk-code's platform note now records the adapter read: the bare `snyk` command on PATH with no per-OS branch, and `_hold` returns None where `fcntl` is missing.

Discovery stays uniform across tiers. The gate reads every `plugin_modules` package's `ASH_SCANNERS` the same way (core, the alpha `ash_*_plugins` packages, and any package a plugin ships), and a new test asserts the registered set equals the union of those lists, spans more than one package, and names no tier. Preps are keyed by scanner name only.

### Evidence

Red first: with the snyk corpus and prep registered but the cells still n/a, the gate refused seven snyk cells (`snyk-code rule_id n/a 2/2 FAIL`, and likewise severity, file_path, line_range, message, taxonomy_cwe, fingerprints). The same step for grype refused nine cells (21/21) and for ferret-scan five (108/108). After the flips: 374 ok, 66 excluded, 0 FAIL over 440 cells.

| Check | Result |
| --- | --- |
| Facets family (7 files) | 525 passed, 1 skipped |
| `tests/unit/plugin_modules` + docs freshness + facet vocabulary, `-n 8` | 9002 passed, 432 skipped, 0 failed |
| Same families on main, same desk | 8972 passed, 432 skipped; failing-id delta 0 |
| `ruff format --check`, `ruff check` | clean |
| Conflict-marker scan (planted control reads 1) | 0 in every touched file |
| Whole-range identity audit | one noreply line for author and committer |

Run on dev-dsk-d14420e2 as a repository, `uv sync --frozen --all-extras --group dev`, `env -i`, `--basetemp` in the lane.

### Not touched

- The spdx license cells (`scanner_operational_facets.py`): recording a license determination needs explicit approval, so they stay "not read".
- The cfn-nag facets row has no cell owed at this tip: #1057 already settled each against the captured SARIF and JSON, and the gate reads it as ok. Its tool-side silencing cell (template Metadata suppressions, UNCONFIRMED) and the grype and snyk silencing cells are separate operational reads left as they are.
- grype's package_path, taxonomy_cve and snippet cells and the grype and snyk fix_available / references cells keep their reasons: the grype capture is over a Ruby and PyPI SBOM (no npm tree, GHSA ids only), and snyk's shape is authored, not captured.
- Trivy and semgrep declare references from the rule's helpUri while the flat reader reads related locations: that is its own finding and is not in this change.

### Validation notes

The captured files hold no host paths or credentials (read with a path and secret scan). The two cdk-nag container-deps tests that pass on main failed in a first run only because the desk venv's editable install pointed at the main copy; with the change inside that tree they pass.
