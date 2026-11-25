## feat(scanners): add the cdxgen alpha scanner plugin (SBOM)

### What it scans

cdxgen (CycloneDX Generator, `@cyclonedx/cdxgen`, Apache-2.0) inventories the
components a source tree uses and writes a CycloneDX document. It reports no findings,
so the scanner overrides `scan()` and returns a `CycloneDXReport`, the way the builtin
syft scanner does. Every run passes `--spec-version=1.6` (the version ASH models) and
`--no-install-deps` (cdxgen's default would run the scanned project's package manager
over code the tree controls). The scanner runs cdxgen from outside the scanned tree so
a `.cdxgenrc` or `package.json` section in the tree cannot configure it, and excludes
ASH's own output directories from the inventory.

### Tier

Alpha, opt-in: it loads only when `ash_cdxgen_plugins` is listed in
`ash_plugin_modules`. The scanner is enabled by default once its module is listed.
Install: `@cyclonedx/cdxgen` 12.9.2 from npm through the npm package manager on every
platform Node.js runs on; the scanner reports a missing `cdxgen` executable instead of
scanning.

### Facets declared

- Mapping register (`facets`): every facet is n/a. An SBOM has no findings and the
  document bypasses the flat findings path, so there is no Result to map. The package
  name and version cells say where the values live (the document's `components[]`)
  and why the register has nothing to observe.
- Operational register (`operational_facets`): network `none` (strict-default sandbox,
  `--no-install-deps`; one unconfirmed row recorded: any other registry lookup under
  that flag), output CycloneDX, target `package_inventory` (SBOM tool type), runtime
  user-installed CLI with `node` as the external program, severity and identity not
  applicable, exit codes `{0}`, tier community opt-in, prerequisite Node.js runtime,
  upstream license recorded as `not read` (see License).

### Findings fixed (RESULTS row for cdxgen)

The row scored 20 of 22 applicable checklist rows with 0 MUST and 2 HIGH, both fixed:

- HIGH, checklist row 24 (no captured real-tool fixtures): a real cdxgen 12.9.2 run on
  a one-line `requirements.txt` is committed unedited at
  `tests/test_data/scanners/cdxgen/captured/cdxgen_pypi_requirements.cdx.json`, with a
  README recording the argv, version and input. `test_cdxgen_captured_output.py` reads
  it through the scanner, with a negative control (components removed reads empty).
- HIGH, checklist row 25 (no sandbox-requirements test): `test_cdxgen_sandbox_requirements.py`
  builds the policy through `build_scanner_policy` and asserts no network, the baseline
  read-only paths and the baseline environment allowlist, with a control showing a
  network grant would be visible.
- Facets: the scanner declares both registers (the registry totality test is fail
  closed).

No MUST was recorded for this row.

### License posture

cdxgen is Apache-2.0 per the license check, and ASH does not redistribute it: the
scanner installs the pinned release from npm on the host. There is no vendored
material and no license-gated no-install design to preserve. The operational register
carries `upstream_license="not read"` until a pinned upstream LICENSE read supplies a
`(source: ...)` citation; no license name is recorded from recall.

### Central registration owed (not made here; an integration lane serializes these)

Adding a scanner class to the in-repo plugin packages moves shared tables and counts
that this module deliberately does not edit. Measured on the desk, these are the only
cdxgen-attributable reds, and each goes green with the edit named:

1. `automated_security_helper/utils/scanner_names.py`: add `"cdxgen": "SBOM",` to
   `SCANNER_TOOL_TYPES` (next to the `guarddog` row). Clears
   `test_tool_type_is_one_story_across_four_declarations[CdxgenScanner]` (KeyError).
2. `tests/unit/walked_package.py` `PACKAGE_DIRS`: add `"plugin_modules/ash_cdxgen_plugins",`
   (next to the guarddog line 54). Without it `tests/unit/test_walked_package.py` fails
   at collection, which interrupts a whole-tree collect.
3. The shipped-scanner count (22 to 23) in `test_scanner_facets_registry_totality.py`,
   `test_scanner_facets_corpus_consistency.py` and
   `test_scanner_operational_facets_consistency.py`, and a `CORPORA` row
   `"cdxgen": None` with the fixture-to-author reason (cdxgen has no SARIF corpus).
4. Opt-in listings, as for guarddog: `automated_security_helper/core/scanner_inventory.py`
   (community module list), `.ash/.ash_community_plugins.yaml`, the Dockerfile
   `ASH_COMMUNITY_PLUGIN_MODULES` args, and the CI plugin-module lists
   (`.github/workflows/ash-unified-ci.yml`, `.github/actions/validate-container/action.yml`),
   each only when the combined PR enables the module by default for those paths.

### Desk validation

dev-dsk-d14420e2, lane under `/run/user/23503848/`, repository shipped, `uv sync
--frozen --all-extras --group dev`, `env -i` with `CI=1`, `-n 4`, `--basetemp` in the
lane.

- cdxgen module tests (behavior, captured output, sandbox requirements): 39 passed, 0 failed.
- Facets registry, totality, corpus, resource-id and operational families (4 files):
  470 passed, 24 failed. 20 of the failures are
  `test_declared_facets_agree_with_the_observed_corpus[<other scanner>]`, which fail
  identically with the cdxgen module removed (measured), so they are not this change's.
  The remaining 4 are the central rows above (items 1 and 3).
- Whole-tree collect: 74302 of 74347 collected, 1 error: `test_walked_package.py`, the
  central row in item 2.
- A real cdxgen 12.9.2 run produced the committed capture (exit 0).
