## secretscanner: alpha community scanner for container-image secrets

### What it scans

Deepfence SecretScanner (`SecretScanner -output=json -image-name=<image>`) over one
container image, read through the local Docker daemon. It is an image-layer scanner:
the source tree ASH hands every scanner is not what it reads. The scanner does
nothing, and its row is SKIPPED, until the operator sets
`scanners.secretscanner.options.image_name`. A value set from a config inside the
scanned tree or by an MCP client is ignored with a warning, because it makes ASH read
an image through the Docker daemon and write what it matched into the report.

The matched text (the secret) is never copied into the SARIF. Findings carry the rule
id, the path inside the image, the image layer id, and a severity.

### Tier

Alpha, opt-in: loaded only when `ash_secretscanner_plugins` is listed in
`ash_plugin_modules`. Module: `automated_security_helper/plugin_modules/ash_secretscanner_plugins`.

### Facets declared

Both registers are declared in the scanner class (`facets`, `operational_facets`).

- Mapped: rule id, severity, file path (path inside the image), message, extras
  (image name, layer id, tool severity).
- Dropped (the native output carries it): snippet, `matches[].Data`, which is the secret.
- N/A with reasons: line range, column, resource id and type (an in-image path is a
  file locator, not a resource), package fields, CVE and CWE taxonomy, fingerprints,
  fix state, remediation text, references, tags.
- Operational: offline strategy bundled, no fetch, sandbox network none, tool JSON
  output, severity native, no tool-side silencing layer, exit code 0 only, community
  opt-in, user-installed CLI, upstream license "not read".

### Findings fixed (RESULTS row: 18/22 met, 0 MUST, 2 HIGH)

- HIGH, no sandbox-requirements test (checklist row 25): `TestSandboxRequirements`
  pins the strict default (no network, no env, no paths) on the class and an instance.
- HIGH, no captured fixture oracle (rows 24 and 18): `tests/test_data/scanners/secretscanner/captured/`
  holds `positive.json`, `negative.json`, `positive.sarif`, `negative.sarif` and a
  README. These are NOT captured from a run: Deepfence publishes no binary and none
  was available, so the JSON is written by hand from the tool's output structs at
  v2.5.8, with a placeholder where the secret would be. The README says so. The tests
  convert each JSON and compare to the SARIF beside it, and check the severity
  mapping over the positive sample. A real capture should replace them when one exists.
- Row 12 (install hint replaced by build-from-source guidance) is unchanged and
  deliberate: the vendor publishes no installable assets.

### License posture

No tool is downloaded or vendored. The scanner expects a user-installed `SecretScanner`
binary on PATH (built from source, or taken from the vendor image). Upstream license in
the operational register is "not read": the module header says MIT, but no pinned
upstream LICENSE was read, so the register does not claim it.

### Central registration owed (not made here)

Per the lane's rules, no shared file was edited. An integration lane owes these edits,
each checked on the desk against this module:

1. `automated_security_helper/core/scanner_inventory.py`: add
   `"automated_security_helper.plugin_modules.ash_secretscanner_plugins",` to
   `_VENDORED_SCANNER_PLUGIN_PACKAGES`.
2. `automated_security_helper/utils/scanner_names.py`: add `"secretscanner": "SECRETS",`
   to `SCANNER_TOOL_TYPES`.
3. `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`: add
   `"secretscanner": CorpusSpec("secretscanner", sarif=("captured/*.sarif",)),` to `CORPORA`.
4. `tests/unit/walked_package.py`: add `"plugin_modules/ash_secretscanner_plugins",`
   to `PACKAGE_DIRS`.
5. The scanner-count asserts (`== 22`) in the registry totality, operational
   consistency and corpus consistency tests move with every added scanner.
6. `tests/unit/plugin_modules/test_walking_scanners_skip_links_leaving_the_tree.py`:
   this scanner reads no file in the tree, so none of the existing link-handling
   constants describes it. It needs a handling value for a scanner that does not walk
   the tree, plus rows in `LINK_HANDLING` and `SCANNER_CLASSES`. This is a decision,
   not a one-liner.
7. Operator-only option policy: `image_name` is gated in the scanner with
   `set_by_operator`; the central lists (`config/ash_config.py`, `client_config_policy.py`)
   that name operator-only options for betterleaks and others do not yet name
   `/scanners/secretscanner/options/image_name`.
8. `UNCLAIMED_TARGET_KINDS` lists `container_image` as wired by no scanner, so this
   scanner declares the nearest kind, `secrets_contents`, and says so in `covers_note`. When this scanner lands, `container_image` can move from the
   unclaimed list to this scanner's `targets.kinds`.

### Desk validation (dev-dsk-cbc4ff77, repository extract, uv sync --frozen, env -i, -n 4)

Base: origin/main e0aac6c3aff.

- Module tests: 65 passed, 0 failed.
- Facets families (totality, corpus consistency, resource-id conformance, operational
  consistency, both vocabulary tests, scanner-list import order, walked-package) with
  central edits 1-5 applied to the desk copy only: no failure names secretscanner,
  except item 6 (the link-handling test, which is a decision). The 20 remaining
  failures are other scanners' `references` and `tags` corpus cells in
  `test_declared_facets_agree_with_the_observed_corpus`, not measured against a clean
  main.
- Whole-tree collect: 74368/74413 collected (45 deselected), 0 errors.
- ruff format --check and ruff check: clean on the module and its tests.
