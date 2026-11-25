## kube_linter: alpha community scanner plugin

Adds KubeLinter (`kube-linter lint`) as an opt-in alpha scanner module,
`automated_security_helper.plugin_modules.ash_kube_linter_plugins`. A scan that does not
list the module in `ash_plugin_modules` is unchanged.

### What it scans

Kubernetes manifests, Helm charts and Kustomize directories (KubeLinter renders the
last two itself). ASH passes an empty stub config, so the checks are KubeLinter's
defaults and a `.kube-linter.yaml` in the scanned tree cannot switch checks off. Tier:
alpha, opt-in. `tool_type` IAC.

### Severity

KubeLinter's SARIF has no level. ASH rates by check name: the checks in
`HIGH_SEVERITY_CHECKS` (privileged containers, host namespaces, the Docker socket,
privilege escalation, wildcard and cluster-admin RBAC) are HIGH and every other check is
MEDIUM. Nothing is CRITICAL.

### Facets declared

- `facets`: rule_id, severity, file_path, line_range, message, extras are MAPPED.
  resource_id and resource_type are N/A on purpose: the object appears only as
  `<namespace>/<name>` in the message text, with no kind, so no resource id is written.
  The remaining cells are N/A with the register's reasons (output not read where it was
  not read).
- `operational_facets`: network none (BUNDLED, helm dependency fetch unconfirmed),
  SARIF output, IAC_KUBERNETES target, runtime USER_INSTALLED_CLI (no central pin),
  severity DERIVED, inline-annotation silencing UNCONFIRMED, positional-only identity,
  exit codes {0, 1}, community opt-in, Apache-2.0.

### Review findings fixed (RESULTS row for kube_linter)

- MUST: the shipped install-commands test errored because
  `pinned_tool_install_commands("kube-linter")` raised `ToolNotProvisionableError` at
  construction (no pin in `tool_downloads.py`). Construction now catches it and leaves
  the table empty; the install test asserts both states. The install hint no longer names
  a `ash dependencies install` command that cannot work.
- HIGH, row 22: the timeout test's wiring assertion could not fail. It now matches
  `timed out after` and asserts the 1800 s limit reached the subprocess call, plus a test
  that `scan_timeout=42` reaches it.
- HIGH, row 25: added a sandbox-requirements test (strict default, no network).
- HIGH, rows 18 and 24: severity and location are now also tested over fixture files in
  `tests/test_data/scanners/kube_linter/recorded/`. These are hand-built to the v0.8.3
  formatter's shape, not captured (the binary was not available); the directory is named
  `recorded/` rather than `captured/` and its README says how to replace them with a real
  capture. This row stays partly open until a real run is committed.

### License posture

Apache-2.0 (KubeLinter at v0.8.3). No license gate applies; nothing is vendored.

### Central edits owed (not made here; the integration lane serializes them)

1. `automated_security_helper/utils/tool_downloads.py`: add the `kube-linter` pin
   (version, release base URL, asset table, `THIRD_PARTY_LICENSES` entry). Then switch
   the runtime row to PINNED_BINARY with `tool_versions_key="kube-linter"` and the
   provenance source to PINNED_RELEASE_BINARY.
2. `automated_security_helper/utils/scanner_names.py`: `"kube_linter": "IAC",` in
   `SCANNER_TOOL_TYPES`.
3. `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`: a `CORPORA`
   row `"kube_linter": CorpusSpec("kube_linter", sarif=("recorded/*.sarif",))`, and the
   shipped-scanner count 22 to 23 here and in `test_scanner_facets_registry_totality.py`
   and `test_scanner_operational_facets_consistency.py`.
4. `tests/unit/walked_package.py`: `"plugin_modules/ash_kube_linter_plugins",` in
   `PACKAGE_DIRS` (a whole-tree collect errors without it).

### Validation

Run on a dev desktop from a repository extract, `uv sync --frozen --all-extras --group dev`,
`env -i`, `-n 4`. With edits 2 to 4 applied in the extract only: module tests 59 passed;
facets registry totality, resource-id conformance, vocabulary and operational consistency
families 0 failed for kube_linter (572 passed in the families run; the 20 failures are the
corpus-gate rows of other scanners, each failing on that scanner's own missing or unconverted corpus; a main-only baseline run was not done);
whole-tree collect 74360 tests, 0 errors. `ruff format --check` and `ruff check` green.
