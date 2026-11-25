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
MEDIUM. Nothing is CRITICAL. Five of the HIGH entries (`access-to-create-pods`,
`access-to-secrets`, `cluster-admin-role-binding`, `privileged-ports`, `wildcard-in-rules`)
are not among KubeLinter 0.8.3's 31 default checks, so a scan with ASH's stub config never
reports them (measured: a cluster-admin binding and a wildcard ClusterRole read "No lint
errors found!"). Enabling them would change what a scan reports and is left to the owner.

### Facets declared

- `facets`: rule_id, severity, file_path, line_range, message, extras are MAPPED.
  resource_id and resource_type are N/A on purpose: the object's name, namespace and kind
  are in the result's `logicalLocations` and message tail, but the adapter does not read
  them, and no resource id is written from prose. The remaining cells are N/A with the
  register's reasons, each read against the captured run.
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
- HIGH, rows 18 and 24: severity and location are now also tested over the files a real
  `kube-linter 0.8.3` run wrote, committed under
  `tests/test_data/scanners/kube_linter/captured/` with the inputs, the argv, the version
  and the binary's sha256 in its README. The capture settled three cells the register had
  left open (no fingerprint on a result; remediation and help URI sit on the driver's
  rules, not the result) and showed the object kind is present in the result (message tail
  and `logicalLocations`), so the resource_id and resource_type reasons now say the adapter
  does not read it rather than that the output has no kind.

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
   row `"kube_linter": CorpusSpec("kube_linter", sarif=("captured/*.sarif",))`, and the
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
whole-tree collect 72858 tests, 0 errors (re-run on main e0aac6c3aff, desk cbc4ff77:
module 59 passed, conformance 61 passed, vocabulary 40 passed, totality/operational/corpus
families 472 passed with kube_linter's own rows green). `ruff format --check` and `ruff check` green.
