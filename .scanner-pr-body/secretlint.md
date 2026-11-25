## Secretlint alpha scanner plugin

Adds `ash_secretlint_plugins`, an alpha-tier (community, opt-in) scanner module that
runs [Secretlint](https://github.com/secretlint/secretlint) 14.0.1 over the scan target
and converts its SARIF into ASH findings. A scan that does not list the module in
`ash_plugin_modules` is unchanged.

### What it scans

Secrets in file contents (not git history), through a `**/*` glob that Secretlint walks
itself. ASH passes the recommended preset inline with `--secretlintrcJSON`, so a
`.secretlintrc.*` in the scanned tree never picks the rules. Secretlint's secret masking
stays on, so reports hold no secret value. `--no-gitignore` is passed so gitignored files,
where credentials often sit, are scanned.

### Tier and install

Alpha, opt-in. Secretlint and `@secretlint/secretlint-formatter-sarif` are installed from
the npm registry at the exact pinned version `14.0.1` (`ash dependencies install`). They
need Node.js 22 or later. No binary is downloaded or redistributed by ASH.

### License posture

MIT for both npm packages (read from the LICENSE and package.json of the 14.0.1 packages).
No license gate applies. Nothing is vendored, so there is no redistribution question; the
deliberate no-download design (npm install by the operator) is kept.

### Facets declared

- Mapping register (`facets`): rule id, severity, file path, line range, column and
  message are mapped. The rule documentation link (`helpUri`) is declared mappable but
  dropped. Resource id and type, package fields, CVE and CWE taxonomy, fingerprints, fix
  state, remediation text, snippet and tags are n/a, each with a reason. Tags are n/a
  because the native SARIF has none: the adapter's `secret` and `security` tags are not
  a native field. `extras` maps the adapter-written `issue_severity`.
- Resource identity: n/a (a secret names a file location, not a deployable resource).
- Operational register (`operational_facets`): no network (BUNDLED), SARIF output,
  secrets-in-contents target, user-installed CLI runtime needing Node.js, native severity,
  repository-writable `.secretlintignore` and `secretlint-disable` layers (both honored,
  declared), positional identity, no rules extensibility, success exit code `{0}`,
  community opt-in tier, MIT.
- Sandbox: the strict default (no network, baseline environment), pinned by a policy test
  built through `build_scanner_policy`.

### Findings fixed

From the build-program results row for this scanner (22 of 24 applicable checklist rows
met at the commissioned tip):

- HIGH, no captured tool output as the test oracle (checklist rows 18 and 24): added
  `tests/test_data/scanners/secretlint/captured/` with a real positive and a real
  negative report from Secretlint 14.0.1 (with a README giving argv, inputs and the
  facts the captures show), and a `TestCapturedReports` class that runs the conversion
  over them.
- Unmet row 25, thin sandbox declaration test: added
  `tests/unit/plugin_modules/test_secretlint_sandbox_requirements.py` using
  `build_scanner_policy`.
- A committed test that cannot pass on current main (found while replaying onto main):
  an unlevelled result was rated CRITICAL, but ASH's SARIF model now reads a missing
  level as SARIF's default `warning`, so the result was MEDIUM. The scanner and its
  docs now say so, the test pins the real behavior, and a separate test pins that a level
  outside the table (for example `none`) is CRITICAL.
- A committed test whose `_plugin_log` stand-in took one positional argument while the
  base scan logs several: the stand-in now takes `*msgs`.

### Central registration still owed (an integration lane makes these)

No file outside the module, its tests and its facets declarations was edited. Current main
needs these edits for the scanner to be fully registered:

1. `automated_security_helper/core/scanner_inventory.py`: add
   `"automated_security_helper.plugin_modules.ash_secretlint_plugins",` to
   `_VENDORED_SCANNER_PLUGIN_PACKAGES`.
2. `automated_security_helper/utils/scanner_names.py`: add `"secretlint": "SECRETS",` to
   `SCANNER_TOOL_TYPES`.
3. `tests/unit/walked_package.py`: add `"plugin_modules/ash_secretlint_plugins",` to the
   package directory list (a whole-tree collect currently errors on it).
4. `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`: add
   `"secretlint": CorpusSpec("secretlint", sarif=("captured/*.sarif",)),` to `CORPORA`.
5. The pinned counts of shipped scanners move from 22 to 23 in
   `test_scanner_facets_registry_totality.py`,
   `test_scanner_operational_facets_consistency.py` and the registry/corpus agreement test.

Generated docs, schemas and inventory rows follow from those edits.

### Desk validation (dev-dsk-d14420e2, `uv sync --frozen --all-extras --group dev`, `env -i`, `-n 4`)

- The scanner's own tests (behavior, captured reports, sandbox policy): 50 passed, 0 failed.
- Facets registry, operational consistency, resource-id conformance and vocabulary
  families, secretlint cells: 19 passed, 0 failed, with edits 2 and 4 above applied to the
  desk extract only.
- Whole-tree collect: 74313 collected, one collection error, the `walked_package.py`
  entry (edit 3 above).
- The same families also fail 20 corpus-consistency cells for other scanners (tags and
  references observed empty), identically for `betterleaks`, which this change does not
  touch, so they are not caused by this module.
- Gates: `ruff format --check` and `ruff check` pass (pre-commit, locked ruff); no
  conflict markers; the `origin/main..HEAD` author and committer audit shows one noreply
  identity.
