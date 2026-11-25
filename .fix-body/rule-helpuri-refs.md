## fix(flat): read a rule's helpUri and tags into the flat row for every scanner

### What

Scanners declare a rule's help link (`helpUri`) and tags (`properties.tags`) once, on the SARIF rule in `tool.driver.rules`. `FlatVulnerability.from_sarif_result` read the flat `references` only from a result's `relatedLocations` and the flat `tags` only from the result's properties, so the rule-level values were dropped from every flat row (trivy, semgrep and nine other scanners declared the cells `DROPPED`).

One read at the shared seam now resolves the result's rule in its run (the same lookup the CWE read already uses) and fills `references` from `helpUri` and `tags` from the rule's tags when the result carries none of its own. Result-level values keep precedence. The tags passed to the scanner-name and severity reads stay the result's own, so a rule's severity word does not change either. The read follows the SARIF rule only: no scanner name and no tier appears in shared code, so core, alpha and SDK-shipped scanners behave alike.

Register cells flipped `DROPPED` to `MAPPED`: references for bandit, cfn-lint, zizmor, trivy, trivy-repo, guarddog, npm-audit, actionlint, cdk-nag; tags for bandit, zizmor, trivy, trivy-repo, guarddog, npm-audit, semgrep, opengrep. The semgrep and opengrep `references` cells go to `N/A` with a reason: their committed captures carry no `helpUri` (the corpus gate refuses `MAPPED` over an empty column), and the cell fails the gate as soon as a capture that carries one is committed.

The corpus gate's guarddog and cdk-nag preps now attach the adapter-built rule descriptors to the run, as the scanners write them, so the rule-level cells are observable.

### Evidence

- Red first: with the decls flipped and no reader change, the gate would fail every flipped cell; with the reader change and the old preps, the gate failed guarddog (references, tags), cdk-nag, semgrep and opengrep references (`declared mapped but the observed column is empty`), which led to the prep and semgrep/opengrep decl changes above.
- New unit tests: `tests/unit/models/test_flat_rule_help_uri_and_tags.py` (three tool names including an unknown plugin name, result precedence, empty rule, no run).

### Validation

Desk validation on a desk (repository clone, `uv sync --frozen --all-extras --group dev`, `env -i`, `-n 8`):

- Corpus gate plus the new tests: 47 passed.
- `tests/unit/plugin_modules`, `tests/unit/models`, `tests/unit/utils`: branch 42 failed / 24579 passed; main (84771d0aa4f) 42 failed / 24573 passed. The two sorted failing-id lists are identical (delta 0). The 42 are pre-existing on main.
- Locked ruff check and format check pass (pre-commit); marker scan zero with a planted control.
