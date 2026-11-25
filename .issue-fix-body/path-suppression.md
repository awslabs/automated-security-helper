# Suppression path matching (#770), and the state of #894

## #770 — repo-relative suppression path globs vs non-relative finding paths

Already fixed on `main`; no code change in this PR. Two landed changes close
the mechanism the issue reports (suppression `path` globs compared against
finding paths that were never made repo-relative):

- Per-scanner SARIF paths are normalized to source-relative before
  suppressions are applied. `sanitize_sarif_paths`
  (`automated_security_helper/utils/sarif_utils.py`) strips `file://` forms
  (bandit's absolute `file://` URIs, the issue's second observed shape) and
  makes absolute URIs relative to the resolved source directory, with a
  resolve fallback for spelling differences added in #865 precisely because an
  absolute URI never matches a suppression `path`, which is written relative
  to the source directory.
- detect-secrets, the issue's repro scanner, now keys findings relative to the
  source directory itself: `_finding_uri` makes each result key absolute and
  then relative to the source directory, as the path sanitizer reads them
  (#830, #865), instead of reporting relative to the worker's own working
  directory (the issue's `../../source/<repo>/...` shape).

Verified with the issue's repro shape at this branch's tip (clean Linux x86_64
host, Python 3.12.15, frozen env, `--scanners detect-secrets --mode local`):

- A repo holding `tests/fixture_creds.py` with fixture secrets and the
  suppression `rule_id: "SECRET-*"`, `path: "tests/**"`: exit 0, finding
  status "0 active, 2 suppressed", and `reports/ash.unused-suppressions.json`
  reads `"used_suppressions": 1, "unused_suppressions": 0`. The merged SARIF
  reports the finding `uri` as `tests/fixture_creds.py` — repo-relative.
- The control without the suppression: exit 2 with the same two findings
  active, so the first run measures the suppression, not the fixture.

One note for the issue's own config: the repro writes
`rule_id: 'detect-secrets.*'`. ASH's detect-secrets rule ids have the form
`SECRET-<RULE>` (for example `SECRET-SECRET-KEYWORD`), and already did at
v3.7.1 (`ruleId=f"SECRET-{rule_id}"`), so that spelling matched no rule id at
filing time either; with it, the suppression still reports unused — on rule
id, not on path. Written `rule_id: "SECRET-*"` (or the concrete rule id) with
`path: "tests/**"`, the suppression behaves exactly as the issue expects.

Closes #770.

## #894 — status: not closed by this PR

#894 asks for two things. Where each stands on `main`, measured at this
branch's tip:

- **Bare-directory patterns.** A trailing-slash directory ignore path now
  matches: `tests/` is read as the directory and matches `tests/test_x.py`,
  and `**/tests/` matches at any depth (`ignore_path_pattern`). A slashless
  bare name (`tests`) still matches nothing, in both `ignore_paths` and
  `suppressions`. The open quality-sweep consolidation PR #1063 adds a
  warning-with-advice for an unused suppression whose slashless path names an
  existing directory, and deliberately leaves the matching semantics
  unchanged.
- **The rule- and path-scoped `global_settings.exclusions` proposal** is not
  implemented.

So #894 stays open, and this PR carries no Closes line for it.
