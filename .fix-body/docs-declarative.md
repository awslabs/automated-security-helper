## Docs from declarative sources, continued

### What and why

The docs-from-declarative-sources plan had three stages with no dispatched unit. This
change lands them.

- The journey schema accepts config markers. A pipeline file a page saves
  (`save-as`) and the fragment that extends it (`extends`) are stated in the journey
  file. The renderer refuses a fragment that extends a file no earlier block saves,
  a file saved as another kind, an unknown kind, and a CI key on a kind with no runner.
- `getting-started/ci.md` is now the render of
  `docs/journeys/getting-started-ci.journey.yaml`. The template and page are byte for
  byte what they were, apart from the banner below.
- Every journey render opens with the generated-file banner that the reference pages
  carry, naming the generator and the journey. This covers `local.md` too, which was
  held to byte identity with main until now.
- Allowlist burn-down, first class: the three hub pages (`reference/index.md`,
  `personas/index.md`, `docs/plugins/community/index.md`) leave the doctest allowlist.
  `tests/unit/docs/test_index_page_claims.py` reads each page's list and holds it to the
  tree and the code: the reference table to the pages and their generators, the six
  community plugins to their pages and modules, the three roles to their pages.
- Defect found by that test: the reference index left out the scanner facets page. The
  row is added.

### Overlap check

Read at origin/main `84771d0aa4f` by `git diff --name-only main...branch`:

- `docs/journey-defined-pages-proof` touches `generate_journey_pages.py`, but its
  content equals main's (the stack landed as #969); its only difference is four lines
  of the local journey that main has and it lacks. Stale, nothing to net off.
- `docs/plugin-page-table-dedup` (two community plugin pages),
  `docs/name-pytest-in-option-spans` (three contributor docs),
  `docs/field-description-backfill` and `feat/docsgen-model-enrichment-20261111`
  (generated reference pages and generator metadata) share no file with this change.
- `docs/v3-rewrite` (last commit 2026-10-11) and `docs/comprehensive-overhaul` rewrite
  the site's index pages, among 49 files, from an old base. They overlap on
  `reference/index.md` and `community/index.md` textually but are not part of any open
  PR, and a merge of either would conflict with the whole docs tree regardless of this
  change. Flagged for the maintainer, not netted off.
- None of the open PRs (1003, 1044, 1063, 1064, 1066, 1069, 1071, 981) is a docs PR.

Nothing to net off.

### Not done

- 13 pages remain on the allowlist (it had 16 on main, not 19). Next easy class:
  the two community plugin pages and three builtin scanner pages, which can be pinned
  against their plugin modules the way the gitleaks and zizmor pages are.
- The twin test for `ci.md` still holds its own step list; folding it into a `twin`
  kind of the journey is a later stage.
- On main, `test_every_page_carries_a_doctest_mechanism_or_is_on_the_shrinking_allowlist`
  is red for `how-to/deduplicate-findings.md`, which has no mechanism and is not on the
  allowlist. It is unchanged by this branch.

### Verification

Desk dev-dsk-d14420e2, repository extract, `uv sync --frozen --all-extras --group dev`,
`env -i`, `-n 8`, basetemp in the lane. Families: `tests/unit/docs`,
`test_generated_docs_freshness`, `test_docs_ci_runner_pages`,
`test_docs_ci_runner_rewrite`. Branch: 947 passed, 711 skipped, 1 failed. Main: 927
passed, 711 skipped, 1 failed. The failing id is the same on both, so the delta is
zero. `generate_journey_pages.py --check` and `verify_docs_freshness.py` (27 checks) pass.
The journey test was run red before the generator change.
