# URL history: every URL the docs site ever served keeps working

This directory holds the record that makes the promise checkable, and CI holds the
promise: a link or bookmark to any URL the documentation site ever served lands on
the page that owns that subject today.

This is not a page source directory. It sits beside `docs/redirects.yml`, outside
`docs/content` (mkdocs's `docs_dir`), so nothing here is built into the site.

## The files

- `historical-urls.tsv` - the ledger of every rename (R) and deletion (D) of a served
  docs page, per release-tag pair, in URL space. Generated 2026-11-25 from this
  repository's git history (the header describes how); append rows when a release
  renames or deletes a page, never rewrite history rows. The distinct old URLs are
  the universe the validator checks coverage of.
- `url-redirect-map.json` - the map from each historical URL that stopped being
  served with no redirect to the URL of the page that covers its subject now, with
  the rule each mapping was chosen by, the section-fallback list for maintainer
  review, and a `tombstones` list for URLs deliberately left dead (empty today).

## How a historical URL stays covered

1. `docs/redirects.yml` carries one entry per dead URL (old page path -> new page
   path). The map in this directory is the source of truth for which URL goes where;
   the yml entry is its materialization, and CI fails when the two disagree.
2. `docs/hooks/redirects.py` writes a redirect page at every old URL in each version
   the site builds: canonical link to the target, `robots: noindex`, a
   hash-preserving `location.replace`, and a meta-refresh fallback.
3. `scripts/docs_versions.py` mirrors every page of the default version - the
   redirect pages included - as stubs at the site root, so the bare historical URL
   (no version prefix) redirects too.

## How CI validates it, across releases

`scripts/validate_url_history.py` (standard library only, run as
`python -I -B scripts/validate_url_history.py --site-dir public` after a build):

- every mapped target is a real page, in `docs/content` and in the built tree;
- every ledger URL is served, redirected, or tombstoned - nothing falls through;
- no redirect chains or loops, within `docs/redirects.yml`, within the map, or
  between them;
- in the built tree, every ledger URL resolves to a real page within a bounded
  number of redirect hops.

It runs in the `build-docs` job on every pull request and merge queue entry, and in
the docs deploy workflow on every publish - a push to main and every release tag -
so each release re-validates the mapping against its own build. Validating the tree
the checkout builds, never the deployed gh-pages branch, is what keeps the check
honest while main is ahead of the deploy. The unit tests
(`tests/unit/scripts/test_validate_url_history.py`) hold the validator itself to its
job with planted-bad fixtures: a missing target, a chain, a loop, an uncovered URL,
a shadowed URL, and a broken built-site stub each have a test that fails if the
validator stops flagging them.

## Choices made, and what was rejected

- Targets are root-level URLs (`/reference/cli/`), not version-pinned ones
  (`/main/reference/cli/`): the published `versions.json` has no `latest` alias yet
  and the root stubs track the default version, so root-level targets keep tracking
  whatever becomes canonical (once the first release publishes with mike, `latest/`)
  instead of pinning a version that goes stale.
- `docs/redirects.yml` entries rather than hand-written gh-pages stubs or a
  `404.html` lookup table: the repository already has the hook, the root-stub
  mirroring and the lint checks for yml entries, so the dead URLs ride the same
  machinery as every other moved page, and nothing new runs in the reader's browser.
- The 36 one-day beta API-module URLs (`/docs/development/api/...`) are mapped to
  the reference section that covers each module today rather than tombstoned; they
  are all in the map's `fallbacks` list, and moving any of them to `tombstones` is
  a one-line map change the validator then enforces.

## Limits

- The ledger records whole pages; anchor-level moves (`page/#section`) are out of
  scope here. `scripts/docs_checks.py check_nav` validates anchors named in
  `docs/redirects.yml` targets.
- The root-level hop the deployed site adds (historical URL at the root -> the same
  path under the default version -> the target) is exercised by
  `scripts/docs_versions.py check`, not by this validator, which sees the
  unversioned build.
- Version trees already published on gh-pages are immutable history; new redirect
  entries reach the deployed site when the next version publishes and the root
  stubs are rewritten.
