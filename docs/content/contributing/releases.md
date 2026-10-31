# Releases and versions

ASH versions come from commit messages. [commitizen](https://commitizen-tools.github.io/commitizen/)
reads the subjects on `main` since the last tag, picks the next version, writes the
changelog entry, and rewrites the files that pin the version. A release is a git tag
and a GitHub Release: nothing is published to PyPI or to a container registry, so users
install ASH from a git URL at a tag (see [Install ASH](../how-to/install.md)). This page
explains each piece, for contributors who need to know what their commit message does
and for maintainers who cut releases.

## Where the version is kept

The version is `version` in the `[tool.commitizen]` table of `pyproject.toml`.
`[project] version` holds the same value: commitizen rewrites both, and
`tests/unit/test_agent_plugin_ash_version.py` fails if they differ. To print it:

<!-- doctest: illustrative reason="runs in a checkout of this repository" -->
```bash
uv run cz version --project
```

An installed ASH reports the version in its package metadata with `ash --version`.

Other files pin an ASH tag that users install from: the Homebrew formula, the sources
of the agent plugins, the install commands in the README and in these docs, the ASH
version that each deployment target in `deploy/` installs when none is given, and the
CodeBuild example in `examples/`. Each is kept current in one of two ways:

- It is listed in `version_files` under `[tool.commitizen]`, and `cz bump` rewrites the
  version in it. The release runs `cz bump --check-consistency`, so a listed file that
  does not contain the current version fails the release before anything is tagged.
  After the rewrite, a `pre_bump_hooks` entry rebuilds the generated agent plugin trees
  so they land in the same commit.
- It is a template. See [Version-pinned pages](#version-pinned-pages).

`tests/unit/test_agent_plugin_ash_version.py` also walks the whole tree for install
references to this repository, such as `automated-security-helper.git@v<version>`, and
fails when one names a version other than the current one. So a new page that pins a
release has to be a template or be listed in `version_files`, or the unit suite fails
at the next release. A floating `@v3` and a `{{VERSION}}` placeholder are not version
pins and pass.

## How the next version is chosen

commitizen reads the subject of each commit on `main` since the last release tag, and
the `BREAKING CHANGE:` footers in their bodies. Pull requests are squash-merged, so each
pull request is one commit (see
[Commit messages and pull request titles](index.md#commit-messages-and-pull-request-titles)).
The largest increment wins:

| Commit | Increment |
|--------|-----------|
| a `!` before the colon, or a `BREAKING CHANGE:` footer | major |
| `feat` | minor |
| `fix`, `refactor`, `perf` | patch |
| any other type | none |

If every commit since the last tag has a type with no increment, there is nothing to
release: `cz bump` exits with code 21, and the release job fails.

### The release line

`main` carries breaking commits that ship in 3.x, because 4.0.0 is reserved for later
packaging work. The `RELEASE_LINE` value at the top of
`.github/workflows/ash-create-release.yml` controls this. It is committed in the file
rather than offered as an input when the workflow runs, so the line a release lands on
is decided in reviewed history.

- `3.x`, the current value: when commitizen detects a major increment, the workflow
  bumps the minor version instead, and its log and run summary name every breaking
  commit it overrode. Patch and minor increments pass through unchanged. The workflow
  refuses to run if the current version is not 3.x, and fails if the bump would leave
  3.x.
- `auto`: commitizen's own choice, so a breaking change produces a major version. To
  release 4.0.0, the change that lands v4 sets `RELEASE_LINE` to `auto`. Once the version
  is 4.x, `3.x` refuses to run, so a value left at `3.x` fails rather than capping 4.x.

The commits themselves are not rewritten, so their breaking-change notes still appear
in the changelog. A release whose version understates what it changes carries
hand-written notes in `.github/release-notes/<tag>.md`. For example,
`.github/release-notes/v3.8.0.md` lists the behavior changes that 3.8.0 ships as a minor
release, with their opt-outs.

To preview a bump locally, without changing anything:

<!-- doctest: illustrative reason="runs in a checkout of this repository" -->
```bash
uv run cz bump --dry-run --changelog --increment MINOR   # what RELEASE_LINE 3.x does when it caps a major
uv run cz bump --dry-run --changelog                     # what RELEASE_LINE auto does
```

The preview shows the curated notes for the next tag, but not the hand-written
`## Unreleased` notes: the release workflow moves those into the release notes file only
when it runs, as described below.

## What the changelog contains

Each release's entry in `CHANGELOG.md` has three parts, in this order:

1. The curated notes from `.github/release-notes/<tag>.md`, when that file exists. The
   changelog template, `.github/changelog/CHANGELOG.md.j2`, includes it under the
   version heading.
2. Hand-written notes. Contributors describe user-visible changes under
   `## Unreleased` at the top of `CHANGELOG.md`. commitizen would replace that section
   with the generated entry, so before it bumps, the release workflow moves the
   section's text into `.github/release-notes/<next tag>.md`, after any curated notes,
   and removes the section. That file is read as a Jinja template, so the release fails
   if the section contains `{{`, `{%`, or `{#`.
3. The generated sections: BREAKING CHANGE, with the text of each `BREAKING CHANGE:`
   footer, then Feat, Fix, Refactor, and Perf, with one line per commit and its scope in
   bold. A commit marked with `!` is listed under its own type, or with no heading when
   its type has none.

Commits of every other type are left out unless they are marked breaking. That includes
dependency updates, which Dependabot titles `build:` or `ci:`, and changes to CI and
tests.

## How a release is cut

A maintainer runs **Actions > ASH - Create Release > Run workflow**. The workflow:

1. applies the release line, and folds the `## Unreleased` notes into the release notes;
2. runs `cz bump --changelog --check-consistency`, which sets the new version, rewrites
   the `version_files`, rebuilds the agent plugin trees, writes the changelog entry, and
   commits all of it as `bump: version <old> → <new>`;
3. renders the version-pinned pages from their templates and regenerates the JSON
   schemas;
4. smoke-tests the result (`ash --help`, `ash config validate`, and one unit test file);
5. commits the rest as `chore(release): <old> -> <new>` on the branch `release/v<new>`,
   pushes it, and opens a pull request with that title.

The release pull request goes through the same checks and review as any other. When it
merges, the "ASH - Tag and Publish Release" workflow, which reacts to a merged pull
request whose title starts with `chore(release):`, does the rest:

- It checks that the curated release notes, if any, are in the changelog entry, and
  refuses to publish otherwise.
- It creates the tag `v<version>` and a GitHub Release at the head of `main`, with the
  version's changelog entry followed by GitHub's generated notes.
- It moves the floating major tag (see [Tags](#tags)).

It does not start the docs workflow. See [The documentation site](#the-documentation-site)
for how a release's docs version is published.

### The release App

A pull request opened with the workflow's `GITHUB_TOKEN` does not start its own required checks
("ash / SAST, SCA, and IaC Scan", `Validate PR title`, `required-checks`):
GitHub creates the runs in an approval-required state, and a maintainer with write
access has to select **Approve workflows to run** in the pull request's merge box. The
release pull request says so in its description when that happens. To have the checks
start on their own, the workflow opens the pull request with a GitHub App token instead.
A repository admin sets that up once:

- A GitHub App owned by the organization, with no webhook and no callback URL.
- Its only repository permission is **Pull requests: Read and write**; GitHub adds
  metadata read. No Contents permission: the branch push stays on `GITHUB_TOKEN`, and
  the App only opens the pull request. The workflow requests exactly
  `pull-requests: write` when it mints the token, so the mint fails if the App lacks
  it.
- The App installed on this repository only.
- Two repository secrets under **Settings > Secrets and variables > Actions**:
  `RELEASE_APP_CLIENT_ID`, the App's Client ID (not the numeric App ID), and
  `RELEASE_APP_PRIVATE_KEY`, the full contents of a private key's `.pem` file.

The workflow uses the App only when both secrets are set. With one or neither, it logs a
warning and falls back to `GITHUB_TOKEN`. With both set, a misconfigured App (not
installed, wrong permission, or bad key) fails the job at the token step, before anything
is bumped or pushed, rather than falling back. A working setup shows the
**Mint a GitHub App token** step running, the App as the pull request's author, and the
checks starting without an approval banner.

## Tags

Every release has an exact tag, `v<version>`, which the release workflows create once and
never move. To install the same ASH every time, pin a git URL or a GitHub Actions
reference to an exact tag, or to a commit SHA, which cannot move at all.

The floating major tag, `v3` for the 3.x releases, points at the newest release of that
major version. The tag workflow moves it with the GitHub API to the commit it
tagged, creating it if it does not exist yet. A reference to `@v3` therefore picks up
every 3.x release, including the minor releases that carry breaking changes under the
release line above.

The tag workflow only tags `main`. A patch release for an older version is built on a
branch from that version's tag, outside the workflow: 3.7.1, for example, was built on
3.7.0, and its tag is not in `main`'s history. When such a release is the newest one, `v3`
points at it, so `v3` can name a commit that is not on `main`. Until its bump is brought
back to `main`, the version that `main` reports is lower than the newest tag and `main`'s
`CHANGELOG.md` has no entry for it; 3.7.1's bump, changelog entry and install pins were
brought back after the fact, so that an install of `main` reports the newest release.
Do that for any later patch release too: bump `main` to the patch version with
`cz bump <version> --version-files-only --check-consistency` (the tag already exists),
copy the tag's `CHANGELOG.md` entry, rerun `generate` below, and commit.

## The documentation site

The site is versioned. Each push to `main` publishes the version `main`. A release
tag does not publish anything by itself. The docs workflow, run by hand on a release
tag, publishes a version named after the release: `v3.8.0` publishes `3.8.0`.
The newest release also moves the `latest` alias, which is where the site root and
search engines send readers, so a release changes what most readers see. A patch
release for an older line, built outside the workflow as described under
[Tags](#tags), publishes its version when the docs workflow is run on its tag and
leaves `latest` where it is. The floating major tag publishes nothing. How the
versions are built and checked is in
[Testing the documentation](documentation.md#versioned-docs).

A tag that the tag workflow creates is created with `GITHUB_TOKEN`, and a push made with
that token starts no workflow, so the docs workflow never runs on it, and the tag
workflow does not start it. To publish a release's docs version, or to publish it again
if the version is missing, run the docs workflow from **Actions > Docs Deploy > Run
workflow**, choosing the release tag as the ref. Running it on `main` publishes `main`
again.

A tag pushed by hand runs the docs workflow as it is at the tagged commit. For a tag on
a commit from before the site was versioned, that is the old workflow, whose
`mkdocs gh-deploy --force` force-pushes a single unversioned build as a commit with no
parent, so every published version disappears from `gh-pages` along with its history.
That applies to pushing the floating `v3` by hand while it points at such a commit,
and to a patch release built on a release from before versioning. A ruleset on `gh-pages` that blocks force
pushes stops it; the versioned deploy only ever fast-forwards the branch. Without one,
recover by running the docs workflow again on `main` and on each release tag whose
version should exist, in any order: whichever release is newest takes `latest`.

## Version-pinned pages

A page that shows an install command pinned to the current release is generated from a
template. The template has the same name plus `.template` (for example
`README.md.template`), and the rendered page is committed beside it. A template has two
placeholders:

- `{{VERSION}}` is the ref an install command uses, written after a `v` where the command
  names a tag: `@v{{VERSION}}`, `rev: v{{VERSION}}`.
- `{{RELEASE}}` is the current release number, for text that needs the number itself:
  what `ash --version` prints, the release that this repository's generated files pin, a
  release named in a table.

Both render as the release version at a release, so the committed page shows the same
number in both places. They differ only on the docs site's `main` version, described
below.

`scripts/version_template_manager.py generate` renders the template of each file listed
in its `target_files` over that file. The release workflow runs it after the bump. Run
it with `uv run`, which reinstalls the project after a version change: the script takes
the version from the installed package's metadata before it looks at `pyproject.toml`.

<!-- doctest: illustrative reason="runs in a checkout of this repository" -->
```bash
uv run python scripts/version_template_manager.py list       # the templates it renders
uv run python scripts/version_template_manager.py generate   # render them over their pages
```

The docs site renders these templates as well, through the mkdocs hook
`docs/hooks/install_refs.py`. When it builds a release's docs it renders them with that
release's version, which gives the committed page. When it builds the `main` version it
renders them with `main`: `v{{VERSION}}` becomes `main`, so `@v{{VERSION}}` becomes
`@main`, `git clone --branch v{{VERSION}}` becomes `git clone --branch main` and
`rev: v{{VERSION}}` becomes `rev: main`; `refs/tags/v{{VERSION}}` becomes `refs/heads/main`;
and a bare `{{VERSION}}` becomes `main`. `{{RELEASE}}` becomes the current release number,
which is what an install of `main` reports. Any other build, such as `mkdocs serve`, shows
the committed pages.

So write every sentence around `{{VERSION}}` to read correctly with either a release or
`main` in its place ("installs ASH `v{{VERSION}}`", not "installs the `v{{VERSION}}`
release"), and use `{{RELEASE}}` only where the number has to stay a release number. Never
write `{{RELEASE}}` as the ref of an install command, in any of the forms
`scripts/version_template_manager.py` lists in `INSTALL_REF_FORMS` (`@v`, `--branch v`,
`rev: v`, `refs/tags/v`, a flake ref, `--ash-revision-to-install v`, `ash-version: v`): the
`main` version would then install a release. The docs checks report one anywhere except
a table row or a `text` block, which may name the release because neither is a command a
reader runs.

Edit the template, not the rendered page: `generate` overwrites the page, so an edit made
only to the page is lost at the next release. `tests/unit/test_version_template_round_trip.py`
renders every template with the current version on each pull request and fails when the
result differs from the committed page, so the two cannot drift in the meantime. To add a
templated page, add it to `target_files`, write its `.template` file with `{{VERSION}}` and,
where it needs one, `{{RELEASE}}`, render it with `generate`, and commit both files. The
round-trip test also fails when a rendered template still contains something shaped like
a placeholder, such as a misspelled `{{RELASE}}`. Avoid the script's `convert` action: it
rewrites the template of every file in `target_files` from its rendered page, and turns
every version reference it finds into the placeholder, including deliberately older
ones.

`scripts/version_bump.py` and `scripts/build_integration.py` are not part of the release
process. `version_bump.py set` writes the same version into both `version =` lines of
`pyproject.toml`, `[project]` and `[tool.commitizen]`, and regenerates the templated pages;
it is a local helper, and the release process bumps with commitizen instead.
