# v4 capabilities: what the packaging plan asked for, and what was already true

Written before any code on this branch, and updated as measurements changed it. Read
this before picking up the remaining work, because roughly half the plan was already
done by the time it was picked up and rebuilding those parts would create conflicts
rather than progress.

Everything below was measured against `main` at `3191ecefc09ff4fd62684ae69f274f8eda38d658`.

## Already done — do not rebuild

| Plan item | Evidence |
|---|---|
| Wheel/sdist build in CI | `ash-package.yml`, 296 lines, runs `uv build` |
| Artifact contents gate | `.github/scripts/assert-artifact-contents.py`, 2,260 lines. `--self-test` plants one payload per detector across both zip and tar containers and asserts an empty archive is rejected, so it cannot pass vacuously. 18 detectors. |
| Incomplete scan exits non-zero | `_COMPLETE_SCANNER_STATUSES` at `run_ash_scan.py:210` |
| Per-tool `--tool/-T` selection | 14 references in `cli/dependencies.py` |
| Installer reports a real verdict | `PluginInstallOutcome` carries counts; `EXIT_OK`/`EXIT_INSTALL_FAILED`/`EXIT_BAD_SELECTION`. The "All dependencies installed successfully!" string survives only inside a docstring describing the *old* behavior. |
| SHA256 pinning, download retry | `install_pinned_tool`, `ToolDownloadIntegrityError`, `tool_downloads.py` pins grype, syft and trivy |
| Node pinning, README install typo, podman/finch scanning, nerdctl coverage | `.nvmrc` present, `setup-node` in the TypeScript workflow, no `3.0,1` left in `README.md` |

The plan's Phases 1 and 2 are therefore closed, and most of Phase 6 with them.

## Done on this branch

- Release wiring and Sigstore provenance in `ash-tag-on-merge.yml`.
- A Debian/Ubuntu package and an Amazon Linux/RHEL package, each verified by building,
  installing and running a real scan in its target distro image.
- CI jobs that do the same on every pull request, the first `container:` jobs in the
  repository.

## The CLI consolidation: already done, except for the part nobody names

The v4 scope includes consolidating `ash` and `ash-multi` into a single `ash` CLI.
**`ash-multi` no longer exists, and the consolidation is effectively already complete.**

An API path filter makes this look contradictory — a tree listing finds nothing while
`commits?path=ash-multi` returns commits. Both are correct. Settled with a full,
non-shallow clone:

- `ash-multi` is absent from `main`; no tracked path matches `ash[-_]multi`.
- It nonetheless has **74 commits of history on main** (82 across all refs), so the
  commit list was real history, not an ignored filter.
- On main's history it was deleted by **exactly one** commit: `1641742c`, 2026-08-19,
  *"fix(logging): restore UTF-8 console reconfiguration on Windows (#412)"* — a 694-line
  legacy script removed inside a commit about Windows logging.
- The commit whose message actually describes the removal, `902776a4`
  *"chore: remove legacy ash-multi script"*, is **not an ancestor of main**. It lives on
  `origin/archive/pr-334-scan-decomposition-lineage`. So the honestly-named removal never
  landed, and the one that did is buried in an unrelated-sounding change.
- `src/automated_security_helper/ash_multi.py` and `tests/test_ash_multi.py` are also
  absent from main.

If you go looking for this later, scope the search to `main` rather than `--all`.
Searching all refs surfaces the archive branch's removal commit and invites the
conclusion that a commit which never landed is what removed the file.

### What actually remains, and it is a decision rather than a task

Two different things are still both called `ash`:

1. A tracked **bash script at the repository root** — 232 lines, 7,332 bytes, parsing 26
   flags of the v2-era container surface (`--source-dir`, `--offline`, `--oci-runner`,
   `--container-uid`, `--build-target`, `--ash-revision`, …) and driving a container build
   directly. Its only Python touchpoints are `python -m automated_security_helper.cli.main`
   with `--help` and `--version`.
2. The **Python console script** from `[project.scripts]`, where all three of `ash`,
   `ashv3` and `automated-security-helper` point at
   `automated_security_helper.cli.main:app`.

Which one runs depends entirely on PATH order. On Windows there is a third collision:
MSYS2 ships its own `ash`, the Almquist shell, which has already shadowed ASH's entry
point in CI and produced `Illegal option --`.

**This is a dependency of native packaging, not a parallel workstream.** Every package
declares the console scripts it installs — the deb and rpm on this branch install
`/usr/bin/ash` as a wrapper onto the venv's entry point — so if consolidation renames or
drops an entry point, those manifests change with it. Settle the entry-point surface
before writing the MSIX, Chocolatey or winget manifests.

It is deliberately **not** attempted on this branch, because the open questions are
compatibility decisions with user-visible consequences rather than mechanical edits:

- Does the root bash `ash` disappear, or survive as a container-mode entry point? Killing
  it means the Python CLI owns container orchestration. Check what
  `run_ash_container.py` already covers — it has
  `_OCI_RUNNER_CANDIDATES = ["finch", "docker", "nerdctl", "podman"]` — before assuming a
  port is needed.
- Which of the three aliases stay, and which become deprecated shims?
- What does a v2-era invocation do: work, warn, or fail with a migration message? A
  silent behavior change on a flag somebody has in CI is the expensive failure here, and
  it cannot be chosen by inference.

## Remaining scope

- **Flatpak, MSIX, Chocolatey, winget** manifests and validation actions. Blocked on the
  entry-point decision above for what they declare. None of `flatpak-builder`,
  `makeappx`, `choco` or `winget` was available on the machine this branch was built on,
  so writing them without local evidence would have produced CI-only code — the opposite
  of how the deb and rpm were done.
- **Homebrew.** `Formula/ash.rb` calls `virtualenv_install_with_resources` with **zero
  `resource` stanzas**, so a real `brew install` would likely fail to vendor
  dependencies. CI only syntax-checks the formula, which is why this is invisible.
  Generating the stanzas needs Homebrew, also absent.
- **MCPB release wiring.** `backends/mcpb/__init__.py` declares `stage="release"` and
  nothing consumes it.
- **VS Code `.vsix` and the JetBrains plugin.**
- **Provenance for the native packages.** The wheel and sdist are attested; the `.deb`
  and `.rpm` are built in CI but not attached to a release or attested.
- **`push: branches: ["!main"]`** in `ash-unified-ci.yml` is untouched here on purpose —
  separate in-flight work fixes exactly that, and this branch avoids the collision.

## One unresolved observation

A run on this branch showed 8 failures, all `ubuntu-24.04-arm` container and scan legs,
in workflows this branch **does not modify** (`ash-unified-ci.yml`,
`ash-install-methods.yml`, `run-scan-test/action.yml`, `validate-container/action.yml` are
all byte-identical to main here). Two recent merge-group runs at main show 35 arm64 legs
with 0 failures, so "pre-existing" is not supported either.

The likeliest cause is a transient upstream failure fetching a pinned scanner asset
during the arm64 image builds — a `HTTP 500` on grype's release download was diagnosed on
another pull request the same day, and all 8 legs share that download. **That was not
confirmed**, because the log could not be extracted cleanly. Treat it as open, and re-run
those legs the next time this branch goes through CI before reading anything into them.
