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
- The Homebrew formula's missing `resource` block, and the checks that would have caught
  it. See "The Homebrew formula could not have worked" below.

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

### What remained, and how it was settled

Two different things used to both be called `ash`:

1. A tracked **bash script at the repository root** — 232 lines, 7,332 bytes, parsing 18
   flags in 27 alias spellings of the v2-era container surface (`--source-dir`,
   `--offline`, `--oci-runner`, `--container-uid`, `--build-target`, `--ash-revision`, …)
   and driving a container build directly.
2. The **Python console script** from `[project.scripts]`.

Which one ran depended entirely on PATH order. On Windows there is a third collision:
MSYS2 ships its own `ash`, the Almquist shell, which has already shadowed ASH's entry
point in CI and produced `Illegal option --`.

**This was a dependency of native packaging, not a parallel workstream.** Every package
declares the console scripts it installs — the deb and rpm here install `/usr/bin/ash` as
a wrapper onto the venv's entry point — so an entry point that got renamed or dropped
would change those manifests with it. That is why it was settled before the MSIX,
Chocolatey and winget manifests rather than alongside them.

**The root bash script is deleted.** No port was written, because none was needed:
`run_ash_container.py` already had `_OCI_RUNNER_CANDIDATES = ["finch", "docker",
"nerdctl", "podman"]`, `_resolve_oci_runner`, `_build_image`, `_assemble_run_command` and
`_execute_container`. Measured against the deleted script's own flag list, the Python
`scan` command accepted 26 of its 27 spellings before this change; the exception was
`-h`, which click does not inject.

Five spellings were added rather than ported: `--ash-revision` and `-rev` as aliases of
`--ash-revision-to-install`, `-q` for `--quiet`, `-h` for help, and `-V` for `--version`.

Three decisions inside that are worth not relitigating:

- **`-V`, not `-v`, is the version flag.** The bash script used `-v` for `--version`, but
  `-v` has been `--verbose` for all of v3. Taking it back would silently turn a verbose
  run into a version print for anyone with it in CI, so version got its own letter and
  `-v` was left alone.
- **`-rev` is a single-dash multi-character option**, which is unusual enough to look like
  a mistake. It works: click matches the whole token before falling back to splitting
  short flags, verified with `-r`, `-e` and `-v` all registered alongside it.
- **`scan` now rejects unknown flags.** It used to accept any unrecognized flag and run a
  full scan regardless, so a typo in CI scanned the wrong thing and exited 0. Nothing read
  `ctx.args` on that path, so the swallowed arguments were being discarded rather than
  forwarded. `build-image` keeps the pass-through, which its help text documents.

Of the three console scripts, `ash` is the name and `automated-security-helper` is kept
indefinitely and silent — it is the escape hatch for exactly the MSYS2 collision above.
`ashv3` warns on stderr and stays, because the name pins a version and so reads wrong the
moment v4 exists.

**One thing this removed that was not a flag.** The CI `method: bash` matrix cells existed
to exercise that script, and went with it — 5 cells across `ubuntu-latest` and
`ubuntu-24.04-arm`. No platform coverage was lost, because each `bash` cell had a
`python-container` cell on the same os and oci-runner, so the pair ran the same container
build from two entrypoints. `utils/ash_helpers.sh`'s `invoke-ash` now calls
`ash --mode container`; `--mode container` is load-bearing there, since the bash script
always ran in a container while the bare Python CLI defaults to local.

**A guardrail that would have gone quiet.**
`tests/unit/test_ash_bash_entrypoint_build_failure.py` covered a real bug: a failed image
build falling through to the run step, which reports a misleading registry error in CI and
silently scans with a stale image locally. It guarded the bash script, and it carried a
`skipif(not ASH_SCRIPT.is_file())`, so deleting the script would have turned it green by
skipping rather than red. The guarantee moved to
`tests/unit/test_container_build_failure_stops_the_run.py` against the Python path, where
it holds for a reason invisible at the call site: `_build_image` never inspects the return
code itself and relies on `run_cmd_direct` defaulting to `check=True`. That default is now
pinned by a test, because flipping it would reintroduce the bug without touching either
function.

**Known gap, pre-existing and not addressed here.** In the bash script `-c` meant
`--no-color`; in the Python CLI `-c` is `--config` and takes a value. A v2 invocation
passing `-c` therefore consumes the next token as a config path instead of disabling
color. That divergence shipped with v3 and is not something this change introduced, so it
was left alone rather than fixed silently under an unrelated commit.

## The Homebrew formula could not have worked

`Formula/ash.rb` called `virtualenv_install_with_resources` with **zero `resource`
stanzas**. The plan recorded this as "would likely fail to vendor dependencies". It is
worse than that and the mechanism is exact.

Homebrew installs into the virtualenv with `Formula#std_pip_args`, which is
`["--verbose", "--no-deps", "--no-binary=:all:", "--ignore-installed", "--no-compile"]`
(read from `Library/Homebrew/formula.rb` at `main`). `--no-deps` means pip resolves
nothing: it installs exactly the sdists Homebrew staged from `resource` stanzas, then ASH
itself. A requirement in `[project.dependencies]` with no stanza is **not an error** --
it is a package that never arrives. So `brew install` reported success, the virtualenv
was built, and the first `ash` run died on `ModuleNotFoundError` naming a module the
build never mentioned.

`ruby -c Formula/ash.rb` in `.github/actions/validate-install/action.yml` was the only
check. It parses the file, and a formula with no resources parses perfectly, so the check
was green on a formula that could not produce a working install.

The block is now generated by `packaging/homebrew/refresh-resources.py`: `uv` resolves
the closure once per Homebrew platform, the PyPI JSON API supplies each sdist URL and
sha256. 78 packages resolved, 77 emitted. A hand-written list was rejected for the reason
the `[tool.commitizen]` comment in `pyproject.toml` gives at length -- a second
hand-maintained copy of the dependency set drifts, and the drift is invisible until
someone installs it.

Two decisions inside that are worth not relitigating.

**`uv` is supplied by `depends_on "uv"`, not by a resource.** It appears in
`[project.dependencies]` and in the formula's dependencies, which reads like the same
thing twice. It is not: ASH needs the uv *executable*. Nothing under
`automated_security_helper/` imports it, and `uv_tool_runner.find_uv_or_none()` resolves
it through `subprocess_utils.find_executable("uv")`, which is `shutil.which` over PATH. A
resource would compile a Rust program Homebrew already ships bottled into `libexec`,
where neither PATH nor `find_executable`'s own fallback -- which searches ASH's bin
directory, not next to `sys.executable` -- would ever look.

**`depends_on "rust" => :build` rather than homebrew-core's newer pattern.** Five
resources are Rust extensions with no pure-Python fallback: `cryptography`,
`pydantic-core`, `rpds-py`, `rtoml` and `orjson`. homebrew-core no longer builds these
inside a consuming formula; it has standalone bottled formulae and consumers write
`depends_on "cryptography" => :no_linkage`, which works because `virtualenv_create`
defaults to `system_site_packages: true`. `aws-sam-cli` does exactly that today, and it
would cut install time from tens of minutes to a couple. It was rejected on two measured
grounds. `orjson`, `rtoml` and `pydantic-core` have no homebrew-core formula at all, so
three of the five would still build from sdist and the toolchain would still be needed.
And a formula dependency supplies whatever version homebrew-core currently ships,
independent of ASH's ranges -- when homebrew-core moves `pydantic` past ASH's `<2.14`
cap, `--no-deps` guarantees nothing complains. If install time becomes the binding
constraint, that is the lever, and taking it needs a check that the supplied versions
still satisfy `[project.dependencies]`.

**What is proven and what is not.** The generator, `ruby -c`, and
`tests/unit/test_homebrew_formula_resources.py` were run locally; the generated
`cryptography` 50.0.1 and `cffi` 2.1.1 stanzas are byte-identical to the `url`/`sha256`
in homebrew-core's own formulae for those versions, which is the control that the
generator reads the right PyPI fields. **The `brew install` itself has not been run.**
Homebrew is absent from the machine this was written on, exactly as the plan recorded, so
the `homebrew` job in `ash-package.yml` is the first place it executes. Read its first
run before treating the resource list as verified.

Three known limitations are recorded in `packaging/homebrew/README.md` rather than here:
pip's default build isolation fetches PEP 517 backends from PyPI unpinned at build time,
`std_pip_args` passes a release cooldown so a freshly published version can be refused
for a few days, and the unit test covers top-level requirements only, so a
transitive-only change is caught by `brew install` or `--check` and not by the test suite.

## Remaining scope

- **Flatpak, MSIX, Chocolatey, winget** manifests and validation actions. No longer
  blocked on the entry-point decision — declare `ash`, `ashv3` and
  `automated-security-helper`, matching `[project.scripts]`. Still outstanding because
  none of `flatpak-builder`, `makeappx`, `choco` or `winget` was available on the machine
  this branch was built on, so writing them without local evidence would have produced
  CI-only code — the opposite of how the deb and rpm were done.
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
