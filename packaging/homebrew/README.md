# Homebrew tap

`Formula/ash.rb` at the repository root is the formula. This directory holds the tool
that keeps its `resource` block in step with `pyproject.toml`, and the reasoning behind
the decisions in it.

## Why the resource block exists at all

Homebrew builds ASH into a virtualenv with `virtualenv_install_with_resources`, and it
installs into that virtualenv using `Formula#std_pip_args`, which is

```
["--verbose", "--no-deps", "--no-binary=:all:", "--ignore-installed", "--no-compile"]
```

`--no-deps` is the whole reason this directory exists. pip resolves nothing. It installs
exactly the sdists Homebrew staged from `resource` stanzas, then ASH itself, and a
requirement in `[project.dependencies]` with no matching stanza is not an error -- it is
a package that never arrives.

The formula shipped with **zero** resources. So `brew install` reported success, the
virtualenv was built, and the first `ash` run died on `ModuleNotFoundError` naming a
module the build never mentioned. The only CI check on the formula was
`ruby -c Formula/ash.rb`, which parses the file, and a formula with no resources parses
perfectly.

`--no-binary=:all:` is the other half of that flag list, and it is why every stanza
points at an sdist. pip is forbidden from consuming a built wheel, so a resource whose
URL ends in `.whl` is not merely off-convention: pip refuses it.

## Regenerating

```
uv run python packaging/homebrew/refresh-resources.py            # print the block to stdout
uv run python packaging/homebrew/refresh-resources.py --write     # rewrite Formula/ash.rb
uv run python packaging/homebrew/refresh-resources.py --check     # exit 1 if it has drifted
```

Run `--write` after any change to `uv.lock`. The script reads `uv.lock` and nothing
else: no resolver run, no network, no Homebrew. The same `uv.lock` always produces a
byte-identical `Formula/ash.rb`, and `tests/unit/test_homebrew_formula_lock_sync.py`
regenerates the formula on every unit test run and fails on any difference.

It rewrites only the text between

```
  # BEGIN generated resources -- packaging/homebrew/refresh-resources.py
  # END generated resources
```

Those markers are load-bearing. Without them the script would have to infer where the
block ends, and a wrong inference would delete `def install`.

## What it does

1. Reads the Python minor version out of the formula's own `depends_on "python@X.Y"`,
   so the closure and the interpreter the virtualenv is built with cannot drift.
2. Walks `uv.lock` from the root package's runtime dependencies (no extras, no
   dependency groups) once per platform Homebrew supports, evaluating each edge's
   PEP 508 marker for that platform: `aarch64-apple-darwin`, `x86_64-apple-darwin`,
   `aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-gnu`. The four closures are
   merged, and a package locked at two different versions across them is a hard
   failure, because one `resource` stanza cannot carry both. A closure computed only
   for the build machine would miss whatever is conditional on the other platforms,
   and that lands on users as a `ModuleNotFoundError`.
3. Takes each package's sdist URL and sha256 from its `sdist = { url, hash }` entry in
   `uv.lock`, refusing a package with no sdist, a hash that is not SHA-256, or a URL
   that is not on `files.pythonhosted.org`.
4. Names each resource the way `brew audit --strict` derives the name it checks
   against: the sdist URL's basename up to its last hyphen, with `_` and `.` mapped to
   `-`. Modern sdists are named in normalized lowercase, so the names are too
   (`gitpython`, `pyyaml`). Emits the stanzas sorted by canonical name.

Windows is absent from the platform list because Homebrew does not run there. Including
it would pull in `pywin32`, which publishes no sdist.

## Why uv.lock and not a fresh resolution

The first version of this script ran `uv pip compile pyproject.toml` per platform and
read each sdist from the PyPI JSON API. That made the block a function of the day it
was generated: an upstream release inside a declared range moved the resolution, so
`--check` reported drift on a formula nobody had touched, and the formula pinned
versions the test suite had never run against. Measured on this branch, the committed
block disagreed with `uv.lock` on 30 of its 77 versions and was missing `uc-micro-py`,
which the locked `linkify-it-py` needs.

Reading `uv.lock` makes the formula install exactly what CI tested, and makes `--check`
a gate that changes its answer only when the repository changes.

## Why generated and not hand-maintained

The closure is 78 packages. A hand-written list of 78 names, versions, URLs and hashes
is a second copy of the dependency set, and the long `[tool.commitizen]` comment block
in `pyproject.toml` is about exactly that failure mode: the repository had three
separate hand-maintained lists of the files that pin ASH's version, and a file absent
from all three was invisible to every one of them. A stale resource block fails the same
way -- silently, one release later, on a user's machine.

`brew update-python-resources` is the normal tool for this. It resolves against PyPI
rather than against a lock, which is the property this script exists to avoid. The
`homebrew` job in `.github/workflows/ash-package.yml` runs `brew audit --strict` against
Homebrew's own rules either way.

## The uv collision, and why there is no `uv` resource

`uv` appears twice and they are different things:

- `pyproject.toml` lists `uv>=0.12.11,<0.13` in `[project.dependencies]`.
- `Formula/ash.rb` has `depends_on "uv"`, which is the Homebrew formula.

ASH needs the uv **executable**, not the uv Python package. Nothing under
`automated_security_helper/` imports it as a module: every use goes through
`uv_tool_runner.find_uv_or_none()`, which calls
`subprocess_utils.find_executable("uv")` -- `shutil.which` over PATH -- and the scanners
that need it build argv lists starting with the string `"uv"`. `depends_on "uv"` is what
puts that binary on PATH, so the Homebrew dependency is the one that matters and the
resource is omitted.

Adding it as a resource would be worse than redundant on three counts. uv's sdist is a
Rust program, so it would compile a second copy of a binary Homebrew already ships
bottled. The copy would be unreachable: `virtualenv_install_with_resources` leaves the
virtualenv at `libexec` and symlinks only ASH's own console scripts into `bin`, and
`find_executable`'s non-PATH fallback searches ASH's own bin directory rather than
alongside `sys.executable`. And it would add minutes to every install for no capability.

The version ranges line up as it happens -- homebrew-core's `uv` is 0.12.15, inside
ASH's `>=0.12.11,<0.13` -- but that is a coincidence of timing rather than something
either side enforces, and it is not the reason the omission is safe. The reason is that
nothing imports the module.

`tests/unit/test_homebrew_formula_resources.py` carries the exemption and asserts that
`depends_on "uv"` is present, so deleting the dependency fails a test rather than
producing an ASH where every `uv tool install` scanner reports MISSING.

## The Rust extensions

Five packages in the closure are Rust extension modules with no pure-Python fallback:
`cryptography`, `pydantic-core`, `rpds-py`, `rtoml` and `orjson`. Because
`--no-binary=:all:` forbids the prebuilt wheel, pip compiles each from its sdist, so the
formula declares `depends_on "rust" => :build`, plus `pkgconf` and `openssl@3` for
`cryptography`, whose build locates OpenSSL through pkg-config. Those names come from
homebrew-core's own `cryptography` formula rather than from working through build errors
one at a time.

An alternative was considered and rejected. homebrew-core no longer builds these from
sdist inside a consuming formula; it has standalone bottled formulae and consumers
declare `depends_on "cryptography" => :no_linkage`, which works because
`virtualenv_create` defaults to `system_site_packages: true`. That would cut install
time from tens of minutes to a couple, and `aws-sam-cli` does exactly this today. Two
things rule it out here. `orjson`, `rtoml` and `pydantic-core` have no homebrew-core
formula at all, so three of the five would still be built from sdist and the Rust
toolchain would still be needed -- the saving is partial. And a formula dependency
supplies whatever version homebrew-core currently ships, independent of ASH's declared
ranges, so when homebrew-core moves `pydantic` past ASH's `<2.14` cap the virtualenv
silently gets an unsupported version and `--no-deps` means nothing complains. Resources
pin the exact version this repository resolved. If install time becomes the binding
constraint, that trade is the lever, and it should be taken deliberately with a check
that the supplied versions still satisfy `[project.dependencies]`.

## Known limitations

- **The closure is for one Python minor version.** It is read from the formula's
  `depends_on "python@X.Y"` rather than hardcoded, but markers are evaluated with
  `python_full_version` set to `X.Y.0`, so a marker keyed on a later patch release would
  be read against `.0`. None in the lock does today. Bumping the Python dependency
  requires regenerating the block.

- **Build backends are fetched unpinned at build time.** `Virtualenv#pip_install`
  defaults to `build_isolation: true`, so pip builds each sdist in an isolated
  environment and fetches its PEP 517 backend -- maturin for the Rust extensions,
  setuptools for the rest -- from PyPI itself. That is network access inside a Homebrew
  build, and `uv.lock` cannot pin it, because the lock records runtime dependencies and
  not build backends. Pinning it would mean replacing `virtualenv_install_with_resources`
  with hand-rolled install code that stages the backends first. This is also why the
  formula does not declare `depends_on "maturin"`: nothing in this install path would
  consult it.

- **A freshly released version can fail to install.** `std_pip_args` also passes
  `--uploaded-prior-to`, a release cooldown intended to avoid installing a
  just-compromised PyPI release. A resource whose version was published inside that
  window is refused. That window is now governed by when `uv.lock` was last updated.

## Publishing boundary

Nothing here vendors third-party code. A `resource` stanza is a URL and a sha256 --
metadata pointing at PyPI, resolved at install time on the user's machine. That keeps
the formula on the permitted side of the boundary described in `packaging/README.md`:
ASH's own code may ship in a published artifact, third-party code never may, and no
dependency source enters this tree.
