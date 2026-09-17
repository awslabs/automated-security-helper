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
python packaging/homebrew/refresh-resources.py            # print the block to stdout
python packaging/homebrew/refresh-resources.py --write     # rewrite Formula/ash.rb
python packaging/homebrew/refresh-resources.py --check     # exit 1 if it has drifted
```

Run `--write` after any change to `[project.dependencies]`. The script needs `uv` on
PATH and network access to PyPI; it needs no Homebrew.

It rewrites only the text between

```
  # BEGIN generated resources -- packaging/homebrew/refresh-resources.py
  # END generated resources
```

Those markers are load-bearing. Without them the script would have to infer where the
block ends, and a wrong inference would delete `def install`.

## What it does

1. Reads the Python minor version out of the formula's own `depends_on "python@X.Y"`,
   so the resolution and the interpreter the virtualenv is built with cannot drift.
2. Runs `uv pip compile pyproject.toml` once per platform Homebrew supports --
   `aarch64-apple-darwin`, `x86_64-apple-darwin`, `aarch64-unknown-linux-gnu`,
   `x86_64-unknown-linux-gnu` -- and merges the four results, failing if any package
   resolved to two different versions. A formula carries one resource list and installs
   it on all four; a closure resolved only on the build machine would be missing
   whatever is conditional on the other platforms, and that lands on users as a
   `ModuleNotFoundError` rather than on whoever regenerated the block.
3. Reads each release's sdist URL and sha256 from the PyPI JSON API
   (`https://pypi.org/pypi/<name>/<version>/json`), taking the entry whose
   `packagetype` is `"sdist"` and its `digests.sha256`.
4. Emits `resource` stanzas sorted by canonical name, using PyPI's own spelling of each
   name (`GitPython`, not `gitpython`) so the block reads the same as one written by
   `brew update-python-resources`.

Windows is absent from the platform list because Homebrew does not run there. Including
it would pull in Windows-only requirements that pip would then refuse to install on the
platforms Homebrew does support.

## Why generated and not hand-maintained

The closure is 78 packages. A hand-written list of 78 names, versions, URLs and hashes
is a second copy of the dependency set, and the long `[tool.commitizen]` comment block
in `pyproject.toml` is about exactly that failure mode: the repository had three
separate hand-maintained lists of the files that pin ASH's version, and a file absent
from all three was invisible to every one of them. A stale resource block fails the same
way -- silently, one release later, on a user's machine.

`brew update-python-resources` is the normal tool for this and is the right one to reach
for when Homebrew is installed. It was unavailable on the machine this was written on,
and writing the block by hand was the alternative being avoided. The PyPI JSON API
returns the same two fields that command writes, and the `homebrew` job in
`.github/workflows/ash-package.yml` runs `brew audit --strict` against Homebrew's own
rules either way.

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

- **The resolution is for one Python minor version.** It is read from the formula's
  `depends_on "python@X.Y"` rather than hardcoded, but it is not a universal resolution
  across interpreters. Bumping that dependency requires regenerating the block.

- **Build backends are fetched unpinned at build time.** `Virtualenv#pip_install`
  defaults to `build_isolation: true`, so pip builds each sdist in an isolated
  environment and fetches its PEP 517 backend -- maturin for the Rust extensions,
  setuptools for the rest -- from PyPI itself. That is network access inside a Homebrew
  build, and the versions are whatever PyPI serves that day. Pinning it would mean
  replacing `virtualenv_install_with_resources` with hand-rolled install code that
  stages the backends first, which is a larger change than the problem currently
  justifies. This is also why the formula does not declare `depends_on "maturin"`:
  nothing in this install path would consult it.

- **A freshly released version can fail to install.** `std_pip_args` also passes
  `--uploaded-prior-to`, a release cooldown intended to avoid installing a
  just-compromised PyPI release. A resource whose version was published inside that
  window is refused. Regenerating immediately after an upstream release can therefore
  produce a block that installs fine in a few days and not today. Wait it out rather
  than editing the formula.

- **A transitive-only change is not caught by the unit test.**
  `tests/unit/test_homebrew_formula_resources.py` asserts that every *top-level* name in
  `[project.dependencies]` has a stanza, which catches the common drift of adding a
  requirement and forgetting to regenerate. A dependency of a dependency gaining a new
  requirement does not touch that array. That case is caught by the real `brew install`
  in CI and by `--check`, both of which need a network; the unit test must not.

- **`--check` re-resolves, so its answer can change without the repository changing.**
  An upstream release inside a declared range moves the resolution, and `--check` then
  reports drift on an untouched formula. That is the correct reading -- the pinned block
  is now behind -- but it means `--check` is a maintenance prompt rather than a gate that
  belongs in front of every pull request.

## Publishing boundary

Nothing here vendors third-party code. A `resource` stanza is a URL and a sha256 --
metadata pointing at PyPI, resolved at install time on the user's machine. That keeps
the formula on the permitted side of the boundary described in `packaging/README.md`:
ASH's own code may ship in a published artifact, third-party code never may, and no
dependency source enters this tree.
