# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Homebrew formula must vendor the dependencies it says it installs.

Why this file exists
--------------------
`Formula/ash.rb` calls `virtualenv_install_with_resources`, and for most of this
formula's life it did so with zero `resource` stanzas. That is not a slow
install or a partial install -- it is an ASH that cannot start.

The reason is one flag. Homebrew installs into the virtualenv with
`Formula#std_pip_args`, which is

    ["--verbose", "--no-deps", "--no-binary=:all:", "--ignore-installed", "--no-compile"]

`--no-deps` means pip never resolves anything. It installs exactly the paths it
is handed -- the staged `resource` sdists, then ASH itself -- and a requirement
in `[project.dependencies]` with no matching `resource` is not an error, it is
simply a package that never gets installed. So `brew install` reports success,
the venv is built, and the first `ash` invocation dies on
`ModuleNotFoundError`. Nothing in the build says which requirement was missing,
because pip was never asked to look.

`--no-binary=:all:` is the other half, and it is why every resource here is an
sdist rather than a wheel. pip is forbidden from consuming a built wheel, so a
resource pointing at a `.whl` is not merely off-convention: pip refuses it.

Why CI could not see this
-------------------------
The only formula check in the repository was `ruby -c Formula/ash.rb` in
`.github/actions/validate-install/action.yml`. `ruby -c` parses the file. A
formula with no resources parses perfectly, so the check was green on a formula
that could not produce a working install. This test is the cheap half of the
fix -- it runs on every unit test run, with no Homebrew and no network. The
expensive half is the `homebrew` job in `.github/workflows/ash-package.yml`,
which does a real `brew install` and `brew test`.

Why the resource list is generated and not hand-maintained
----------------------------------------------------------
`packaging/homebrew/refresh-resources.py` resolves the closure with `uv` and
reads each sdist URL and sha256 from the PyPI JSON API. The same reasoning as
the long `[tool.commitizen]` comment block in pyproject.toml applies: a
hand-maintained second list of what ASH depends on drifts from the first one,
and the drift is invisible until someone installs it. This test does not
re-derive the closure -- resolving 78 packages needs a network -- it asserts the
property that catches the common drift, which is a *new top-level* requirement
added to pyproject.toml without regenerating the block.

What this test deliberately does not catch
------------------------------------------
A transitive-only change (a dependency of a dependency gaining a new
requirement) does not touch `[project.dependencies]`, so nothing here fires.
That case is caught by the real `brew install` in CI, and by
`refresh-resources.py --check`, which re-resolves and diffs. Both need a
network; this file must not.
"""

import re
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on 3.10
    import tomli as tomllib

REPO_ROOT = Path(__file__).resolve().parents[2]
FORMULA_PATH = REPO_ROOT / "Formula" / "ash.rb"
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"

# `  resource "GitPython" do`
_RESOURCE = re.compile(r'^\s*resource\s+"(?P<name>[^"]+)"\s+do\s*$', re.MULTILINE)
# `  depends_on "uv"` and `  depends_on "rust" => :build`
_DEPENDS_ON = re.compile(r'^\s*depends_on\s+"(?P<name>[^"]+)"', re.MULTILINE)

# Requirements that are deliberately NOT resources, and the Homebrew formula
# dependency that covers each one instead.
#
# uv is the only entry, and it is here because ASH needs the uv *executable*,
# not the uv Python package. There is no `import uv` anywhere under
# automated_security_helper/; every use goes through
# `uv_tool_runner.find_uv_or_none()` -> `subprocess_utils.find_executable("uv")`,
# which is `shutil.which` over PATH, and every command is built as an argv list
# starting with the string "uv". `depends_on "uv"` puts that executable on PATH.
#
# Adding it as a resource would be worse than redundant. uv's sdist is a Rust
# program, so it would compile a second copy of a binary Homebrew already ships
# bottled. And the copy would be unreachable: `virtualenv_install_with_resources`
# leaves the venv at `libexec` and symlinks only ASH's own console scripts into
# `bin`, so a venv-local `uv` is on no PATH, and `find_executable`'s non-PATH
# fallback looks in ASH's own bin directory (`ASH_BIN_PATH`), not next to
# `sys.executable`.
_COVERED_BY_HOMEBREW_DEPENDENCY = {
    "uv": "uv",
}


def _canonical(name: str) -> str:
    """PEP 503 normalization, so `GitPython` and `gitpython` compare equal."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _formula_text() -> str:
    assert FORMULA_PATH.is_file(), (
        f"{FORMULA_PATH} is absent. This file asserts properties of the in-tree "
        "Homebrew tap; if the tap moved out of this repository, delete this test "
        "rather than letting it skip, because a skipped test reads as a pass."
    )
    return FORMULA_PATH.read_text(encoding="utf-8")


def _resource_names(text: str) -> list[str]:
    return [match.group("name") for match in _RESOURCE.finditer(text)]


def _declared_dependencies(text: str) -> set[str]:
    return {_canonical(match.group("name")) for match in _DEPENDS_ON.finditer(text)}


def _top_level_requirement_names() -> list[str]:
    """The bare package names in `[project.dependencies]`.

    Strips extras, version specifiers and markers: `pydantic>=2.13.5,<2.14` ->
    `pydantic`, `bandit[sarif]>=1.7` -> `bandit`.
    """
    with PYPROJECT_PATH.open("rb") as handle:
        data = tomllib.load(handle)
    names = []
    for spec in data["project"]["dependencies"]:
        name = re.split(r"[\[<>=!~;\s]", spec, maxsplit=1)[0].strip()
        assert name, f"Could not read a package name out of the requirement {spec!r}"
        names.append(name)
    return names


class TestHomebrewFormulaVendorsItsDependencies:
    def test_the_formula_declares_resources_at_all(self):
        """The original defect, asserted on its own.

        Kept separate from the per-requirement check below so that a formula
        that lost its whole generated block fails with a message naming the
        generator, rather than with 21 near-identical missing-resource
        failures.
        """
        resources = _resource_names(_formula_text())

        assert resources, (
            "Formula/ash.rb calls virtualenv_install_with_resources but declares "
            "no `resource` stanzas. Homebrew installs with --no-deps, so pip will "
            "install ASH and none of its dependencies, `brew install` will still "
            "report success, and the first `ash` run will fail on "
            "ModuleNotFoundError. Regenerate the block with "
            "`python packaging/homebrew/refresh-resources.py --write`."
        )

    def test_every_top_level_requirement_has_a_resource(self):
        text = _formula_text()
        resources = {_canonical(name) for name in _resource_names(text)}

        missing = []
        for requirement in _top_level_requirement_names():
            canonical = _canonical(requirement)
            if canonical in resources:
                continue
            if canonical in _COVERED_BY_HOMEBREW_DEPENDENCY:
                continue
            missing.append(requirement)

        assert not missing, (
            "These names are in [project.dependencies] but have no `resource` "
            f"stanza in Formula/ash.rb: {sorted(missing)}. Homebrew installs with "
            "--no-deps, so each one is a module that will be absent from the "
            "installed venv. Run `python packaging/homebrew/refresh-resources.py "
            "--write` to regenerate the block, or, if the requirement is supplied "
            "by a Homebrew formula rather than by the venv, add it to "
            "_COVERED_BY_HOMEBREW_DEPENDENCY in this file with the reason."
        )

    def test_each_exempt_requirement_names_a_formula_the_tap_depends_on(self):
        """The positive control for the exemption above.

        Without this, `_COVERED_BY_HOMEBREW_DEPENDENCY` would be a way to make
        the previous test pass by asserting nothing: drop `depends_on "uv"` from
        the formula and the exemption still suppresses the failure, while the
        installed ASH now has no uv at all and every `uv tool install` scanner
        reports MISSING.
        """
        declared = _declared_dependencies(_formula_text())

        for requirement, formula in _COVERED_BY_HOMEBREW_DEPENDENCY.items():
            assert _canonical(formula) in declared, (
                f"{requirement!r} is exempt from needing a `resource` because "
                f"the Homebrew formula {formula!r} is supposed to supply it, but "
                f"Formula/ash.rb has no `depends_on \"{formula}\"`. Either add the "
                "dependency back or remove the exemption and add a resource."
            )

    def test_no_requirement_is_both_a_resource_and_exempt(self):
        """Two ways to supply one package is one way too many.

        A stale exemption left behind after a resource was added would go
        unnoticed forever, because the check above is satisfied either way.
        """
        resources = {_canonical(name) for name in _resource_names(_formula_text())}

        both = sorted(
            name
            for name in _COVERED_BY_HOMEBREW_DEPENDENCY
            if _canonical(name) in resources
        )

        assert not both, (
            f"{both} are listed in _COVERED_BY_HOMEBREW_DEPENDENCY and also have "
            "a `resource` stanza. Pick one: if the resource is intended, delete "
            "the exemption from this file."
        )

    def test_every_resource_carries_an_sdist_url_and_a_sha256(self):
        """Well-formedness, checkable without Homebrew or a network.

        `brew audit --strict` covers this too, but only in the one CI job that
        has Homebrew. This runs everywhere, and it is what catches a generator
        that emitted a wheel: pip is invoked with `--no-binary=:all:`, so a
        `.whl` resource fails the install rather than degrading it.
        """
        text = _formula_text()
        # Each `resource "x" do ... end` block, non-greedy to the first `end`.
        blocks = re.findall(
            r'^\s*resource\s+"(?P<name>[^"]+)"\s+do\s*\n(?P<body>.*?)^\s*end\s*$',
            text,
            re.MULTILINE | re.DOTALL,
        )
        assert blocks, "No parsable `resource ... do ... end` blocks in the formula"

        problems = []
        for name, body in blocks:
            url = re.search(r'^\s*url\s+"(?P<url>[^"]+)"', body, re.MULTILINE)
            sha = re.search(r'^\s*sha256\s+"(?P<sha>[0-9a-f]{64})"', body, re.MULTILINE)
            if url is None:
                problems.append(f"{name}: no url")
                continue
            if sha is None:
                problems.append(f"{name}: no 64-hex sha256")
            if url.group("url").endswith(".whl"):
                problems.append(
                    f"{name}: url is a wheel, and Homebrew passes "
                    "--no-binary=:all: so pip will refuse it"
                )

        assert not problems, "Malformed resource stanzas: " + "; ".join(problems)

    def test_resource_names_are_unique(self):
        """A duplicate name installs one package twice and hides the other.

        Two stanzas with the same name are both staged and both installed, in
        file order, so the second silently wins. `brew audit` flags it, but only
        where Homebrew exists.
        """
        names = [_canonical(name) for name in _resource_names(_formula_text())]

        duplicates = sorted({name for name in names if names.count(name) > 1})

        assert not duplicates, (
            f"Formula/ash.rb declares these resource names more than once: "
            f"{duplicates}. Whichever stanza comes last is the version that ends "
            "up installed, so the earlier one is a pin that does nothing."
        )
