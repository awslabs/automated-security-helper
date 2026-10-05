# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Formula/ash.rb's resource block is a pure function of uv.lock.

packaging/homebrew/refresh-resources.py generates the block from uv.lock alone:
no resolver run and no network. That makes regeneration cheap enough to do on
every unit test run, which is what this file does -- it regenerates the formula
from the committed lock and requires the result to be byte-identical to the
committed formula.

That closes the gap tests/unit/test_homebrew_formula_resources.py documents for
itself: a transitive-only change (a dependency of a dependency gaining a
requirement, or a version bump in uv.lock) does not touch [project.dependencies],
so that file cannot see it. Here, any uv.lock change that moves the Homebrew
closure fails until the formula is regenerated.

Each check that can only pass has a control beside it that has to fail: a perturbed
sdist hash in a copy of the lock must be reported as drift, and a perturbed hash on
a package outside the closure must not be, so a regeneration that ignored the lock
entirely, or one that emitted the whole lock, is caught either way.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on 3.10
    import tomli as tomllib

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "packaging" / "homebrew" / "refresh-resources.py"
LOCK = REPO_ROOT / "uv.lock"
FORMULA = REPO_ROOT / "Formula" / "ash.rb"

_RESOURCE_BLOCK = re.compile(
    r'^  resource "(?P<name>[^"]+)" do\n'
    r'    url "(?P<url>[^"]+)"\n'
    r'    sha256 "(?P<sha>[0-9a-f]{64})"\n'
    r"  end$",
    re.MULTILINE,
)


@pytest.fixture(scope="module")
def refresh():
    spec = importlib.util.spec_from_file_location("ash_refresh_resources", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
        yield module
    finally:
        sys.modules.pop(spec.name, None)


def _formula() -> str:
    return FORMULA.read_text(encoding="utf-8")


def _lock_packages() -> list[dict]:
    with LOCK.open("rb") as handle:
        return tomllib.load(handle)["package"]


def _perturb_sdist_hash(lock_text: str, package: str) -> tuple[str, str, str]:
    """A copy of the lock text with one package's sdist sha256 changed.

    Returns (new text, old digest, new digest). The digest is changed in the
    `sdist = {...}` line of that package's [[package]] table only, so wheels and
    every other package are untouched.
    """
    pattern = re.compile(
        r'(\[\[package\]\]\nname = "' + re.escape(package) + r'"\n'
        r'(?:(?!\[\[package\]\]).)*?\nsdist = \{[^\n]*?hash = "sha256:)([0-9a-f]{64})',
        re.DOTALL,
    )
    match = pattern.search(lock_text)
    assert match, f"{package} has no sdist line in uv.lock"
    old = match.group(2)
    new = ("0" if old[0] != "0" else "1") + old[1:]
    return lock_text[: match.start(2)] + new + lock_text[match.end(2) :], old, new


class TestFormulaIsGeneratedFromTheLock:
    def test_committed_formula_is_byte_identical_to_its_regeneration(self, refresh):
        lines = refresh.drift(_formula(), LOCK)

        assert not lines, (
            "Formula/ash.rb does not match its regeneration from uv.lock. Run\n"
            "    uv run python packaging/homebrew/refresh-resources.py --write\n"
            "and commit the result.\n\n" + "\n".join(lines[:80])
        )

    def test_regeneration_is_deterministic(self, refresh):
        first, count = refresh.generate(_formula(), LOCK)
        second, _ = refresh.generate(_formula(), LOCK)

        assert first == second
        assert count > 30, (
            f"the closure produced {count} resources; ASH's runtime closure is "
            "about 78, so a count this low means the lock walk stopped early"
        )

    def test_lock_package_order_does_not_change_the_output(self, refresh, tmp_path):
        """Sorted by name, so only the lock's content and not its layout matters."""
        text = LOCK.read_text(encoding="utf-8")
        header, *tables = text.split("\n[[package]]\n")
        reordered = tmp_path / "uv.lock"
        reordered.write_text(
            header
            + "".join(
                "\n[[package]]\n" + t.rstrip("\n") + "\n" for t in reversed(tables)
            ),
            encoding="utf-8",
        )

        assert refresh.generate(_formula(), reordered) == refresh.generate(
            _formula(), LOCK
        )

    def test_resources_are_sorted_by_canonical_name(self, refresh):
        names = [m.group("name") for m in _RESOURCE_BLOCK.finditer(_formula())]

        assert names == sorted(names, key=refresh.canonical)

    def test_every_url_and_sha256_is_the_sdist_uv_lock_records(self, refresh):
        locked = {}
        for package in _lock_packages():
            sdist = package.get("sdist")
            if sdist:
                locked.setdefault(refresh.canonical(package["name"]), set()).add(
                    (sdist["url"], sdist["hash"].split(":", 1)[1])
                )
        blocks = list(_RESOURCE_BLOCK.finditer(_formula()))
        assert blocks, "no resource stanzas in the generated layout"

        foreign = [
            m.group("name")
            for m in blocks
            if (m.group("url"), m.group("sha"))
            not in locked.get(refresh.canonical(m.group("name")), set())
        ]
        assert not foreign, f"resources not taken from uv.lock: {foreign}"

    def test_the_cdk_extra_and_dev_group_stay_out(self, refresh):
        """cdk-nag is a scanner and rides on the optional cdk extra only."""
        closure = refresh.compute_closure(
            LOCK, refresh.formula_python_version(_formula())
        )

        assert "cdk-nag" not in closure
        assert "aws-cdk-lib" not in closure
        assert "pytest" not in closure


class TestNegativeControls:
    def test_a_perturbed_hash_in_the_closure_is_reported_as_drift(
        self, refresh, tmp_path
    ):
        text, old, new = _perturb_sdist_hash(
            LOCK.read_text(encoding="utf-8"), "pydantic"
        )
        perturbed = tmp_path / "uv.lock"
        perturbed.write_text(text, encoding="utf-8")

        lines = refresh.drift(_formula(), perturbed)

        assert any(line.startswith("-") and old in line for line in lines), lines
        assert any(line.startswith("+") and new in line for line in lines), lines

    def test_a_perturbed_hash_outside_the_closure_is_not(self, refresh, tmp_path):
        """pytest is dev-only. If this drifted, the walk would be emitting the
        whole lock rather than the runtime closure."""
        text, _, _ = _perturb_sdist_hash(LOCK.read_text(encoding="utf-8"), "pytest")
        perturbed = tmp_path / "uv.lock"
        perturbed.write_text(text, encoding="utf-8")

        assert refresh.drift(_formula(), perturbed) == []

    def test_check_mode_exits_nonzero_on_a_perturbed_lock(
        self, refresh, tmp_path, capsys
    ):
        text, _, _ = _perturb_sdist_hash(LOCK.read_text(encoding="utf-8"), "pydantic")
        perturbed = tmp_path / "uv.lock"
        perturbed.write_text(text, encoding="utf-8")

        assert refresh.main(["--check", "--lock", str(perturbed)]) == 1
        assert refresh.main(["--check"]) == 0

    def test_an_sdist_off_pypi_is_refused(self, refresh):
        package = {
            "name": "pydantic",
            "version": "1.0.0",
            "sdist": {
                "url": "https://example.com/pydantic-1.0.0.tar.gz",
                "hash": "sha256:" + "a" * 64,
            },
        }
        with pytest.raises(refresh.RefreshError, match="not an https URL on"):
            refresh.sdist_of("pydantic", package)

    def test_a_package_without_an_sdist_is_refused(self, refresh):
        with pytest.raises(refresh.RefreshError, match="no sdist"):
            refresh.sdist_of("pywin32", {"name": "pywin32", "version": "311"})

    def test_a_url_brew_audit_would_name_differently_is_refused(self, refresh):
        package = {
            "name": "pydantic",
            "version": "1.0.0",
            "sdist": {
                "url": "https://files.pythonhosted.org/packages/aa/other-1.0.0.tar.gz",
                "hash": "sha256:" + "a" * 64,
            },
        }
        with pytest.raises(refresh.RefreshError, match="brew audit"):
            refresh.sdist_of("pydantic", package)
