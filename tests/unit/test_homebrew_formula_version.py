# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Homebrew formula must point at the version this repository ships.

Why this file exists
--------------------
`Formula/ash.rb` pins the git tag Homebrew builds from. Nothing updated it: the
commitizen `version_files` list covered `pyproject.toml` only, so every release
bumped the package and left the formula behind. It reached v3.4.1 while the
repository was on v3.6.0, and `brew install` broke for anyone using the tap.

A stale tag does not fail any build. Homebrew resolves it happily -- it is a
real tag -- and just installs an old ASH, so the only signal is a user
reporting it. This test converts that into a failing check at the point the
drift is introduced.

Reading the version
-------------------
The comparison reads `pyproject.toml` directly rather than calling
`version_management.get_version()`. get_version() prefers installed package
metadata over pyproject, so in any environment where ASH is installed from
somewhere other than this checkout it reports that other version, and the test
would compare the formula against an unrelated number.

If this test fails after a release
----------------------------------
The formula did not get bumped. Check that `Formula/ash.rb` is still listed
under `[tool.commitizen] version_files` in pyproject.toml; if the entry was
removed or its pattern stopped matching the `tag:` line, `cz bump` silently
skips the file rather than reporting anything.
"""

import re
import sys
from pathlib import Path

import pytest

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on 3.10
    import tomli as tomllib

REPO_ROOT = Path(__file__).resolve().parents[2]
FORMULA_PATH = REPO_ROOT / "Formula" / "ash.rb"
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"

# `url "...git", tag: "v3.6.0"` -- captures the tag without the leading v.
_FORMULA_TAG = re.compile(r'tag:\s*"v(?P<version>[^"]+)"')


def _formula_tag_version() -> str:
    text = FORMULA_PATH.read_text(encoding="utf-8")
    match = _FORMULA_TAG.search(text)
    assert match is not None, (
        f'No `tag: "v<version>"` found in {FORMULA_PATH}. If the formula moved '
        "to a release tarball with a sha256 instead of a git tag, this test needs "
        "to read whichever field now carries the version."
    )
    return match.group("version")


def _pyproject_version() -> str:
    with PYPROJECT_PATH.open("rb") as handle:
        data = tomllib.load(handle)
    return data["project"]["version"]


@pytest.mark.skipif(
    not FORMULA_PATH.exists(),
    reason="Formula/ash.rb is absent; the tap is not maintained in-tree",
)
class TestHomebrewFormulaTracksPackageVersion:
    def test_formula_tag_matches_pyproject_version(self):
        formula_version = _formula_tag_version()
        package_version = _pyproject_version()

        assert formula_version == package_version, (
            f"Formula/ash.rb builds from v{formula_version} but this repository "
            f"is version {package_version}. `brew install` would fetch the older "
            "release. Bump the tag in Formula/ash.rb, and confirm the file is "
            "listed under [tool.commitizen] version_files so the next release "
            "does this automatically."
        )

    def test_commitizen_bumps_the_formula(self):
        """The prevention half of the fix, asserted directly.

        Without this, a future edit could drop Formula/ash.rb from version_files
        and the test above would only start failing one release later, by which
        point the cause is no longer in the recent history.
        """
        with PYPROJECT_PATH.open("rb") as handle:
            data = tomllib.load(handle)
        version_files = data["tool"]["commitizen"]["version_files"]

        assert any("Formula/ash.rb" in entry for entry in version_files), (
            "Formula/ash.rb is not in [tool.commitizen] version_files, so "
            f"`cz bump` will not update it. Current entries: {version_files}"
        )
