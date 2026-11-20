"""The e2e's ASH image build context, checked without docker or a cluster.

The e2e builds ASH from a staged copy of the checkout. That context once lacked the
root Dockerfile, which hatch_build.py turns into the force-included
automated_security_helper/assets/Dockerfile, and it still built on a developer's
machine because an earlier build had left the generated file in the checkout and
the copy carried it along. On a clean CI checkout every e2e test errored at setup.
These run in the ordinary unit job, so a context that would fail that way goes red
there and not only behind ASH_OPERATOR_E2E=1.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.e2e.helpers import (
    ASH_GENERATED_ASSETS,
    ASH_SOURCE_FILES,
    REPO_ROOT,
    stage_ash_source,
)

FORCE_INCLUDED_ASSET = re.compile(r'^"automated_security_helper/assets/([^"/]+)"\s*=', re.M)


def _force_included_assets() -> set[str]:
    names = set(FORCE_INCLUDED_ASSET.findall((REPO_ROOT / "pyproject.toml").read_text()))
    assert names, "found no force-included assets in pyproject.toml; the pattern is stale"
    return names


def _fake_repo(root: Path, *, omit: str | None = None) -> Path:
    root.mkdir()
    for name in ASH_SOURCE_FILES:
        if name != omit:
            (root / name).write_text(f"{name}\n")
    assets = root / "automated_security_helper" / "assets"
    (assets / "__pycache__").mkdir(parents=True)
    (assets / "__pycache__" / "x.cpython-312.pyc").write_bytes(b"")
    (assets / "with-retry.sh").write_text("tracked\n")
    for name in ASH_GENERATED_ASSETS:
        (assets / name).write_text("left behind by an earlier build\n")
    return root


def test_the_root_dockerfile_is_staged_from_the_real_checkout(tmp_path):
    dest = tmp_path / "ash-source"
    stage_ash_source(dest)
    for name in ASH_SOURCE_FILES:
        assert (dest / name).read_bytes() == (REPO_ROOT / name).read_bytes(), name
    assert (dest / "Dockerfile").is_file()
    assert (dest / "automated_security_helper" / "__init__.py").is_file()


def test_every_force_included_asset_is_one_the_build_generates():
    # Each force-included asset is gitignored and produced during the build, so it is
    # absent from a clean checkout. If pyproject.toml gains another, its source has to
    # be staged and ASH_GENERATED_ASSETS has to name it, or the clean build breaks the
    # same way again.
    assert _force_included_assets() <= ASH_GENERATED_ASSETS
    assert "Dockerfile" in ASH_SOURCE_FILES


def test_generated_assets_left_in_the_checkout_are_not_carried(tmp_path):
    repo = _fake_repo(tmp_path / "repo")
    dest = tmp_path / "ash-source"
    stage_ash_source(dest, repo_root=repo)
    staged_assets = dest / "automated_security_helper" / "assets"
    assert sorted(path.name for path in staged_assets.iterdir()) == ["with-retry.sh"]


@pytest.mark.parametrize("name", ASH_SOURCE_FILES)
def test_a_missing_source_file_refuses_rather_than_skipping(tmp_path, name):
    repo = _fake_repo(tmp_path / "repo", omit=name)
    with pytest.raises(FileNotFoundError, match=re.escape(repr(name))):
        stage_ash_source(tmp_path / "ash-source", repo_root=repo)
