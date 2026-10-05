"""The sdist selects files from the repository root, not from anywhere in the tree.

`[tool.hatch.build.targets.sdist] include` is a list of gitignore patterns, so an
unanchored "Dockerfile" matched every Dockerfile at any depth. When the Kubernetes
operator landed with deploy/kubernetes-operator/Dockerfile, the sdist picked it up
and the artifact gate rejected the release build. A developer checkout with
deploy/cdk/node_modules installed pulled four more vendor Dockerfiles in.

These tests ask hatchling itself which files the sdist would carry, using the
project's real pyproject.toml, so they need no build and see exactly what
`uv build --sdist` sees. The artifact gate (.github/scripts/assert-artifact-contents.py)
still checks the built archive; this pins the cause one layer earlier.
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from hatchling.builders import sdist as hatchling_sdist

REPO_ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = REPO_ROOT / "pyproject.toml"

# Trees beside the package that hold their own build inputs. None of them is part
# of the Python distribution.
FORBIDDEN_TOP_LEVEL = ("deploy", "editors", "packaging")


def _load_pyproject() -> dict:
    with PYPROJECT.open("rb") as handle:
        return tomllib.load(handle)


def _selected_paths(config: dict) -> list[str]:
    builder = hatchling_sdist.SdistBuilder(str(REPO_ROOT), config=config)
    return sorted(
        included.distribution_path.replace("\\", "/")
        for included in builder.recurse_included_files()
    )


def _forbidden(paths: list[str]) -> list[str]:
    return [path for path in paths if path.split("/", 1)[0] in FORBIDDEN_TOP_LEVEL]


def test_sdist_carries_nothing_from_deploy_editors_or_packaging():
    paths = _selected_paths(_load_pyproject())
    assert paths, (
        "hatchling selected no files at all; the probe is not measuring anything"
    )
    assert "Dockerfile" in paths, "the root Dockerfile must still ship in the sdist"
    assert _forbidden(paths) == []


def test_sdist_include_patterns_are_anchored_to_the_root():
    patterns = _load_pyproject()["tool"]["hatch"]["build"]["targets"]["sdist"][
        "include"
    ]
    unanchored = [p for p in patterns if "/" not in p.rstrip("/")]
    assert unanchored == [], (
        f"{unanchored} have no slash, so gitignore matching applies them at every depth. "
        "Prefix them with '/'."
    )


def test_unanchored_patterns_would_pull_the_operator_dockerfile_in():
    """Negative control: the old patterns, run through the same probe, are caught.

    If this stops failing the forbidden check, the probe above cannot tell an
    anchored include from an unanchored one, and its pass means nothing.
    """
    config = copy.deepcopy(_load_pyproject())
    sdist = config["tool"]["hatch"]["build"]["targets"]["sdist"]
    sdist["include"] = [p.lstrip("/") for p in sdist["include"]]
    leaked = _forbidden(_selected_paths(config))
    assert "deploy/kubernetes-operator/Dockerfile" in leaked
