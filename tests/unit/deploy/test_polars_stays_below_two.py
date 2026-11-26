#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""polars stays below 2, and Dependabot is told never to bump it.

Why this file exists
--------------------
``pyproject.toml`` declares ``polars>=1.33,<2.0``. polars 2.x is a major release and
raising the cap is a separate, deliberate change. Dependabot's ``engine-major-upgrade``
group matches every dependency, so it rewrote the requirement to ``>=2.1.0,<3.0`` (#1071).
The cap alone does not hold: an automated bump edits the cap itself. The
``.github/dependabot.yml`` ``ignore`` entry for ``polars`` is what keeps the bump from
being proposed.

What is asserted
----------------
1. The ``polars`` requirement in ``[project].dependencies`` has an upper bound that admits
   no 2.x release: a ``<`` or ``<=`` clause whose version is at most 2.
2. ``.github/dependabot.yml`` carries an ``ignore`` entry for ``polars`` with no
   ``update-types`` restriction, in an entry that manages the root ``pyproject.toml``.

Both predicates take parsed data, so the tests below can feed them a mutated copy and show
that they flag it.
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml
from packaging.requirements import Requirement
from packaging.version import Version

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on 3.10
    import tomli as tomllib

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
PYPROJECT = REPO_ROOT / "pyproject.toml"
DEPENDABOT = REPO_ROOT / ".github" / "dependabot.yml"

PACKAGE = "polars"
CEILING = Version("2")


def polars_requirement_is_capped_below_two(pyproject: dict[str, Any]) -> bool:
    """True when every ``polars`` requirement has an upper bound that excludes 2.x."""
    found = False
    for text in pyproject.get("project", {}).get("dependencies", []):
        requirement = Requirement(text)
        if requirement.name.lower() != PACKAGE:
            continue
        found = True
        capped = any(
            (spec.operator == "<" and Version(spec.version) <= CEILING)
            or (spec.operator == "<=" and Version(spec.version) < CEILING)
            or (
                spec.operator in ("==", "===")
                and Version(spec.version.rstrip(".*")) < CEILING
            )
            for spec in requirement.specifier
        )
        if not capped:
            return False
    return found


def dependabot_ignores_polars(config: dict[str, Any]) -> bool:
    """True when a root-manifest uv or pip entry ignores every update of ``polars``."""
    for entry in config.get("updates", []):
        if (
            entry.get("package-ecosystem") not in ("uv", "pip")
            or entry.get("directory") != "/"
        ):
            continue
        for rule in entry.get("ignore", []):
            if (
                rule.get("dependency-name") == PACKAGE
                and not rule.get("update-types")
                and not rule.get("versions")
            ):
                return True
    return False


def _load_pyproject() -> dict[str, Any]:
    with PYPROJECT.open("rb") as handle:
        return tomllib.load(handle)


def _load_dependabot() -> dict[str, Any]:
    return yaml.safe_load(DEPENDABOT.read_text(encoding="utf-8"))


def test_pyproject_caps_polars_below_two() -> None:
    assert polars_requirement_is_capped_below_two(_load_pyproject()), (
        "pyproject.toml's polars requirement has no upper bound below 2: polars stays on 1.x"
    )


def test_dependabot_ignores_polars() -> None:
    assert dependabot_ignores_polars(_load_dependabot()), (
        ".github/dependabot.yml has no `ignore` entry for polars on the root uv entry: "
        "Dependabot would propose raising the cap"
    )


def test_cap_predicate_flags_a_cap_that_admits_two() -> None:
    pyproject = _load_pyproject()
    mutated = copy.deepcopy(pyproject)
    mutated["project"]["dependencies"] = [
        "polars>=1.33,<3.0" if Requirement(d).name.lower() == PACKAGE else d
        for d in mutated["project"]["dependencies"]
    ]
    assert not polars_requirement_is_capped_below_two(mutated)
    uncapped = copy.deepcopy(pyproject)
    uncapped["project"]["dependencies"] = [
        "polars>=1.33" if Requirement(d).name.lower() == PACKAGE else d
        for d in uncapped["project"]["dependencies"]
    ]
    assert not polars_requirement_is_capped_below_two(uncapped)
    assert not polars_requirement_is_capped_below_two({"project": {"dependencies": []}})


def test_ignore_predicate_flags_a_missing_or_narrowed_entry() -> None:
    config = _load_dependabot()
    missing = copy.deepcopy(config)
    for entry in missing["updates"]:
        entry["ignore"] = [
            r for r in entry.get("ignore", []) if r.get("dependency-name") != PACKAGE
        ]
    assert not dependabot_ignores_polars(missing)
    narrowed = copy.deepcopy(config)
    for entry in narrowed["updates"]:
        for rule in entry.get("ignore", []):
            if rule.get("dependency-name") == PACKAGE:
                rule["update-types"] = ["version-update:semver-major"]
    assert not dependabot_ignores_polars(narrowed)
