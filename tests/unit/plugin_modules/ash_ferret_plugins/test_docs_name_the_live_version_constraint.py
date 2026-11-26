# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every docs copy of the ferret-scan version constraint is the live one.

Why this exists
---------------
``ferret_scanner.DEFAULT_VERSION_CONSTRAINT`` is the one source for the supported
ferret-scan range: the installer uses it and the CI scan-test action reads it from
the module. The plugin's README, its DEVELOPMENT notes and the alpha plugin page
spell the range out in ``pip install`` lines and ``tool_version`` examples, by
hand. A bump of the constant that misses one of those lines ships documentation
that installs a release the plugin was not tested with.

What this checks
----------------
Each spelling of the range in the three pages (a ``pip install 'ferret-scan...'``
line, a ``tool_version: ">=..."`` example, DEVELOPMENT.md's "unset uses" cell)
equals the constant. Deliberate non-copies are not matched: the hypothetical
bump example in DEVELOPMENT.md ("If new version is compatible") and the generic
``e.g., >=1.0.0,<2.0.0`` form in README's option table spell the range without
the shapes this test reads.
"""

import re
from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
    DEFAULT_VERSION_CONSTRAINT,
)

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[4]
PAGES = (
    "automated_security_helper/plugin_modules/ash_ferret_plugins/README.md",
    "automated_security_helper/plugin_modules/ash_ferret_plugins/DEVELOPMENT.md",
    "docs/content/docs/plugins/alpha/ferret-scan-plugin.md",
)
_RANGE = r"(>=\d[\d.]*,<\d[\d.]*)"
_COPY_SHAPES = (
    re.compile(rf"ferret-scan{_RANGE}"),
    re.compile(rf'tool_version:\s*"{_RANGE}"'),
    re.compile(rf"unset uses `{_RANGE}`"),
)


def _copies(text: str) -> "list[str]":
    return [match for shape in _COPY_SHAPES for match in shape.findall(text)]


def test_every_docs_copy_of_the_constraint_is_the_constant():
    stale = []
    found = 0
    for rel in PAGES:
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        for copy in _copies(text):
            found += 1
            if copy != DEFAULT_VERSION_CONSTRAINT:
                stale.append(f"{rel}: '{copy}'")
    assert found >= 3, (
        "the docs no longer spell the ferret-scan range in any shape this test "
        "reads; update _COPY_SHAPES with the docs"
    )
    assert not stale, (
        f"stale ferret-scan ranges (the live constraint is "
        f"'{DEFAULT_VERSION_CONSTRAINT}'):\n" + "\n".join(stale)
    )


def test_the_shapes_catch_a_stale_copy():
    """Control: a drifted spelling in each shape is found and compared."""
    sample = (
        "pip install 'ferret-scan>=0.0.1,<0.0.2'\n"
        'tool_version: ">=0.0.1,<0.0.2"\n'
        "unset uses `>=0.0.1,<0.0.2`\n"
    )
    copies = _copies(sample)
    assert len(copies) == 3
    assert all(copy != DEFAULT_VERSION_CONSTRAINT for copy in copies)
