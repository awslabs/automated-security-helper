# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The trivy fixture repository, materialized for a test.

``tests/test_data/scanners/trivy/fixture_repo`` holds deliberately vulnerable
manifests (requests 2.19.1, lodash 4.17.20). They are committed with a ``.fixture``
suffix so that GitHub's dependency graph, and the Dependency Review check built on
it, do not read them as this repository's own dependencies; under their real names
the check fails every pull request on lodash's advisories. ``materialize`` copies the
tree and restores the names trivy looks for.
"""

from __future__ import annotations

import shutil
from pathlib import Path

TEMPLATE = (
    Path(__file__).resolve().parents[1]
    / "test_data"
    / "scanners"
    / "trivy"
    / "fixture_repo"
)
SUFFIX = ".fixture"


def materialize(dest: Path) -> Path:
    """Copy the fixture repo to *dest* with every ``.fixture`` suffix removed."""
    shutil.copytree(TEMPLATE, dest)
    for path in list(dest.rglob(f"*{SUFFIX}")):
        path.rename(path.with_name(path.name[: -len(SUFFIX)]))
    return dest
