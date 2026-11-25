# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Self-scan oracle for the sdist lockfile harvest (A7 row 8, online leg).

ASH's own ``uv.lock`` resolves ``polars-runtime-32``, a compiled wheel whose
shared library carries no cargo-auditable audit data (the measured fact behind
this feature), so ASH's own scan autodetects it and harvests the upstream
``Cargo.lock`` from the sdist the lock pins by sha256. This oracle runs the real
harvester against this repository and asserts floors, not exact counts, so a
polars bump moves the numbers without breaking the oracle: at polars-runtime-32
1.44.2 the lockfile carries 581 packages (542 registry + 39 workspace), and the
prior lane measured the pinned syft reading all 581 from the extract.

It replaces the drift-gate test of the rejected vendored-lockfile approach:
instead of holding a committed file to ``uv.lock``, it holds the live harvest to
``uv.lock`` -- there is no committed artifact to go stale.

Online leg only: the harvest fetches the pinned sdist (~3 MB). It is skipped,
not failed, when ASH runs offline.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from automated_security_helper.core.constants import is_offline_mode

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        is_offline_mode(), reason="the harvest fetches the pinned sdist (online leg)"
    ),
]

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_ash_harvests_the_polars_crate_tree_from_its_own_lock(tmp_path: Path) -> None:
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.plugin_modules.ash_builtin.converters import (
        SdistLockHarvester,
    )
    from automated_security_helper.utils.sdist_harvest import (
        HARVEST_DIR_NAME,
        HARVEST_MANIFEST_NAME,
        flagged_packages_in_uv_lock,
    )

    lock_bytes = REPO_ROOT.joinpath("uv.lock").read_bytes()
    flagged = {p.name: p for p in flagged_packages_in_uv_lock(lock_bytes, "uv.lock")}
    assert "polars-runtime-32" in flagged, (
        "ASH's own lock resolves the compiled polars runtime; if this moved, the "
        "feature's own reason to exist moved with it"
    )
    polars = flagged["polars-runtime-32"]
    assert polars.sdist_sha256 is not None

    # A one-package source tree holding only the real lock entry under test, so
    # the oracle fetches one sdist, not every flagged package of the repository.
    source = tmp_path / "src"
    source.mkdir()
    entry_pattern = re.compile(
        r'\[\[package\]\]\nname = "polars-runtime-32"\n.*?(?=\n\[\[package\]\]\n|\Z)',
        re.DOTALL,
    )
    match = entry_pattern.search(lock_bytes.decode("utf-8"))
    assert match is not None
    source.joinpath("uv.lock").write_text(
        'version = 1\nrevision = 3\nrequires-python = ">=3.11"\n\n' + match.group(0),
        encoding="utf-8",
    )
    context = PluginContext(
        source_dir=source, output_dir=tmp_path / "out", config=get_default_config()
    )
    converter = SdistLockHarvester(context=context)

    results = converter.convert()

    harvest_root = converter.results_dir.joinpath(
        HARVEST_DIR_NAME, "polars-runtime-32", polars.version
    )
    lockfile = harvest_root.joinpath("Cargo.lock")
    assert lockfile.is_file(), (
        f"harvest produced {sorted(p.as_posix() for p in results)} and refused "
        f"{[r.reason for r in converter.refused_inputs]}"
    )
    content = lockfile.read_text(encoding="utf-8")
    packages = content.count("[[package]]")
    # Floor, not an exact count: 581 at polars-runtime-32 1.44.2 (542 registry +
    # 39 workspace); the pinned syft was measured reading every lockfile package
    # from the extract, so the lockfile's count is the SBOM's.
    assert packages >= 500
    registry = content.count('source = "registry+')
    assert registry >= 400
    assert packages > registry, "workspace crates carry no source line"
    manifest = json.loads(
        harvest_root.joinpath(HARVEST_MANIFEST_NAME).read_text(encoding="utf-8")
    )
    assert manifest["parent_purl"] == f"pkg:pypi/polars-runtime-32@{polars.version}"
    assert manifest["sdist_sha256"] == polars.sdist_sha256
