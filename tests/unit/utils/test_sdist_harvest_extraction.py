# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Safe extraction of embedded lockfiles from a verified sdist (A7 row 6).

The harvest never calls ``extractall`` and never uses a member's own path for
filesystem placement: only regular-file members whose BASENAME is a recognized
lockfile are read, and their content is written under a path the harvester
builds. These tests feed a generated malicious archive (a ``..`` member, an
absolute-path member, a link member) and assert nothing lands outside the
destination directory and only the honest member is harvested.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.utils.sdist_harvest import (
    harvest_lockfiles_from_sdist,
)
from tests.utils.sdist_fixture import (
    CARGO_LOCK,
    fixture_sdist_bytes,
    malicious_sdist_bytes,
)

pytestmark = pytest.mark.unit


def _everything_under(root: Path) -> set[str]:
    return {p.relative_to(root).as_posix() for p in root.rglob("*")}


def test_malicious_members_are_refused_and_nothing_escapes(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    archive = sandbox / "evil-0.1.0.tar.gz"
    archive.write_bytes(malicious_sdist_bytes())
    destination = sandbox / "extract"

    written = harvest_lockfiles_from_sdist(
        archive, ["Cargo.lock", "go.sum"], destination
    )

    # Only the honest regular-file member was harvested; the symlinked go.sum,
    # the absolute-path member and the ".." member were not read at all.
    assert written == ["Cargo.lock"]
    assert destination.joinpath("Cargo.lock").read_text(encoding="utf-8") == CARGO_LOCK
    # Nothing anywhere outside the destination: the sandbox holds exactly the
    # archive and the confined extract.
    assert _everything_under(sandbox) == {
        "evil-0.1.0.tar.gz",
        "extract",
        "extract/Cargo.lock",
    }
    assert _everything_under(tmp_path) == {"sandbox"} | {
        f"sandbox/{p}" for p in _everything_under(sandbox)
    }


def test_shallowest_lockfile_wins_over_a_vendored_copy(tmp_path: Path) -> None:
    """The workspace lockfile at the archive root beats a deeper vendored copy."""
    deep = b"# the vendored copy that must lose\nversion = 3\n"
    archive = tmp_path / "fixture.tar.gz"
    archive.write_bytes(
        fixture_sdist_bytes(
            extra_members={"fixturepkg-0.1.0/vendor/dep/Cargo.lock": deep}
        )
    )
    destination = tmp_path / "extract"

    written = harvest_lockfiles_from_sdist(archive, ["Cargo.lock"], destination)

    assert written == ["Cargo.lock"]
    assert destination.joinpath("Cargo.lock").read_text(encoding="utf-8") == CARGO_LOCK


def test_only_wanted_basenames_are_materialized(tmp_path: Path) -> None:
    """Narrowing the ecosystems list narrows what is written."""
    archive = tmp_path / "fixture.tar.gz"
    archive.write_bytes(fixture_sdist_bytes())
    destination = tmp_path / "extract"

    written = harvest_lockfiles_from_sdist(archive, ["go.sum"], destination)

    assert written == []
    assert not destination.exists()
