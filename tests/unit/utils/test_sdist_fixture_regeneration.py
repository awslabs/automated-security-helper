# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The committed sdist-harvest fixtures equal what our generator writes (A7 row 1).

The fixture pair under ``tests/test_data/sdist_harvest/`` is committed so tests
have stable on-disk bytes, and generated so the bytes are reproducible and
provably authored in this repository -- never copied from any upstream package.
This test is the drift gate between the two: a change to the generator without
regenerating the committed files (or an edit to the committed files by hand)
fails here. Regenerate with::

    uv run python tests/utils/sdist_fixture.py
"""

from __future__ import annotations

import gzip
import tarfile
import zipfile
from pathlib import Path

import pytest

from tests.utils.sdist_fixture import (
    FIXTURE_DATA_DIR,
    FIXTURE_SDIST_NAME,
    FIXTURE_WHEEL_NAME,
    fixture_sdist_bytes,
    fixture_wheel_bytes,
)

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]


def test_committed_sdist_equals_generator_output() -> None:
    committed = REPO_ROOT.joinpath(FIXTURE_DATA_DIR, FIXTURE_SDIST_NAME).read_bytes()
    # Compare the decompressed tar: the gzip stream's bytes vary with the zlib
    # build (zlib-ng writes different deflate output), the tar inside does not.
    assert gzip.decompress(committed) == gzip.decompress(fixture_sdist_bytes())


def test_committed_wheel_equals_generator_output() -> None:
    committed = REPO_ROOT.joinpath(FIXTURE_DATA_DIR, FIXTURE_WHEEL_NAME).read_bytes()
    assert committed == fixture_wheel_bytes()


def test_generator_is_deterministic() -> None:
    assert fixture_sdist_bytes() == fixture_sdist_bytes()
    assert fixture_wheel_bytes() == fixture_wheel_bytes()


def test_sdist_ships_the_lockfile_at_its_root(tmp_path: Path) -> None:
    archive = tmp_path / FIXTURE_SDIST_NAME
    archive.write_bytes(fixture_sdist_bytes())
    with tarfile.open(archive, mode="r:gz") as tar:
        names = tar.getnames()
    assert "fixturepkg-0.1.0/Cargo.lock" in names
    assert "fixturepkg-0.1.0/PKG-INFO" in names


def test_wheel_filename_carries_a_platform_tag_and_is_a_zip(tmp_path: Path) -> None:
    from automated_security_helper.utils.sdist_harvest import (
        is_platform_wheel_filename,
    )

    assert is_platform_wheel_filename(FIXTURE_WHEEL_NAME)
    bundle = tmp_path / FIXTURE_WHEEL_NAME
    bundle.write_bytes(fixture_wheel_bytes())
    with zipfile.ZipFile(bundle) as wheel:
        assert "fixturepkg/_native.abi3.so" in wheel.namelist()
