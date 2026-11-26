# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Shared fixtures of the plugin conformance tests: the fixture plugin and a copy of its
transcript directory a test may damage."""

import shutil
import sys
from pathlib import Path

import pytest

_FIXTURE = Path(__file__).resolve().parent / "fixture_plugin"


@pytest.fixture
def fixture_manifest(monkeypatch):
    """The fixture plugin's manifest, with its package importable for the test only."""
    monkeypatch.syspath_prepend(str(_FIXTURE))
    for name in [m for m in sys.modules if m.split(".")[0] == "ash_fixture_plugin"]:
        monkeypatch.delitem(sys.modules, name)
    from ash_fixture_plugin.manifest import MANIFEST

    yield MANIFEST
    for name in [m for m in sys.modules if m.split(".")[0] == "ash_fixture_plugin"]:
        sys.modules.pop(name, None)


@pytest.fixture
def transcripts_copy(tmp_path) -> Path:
    """A private copy of the fixture plugin's transcript directory."""
    target = tmp_path / "scanners" / "fixture"
    shutil.copytree(_FIXTURE / "transcripts", target)
    return tmp_path / "scanners"
