# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fixtures shared by the real-trivy tests in this directory.

``trivy_bin_dir`` finds the pinned trivy release or installs it through ASH's own
verified installer, and a failure to provision it FAILS the test rather than skipping
it, so a test that uses it cannot pass in CI without running trivy.
It has session scope, so a host without the pinned release downloads and verifies it
once for the whole run, not once for each module that uses the fixture.
``trivy_on_path`` puts that directory first on PATH for one test and clears the
process-wide cache of executable lookups, which holds a miss as well as a hit.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from tests.utils.trivy_fixture import (
    PINNED_TRIVY,
    host_arch,
    host_platform,
    version_of,
)


@pytest.fixture(scope="session")
def trivy_bin_dir(tmp_path_factory) -> Path:
    """A directory holding the pinned trivy, provisioned if need be, once per run."""
    on_path = shutil.which("trivy")
    if on_path and version_of(on_path) == PINNED_TRIVY:
        return Path(on_path).parent
    from automated_security_helper.utils.download_utils import install_pinned_tool

    bin_dir = tmp_path_factory.mktemp("trivy-bin")
    try:
        installed = install_pinned_tool("trivy", host_platform(), host_arch(), bin_dir)
    except Exception as exc:  # pragma: no cover - network-dependent
        pytest.fail(
            f"could not provision trivy {PINNED_TRIVY} through ASH's pinned installer "
            f"({exc}). These tests must run, not skip."
        )
    assert version_of(str(installed)) == PINNED_TRIVY
    return bin_dir


@pytest.fixture
def trivy_on_path(trivy_bin_dir, monkeypatch) -> Path:
    """The pinned trivy first on PATH, with no executable lookup remembered."""
    from automated_security_helper.utils import subprocess_utils

    monkeypatch.setenv("PATH", f"{trivy_bin_dir}{os.pathsep}{os.environ['PATH']}")
    # find_executable caches per process, including a miss.
    monkeypatch.setattr(subprocess_utils, "_find_executable_cache", {})
    return trivy_bin_dir
