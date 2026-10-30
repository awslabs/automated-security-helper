# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Fixtures the ``ash report`` and ``ash merge`` tests share.

The ``capture`` fixture (ASH's logger routed into caplog) lives one level up, in
tests/unit/conftest.py: a module outside this directory binds it by name too.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.unit.cli.off_host_plugin_support import (
    DECLARED_ON_PLUGIN,
    DECLARED_ON_SOURCE,
    DECLARED_PLUGIN,
    DECLARED_SOURCE,
    PLUGIN,
    PLUGIN_SOURCE,
    make_plugin_site,
)


@pytest.fixture
def plugin_site(tmp_path: Path) -> Path:
    """An installed plugin package, outside every scanned tree in these tests.

    The package holds the stand-in off-host reporter that declares no destination
    options (``off_host_plugin_support``); a test makes it importable in a
    subprocess with ``plugin_environment(plugin_site)``.
    """
    return make_plugin_site(tmp_path, PLUGIN, PLUGIN_SOURCE)


@pytest.fixture
def declared_site(tmp_path: Path) -> Path:
    """The stand-in that declares ``endpoint`` as a destination option, off by default."""
    return make_plugin_site(tmp_path, DECLARED_PLUGIN, DECLARED_SOURCE)


@pytest.fixture
def declared_on_site(tmp_path: Path) -> Path:
    """The same stand-in with ``enabled`` on by default."""
    return make_plugin_site(tmp_path, DECLARED_ON_PLUGIN, DECLARED_ON_SOURCE)
