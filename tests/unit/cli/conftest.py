# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Fixtures the ``ash report`` and ``ash merge`` plugin-reporter tests share."""

from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor
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


@pytest.fixture(autouse=True)
def _the_source_delivery_pools_are_this_tests_own(monkeypatch):
    """Each test gets clone and delivery pools of its own, started on first use.

    A stdio server's lifespan and an HTTP app's shutdown close the two pools in
    ``cli/mcp_server``, as the server's exit does
    (``_begin_stopping_source_jobs``), and a closed pool takes no more jobs.
    The pools are module-global, so a test that closes an app or leaves the stdio
    lifespan would otherwise make every later test in its worker fail on submit.

    Left alone when the module has not been imported: there is no pool to close,
    and importing it here would load the MCP server for every test of this
    directory.
    """
    module = sys.modules.get("automated_security_helper.cli.mcp_server")
    if module is None:
        yield
        return
    from automated_security_helper.cli.mcp import source_delivery

    clone = ThreadPoolExecutor(
        max_workers=source_delivery.CLONE_MAX_WORKERS,
        thread_name_prefix="ash-mcp-clone",
    )
    delivery = ThreadPoolExecutor(
        max_workers=source_delivery.DELIVERY_MAX_WORKERS,
        thread_name_prefix="ash-mcp-delivery",
    )
    monkeypatch.setattr(module, "_CLONE_EXECUTOR", clone)
    monkeypatch.setattr(module, "_DELIVERY_EXECUTOR", delivery)
    yield
    clone.shutdown(wait=False, cancel_futures=True)
    delivery.shutdown(wait=False, cancel_futures=True)


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
