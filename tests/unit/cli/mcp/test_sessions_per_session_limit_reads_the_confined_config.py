# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The per-session scan limit is read as the server's other limits are.

``mcp_tools._resource_limits`` reads ``max_concurrent_scans`` with
``default_config_for_tree``: the operator's ASH_CONFIG loaded as a scan rooted at
the server's working directory loads it. ``per_session_scan_limit`` read
``max_concurrent_scans_per_session`` with an unconfined ``get_default_config``, so
one file could yield the operator's server-wide limit and the default per-session
limit, when the confined read loaded it and the unconfined one refused it (an
operator-only option written inside the checkout). Both limits come from the same
read.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from automated_security_helper.cli.mcp import sandbox
from automated_security_helper.cli.mcp.sessions import per_session_scan_limit
from automated_security_helper.config import default_config
from automated_security_helper.config.ash_config import MCPResourceManagementConfig

pytestmark = pytest.mark.unit

OPERATORS_LIMIT = 7
DEFAULT_LIMIT = MCPResourceManagementConfig().max_concurrent_scans_per_session


@pytest.fixture
def remote_caller(monkeypatch) -> None:
    monkeypatch.setattr(sandbox, "caller_is_remote", lambda session_id: True)


def _a_config_with_the_limit(limit: int) -> SimpleNamespace:
    return SimpleNamespace(
        mcp_resource_management=MCPResourceManagementConfig(
            max_concurrent_scans_per_session=limit
        )
    )


def test_the_limit_comes_from_the_confined_read(remote_caller, monkeypatch) -> None:
    assert OPERATORS_LIMIT != DEFAULT_LIMIT, "control: the limits must differ"
    monkeypatch.setattr(
        default_config,
        "default_config_for_tree",
        lambda scan_root=None: _a_config_with_the_limit(OPERATORS_LIMIT),
    )

    def an_unconfined_read_that_is_not_made(*args, **kwargs):
        raise AssertionError("the limit was read with get_default_config")

    monkeypatch.setattr(
        default_config, "get_default_config", an_unconfined_read_that_is_not_made
    )

    assert per_session_scan_limit("a-remote-session") == OPERATORS_LIMIT


def test_a_confined_read_that_fails_keeps_the_default(
    remote_caller, monkeypatch
) -> None:
    def a_file_that_does_not_load(scan_root=None):
        raise ValueError("a planted unloadable file")

    monkeypatch.setattr(
        default_config, "default_config_for_tree", a_file_that_does_not_load
    )

    assert per_session_scan_limit("a-remote-session") == DEFAULT_LIMIT


def test_a_local_caller_has_no_limit(monkeypatch) -> None:
    monkeypatch.setattr(sandbox, "caller_is_remote", lambda session_id: False)

    assert per_session_scan_limit(None) is None
