# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The uv runner's timeout texts quote the limit as its own token, ``'67' s``.

The texts reach the plugin's errors and the row's reason, which are redacted
with the config's environment values, and a short number is replaced only where
it is quoted whole: a two-digit limit inside "67s" or "67 seconds" is not a
replaceable token. The subprocess layer's timeout reasons use the same form, so
every timeout reads alike.
"""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock

import pytest

from automated_security_helper.utils.uv_tool_runner import (
    UVToolRunner,
    UVToolRunnerError,
    _reset_uv_tool_runner_caches,
)

_SPAWN_RUN = "automated_security_helper.utils.uv_tool_runner.spawn_run"


@pytest.fixture
def uv_runner():
    _reset_uv_tool_runner_caches()
    runner = UVToolRunner(uv_executable="uv")
    runner._uv_available_cache = True
    yield runner
    _reset_uv_tool_runner_caches()


def test_the_install_timeout_quotes_its_limit(uv_runner, monkeypatch):
    # Past the already-installed probe, so the attempt loop's spawn is the one
    # that times out.
    monkeypatch.setattr(UVToolRunner, "is_tool_installed", lambda self, name: False)
    monkeypatch.setattr(
        _SPAWN_RUN,
        MagicMock(side_effect=subprocess.TimeoutExpired(cmd=["uv"], timeout=67)),
    )

    with pytest.raises(UVToolRunnerError) as info:
        uv_runner.install_tool_with_version("bandit", timeout=67)

    # ASH's own clause, apart from the appended stdlib exception text, which
    # keeps its library wording.
    ash_text = str(info.value).split("Error:", 1)[0]
    assert "timed out after '67' s" in ash_text, ash_text
    assert "67 seconds" not in ash_text, ash_text


def test_the_fallback_run_timeout_quotes_its_limit(uv_runner, monkeypatch):
    """The no-results-dir branch returns a timed-out result whose error and
    stderr both quote the limit whole."""
    monkeypatch.setattr(
        _SPAWN_RUN,
        MagicMock(side_effect=subprocess.TimeoutExpired(cmd=["uv"], timeout=67)),
    )

    result = uv_runner.run_tool("bandit", args=[], timeout=67)

    assert getattr(result, "timed_out", False) is True, result
    assert "timed out after '67' s" in str(result.error), result.error
    assert "timed out after '67' s" in str(result.stderr), result.stderr
    assert "67s" not in str(result.error), result.error
