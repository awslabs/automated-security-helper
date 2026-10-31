# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scan tool's config pre-check builds its settings with the scan's own predicate.

The scan reads a named config with every chain file confined when the path the
client named is the client's: not in a configured config root and not the
session's own profile file (``sandbox.client_named_config_is_untrusted``, the
``untrusted_config`` of ``_run_scan``). The pre-check that resolves the same
chain before the scan is registered judged the file by ``config_is_client_supplied``
instead, which is true only for a file under the shared workspace root, so a
named file elsewhere was read with the operator's settings while the scan read
it confined: the pre-check's own docstring promises the scan's settings, and a
refusal of its read is swallowed as the scan's. Both now use the scan's predicate.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, List

import pytest

pytestmark = pytest.mark.unit

SESSION = "client-one"


@pytest.fixture
def recorded_every_file(monkeypatch) -> List[Any]:
    """The ``every_file`` each ``scan_repository_settings`` call was built with."""
    from automated_security_helper.config import operator_only_options

    seen: List[Any] = []
    original = operator_only_options.scan_repository_settings

    def recording(trees, every_file: bool = False):
        seen.append(every_file)
        return original(trees, every_file=every_file)

    monkeypatch.setattr(operator_only_options, "scan_repository_settings", recording)
    return seen


@pytest.fixture
def layout(tmp_path, monkeypatch) -> Path:
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    source = tmp_path / "scan"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    return tmp_path


def test_a_named_config_outside_the_config_roots_is_read_confined(
    layout: Path, recorded_every_file: List[Any]
) -> None:
    from automated_security_helper.cli.mcp.sandbox import (
        client_named_config_is_untrusted,
    )
    from automated_security_helper.cli.mcp_tools import _config_pre_check

    named = layout / "elsewhere" / "ash.yaml"
    named.parent.mkdir()
    named.write_text("project_name: named\n", encoding="utf-8")
    # The premise: the scan reads this file as the client's.
    assert client_named_config_is_untrusted(named, session_id=SESSION) is True

    pre_check = _config_pre_check(named, layout / "scan", SESSION)

    assert pre_check.env_refusal is None and pre_check.load_refusal is None
    assert recorded_every_file == [True], recorded_every_file


def test_a_named_config_in_a_config_root_is_the_operators(
    layout: Path, recorded_every_file: List[Any], monkeypatch
) -> None:
    from automated_security_helper.cli.mcp_tools import _config_pre_check

    operator = layout / "operator"
    operator.mkdir()
    named = operator / "ash.yaml"
    named.write_text("project_name: operator\n", encoding="utf-8")
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(operator))

    pre_check = _config_pre_check(named, layout / "scan", SESSION)

    assert pre_check.env_refusal is None and pre_check.load_refusal is None
    assert recorded_every_file == [False], recorded_every_file


def test_a_discovered_config_is_never_the_clients_by_name(
    layout: Path, recorded_every_file: List[Any]
) -> None:
    from automated_security_helper.cli.mcp_tools import _config_pre_check

    (layout / "scan" / ".ash.yaml").write_text(
        "project_name: discovered\n", encoding="utf-8"
    )

    pre_check = _config_pre_check(None, layout / "scan", SESSION)

    assert pre_check.env_refusal is None and pre_check.load_refusal is None
    assert recorded_every_file == [False], recorded_every_file
