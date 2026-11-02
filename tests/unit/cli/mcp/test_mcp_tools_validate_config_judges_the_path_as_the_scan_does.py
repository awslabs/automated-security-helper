# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""validate_config judges a named config path by the predicate the scan uses.

``validate_config`` decided ``untrusted_config`` with ``config_is_client_supplied``
(was the file delivered by a client?), while a scan decides it with
``client_named_config_is_untrusted`` (did the client name a path the operator
did not set aside?). For a repository config under the scan roots that no client
delivered, the two disagree: the validator read it as the operator's and
reported it valid, and the scan then refused it as the client's (or the reverse,
for a file the operator set aside). The validator now asks the scan's question.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict

import pytest

from automated_security_helper.cli.mcp.profile_registry import (
    clear_all_session_state,
    clear_profile_registry,
)
from automated_security_helper.config.config_validator import ConfigValidator

pytestmark = pytest.mark.unit

SESSION = "client-1"


class _Captured(Exception):
    pass


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Dict[str, Path]:
    scan_root = tmp_path / "scan-root"
    other = scan_root / "other"
    other.mkdir(parents=True)
    operator = tmp_path / "operator"
    operator.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(scan_root))
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(operator))
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    clear_profile_registry()
    clear_all_session_state()
    yield {"other": other, "operator": operator}
    clear_profile_registry()
    clear_all_session_state()


def _capturing(seen: Dict[str, Any], monkeypatch) -> None:
    def check_config_file(path: Path, **kwargs: Any) -> Any:
        seen.update(kwargs)
        seen["path"] = path
        raise _Captured

    monkeypatch.setattr(
        ConfigValidator, "check_config_file", staticmethod(check_config_file)
    )


def _validate(path: Path) -> None:
    from automated_security_helper.cli.mcp_tools import mcp_validate_config

    try:
        mcp_validate_config(config_path=str(path), session_id=SESSION)
    except _Captured:
        pass


def test_a_repository_config_a_remote_client_names_is_the_clients(
    _server, monkeypatch
) -> None:
    from automated_security_helper.cli.mcp.sandbox import (
        client_named_config_is_untrusted,
        config_is_client_supplied,
    )

    named = _server["other"] / "ash.yaml"
    named.write_text("project_name: x\n", encoding="utf-8")
    # The two predicates disagree on this file: nobody delivered it, and the
    # operator did not set it aside.
    assert config_is_client_supplied(named) is False
    assert client_named_config_is_untrusted(named, session_id=SESSION) is True
    seen: Dict[str, Any] = {}
    _capturing(seen, monkeypatch)

    _validate(named)

    assert seen, "the validator never reached the file check"
    assert seen["untrusted_config"] is True, seen


def test_a_config_the_operator_set_aside_keeps_the_operators_trust(
    _server, monkeypatch
) -> None:
    named = _server["operator"] / "ash.yaml"
    named.write_text("project_name: x\n", encoding="utf-8")
    seen: Dict[str, Any] = {}
    _capturing(seen, monkeypatch)

    _validate(named)

    assert seen, "the validator never reached the file check"
    assert seen["untrusted_config"] is False, seen


def test_the_session_copy_of_a_bound_profile_keeps_the_operators_trust(
    monkeypatch,
) -> None:
    """Everything under the shared workspace root is a client's delivery except
    the profile files the server writes in a session's ``config/`` directory, so
    the copy of a bound profile sits under that root and is still the operator's:
    neither predicate calls it the client's, and the validator reports it
    trusted. A validator that judged by the location alone, or by the file
    existing under the root, would call it the client's and drop the operator's
    settings from the answer."""
    from automated_security_helper.cli.mcp.profile_registry import (
        SESSION_CONFIG_FILENAME,
    )
    from automated_security_helper.cli.mcp.sandbox import (
        CONFIG_DIR_NAME,
        client_named_config_is_untrusted,
        config_is_client_supplied,
    )

    copy = (
        Path(os.environ["ASH_MCP_WORKSPACE_ROOT"])
        / SESSION
        / CONFIG_DIR_NAME
        / SESSION_CONFIG_FILENAME
    )
    copy.parent.mkdir(parents=True)
    copy.write_text("project_name: x\n", encoding="utf-8")
    assert config_is_client_supplied(copy) is False
    assert client_named_config_is_untrusted(copy, session_id=SESSION) is False
    seen: Dict[str, Any] = {}
    _capturing(seen, monkeypatch)

    _validate(copy)

    assert seen, "the validator never reached the file check"
    assert seen["untrusted_config"] is False, seen
