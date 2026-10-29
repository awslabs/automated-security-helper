# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""validate_config refuses an environment reference in a remote caller's named file.

Why this file exists
--------------------
The environment a config reference reads is the server's. For a remote caller,
``config_sources.env_refused_for`` refuses every config file that is not one of
the operator's (a file under ``ASH_MCP_ALLOWED_CONFIG_ROOTS`` or the session's own
profile directory), so a ``${VAR}`` reference or an ``!ENV`` tag in such a file is
``config_env_not_resolved`` and nothing is read from the environment. A scan of the
same file is refused that way, and so is ``config_content`` from the same caller.

``validate_config`` computed whether the caller is remote and then handed the
named file to the validator, which resolves every reference it finds. The file was
read with the server's environment and reported valid, so the answer depended on
what the server had set.

Each case names a file in the scan root, outside the config roots, as a remote
client does. The controls pass before and after: the same file from the local
caller resolves its references, and a remote caller's file in the config roots does
too.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.cli.mcp.profile_registry import (
    DEFAULT_SESSION_ID,
    clear_all_session_state,
    clear_profile_registry,
)

pytestmark = pytest.mark.unit

REMOTE = "client-1"
PROBE_VAR = "ASH_NAMED_ENV_PROBE"
PROBE_VALUE = "probe-value-from-the-servers-environment"

#: The same reference spelled as a plain scalar and as the !ENV tag.
REFERENCES = {
    "plain": f"project_name: ${{{PROBE_VAR}}}\n",
    "tag": f"project_name: !ENV ${{{PROBE_VAR}:fallback}}\n",
}


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    scan_root = tmp_path / "scan-root"
    (scan_root / "repo").mkdir(parents=True)
    operator = tmp_path / "operator"
    operator.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(scan_root))
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(operator))
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    monkeypatch.setenv(PROBE_VAR, PROBE_VALUE)
    clear_profile_registry()
    clear_all_session_state()
    yield {"repo": scan_root / "repo", "operator": operator}
    clear_profile_registry()
    clear_all_session_state()


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _types(result: Dict[str, Any]) -> List[str]:
    return [error["type"] for error in result["errors"]]


def _validate(**kwargs: Any) -> Dict[str, Any]:
    from automated_security_helper.cli.mcp_tools import mcp_validate_config

    return mcp_validate_config(**kwargs)


@pytest.mark.parametrize("text", REFERENCES.values(), ids=REFERENCES)
def test_a_remote_callers_named_file_that_reads_the_environment_is_refused(
    _server, text
) -> None:
    named = _write(_server["repo"] / "ash.yaml", text)

    result = _validate(config_path=str(named), session_id=REMOTE)

    assert result["valid"] is False, result
    assert _types(result) == ["config_env_not_resolved"], result
    assert PROBE_VALUE not in json.dumps(result), result


@pytest.mark.parametrize("text", REFERENCES.values(), ids=REFERENCES)
def test_the_refusal_does_not_depend_on_the_variable_being_set(
    _server, monkeypatch, text
) -> None:
    """A variable the server has not set is no different from one it has, so the
    answer does not say which of the server's variables exist."""
    monkeypatch.delenv(PROBE_VAR)
    named = _write(_server["repo"] / "ash.yaml", text)

    result = _validate(config_path=str(named), session_id=REMOTE)

    assert _types(result) == ["config_env_not_resolved"], result


@pytest.mark.parametrize("text", REFERENCES.values(), ids=REFERENCES)
def test_control_the_local_caller_resolves_the_reference(_server, text) -> None:
    named = _write(_server["repo"] / "ash.yaml", text)

    result = _validate(config_path=str(named), session_id=DEFAULT_SESSION_ID)

    assert result["valid"] is True, result


@pytest.mark.parametrize("text", REFERENCES.values(), ids=REFERENCES)
def test_control_a_remote_callers_file_in_the_config_roots_resolves_it(
    _server, text
) -> None:
    named = _write(_server["operator"] / "ash.yaml", text)

    result = _validate(config_path=str(named), session_id=REMOTE)

    assert result["valid"] is True, result
