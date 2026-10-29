# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A delivered config's ``${VAR}`` reads nothing from the server's environment, in every form.

``test_delivered_config_env.py`` pins the refusal with ``${VAR:unset}`` only. Once
the bare form ``${VAR}`` resolves (it did not before), a delivered config that
writes it must be refused the same way, so each form is checked here: the bare
form, the colon forms, and the tagged bare form. ``ASH_ENVX_SERVER`` is set in the
server's environment, and its value must appear in no response. An operator
config under ``ASH_MCP_ALLOWED_CONFIG_ROOTS`` still resolves, as the control.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

VAR = "ASH_ENVX_SERVER"
VALUE = "server-side-value-envx"
SESSION = "envx-session"
ENV_REFUSED = "config_env_not_resolved"

DELIVERED_FORMS = [
    pytest.param("${%s}" % VAR, id="bare"),
    pytest.param("${%s:}" % VAR, id="colon-empty"),
    pytest.param("${%s:unset}" % VAR, id="colon-default"),
    pytest.param("!ENV ${%s}" % VAR, id="tagged-bare"),
]


@pytest.fixture
def server(tmp_path, monkeypatch):
    """A remote session's workspace, an operator config root, and VAR set."""
    from automated_security_helper.cli.mcp import profile_registry

    workspace = tmp_path / "mcp-workspaces"
    operator = tmp_path / "operator"
    operator.mkdir()
    monkeypatch.setenv(VAR, VALUE)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(operator))
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    profile_registry.clear_all_session_state()
    source = workspace / SESSION / "source"
    source.mkdir(parents=True)
    yield source, operator
    profile_registry.clear_all_session_state()


def _write(directory: Path, reference: str) -> Path:
    path = directory / ".ash.yaml"
    path.write_text(f"project_name: {reference}\n", encoding="utf-8")
    return path


@pytest.mark.parametrize("reference", DELIVERED_FORMS)
@pytest.mark.parametrize("raw", [False, True], ids=["resolved", "raw"])
def test_get_config_refuses_a_delivered_reference(server, reference, raw):
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    source, _ = server
    delivered = _write(source, reference)

    result = mcp_get_config(config_path=str(delivered), raw=raw, session_id=SESSION)

    if raw:
        # Raw mode asks for a document, not a run, so it judges nothing and
        # reads nothing from the environment: the reference comes back as the
        # file writes it, marked (mcp_tools.ENV_VALUE_PREFIX), in every form.
        marked = "!ENV " + reference.removeprefix("!ENV ")
        assert result == {"project_name": marked}, result
    else:
        assert result["success"] is False, result
        assert result["error_type"] == ENV_REFUSED, result
    assert VALUE not in repr(result)


@pytest.mark.parametrize("reference", DELIVERED_FORMS)
def test_validate_config_refuses_a_delivered_reference(server, reference):
    from automated_security_helper.cli.mcp_tools import mcp_validate_config

    source, _ = server
    delivered = _write(source, reference)

    result = mcp_validate_config(config_path=str(delivered), session_id=SESSION)

    assert result["valid"] is False, result
    assert ENV_REFUSED in repr(result)
    assert VALUE not in repr(result)


@pytest.mark.parametrize(
    "reference",
    [
        pytest.param("${%s:unset}" % VAR, id="colon-default"),
    ],
)
def test_control_an_operator_config_still_resolves(server, reference):
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    _, operator = server
    own = _write(operator, reference)

    result = mcp_get_config(config_path=str(own), session_id=SESSION)

    # The value read is shown as the reference, marked, never as the value.
    assert result.get("project_name") == f"<from {reference}>", result
    assert VALUE not in repr(result)
