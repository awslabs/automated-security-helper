# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A client's patched copy of a profile holds its references as text, and is
read against the operator's copy.

``select_profile`` with ``patch_ops`` writes the profile twice. The operator's
copy, in the session's ``config/`` directory, tags each value the profile read
from the environment ``!ENV``. The client's patched copy, in ``client-config/``,
holds the same reference as quoted text, because a config a client delivered
may not read the environment (an ``!ENV`` tag in it is refused). Both
``resolve_config`` and ``get_config`` fill the values back in from the
operator's copy, wherever a patch moved the entry.

A reader that opens the patched copy alone therefore sees the reference text,
never the value: that is the property of the design, and the one that keeps a
client from reading the operator's variables. These cases pin each half, so a
change that writes ``!ENV`` into the client's copy, or stops the fill, fails
here.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

CANARY = "ash-canary-3c9a-0123456789"
REFERENCE = "${ASH_PN}"
PROFILE = (
    "external_reports_to_include:\n"
    "  - ${ASH_PN}\n"
    "  - other.sarif\n"
    "global_settings:\n"
    "  mcp:\n"
    "    runtime_overrides:\n"
    "      enabled: true\n"
    "      allowed_paths:\n"
    "        - /external_reports_to_include\n"
    "        - /external_reports_to_include/**\n"
    "      denied_paths: []\n"
)
ADD_BEFORE = {
    "op": "add",
    "path": "/external_reports_to_include/0",
    "value": "c.sarif",
}


@pytest.fixture
def bound(tmp_path, monkeypatch):
    """The client's patched copy and the operator's copy of one bound session."""
    from automated_security_helper.cli.mcp import profile_registry
    from automated_security_helper.cli.mcp_tools import mcp_select_profile

    monkeypatch.setenv("ASH_PN", CANARY)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    profile = tmp_path / "operator.ash.yaml"
    profile.write_text(PROFILE, encoding="utf-8")
    profile_registry.clear_profile_registry()
    profile_registry.clear_all_session_state()
    profile_registry.set_profile_registry(
        profile_registry.register_profiles([f"op={profile}"])
    )
    result = mcp_select_profile("op", patch_ops=[ADD_BEFORE], session_id="session-a")
    assert result["success"] is True, result.get("error")
    client = Path(profile_registry.resolve_session_config_path("session-a") or "")
    operator = Path(
        profile_registry.resolve_session_trusted_config_path("session-a") or ""
    )
    # Controls: two files, in the two directories.
    assert client.parent.name == "client-config", client
    assert operator.parent.name == "config", operator
    yield client, operator
    profile_registry.clear_profile_registry()
    profile_registry.clear_all_session_state()


def test_the_operators_copy_tags_the_reference(bound):
    _, operator = bound
    text = operator.read_text(encoding="utf-8")
    # Booleans, so a failure does not print the value.
    tagged = "!ENV" in text and text.count(REFERENCE) == 1
    assert tagged, "the operator's copy does not hold the tagged reference once"
    assert CANARY not in text, "the operator's copy holds the value"


def test_the_patched_copy_holds_the_reference_as_quoted_text(bound):
    client, _ = bound
    text = client.read_text(encoding="utf-8")
    quoted = f"'{REFERENCE}'" in text and text.count(REFERENCE) == 1
    assert quoted, "the patched copy does not hold the reference once, quoted"
    assert "!ENV" not in text, "the patched copy is tagged"
    assert CANARY not in text, "the patched copy holds the value"


def test_the_patched_copy_alone_reads_the_reference_text(bound):
    from automated_security_helper.config.resolve_config import resolve_config

    client, _ = bound
    entries = resolve_config(client).external_reports_to_include
    text_only = entries == ["c.sarif", REFERENCE, "other.sarif"]
    assert text_only, "the patched copy alone reads something else"


def test_the_patched_copy_read_against_the_operators_gives_the_value_at_its_entry(
    bound,
):
    from automated_security_helper.config.resolve_config import resolve_config

    client, operator = bound
    entries = resolve_config(
        client, trusted_config_path=operator
    ).external_reports_to_include
    filled = entries == ["c.sarif", CANARY, "other.sarif"]
    assert filled, "the reference does not read the value at its moved entry"


def test_get_config_marks_the_reference_at_its_moved_entry(bound):
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    client, _ = bound
    shown = mcp_get_config(config_path=str(client), session_id="session-a")
    marked = shown["external_reports_to_include"] == [
        "c.sarif",
        f"<from {REFERENCE}>",
        "other.sarif",
    ]
    assert marked, "get_config does not mark the reference at its moved entry"
    shows_the_value = CANARY in json.dumps(shown)
    assert not shows_the_value, "get_config shows the value the reference reads"
