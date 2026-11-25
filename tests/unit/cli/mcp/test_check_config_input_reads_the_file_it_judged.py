# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``check_config_input`` reads the file its check approved, not the one the name leads to later.

The check judged the path by name, and the read then opened the name again with no
identity to hold it to (``resolve_config_document`` takes the identity of the root
when the read starts). A name that led to one file at the check and another by the
read, a link re-pointed by a concurrent re-delivery of the session's tree or by
anyone who can write a granted root, was therefore parsed and validated as a file
nothing had judged, and the answer (that it parses, which keys its errors name)
described the outside file. The read is now held to the identity the check
returned, as ``mcp_tools.validate_config`` holds its own
(``identity_to_hold`` and ``expect=``).
"""

from __future__ import annotations

import os

import pytest

from automated_security_helper.config import mcp_sandbox

pytestmark = pytest.mark.unit

pytest.importorskip("yaml")


@pytest.fixture(autouse=True)
def _local_transport(monkeypatch, tmp_path):
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)


@pytest.fixture
def two_files_and_a_link(tmp_path):
    judged = tmp_path / "judged.yaml"
    judged.write_text("project_name: judged\n", encoding="utf-8")
    unjudged = tmp_path / "unjudged.yaml"
    unjudged.write_text("project_name: unjudged\n", encoding="utf-8")
    link = tmp_path / "config.yaml"
    link.symlink_to(judged)
    return judged, unjudged, link


def _swap_the_link_after_the_check(monkeypatch, link, to):
    """The name leads to ``to`` from the moment the check has returned."""
    real = mcp_sandbox.validate_config_input

    def check_then_swap(*args, **kwargs):
        verdict = real(*args, **kwargs)
        link.unlink()
        link.symlink_to(to)
        return verdict

    monkeypatch.setattr(mcp_sandbox, "validate_config_input", check_then_swap)


def test_control_a_name_that_still_leads_to_the_judged_file_loads(
    two_files_and_a_link,
):
    judged, _, link = two_files_and_a_link

    checked = mcp_sandbox.check_config_input(link)

    assert checked.refusal is None and checked.load_error is None
    assert checked.document is not None
    assert checked.document.data["project_name"] == "judged"


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symbolic links")
def test_a_name_that_led_elsewhere_by_the_read_is_refused_not_parsed(
    two_files_and_a_link, monkeypatch
):
    """Red at the base: the file the link led to by the read was parsed, and the
    answer was a document of the unjudged file."""
    judged, unjudged, link = two_files_and_a_link
    _swap_the_link_after_the_check(monkeypatch, link, unjudged)

    checked = mcp_sandbox.check_config_input(link)

    assert checked.document is None, "the unjudged file was read and parsed"
    assert checked.load_error is not None
    assert "changed after it was checked" in str(checked.load_error)
    assert "unjudged" not in str(checked.load_error)


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symbolic links")
def test_a_name_that_led_nowhere_at_the_check_is_held_to_no_file(tmp_path, monkeypatch):
    """A path absent at the check is held to the identity no file has, so a file
    put at the name between the check and the read is refused."""
    outside = tmp_path / "outside.yaml"
    outside.write_text("project_name: outside\n", encoding="utf-8")
    link = tmp_path / "later.yaml"
    real = mcp_sandbox.validate_config_input

    def check_then_make_the_link(*args, **kwargs):
        verdict = real(*args, **kwargs)
        link.symlink_to(outside)
        return verdict

    monkeypatch.setattr(mcp_sandbox, "validate_config_input", check_then_make_the_link)

    checked = mcp_sandbox.check_config_input(link)

    assert checked.document is None
    assert checked.load_error is not None
