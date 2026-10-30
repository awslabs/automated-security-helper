# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A module location an MCP client delivered is refused as delivered, not as a tree.

``scanned_tree_judgment`` is True for a path in a tree the scanned repository
controls and, under the MCP server, for a file a client delivered. The second
arm found no tree, but the refusal worded both as "it resolves inside the scanned
tree", even for a load with no scanned tree. The judgment now says which arm it
is (``WalkJudgment.client_delivered``) and ``refusal_reason`` words that arm as
delivered.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config import plugin_module_trust
from automated_security_helper.config.path_trust import scanned_tree_judgment
from automated_security_helper.config.plugin_module_trust import refusal_reason

pytestmark = pytest.mark.unit

DELIVERED = "it is a file an MCP client delivered"


@pytest.fixture
def located(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A module whose one location is ``tmp_path/mods/mod.py``, found without imports."""
    location = tmp_path / "mods" / "mod.py"
    monkeypatch.setattr(
        plugin_module_trust, "_spec_without_importing", lambda _name, _parent: object()
    )
    monkeypatch.setattr(
        plugin_module_trust, "_spec_locations", lambda _spec: [location]
    )
    return location


def _client_supplies_everything(monkeypatch: pytest.MonkeyPatch) -> None:
    from automated_security_helper.cli.mcp import sandbox

    monkeypatch.setattr(sandbox, "config_is_client_supplied", lambda _path: True)


def test_the_judgment_says_it_is_the_client_delivered_arm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    _client_supplies_everything(monkeypatch)

    judgment = scanned_tree_judgment(tmp_path / "mods" / "mod.py", None)

    assert judgment.verdict is True
    assert judgment.decided is True
    assert judgment.client_delivered is True


def test_a_path_in_the_scanned_tree_is_not_the_client_delivered_arm(tmp_path: Path):
    scan = tmp_path / "scan"
    scan.mkdir()

    judgment = scanned_tree_judgment(scan / "mod.py", scan)

    assert judgment.verdict is True
    assert judgment.client_delivered is False


def test_a_delivered_location_is_refused_as_delivered_with_a_scanned_tree(
    tmp_path: Path, located: Path, monkeypatch: pytest.MonkeyPatch
):
    _client_supplies_everything(monkeypatch)

    assert refusal_reason("their_ash_plugins", tmp_path / "scan") == DELIVERED


def test_a_delivered_location_is_refused_as_delivered_with_no_scanned_tree(
    located: Path, monkeypatch: pytest.MonkeyPatch
):
    _client_supplies_everything(monkeypatch)

    assert refusal_reason("their_ash_plugins", None, any_checkout=True) == DELIVERED
    assert refusal_reason("their_ash_plugins", None, root_judged=True) == DELIVERED


def test_control_a_location_in_the_scanned_tree_still_names_the_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    scan = tmp_path / "scan"
    scan.mkdir()
    location = scan / "mod.py"
    monkeypatch.setattr(
        plugin_module_trust, "_spec_without_importing", lambda _name, _parent: object()
    )
    monkeypatch.setattr(
        plugin_module_trust, "_spec_locations", lambda _spec: [location]
    )

    assert refusal_reason("their_ash_plugins", scan) == (
        "it resolves inside the scanned tree"
    )
