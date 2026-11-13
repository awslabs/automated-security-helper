# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A session id never has the shape of a hidden delete name, and the sweep checks.

What the code does, by path
---------------------------
An ended session's workspace is renamed to ``.<session id>.deleting-<uuid4>`` and
deleted under that name; what the delete cannot finish stays there, and the TTL
sweep removes such a leftover once it is older than the TTL.

* ``session_paths.validated_path_component`` is the one rule for an id that
  becomes a path component. It admits a leading ``.``, so before this change an id
  with the shape of a hidden delete name named a live session whose workspace the
  sweep then took for a leftover. The rule now refuses an id of that exact shape,
  for the transport, the registry and source delivery alike. An id with a leading
  dot, or with ``.deleting-`` in it, that is not the whole shape is still admitted.
* The sweep removes an entry of that shape only when nothing owns the name: no
  registry entry, and no scan-presence directory. An entry something owns is left
  alone, whatever its age.

Every cell is DISARMED: the workspace root is the cell's own tmp_path, and nothing
runs git, a scanner or the network.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.session_paths import (
    SESSION_MARKER,
    hidden_deleting_name,
    is_a_deleting_name,
    validated_path_component,
)
from automated_security_helper.cli.mcp.sessions import (
    SCAN_PRESENCE_DIR,
    MCPSession,
    get_default_registry,
    reset_default_registry_for_tests,
    sweep_stale_workspaces,
)

pytestmark = pytest.mark.unit

LONG_AGO_SECONDS = 10_000.0
TTL_SECONDS = 600.0


def _a_hidden_delete_name() -> str:
    return hidden_deleting_name("some-session")


@pytest.fixture(autouse=True)
def workspace_root(tmp_path, monkeypatch) -> Path:
    root = tmp_path / "ws"
    root.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    monkeypatch.setattr(sd, "_SESSION_SOURCE_DIRS", {})
    reset_default_registry_for_tests()
    yield root
    reset_default_registry_for_tests()


def _an_old_directory_with_a_file(root: Path, name: str, *, marker: bool) -> Path:
    directory = root / name
    directory.mkdir()
    if marker:
        (directory / SESSION_MARKER).touch()
    (directory / "tree.txt").write_text("a scan's tree\n", encoding="utf-8")
    then = time.time() - LONG_AGO_SECONDS
    os.utime(directory / "tree.txt", (then, then))
    os.utime(directory, (then, then))
    return directory


def test_an_id_with_the_shape_of_a_hidden_delete_name_is_refused() -> None:
    name = _a_hidden_delete_name()

    with pytest.raises(ValueError):
        validated_path_component(name)
    with pytest.raises(ValueError):
        get_default_registry().get_or_create(name)


@pytest.mark.parametrize(
    "name",
    [
        pytest.param(
            ".some-session.deleting-0f8fad5b-d9cb-469f-a165-70867728950e",
            id="lowercase-uuid",
        ),
        pytest.param(
            ".some-session.deleting-0F8FAD5B-D9CB-469F-A165-70867728950E",
            id="uppercase-uuid",
        ),
        pytest.param(
            ".some-session.deleting-0f8fad5bd9cb469fa16570867728950e", id="uuid-hex"
        ),
        pytest.param(
            f".{'a' * 100}.deleting-0f8fad5b-d9cb-469f-a165-70867728950e",
            id="longer-than-an-id-may-be",
        ),
        pytest.param(".some-session.deleting-0f8fad5b-d9cb-469f-a165", id="short-uuid"),
    ],
)
def test_the_id_rule_and_the_sweep_read_a_hidden_delete_name_alike(name: str) -> None:
    """An id is refused exactly when the sweep would take its name for a leftover.
    The sweep deletes whatever ``is_a_deleting_name`` matches, so an id that rule
    admits and the id rule refuses, or the other way round, would name a live tree
    the sweep deletes, or refuse an id for nothing."""
    try:
        validated_path_component(name)
        refused = False
    except ValueError:
        refused = True

    assert refused == is_a_deleting_name(name), (name, refused)


@pytest.mark.parametrize("step", ["chunk", "finalize", "git"])
def test_a_delivery_with_such_an_id_is_refused_before_it_makes_anything(
    workspace_root, step
) -> None:
    """The refusal holds for source delivery too, not only for the registry: no
    delivery step creates a workspace under an id of the shape."""
    name = _a_hidden_delete_name()

    with pytest.raises(ValueError):
        if step == "chunk":
            sd.set_source_zip_chunk(
                upload_id="u1", sequence=0, data_b64="", last=False, session_id=name
            )
        elif step == "finalize":
            sd.set_source_zip_finalize(
                upload_id="u1", expected_sha256="0" * 64, session_id=name
            )
        else:
            sd.set_source_git("https://example.com/org/repo.git", session_id=name)

    assert [p.name for p in workspace_root.iterdir() if name in p.name] == []


def test_the_git_tool_answers_such_an_id_as_invalid(
    workspace_root, monkeypatch
) -> None:
    from automated_security_helper.cli.mcp_tools import mcp_set_source_git

    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", "example.com")

    result = mcp_set_source_git(
        url="https://example.com/org/repo.git", session_id=_a_hidden_delete_name()
    )

    assert result["success"] is False, result
    assert result["error_type"] == "invalid_session_id", result


@pytest.mark.parametrize(
    "name",
    [
        ".dotfile",
        ".some-session.deleting-not-a-uuid",
        ".some-session.deleting-00000000-0000-0000",
        "some-session.deleting-0f8fad5b-d9cb-469f-a165-70867728950e",
        ".some-session.deleting-0f8fad5b-d9cb-469f-a165-70867728950e-more",
    ],
)
def test_an_id_that_is_not_the_whole_shape_is_still_admitted(name: str) -> None:
    """Controls for the cell above, each a must-admit input: a leading dot alone,
    the infix with something other than a uuid after it, a partial uuid, no
    leading dot, and a suffix after the uuid."""
    assert validated_path_component(name) == name


def test_the_sweep_leaves_an_old_entry_of_that_shape_a_session_owns(
    workspace_root,
) -> None:
    """A registry entry owns the name (an id admitted by an older server, or set
    some other way): its tree is a live session's, however old and with or
    without the marker."""
    name = _a_hidden_delete_name()
    tree = _an_old_directory_with_a_file(workspace_root, name, marker=False)
    registry = get_default_registry()
    registry._sessions[name] = MCPSession(id=name, workspace_root=tree)

    sweep_stale_workspaces(ttl_seconds=TTL_SECONDS)

    assert (tree / "tree.txt").is_file(), "a live session's tree was deleted"


def test_the_sweep_leaves_an_old_entry_of_that_shape_a_scan_presence_names(
    workspace_root,
) -> None:
    """A scan of another server registered a presence directory for the name: the
    tree is under a scan, so it stays."""
    name = _a_hidden_delete_name()
    tree = _an_old_directory_with_a_file(workspace_root, name, marker=True)
    (workspace_root / SCAN_PRESENCE_DIR / name).mkdir(parents=True)

    sweep_stale_workspaces(ttl_seconds=TTL_SECONDS)

    assert (tree / "tree.txt").is_file(), "a scanned tree was deleted"


def test_the_sweep_still_removes_an_unowned_old_leftover(workspace_root) -> None:
    """Control: the same old entry with no registry entry and no presence
    directory is a leftover and is removed."""
    name = _a_hidden_delete_name()
    tree = _an_old_directory_with_a_file(workspace_root, name, marker=False)

    sweep_stale_workspaces(ttl_seconds=TTL_SECONDS)

    assert not tree.exists()
