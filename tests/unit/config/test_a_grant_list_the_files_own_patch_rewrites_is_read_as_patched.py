# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A grant list the config file's own patch rewrites is read as patched.

``_own_sandbox_settings`` gives the ``sandbox`` section an operator's root config
writes itself, and ``_with_own_sandbox`` merges it into the trusted base the scan's
sandbox grants are held to. The merge applies a file's ``patch`` after the file, so
a grant list the file writes and then removes or rewrites with its own patch is not
the list the operator ends with. The section has to agree:

- a grant list the patch rewrites (``add`` or ``replace`` at ``/sandbox/<list>``, a
  ``replace`` or ``remove`` at ``/sandbox/<list>/<index>``, or a rewrite of
  ``/sandbox`` or of the whole document that carries the list) is kept to the
  entries that both the list the file wrote and the list the patch leaves name. The
  result still replaces the trusted base's list, so the scan is granted nothing that
  either list does not name, even when the base grants a path of its own;
- a grant list the patch removes (``remove`` at ``/sandbox/<list>``, or a rewrite
  that carries no such list) is not what the file ends with, so the file writes
  nothing for it and the trusted base's list stands;
- an ``add`` at ``/sandbox/<list>/<index>`` only inserts an entry, so the written
  list stays (the scan is granted the entries the file wrote, never one a patch
  adds);
- a setting no class names is dropped when the patch touches it, whatever it is
  named;
- ``network_scanners`` is narrowed, not dropped: a list there restricts, and dropping
  it would leave the default, which allows each scanner its declared network. The
  file keeps the scanners that both the list it wrote and the list its patch leaves
  name, and an empty list when the patch removes it;
- a grant list or a network list the patch writes where the file wrote none (no key,
  or a null) is a limit on the trusted base's list: the scan keeps the entries of
  that list that the patched list names, and the patch can only narrow it;
- a grant list the patch touches where the file wrote none, and leaves with no list
  (it removes the list, rewrites the section or the document without it, removes or
  replaces an entry of it, or writes something that is no list), is limited to
  nothing. The operator's own config ends with the model's empty list there, which is
  the narrowest, so the scan gets no entry of the trusted base's list. (A missing
  ``network_scanners`` is the widest, which is why that list is not read this way.)
  A patch that only inserts an entry (``add`` at ``/-`` or at an index) is no limit:
  an entry a patch writes is never adopted, so the insert takes nothing from the
  trusted list and the scan keeps it in full.

The values a patch writes are never adopted.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml

from automated_security_helper.config import resolve_config as resolve_config_module
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.config_sources import _PATCH_OPS
from automated_security_helper.config.resolve_config import (
    _own_sandbox_settings,
    _warn_dropped_own_sandbox,
    _with_own_sandbox,
    reset_dropped_own_sandbox_warnings,
    resolve_config,
)
from automated_security_helper.config.sandbox_grants import scanned_trees
from automated_security_helper.utils.log import ASH_LOGGER
from tests.utils.helpers import mark_git_checkout

pytestmark = pytest.mark.unit

ADDITIVE_LISTS = ("extra_read_paths", "read_path_scanners", "env_scanners")
#: A setting no list in the code names: the section keeps nothing a patch touched
#: just because its name is on a list.
UNNAMED = "future_grant"


def _op(op: str, path: str, value: Any = None) -> Dict[str, Any]:
    operation: Dict[str, Any] = {"op": op, "path": path}
    if op != "remove":
        operation["value"] = value
    return operation


def _config_of(tmp_path: Path, document: Dict[str, Any]) -> Path:
    path = tmp_path / "cfg" / "root.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


def _written() -> Dict[str, Any]:
    """The grants a file writes directly, one entry in each list."""
    return {
        "extra_read_paths": ["/opt/a"],
        "read_path_scanners": ["semgrep"],
        "env_scanners": ["semgrep"],
    }


def _own(tmp_path: Path, written: Dict[str, Any], operations: List[Any]):
    document = {"sandbox": written, "patch": operations}
    return _own_sandbox_settings(_config_of(tmp_path, document))


# --- The lists a patch removes or rewrites -------------------------------------


@pytest.mark.parametrize("name", ADDITIVE_LISTS)
@pytest.mark.parametrize(
    "operation, kept",
    [
        pytest.param(_op("replace", "/sandbox/LIST", ["/opt/z"]), [], id="replace"),
        pytest.param(_op("remove", "/sandbox/LIST"), None, id="remove"),
        pytest.param(
            _op("add", "/sandbox/LIST", ["/opt/z"]), [], id="add-over-the-list"
        ),
        pytest.param(
            _op("replace", "/sandbox/LIST/0", "/opt/z"), [], id="replace-entry"
        ),
        pytest.param(_op("remove", "/sandbox/LIST/0"), [], id="remove-entry"),
    ],
)
def test_a_list_the_patch_rewrites_is_not_the_list_the_file_wrote(
    tmp_path, name, operation, kept
):
    operation = dict(operation, path=operation["path"].replace("LIST", name))

    own = _own(tmp_path, _written(), [operation])

    expected = _written()
    if kept is None:
        del expected[name]
    else:
        expected[name] = kept
    assert own == expected


TWO = ["/opt/a", "/opt/b"]


@pytest.mark.parametrize("name", ADDITIVE_LISTS)
@pytest.mark.parametrize(
    "operation, kept",
    [
        pytest.param(
            _op("replace", "/sandbox/LIST/0", "/opt/z"), ["/opt/b"], id="entry"
        ),
        pytest.param(_op("remove", "/sandbox/LIST/0"), ["/opt/b"], id="remove-entry"),
        pytest.param(
            _op("replace", "/sandbox/LIST", ["/opt/b", "/opt/z"]),
            ["/opt/b"],
            id="overlapping-list",
        ),
        pytest.param(
            _op("replace", "/sandbox/LIST", ["/opt/z"]), [], id="disjoint-list"
        ),
        pytest.param(
            _op("replace", "/sandbox/LIST", ["/opt/b", "/opt/a"]),
            TWO,
            id="the-same-entries-in-another-order",
        ),
        pytest.param(
            _op("add", "/sandbox/LIST/0", "/opt/z"), TWO, id="an-inserted-entry"
        ),
    ],
)
def test_a_rewritten_list_keeps_the_entries_both_lists_name(
    tmp_path, name, operation, kept
):
    operation = dict(operation, path=operation["path"].replace("LIST", name))

    own = _own(tmp_path, {name: list(TWO)}, [operation])

    assert own == {name: kept}


def test_a_list_spelled_with_hyphens_is_the_same_list(tmp_path):
    own = _own(
        tmp_path,
        {"extra-read-paths": ["/opt/a"], "env_scanners": ["semgrep"]},
        [_op("replace", "/sandbox/extra_read_paths", ["/opt/z"])],
    )

    assert own == {"extra-read-paths": [], "env_scanners": ["semgrep"]}


@pytest.mark.parametrize(
    "operation",
    [
        pytest.param(_op("remove", "/sandbox"), id="remove-the-section"),
        pytest.param(_op("add", "/sandbox", {}), id="rewrite-the-section"),
        pytest.param(
            _op("add", "", {"project_name": "rewritten"}), id="rewrite-the-document"
        ),
    ],
)
def test_a_patch_that_leaves_no_section_drops_every_list(tmp_path, operation):
    own = _own(tmp_path, dict(_written(), mode="bwrap"), [operation])

    assert own == {}


@pytest.mark.parametrize(
    "operation",
    [
        pytest.param(
            _op("replace", "/sandbox", {"extra_read_paths": ["/opt/a", "/opt/z"]}),
            id="replace-the-section",
        ),
        pytest.param(
            _op("replace", "", {"sandbox": {"extra_read_paths": ["/opt/a", "/opt/z"]}}),
            id="replace-the-document",
        ),
    ],
)
def test_a_rewritten_section_keeps_the_entries_the_file_and_the_rewrite_name(
    tmp_path, operation
):
    own = _own(tmp_path, dict(_written(), mode="bwrap"), [operation])

    assert own == {"extra_read_paths": ["/opt/a"]}


def test_a_rewritten_section_keeps_its_mode_and_the_lists_it_still_names(tmp_path):
    own = _own(
        tmp_path,
        dict(_written(), mode="bwrap"),
        [_op("add", "/sandbox", {"mode": "off", "extra_read_paths": ["/opt/z"]})],
    )

    assert own == {"mode": "off", "extra_read_paths": []}


def test_a_rewritten_document_keeps_its_mode_and_the_lists_it_still_names(tmp_path):
    own = _own(
        tmp_path,
        dict(_written(), mode="bwrap"),
        [_op("add", "", {"sandbox": {"mode": "auto", "env_scanners": ["x"]}})],
    )

    assert own == {"mode": "auto", "env_scanners": []}


def test_the_operations_apply_in_order_and_a_later_add_is_not_adopted(tmp_path):
    own = _own(
        tmp_path,
        _written(),
        [
            _op("remove", "/sandbox/extra_read_paths"),
            _op("add", "/sandbox/extra_read_paths", ["/opt/a", "/opt/z"]),
        ],
    )

    assert own["extra_read_paths"] == ["/opt/a"]
    assert own["env_scanners"] == ["semgrep"]


def test_a_list_removed_and_not_written_back_is_left_to_the_trusted_base(tmp_path):
    own = _own(
        tmp_path,
        _written(),
        [
            _op("add", "/sandbox/extra_read_paths", ["/opt/a"]),
            _op("remove", "/sandbox/extra_read_paths"),
        ],
    )

    assert "extra_read_paths" not in own
    assert own["env_scanners"] == ["semgrep"]


# --- A setting no list names ---------------------------------------------------


@pytest.mark.parametrize(
    "operation",
    [
        pytest.param(_op("remove", "/sandbox"), id="remove-the-section"),
        pytest.param(_op("add", "/sandbox", {}), id="rewrite-the-section"),
        pytest.param(
            _op("add", "", {"project_name": "rewritten"}), id="rewrite-the-document"
        ),
    ],
)
def test_a_rewrite_keeps_no_setting_whatever_it_is_named(tmp_path, operation):
    written = dict(_written(), mode="bwrap")
    written[UNNAMED] = ["/opt/q"]

    own = _own(tmp_path, written, [operation])

    assert own == {}


def test_a_rewrite_that_carries_a_mode_keeps_only_the_mode(tmp_path):
    own = _own(
        tmp_path,
        {"mode": "bwrap", UNNAMED: ["/opt/q"]},
        [_op("add", "/sandbox", {"mode": "off", UNNAMED: ["/opt/z"]})],
    )

    assert own == {"mode": "off"}


@pytest.mark.parametrize(
    "operation",
    [
        pytest.param(_op("replace", f"/sandbox/{UNNAMED}", ["/opt/z"]), id="replace"),
        pytest.param(_op("remove", f"/sandbox/{UNNAMED}"), id="remove"),
        pytest.param(_op("add", f"/sandbox/{UNNAMED}", ["/opt/z"]), id="add-over"),
        pytest.param(
            _op("replace", f"/sandbox/{UNNAMED}/0", "/opt/z"), id="replace-entry"
        ),
        pytest.param(_op("remove", f"/sandbox/{UNNAMED}/0"), id="remove-entry"),
        pytest.param(
            _op("replace", "/sandbox/future-grant", ["/opt/z"]), id="hyphen-pointer"
        ),
    ],
)
def test_a_setting_the_patch_touches_is_dropped_whatever_it_is_named(
    tmp_path, operation
):
    own = _own(tmp_path, dict(_written(), **{UNNAMED: ["/opt/q"]}), [operation])

    assert own == _written()


def test_an_insert_into_an_unnamed_written_list_keeps_the_list(tmp_path):
    written = dict(_written(), **{UNNAMED: ["/opt/q"]})

    own = _own(tmp_path, written, [_op("add", f"/sandbox/{UNNAMED}/-", "/opt/z")])

    assert own == written


def test_an_add_inside_an_unnamed_written_mapping_drops_it(tmp_path):
    written = dict(_written(), future_map={"a": 1})

    own = _own(tmp_path, written, [_op("add", "/sandbox/future_map/b", 2)])

    assert own == _written()


# --- The operations the loader admits -------------------------------------------
# ``_apply_patch`` refuses every operation outside ``_PATCH_OPS`` before the file is
# read here, so this walk reads the three that write (add, replace, remove) and
# ignores ``test``. A loader that admits another operation needs a branch in the walk.


def test_the_loader_admits_no_patch_operation_this_walk_does_not_read():
    assert _PATCH_OPS == {"add", "remove", "replace", "test"}


# --- network_scanners: what both lists name ------------------------------------

NETWORK = ["grype", "semgrep"]


@pytest.mark.parametrize(
    "operations, kept",
    [
        pytest.param([], NETWORK, id="control-no-patch"),
        pytest.param(
            [_op("replace", "/project_name", "other")],
            NETWORK,
            id="control-another-setting",
        ),
        pytest.param(
            [_op("test", "/sandbox/network_scanners", NETWORK)],
            NETWORK,
            id="control-a-test",
        ),
        pytest.param(
            [_op("remove", "/sandbox/network_scanners")], [], id="remove-the-list"
        ),
        pytest.param([_op("remove", "/sandbox")], [], id="remove-the-section"),
        pytest.param(
            [_op("add", "/sandbox", {})], [], id="rewrite-the-section-without-the-list"
        ),
        pytest.param(
            [_op("add", "", {"project_name": "rewritten"})],
            [],
            id="rewrite-the-document-without-the-section",
        ),
        pytest.param(
            [_op("replace", "/sandbox/network_scanners", ["trivy"])],
            [],
            id="replace-with-a-disjoint-list",
        ),
        pytest.param(
            [_op("replace", "/sandbox/network_scanners", ["semgrep", "trivy"])],
            ["semgrep"],
            id="replace-with-an-overlapping-list",
        ),
        pytest.param(
            [_op("add", "/sandbox", {"network_scanners": ["grype"]})],
            ["grype"],
            id="rewrite-the-section-with-a-narrower-list",
        ),
        pytest.param(
            [
                _op(
                    "replace",
                    "",
                    {"sandbox": {"network_scanners": ["semgrep", "trivy"]}},
                )
            ],
            ["semgrep"],
            id="replace-the-document-with-an-overlapping-list",
        ),
        pytest.param(
            [_op("remove", "/sandbox/network_scanners/0")],
            ["semgrep"],
            id="remove-the-first-entry",
        ),
        pytest.param(
            [_op("replace", "/sandbox/network_scanners/1", "trivy")],
            ["grype"],
            id="replace-the-second-entry",
        ),
        pytest.param(
            [_op("add", "/sandbox/network_scanners/-", "trivy")],
            NETWORK,
            id="an-appended-entry-is-not-adopted",
        ),
        pytest.param(
            [
                _op("add", "/sandbox/network_scanners/0", "trivy"),
                _op("remove", "/sandbox/network_scanners/0"),
            ],
            NETWORK,
            id="an-inserted-entry-moves-the-index",
        ),
        pytest.param(
            [
                _op("remove", "/sandbox/network_scanners"),
                _op("add", "/sandbox/network_scanners", ["grype"]),
            ],
            ["grype"],
            id="removed-then-added-back-narrower",
        ),
    ],
)
def test_a_network_list_the_patch_changes_keeps_what_both_lists_name(
    tmp_path, operations, kept
):
    written = dict(_written(), network_scanners=list(NETWORK))

    own = _own(tmp_path, written, operations)

    assert own["network_scanners"] == kept


def test_a_network_list_written_with_a_hyphen_is_narrowed_under_its_spelling(tmp_path):
    for pointer in ("/sandbox/network_scanners", "/sandbox/network-scanners"):
        own = _own(
            tmp_path,
            {"network-scanners": ["grype"], "env_scanners": ["semgrep"]},
            [_op("remove", pointer)],
        )

        assert own == {"network-scanners": [], "env_scanners": ["semgrep"]}, pointer


def test_a_null_network_list_the_patch_does_not_touch_stays_null(tmp_path):
    own = _own(
        tmp_path,
        {"network_scanners": None},
        [_op("replace", "/project_name", "other")],
    )

    assert own == {"network_scanners": None}


def test_a_null_network_list_the_patch_touches_is_not_written_by_the_file(tmp_path):
    own = _own(
        tmp_path,
        {"network_scanners": None},
        [_op("replace", "/sandbox/network_scanners", ["grype"])],
    )

    assert own == {}


# --- What stays ----------------------------------------------------------------


@pytest.mark.parametrize(
    "operation",
    [
        pytest.param(_op("add", "/sandbox/extra_read_paths/0", "/opt/b"), id="insert"),
        pytest.param(_op("add", "/sandbox/extra_read_paths/-", "/opt/b"), id="append"),
        pytest.param(_op("test", "/sandbox/extra_read_paths", ["/opt/a"]), id="test"),
        pytest.param(_op("replace", "/project_name", "other"), id="other-setting"),
        pytest.param(_op("replace", "/sandbox/mode", "off"), id="the-mode"),
        pytest.param(_op("replace", "/sandboxes/extra_read_paths", []), id="other-key"),
    ],
)
def test_an_operation_that_leaves_the_list_in_place_keeps_it(tmp_path, operation):
    own = _own(tmp_path, dict(_written(), mode="bwrap"), [operation])

    assert own["extra_read_paths"] == ["/opt/a"]
    assert own["read_path_scanners"] == ["semgrep"]
    assert own["env_scanners"] == ["semgrep"]


def test_a_file_without_a_patch_keeps_the_lists_it_wrote(tmp_path):
    root = _config_of(tmp_path, {"sandbox": _written()})

    assert _own_sandbox_settings(root) == _written()


def test_the_carried_document_is_not_changed(tmp_path):
    root = tmp_path / "cfg" / "carried.yaml"
    document = {
        "sandbox": _written(),
        "patch": [_op("remove", "/sandbox/extra_read_paths")],
    }
    before = yaml.safe_dump(document)

    own = _own_sandbox_settings(root, documents={root.resolve(): document})

    assert "extra_read_paths" not in own
    assert yaml.safe_dump(document) == before


# --- A carried mapping that lacks the file --------------------------------------


class _Collect(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.messages: List[str] = []
        self.records: List[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(" ".join(record.getMessage().split()))
        self.records.append(record)


@pytest.fixture
def _collected():
    """The handler that collects what ASH logs while a test runs."""
    handler = _Collect()
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(logging.DEBUG)
    ASH_LOGGER.addHandler(handler)
    reset_dropped_own_sandbox_warnings()
    try:
        yield handler
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)
        reset_dropped_own_sandbox_warnings()


@pytest.fixture
def logged(_collected):
    """What ASH logs while a test runs, as one line each; filled as it runs."""
    return _collected.messages


@pytest.fixture
def logged_records(_collected):
    """The records themselves, as logged; filled as the test runs."""
    return _collected.records


def test_a_carried_mapping_that_lacks_the_file_gives_nothing_and_names_the_file(
    tmp_path, logged
):
    root = _config_of(tmp_path, {"sandbox": _written()})

    own = _own_sandbox_settings(root, documents={})

    assert own == {}
    named = [message for message in logged if "root.yaml" in message]
    assert len(named) == 1, logged
    assert named[0].startswith("Could not read the sandbox settings")
    assert "grants no sandbox access" in named[0]
    # The values are not the warning's to show.
    assert "/opt/a" not in named[0]


def test_the_file_is_named_once_however_often_it_is_read(tmp_path, logged):
    root = _config_of(tmp_path, {"sandbox": _written()})

    for _ in range(3):
        _own_sandbox_settings(root, documents={})

    assert len([m for m in logged if "root.yaml" in m]) == 1, logged


def test_control_a_carried_mapping_that_holds_the_file_names_nothing(tmp_path, logged):
    root = _config_of(tmp_path, {"sandbox": _written()})
    document = {"sandbox": _written()}

    own = _own_sandbox_settings(root, documents={root.resolve(): document})

    assert own == _written()
    assert not [message for message in logged if "root.yaml" in message], logged


# --- The three call sites, through resolve_config ------------------------------

OWN_GRANT = "/opt/operator-own-grant"
REPOSITORY_GRANT = "/opt/repository-grant"
PATCH_SHAPES = {
    "replace-the-list": _op("replace", "/sandbox/extra_read_paths", ["/opt/patched"]),
    "remove-the-section": _op("remove", "/sandbox"),
    "rewrite-the-document": _op("add", "", {"project_name": "rewritten"}),
}
SITES = ["the-selected-config", "the-file-ASH_CONFIG-names", "the-trusted-config"]


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    # ASH_CONFIG would add a file of its own to the resolution, and a basetemp
    # inside a checkout would put every layout inside that checkout too. A
    # workspace root of the MCP server that holds the basetemp would make every
    # file here a client's, so it is pointed at a directory nothing is in.
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    for directory in (tmp_path, *tmp_path.parents):
        assert not os.path.lexists(directory / ".git"), (
            f"{tmp_path} is inside a git checkout; run with --basetemp outside one"
        )


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _layout(
    w: Path, patch: List[Any], written: Dict[str, Any] | None = None
) -> tuple[Path, Path]:
    """(W/operator.yaml, W/repo): the operator's file outside every checkout,
    extending a base inside the scanned checkout W/repo, which also holds a config
    of its own that grants a path. The operator's file writes *written* (one path
    grant by default) and then applies *patch*."""
    repo = w / "repo"
    mark_git_checkout(repo)
    _write(repo / "a.py", "x = 1\n")
    _write(
        repo / ".ash" / ".ash.yaml",
        yaml.safe_dump({"sandbox": {"extra_read_paths": [REPOSITORY_GRANT]}}),
    )
    _write(repo / ".ash" / "base.yaml", "project_name: base\n")
    section = {"extra_read_paths": [OWN_GRANT]} if written is None else written
    document: Dict[str, Any] = {"extends": "repo/.ash/base.yaml", "sandbox": section}
    if patch:
        document["patch"] = patch
    operator = _write(w / "operator.yaml", yaml.safe_dump(document, sort_keys=False))
    return operator, repo


def _resolved_sandbox(site: str, operator: Path, repo: Path, monkeypatch):
    if site == "the-selected-config":
        return resolve_config(config_path=operator, source_dir=repo).sandbox
    if site == "the-file-ASH_CONFIG-names":
        monkeypatch.setenv("ASH_CONFIG", str(operator))
        return resolve_config(source_dir=repo).sandbox
    return resolve_config(source_dir=repo, trusted_config_path=operator).sandbox


@pytest.mark.parametrize("site", SITES)
def test_control_a_root_without_a_patch_keeps_the_list_it_wrote(
    site, tmp_path, monkeypatch
):
    operator, repo = _layout(tmp_path / "W", [])

    sandbox = _resolved_sandbox(site, operator, repo, monkeypatch)

    assert list(sandbox.extra_read_paths) == [OWN_GRANT]


@pytest.mark.parametrize("shape", sorted(PATCH_SHAPES))
@pytest.mark.parametrize("site", SITES)
def test_the_scan_is_not_granted_a_list_the_roots_own_patch_rewrote(
    site, shape, tmp_path, monkeypatch
):
    operator, repo = _layout(tmp_path / "W", [PATCH_SHAPES[shape]])

    sandbox = _resolved_sandbox(site, operator, repo, monkeypatch)

    assert list(sandbox.extra_read_paths) == []


NETWORK_WRITTEN = {"network_scanners": ["detect-secrets"]}
NETWORK_PATCH_SHAPES = {
    "remove-the-list": _op("remove", "/sandbox/network_scanners"),
    "remove-the-section": _op("remove", "/sandbox"),
    "replace-the-list-with-another": _op(
        "replace", "/sandbox/network_scanners", ["semgrep"]
    ),
    "rewrite-the-document": _op("add", "", {"project_name": "rewritten"}),
}


@pytest.mark.parametrize("site", SITES)
def test_control_a_root_without_a_patch_keeps_the_network_list_it_wrote(
    site, tmp_path, monkeypatch
):
    operator, repo = _layout(tmp_path / "W", [], NETWORK_WRITTEN)

    sandbox = _resolved_sandbox(site, operator, repo, monkeypatch)

    assert sandbox.network_scanners == ["detect-secrets"]


@pytest.mark.parametrize("shape", sorted(NETWORK_PATCH_SHAPES))
@pytest.mark.parametrize("site", SITES)
def test_the_scan_is_given_no_network_the_roots_own_patch_took_away(
    site, shape, tmp_path, monkeypatch
):
    operator, repo = _layout(
        tmp_path / "W", [NETWORK_PATCH_SHAPES[shape]], NETWORK_WRITTEN
    )

    sandbox = _resolved_sandbox(site, operator, repo, monkeypatch)

    assert sandbox.network_scanners == []


# --- A trusted base that grants a list of its own --------------------------------
# The list a file's patch rewrites replaces the trusted base's list, as the list the
# file wrote did. Left out of the file's section instead, it would give the scan the
# base's list: a path that neither the list the file wrote nor the list the patch
# leaves names.

CACHE = "/home/op/cache"
TOOL = "/opt/tool"


def _named(operation: Dict[str, Any], name: str) -> Dict[str, Any]:
    """*operation* with the placeholder LIST taken as the setting *name*, in its path
    and in the keys of its value."""
    return json.loads(json.dumps(operation).replace("LIST", name))


def _trusted(**lists: List[str]) -> AshConfig:
    trusted = AshConfig()
    for name, entries in lists.items():
        setattr(trusted.sandbox, name, list(entries))
    return trusted


def _merged_sandbox(tmp_path: Path, trusted: AshConfig, written, operations):
    """The sandbox section ``_with_own_sandbox`` gives, for an operator's file outside
    every checkout that writes *written* and then applies *operations*."""
    repo = tmp_path / "repo"
    mark_git_checkout(repo)
    root = _config_of(tmp_path, {"sandbox": written, "patch": operations})
    merged, _wrote_mode = _with_own_sandbox(
        trusted, root, repo, [], scanned_trees(repo), None
    )
    return merged.sandbox


def test_the_additive_lists_the_walk_classes_are_the_ones_these_tests_cover():
    """The three lists of paths and scanner names, which these tests build with path
    entries, and the environment list, whose entries are variables and whose cases
    are in ``test_sandbox_environment_setting``."""
    assert resolve_config_module._ADDITIVE_SANDBOX_SETTINGS == frozenset(
        ADDITIVE_LISTS
    ) | {"environment"}


@pytest.mark.parametrize("name", ADDITIVE_LISTS)
def test_control_a_file_without_a_patch_replaces_the_trusted_bases_list(tmp_path, name):
    sandbox = _merged_sandbox(tmp_path, _trusted(**{name: [CACHE]}), {name: [TOOL]}, [])

    assert getattr(sandbox, name) == [TOOL]


@pytest.mark.parametrize("name", ADDITIVE_LISTS)
@pytest.mark.parametrize(
    "operation, kept",
    [
        pytest.param(_op("replace", "/sandbox/LIST/0", "/opt/tool2"), [], id="entry"),
        pytest.param(_op("remove", "/sandbox/LIST/0"), [], id="remove-entry"),
        pytest.param(
            _op("replace", "/sandbox/LIST", ["/opt/tool2"]), [], id="disjoint-list"
        ),
        pytest.param(
            _op("replace", "/sandbox/LIST", [TOOL, "/opt/tool2"]),
            [TOOL],
            id="overlapping-list",
        ),
        pytest.param(
            _op("replace", "/sandbox", {"LIST": ["/opt/tool2"]}),
            [],
            id="replace-the-section",
        ),
        pytest.param(
            _op("replace", "", {"sandbox": {"LIST": [TOOL, "/opt/tool2"]}}),
            [TOOL],
            id="replace-the-document",
        ),
    ],
)
def test_a_list_the_patch_rewrites_is_not_replaced_by_the_trusted_bases_list(
    tmp_path, name, operation, kept
):
    operation = _named(operation, name)

    sandbox = _merged_sandbox(
        tmp_path, _trusted(**{name: [CACHE]}), {name: [TOOL]}, [operation]
    )

    assert getattr(sandbox, name) == kept
    assert CACHE not in getattr(sandbox, name)


@pytest.mark.parametrize("name", ADDITIVE_LISTS)
@pytest.mark.parametrize(
    "operation",
    [
        pytest.param(_op("remove", "/sandbox/LIST"), id="remove-the-list"),
        pytest.param(_op("remove", "/sandbox"), id="remove-the-section"),
        pytest.param(_op("replace", "/sandbox", {}), id="rewrite-the-section"),
    ],
)
def test_a_list_the_patch_removes_is_left_to_the_trusted_bases_list(
    tmp_path, name, operation
):
    operation = _named(operation, name)

    sandbox = _merged_sandbox(
        tmp_path, _trusted(**{name: [CACHE]}), {name: [TOOL]}, [operation]
    )

    assert getattr(sandbox, name) == [CACHE]


@pytest.mark.parametrize("name", ADDITIVE_LISTS)
def test_an_insert_into_the_list_keeps_the_list_the_file_wrote(tmp_path, name):
    sandbox = _merged_sandbox(
        tmp_path,
        _trusted(**{name: [CACHE]}),
        {name: [TOOL]},
        [_op("add", f"/sandbox/{name}/-", "/opt/tool2")],
    )

    assert getattr(sandbox, name) == [TOOL]


def test_the_scan_is_not_given_the_list_a_trusted_config_grants_over_a_patched_one(
    tmp_path, monkeypatch
):
    ops = _write(
        tmp_path / "ops" / "ash.yaml",
        yaml.safe_dump({"sandbox": {"extra_read_paths": [CACHE]}}),
    )
    operator, repo = _layout(
        tmp_path / "W",
        [_op("replace", "/sandbox/extra_read_paths/0", "/opt/tool2")],
        {"extra_read_paths": [TOOL]},
    )
    monkeypatch.setenv("ASH_CONFIG", str(ops))

    sandbox = resolve_config(config_path=operator, source_dir=repo).sandbox

    assert list(sandbox.extra_read_paths) == []


def test_control_the_scan_is_given_the_list_the_root_wrote_over_a_trusted_configs(
    tmp_path, monkeypatch
):
    ops = _write(
        tmp_path / "ops" / "ash.yaml",
        yaml.safe_dump({"sandbox": {"extra_read_paths": [CACHE]}}),
    )
    operator, repo = _layout(tmp_path / "W", [], {"extra_read_paths": [TOOL]})
    monkeypatch.setenv("ASH_CONFIG", str(ops))

    sandbox = resolve_config(config_path=operator, source_dir=repo).sandbox

    assert list(sandbox.extra_read_paths) == [TOOL]


# --- A list the file wrote as a null, which its patch then writes over -----------
# The loader checks a file's document once the patch has applied, so a null that the
# patch replaces is a list by then. The file wrote no list, so none of it is the
# file's. Left in the section as a null it would fail the section's validation, and
# the file would lose its mode and its network list along with it.


@pytest.mark.parametrize("name", ADDITIVE_LISTS)
@pytest.mark.parametrize(
    "operation",
    [
        pytest.param(_op("replace", "/sandbox/LIST", ["/opt/z"]), id="replace"),
        pytest.param(_op("add", "/sandbox/LIST", ["/opt/z"]), id="add-over-the-null"),
    ],
)
def test_a_null_list_the_patch_writes_over_is_not_a_setting_of_the_file(
    tmp_path, name, operation
):
    own = _own(tmp_path, {"mode": "bwrap", name: None}, [_named(operation, name)])

    assert own == {"mode": "bwrap"}


@pytest.mark.parametrize("name", ADDITIVE_LISTS)
def test_a_null_list_the_patch_writes_over_does_not_cost_the_file_its_other_settings(
    tmp_path, name
):
    sandbox = _merged_sandbox(
        tmp_path,
        _trusted(**{name: [CACHE]}),
        {"mode": "bwrap", "network_scanners": [], name: None},
        [_op("replace", f"/sandbox/{name}", [TOOL])],
    )

    assert sandbox.mode == "bwrap"
    assert sandbox.network_scanners == []
    assert TOOL not in getattr(sandbox, name)


@pytest.mark.parametrize("name", ADDITIVE_LISTS)
def test_control_a_null_list_the_patch_does_not_touch_is_left_as_written(
    tmp_path, name
):
    own = _own(
        tmp_path,
        {"mode": "bwrap", name: None},
        [_op("replace", "/project_name", "other")],
    )

    assert own == {"mode": "bwrap", name: None}


# --- A grant list the file's patch writes where the file wrote none ----------------
# The merge applies the patch to the operator's resolved config, so a list it writes
# replaces the list in force there, and the trusted base's list is not the one the
# operator ends with. Like a network list below, it is a limit and never an addition:
# the scan keeps the entries of the trusted base's list that the patched list names,
# so a patch can only narrow what the base grants, and an entry it names that the
# base lacks adds nothing.

TRUSTED_TWO = [CACHE, TOOL]


def _wrote_no_list(name: str, null: bool) -> Dict[str, Any]:
    return {name: None} if null else {}


@pytest.mark.parametrize("null", [False, True], ids=["no-key", "a-null"])
@pytest.mark.parametrize("name", ADDITIVE_LISTS)
@pytest.mark.parametrize(
    "operation, kept",
    [
        pytest.param(
            _op("replace", "/sandbox/LIST", [TOOL, "/opt/z"]),
            [TOOL],
            id="an-overlapping-list",
        ),
        pytest.param(
            _op("replace", "/sandbox/LIST", ["/opt/z"]), [], id="a-disjoint-list"
        ),
        pytest.param(_op("replace", "/sandbox/LIST", []), [], id="an-empty-list"),
        pytest.param(
            _op("add", "/sandbox", {"LIST": [TOOL]}),
            [TOOL],
            id="a-section-that-carries-a-list",
        ),
        pytest.param(
            _op("add", "", {"sandbox": {"LIST": [CACHE]}}),
            [CACHE],
            id="a-document-that-carries-a-list",
        ),
        pytest.param(
            _op("replace", "/sandbox/LIST", [CACHE, TOOL]),
            TRUSTED_TWO,
            id="the-same-entries",
        ),
    ],
)
def test_a_grant_list_the_patch_writes_limits_a_file_that_wrote_none(
    tmp_path, null, name, operation, kept
):
    sandbox = _merged_sandbox(
        tmp_path,
        _trusted(**{name: TRUSTED_TWO}),
        _wrote_no_list(name, null),
        [_named(operation, name)],
    )

    assert getattr(sandbox, name) == kept


@pytest.mark.parametrize("null", [False, True], ids=["no-key", "a-null"])
@pytest.mark.parametrize("name", ADDITIVE_LISTS)
@pytest.mark.parametrize(
    "operation",
    [
        pytest.param(_op("remove", "/sandbox/LIST"), id="remove-the-list"),
        pytest.param(_op("remove", "/sandbox"), id="remove-the-section"),
        pytest.param(_op("replace", "/sandbox", {}), id="rewrite-the-section"),
    ],
)
def test_a_patch_that_leaves_no_grant_list_limits_the_scan_to_no_entries(
    tmp_path, null, name, operation
):
    """The operator's own config ends with the model's empty list there, so the
    scan gets none of the trusted base's entries."""
    sandbox = _merged_sandbox(
        tmp_path,
        _trusted(**{name: TRUSTED_TWO}),
        _wrote_no_list(name, null),
        [_named(operation, name)],
    )

    assert getattr(sandbox, name) == []


@pytest.mark.parametrize("null", [False, True], ids=["no-key", "a-null"])
@pytest.mark.parametrize("name", ADDITIVE_LISTS)
@pytest.mark.parametrize(
    "operation",
    [
        pytest.param(_op("remove", "/sandbox/LIST/0"), id="remove-an-entry"),
        pytest.param(_op("replace", "/sandbox/LIST/0", TOOL), id="replace-an-entry"),
        pytest.param(
            _op("replace", "/sandbox/LIST", "not-a-list"), id="a-value-no-list"
        ),
    ],
)
def test_a_patch_that_edits_an_entry_of_a_list_the_file_did_not_write_limits_it_to_nothing(
    tmp_path, null, name, operation
):
    """Which entry of the list in force an index names is not known here, so the
    edit fails closed: the list the file did not write is not widened to the trusted
    base's."""
    sandbox = _merged_sandbox(
        tmp_path,
        _trusted(**{name: TRUSTED_TWO}),
        _wrote_no_list(name, null),
        [_named(operation, name)],
    )

    assert getattr(sandbox, name) == []


@pytest.mark.parametrize("null", [False, True], ids=["no-key", "a-null"])
@pytest.mark.parametrize("name", ADDITIVE_LISTS)
@pytest.mark.parametrize(
    "operation",
    [
        pytest.param(_op("add", "/sandbox/LIST/-", TOOL), id="append-an-entry"),
        pytest.param(_op("add", "/sandbox/LIST/0", TOOL), id="insert-an-entry"),
    ],
)
def test_a_patch_that_only_inserts_an_entry_into_a_list_the_file_did_not_write_keeps_the_trusted_list(
    tmp_path, logged, null, name, operation
):
    """An entry a patch writes is never adopted, so an insert can only add to the
    list in force and takes nothing from the trusted list. Emptying the list for it
    would give the scan less than the same file with no patch at all."""
    sandbox = _merged_sandbox(
        tmp_path,
        _trusted(**{name: TRUSTED_TWO}),
        _wrote_no_list(name, null),
        [_named(operation, name)],
    )

    assert getattr(sandbox, name) == TRUSTED_TWO
    assert [m for m in logged if "root.yaml" in m and name in m] == [], logged


def test_an_insert_beside_an_edit_of_a_list_the_file_did_not_write_still_limits_it(
    tmp_path,
):
    sandbox = _merged_sandbox(
        tmp_path,
        _trusted(extra_read_paths=TRUSTED_TWO),
        {},
        [
            _op("add", "/sandbox/extra_read_paths/-", TOOL),
            _op("remove", "/sandbox/extra_read_paths/0"),
        ],
    )

    assert sandbox.extra_read_paths == []


def test_a_patch_that_edits_entries_of_a_list_the_file_did_not_write_says_so(
    tmp_path, logged
):
    """The list is limited to nothing, and the warning says what happened: the edit
    of entries of a list the file does not write, not a limit by a list the patch
    names, which is what the other sentence describes."""
    sandbox = _merged_sandbox(
        tmp_path,
        _trusted(extra_read_paths=TRUSTED_TWO),
        {},
        [_op("remove", "/sandbox/extra_read_paths/0")],
    )

    assert sandbox.extra_read_paths == []
    [warning] = [m for m in logged if "root.yaml" in m and "extra_read_paths" in m]
    assert "edits entries of extra_read_paths" in warning, warning
    assert "a list the file does not write" in warning, warning
    assert "none of the trusted list's 2 entries is kept" in warning, warning
    assert "left out" not in warning, warning


def test_control_a_patch_that_leaves_a_list_the_file_did_not_write_alone_keeps_the_trusted_list(
    tmp_path,
):
    sandbox = _merged_sandbox(
        tmp_path,
        _trusted(extra_read_paths=TRUSTED_TWO),
        {},
        [_op("replace", "/project_name", "other")],
    )

    assert sandbox.extra_read_paths == TRUSTED_TWO


def test_control_a_patch_that_removes_the_network_list_keeps_the_trusted_one(tmp_path):
    """A missing ``network_scanners`` is the widest, so removing it never widens."""
    trusted = _trusted()
    trusted.sandbox.network_scanners = ["grype", "semgrep"]

    sandbox = _merged_sandbox(
        tmp_path, trusted, {}, [_op("remove", "/sandbox/network_scanners")]
    )

    assert sandbox.network_scanners == ["grype", "semgrep"]


@pytest.mark.parametrize("name", ADDITIVE_LISTS)
def test_control_a_list_the_patch_writes_adds_nothing_to_a_base_without_one(
    tmp_path, name
):
    sandbox = _merged_sandbox(
        tmp_path,
        AshConfig(),
        {},
        [_named(_op("replace", "/sandbox/LIST", [TOOL]), name)],
    )

    assert getattr(sandbox, name) == []


# --- The operator's own file is told when its patch's limit leaves entries out -------
# The limit keeps the trusted entries that the patched list names, compared as spelled.
# The trusted list's relative entries are already absolute, so a patch that spells the
# same path relatively names an entry the list lacks and keeps nothing, which would
# otherwise leave a scanner without its files and the log silent.


def _limit_warnings(logged: List[str], name: str) -> List[str]:
    return [
        message
        for message in logged
        if "root.yaml" in message and "limits" in message and name in message
    ]


def test_a_patch_that_spells_a_trusted_path_differently_is_named_in_one_warning(
    tmp_path, logged
):
    sandbox = _merged_sandbox(
        tmp_path,
        _trusted(extra_read_paths=["/ops/certs/ca.pem"]),
        {},
        [_op("replace", "/sandbox/extra_read_paths", ["certs/ca.pem"])],
    )

    assert sandbox.extra_read_paths == []
    [warning] = _limit_warnings(logged, "extra_read_paths")
    assert "not in the trusted list as spelled" in warning, warning
    assert "leaving out 1 of the trusted list's 1 entry" in warning, warning
    assert "1 entries" not in warning, warning


def test_a_patch_that_leaves_trusted_entries_out_is_named_in_one_warning(
    tmp_path, logged
):
    sandbox = _merged_sandbox(
        tmp_path,
        _trusted(extra_read_paths=TRUSTED_TWO),
        {},
        [_op("replace", "/sandbox/extra_read_paths", [TOOL])],
    )

    assert sandbox.extra_read_paths == [TOOL]
    [warning] = _limit_warnings(logged, "extra_read_paths")
    assert "leaving out 1 of the trusted list's 2 entries" in warning, warning
    assert "not in the trusted list as spelled" not in warning, warning


def test_a_patch_that_removes_the_list_is_named_in_one_warning(tmp_path, logged):
    sandbox = _merged_sandbox(
        tmp_path,
        _trusted(extra_read_paths=TRUSTED_TWO),
        {},
        [_op("remove", "/sandbox/extra_read_paths")],
    )

    assert sandbox.extra_read_paths == []
    [warning] = _limit_warnings(logged, "extra_read_paths")
    assert "leaving out 2 of the trusted list's 2 entries" in warning, warning


@pytest.mark.parametrize("name", ["read_path_scanners", "env_scanners"])
def test_the_warning_for_a_list_of_scanner_names_speaks_of_scanners_not_paths(
    tmp_path, logged, name
):
    sandbox = _merged_sandbox(
        tmp_path,
        _trusted(**{name: ["semgrep", "grype"]}),
        {},
        [_op("replace", f"/sandbox/{name}", ["zzz"])],
    )

    assert getattr(sandbox, name) == []
    [warning] = _limit_warnings(logged, name)
    assert "name it exactly as the trusted list does" in warning, warning
    assert "relative path" not in warning, warning
    assert "spell it" not in warning, warning


def test_the_warning_for_a_list_of_paths_says_how_to_spell_a_path(tmp_path, logged):
    _merged_sandbox(
        tmp_path,
        _trusted(extra_read_paths=["/ops/certs/ca.pem"]),
        {},
        [_op("replace", "/sandbox/extra_read_paths", ["certs/ca.pem"])],
    )

    [warning] = _limit_warnings(logged, "extra_read_paths")
    assert "spell it exactly as the trusted list does" in warning, warning
    assert "a relative path there is already absolute" in warning, warning


def test_the_warning_does_not_send_an_entry_the_patch_adds_the_wrong_way(
    tmp_path, logged
):
    """An entry a patch writes is never adopted. A warning that only says to spell
    entries as the trusted list does points an operator who meant to add one at a
    spelling that is not the cause."""
    _merged_sandbox(
        tmp_path,
        _trusted(extra_read_paths=TRUSTED_TWO),
        {},
        [_op("replace", "/sandbox/extra_read_paths", [TOOL, "/opt/new"])],
    )

    [warning] = _limit_warnings(logged, "extra_read_paths")
    assert "1 entry it names is not in the trusted list as spelled" in warning, warning
    assert "an entry a patch writes is never adopted" in warning, warning
    assert "so it adds nothing" in warning, warning


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="NTFS refuses a control character in a file name, so the directory "
    "this test names with a newline cannot be made",
)
def test_the_warnings_are_logged_as_data_on_one_line(tmp_path, logged_records):
    """The file's path is data: it is not read as markup, and a control character in
    its name does not start a line of its own."""
    sandbox = _merged_sandbox(
        tmp_path / "work\ndir",
        _trusted(extra_read_paths=TRUSTED_TWO, env_scanners=["semgrep"]),
        {},
        [
            _op("replace", "/sandbox/extra_read_paths", [TOOL]),
            _op("remove", "/sandbox/env_scanners/0"),
        ],
    )

    assert sandbox.extra_read_paths == [TOOL]
    named = [r for r in logged_records if "root.yaml" in r.getMessage()]
    assert len(named) == 2, [r.getMessage() for r in logged_records]
    for record in named:
        assert getattr(record, "markup", True) is False, record.getMessage()
        assert "\n" not in record.getMessage(), record.getMessage()


def test_a_limit_that_a_failed_section_validation_throws_away_is_not_announced(
    tmp_path, logged
):
    """A section that does not validate adds nothing, so the trusted list stays in
    full. A warning that says entries are left out would be false, and the once-per-
    process set would keep it from ever being corrected."""
    sandbox = _merged_sandbox(
        tmp_path,
        _trusted(extra_read_paths=TRUSTED_TWO),
        {"mode": "not-a-mode"},
        [_op("replace", "/sandbox/extra_read_paths", [TOOL])],
    )

    assert sandbox.extra_read_paths == TRUSTED_TWO
    assert _limit_warnings(logged, "extra_read_paths") == [], logged


def test_the_limit_is_announced_when_the_section_validates(tmp_path, logged):
    """The control for the test above: the same patch, with a section that
    validates, is applied and announced once."""
    sandbox = _merged_sandbox(
        tmp_path,
        _trusted(extra_read_paths=TRUSTED_TWO),
        {"mode": "bwrap"},
        [_op("replace", "/sandbox/extra_read_paths", [TOOL])],
    )

    assert sandbox.extra_read_paths == [TOOL]
    assert len(_limit_warnings(logged, "extra_read_paths")) == 1, logged


def test_the_file_is_named_once_however_often_the_limit_is_applied(tmp_path, logged):
    for _ in range(2):
        _merged_sandbox(
            tmp_path,
            _trusted(extra_read_paths=TRUSTED_TWO),
            {},
            [_op("replace", "/sandbox/extra_read_paths", [TOOL])],
        )

    assert len(_limit_warnings(logged, "extra_read_paths")) == 1, logged


def test_control_a_limit_that_keeps_every_trusted_entry_says_nothing(tmp_path, logged):
    sandbox = _merged_sandbox(
        tmp_path,
        _trusted(extra_read_paths=TRUSTED_TWO),
        {},
        [_op("replace", "/sandbox/extra_read_paths", [CACHE, TOOL])],
    )

    assert sandbox.extra_read_paths == TRUSTED_TWO
    assert _limit_warnings(logged, "extra_read_paths") == []


def test_control_a_patch_that_does_not_touch_a_grant_list_says_nothing(
    tmp_path, logged
):
    _merged_sandbox(
        tmp_path,
        _trusted(extra_read_paths=TRUSTED_TWO),
        {},
        [_op("replace", "/project_name", "other")],
    )

    assert _limit_warnings(logged, "extra_read_paths") == []


def test_a_list_spelled_with_hyphens_in_the_pointer_is_the_same_list(tmp_path):
    sandbox = _merged_sandbox(
        tmp_path,
        _trusted(extra_read_paths=TRUSTED_TWO),
        {},
        [_op("replace", "/sandbox/extra-read-paths", [TOOL])],
    )

    assert sandbox.extra_read_paths == [TOOL]


def test_each_list_is_limited_by_the_patch_that_writes_it(tmp_path):
    sandbox = _merged_sandbox(
        tmp_path,
        _trusted(extra_read_paths=TRUSTED_TWO, read_path_scanners=["semgrep", "grype"]),
        {"extra_read_paths": [TOOL]},
        [_op("replace", "/sandbox/read_path_scanners", ["grype"])],
    )

    assert sandbox.extra_read_paths == [TOOL]
    assert sandbox.read_path_scanners == ["grype"]


def test_a_path_limit_and_a_network_limit_apply_together(tmp_path):
    trusted = _trusted(extra_read_paths=TRUSTED_TWO)
    trusted.sandbox.network_scanners = ["grype", "semgrep"]

    sandbox = _merged_sandbox(
        tmp_path,
        trusted,
        {},
        [
            _op("replace", "/sandbox/extra_read_paths", [TOOL]),
            _op("replace", "/sandbox/network_scanners", ["semgrep", "trivy"]),
        ],
    )

    assert sandbox.extra_read_paths == [TOOL]
    assert sandbox.network_scanners == ["semgrep"]


def test_the_scan_is_not_given_the_list_a_trusted_config_grants_when_the_patch_writes_one(
    tmp_path, monkeypatch
):
    ops = _write(
        tmp_path / "ops" / "ash.yaml",
        yaml.safe_dump({"sandbox": {"extra_read_paths": [CACHE]}}),
    )
    operator, repo = _layout(
        tmp_path / "W", [_op("add", "/sandbox/extra_read_paths", ["/opt/x"])], {}
    )
    monkeypatch.setenv("ASH_CONFIG", str(ops))

    sandbox = resolve_config(config_path=operator, source_dir=repo).sandbox

    assert list(sandbox.extra_read_paths) == []


def test_the_scan_keeps_only_the_entries_a_trusted_config_grants_and_the_patch_names(
    tmp_path, monkeypatch
):
    ops = _write(
        tmp_path / "ops" / "ash.yaml",
        yaml.safe_dump({"sandbox": {"extra_read_paths": [CACHE, TOOL]}}),
    )
    operator, repo = _layout(
        tmp_path / "W", [_op("add", "/sandbox/extra_read_paths", [TOOL])], {}
    )
    monkeypatch.setenv("ASH_CONFIG", str(ops))

    sandbox = resolve_config(config_path=operator, source_dir=repo).sandbox

    assert list(sandbox.extra_read_paths) == [TOOL]


# --- A network list the file's patch writes where the file wrote none --------------
# A patch is a limit the operator wrote: a file that wrote no list (a null, or no
# key) and then patches one in is read the same way either time. The scan gets the
# scanners that the patched list and the trusted base's list both name (a base list
# of null names every scanner), so the patch can only narrow what the base allows.

BASE_NETWORK = ["grype", "semgrep"]
WRITES_NONE = [
    pytest.param({"network_scanners": None}, id="a-null"),
    pytest.param({}, id="no-key"),
]


@pytest.mark.parametrize("written", WRITES_NONE)
@pytest.mark.parametrize(
    "base, operation, kept",
    [
        pytest.param(
            None,
            _op("replace", "/sandbox/network_scanners", ["grype"]),
            ["grype"],
            id="a-list-over-a-base-without-one",
        ),
        pytest.param(
            BASE_NETWORK,
            _op("replace", "/sandbox/network_scanners", ["grype", "trivy"]),
            ["grype"],
            id="an-overlapping-list",
        ),
        pytest.param(
            BASE_NETWORK,
            _op("replace", "/sandbox/network_scanners", ["trivy"]),
            [],
            id="a-disjoint-list",
        ),
        pytest.param(
            BASE_NETWORK,
            _op("replace", "/sandbox/network_scanners", []),
            [],
            id="an-empty-list",
        ),
        pytest.param(
            BASE_NETWORK,
            _op("add", "/sandbox", {"network_scanners": ["semgrep"]}),
            ["semgrep"],
            id="a-section-that-carries-a-list",
        ),
        pytest.param(
            None,
            _op("add", "", {"sandbox": {"network_scanners": ["semgrep"]}}),
            ["semgrep"],
            id="a-document-that-carries-a-list",
        ),
    ],
)
def test_a_network_list_the_patch_writes_limits_a_file_that_wrote_none(
    tmp_path, written, base, operation, kept
):
    trusted = AshConfig()
    trusted.sandbox.network_scanners = base

    sandbox = _merged_sandbox(tmp_path, trusted, written, [operation])

    assert sandbox.network_scanners == kept


@pytest.mark.parametrize("written", WRITES_NONE)
@pytest.mark.parametrize("base", [None, BASE_NETWORK], ids=["no-base-list", "a-base"])
@pytest.mark.parametrize(
    "operation",
    [
        pytest.param(_op("remove", "/sandbox/network_scanners"), id="remove-the-list"),
        pytest.param(_op("remove", "/sandbox"), id="remove-the-section"),
        pytest.param(_op("replace", "/sandbox", {}), id="rewrite-the-section"),
    ],
)
def test_a_patch_that_leaves_no_network_list_leaves_the_trusted_base_in_place(
    tmp_path, written, base, operation
):
    trusted = AshConfig()
    trusted.sandbox.network_scanners = base

    sandbox = _merged_sandbox(tmp_path, trusted, written, [operation])

    assert sandbox.network_scanners == base


# --- A file that is left out is named for a list only its patch writes -------------
# ``_with_own_sandbox`` applies a list that a file's patch writes where the file wrote
# none, as a limit on the trusted base's list. A file left out because it is not the
# operator's (or because its name walk stopped) has that limit left out with the rest
# of it, so it is named for it, as for a section it wrote itself.


@pytest.mark.parametrize("undecided", [False, True], ids=["decided", "undecided"])
@pytest.mark.parametrize(
    "written, operations",
    [
        pytest.param(
            {"network_scanners": None},
            [_op("replace", "/sandbox/network_scanners", ["grype"])],
            id="a-null-network-list-that-is-replaced",
        ),
        pytest.param(
            {},
            [_op("add", "/sandbox/network_scanners", ["grype"])],
            id="a-network-list-that-is-added",
        ),
        pytest.param(
            {"extra_read_paths": None},
            [_op("replace", "/sandbox/extra_read_paths", ["/opt/z"])],
            id="a-null-grant-list-that-is-replaced",
        ),
        pytest.param(
            {},
            [_op("add", "/sandbox", {"env_scanners": ["semgrep"]})],
            id="a-section-that-carries-a-grant-list",
        ),
        pytest.param(
            {"extra_read_paths": ["/opt/a"]}, [], id="a-section-the-file-wrote"
        ),
    ],
)
def test_a_file_left_out_is_named_for_the_lists_it_writes_or_its_patch_writes(
    tmp_path, logged, undecided, written, operations
):
    root = _config_of(tmp_path, {"sandbox": written, "patch": operations})

    _warn_dropped_own_sandbox(root, [], None, undecided=undecided)

    named = [message for message in logged if "root.yaml" in message]
    assert len(named) == 1, logged
    assert named[0].startswith("Ignoring the sandbox settings"), named
    # The values are not the warning's to show.
    for value in ("grype", "semgrep", "/opt/z", "/opt/a"):
        assert value not in named[0], named


@pytest.mark.parametrize("undecided", [False, True], ids=["decided", "undecided"])
@pytest.mark.parametrize(
    "written, operations",
    [
        pytest.param({}, [], id="nothing-written"),
        pytest.param(
            {"network_scanners": None},
            [_op("remove", "/sandbox/network_scanners")],
            id="a-null-list-that-is-removed",
        ),
        pytest.param(
            {}, [_op("replace", "/project_name", "other")], id="another-setting"
        ),
    ],
)
def test_control_a_file_that_writes_nothing_for_the_scan_is_not_named(
    tmp_path, logged, undecided, written, operations
):
    root = _config_of(tmp_path, {"sandbox": written, "patch": operations})

    _warn_dropped_own_sandbox(root, [], None, undecided=undecided)

    assert not [message for message in logged if "root.yaml" in message], logged
