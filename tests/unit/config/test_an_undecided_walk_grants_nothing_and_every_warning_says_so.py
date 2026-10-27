# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config file whose directory walk did not finish grants nothing, and says so.

``confined_files`` judges a name whose walk stopped before the end (an
unsearchable parent, a link that cannot be read) to be the repository's, because
the alternative hands out grants on a walk that never finished. Two places read
that same walk differently, and this file pins both to the rule, with the wording
that follows from it:

- The operator's own ``sandbox`` section (``_with_own_sandbox``). A root whose own
  walk stopped found no link in a tree, but it found nothing either way, so its
  settings are not the operator's and join no grant. The load tells
  ``_with_own_sandbox`` whether the walk stopped, for each of the three roots (the
  selected config, the file ASH_CONFIG names and the operator's trusted config), and
  a warning names the file.
- The warnings the other confinement steps give (the reporters' destinations, the
  scanners' own configuration, ``tool_version``, the content database staleness
  policy, detect-secrets' scan settings, ``honor_ignore_files``, the archive
  extraction limits and the destinations a plugin module's reporter declares).
  They state where the file sits ("inside a git checkout or the scanned tree"),
  which a walk that never finished did not establish, so they carry the same
  sentence the sandbox and settle warnings carry (``confinement_membership``).
  They also end with the remedy for a file nobody could place, which is to let the
  walk finish; moving a file out of every checkout changes nothing for a file that
  is not known to be in one. A value an MCP client's overrides set is attributed to
  the client, not to the walk.

Where the walk decided, nothing changes: the grants and the text of every
warning are what they were, and the controls below pin that.

The walk is cut short with an ``os.lstat`` wrapper that refuses one directory
component, for the walk's own read only, so the file itself still loads.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Literal, Tuple

import pytest

from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.config import resolve_config as resolve_config_module
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.confinement_remedy import KEEP_A_SETTING
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.config.sandbox_grants import (
    REPOSITORY_WRITTEN,
    confinement_membership,
)
from automated_security_helper.config.untrusted_source import IN_TREE_OR_DELIVERED
from tests.utils.helpers import mark_git_checkout

_WALK_STOPPED = "resolving its name stopped before the walk finished"
_OWN_GRANT = "/opt/operator-own-grant"
#: Fragments of the sentences that claim a location, one for each way
#: ``membership_clause`` places a file. A warning for a file whose walk stopped
#: carries none of them.
_LOCATION_CLAIMS = (
    "inside a git checkout or the scanned",
    "delivered by an MCP client",
    "the file is inside the scanned tree",
    "the file is inside the given root's trees",
    "the file is in a checkout, which",
    "by where it sits",
)
#: The head every warning for a file whose walk stopped carries. A literal, not
#: the output of ``membership_clause``: a test that builds its expectation with the
#: code under test cannot see that code's wording change.
_UNDECIDED_HEAD = (
    "whether the file is the repository's could not be decided (resolving its "
    "name stopped before the walk finished), which is read as the repository's"
)

_SECURITY_HUB = {"enabled": True, "options": {"aws_region": "repo-region"}}
_VERIFICATION_FILTER = (
    "detect_secrets.filters.common.is_ignored_due_to_verification_policies"
)
_DETECT_SECRETS = {
    "enabled": True,
    "options": {
        "scan_settings": {
            "version": "1.5.0",
            "plugins_used": [{"name": "AWSKeyDetector"}],
            "filters_used": [{"path": _VERIFICATION_FILTER, "min_level": 2}],
        }
    },
}
_LET_IT_FINISH = "make each directory on the file's path searchable"
_MOVE_IT_OUT = "move the file outside every git checkout"
_FROM_A_CLIENT = "came from an MCP client"
#: What the archive extraction limits' warning says of a file whose walk finished.
_ARCHIVE_WROTE_IT = "the scanned repository or an MCP client wrote that file"
#: The text each voice gives for a file whose walk finished, where it is not
#: ``IN_TREE_OR_DELIVERED``'s reason: the plain string ``REPOSITORY_WRITTEN``, or the
#: archive limits' own sentence.
_DECIDED_TEXT = {
    "detect-secrets": REPOSITORY_WRITTEN,
    "honor-ignore-files": REPOSITORY_WRITTEN,
    "archive-limits": _ARCHIVE_WROTE_IT,
}

#: One document and one marker fragment per confinement voice. Each document
#: sets a value the operator alone chooses, and each marker is a fragment that
#: only that voice's warning holds.
_VOICES: Dict[str, Tuple[Dict[str, Any], str]] = {
    "reporter-destinations": (
        {"reporters": {"aws-security-hub": _SECURITY_HUB}},
        "options choose whether findings are sent",
    ),
    "scanner-config-file": (
        {"scanners": {"bandit": {"options": {"config_file": ".ash/tool.yaml"}}}},
        "a scanner's own configuration",
    ),
    "detect-secrets": (
        {"scanners": {"detect-secrets": _DETECT_SECRETS}},
        "scanners.detect-secrets.options.scan_settings",
    ),
    "tool-version": (
        {"scanners": {"bandit": {"options": {"tool_version": "==1.7.9"}}}},
        "chooses which release of a tool",
    ),
    "content-db-staleness": (
        {"content_db_staleness": "warn"},
        "relaxing the stale content database check",
    ),
    "honor-ignore-files": (
        {"honor_ignore_files": False},
        "Ignoring honor_ignore_files",
    ),
    "archive-limits": (
        {"converters": {"archive": {"options": {"max_members": 500_000}}}},
        "converters.archive.options.max_members",
    ),
}


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    # ASH_CONFIG would add a file of its own to the resolution, and a basetemp
    # inside a checkout would put every layout inside that checkout too.
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)
    for directory in (tmp_path, *tmp_path.parents):
        assert not os.path.lexists(directory / ".git"), (
            f"{tmp_path} is inside a git checkout; run with --basetemp outside one"
        )


def _ignoring(records: List[logging.LogRecord], marker: str) -> List[str]:
    """The "Ignoring ..." warnings that hold ``marker``."""
    return [
        message
        for message in (record.getMessage() for record in records)
        if message.startswith("Ignoring") and marker in message
    ]


def _undecided_shape(w: Path, unjudgeable, document: Dict[str, Any]):
    """A scanned checkout and a config outside every checkout, whose name walk
    stops. Returns the config and the source directory."""
    mark_git_checkout(w / "repo")
    source = w / "repo" / "app"
    source.mkdir(parents=True)
    config = w / "ops" / "gate" / "cfg.yaml"
    config.parent.mkdir(parents=True)
    config.write_text(json.dumps(document), encoding="utf-8")
    unjudgeable(w / "ops" / "gate")
    return config, source


def _in_tree_shape(w: Path, document: Dict[str, Any]):
    """A scanned checkout holding its own config, whose walk is decided. Returns
    the config and the source directory."""
    repo = w / "repo"
    mark_git_checkout(repo)
    config = repo / ".ash" / "ash-config.yaml"
    config.parent.mkdir(parents=True)
    config.write_text(json.dumps(document), encoding="utf-8")
    return config, repo


class TestTheOwnSandboxSectionOfAFileWhoseWalkStopped:
    def test_a_root_whose_walk_stopped_keeps_no_grant_it_writes(
        self, tmp_path, unjudgeable, ash_log
    ):
        config, source = _undecided_shape(
            tmp_path,
            unjudgeable,
            {"project_name": "x", "sandbox": {"extra_read_paths": [_OWN_GRANT]}},
        )

        resolved = resolve_config(config_path=config, source_dir=source)

        assert list(resolved.sandbox.extra_read_paths) == []
        lines = _ignoring(ash_log, "sandbox.extra_read_paths")
        assert lines, [record.getMessage() for record in ash_log]
        assert all(_WALK_STOPPED in line for line in lines), lines
        assert all(_UNDECIDED_HEAD in line for line in lines), lines

    def test_a_root_whose_walk_stopped_beside_a_base_in_the_tree_keeps_no_grant(
        self, tmp_path, unjudgeable, ash_log
    ):
        mark_git_checkout(tmp_path / "repo")
        source = tmp_path / "repo" / "app"
        source.mkdir(parents=True)
        base = source / "base.yaml"
        base.write_text("project_name: x\n", encoding="utf-8")
        config = tmp_path / "ash.yaml"
        config.write_text(
            f"extends: {base.as_posix()}\n"
            f"sandbox:\n  extra_read_paths:\n    - {_OWN_GRANT}\n",
            encoding="utf-8",
        )
        unjudgeable(tmp_path)

        resolved = resolve_config(config_path=config, source_dir=source)

        assert list(resolved.sandbox.extra_read_paths) == []
        lines = _ignoring(ash_log, "sandbox.extra_read_paths")
        assert lines, [record.getMessage() for record in ash_log]
        assert all(_WALK_STOPPED in line for line in lines), lines

    def test_control_a_root_outside_the_tree_with_a_decided_walk_keeps_its_grant(
        self, tmp_path
    ):
        """Control: the operator's file extends a base in the tree. The base's
        grant is dropped, the file's own is kept, as before."""
        repo = tmp_path / "repo"
        mark_git_checkout(repo)
        (repo / ".ash").mkdir()
        (repo / ".ash" / "base.yaml").write_text(
            "project_name: base\nsandbox:\n  network_scanners:\n    - grype\n",
            encoding="utf-8",
        )
        config = tmp_path / "ash-config.yaml"
        config.write_text(
            "extends: repo/.ash/base.yaml\n"
            f"sandbox:\n  extra_read_paths:\n    - {_OWN_GRANT}\n",
            encoding="utf-8",
        )

        sandbox = resolve_config(config_path=config, source_dir=repo).sandbox

        assert list(sandbox.extra_read_paths) == [_OWN_GRANT]
        assert "grype" not in (sandbox.network_scanners or [])

    def test_control_a_root_inside_the_tree_keeps_no_grant(self, tmp_path):
        """Control: a file the repository holds grants nothing, decided walk."""
        config, repo = _in_tree_shape(
            tmp_path,
            {"project_name": "x", "sandbox": {"extra_read_paths": [_OWN_GRANT]}},
        )

        sandbox = resolve_config(config_path=config, source_dir=repo).sandbox

        assert list(sandbox.extra_read_paths) == []


#: The warning for a root whose own sandbox section is left out
#: (``_warn_dropped_own_sandbox``), which names the file itself.
_OWN_SANDBOX_DROPPED = "Ignoring the sandbox settings"
_GRANT_DOCUMENT: Dict[str, Any] = {
    "project_name": "x",
    "sandbox": {"extra_read_paths": [_OWN_GRANT]},
}
#: The three places ``resolve_config`` merges a root's own sandbox section: the
#: selected config, the file ASH_CONFIG names, and the operator's trusted config.
_ROOTS = ("selected", "ash-config", "operator")


def _a_root_at(
    site: str, w: Path, unjudgeable, monkeypatch, document: Dict[str, Any]
) -> Tuple[Path, Dict[str, Any]]:
    """A config outside every checkout whose name walk stops, reached by the call
    site *site* of ``_with_own_sandbox``. Returns the file and the arguments for
    ``resolve_config``. The selected config is the file itself; for the other two
    the selected config is a plain file in the scanned checkout."""
    repo = w / "repo"
    mark_git_checkout(repo)
    source = repo / "app"
    source.mkdir(parents=True)
    undecided = w / "ops" / "gate" / "cfg.yaml"
    undecided.parent.mkdir(parents=True)
    undecided.write_text(json.dumps(document), encoding="utf-8")
    unjudgeable(w / "ops" / "gate")
    if site == "selected":
        return undecided, {"config_path": undecided, "source_dir": source}
    in_tree = repo / ".ash" / "ash-config.yaml"
    in_tree.parent.mkdir()
    in_tree.write_text("project_name: in-tree\n", encoding="utf-8")
    arguments: Dict[str, Any] = {"config_path": in_tree, "source_dir": source}
    if site == "ash-config":
        monkeypatch.setenv("ASH_CONFIG", str(undecided))
    else:
        arguments["trusted_config_path"] = undecided
    return undecided, arguments


def _a_decided_root_beside_a_base_in_the_tree(w: Path) -> Tuple[Path, Path]:
    """An operator's file outside every checkout, whose walk finishes, extending
    a base in the scanned checkout (which puts the chain under the confinement).
    Returns the file and the checkout."""
    repo = w / "repo"
    mark_git_checkout(repo)
    (repo / ".ash").mkdir()
    (repo / ".ash" / "base.yaml").write_text("project_name: base\n", encoding="utf-8")
    config = w / "ash-config.yaml"
    config.write_text(
        "extends: repo/.ash/base.yaml\n"
        f"sandbox:\n  extra_read_paths:\n    - {_OWN_GRANT}\n",
        encoding="utf-8",
    )
    return config, repo


def _dropped_own_sandbox(records: List[logging.LogRecord], file: Path) -> List[str]:
    """The warnings that name *file* as a root whose own sandbox section is left out."""
    return [
        message
        for message in (record.getMessage() for record in records)
        if message.startswith(_OWN_SANDBOX_DROPPED) and file.name in message
    ]


def _announcing_the_loss(
    records: List[logging.LogRecord], file: Path, site: str
) -> List[str]:
    """The warnings that announce the sandbox settings *file* lost. The selected
    config's files are named by ``confine_sandbox_grants``, which says which
    settings were lost and why; the file ASH_CONFIG names beside a selected config,
    and the operator's trusted config, are named by the own-sandbox rule."""
    if site == "selected":
        return [
            message
            for message in (record.getMessage() for record in records)
            if message.startswith("Ignoring sandbox.")
        ]
    return _dropped_own_sandbox(records, file)


class TestEveryRootThatIsLeftOutIsNamedWithTheWalk:
    """The warning for the sandbox settings a root writes itself was
    ``confine_sandbox_grants``'s alone, which speaks for the selected config's
    files. The file ASH_CONFIG names and the operator's trusted config are other
    roots: their grants were left out with nothing to say so, or with a warning
    that named the selected config's files instead."""

    @pytest.mark.parametrize("site", _ROOTS)
    def test_a_root_left_out_for_an_unfinished_walk_is_named_with_the_walk(
        self, tmp_path, unjudgeable, monkeypatch, ash_log, site
    ):
        undecided, arguments = _a_root_at(
            site, tmp_path, unjudgeable, monkeypatch, _GRANT_DOCUMENT
        )

        resolved = resolve_config(**arguments)

        assert _OWN_GRANT not in list(resolved.sandbox.extra_read_paths)
        lines = _announcing_the_loss(ash_log, undecided, site)
        assert lines, [record.getMessage() for record in ash_log]
        assert all(_WALK_STOPPED in line for line in lines), lines
        for claim in _LOCATION_CLAIMS:
            assert not any(claim in line for line in lines), (claim, lines)
        if site == "selected":
            # The confinement warning builds its sentence from the head; the
            # own-sandbox warning for the other two roots has its own wording.
            assert len(lines) == 1, lines
            assert _UNDECIDED_HEAD in lines[0], lines

    @pytest.mark.parametrize("site", ["ash-config", "operator"])
    def test_the_file_is_named_once_however_many_times_it_is_resolved(
        self, tmp_path, unjudgeable, monkeypatch, ash_log, _warned_window, site
    ):
        # The warned-once store is shared by the process, and a full store clears
        # itself: the fixture starts this test from an empty one, so the second
        # resolve cannot warn again, and puts back what the store held.
        undecided, arguments = _a_root_at(
            site, tmp_path, unjudgeable, monkeypatch, _GRANT_DOCUMENT
        )
        resolve_config(**arguments)
        resolve_config(**arguments)

        lines = _dropped_own_sandbox(ash_log, undecided)
        assert len(lines) == 1, lines

    def test_control_a_root_with_a_decided_walk_is_not_named(self, tmp_path, ash_log):
        """Control: an operator's file outside every checkout whose walk finished
        keeps its grant and is not named as one that was left out."""
        config, repo = _a_decided_root_beside_a_base_in_the_tree(tmp_path)

        resolved = resolve_config(config_path=config, source_dir=repo)

        assert list(resolved.sandbox.extra_read_paths) == [_OWN_GRANT]
        assert _dropped_own_sandbox(ash_log, config) == []

    def test_a_root_in_a_scanned_tree_is_named_by_where_it_sits_when_its_walk_also_stopped(
        self, tmp_path, ash_log
    ):
        """The walk wording is for a root nothing located. A root inside a scanned
        tree is named by that tree, whatever else is true of the walk of one of its
        names: the warning says the true place, and the remedy that goes with it."""
        tree = tmp_path / "repo"
        mark_git_checkout(tree)
        root = tree / "ash.yaml"
        root.write_text(json.dumps(_GRANT_DOCUMENT), encoding="utf-8")

        resolve_config_module._warn_dropped_own_sandbox(
            path=root, trees=[tree], names=None, undecided=True
        )

        lines = _dropped_own_sandbox(ash_log, root)
        assert len(lines) == 1, lines
        assert "it is inside the checkout" in lines[0], lines
        assert _WALK_STOPPED not in lines[0], lines

    def test_a_root_no_scanned_tree_holds_is_named_for_its_unfinished_walk(
        self, tmp_path, ash_log
    ):
        root = tmp_path / "ops" / "gate" / "operator-base.yaml"
        root.parent.mkdir(parents=True)
        root.write_text(json.dumps(_GRANT_DOCUMENT), encoding="utf-8")

        resolve_config_module._warn_dropped_own_sandbox(
            path=root, trees=[tmp_path / "repo"], names=None, undecided=True
        )

        lines = _dropped_own_sandbox(ash_log, root)
        assert len(lines) == 1, lines
        assert _WALK_STOPPED in lines[0], lines

    def test_the_warning_for_an_unfinished_walk_is_logged_as_data(
        self, tmp_path, ash_log
    ):
        """It names the file by its path, which is data: the sibling warnings that
        name config paths are logged without markup, and this one is too."""
        root = tmp_path / "ops" / "gate" / "operator-base.yaml"
        root.parent.mkdir(parents=True)
        root.write_text(json.dumps(_GRANT_DOCUMENT), encoding="utf-8")

        resolve_config_module._warn_dropped_own_sandbox(
            path=root, trees=[tmp_path / "repo"], names=None, undecided=True
        )

        [record] = [
            record
            for record in ash_log
            if record.getMessage().startswith(_OWN_SANDBOX_DROPPED)
        ]
        assert getattr(record, "markup", True) is False, record.getMessage()

    def test_the_warning_for_a_file_a_tree_holds_names_its_path_as_data_too(
        self, tmp_path, ash_log
    ):
        """The other branch of the same function names the file by its path and the
        tree it sits in. Both are data: a ``[bold]`` in either is not markup."""
        repo = tmp_path / "[bold]repo"
        mark_git_checkout(repo)
        root = repo / "ash.yaml"
        root.write_text(json.dumps(_GRANT_DOCUMENT), encoding="utf-8")

        resolve_config_module._warn_dropped_own_sandbox(
            path=root, trees=[repo], names=None
        )

        [record] = [
            record
            for record in ash_log
            if record.getMessage().startswith(_OWN_SANDBOX_DROPPED)
        ]
        assert "[bold]repo" in record.getMessage(), record.getMessage()
        assert getattr(record, "markup", True) is False, record.getMessage()


class TestTheCheckoutGuardReadsTheFieldsOfAJudgment:
    """``_with_own_sandbox`` asks whether a checkout could not be ruled out and none
    was found. It read that as two whole ``WalkJudgment`` tuples, so a judgment that
    carried the same two answers in another shape (a subclass, a field added later)
    stopped matching without an error, the guard missed, and the file was dropped
    with no warning or kept. The guard reads the two fields."""

    class _Judgment:
        """The answers of a ``WalkJudgment``, not one: equal to none of them."""

        def __init__(self, in_a_checkout: bool, decided: bool) -> None:
            self.verdict = in_a_checkout
            self.decided = decided

    def _call(self, tmp_path, monkeypatch, in_a_checkout: bool, decided: bool):
        repo = tmp_path / "repo"
        mark_git_checkout(repo)
        file = tmp_path / "plain" / "ash.yaml"
        file.parent.mkdir()
        file.write_text(json.dumps(_GRANT_DOCUMENT), encoding="utf-8")
        documents = {file.resolve(): {"sandbox": {"extra_read_paths": [_OWN_GRANT]}}}
        monkeypatch.setattr(
            resolve_config_module,
            "checkout_judgment",
            lambda path: self._Judgment(in_a_checkout, decided),
        )
        updated, _wrote_mode = resolve_config_module._with_own_sandbox(
            trusted=AshConfig(),
            path=file,
            scan_root=repo,
            lexical=[file],
            trees=[repo],
            names={},
            documents=documents,
        )
        return file, updated

    def test_a_checkout_that_could_not_be_ruled_out_and_was_not_found_grants_nothing(
        self, tmp_path, monkeypatch, ash_log
    ):
        file, updated = self._call(
            tmp_path, monkeypatch, in_a_checkout=True, decided=False
        )

        assert list(updated.sandbox.extra_read_paths) == []
        lines = _dropped_own_sandbox(ash_log, file)
        assert len(lines) == 1, [record.getMessage() for record in ash_log]
        assert _WALK_STOPPED in lines[0], lines

    def test_control_a_file_no_checkout_holds_keeps_its_grant(
        self, tmp_path, monkeypatch, ash_log
    ):
        file, updated = self._call(
            tmp_path, monkeypatch, in_a_checkout=False, decided=True
        )

        assert list(updated.sandbox.extra_read_paths) == [_OWN_GRANT]
        assert _dropped_own_sandbox(ash_log, file) == []


class TestARootFoundInACheckoutIsNotToldToLetItsWalkFinish:
    """A root that sits in a checkout no scanned tree holds, such as an operator's
    ops repository, is found there by one of its names. Another of its names may be
    reached through a directory that cannot be searched. The walk of that name did
    not finish, but the file was located, and making a walk able to finish does not
    move a file out of the checkout it is in."""

    @staticmethod
    def _root_in_an_ops_checkout(w: Path, unjudgeable=None) -> Tuple[Path, Path, Path]:
        ops = w / "ops-repo"
        mark_git_checkout(ops)
        root = ops / "ash.yaml"
        root.write_text(json.dumps(_GRANT_DOCUMENT), encoding="utf-8")
        repo = w / "repo"
        mark_git_checkout(repo)
        link = w / "gate" / "link.yaml"
        link.parent.mkdir()
        link.symlink_to(root)
        if unjudgeable is not None:
            unjudgeable(link.parent)
        return root, link, repo

    def test_a_root_found_in_another_checkout_is_not_told_to_make_its_walk_finish(
        self, tmp_path, unjudgeable, ash_log
    ):
        root, link, repo = self._root_in_an_ops_checkout(tmp_path, unjudgeable)

        updated, _wrote_mode = resolve_config_module._with_own_sandbox(
            trusted=AshConfig(),
            path=root,
            scan_root=repo,
            lexical=[link],
            trees=[repo],
            names=None,
        )

        assert list(updated.sandbox.extra_read_paths) == []
        messages = [record.getMessage() for record in ash_log]
        assert not any("could not be decided" in message for message in messages), (
            messages
        )
        assert not any(_LET_IT_FINISH in message for message in messages), messages

    def test_control_a_root_found_in_another_checkout_with_every_walk_finished(
        self, tmp_path, ash_log
    ):
        root, link, repo = self._root_in_an_ops_checkout(tmp_path)

        updated, _wrote_mode = resolve_config_module._with_own_sandbox(
            trusted=AshConfig(),
            path=root,
            scan_root=repo,
            lexical=[link],
            trees=[repo],
            names=None,
        )

        assert list(updated.sandbox.extra_read_paths) == []
        assert _dropped_own_sandbox(ash_log, root) == []

    def test_the_load_names_a_root_found_in_another_checkout_by_that_checkout(
        self, tmp_path, ash_log
    ):
        """The direct calls above pass on a call that logs nothing: the own-sandbox
        step leaves a file a checkout holds out without a line, because the
        confinement warning names it. This goes through ``resolve_config`` and asks
        for that line: the settings are lost, one warning says why, and it says the
        file is in a checkout, not that its walk stopped."""
        root, _link, repo = self._root_in_an_ops_checkout(tmp_path)

        resolved = resolve_config(config_path=root, source_dir=repo)

        assert list(resolved.sandbox.extra_read_paths) == []
        lines = [
            message
            for message in (record.getMessage() for record in ash_log)
            if message.startswith("Ignoring sandbox.extra_read_paths")
        ]
        assert len(lines) == 1, [record.getMessage() for record in ash_log]
        assert _OUTSIDE_SENTENCE in lines[0], lines
        assert _WALK_STOPPED not in lines[0], lines
        assert _LET_IT_FINISH not in lines[0], lines

    def test_control_a_root_no_checkout_holds_is_still_told_to_make_its_walk_finish(
        self, tmp_path, unjudgeable, ash_log
    ):
        repo = tmp_path / "repo"
        mark_git_checkout(repo)
        root = tmp_path / "ops" / "gate" / "ash.yaml"
        root.parent.mkdir(parents=True)
        root.write_text(json.dumps(_GRANT_DOCUMENT), encoding="utf-8")
        unjudgeable(root.parent)

        resolve_config_module._with_own_sandbox(
            trusted=AshConfig(),
            path=root,
            scan_root=repo,
            lexical=[root],
            trees=[repo],
            names=None,
        )

        lines = _dropped_own_sandbox(ash_log, root)
        assert len(lines) == 1, [record.getMessage() for record in ash_log]
        assert _LET_IT_FINISH in lines[0], lines


class TestARootOnlyTheAnyCheckoutWalkCouldNotPlace:
    """The load judges a root twice: over the scanned trees (``confined_files``,
    which walks the names it is given) and for any checkout
    (``_with_any_checkout_files``, which also walks each chain file). A root whose
    walk stopped only in the second is on the confinement line for everything
    else, so its own sandbox settings are not the operator's either. Here the first
    walk is given no names, the shape of a chain file it did not cover."""

    @staticmethod
    def _the_trees_walk_covers_no_name(monkeypatch) -> None:
        real = resolve_config_module.confined_files

        def walking_no_names(chain, trees, named=()):
            return real(chain, trees, [])

        monkeypatch.setattr(resolve_config_module, "confined_files", walking_no_names)

    @pytest.mark.parametrize("site", _ROOTS)
    def test_a_root_the_trees_walk_did_not_cover_keeps_no_grant(
        self, tmp_path, unjudgeable, monkeypatch, ash_log, site
    ):
        undecided, arguments = _a_root_at(
            site, tmp_path, unjudgeable, monkeypatch, _GRANT_DOCUMENT
        )
        self._the_trees_walk_covers_no_name(monkeypatch)

        resolved = resolve_config(**arguments)

        assert _OWN_GRANT not in list(resolved.sandbox.extra_read_paths)
        lines = _announcing_the_loss(ash_log, undecided, site)
        assert lines, [record.getMessage() for record in ash_log]
        assert all(_WALK_STOPPED in line for line in lines), lines

    def test_control_a_root_whose_walks_both_finish_keeps_its_grant(
        self, tmp_path, monkeypatch, ash_log
    ):
        config, repo = _a_decided_root_beside_a_base_in_the_tree(tmp_path)
        self._the_trees_walk_covers_no_name(monkeypatch)

        resolved = resolve_config(config_path=config, source_dir=repo)

        assert list(resolved.sandbox.extra_read_paths) == [_OWN_GRANT]
        assert _dropped_own_sandbox(ash_log, config) == []


class TestTheLoadsAnswerDecidesTheWalk:
    """``_with_own_sandbox`` is told by the load whether the file's walk stopped,
    so it never judges the file by a second walk of its own. The load's walk and
    a second one can read different name sets, or the file can change between
    them: a file the load found undecided would keep its grant when the second
    walk finished, and a file the load found decided would be dropped as undecided."""

    @staticmethod
    def _operators_file(w: Path) -> Tuple[Path, Path, Dict[Path, Any]]:
        repo = w / "repo"
        mark_git_checkout(repo)
        file = w / "plain" / "ash.yaml"
        file.parent.mkdir()
        file.write_text(json.dumps(_GRANT_DOCUMENT), encoding="utf-8")
        documents = {file.resolve(): {"sandbox": {"extra_read_paths": [_OWN_GRANT]}}}
        return repo, file, documents

    @staticmethod
    def _count_the_walks(monkeypatch) -> List[List[Path]]:
        walked: List[List[Path]] = []
        real = resolve_config_module.confined_files

        def counting(chain, trees, named=()):
            walked.append(list(chain))
            return real(chain, trees, named)

        monkeypatch.setattr(resolve_config_module, "confined_files", counting)
        return walked

    def test_it_walks_nothing_itself_when_the_load_answers(self, tmp_path, monkeypatch):
        repo, file, documents = self._operators_file(tmp_path)
        walked = self._count_the_walks(monkeypatch)

        updated, _wrote_mode = resolve_config_module._with_own_sandbox(
            trusted=AshConfig(),
            path=file,
            scan_root=repo,
            lexical=[file],
            trees=[repo],
            names={},
            documents=documents,
            undecided=False,
        )

        assert walked == []
        assert list(updated.sandbox.extra_read_paths) == [_OWN_GRANT]

    def test_the_loads_answer_that_the_walk_stopped_grants_nothing(
        self, tmp_path, ash_log
    ):
        """The file's own walk finishes here; the answer the load gave is the one
        that counts."""
        repo, file, documents = self._operators_file(tmp_path)

        updated, _wrote_mode = resolve_config_module._with_own_sandbox(
            trusted=AshConfig(),
            path=file,
            scan_root=repo,
            lexical=[file],
            trees=[repo],
            names={},
            documents=documents,
            undecided=True,
        )

        assert list(updated.sandbox.extra_read_paths) == []
        lines = _dropped_own_sandbox(ash_log, file)
        assert lines, [record.getMessage() for record in ash_log]
        assert all(_WALK_STOPPED in line for line in lines), lines

    def test_control_a_direct_caller_that_gives_no_answer_gets_the_file_walked(
        self, tmp_path, monkeypatch
    ):
        """Control: with no answer from a load, the function judges the file
        itself, as it always did, and keeps the grant of a file whose walk
        finished."""
        repo, file, documents = self._operators_file(tmp_path)
        walked = self._count_the_walks(monkeypatch)

        updated, _wrote_mode = resolve_config_module._with_own_sandbox(
            trusted=AshConfig(),
            path=file,
            scan_root=repo,
            lexical=[file],
            trees=[repo],
            names={},
            documents=documents,
        )

        assert [file] in walked
        assert list(updated.sandbox.extra_read_paths) == [_OWN_GRANT]

    @pytest.mark.parametrize("site", _ROOTS)
    def test_every_call_site_gives_the_answer_the_load_reached(
        self, tmp_path, unjudgeable, monkeypatch, site
    ):
        undecided, arguments = _a_root_at(
            site, tmp_path, unjudgeable, monkeypatch, _GRANT_DOCUMENT
        )
        answers: List[Any] = []
        real = resolve_config_module._with_own_sandbox

        def recording(*args, **kwargs):
            answers.append(kwargs.get("undecided", "no answer"))
            return real(*args, **kwargs)

        monkeypatch.setattr(resolve_config_module, "_with_own_sandbox", recording)

        resolve_config(**arguments)

        if site == "selected":
            # The selected config's files are named by the confinement warning,
            # which says the walk stopped, so the load does not ask the rule about
            # a root of the selected chain whose walk stopped.
            assert answers == [], answers
            return
        assert answers, "_with_own_sandbox was never called"
        # An answer of the load's own, a bool: not a missing one, and not the None
        # that makes the function walk the file itself.
        assert all(isinstance(answer, bool) for answer in answers), answers
        assert answers.count(True) == 1, answers

    def test_control_a_root_whose_walk_finished_is_given_a_false_answer(
        self, tmp_path, monkeypatch
    ):
        config, repo = _a_decided_root_beside_a_base_in_the_tree(tmp_path)
        answers: List[Any] = []
        real = resolve_config_module._with_own_sandbox

        def recording(*args, **kwargs):
            answers.append(kwargs.get("undecided", "no answer"))
            return real(*args, **kwargs)

        monkeypatch.setattr(resolve_config_module, "_with_own_sandbox", recording)

        resolve_config(config_path=config, source_dir=repo)

        assert answers == [False], answers


class TestEveryWarningForAFileWhoseWalkStopped:
    @pytest.mark.parametrize("voice", sorted(_VOICES))
    def test_the_warning_says_the_walk_stopped_and_claims_no_location(
        self, tmp_path, unjudgeable, ash_log, voice
    ):
        document, marker = _VOICES[voice]
        config, source = _undecided_shape(
            tmp_path, unjudgeable, {"project_name": "x", **document}
        )

        resolve_config(config_path=config, source_dir=source)

        lines = _ignoring(ash_log, marker)
        assert lines, [record.getMessage() for record in ash_log]
        assert all(_WALK_STOPPED in line for line in lines), lines
        assert all(_UNDECIDED_HEAD in line for line in lines), lines
        for claim in _LOCATION_CLAIMS:
            assert not any(claim in line for line in lines), (claim, lines)

    @pytest.mark.parametrize("voice", sorted(_VOICES))
    def test_control_the_warning_for_a_file_in_the_tree_keeps_its_text(
        self, tmp_path, ash_log, voice
    ):
        """Control: with the walk decided, each voice says what it said."""
        document, marker = _VOICES[voice]
        config, repo = _in_tree_shape(tmp_path, {"project_name": "x", **document})

        resolve_config(config_path=config, source_dir=repo)

        lines = _ignoring(ash_log, marker)
        assert lines, [record.getMessage() for record in ash_log]
        fixed = _DECIDED_TEXT.get(voice, IN_TREE_OR_DELIVERED.reason)
        assert all(fixed in line for line in lines), (fixed, lines)
        assert all(KEEP_A_SETTING in line for line in lines), (KEEP_A_SETTING, lines)
        assert not any(_LET_IT_FINISH in line for line in lines), lines
        assert not any(_WALK_STOPPED in line for line in lines), lines


class TestTheRemedyForAFileWhoseWalkStopped:
    """A file whose walk stopped is not known to be in a checkout, so "move the
    file outside every git checkout" tells the operator to do what the file may
    already be. What keeps its settings is a walk that can finish."""

    @pytest.mark.parametrize("voice", sorted(_VOICES))
    def test_the_remedy_is_to_let_the_walk_finish(
        self, tmp_path, unjudgeable, ash_log, voice
    ):
        document, marker = _VOICES[voice]
        config, source = _undecided_shape(
            tmp_path, unjudgeable, {"project_name": "x", **document}
        )

        resolve_config(config_path=config, source_dir=source)

        lines = _ignoring(ash_log, marker)
        assert lines, [record.getMessage() for record in ash_log]
        assert all(_LET_IT_FINISH in line for line in lines), lines
        assert not any(_MOVE_IT_OUT in line for line in lines), lines

    def test_the_sandbox_warning_gives_the_same_remedy(
        self, tmp_path, unjudgeable, ash_log
    ):
        config, source = _undecided_shape(tmp_path, unjudgeable, _GRANT_DOCUMENT)

        resolve_config(config_path=config, source_dir=source)

        lines = _ignoring(ash_log, "sandbox.extra_read_paths")
        assert lines, [record.getMessage() for record in ash_log]
        assert all(_LET_IT_FINISH in line for line in lines), lines
        assert not any(_MOVE_IT_OUT in line for line in lines), lines

    def test_a_line_of_a_located_file_and_an_undecided_one_keeps_both_remedies(
        self, tmp_path, unjudgeable, ash_log
    ):
        """The base in the tree is moved out of it; the file whose walk stopped
        is made resolvable. The head already says each file's own reason."""
        mark_git_checkout(tmp_path / "repo")
        source = tmp_path / "repo" / "app"
        source.mkdir(parents=True)
        base = source / "base.yaml"
        base.write_text("content_db_staleness: warn\n", encoding="utf-8")
        config = tmp_path / "ash.yaml"
        config.write_text(
            f"project_name: x\nextends: {base.as_posix()}\n", encoding="utf-8"
        )
        unjudgeable(tmp_path)

        resolve_config(config_path=config, source_dir=source)

        lines = _ignoring(ash_log, "relaxing the stale content database check")
        assert lines, [record.getMessage() for record in ash_log]
        assert all(
            f"each file is the repository's -- by where it sits, or because {_WALK_STOPPED}"
            in line
            for line in lines
        ), lines
        assert all(KEEP_A_SETTING in line for line in lines), lines
        assert all(_LET_IT_FINISH in line for line in lines), lines


#: The two warnings for a trusted chain that ``trusted_base_config`` dropped whole
#: (``_warn_dropped_operator_reporters`` and ``_warn_dropped_honor_ignore_files``),
#: each with the document that makes it speak and a fragment only it holds.
_DROPPED_CHAIN_VOICES: Dict[str, Tuple[Dict[str, Any], str]] = {
    "operator-reporters": (
        {"reporters": {"s3": {"enabled": True, "options": {"bucket_name": "ops"}}}},
        "Ignoring reporters.s3 from ",
    ),
    "operator-honor-ignore-files": (
        {"honor_ignore_files": False},
        "Ignoring honor_ignore_files from ",
    ),
}
#: What both say of a file in another checkout, and the claims they must not make
#: of a file whose walk stopped. A literal, so the control that pins the text of a
#: file whose walk finished fails when the wording changes.
_OUTSIDE_SENTENCE = (
    "the file is inside the scanned tree or a git checkout, or an MCP client "
    "delivered it, so someone other than the operator may have written it"
)
_OUTSIDE_CLAIMS = (
    "inside the scanned tree or a git checkout",
    "an MCP client delivered it",
)


class TestTheWarningsForATrustedChainWhoseWalkStopped:
    """A trusted config whose name walk stopped is read as the repository's, so
    ``trusted_base_config`` drops its chain. The two warnings that name what the
    drop took (the off-host reporter sections and ``honor_ignore_files``) said the
    file is inside the scanned tree or a checkout, or was delivered, and ended with
    the remedy for a file that is in one."""

    @pytest.mark.parametrize("voice", sorted(_DROPPED_CHAIN_VOICES))
    def test_the_warning_says_the_walk_stopped_and_claims_no_location(
        self, tmp_path, unjudgeable, monkeypatch, ash_log, voice
    ):
        document, marker = _DROPPED_CHAIN_VOICES[voice]
        _, arguments = _a_root_at(
            "operator",
            tmp_path,
            unjudgeable,
            monkeypatch,
            {"project_name": "x", **document},
        )

        resolve_config(**arguments)

        lines = _ignoring(ash_log, marker)
        assert len(lines) == 1, [record.getMessage() for record in ash_log]
        assert _WALK_STOPPED in lines[0], lines
        for claim in _OUTSIDE_CLAIMS:
            assert claim not in lines[0], (claim, lines)

    @pytest.mark.parametrize("voice", sorted(_DROPPED_CHAIN_VOICES))
    def test_the_remedy_is_to_let_the_walk_finish(
        self, tmp_path, unjudgeable, monkeypatch, ash_log, voice
    ):
        document, marker = _DROPPED_CHAIN_VOICES[voice]
        _, arguments = _a_root_at(
            "operator",
            tmp_path,
            unjudgeable,
            monkeypatch,
            {"project_name": "x", **document},
        )

        resolve_config(**arguments)

        [line] = _ignoring(ash_log, marker)
        assert _LET_IT_FINISH in line, line
        assert _MOVE_IT_OUT not in line, line

    @pytest.mark.parametrize("voice", sorted(_DROPPED_CHAIN_VOICES))
    def test_control_a_file_in_another_checkout_keeps_its_text(
        self, tmp_path, ash_log, monkeypatch, voice
    ):
        """Control: with the walk decided, each warning says what it said."""
        monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
        document, marker = _DROPPED_CHAIN_VOICES[voice]
        repo = tmp_path / "repo"
        mark_git_checkout(repo)
        (repo / ".ash").mkdir()
        (repo / ".ash" / ".ash.yaml").write_text(
            "project_name: repo\n", encoding="utf-8"
        )
        mark_git_checkout(tmp_path / "ops")
        trusted = tmp_path / "ops" / "ash.yaml"
        trusted.write_text(
            json.dumps({"project_name": "x", **document}), encoding="utf-8"
        )

        resolve_config(source_dir=repo, trusted_config_path=trusted)

        [line] = _ignoring(ash_log, marker)
        assert _OUTSIDE_SENTENCE in line, line
        assert KEEP_A_SETTING in line, line
        assert _LET_IT_FINISH not in line, line
        assert _WALK_STOPPED not in line, line

    def test_the_sentence_and_remedy_follow_the_files_that_stopped(self):
        """A stopped file beside a located one keeps both remedies; a stopped file
        alone gets the remedy for a file nobody could place; with none stopped the
        sentence is the one for a file in another checkout, byte for byte."""
        from automated_security_helper.config.confinement_remedy import (
            KEEP_A_SETTING_BESIDE_A_LOCATED_FILE,
            KEEP_A_SETTING_WHEN_THE_WALK_STOPPED,
        )
        from automated_security_helper.config.resolve_config import (
            _dropped_chain_membership,
        )

        located = Path("/checkout/.ash/base.yaml")
        stopped = Path("/ops/gate/cfg.yaml")
        flags = {"given_root_membership": False, "rootless_wording": False}

        sentence, remedy = _dropped_chain_membership([stopped], [stopped], **flags)
        assert _WALK_STOPPED in sentence, sentence
        assert remedy == KEEP_A_SETTING_WHEN_THE_WALK_STOPPED

        sentence, remedy = _dropped_chain_membership(
            [located, stopped], [stopped], **flags
        )
        assert _WALK_STOPPED in sentence, sentence
        assert remedy == KEEP_A_SETTING_BESIDE_A_LOCATED_FILE

        sentence, remedy = _dropped_chain_membership([located], [], **flags)
        assert sentence == confinement_membership(
            checkout_membership=False, given_root=False, outside=True
        )
        assert remedy == KEEP_A_SETTING


class TestAnMcpClientsOverridesAreNotBlamedOnTheWalk:
    """With a client's overrides beside a file whose walk stopped, a value the
    overrides set was blamed on the walk in every warning, though the overrides
    are the client's whatever the file is."""

    def test_a_value_the_overrides_set_is_attributed_to_the_client(
        self, tmp_path, unjudgeable, ash_log
    ):
        config, source = _undecided_shape(tmp_path, unjudgeable, {"project_name": "x"})

        resolve_config(
            config_path=config,
            source_dir=source,
            config_overrides=["content_db_staleness=warn"],
            client_overrides=True,
        )

        lines = _ignoring(ash_log, "relaxing the stale content database check")
        assert lines, [record.getMessage() for record in ash_log]
        assert all(_WALK_STOPPED in line for line in lines), lines
        assert all(_UNDECIDED_HEAD in line for line in lines), lines
        assert all(_FROM_A_CLIENT in line for line in lines), lines

    def test_honor_ignore_files_set_by_the_overrides_is_attributed_to_the_client(
        self, tmp_path, unjudgeable, ash_log
    ):
        config, source = _undecided_shape(tmp_path, unjudgeable, {"project_name": "x"})

        resolve_config(
            config_path=config,
            source_dir=source,
            config_overrides=["honor_ignore_files=false"],
            client_overrides=True,
        )

        lines = _ignoring(ash_log, "Ignoring honor_ignore_files")
        assert lines, [record.getMessage() for record in ash_log]
        assert all(_WALK_STOPPED in line for line in lines), lines
        assert all(_UNDECIDED_HEAD in line for line in lines), lines
        assert all(_FROM_A_CLIENT in line for line in lines), lines

    def test_control_without_overrides_the_client_is_not_named(
        self, tmp_path, unjudgeable, ash_log
    ):
        config, source = _undecided_shape(
            tmp_path, unjudgeable, {"project_name": "x", "content_db_staleness": "warn"}
        )

        resolve_config(config_path=config, source_dir=source)

        lines = _ignoring(ash_log, "relaxing the stale content database check")
        assert lines, [record.getMessage() for record in ash_log]
        assert not any(_FROM_A_CLIENT in line for line in lines), lines

    def test_control_overrides_that_do_not_set_the_key_leave_the_walk_the_reason(
        self, tmp_path, unjudgeable, ash_log
    ):
        """The file writes ``honor_ignore_files``; the overrides write something
        else. The value is the file's, so the walk is the reason and the client
        is not named."""
        config, source = _undecided_shape(
            tmp_path, unjudgeable, {"project_name": "x", "honor_ignore_files": False}
        )

        resolve_config(
            config_path=config,
            source_dir=source,
            config_overrides=["project_name=client"],
            client_overrides=True,
        )

        lines = _ignoring(ash_log, "Ignoring honor_ignore_files")
        assert lines, [record.getMessage() for record in ash_log]
        assert all(_WALK_STOPPED in line for line in lines), lines
        assert not any(_FROM_A_CLIENT in line for line in lines), lines


class TestConfineToTrustedBaseGivesTheSameSource:
    """``confine_to_trusted_base`` (``ash merge`` and the MCP ``get_config``
    construction) runs the steps the load runs, over files it judges with the
    same walk, and gave three of them the source for a located file."""

    _VOICES_IT_RUNS = ("reporter-destinations", "scanner-config-file", "tool-version")

    @staticmethod
    def _config_for(voice: str) -> AshConfig:
        document, _marker = _VOICES[voice]
        return resolve_config_module.build_config({"project_name": "x", **document})

    @pytest.mark.parametrize("voice", _VOICES_IT_RUNS)
    def test_the_warning_says_the_walk_stopped_for_a_file_whose_walk_stopped(
        self, tmp_path, unjudgeable, ash_log, voice
    ):
        repo = tmp_path / "repo"
        mark_git_checkout(repo)
        file = tmp_path / "ops" / "gate" / "cfg.yaml"
        file.parent.mkdir(parents=True)
        file.write_text("project_name: x\n", encoding="utf-8")
        unjudgeable(tmp_path / "ops" / "gate")

        resolve_config_module.confine_to_trusted_base(
            self._config_for(voice), AshConfig(), [], repo, [file]
        )

        lines = _ignoring(ash_log, _VOICES[voice][1])
        assert lines, [record.getMessage() for record in ash_log]
        assert all(_WALK_STOPPED in line for line in lines), lines
        for claim in _LOCATION_CLAIMS:
            assert not any(claim in line for line in lines), (claim, lines)
        assert all(_LET_IT_FINISH in line for line in lines), lines

    @pytest.mark.parametrize("voice", _VOICES_IT_RUNS)
    def test_a_source_the_caller_passes_is_kept_even_when_it_is_the_default_text(
        self, tmp_path, unjudgeable, ash_log, voice
    ):
        """No source asks for the one the file's walk gives. A source passed on
        purpose is the caller's, including the one whose text is the default's: it
        is not told apart from a missing one by being the same object."""
        repo = tmp_path / "repo"
        mark_git_checkout(repo)
        file = tmp_path / "ops" / "gate" / "cfg.yaml"
        file.parent.mkdir(parents=True)
        file.write_text("project_name: x\n", encoding="utf-8")
        unjudgeable(tmp_path / "ops" / "gate")

        resolve_config_module.confine_to_trusted_base(
            self._config_for(voice),
            AshConfig(),
            [],
            repo,
            [file],
            source=IN_TREE_OR_DELIVERED,
        )

        lines = _ignoring(ash_log, _VOICES[voice][1])
        assert lines, [record.getMessage() for record in ash_log]
        assert all(IN_TREE_OR_DELIVERED.reason in line for line in lines), lines
        assert all(KEEP_A_SETTING in line for line in lines), lines
        assert not any(_LET_IT_FINISH in line for line in lines), lines

    @pytest.mark.parametrize("voice", _VOICES_IT_RUNS)
    def test_control_a_file_in_the_tree_keeps_its_text(self, tmp_path, ash_log, voice):
        repo = tmp_path / "repo"
        mark_git_checkout(repo)
        file = repo / ".ash" / ".ash.yaml"

        resolve_config_module.confine_to_trusted_base(
            self._config_for(voice), AshConfig(), [], repo, [file]
        )

        lines = _ignoring(ash_log, _VOICES[voice][1])
        assert lines, [record.getMessage() for record in ash_log]
        assert all(IN_TREE_OR_DELIVERED.reason in line for line in lines), lines
        assert all(KEEP_A_SETTING in line for line in lines), lines
        assert not any(_WALK_STOPPED in line for line in lines), lines


class _DeclaredOptions(ReporterOptionsBase):
    region: str = "default-region"


class _DeclaredConfig(ReporterPluginConfigBase):
    name: Literal["declared-reporter"] = "declared-reporter"
    options: _DeclaredOptions = _DeclaredOptions()


class _DeclaredReporter(ReporterPluginBase[_DeclaredConfig]):
    destination_options: ClassVar[Tuple[str, ...]] = ("region",)

    def report(self, model):
        return None


_DECLARED_DOCUMENT = {
    "project_name": "x",
    "reporters": {"declared-reporter": {"options": {"region": "repo-region"}}},
}
_DECLARED_MARKER = "reporters.declared-reporter.options.region"


class TestTheWarningForAReportersDeclaredDestinations:
    """``confine_declared_reporter_destinations`` runs once the plugin modules are
    loaded, with no source of its own, so it reads what the resolution recorded."""

    def test_it_says_the_walk_stopped_for_a_file_whose_walk_stopped(
        self, tmp_path, unjudgeable, ash_log
    ):
        from automated_security_helper.config.reporter_trust import (
            confine_declared_reporter_destinations,
        )

        config, source = _undecided_shape(tmp_path, unjudgeable, _DECLARED_DOCUMENT)
        resolved = resolve_config(config_path=config, source_dir=source)

        confine_declared_reporter_destinations(resolved, [_DeclaredReporter])

        lines = _ignoring(ash_log, _DECLARED_MARKER)
        assert lines, [record.getMessage() for record in ash_log]
        assert all(_WALK_STOPPED in line for line in lines), lines
        for claim in _LOCATION_CLAIMS:
            assert not any(claim in line for line in lines), (claim, lines)

    def test_it_gives_the_remedy_for_a_file_nobody_could_place(
        self, tmp_path, unjudgeable, ash_log
    ):
        from automated_security_helper.config.reporter_trust import (
            confine_declared_reporter_destinations,
        )

        config, source = _undecided_shape(tmp_path, unjudgeable, _DECLARED_DOCUMENT)
        resolved = resolve_config(config_path=config, source_dir=source)

        confine_declared_reporter_destinations(resolved, [_DeclaredReporter])

        lines = _ignoring(ash_log, _DECLARED_MARKER)
        assert lines, [record.getMessage() for record in ash_log]
        assert all(_LET_IT_FINISH in line for line in lines), lines
        assert not any(_MOVE_IT_OUT in line for line in lines), lines

    def test_it_speaks_the_source_of_the_record_it_confines_by(
        self, tmp_path, unjudgeable, ash_log
    ):
        """``ash report`` holds the file it was given to its own source after the
        load, and the declared step then confines by that record. The source the
        load left behind described a record that was replaced; the step reads the
        one recorded beside the record it uses."""
        from automated_security_helper.config.reporter_trust import (
            confine_declared_reporter_destinations,
            confine_off_host_reporters_to_overrides,
        )
        from automated_security_helper.config.untrusted_source import (
            REPORT_CONFIG_FILE,
        )

        config, source = _undecided_shape(tmp_path, unjudgeable, _DECLARED_DOCUMENT)
        resolved = resolve_config(config_path=config, source_dir=source)
        confine_off_host_reporters_to_overrides(
            resolved, [config], [], REPORT_CONFIG_FILE
        )
        ash_log.clear()

        confine_declared_reporter_destinations(resolved, [_DeclaredReporter])

        lines = _ignoring(ash_log, _DECLARED_MARKER)
        assert lines, [record.getMessage() for record in ash_log]
        assert all(REPORT_CONFIG_FILE.reason in line for line in lines), lines
        assert not any(_WALK_STOPPED in line for line in lines), lines

    def test_control_it_keeps_its_text_for_a_file_in_the_tree(self, tmp_path, ash_log):
        from automated_security_helper.config.reporter_trust import (
            confine_declared_reporter_destinations,
        )

        config, repo = _in_tree_shape(tmp_path, _DECLARED_DOCUMENT)
        resolved = resolve_config(config_path=config, source_dir=repo)

        confine_declared_reporter_destinations(resolved, [_DeclaredReporter])

        lines = _ignoring(ash_log, _DECLARED_MARKER)
        assert lines, [record.getMessage() for record in ash_log]
        assert all(IN_TREE_OR_DELIVERED.reason in line for line in lines), lines
        assert not any(_WALK_STOPPED in line for line in lines), lines
