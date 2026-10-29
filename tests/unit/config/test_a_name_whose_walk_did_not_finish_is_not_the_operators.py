# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A name whose directory walk did not finish is not the operator's.

``sandbox_grants.untrusted_reason`` is the one per-path rule that config files
(``repository_written``), the tool paths a config file names
(``path_trust.scanned_tree_reason``) and ``resolve_config._operator_wrote`` all
read. It followed the links of a name with ``links_followed``, which returns the
links found so far and drops whether the walk reached its end. A name whose walk
stopped early therefore read as outside every tree, while the same file sat on
the confinement's list as the repository's: ``_operator_wrote`` called it the
operator's, and the paths its document named were recorded as operator-named.

An unfinished walk cannot rule out a link in a tree, so the rule now fails closed
with a reason of its own. The rule for a path the operator named
(``sandbox_grants.in_tree_reason``, read by ``path_trust.operator_reason`` and
``honored_path``) reads the same walk and fails closed the same way: the warning
for an unfinished walk says the name is treated as inside the tree, and the path is
not handed to the tool. The advice that goes with the refusal is the one that can
help, which is to let the walk finish.

The walk is made unfinished for real: one directory component of the name is made
unjudgeable for the link walk's own ``lstat`` (the failure a parent that cannot be
searched gives), and every other path keeps the real ``lstat``, so the checks
around it are real.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.confinement_remedy import (
    KEEP_A_SETTING,
    LET_THE_WALK_FINISH,
)
from automated_security_helper.config.path_trust import (
    honored_path,
    operator_reason,
    reset_path_refusal_warnings,
)
from automated_security_helper.config.resolve_config import _operator_wrote
from automated_security_helper.config.sandbox_grants import (
    UNFINISHED_WALK_REASON,
    forget_unverifiable_warnings,
    in_any_checkout,
    in_tree_reason,
    repository_written,
    untrusted_path,
    untrusted_reason,
)
from tests.utils.helpers import link_walk_cannot_examine, mark_git_checkout

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()

_WALK_STOPPED = "resolving its name stopped before the walk finished"

#: A key shaped like an environment variable's name: a value under it is one the
#: operator named. ``"config"`` is a dotted option key: a value a config file wrote.
_OPERATOR_KEY = "SOME_TOOL_CONFIG_FILE"
_CONFIG_WRITTEN_KEY = "config"


@pytest.fixture(autouse=True)
def _fresh_scene(tmp_path: Path, monkeypatch) -> None:
    assert not in_any_checkout(tmp_path), (
        f"{tmp_path} is inside a git checkout; run with --basetemp outside one"
    )
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    reset_path_refusal_warnings()
    forget_unverifiable_warnings()
    yield
    reset_path_refusal_warnings()
    forget_unverifiable_warnings()


def _scene(tmp_path: Path):
    """A scanned checkout with its scanned directory, and a file outside every
    checkout whose parent directory is the component the walk will not examine."""
    mark_git_checkout(tmp_path / "repo")
    source = tmp_path / "repo" / "app"
    source.mkdir(parents=True)
    config = tmp_path / "ops" / "gate" / "ash.yaml"
    config.parent.mkdir(parents=True)
    config.write_text("project_name: ops\n", encoding="utf-8")
    assert not in_any_checkout(config)
    return source, config


def test_the_rule_gives_a_reason_for_a_name_whose_walk_did_not_finish(
    tmp_path, monkeypatch
):
    source, config = _scene(tmp_path)
    refused = link_walk_cannot_examine(monkeypatch, config.parent)

    reason = untrusted_reason(config, source)

    assert refused.asked > 0, "the walk never asked to look at the component"
    assert reason is not None
    assert _WALK_STOPPED in reason, reason
    assert untrusted_path(config, source) is True
    assert repository_written([config], source, [config]) == [config]


def test_control_the_same_name_with_its_walk_finished_is_the_operators(tmp_path):
    source, config = _scene(tmp_path)

    assert untrusted_reason(config, source) is None
    assert untrusted_path(config, source) is False
    assert repository_written([config], source, [config]) == []


def test_a_link_the_walk_found_is_named_before_the_walk_that_ended_after_it(
    tmp_path, monkeypatch
):
    """The links found before the walk ended are judged first: a link that sits in
    the checkout is named as the reason, not the unfinished walk."""
    source, config = _scene(tmp_path)
    link = tmp_path / "repo" / "ci-link.yaml"
    link.symlink_to(config)
    named = tmp_path / "ops" / "via.yaml"
    named.symlink_to(link)
    refused = link_walk_cannot_examine(monkeypatch, config.parent)

    reason = untrusted_reason(named, source)

    # The walk went on past the link in the checkout and reached the directory it
    # cannot examine; the reason still names the link it found on the way.
    assert refused.asked > 0, "the walk never asked to look at the component"
    assert reason is not None
    assert "a link inside the git checkout" in reason, reason
    assert _WALK_STOPPED not in reason, reason


def test_control_the_same_scene_with_every_hop_outside_the_checkout_gives_the_walk(
    tmp_path, monkeypatch
):
    """The control for the test above: with no link in the checkout, the same walk
    that ends at the directory it cannot examine is the reason."""
    source, config = _scene(tmp_path)
    named = tmp_path / "ops" / "via.yaml"
    named.symlink_to(config)
    refused = link_walk_cannot_examine(monkeypatch, config.parent)

    reason = untrusted_reason(named, source)

    assert refused.asked > 0, "the walk never asked to look at the component"
    assert reason is not None
    assert _WALK_STOPPED in reason, reason
    assert "a link inside the git checkout" not in reason, reason


def test_the_file_of_a_walk_that_did_not_finish_is_not_the_operators(
    tmp_path, monkeypatch
):
    source, config = _scene(tmp_path)
    link_walk_cannot_examine(monkeypatch, config.parent)

    assert _operator_wrote(config, source) is False


def test_control_the_file_of_a_walk_that_finished_is_the_operators(tmp_path):
    source, config = _scene(tmp_path)

    assert _operator_wrote(config, source) is True


def test_a_path_a_config_names_through_an_unfinished_walk_is_not_passed_to_the_tool(
    tmp_path, monkeypatch, caplog
):
    """The tool-path rule for a value a config file wrote reads the same predicate:
    the path is not handed to the tool, and the warning says why."""
    source, config = _scene(tmp_path)
    link_walk_cannot_examine(monkeypatch, config.parent)

    with caplog.at_level(logging.WARNING):
        honored = honored_path(str(config), source_dir=source, key="config")

    assert honored is None
    lines = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Ignoring config (")
    ]
    assert len(lines) == 1, caplog.text
    assert _WALK_STOPPED in lines[0], lines


def test_control_a_path_whose_walk_finished_is_passed_to_the_tool(tmp_path):
    source, config = _scene(tmp_path)

    assert honored_path(str(config), source_dir=source, key="config") == (
        config.resolve()
    )


def _lines_starting(caplog, start: str) -> list:
    return [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith(start)
    ]


class TestThePathTheOperatorNamed:
    """``in_tree_reason`` is the rule for a path the operator named. It read the
    walk's links and dropped whether the walk reached its end, so a name whose walk
    stopped read as outside the scanned tree and the path was handed to the tool,
    while the walk's own warning said the name is treated as inside it."""

    def test_the_rule_gives_the_walk_reason_for_a_name_whose_walk_did_not_finish(
        self, tmp_path, monkeypatch
    ):
        source, config = _scene(tmp_path)
        link_walk_cannot_examine(monkeypatch, config.parent)

        assert in_tree_reason(config, source) == UNFINISHED_WALK_REASON
        assert operator_reason(config, source) == UNFINISHED_WALK_REASON

    def test_a_file_a_client_delivered_is_named_as_delivered_when_its_walk_did_not_finish(
        self, tmp_path, monkeypatch
    ):
        """A delivered file is refused after the walk finishes too, so the walk is
        not the reason to give: the reason that stays true whatever the walk does
        is the one named."""
        source, config = _scene(tmp_path)
        refused = link_walk_cannot_examine(monkeypatch, config.parent)
        monkeypatch.setattr(
            "automated_security_helper.cli.mcp.sandbox.config_is_client_supplied",
            lambda path: True,
        )

        reason = operator_reason(config, source)

        assert refused.asked > 0, "the walk never asked to look at the component"
        assert reason == "it is a file an MCP client delivered", reason

    @pytest.mark.parametrize(
        "error",
        [
            RuntimeError("Symlink loop from 'a'"),
            OSError(40, "Too many levels of symbolic links"),
        ],
        ids=["runtime-error", "os-error"],
    )
    @pytest.mark.parametrize(
        "helper",
        [
            "automated_security_helper.cli.mcp.profile_registry.session_config_was_patched",
            "automated_security_helper.cli.mcp.sandbox.config_is_client_supplied",
        ],
        ids=["session-profile-check", "client-delivery-check"],
    )
    def test_a_check_that_cannot_resolve_the_name_leaves_the_walks_reason(
        self, tmp_path, monkeypatch, helper, error
    ):
        """The two MCP checks run for a name whose walk stopped, and they resolve
        the name themselves: ``Path.resolve`` raises ``RuntimeError`` for a symlink
        loop up to Python 3.12 and ``OSError`` for a name the system refuses. Before
        a stopped walk ended the rule early, they were not asked about such a name,
        and a raise out of ``operator_reason`` would escape ``honored_path``."""
        source, config = _scene(tmp_path)
        link_walk_cannot_examine(monkeypatch, config.parent)

        def cannot_resolve(path):
            raise error

        monkeypatch.setattr(helper, cannot_resolve)

        assert operator_reason(config, source) == UNFINISHED_WALK_REASON

    def test_a_path_the_operator_named_that_a_check_cannot_resolve_is_refused(
        self, tmp_path, monkeypatch, caplog
    ):
        source, config = _scene(tmp_path)
        link_walk_cannot_examine(monkeypatch, config.parent)

        def cannot_resolve(path):
            raise RuntimeError("Symlink loop from 'a'")

        monkeypatch.setattr(
            "automated_security_helper.cli.mcp.profile_registry."
            "session_config_was_patched",
            cannot_resolve,
        )

        with caplog.at_level(logging.WARNING):
            honored = honored_path(str(config), source_dir=source, key=_OPERATOR_KEY)

        assert honored is None
        lines = _lines_starting(caplog, f"Ignoring {_OPERATOR_KEY} (")
        assert len(lines) == 1, caplog.text
        assert _WALK_STOPPED in lines[0], lines

    def test_a_check_that_cannot_resolve_a_name_the_walk_decided_does_not_answer_none(
        self, tmp_path, monkeypatch
    ):
        """The check that cannot answer is not an answer of "no": with the walk
        decided there is no reason of its own to fall back to, so the name is
        refused as one whose resolving failed."""
        source, config = _scene(tmp_path)
        assert operator_reason(config, source) is None

        def cannot_resolve(path):
            raise RuntimeError("Symlink loop from 'a'")

        monkeypatch.setattr(
            "automated_security_helper.cli.mcp.profile_registry."
            "session_config_was_patched",
            cannot_resolve,
        )

        assert operator_reason(config, source) == UNFINISHED_WALK_REASON

    def test_a_name_that_is_a_symlink_loop_has_a_reason_and_raises_nothing(
        self, tmp_path, monkeypatch
    ):
        """A real ``a -> b -> a`` loop under a workspace root, so the checks reach
        their own resolve of the name. The walk cannot end on it."""
        source, _config = _scene(tmp_path)
        workspace = tmp_path / "mcp-workspaces"
        workspace.mkdir()
        monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
        loop_a = tmp_path / "ops" / "loop-a.yaml"
        loop_b = tmp_path / "ops" / "loop-b.yaml"
        loop_a.symlink_to(loop_b)
        loop_b.symlink_to(loop_a)

        reason = operator_reason(loop_a, source)

        assert reason is not None
        assert _WALK_STOPPED in reason, reason

    def test_control_the_same_name_with_its_walk_finished_has_no_reason(self, tmp_path):
        source, config = _scene(tmp_path)

        assert in_tree_reason(config, source) is None
        assert operator_reason(config, source) is None

    def test_a_link_in_the_scanned_tree_is_named_before_the_walk_that_ended_after_it(
        self, tmp_path, monkeypatch
    ):
        """The links found before the walk ended are judged first, so the reason
        names the link that sits in the tree, not the unfinished walk."""
        source, config = _scene(tmp_path)
        link = tmp_path / "repo" / "ci-link.yaml"
        link.symlink_to(config)
        named = tmp_path / "ops" / "via.yaml"
        named.symlink_to(link)
        refused = link_walk_cannot_examine(monkeypatch, config.parent)

        reason = in_tree_reason(named, source)

        assert refused.asked > 0, "the walk never asked to look at the component"
        assert reason is not None
        assert "a link inside the scanned tree" in reason, reason
        assert _WALK_STOPPED not in reason, reason

    def test_a_path_the_operator_named_through_an_unfinished_walk_is_not_passed_to_the_tool(
        self, tmp_path, monkeypatch, caplog
    ):
        source, config = _scene(tmp_path)
        link_walk_cannot_examine(monkeypatch, config.parent)

        with caplog.at_level(logging.WARNING):
            honored = honored_path(str(config), source_dir=source, key=_OPERATOR_KEY)

        assert honored is None
        lines = _lines_starting(caplog, f"Ignoring {_OPERATOR_KEY} (")
        assert len(lines) == 1, caplog.text
        assert _WALK_STOPPED in lines[0], lines

    def test_control_a_path_the_operator_named_whose_walk_finished_is_passed_to_the_tool(
        self, tmp_path
    ):
        source, config = _scene(tmp_path)

        assert honored_path(str(config), source_dir=source, key=_OPERATOR_KEY) == (
            config.resolve()
        )


class TestTheRefusalAndTheWalkWarningAgree:
    """Where the walk logs that it stopped, it says the name is treated as inside
    the tree. The path is then withheld from the tool, whoever named it, and the
    advice on the refusal is the one that can help: let the walk finish."""

    @pytest.mark.parametrize(
        "key",
        [_OPERATOR_KEY, _CONFIG_WRITTEN_KEY],
        ids=["operator-named", "config-written"],
    )
    def test_whatever_the_walk_says_the_path_is_withheld_when_its_name_is_unresolved(
        self, tmp_path, monkeypatch, caplog, key
    ):
        source, config = _scene(tmp_path)
        link_walk_cannot_examine(monkeypatch, config.parent)

        with caplog.at_level(logging.WARNING):
            honored = honored_path(str(config), source_dir=source, key=key)

        # The walk says the name is treated as inside the tree for the endings it
        # logs (a link it cannot read, the link bound); the ending at a component
        # it cannot examine is not logged on this line. Whatever it logs, the path
        # is then withheld.
        walk = _lines_starting(caplog, "The link walk for ")
        assert all("is treated as inside it" in line for line in walk), walk
        assert honored is None

    @pytest.mark.parametrize(
        "key",
        [_OPERATOR_KEY, _CONFIG_WRITTEN_KEY],
        ids=["operator-named", "config-written"],
    )
    def test_the_refusal_for_an_unfinished_walk_gives_the_advice_that_can_help(
        self, tmp_path, monkeypatch, caplog, key
    ):
        source, config = _scene(tmp_path)
        link_walk_cannot_examine(monkeypatch, config.parent)

        with caplog.at_level(logging.WARNING):
            honored_path(str(config), source_dir=source, key=key)

        lines = _lines_starting(caplog, f"Ignoring {key} (")
        assert len(lines) == 1, caplog.text
        assert lines[0].endswith(f"{LET_THE_WALK_FINISH}."), lines
        assert KEEP_A_SETTING not in lines[0], lines
        assert "name one outside it" not in lines[0], lines

    def test_control_a_refusal_that_is_not_about_the_walk_keeps_its_own_advice(
        self, tmp_path, caplog
    ):
        """A path inside the scanned tree is refused for where it sits, and the
        advice still says to move it."""
        source, _ = _scene(tmp_path)
        inside = source / "tool.yaml"
        inside.write_text("a: 1\n", encoding="utf-8")

        with caplog.at_level(logging.WARNING):
            assert (
                honored_path(str(inside), source_dir=source, key=_OPERATOR_KEY) is None
            )
            assert (
                honored_path(str(inside), source_dir=source, key=_CONFIG_WRITTEN_KEY)
                is None
            )

        operator_line = _lines_starting(caplog, f"Ignoring {_OPERATOR_KEY} (")
        written_line = _lines_starting(caplog, f"Ignoring {_CONFIG_WRITTEN_KEY} (")
        assert len(operator_line) == 1 and len(written_line) == 1, caplog.text
        assert operator_line[0].endswith("name one outside it."), operator_line
        assert written_line[0].endswith(KEEP_A_SETTING), written_line
        assert LET_THE_WALK_FINISH not in operator_line[0] + written_line[0]
