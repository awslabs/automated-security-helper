# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A warning for a file an unfinished walk confined says the walk stopped.

``files_inside`` and ``in_a_checkout`` fail closed on a link walk that never
finished (``_walk_links``): the file is confined. The sentence the warnings
built from that membership used to claim a location -- "inside the scanned
tree", "in a checkout" -- that the walk never established. The result carriers
(``confined_files``, ``checkout_judgment``, ``scanned_tree_judgment``) keep
the judgment byte-identical and carry decidedness beside it, so the one
sentence (``membership_clause``/``confinement_membership``) states the true
reason instead. The judgments themselves are pinned unchanged here: an
undecided walk still confines exactly as before.

The undecided walks are real ``_walk_links`` runs over real files; only one
planted directory component is made unjudgeable, by an ``os.lstat`` wrapper
that refuses that single path (the EACCES shape ``_link_state`` maps to
"unknown"), the simulation shape the link-gate cells already use.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

import pytest

from automated_security_helper.config import sandbox_grants
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.sandbox_grants import (
    checkout_judgment,
    confined_files,
    confinement_membership,
    files_inside,
    forget_unverifiable_warnings,
    in_a_checkout,
    membership_clause,
)
from tests.utils.helpers import mark_git_checkout as _checkout

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()

_WALK_STOPPED = "resolving its name stopped before the walk finished"
_LOCATION_WALK_STOPPED = "the walk of its location stopped before the end"


def _undecided_config(w: Path, unjudgeable, doc: dict) -> Path:
    """A loadable config outside every checkout whose name walk is undecided."""
    config = w / "ops" / "gate" / "cfg.yaml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(json.dumps(doc), encoding="utf-8")
    unjudgeable(w / "ops" / "gate")
    return config


def _ignoring_lines(caplog) -> list:
    return [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Ignoring")
    ]


class TestTheSentenceArms:
    def test_the_undecided_head_names_the_walk_stopping(self):
        head = membership_clause(checkout_membership=False, undecided=True)
        assert head == (
            "whether the file is the repository's could not be decided "
            "(resolving its name stopped before the walk finished), which "
            "is read as the repository's"
        )

    def test_the_mixed_undecided_head_names_each_files_own_reason(self):
        head = membership_clause(checkout_membership=False, mixed=True, undecided=True)
        assert "by where it sits" in head, head
        assert _WALK_STOPPED in head, head
        assert head.endswith("--"), head

    def test_the_client_sentence_still_wins_over_undecided(self):
        with_undecided = membership_clause(
            checkout_membership=False, client_supplied=True, undecided=True
        )
        without = membership_clause(checkout_membership=False, client_supplied=True)
        assert with_undecided == without

    def test_the_confinement_sentence_does_not_claim_who_wrote_the_file(self):
        sentence = confinement_membership(checkout_membership=False, undecided=True)
        assert sentence.endswith(", so that repository may have written it"), sentence
        assert _WALK_STOPPED in sentence, sentence

    def test_every_decided_sentence_is_unchanged(self):
        """Byte-compatibility where the walk decided: green at base by design,
        and what the wording mutants are killed against. The mixed sentence
        is not among these: it changed when the mixed head became root-aware,
        and its full text is pinned in
        test_a_rootless_mixed_line_does_not_claim_the_given_root.py."""
        assert confinement_membership(checkout_membership=False) == (
            "the file is inside the scanned tree, so the repository being "
            "scanned wrote it"
        )
        assert confinement_membership(checkout_membership=True) == (
            "the file is in a checkout, which with no working directory is "
            "read as the scanned tree, so that repository wrote it"
        )
        assert confinement_membership(checkout_membership=True, given_root=True) == (
            "the file is in a checkout, which with no scanned tree is read "
            "as the repository's, so that repository wrote it"
        )
        assert confinement_membership(checkout_membership=False, given_root=True) == (
            "the file is inside the given root's trees, so that repository wrote it"
        )
        assert confinement_membership(
            checkout_membership=False, client_supplied=True
        ) == (
            "the file's content is the session client's, which is read as "
            "the repository's, so that content wrote it"
        )


class TestTheResultCarriers:
    def test_a_walk_judgment_is_not_a_bool(self, tmp_path):
        judgment = checkout_judgment(tmp_path / "plain.yaml")
        with pytest.raises(TypeError):
            bool(judgment)
        assert judgment.verdict is False
        assert judgment.decided is True

    def test_confined_files_is_not_a_bool(self):
        judged = confined_files([], [])
        with pytest.raises(TypeError):
            bool(judged)
        assert judged.members == ()
        assert judged.undecided == ()

    def test_an_undecided_name_is_a_member_and_listed_undecided(
        self, tmp_path, unjudgeable
    ):
        _checkout(tmp_path / "repo")
        name = _undecided_config(tmp_path, unjudgeable, {"project_name": "x"})
        trees = [tmp_path / "repo"]
        judged = confined_files([name], trees, named=[name])
        assert list(judged.members) == [name]
        assert list(judged.undecided) == [name]
        # The fail-closed collapse is byte-identical: the judgment did not move.
        assert files_inside([name], trees, named=[name]) == [name]

    def test_a_name_a_seen_in_tree_link_admits_is_not_listed_undecided(
        self, tmp_path, unjudgeable
    ):
        """A link the walk already saw inside a tree is found membership,
        whatever the rest of the walk; only a membership nothing was found
        for is undecided. The name is spelled outside the tree and reaches
        the in-tree link only through another link, so neither the name's
        location nor the resolved file decides it."""
        repo = tmp_path / "repo"
        _checkout(repo)
        (repo / "hop").mkdir()
        elsewhere = tmp_path / "elsewhere"
        (elsewhere / "gate").mkdir(parents=True)
        (elsewhere / "gate" / "cfg.yaml").write_text("project_name: x\n", "utf-8")
        (tmp_path / "entry").symlink_to(repo / "hop")
        (repo / "hop" / "jump").symlink_to(elsewhere)
        name = tmp_path / "entry" / "jump" / "gate" / "cfg.yaml"
        unjudgeable(elsewhere / "gate")
        judged = confined_files([name], [repo], named=[name])
        assert list(judged.members) == [name]
        assert judged.undecided == ()

    def test_the_checkout_collapse_is_unchanged_and_decidedness_rides_beside(
        self, tmp_path, unjudgeable
    ):
        target = tmp_path / "ops" / "gate" / "cfg.yaml"
        target.parent.mkdir(parents=True)
        target.write_text("project_name: x\n", encoding="utf-8")
        unjudgeable(tmp_path / "ops" / "gate")
        judgment = checkout_judgment(target)
        assert judgment.verdict is True
        assert judgment.decided is False
        assert in_a_checkout(target) is True

    def test_the_any_checkout_extension_reports_its_undecided_files(
        self, tmp_path, unjudgeable
    ):
        """The no-scanned-tree extension admits a file on an unfinished walk
        exactly as before and reports it, while a file a checkout was found
        for is not reported."""
        from automated_security_helper.config.resolve_config import (
            _with_any_checkout_files,
        )

        inside = tmp_path / "repo" / "cfg.yaml"
        _checkout(tmp_path / "repo")
        inside.write_text("project_name: x\n", encoding="utf-8")
        unresolved = tmp_path / "ops" / "gate" / "cfg.yaml"
        unresolved.parent.mkdir(parents=True)
        unresolved.write_text("project_name: x\n", encoding="utf-8")
        unjudgeable(tmp_path / "ops" / "gate")
        undecided: list = []
        files = _with_any_checkout_files(
            [], [inside, unresolved], [inside, unresolved], undecided_out=undecided
        )
        assert files == [inside, unresolved]
        assert undecided == [unresolved]


class TestTheSandboxVoice:
    def test_an_undecided_config_warning_says_the_walk_stopped(
        self, tmp_path, unjudgeable, caplog
    ):
        """End to end through resolve_config: the flag is computed from the
        load's own membership, and the fail-closed settle of the grants is
        unchanged beside the reworded sentence."""
        from automated_security_helper.config.resolve_config import resolve_config

        _checkout(tmp_path / "repo")
        src = tmp_path / "repo" / "app"
        src.mkdir(parents=True)
        config = _undecided_config(
            tmp_path,
            unjudgeable,
            {"project_name": "x", "sandbox": {"network_scanners": ["grype"]}},
        )
        with caplog.at_level(logging.WARNING):
            resolved = resolve_config(config_path=config, source_dir=src)
        lines = [
            line
            for line in _ignoring_lines(caplog)
            if "sandbox.network_scanners" in line
        ]
        assert lines, caplog.text
        assert all(_WALK_STOPPED in line for line in lines), lines
        assert not any("inside the scanned tree" in line for line in lines), lines
        # The judgment is unchanged: the grant is still taken away, and the
        # written list still stands as a limit.
        assert resolved.sandbox.network_scanners == AshConfig().sandbox.network_scanners
        assert resolved.sandbox.network_limit == ["grype"]

    def test_a_decided_config_warning_is_byte_identical_to_the_located_one(
        self, tmp_path, caplog
    ):
        """The same load with the walk left real keeps the base sentence."""
        from automated_security_helper.config.resolve_config import resolve_config

        _checkout(tmp_path / "repo")
        src = tmp_path / "repo" / "app"
        src.mkdir(parents=True)
        config = src / "cfg" / "ash.yaml"
        config.parent.mkdir(parents=True)
        config.write_text(
            json.dumps(
                {"project_name": "x", "sandbox": {"network_scanners": ["grype"]}}
            ),
            encoding="utf-8",
        )
        with caplog.at_level(logging.WARNING):
            resolve_config(config_path=config, source_dir=src)
        lines = [
            line
            for line in _ignoring_lines(caplog)
            if "sandbox.network_scanners" in line
        ]
        assert lines, caplog.text
        assert all(
            "the file is inside the scanned tree, so the repository being "
            "scanned wrote it" in line
            for line in lines
        ), lines
        assert not any(_WALK_STOPPED in line for line in lines), lines


class TestTheMarkedWalkVoice:
    """A scan inside a container is told which mounted files the host placed in
    another checkout (``--config-file-from-another-checkout``). Its warnings give
    the located sentence, and the file is confined as one found in a checkout. A
    file whose walk stopped has no mark of its own: the host never sends one for
    it, because the scanned-tree judgment claims such a name first."""

    @staticmethod
    def _mounted_config(tmp_path: Path):
        _checkout(tmp_path / "repo")
        src = tmp_path / "repo" / "app"
        src.mkdir(parents=True)
        config = tmp_path / "mounted" / "cfg.yaml"
        config.parent.mkdir(parents=True)
        config.write_text(
            json.dumps(
                {"project_name": "x", "sandbox": {"network_scanners": ["grype"]}}
            ),
            encoding="utf-8",
        )
        return src, config

    def test_a_file_marked_as_found_in_another_checkout_gets_the_located_sentence(
        self, tmp_path, caplog
    ):
        from automated_security_helper.config.resolve_config import resolve_config
        from automated_security_helper.config.sandbox_grants import (
            marked_files_in_another_checkout,
        )

        src, config = self._mounted_config(tmp_path)
        with marked_files_in_another_checkout([config]):
            with caplog.at_level(logging.WARNING):
                resolved = resolve_config(config_path=config, source_dir=src)
        lines = [
            line
            for line in _ignoring_lines(caplog)
            if "sandbox.network_scanners" in line
        ]
        assert lines, caplog.text
        assert not any(_WALK_STOPPED in line for line in lines), lines
        assert resolved.sandbox.network_scanners == AshConfig().sandbox.network_scanners
        assert resolved.sandbox.network_limit == ["grype"]


class TestTheSettleVoice:
    @staticmethod
    def _settle(
        tmp_path,
        caplog,
        *,
        mixed_membership: bool = False,
        outside_membership: bool = False,
    ) -> list:
        """The lines the settle step gives for a file whose walk stopped."""
        from automated_security_helper.config.operator_only_options import (
            RepositorySettings,
            confine_operator_only_options,
        )

        config = AshConfig.model_validate(
            {"reporters": {"aws-security-hub": {"options": {"findings_scope": "all"}}}}
        )
        repository = RepositorySettings([tmp_path])
        repository.found.append(
            (
                "reporters",
                "aws-security-hub",
                "aws-security-hub",
                "findings_scope",
                "all",
            )
        )
        with caplog.at_level(logging.WARNING):
            confine_operator_only_options(
                config,
                AshConfig(),
                [],
                [tmp_path / "ops" / "gate" / "cfg.yaml"],
                repository=repository,
                checkout_membership=False,
                mixed_membership=mixed_membership,
                given_root_membership=False,
                undecided_membership=True,
                outside_membership=outside_membership,
            )
        return _ignoring_lines(caplog)

    def test_the_settle_warning_says_the_walk_stopped(self, tmp_path, caplog):
        lines = self._settle(tmp_path, caplog)
        assert lines, caplog.text
        assert all(_WALK_STOPPED in line for line in lines), lines
        assert not any("inside the scanned tree" in line for line in lines), lines

    def test_the_settle_remedy_is_to_let_the_walk_finish(self, tmp_path, caplog):
        """A file the walk could not place is not told to be a config file outside
        the tree, which it may already be."""
        lines = self._settle(tmp_path, caplog)
        assert lines, caplog.text
        assert all(
            "make each directory on the file's path searchable" in line
            for line in lines
        ), lines
        assert not any("a config file outside the tree" in line for line in lines), (
            lines
        )

    def test_the_settle_remedy_beside_a_located_file_keeps_both(self, tmp_path, caplog):
        from automated_security_helper.config.confinement_remedy import (
            KEEP_A_SETTING,
        )

        lines = self._settle(tmp_path, caplog, mixed_membership=True)
        assert lines, caplog.text
        assert all(KEEP_A_SETTING in line for line in lines), lines
        assert all(
            "make each directory on the file's path searchable" in line
            for line in lines
        ), lines

    def test_the_settle_remedy_when_only_the_checkout_walk_stopped_agrees_with_the_other_voices(
        self, tmp_path, caplog
    ):
        """The shape where only the any-checkout walk stopped: the file is on the
        line as a checkout file and as an undecided one, and no located file
        stands beside it. The other voices take their remedy from ``mixed`` alone
        (``_tier_two_source``), which is false here, so the settle voice gives the
        remedy for a file nobody could place too, not the one that tells a located
        file to move out."""
        from automated_security_helper.config.confinement_remedy import (
            KEEP_A_SETTING,
            KEEP_A_SETTING_WHEN_THE_WALK_STOPPED,
        )
        from automated_security_helper.config.resolve_config import _tier_two_source

        other_voices = _tier_two_source(
            checkout_membership=False,
            client_supplied=False,
            mixed=False,
            given_root=False,
            undecided=True,
            outside=True,
        )
        assert other_voices.remedy == KEEP_A_SETTING_WHEN_THE_WALK_STOPPED

        lines = self._settle(tmp_path, caplog, outside_membership=True)
        assert lines, caplog.text
        assert all(
            "make each directory on the file's path searchable" in line
            for line in lines
        ), lines
        assert not any(KEEP_A_SETTING in line for line in lines), lines

    def test_control_the_settle_remedy_beside_a_located_file_and_outside_keeps_both(
        self, tmp_path, caplog
    ):
        from automated_security_helper.config.confinement_remedy import (
            KEEP_A_SETTING,
        )

        lines = self._settle(
            tmp_path, caplog, mixed_membership=True, outside_membership=True
        )
        assert lines, caplog.text
        assert all(KEEP_A_SETTING in line for line in lines), lines
        assert all(
            "make each directory on the file's path searchable" in line
            for line in lines
        ), lines


class TestThePluginModuleVoice:
    def _refused(self, monkeypatch, location: Path) -> None:
        from automated_security_helper.config import plugin_module_trust

        monkeypatch.setattr(
            plugin_module_trust,
            "_spec_without_importing",
            lambda _prefix, _parent: object(),
        )
        monkeypatch.setattr(
            plugin_module_trust, "_spec_locations", lambda _spec: [location]
        )

    def test_the_drop_warning_head_says_the_walk_stopped(
        self, tmp_path, monkeypatch, caplog
    ):
        from automated_security_helper.config.plugin_module_trust import (
            confine_plugin_modules,
        )

        _checkout(tmp_path / "repo")
        self._refused(monkeypatch, tmp_path / "repo" / "mods" / "mod.py")
        config = AshConfig()
        # A name in the plugin namespace: one outside it is kept for the scan's
        # namespace refusal and never reaches this warning.
        config.ash_plugin_modules = ["their_ash_plugins"]
        with caplog.at_level(logging.WARNING):
            confine_plugin_modules(
                config,
                AshConfig(),
                [],
                tmp_path / "repo",
                [tmp_path / "ops" / "gate" / "cfg.yaml"],
                checkout_membership=False,
                mixed_membership=False,
                given_root_membership=False,
                undecided_membership=True,
            )
        lines = _ignoring_lines(caplog)
        assert lines, caplog.text
        assert all(_WALK_STOPPED in line for line in lines), lines
        assert all(
            "so only installed modules outside the scanned tree and every git "
            "checkout are imported from it" in line
            for line in lines
        ), lines
        assert config.ash_plugin_modules == []

    def test_the_drop_warning_remedy_is_to_let_the_walk_finish(
        self, tmp_path, monkeypatch, unjudgeable, caplog
    ):
        """Through the whole load: a module the config of a file whose walk stopped
        names is dropped, and the warning does not tell the operator to move a
        file that is not known to be in a checkout."""
        from automated_security_helper.config.resolve_config import resolve_config

        _checkout(tmp_path / "repo")
        src = tmp_path / "repo" / "app"
        src.mkdir(parents=True)
        self._refused(monkeypatch, tmp_path / "repo" / "mods" / "mod.py")
        config = _undecided_config(
            tmp_path,
            unjudgeable,
            {"project_name": "x", "ash_plugin_modules": ["their_ash_plugins"]},
        )
        with caplog.at_level(logging.WARNING):
            resolve_config(config_path=config, source_dir=src)
        lines = [
            line
            for line in _ignoring_lines(caplog)
            if "ash_plugin_modules entries" in line
        ]
        assert lines, caplog.text
        assert all(_WALK_STOPPED in line for line in lines), lines
        assert all(
            "make each directory on the file's path searchable" in line
            for line in lines
        ), lines
        assert all("--ash-plugin-modules" in line for line in lines), lines
        assert not any("a config file outside the tree" in line for line in lines), (
            lines
        )

    def test_the_per_entry_reason_says_the_tree_walk_stopped(
        self, tmp_path, monkeypatch, unjudgeable
    ):
        from automated_security_helper.config.plugin_module_trust import (
            refusal_reason,
        )

        _checkout(tmp_path / "repo")
        location = tmp_path / "ops" / "gate" / "mod.py"
        location.parent.mkdir(parents=True)
        location.write_text("x = 1\n", encoding="utf-8")
        self._refused(monkeypatch, location)
        unjudgeable(tmp_path / "ops" / "gate")
        reason = refusal_reason("their_module", tmp_path / "repo")
        assert reason == (
            "whether it resolves inside the scanned tree could not be decided "
            "(the walk of its location stopped before the end), and an "
            "undecided location is refused"
        )
        root_reason = refusal_reason(
            "their_module", tmp_path / "repo", root_judged=True
        )
        assert root_reason == (
            "whether it resolves inside the given root's trees could not be "
            "decided (the walk of its location stopped before the end), and "
            "an undecided location is refused"
        )

    def test_the_per_entry_checkout_reason_names_the_stopped_walk(
        self, monkeypatch, tmp_path
    ):
        """The checkout arm's undecided wording. The arm is defensive: the
        tree arm walks the same location first and fails closed on the same
        unfinished walk, so the judgments are stubbed to reach this arm's
        sentence at all."""
        from automated_security_helper.config import plugin_module_trust
        from automated_security_helper.config.plugin_module_trust import (
            refusal_reason,
        )
        from automated_security_helper.config.sandbox_grants import WalkJudgment

        self._refused(monkeypatch, tmp_path / "mod.py")
        monkeypatch.setattr(
            plugin_module_trust,
            "scanned_tree_judgment",
            lambda _location, _root: WalkJudgment(verdict=False, decided=True),
        )
        monkeypatch.setattr(
            plugin_module_trust,
            "checkout_judgment",
            lambda _location: WalkJudgment(verdict=True, decided=False),
        )
        reason = refusal_reason("their_module", None, any_checkout=True)
        assert reason == (
            "whether it resolves inside a checkout could not be decided (the "
            "walk of its location stopped before the end), and an undecided "
            "location is refused"
        )

    def test_a_rootless_undecided_reason_speaks_the_checkout_not_a_tree(
        self, tmp_path, monkeypatch, unjudgeable
    ):
        """A rootless load passes no trees to the walk, so its undecided
        reason cannot name a scanned tree, or the given root's trees, that
        the judgment never had. Nothing is stubbed: the same real unfinished
        walk the rooted cell above reads, through a load with no root."""
        from automated_security_helper.config.plugin_module_trust import (
            refusal_reason,
        )

        location = tmp_path / "ops" / "gate" / "mod.py"
        location.parent.mkdir(parents=True)
        location.write_text("x = 1\n", encoding="utf-8")
        self._refused(monkeypatch, location)
        unjudgeable(tmp_path / "ops" / "gate")
        expected = (
            "whether it resolves inside a checkout could not be decided (the "
            "walk of its location stopped before the end), and an undecided "
            "location is refused"
        )
        assert refusal_reason("their_module", None, any_checkout=True) == expected
        assert (
            refusal_reason("their_module", None, any_checkout=True, root_judged=True)
            == expected
        )

    def test_undecided_counts_as_a_stated_membership_for_the_flag_guard(
        self, tmp_path, monkeypatch, caplog
    ):
        """A rootless load whose only membership statement is the undecided
        flag builds the undecided sentence instead of being refused as
        contradictory: the head claims no location at all."""
        from automated_security_helper.config.plugin_module_trust import (
            confine_plugin_modules,
        )

        self._refused(monkeypatch, tmp_path / "mods" / "mod.py")
        _checkout(tmp_path / "mods")
        config = AshConfig()
        config.ash_plugin_modules = ["their_ash_plugins"]
        with caplog.at_level(logging.WARNING):
            confine_plugin_modules(
                config,
                AshConfig(),
                [],
                None,
                [tmp_path / "cfg.yaml"],
                no_scanned_tree=True,
                checkout_membership=False,
                mixed_membership=False,
                given_root_membership=False,
                undecided_membership=True,
            )
        lines = _ignoring_lines(caplog)
        assert lines, caplog.text
        assert all(_WALK_STOPPED in line for line in lines), lines


class TestTheWorkspaceVoice:
    def test_the_per_project_resolve_says_the_walk_stopped(
        self, tmp_path, unjudgeable, caplog
    ):
        """The workspace path resolves each project through the same load, so
        an operator config whose name walk is undecided gets the same true
        sentence there."""
        from automated_security_helper.workspace.execution import (
            ProjectScanSettings,
            _project_config_with_policy,
        )
        from automated_security_helper.workspace.plan import ProjectPlan

        root = tmp_path / "ws"
        _checkout(root)
        project_dir = root / "api"
        project_dir.mkdir(parents=True)
        (project_dir / "a.py").write_text("x = 1\n", encoding="utf-8")
        config = _undecided_config(
            tmp_path,
            unjudgeable,
            {"project_name": "x", "sandbox": {"network_scanners": ["grype"]}},
        )
        project = ProjectPlan(
            key="api",
            relative_path="api",
            path=project_dir.as_posix(),
            label="api",
            display_label="api",
            severity_threshold="MEDIUM",
        )
        settings = ProjectScanSettings(
            output_dir=tmp_path / "out",
            default_config_path=config.as_posix(),
        )
        with caplog.at_level(logging.WARNING):
            resolved = _project_config_with_policy(project, settings)
        lines = [
            line
            for line in _ignoring_lines(caplog)
            if "sandbox.network_scanners" in line
        ]
        assert lines, caplog.text
        assert all(_WALK_STOPPED in line for line in lines), lines
        assert resolved.sandbox.network_limit == ["grype"]


_OPERATOR_ONLY_DOC = {
    "project_name": "env",
    "reporters": {
        "aws-security-hub": {
            "enabled": True,
            "options": {"findings_scope": "repo-scope", "aws_region": "repo-region"},
        }
    },
}


def _without_a_working_directory(tmp_path: Path, monkeypatch) -> None:
    """The process's working directory removed, so no scanned tree exists."""
    import sys

    if sys.platform == "win32":
        pytest.skip("the working directory cannot be removed on Windows")
    launched = tmp_path / "launched-here"
    launched.mkdir()
    monkeypatch.chdir(launched)
    os.rmdir(launched)
    with pytest.raises(FileNotFoundError):
        Path.cwd()


class TestTheResolveConfigLevel:
    """The wording flags resolve_config computes from its own membership
    reads, checked through the whole load instead of the helpers alone."""

    def test_the_fail_closed_warning_says_the_walk_stopped_for_an_undecided_file(
        self, tmp_path, monkeypatch, unjudgeable, caplog
    ):
        from automated_security_helper.config.resolve_config import resolve_config

        env_config = _undecided_config(tmp_path, unjudgeable, _OPERATOR_ONLY_DOC)
        monkeypatch.setenv("ASH_CONFIG", str(env_config))
        named = tmp_path / "operator.yaml"
        named.write_text("project_name: named\n", encoding="utf-8")
        _without_a_working_directory(tmp_path, monkeypatch)
        with caplog.at_level(logging.WARNING):
            resolve_config(config_path=named)
        lines = [
            record.getMessage()
            for record in caplog.records
            if "read fail-closed" in record.getMessage()
        ]
        assert len(lines) == 1, caplog.text
        assert _WALK_STOPPED in lines[0], lines
        assert "findings_scope" in lines[0], lines
        assert "in a checkout" not in lines[0], lines

    def test_the_fail_closed_warning_keeps_the_located_wording_for_a_found_file(
        self, tmp_path, monkeypatch, caplog
    ):
        from automated_security_helper.config.resolve_config import resolve_config

        checkout = tmp_path / "checkout"
        _checkout(checkout)
        env_config = checkout / ".ash" / ".ash.yaml"
        env_config.parent.mkdir(parents=True)
        env_config.write_text(json.dumps(_OPERATOR_ONLY_DOC), encoding="utf-8")
        monkeypatch.setenv("ASH_CONFIG", str(env_config))
        named = tmp_path / "operator.yaml"
        named.write_text("project_name: named\n", encoding="utf-8")
        _without_a_working_directory(tmp_path, monkeypatch)
        with caplog.at_level(logging.WARNING):
            resolve_config(config_path=named)
        lines = [
            record.getMessage()
            for record in caplog.records
            if "read fail-closed" in record.getMessage()
        ]
        assert len(lines) == 1, caplog.text
        assert "from its files in a checkout is left out" in lines[0], lines
        assert _WALK_STOPPED not in lines[0], lines

    def test_an_undecided_ash_config_file_with_no_config_selected_says_the_walk_stopped(
        self, tmp_path, monkeypatch, unjudgeable, caplog
    ):
        """No config is selected and no scanned tree exists, so the
        configuration is ASH_CONFIG's file and the settle step is the one
        voice: it reads the file's undecided walk, never a checkout."""
        from automated_security_helper.config.resolve_config import resolve_config

        env_config = _undecided_config(tmp_path, unjudgeable, _OPERATOR_ONLY_DOC)
        monkeypatch.setenv("ASH_CONFIG", str(env_config))
        _without_a_working_directory(tmp_path, monkeypatch)
        with caplog.at_level(logging.WARNING):
            resolve_config()
        lines = _ignoring_lines(caplog)
        assert lines, caplog.text
        assert all(_WALK_STOPPED in line for line in lines), lines
        assert not any("in a checkout" in line for line in lines), lines

    def test_a_chain_of_a_found_file_and_an_undecided_file_gets_the_mixed_sentence(
        self, tmp_path, unjudgeable, caplog
    ):
        """A config outside the scanned tree, whose name walk is undecided,
        extends a base inside the tree: the line names files of both reasons,
        so the sentence says each file's own. The undecided-only sentence
        would claim nothing was found for the file that sits in the tree."""
        from automated_security_helper.config.resolve_config import resolve_config

        _checkout(tmp_path / "repo")
        src = tmp_path / "repo" / "app"
        src.mkdir(parents=True)
        base = src / "base.yaml"
        base.write_text(
            "sandbox:\n  network_scanners:\n    - grype\n", encoding="utf-8"
        )
        config = tmp_path / "ash.yaml"
        config.write_text(f"extends: {base.as_posix()}\n", encoding="utf-8")
        unjudgeable(tmp_path)
        with caplog.at_level(logging.WARNING):
            resolve_config(config_path=config, source_dir=src)
        lines = [
            line
            for line in _ignoring_lines(caplog)
            if "sandbox.network_scanners" in line
        ]
        assert lines, caplog.text
        assert all(
            "each file is the repository's -- by where it sits, or because "
            f"{_WALK_STOPPED}" in line
            for line in lines
        ), lines
        assert not any("could not be decided" in line for line in lines), lines

    def test_an_ash_config_chain_of_both_reasons_gets_the_mixed_sentence(
        self, tmp_path, monkeypatch, unjudgeable, caplog
    ):
        """The same two reasons in the chain ASH_CONFIG names, with no config
        selected and no scanned tree: a file in a checkout extends a base whose
        name walk is undecided."""
        from automated_security_helper.config.resolve_config import resolve_config

        checkout = tmp_path / "checkout"
        _checkout(checkout)
        base = checkout / ".ash" / "gate" / "base.yaml"
        base.parent.mkdir(parents=True)
        base.write_text(json.dumps({"project_name": "base"}), encoding="utf-8")
        env_config = checkout / ".ash" / ".ash.yaml"
        env_config.write_text(
            json.dumps({**_OPERATOR_ONLY_DOC, "extends": base.as_posix()}),
            encoding="utf-8",
        )
        unjudgeable(base.parent)
        monkeypatch.setenv("ASH_CONFIG", str(env_config))
        _without_a_working_directory(tmp_path, monkeypatch)
        with caplog.at_level(logging.WARNING):
            resolve_config()
        lines = _ignoring_lines(caplog)
        assert lines, caplog.text
        assert all(
            "each file is the repository's -- by where it sits, or because "
            f"{_WALK_STOPPED}" in line
            for line in lines
        ), lines
        assert not any("could not be decided" in line for line in lines), lines

    @pytest.mark.parametrize("selected", [True, False], ids=["selected", "ash-config"])
    def test_a_rootless_load_of_a_checkout_file_and_an_undecided_file_names_no_tree(
        self, tmp_path, monkeypatch, unjudgeable, caplog, selected
    ):
        """With no scanned tree at all, a config whose name walk is undecided
        extends a base in a checkout. The mixed-undecided sentence the override
        reaches names no tree, so the rootless guard on the plain mixed flag is
        not repeated there: restoring it would word the line as undecided
        only, which is false for the base whose checkout was found."""
        from automated_security_helper.config.resolve_config import resolve_config

        checkout = tmp_path / "checkout"
        _checkout(checkout)
        base = checkout / "base.yaml"
        base.write_text(
            json.dumps(
                {
                    **_OPERATOR_ONLY_DOC,
                    "sandbox": {"network_scanners": ["grype"]},
                }
            ),
            encoding="utf-8",
        )
        config = tmp_path / "ash.yaml"
        config.write_text(f"extends: {base.as_posix()}\n", encoding="utf-8")
        unjudgeable(config)
        if not selected:
            monkeypatch.setenv("ASH_CONFIG", str(config))
        _without_a_working_directory(tmp_path, monkeypatch)
        with caplog.at_level(logging.WARNING):
            if selected:
                resolve_config(config_path=config)
            else:
                resolve_config()
        lines = _ignoring_lines(caplog)
        assert lines, caplog.text
        assert all(
            "each file is the repository's -- by where it sits, or because "
            f"{_WALK_STOPPED}" in line
            for line in lines
        ), lines
        assert not any(
            "inside the scanned tree" in line
            or "inside the given root's trees" in line
            or "could not be decided" in line
            for line in lines
        ), lines


def _spy_on_the_wording_memberships(monkeypatch) -> list:
    """Record what ``_wording_memberships`` returns for each call, leaving its
    behavior alone."""
    from automated_security_helper.config import resolve_config as module

    results: list = []
    real = module._wording_memberships

    def spy(*args, **kwargs):
        result = real(*args, **kwargs)
        results.append(result)
        return result

    monkeypatch.setattr(module, "_wording_memberships", spy)
    return results


def _undecided_config_extending_a_tree_file(w: Path, unjudgeable) -> tuple:
    """A config outside the scanned tree, with an undecided name walk, that
    extends a base inside the tree: the chain holds one located file and one
    undecided file. The config sits at the root config bases must stay
    inside, so the in-tree base is accepted. Returns (config, source dir)."""
    _checkout(w / "repo")
    src = w / "repo" / "app"
    src.mkdir(parents=True)
    base = src / "base.yaml"
    base.write_text(
        "project_name: x\nsandbox:\n  network_scanners: [grype]\n",
        encoding="utf-8",
    )
    config = w / "ash.yaml"
    config.write_text(f"extends: {base.as_posix()}\n", encoding="utf-8")
    unjudgeable(w)
    return config, src


class TestTheUndecidedOverrideLivesInTheHelper:
    """Each chain branch of resolve_config gets the mixed-undecided reading
    from ``_wording_memberships``: with an undecided file beside a located one
    the mixed value is True, and the flag that says the walk stopped is True.
    The sentence assertion comes first; it is the behavior-preservation check
    and does not depend on where the override is computed."""

    def _assert_the_mixed_undecided_reading(self, caplog, results) -> None:
        lines = [
            line
            for line in _ignoring_lines(caplog)
            if "sandbox.network_scanners" in line
        ]
        assert lines, caplog.text
        assert any(_WALK_STOPPED in line for line in lines), lines
        assert any("by where it sits" in line for line in lines), lines
        assert results, "the helper was never called"
        assert results[-1].mixed is True, results[-1]
        assert results[-1].undecided is True, results[-1]

    def test_the_selected_chain_branch_reads_mixed_undecided(
        self, tmp_path, monkeypatch, unjudgeable, caplog
    ):
        from automated_security_helper.config.resolve_config import resolve_config

        monkeypatch.delenv("ASH_CONFIG", raising=False)
        config, src = _undecided_config_extending_a_tree_file(tmp_path, unjudgeable)
        results = _spy_on_the_wording_memberships(monkeypatch)
        with caplog.at_level(logging.WARNING):
            resolve_config(config_path=config, source_dir=src)
        self._assert_the_mixed_undecided_reading(caplog, results)

    def test_the_ash_config_chain_branch_reads_mixed_undecided(
        self, tmp_path, monkeypatch, unjudgeable, caplog
    ):
        from automated_security_helper.config.resolve_config import resolve_config

        config, src = _undecided_config_extending_a_tree_file(tmp_path, unjudgeable)
        monkeypatch.setenv("ASH_CONFIG", str(config))
        results = _spy_on_the_wording_memberships(monkeypatch)
        with caplog.at_level(logging.WARNING):
            resolve_config(source_dir=src)
        self._assert_the_mixed_undecided_reading(caplog, results)


def _a_chain_of_links(root: Path, first_target: str) -> Path:
    """The last of more links than the walk follows, each naming the one before.

    The first link names *first_target*, a sibling of the links in *root*."""
    previous = first_target
    for index in range(sandbox_grants._MAX_LINKS + 2):
        link = root / f"hop{index}"
        link.symlink_to(previous)
        previous = link.name
    return link


def _walk_lines(caplog) -> list:
    return [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("The link walk for")
    ]


class TestTheWarnedWindow:
    def test_a_component_the_walk_cannot_examine_is_named_where_the_walk_stops(
        self, tmp_path, unjudgeable, caplog, _warned_window
    ):
        """A walk that stops because one component cannot be examined (a
        directory the process cannot search) names the config and that
        component once per name and run, as the link-bound and unreadable-link
        endings do. That ending was silent, so a file read as the repository's
        for this reason had no line saying why. The walk still ends undecided."""
        config = tmp_path / "ops" / "gate" / "cfg.yaml"
        config.parent.mkdir(parents=True)
        config.write_text("project_name: x\n", encoding="utf-8")
        unjudgeable(config.parent)
        with caplog.at_level(logging.WARNING):
            links, decided = sandbox_grants._walk_links(config)
            sandbox_grants._walk_links(config)
        assert decided is False
        lines = _walk_lines(caplog)
        assert len(lines) == 1, caplog.text
        assert lines[0].startswith(
            f"The link walk for {config.as_posix()} stopped at "
        ), lines
        assert f"stopped at {config.parent.as_posix()} (" in lines[0], lines
        assert "could not be examined" in lines[0], lines
        assert "cannot be ruled out as the scanned repository's" in lines[0], lines

    def test_a_walk_that_reaches_its_end_names_nothing(
        self, tmp_path, caplog, _warned_window
    ):
        config = tmp_path / "ops" / "gate" / "cfg.yaml"
        config.parent.mkdir(parents=True)
        config.write_text("project_name: x\n", encoding="utf-8")
        with caplog.at_level(logging.WARNING):
            links, decided = sandbox_grants._walk_links(config)
        assert decided is True
        assert _walk_lines(caplog) == [], caplog.text

    def test_a_new_window_warns_again_about_a_name_whose_walk_stopped(
        self, tmp_path, caplog, _warned_window
    ):
        """Forget opens a new window for a stopped walk: green at base by design,
        since forget already cleared entries by their run scope before the
        warned set was keyed by the kind of warning."""
        (tmp_path / "end.yaml").write_text("project_name: x\n", encoding="utf-8")
        name = _a_chain_of_links(tmp_path, "end.yaml")
        with caplog.at_level(logging.WARNING):
            checkout_judgment(name)
            checkout_judgment(name)
            assert len(_walk_lines(caplog)) == 1, caplog.text
            forget_unverifiable_warnings()
            checkout_judgment(name)
        assert len(_walk_lines(caplog)) == 2, caplog.text

    @pytest.mark.skipif(
        os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
        reason="a mode 000 directory is searchable by root and has no modes on Windows",
    )
    def test_a_walk_warning_and_a_git_warning_for_one_name_both_print_once(
        self, tmp_path, monkeypatch, caplog, _warned_window
    ):
        """A name whose link walk stopped and the .git entry that cannot be
        examined behind it each print their own warning, once, however often
        the name is judged. The key of each warning carries its kind, so the
        two cannot take each other's place.

        The name here is itself a mode 000 .git directory, so the first entry
        the boundary look-up reaches is the .git inside it, which nobody can
        examine; that entry, not the name, is the one the warning spells. An
        entry that cannot be examined bounds the tree the way a .git that
        cannot be searched does, so the look-up stops there.

        The link bound is lowered to 1 for the cell. At its real value of 40 a
        name the walk stops on cannot be looked up at all: the kernel follows
        no more than 40 links either, so the entry behind such a name is never
        read and never warned about."""
        monkeypatch.setattr(sandbox_grants, "_MAX_LINKS", 1)
        real = tmp_path / "real"
        real.mkdir()
        git_dir = real / ".git"
        git_dir.mkdir()
        (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
        os.chmod(git_dir, 0)
        name = _a_chain_of_links(tmp_path, "real") / ".git"
        try:
            with caplog.at_level(logging.WARNING):
                checkout_judgment(name)
                checkout_judgment(name)
        finally:
            os.chmod(git_dir, 0o755)
        spelled = name.as_posix()
        walk = [
            line
            for line in _walk_lines(caplog)
            if line.startswith(f"The link walk for {spelled} stopped")
        ]
        git = [
            record.getMessage()
            for record in caplog.records
            if record.getMessage().startswith(f"Treating {spelled}/.git as a checkout")
        ]
        assert len(walk) == 1, caplog.text
        assert len(git) == 1, caplog.text
