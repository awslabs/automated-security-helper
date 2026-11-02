# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The engine-block dispatch for scoped suppressions, and its fail-closed edges.

A ``scope.engines`` block is owned by the named scanner plugin through three
hooks (ScannerPluginBase): validate at config time, match at suppression time,
and the rule-qualifier split. The registry
(utils/suppression_scope_registry.py) is where the matcher finds the plugin;
a name with no registration matches nothing and warns once.
"""

import logging

import pytest

from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils import suppression_scope_registry as registry

pytestmark = pytest.mark.unit


class FakeEngineHooks:
    """The hook surface a registered plugin class exposes (classmethods)."""

    @classmethod
    def validate_suppression_scope(cls, block):
        extras = sorted(set(block) - {"marker"})
        return [f"unknown block keys: {', '.join(extras)}"] if extras else []

    @classmethod
    def suppression_scope_matches(cls, block, finding):
        return block.get("marker") == finding.rule_id

    @classmethod
    def split_rule_qualifier(cls, rule_id):
        open_at = rule_id.find("[")
        if open_at == -1 or not rule_id.endswith("]"):
            return rule_id, None
        return rule_id[:open_at], rule_id[open_at + 1 : -1] or None


@pytest.fixture
def fake_engine(monkeypatch):
    monkeypatch.setitem(registry._ENGINE_HOOKS, "fake-engine", FakeEngineHooks)
    yield "fake-engine"


def _finding(**overrides):
    values = dict(
        id="f1",
        title="t",
        description="d",
        severity="HIGH",
        scanner="fake-engine",
        scanner_type="IAC",
        rule_id="RULE-1",
        file_path="a.py",
    )
    values.update(overrides)
    return FlatVulnerability(**values)


def _entry(engines, rule_id="RULE-1"):
    return AshSuppression.model_validate(
        {"rule_id": rule_id, "path": "a.py", "reason": "r", "scope": {"engines": engines}}
    )


class TestDefaults:
    def test_default_validate_reports_unsupported(self):
        problems = ScannerPluginBase.validate_suppression_scope({"any": 1})
        assert problems
        assert "engine-scoped suppressions" in problems[0]

    def test_default_match_never_matches(self):
        assert ScannerPluginBase.suppression_scope_matches({"any": 1}, _finding()) is False

    def test_default_split_is_no_split(self):
        assert ScannerPluginBase.split_rule_qualifier("R[1]") == ("R[1]", None)


class TestDispatch:
    def test_a_registered_engine_matches_through_its_hook(self, fake_engine):
        entry = _entry({fake_engine: {"marker": "RULE-1"}})
        assert entry.matches(_finding())

    def test_the_hook_can_refuse(self, fake_engine):
        entry = _entry({fake_engine: {"marker": "OTHER"}})
        assert not entry.matches(_finding())

    def test_an_unregistered_engine_fails_closed_and_warns_once(self, caplog):
        registry._WARNED_ENGINES.discard("ghost-engine")
        entry = _entry({"ghost-engine": {"marker": "RULE-1"}})
        with caplog.at_level(logging.WARNING):
            assert not entry.matches(_finding(scanner="ghost-engine"))
            assert not entry.matches(_finding(scanner="ghost-engine"))
        warnings = [
            record
            for record in caplog.records
            if "ghost-engine" in record.getMessage()
        ]
        assert len(warnings) == 1
        assert "fail closed" in warnings[0].getMessage()

    def test_a_scoped_entry_matches_the_qualified_rule_id(self, fake_engine):
        entry = _entry({fake_engine: {"marker": "RULE-1[Resource::*]"}})
        qualified = _finding(rule_id="RULE-1[Resource::*]")
        # rule_id "RULE-1" does not glob-match the qualified id; the scoped
        # entry falls back to the engine's base id through the split hook.
        assert entry.matches(qualified)

    def test_an_unscoped_entry_keeps_todays_rule_comparison(self):
        entry = AshSuppression.model_validate(
            {"rule_id": "RULE-1", "path": "a.py", "reason": "r"}
        )
        assert not entry.matches(_finding(rule_id="RULE-1[Resource::*]"))


class TestLoadTimeProblems:
    def test_an_unknown_engine_name_gets_a_did_you_mean(self, fake_engine):
        entry = _entry({"fake-enginee": {"marker": "RULE-1"}})
        problems = registry.suppression_scope_problems([entry], {fake_engine})
        assert len(problems) == 1
        assert "'fake-enginee'" in problems[0]
        assert "did you mean 'fake-engine'?" in problems[0]

    def test_a_known_names_block_goes_to_its_validate_hook(self, fake_engine):
        entry = _entry({fake_engine: {"bogus": 1}})
        problems = registry.suppression_scope_problems([entry], {fake_engine})
        assert len(problems) == 1
        assert "unknown block keys" in problems[0]

    def test_a_registered_scanner_without_hooks_is_named(self, fake_engine):
        entry = _entry({"bandit": {"x": 1}})
        problems = registry.suppression_scope_problems(
            [entry], {fake_engine, "bandit"}
        )
        assert len(problems) == 1
        assert "does not support engine-scoped suppressions" in problems[0]

    def test_a_clean_block_reports_nothing(self, fake_engine):
        entry = _entry({fake_engine: {"marker": "RULE-1"}})
        assert registry.suppression_scope_problems([entry], {fake_engine}) == []
