# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A repository value equal to the default no longer stands in for the operator's.

cfn-guard's ``_operator_rule_sets`` and cfn-lint's ``_operator_option`` took a value
equal to the option's default as it stood, before any provenance check, so a config
inside the scanned tree (or an MCP client) could narrow an operator's wider rule set
down to the default, or undo the operator's ``ignore_checks``, by writing the
default. Both now take the operator's own value (the trusted base with the
operator's overrides replayed, ``config_trust.operator_value``) when the value is
not the operator's, and the default only when the operator chose none.

Red at the base: the repository's default-equal value was returned and the
operator's set or list was not.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_guard_scanner import (
    DEFAULT_RULE_SET,
    CfnGuardScanner,
    CfnGuardScannerConfig,
    CfnGuardScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_lint_scanner import (
    CfnLintScanner,
    CfnLintScannerConfig,
    CfnLintScannerConfigOptions,
)
from automated_security_helper.utils.config_trust import (
    operator_value,
    record_provenance,
)

pytestmark = pytest.mark.unit

OPERATOR_RULE_SETS = ["wa-Reliability-Pillar", "cis-aws-benchmark-level-1"]
OPERATOR_IGNORED = ["W3005", "E3012"]


def _trusted(scanners: Dict[str, Any]) -> AshConfig:
    """The operator's trusted base, with ``scanners`` written as a file writes them."""
    return AshConfig.model_validate({"scanners": scanners})


def _context(repo: Path, trusted: AshConfig, *, operator: bool) -> PluginContext:
    config = get_default_config()
    record_provenance(
        config,
        in_tree=[] if operator else [repo / ".ash" / ".ash.yaml"],
        trusted=trusted,
    )
    return PluginContext(
        source_dir=repo,
        output_dir=repo / ".ash" / "ash_output",
        work_dir=repo / ".ash" / "ash_output" / "converted",
        config=config,
    )


def _guard(
    repo: Path, trusted: AshConfig, *, operator: bool, **options
) -> CfnGuardScanner:
    return CfnGuardScanner(
        context=_context(repo, trusted, operator=operator),
        config=CfnGuardScannerConfig(
            enabled=True, options=CfnGuardScannerConfigOptions(**options)
        ),
    )


def _lint(
    repo: Path, trusted: AshConfig, *, operator: bool, **options
) -> CfnLintScanner:
    return CfnLintScanner(
        context=_context(repo, trusted, operator=operator),
        config=CfnLintScannerConfig(
            enabled=True, options=CfnLintScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / ".ash").mkdir(parents=True)
    return root


class TestOperatorValue:
    def test_the_trusted_bases_value_is_the_operators(self):
        config = get_default_config()
        record_provenance(
            config,
            in_tree=[Path("/scanned/.ash/.ash.yaml")],
            trusted=_trusted(
                {"cfn-guard": {"options": {"rule_sets": OPERATOR_RULE_SETS}}}
            ),
        )

        found, value = operator_value(config, "scanners.cfn-guard.options.rule_sets")

        assert found is True
        assert value == OPERATOR_RULE_SETS

    def test_an_override_is_replayed_onto_the_trusted_base(self):
        config = get_default_config()
        record_provenance(
            config,
            in_tree=[Path("/scanned/.ash/.ash.yaml")],
            trusted=AshConfig(),
            config_overrides=["scanners.cfn-lint.options.ignore_checks=[W3005]"],
        )

        found, value = operator_value(config, "scanners.cfn-lint.options.ignore_checks")

        assert (found, value) == (True, ["W3005"])

    def test_a_config_without_provenance_records_no_operator_value(self):
        assert operator_value(AshConfig(), "scanners.cfn-guard.options.rule_sets") == (
            False,
            None,
        )
        assert operator_value(None, "scanners.cfn-guard.options.rule_sets") == (
            False,
            None,
        )


class TestCfnGuardRuleSets:
    def test_a_repository_default_does_not_narrow_the_operators_wider_set(
        self, repo, caplog
    ):
        trusted = _trusted(
            {"cfn-guard": {"options": {"rule_sets": OPERATOR_RULE_SETS}}}
        )
        scanner = _guard(repo, trusted, operator=False, rule_sets=[DEFAULT_RULE_SET])

        with caplog.at_level(logging.WARNING):
            assert scanner._operator_rule_sets() == OPERATOR_RULE_SETS
        assert "Ignoring scanners.cfn-guard.options.rule_sets" in caplog.text
        assert "the operator's rule sets" in caplog.text

    def test_a_repository_set_is_replaced_by_the_operators_set(self, repo):
        trusted = _trusted(
            {"cfn-guard": {"options": {"rule_sets": OPERATOR_RULE_SETS}}}
        )
        scanner = _guard(repo, trusted, operator=False, rule_sets=["custom-set"])

        assert scanner._operator_rule_sets() == OPERATOR_RULE_SETS

    def test_the_default_set_stands_when_the_operator_chose_none(self, repo, caplog):
        """The control: with the defaults as the trusted base, a repository's own
        set is still replaced by the default set, with the default named."""
        scanner = _guard(repo, AshConfig(), operator=False, rule_sets=["custom-set"])

        with caplog.at_level(logging.WARNING):
            assert scanner._operator_rule_sets() == [DEFAULT_RULE_SET]
        assert f"ASH's default rule set, {DEFAULT_RULE_SET}" in caplog.text

    def test_a_repository_default_over_a_default_base_is_used_without_a_warning(
        self, repo, caplog
    ):
        """The control: the value and the operator's choice agree."""
        scanner = _guard(
            repo, AshConfig(), operator=False, rule_sets=[DEFAULT_RULE_SET]
        )

        with caplog.at_level(logging.WARNING):
            assert scanner._operator_rule_sets() == [DEFAULT_RULE_SET]
        assert "Ignoring" not in caplog.text

    def test_the_operators_own_file_is_taken_as_written(self, repo):
        """The control: a config built from no file in the tree is the operator's."""
        scanner = _guard(repo, AshConfig(), operator=True, rule_sets=["custom-set"])

        assert scanner._operator_rule_sets() == ["custom-set"]


class TestCfnLintOptions:
    def test_a_repository_default_does_not_undo_the_operators_ignored_checks(
        self, repo, caplog
    ):
        trusted = _trusted(
            {"cfn-lint": {"options": {"ignore_checks": OPERATOR_IGNORED}}}
        )
        scanner = _lint(repo, trusted, operator=False, ignore_checks=[])

        with caplog.at_level(logging.WARNING):
            assert scanner._operator_option("ignore_checks") == OPERATOR_IGNORED
        assert "Ignoring scanners.cfn-lint.options.ignore_checks" in caplog.text
        assert "the operator's value" in caplog.text

    def test_a_repository_list_is_replaced_by_the_operators_list(self, repo):
        trusted = _trusted({"cfn-lint": {"options": {"regions": ["eu-west-1"]}}})
        scanner = _lint(repo, trusted, operator=False, regions=["us-east-1"])

        assert scanner._operator_option("regions") == ["eu-west-1"]

    def test_the_default_stands_when_the_operator_set_none(self, repo, caplog):
        """The control: the default is named, as before."""
        scanner = _lint(repo, AshConfig(), operator=False, ignore_checks=["W1"])

        with caplog.at_level(logging.WARNING):
            assert scanner._operator_option("ignore_checks") == []
        assert "cfn-lint uses the default, []" in caplog.text

    def test_a_repository_default_over_a_default_base_is_used_without_a_warning(
        self, repo, caplog
    ):
        scanner = _lint(repo, AshConfig(), operator=False, ignore_checks=[])

        with caplog.at_level(logging.WARNING):
            assert scanner._operator_option("ignore_checks") == []
        assert "Ignoring" not in caplog.text

    def test_the_returned_list_is_a_copy_of_the_operators(self, repo):
        trusted = _trusted(
            {"cfn-lint": {"options": {"ignore_checks": OPERATOR_IGNORED}}}
        )
        scanner = _lint(repo, trusted, operator=False, ignore_checks=[])

        first = scanner._operator_option("ignore_checks")
        first.append("W9999")

        assert scanner._operator_option("ignore_checks") == OPERATOR_IGNORED
