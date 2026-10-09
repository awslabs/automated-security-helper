# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What a client-delivered config document is checked for, and against which rules.

The MCP-level behavior is in tests/unit/cli/mcp/test_client_configs_honor_denied_paths.py.
These pin the pieces it is built from: ``runtime_patch.config_document_denials``
(which writes a document makes, and which of them the denials refuse) and
``client_config_policy.apply_client_config_rules`` (which files are checked,
whose rules apply, and what a denial does under each decision point).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config import client_config_policy as ccp
from automated_security_helper.config.ash_config import (
    AshConfig,
    RuntimeOverridesConfig,
)
from automated_security_helper.config.client_config_policy import (
    apply_client_config_rules,
    rules_from,
)
from automated_security_helper.config.runtime_patch import config_document_denials
from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError


def _denied_keys(document, *, base=None, exempt=(), **policy) -> list:
    allowlist = RuntimeOverridesConfig(**policy)
    return [
        denial.key
        for denial in config_document_denials(
            document, allowlist=allowlist, config=base, exempt=exempt
        )
    ]


# ---------------------------------------------------------------------------
# Which writes a document makes
# ---------------------------------------------------------------------------


def test_each_leaf_is_checked_and_named() -> None:
    document = {
        "project_name": "x",
        "reporters": {
            "csv": {"enabled": False},
            "bedrock-summary-reporter": {"options": {"aws_region": "r"}},
        },
    }
    assert _denied_keys(document) == [
        "reporters.bedrock-summary-reporter.options.aws_region"
    ]


def test_an_empty_section_sets_nothing() -> None:
    assert _denied_keys({"reporters": {"bedrock-summary-reporter": {}}}) == []


def test_the_denials_apply_whether_or_not_runtime_overrides_are_on() -> None:
    """A config file is not a runtime override: enabled and allowed_paths do not apply."""
    document = {"fail_on_findings": False, "project_name": "x"}
    assert _denied_keys(document, enabled=False, allowed_paths=[]) == [
        "fail_on_findings"
    ]
    assert _denied_keys(document, enabled=True, allowed_paths=["/**"]) == [
        "fail_on_findings"
    ]


def test_a_value_pattern_refuses_the_leaf_it_binds() -> None:
    keys = _denied_keys(
        {"project_name": "secret-x", "global_settings": {"severity_threshold": "LOW"}},
        denied_paths=[],
        denied_value_patterns={"/project_name": r"^secret-"},
    )
    assert keys == ["project_name"]


def test_a_value_pattern_sees_mapping_keys_as_in_a_patch_op() -> None:
    keys = _denied_keys(
        {"scanners": {"bandit": {"options": {"env": {"AWS_SECRET_ACCESS_KEY": "x"}}}}},
        denied_paths=[],
        denied_value_patterns={"/scanners/*/options/**": "^AWS_"},
    )
    assert keys == ["scanners.bandit.options.env.AWS_SECRET_ACCESS_KEY"]


def test_extends_is_not_a_field_and_patch_ops_are_writes() -> None:
    document = {
        "extends": "base.yaml",
        "patch": [
            {"op": "test", "path": "/fail_on_findings", "value": True},
            {"op": "move", "from": "/sandbox/mode", "path": "/project_name"},
            {"op": "add", "path": "/project_name", "value": "x"},
        ],
    }
    assert _denied_keys(document) == ["/sandbox/mode"]


# ---------------------------------------------------------------------------
# A value equal to the trusted config's, and the restrict-only exemptions
# ---------------------------------------------------------------------------


def test_a_leaf_equal_to_the_trusted_value_changes_nothing() -> None:
    base = AshConfig()
    assert _denied_keys({"fail_on_findings": True}, base=base) == []
    assert _denied_keys({"global_settings": {"suppressions": []}}, base=base) == []
    assert _denied_keys({"fail_on_findings": False}, base=base) == ["fail_on_findings"]


def test_a_pointer_the_trusted_config_lacks_counts_as_a_change() -> None:
    document = {"reporters": {"BedrockSummary": {"options": {"aws_region": "r"}}}}
    assert _denied_keys(document, base=AshConfig()) == [
        "reporters.BedrockSummary.options.aws_region"
    ]


def test_the_trusted_value_is_found_under_another_spelling() -> None:
    base = AshConfig.model_validate(
        {"reporters": {"bedrock-summary-reporter": {"options": {"aws_region": "r"}}}}
    )
    document = {"reporters": {"BedrockSummary": {"options": {"aws_region": "r"}}}}
    assert _denied_keys(document, base=base) == []


def test_a_patch_op_is_refused_even_when_it_writes_the_trusted_value() -> None:
    document = {
        "patch": [{"op": "replace", "path": "/fail_on_findings", "value": True}]
    }
    assert _denied_keys(document, base=AshConfig()) == ["/fail_on_findings"]


def test_restrict_only_paths_are_left_to_their_own_checks() -> None:
    document = {
        "sandbox": {"mode": "off", "network_scanners": []},
        "ash_plugin_modules": ["standin_module"],
    }
    assert _denied_keys(document, exempt=ccp.RESTRICT_ONLY_PATHS) == []
    default = ccp.exempt_paths(RuntimeOverridesConfig())
    assert default[: len(ccp.RESTRICT_ONLY_PATHS)] == ccp.RESTRICT_ONLY_PATHS


def test_the_current_default_is_a_shipped_default() -> None:
    """A new default denied_paths list has to be added to the shipped lists."""
    current = frozenset(RuntimeOverridesConfig().denied_paths)
    assert current in ccp.SHIPPED_DEFAULT_DENIED_PATHS


@pytest.mark.parametrize("shipped", range(7))
def test_a_written_out_shipped_default_still_counts_as_default(shipped: int) -> None:
    listed = sorted(ccp.SHIPPED_DEFAULT_DENIED_PATHS[shipped], reverse=True)
    policy = RuntimeOverridesConfig(denied_paths=listed)
    assert "denied_paths" in policy.model_fields_set
    assert ccp.policy_is_default(policy)
    assert ccp.exempt_paths(policy) != ()


def test_an_edited_list_is_the_operators_own() -> None:
    edited = [*RuntimeOverridesConfig().denied_paths, "/project_name"]
    policy = RuntimeOverridesConfig(denied_paths=edited)
    assert not ccp.policy_is_default(policy)
    assert ccp.exempt_paths(policy) == ()


def test_value_patterns_still_apply_on_exempt_paths() -> None:
    keys = _denied_keys(
        {"ash_plugin_modules": ["standin_trivy"]},
        exempt=ccp.RESTRICT_ONLY_PATHS,
        denied_paths=[],
        denied_value_patterns={"/ash_plugin_modules/**": "trivy"},
    )
    assert keys == ["ash_plugin_modules"]


def test_a_key_is_checked_only_against_patterns_covering_it() -> None:
    policy = {
        "denied_paths": [],
        "denied_value_patterns": {"/reporters/*/options/aws_region": "^(?!us-)"},
    }
    assert _denied_keys({"project_name": "plain"}, **policy) == []
    keys = _denied_keys(
        {"scanners": {"bandit": {"options": {"env": {"AWS_KEY": "x"}}}}},
        denied_paths=[],
        denied_value_patterns={"/scanners/bandit/options/env/**": "^AWS_"},
    )
    assert keys == ["scanners.bandit.options.env.AWS_KEY"]


def test_an_inert_section_is_not_checked() -> None:
    document = {"global_settings": {"mcp": {"runtime_overrides": {"enabled": True}}}}
    assert _denied_keys(document) == ["global_settings.mcp.runtime_overrides.enabled"]
    assert (
        config_document_denials(
            document, allowlist=RuntimeOverridesConfig(), inert=ccp.INERT_PATHS
        )
        == []
    )


def test_two_sections_reading_as_one_plugin_make_the_rules_unreadable(
    tmp_path, monkeypatch
) -> None:
    """Held, not raised: only a config with a client-delivered file is refused."""
    from automated_security_helper.core.exceptions import (
        ASHConfigPolicyUnreadableError,
    )

    profile = AshConfig.model_validate(
        {
            "reporters": {
                "bedrock-summary": {"options": {"aws_region": "eu-west-1"}},
                "bedrock-summary-reporter": {"options": {"aws_region": "us-east-1"}},
            }
        }
    )
    rules = rules_from(profile)
    assert rules.unreadable is not None and "same plugin" in rules.unreadable
    operator = tmp_path / "operator.yaml"
    assert _apply({operator: {"project_name": "o"}}, rules=rules).project_name == "o"
    client = _client_file(tmp_path, monkeypatch, "")
    with pytest.raises(ASHConfigPolicyUnreadableError, match="same plugin"):
        _apply({client: {"project_name": "c"}}, rules=rules)


def test_the_trusted_value_is_what_the_plugin_reads() -> None:
    """A respelled key compares against the section get_plugin_config returns."""
    base = AshConfig.model_validate(
        {"reporters": {"BedrockSummaryReporter": {"options": {"aws_region": "r"}}}}
    )
    document = {
        "reporters": {"bedrock-summary-reporter": {"options": {"aws_region": "r"}}}
    }
    assert _denied_keys(document, base=base) == []


def test_the_default_policy_accepts_an_ash_config_init_file(tmp_path) -> None:
    from automated_security_helper.cli.config import init
    from automated_security_helper.config.config_sources import read_config_file

    target = tmp_path / ".ash" / ".ash.yaml"
    init(config=str(target), color=False)
    policy = RuntimeOverridesConfig()
    denials = config_document_denials(
        read_config_file(target),
        allowlist=policy,
        config=AshConfig(),
        exempt=ccp.exempt_paths(policy),
        inert=ccp.INERT_PATHS,
    )
    assert denials == []


def test_the_default_policy_accepts_ashs_own_repository_config() -> None:
    """ASH's own .ash/.ash.yaml writes defaults, plugin modules and suppressions.

    ``fail_on_findings: true`` is the default, plugin modules are left to
    plugin_module_trust, and a delivered repository's own suppressions and ignore
    paths are honored (decision point 1), so nothing in it is refused.
    """
    from automated_security_helper.config.config_sources import read_config_file

    own = Path(__file__).resolve().parents[3] / ".ash" / ".ash.yaml"
    policy = RuntimeOverridesConfig()
    denials = config_document_denials(
        read_config_file(own),
        allowlist=policy,
        config=AshConfig(),
        exempt=ccp.exempt_paths(policy),
        inert=ccp.INERT_PATHS,
    )
    assert denials == []


# ---------------------------------------------------------------------------
# Which files are checked, against whose rules, and the two decision points
# ---------------------------------------------------------------------------


def _client_file(tmp_path: Path, monkeypatch, text: str) -> Path:
    root = tmp_path / "ash-mcp"
    path = root / "session-a" / "source" / "ash.yaml"
    path.parent.mkdir(parents=True)
    path.write_text(text, encoding="utf-8")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    return path


def _apply(documents, rules=None, trusted=None):
    return apply_client_config_rules(
        AshConfig.model_validate(
            {
                key: value
                for document in documents.values()
                for key, value in document.items()
            }
        ),
        documents,
        rules=rules,
        trusted_config_path=trusted,
        source_dir=None,
        permit_base=None,
    )


def test_only_files_a_client_delivered_are_checked(tmp_path, monkeypatch) -> None:
    client = _client_file(tmp_path, monkeypatch, "")
    operator = tmp_path / "operator" / "base.yaml"
    _apply({operator: {"fail_on_findings": False}, client: {"project_name": "c"}})
    with pytest.raises(ASHConfigFieldDeniedError, match="fail_on_findings"):
        _apply({operator: {"project_name": "o"}, client: {"fail_on_findings": False}})


def test_without_rules_the_trusted_configs_apply(tmp_path, monkeypatch) -> None:
    client = _client_file(tmp_path, monkeypatch, "")
    operator = tmp_path / "operator" / "profile.yaml"
    operator.parent.mkdir()
    operator.write_text(
        "global_settings:\n  mcp:\n    runtime_overrides:\n"
        '      denied_paths: ["/project_name"]\n',
        encoding="utf-8",
    )
    with pytest.raises(ASHConfigFieldDeniedError, match="project_name"):
        _apply({client: {"project_name": "c"}}, trusted=operator)
    # Rules passed in win over the trusted config's.
    _apply(
        {client: {"project_name": "c"}},
        rules=rules_from(
            AshConfig.model_validate(
                {
                    "global_settings": {
                        "mcp": {"runtime_overrides": {"denied_paths": []}}
                    }
                }
            )
        ),
        trusted=operator,
    )


_SUPPRESSION = {
    "global_settings": {"suppressions": [{"path": "app.py", "reason": "delivered"}]}
}


@pytest.mark.parametrize("honor", [False, True])
def test_decision_one_delivered_suppressions(
    tmp_path, monkeypatch, honor: bool
) -> None:
    """HONOR_DELIVERED_SUPPRESSIONS decides whether a delivered suppression applies."""
    monkeypatch.setattr(ccp, "HONOR_DELIVERED_SUPPRESSIONS", honor)
    client = _client_file(tmp_path, monkeypatch, "")
    if honor:
        config = _apply({client: _SUPPRESSION})
        [entry] = config.global_settings.suppressions
        assert entry.path == "app.py"
        assert entry.client_supplied is True
    else:
        with pytest.raises(ASHConfigFieldDeniedError, match="suppressions"):
            _apply({client: _SUPPRESSION})


def test_the_decision_taken_honors_and_marks_delivered_suppressions(
    tmp_path, monkeypatch
) -> None:
    assert ccp.HONOR_DELIVERED_SUPPRESSIONS is True
    client = _client_file(tmp_path, monkeypatch, "")
    document = {
        "global_settings": {
            **_SUPPRESSION["global_settings"],
            "ignore_paths": [{"path": "vendor/**", "reason": "delivered"}],
        }
    }
    config = _apply({client: document})
    assert [s.client_supplied for s in config.global_settings.suppressions] == [True]
    assert [i.client_supplied for i in config.global_settings.ignore_paths] == [True]


def test_an_operators_explicit_denial_of_suppressions_still_refuses(
    tmp_path, monkeypatch
) -> None:
    client = _client_file(tmp_path, monkeypatch, "")
    rules = rules_from(
        AshConfig.model_validate(
            {
                "global_settings": {
                    "mcp": {
                        "runtime_overrides": {
                            "denied_paths": ["/global_settings/suppressions"]
                        }
                    }
                }
            }
        )
    )
    with pytest.raises(ASHConfigFieldDeniedError, match="suppressions"):
        _apply({client: _SUPPRESSION}, rules=rules)


def test_an_operators_entry_is_not_marked(tmp_path) -> None:
    operator = tmp_path / "operator.yaml"
    config = apply_client_config_rules(
        AshConfig.model_validate(_SUPPRESSION),
        {operator: _SUPPRESSION},
        rules=None,
        trusted_config_path=None,
        source_dir=None,
        permit_base=None,
    )
    assert [s.client_supplied for s in config.global_settings.suppressions] == [False]


@pytest.mark.parametrize("handling", ["refuse", "drop"])
def test_decision_two_refuse_or_drop(tmp_path, monkeypatch, handling: str) -> None:
    """DENIED_FIELD_HANDLING decides between refusing and dropping with a warning."""
    monkeypatch.setattr(ccp, "DENIED_FIELD_HANDLING", handling)
    client = _client_file(tmp_path, monkeypatch, "")
    document = {
        "project_name": "c",
        "fail_on_findings": False,
        "reporters": {"BedrockSummary": {"options": {"aws_region": "r"}}},
    }
    if handling == "refuse":
        with pytest.raises(ASHConfigFieldDeniedError):
            _apply({client: document})
        return
    config = _apply({client: document})
    assert config.project_name == "c"
    assert config.fail_on_findings is True
    assert config.get_plugin_config("reporter", "bedrock-summary-reporter") in (
        None,
        {"options": {}},
    ) or "aws_region" not in (
        config.get_plugin_config("reporter", "bedrock-summary-reporter") or {}
    ).get("options", {})
    assert len(config._resolution_warnings) == 1
    warning = config._resolution_warnings[0]
    assert "fail_on_findings" in warning and "aws_region" in warning


def test_drop_still_refuses_a_denied_patch_op(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(ccp, "DENIED_FIELD_HANDLING", "drop")
    client = _client_file(tmp_path, monkeypatch, "")
    with pytest.raises(ASHConfigFieldDeniedError):
        apply_client_config_rules(
            AshConfig(),
            {
                client: {
                    "patch": [
                        {"op": "replace", "path": "/fail_on_findings", "value": False}
                    ]
                }
            },
            rules=None,
            trusted_config_path=None,
            source_dir=None,
            permit_base=None,
        )
