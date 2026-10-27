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
        {"scanners": {"bandit": {"options": {"env": {"AWS_SECRET_ACCESS_KEY": "x"}}}}},  # nosec B105 - an env var name in a fixture, not a credential
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


@pytest.mark.parametrize("shipped", range(len(ccp.SHIPPED_DEFAULT_DENIED_PATHS)))
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


def _grep_scanners(enabled: bool) -> AshConfig:
    """A trusted config with opengrep and semgrep on or off, on any platform.

    ``AshConfig()`` has both on everywhere but Windows, where neither scanner
    runs: ``platform.system()`` picks the default when each config class is
    defined. A test that compares a file with ``AshConfig()`` reads one base on
    Windows and another elsewhere.
    """
    return AshConfig.model_validate(
        {"scanners": {name: {"enabled": enabled} for name in ("opengrep", "semgrep")}}
    )


def _denials_of_ashs_own_config(trusted: AshConfig) -> list:
    from automated_security_helper.config.config_sources import read_config_file

    own = Path(__file__).resolve().parents[3] / ".ash" / ".ash.yaml"
    policy = RuntimeOverridesConfig()
    return config_document_denials(
        read_config_file(own),
        allowlist=policy,
        config=trusted,
        exempt=ccp.exempt_paths(policy),
        inert=ccp.INERT_PATHS,
    )


def test_the_default_policy_accepts_ashs_own_repository_config() -> None:
    """ASH's own .ash/.ash.yaml writes defaults, plugin modules and suppressions.

    ``fail_on_findings: true`` is the default, plugin modules are left to
    plugin_module_trust, and a delivered repository's own suppressions and ignore
    paths are honored (decision point 1), so nothing in it is refused.

    The file turns opengrep and semgrep on, so the trusted config has them on.
    Both default to off on Windows, where the file's ``enabled: true`` is a change
    from the default and is refused, as
    ``test_ashs_own_config_is_refused_where_its_scanners_are_off`` pins.
    """
    assert _denials_of_ashs_own_config(_grep_scanners(True)) == []


def test_ashs_own_config_is_refused_where_its_scanners_are_off() -> None:
    """The refusal Windows meets, pinned where any platform can see it.

    With opengrep and semgrep off in the trusted config, as their defaults are on
    Windows, the file's two ``enabled: true`` writes are refused and nothing else
    in it is. The scanner sections stay under denied_paths, so a delivered file
    cannot turn on a scanner the trusted config leaves off.
    """
    denials = _denials_of_ashs_own_config(_grep_scanners(False))
    assert [denial.key for denial in denials] == [
        "scanners.opengrep.enabled",
        "scanners.semgrep.enabled",
    ]


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


# ---------------------------------------------------------------------------
# A delivered file's own ``patch`` and the restrict-only check
# ---------------------------------------------------------------------------

#: The trusted base of the cell below: sandbox mode ``auto``, one network
#: scanner, no extra read paths and no plugin modules.
_RESTRICT_ONLY_BASE = {"sandbox": {"mode": "auto", "network_scanners": ["bandit"]}}

#: What a delivered file may not ask for beyond that base, as (the fields written
#: out, the patch op that writes the same change, the start of the refusal text
#: that names it).
_WIDENINGS = (
    (
        {"sandbox": {"extra_read_paths": ["/etc"]}},
        {"op": "add", "path": "/sandbox/extra_read_paths", "value": ["/etc"]},
        "sandbox.extra_read_paths (lets scanners read /etc",
    ),
    (
        {"sandbox": {"network_scanners": ["checkov"]}},
        {"op": "add", "path": "/sandbox/network_scanners", "value": ["checkov"]},
        "sandbox.network_scanners (gives a network to checkov",
    ),
    (
        {"ash_plugin_modules": ["no_such_mod_9q"]},
        {"op": "add", "path": "/ash_plugin_modules", "value": ["no_such_mod_9q"]},
        "ash_plugin_modules (adds 'no_such_mod_9q'",
    ),
)


def test_a_patched_client_configs_widening_of_a_restrict_only_field_is_seen(
    tmp_path, monkeypatch
) -> None:
    """A delivered file's own ``patch`` does not hide a widening from the check.

    Route, nothing private called: ``apply_client_config_rules`` (what
    ``resolve_config`` and the MCP tools call for a file under the MCP workspace
    root) -> ``client_file_denials`` -> ``_with_own_patch`` -> ``_widenings``.
    ``_with_own_patch`` is reached only through ``client_file_denials``, so the
    cell drives the public route it feeds.
    ``test_denied_paths_edits.py::test_a_patch_op_asking_for_more_is_refused``
    pins the patch-op arm through ``client_file_denials(all_delivered=True)``;
    this cell adds the production classification (a path under the workspace
    root), the entry that refuses, and the arm with the fields written out.

    Prediction, read from the code and not run: RED. ``_with_own_patch`` returns
    what ``config_sources._apply_patch`` returns, a ``_Patched`` dataclass and
    not the document (its other caller reads ``patched.document``).
    ``_widenings`` then walks a non-dict: ``runtime_patch._walk`` answers
    ``(False, None)`` at its first segment, so ``sandbox`` and
    ``ash_plugin_modules`` read as absent. For a document with a non-empty
    ``patch`` the check finds nothing at all, so a field written out beside the
    patch is hidden too. No gate on this route catches it: the default
    ``denied_paths`` exempt both fields (``exempt_paths``), and the default
    ``denied_value_patterns`` is empty, so ``config_document_denials`` refuses
    nothing. Confinement after resolution (``sandbox_grants``,
    ``plugin_module_trust``) drops a widening where this check would refuse it,
    so it would not turn this cell green; it is not read here.

    Controls, through the same entry point, fail with a message that starts
    "CONTROL": a patch that sets only ``project_name`` is accepted, and each
    widening written out with no patch is refused by name. A failure that does
    not start so is the subject: ``missed`` lists the widenings no gate saw.
    """
    monkeypatch.setattr(ccp, "DENIED_FIELD_HANDLING", "refuse")
    client = _client_file(tmp_path, monkeypatch, "")
    rules = rules_from(AshConfig.model_validate(_RESTRICT_ONLY_BASE))
    only_a_name = {"op": "add", "path": "/project_name", "value": "delivered"}

    def refusal(document: dict) -> str:
        """What the entry point says to ``document``; "" when it accepts it."""
        try:
            apply_client_config_rules(
                AshConfig.model_validate(_RESTRICT_ONLY_BASE),
                {client: document},
                rules=rules,
                trusted_config_path=None,
                source_dir=None,
                permit_base=None,
                scanned_root=tmp_path,
            )
        except ASHConfigFieldDeniedError as exc:
            return str(exc)
        return ""

    assert refusal({"patch": [only_a_name]}) == "", (
        "CONTROL: a patch that sets only project_name was refused"
    )
    unseen = [
        phrase for written, _, phrase in _WIDENINGS if phrase not in refusal(written)
    ]
    assert unseen == [], (
        f"CONTROL: a widening written out with no patch was not refused: {unseen}"
    )

    missed = {
        "as a patch op": [
            phrase
            for _, op, phrase in _WIDENINGS
            if phrase not in refusal({"patch": [op]})
        ],
        "written out beside a patch that sets only project_name": [
            phrase
            for written, _, phrase in _WIDENINGS
            if phrase not in refusal({**written, "patch": [only_a_name]})
        ],
    }
    assert not any(missed.values()), (
        "a client-delivered config with a patch widened a restrict-only field and "
        f"apply_client_config_rules accepted it; missed: {missed}"
    )
