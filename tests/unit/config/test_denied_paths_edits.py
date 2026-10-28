# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What an operator's own ``denied_paths`` list does.

A list that is not one of ASH's defaults adds to the current defaults, so an
operator who denies one more field does not lift the others. With
``replace_default_denied_paths`` the list is used as written, and the default
entries it leaves out are named in a warning. Every entry, and every
``denied_value_patterns`` key, is a JSON pointer starting with ``/``: one that
is not would match nothing, so it is refused when the config is read.
"""

from __future__ import annotations

import logging
from typing import List

import pytest
from pydantic import ValidationError

from automated_security_helper.config import client_config_policy as ccp
from automated_security_helper.config.ash_config import (
    AshConfig,
    RuntimeOverridesConfig,
)
from automated_security_helper.utils.log import ASH_LOGGER


def _policy(**fields) -> RuntimeOverridesConfig:
    config = AshConfig.model_validate(
        {"global_settings": {"mcp": {"runtime_overrides": fields}}}
    )
    return ccp.policy_of(config)


@pytest.fixture
def ash_log():
    records: List[logging.LogRecord] = []

    class _Keep(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _Keep(level=logging.WARNING)
    ASH_LOGGER.addHandler(handler)
    ccp._WARNED_REPLACEMENTS.clear()
    try:
        yield records
    finally:
        ASH_LOGGER.removeHandler(handler)
        ccp._WARNED_REPLACEMENTS.clear()


@pytest.mark.parametrize(
    "field,value",
    [
        ("denied_paths", ["fail_on_findings"]),
        ("denied_paths", ["/project_name", "scanners/*/enabled"]),
        ("denied_value_patterns", {"global_settings/suppressions": ".*"}),
    ],
)
def test_an_entry_without_a_leading_slash_is_refused(field, value) -> None:
    with pytest.raises(ValidationError) as excinfo:
        RuntimeOverridesConfig(**{field: value})
    assert "start with '/'" in str(excinfo.value)


def test_an_edited_list_adds_to_the_defaults() -> None:
    policy = _policy(denied_paths=["/project_name"])

    assert "/project_name" in policy.denied_paths
    for entry in RuntimeOverridesConfig().denied_paths:
        assert entry in policy.denied_paths


def test_replace_uses_the_list_as_written_and_names_what_it_drops(ash_log) -> None:
    from automated_security_helper.config.ash_config import ALWAYS_DENIED_PATHS

    policy = _policy(denied_paths=["/project_name"], replace_default_denied_paths=True)

    # As written, and the entries ASH always denies, which no list removes.
    assert policy.denied_paths == ["/project_name", *ALWAYS_DENIED_PATHS]
    (warning,) = [
        r.getMessage() for r in ash_log if "replace_default" in r.getMessage()
    ]
    assert "/fail_on_findings" in warning
    assert "/sandbox," not in warning, "an always-denied entry is not dropped"
    ccp.policy_of(
        AshConfig.model_validate(
            {
                "global_settings": {
                    "mcp": {
                        "runtime_overrides": {
                            "denied_paths": ["/project_name"],
                            "replace_default_denied_paths": True,
                        }
                    }
                }
            }
        )
    )
    assert len([r for r in ash_log if "replace_default" in r.getMessage()]) == 1, (
        "warned once per list"
    )


def test_effective_policy_is_idempotent() -> None:
    policy = _policy(denied_paths=["/project_name"])
    assert ccp.effective_policy(policy) is policy
    # The merge itself: a list that already holds the defaults merges to itself.
    again = _policy(denied_paths=list(policy.denied_paths))
    assert again.denied_paths == policy.denied_paths


def test_a_short_list_keeps_the_restrict_only_and_suppression_rules() -> None:
    """Listing one other field leaves sandbox, modules and suppressions to their rules."""
    policy = _policy(denied_paths=["/project_name"])
    assert set(ccp.exempt_paths(policy)) == set(
        ccp.RESTRICT_ONLY_PATHS + ccp.SUPPRESSION_PATHS
    )


def test_listing_suppressions_decides_them_in_denied_paths() -> None:
    policy = _policy(denied_paths=["/global_settings/suppressions"])
    exempt = ccp.exempt_paths(policy)
    assert "/global_settings/suppressions" not in exempt
    assert "/global_settings/suppressions/**" not in exempt
    assert "/global_settings/ignore_paths" in exempt
    assert "/sandbox" in exempt


def test_an_entry_above_a_field_names_it_too() -> None:
    policy = _policy(denied_paths=["/global_settings/**"])
    exempt = ccp.exempt_paths(policy)
    assert not any(path.startswith("/global_settings/") for path in exempt)
    assert "/sandbox" in exempt


def test_a_written_out_default_list_plus_one_decides_every_entry() -> None:
    """``ash config init``'s list with an entry added names all four fields itself."""
    policy = _policy(
        denied_paths=[*RuntimeOverridesConfig().denied_paths, "/project_name"]
    )
    assert ccp.exempt_paths(policy) == ()


def test_an_entry_inside_a_field_decides_the_whole_field() -> None:
    """Listing ``/sandbox/mode`` takes the sandbox out of the restrict-only rule."""
    policy = _policy(denied_paths=["/sandbox/mode"])
    exempt = ccp.exempt_paths(policy)
    assert "/sandbox" not in exempt and "/sandbox/**" not in exempt
    assert "/ash_plugin_modules" in exempt


@pytest.mark.parametrize(
    "entry,field",
    [
        ("/global-settings/suppressions", "/global_settings/suppressions"),
        ("/global-settings", "/global_settings/suppressions"),
        ("/global_settings/ignore-paths", "/global_settings/ignore_paths"),
        ("/global_settings/*/**", "/global_settings/ignore_paths"),
        ("/*/**", "/global_settings/suppressions"),
        ("/*/mode", "/sandbox"),
        ("/**/mode", "/sandbox"),
        ("/ash-plugin-modules", "/ash_plugin_modules"),
    ],
)
def test_an_entry_names_a_field_in_every_spelling_the_matcher_reads(
    entry: str, field: str
) -> None:
    """``-`` for ``_`` and glob segments, as ``runtime_patch`` matches them."""
    exempt = ccp.exempt_paths(_policy(denied_paths=[entry]))
    assert field not in exempt and f"{field}/**" not in exempt


def test_a_lookalike_entry_does_not_name_a_field() -> None:
    exempt = ccp.exempt_paths(
        _policy(denied_paths=["/global_settings/suppressions_extra"])
    )
    assert "/global_settings/suppressions" in exempt


def _denials(document: dict, rules: ccp.ClientConfigRules, tmp_path) -> List[str]:
    found = ccp.client_file_denials(
        {tmp_path / "delivered.yaml": document},
        rules,
        scanned_root=tmp_path,
        all_delivered=True,
    )
    return [denial.key for _, denials in found for denial in denials]


def _refusals(document: dict, rules: ccp.ClientConfigRules, tmp_path) -> list:
    """(field, reason) for each refusal a delivered ``document`` draws."""
    found = ccp.client_file_denials(
        {tmp_path / "delivered.yaml": document},
        rules,
        scanned_root=tmp_path,
        all_delivered=True,
    )
    return [(denial.key, denial.reason) for _, denials in found for denial in denials]


#: The reason a delivered ``network_scanners`` list draws, for the scanners it names.
_NETWORK_REFUSAL = "gives a network to {}, which the server's sandbox settings do not"


@pytest.mark.parametrize(
    "sandbox,field",
    [
        ({"network_scanners": ["bandit", "checkov"]}, "sandbox.network_scanners"),
        ({"extra_read_paths": ["/etc"]}, "sandbox.extra_read_paths"),
        ({"mode": "off"}, "sandbox.mode"),
    ],
)
def test_replace_mode_with_one_sandbox_entry_still_refuses_widening(
    tmp_path, sandbox: dict, field: str
) -> None:
    """The operator's list covers only ``mode``; the restrict-only check covers the rest."""
    base = AshConfig.model_validate(
        {
            "sandbox": {"mode": "auto", "network_scanners": ["bandit"]},
            "global_settings": {
                "mcp": {
                    "runtime_overrides": {
                        "denied_paths": ["/fail_on_findings", "/sandbox/mode"],
                        "replace_default_denied_paths": True,
                    }
                }
            },
        }
    )
    assert field in _denials({"sandbox": sandbox}, ccp.rules_from(base), tmp_path)


def test_narrowing_the_network_scanners_to_one_that_has_a_network_is_accepted(
    tmp_path,
) -> None:
    """With ``network_scanners`` unset, semgrep's own declared need gives it one."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
        SemgrepScanner,
    )

    assert SemgrepScanner.sandbox_requirements.network
    rules = ccp.rules_from(AshConfig())
    assert rules.base.sandbox.network_scanners is None
    assert (
        _denials({"sandbox": {"network_scanners": ["semgrep"]}}, rules, tmp_path) == []
    )
    assert _denials(
        {"sandbox": {"network_scanners": ["semgrep", "no-such-scanner"]}},
        rules,
        tmp_path,
    ) == ["sandbox.network_scanners"]


@pytest.mark.parametrize(
    "listed,named",
    [
        (["cfn-guard"], "cfn-guard"),
        (["detect-secrets"], "detect-secrets"),
        (["semgrep", "cfn-guard"], "cfn-guard"),
        (["cfn-guard", "detect-secrets"], "cfn-guard, detect-secrets"),
    ],
)
def test_listing_a_scanner_whose_requirements_are_computed_per_instance_is_refused(
    tmp_path, listed: List[str], named: str
) -> None:
    """With ``network_scanners`` unset, naming such a scanner asks for more.

    cfn-guard and detect-secrets declare ``sandbox_requirements`` as a property,
    because the answer depends on the instance: the rules directory the
    environment names, the settings a baseline enables. Read from the class, a
    property is the property object and not a ``SandboxRequirements``. The check
    took whatever it read and asked it for ``network``, so the config was
    reported as one that could not be checked instead of being judged. Neither
    scanner is given a network by default (cfn-guard needs none; detect-secrets
    needs one only with a grant), so a list that names it is a widening and is
    refused like any other, naming only the scanners that widen.
    """
    rules = ccp.rules_from(AshConfig())
    assert rules.base.sandbox.network_scanners is None
    assert _refusals({"sandbox": {"network_scanners": listed}}, rules, tmp_path) == [
        ("sandbox.network_scanners", _NETWORK_REFUSAL.format(named))
    ]


def test_a_listed_scanner_whose_class_declares_a_network_without_a_grant_is_accepted(
    tmp_path,
) -> None:
    """Control: a class attribute is read as before, and grype's network is its own."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
        GrypeScanner,
    )

    declared = GrypeScanner.sandbox_requirements
    assert declared.network and not declared.network_requires_grant
    rules = ccp.rules_from(AshConfig())
    assert rules.base.sandbox.network_scanners is None
    assert (
        _refusals({"sandbox": {"network_scanners": ["grype"]}}, rules, tmp_path) == []
    )


def test_a_listed_scanner_whose_class_declares_no_network_is_refused(tmp_path) -> None:
    """Control: a class attribute with no network is still a widening when named."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_lint_scanner import (
        CfnLintScanner,
    )

    assert not CfnLintScanner.sandbox_requirements.network
    rules = ccp.rules_from(AshConfig())
    assert _refusals(
        {"sandbox": {"network_scanners": ["cfn-lint"]}}, rules, tmp_path
    ) == [("sandbox.network_scanners", _NETWORK_REFUSAL.format("cfn-lint"))]


@pytest.mark.parametrize(
    "trusted,refused",
    [(["cfn-guard"], False), (["bandit"], True)],
)
def test_an_operators_own_list_decides_without_reading_a_scanner_class(
    tmp_path, trusted: List[str], refused: bool
) -> None:
    """Control: with ``network_scanners`` set, membership in it is the whole answer."""
    base = AshConfig.model_validate(
        {"sandbox": {"mode": "auto", "network_scanners": trusted}}
    )
    expected = (
        [("sandbox.network_scanners", _NETWORK_REFUSAL.format("cfn-guard"))]
        if refused
        else []
    )
    assert (
        _refusals(
            {"sandbox": {"network_scanners": ["cfn-guard"]}},
            ccp.rules_from(base),
            tmp_path,
        )
        == expected
    )


@pytest.mark.parametrize("field", ["read_path_scanners", "env_scanners"])
def test_a_delivered_scanner_grant_list_is_held_to_the_trusted_one(
    tmp_path, field: str
) -> None:
    """``read_path_scanners`` and ``env_scanners`` grant access, as ``extra_read_paths`` does.

    Under a default ``denied_paths`` the whole ``sandbox`` section is exempt from
    it, so the restrict-only check is the only one that sees these two lists.
    """
    rules = ccp.rules_from(AshConfig())
    assert "/sandbox/**" in ccp.exempt_paths(rules.policy)
    assert getattr(rules.base.sandbox, field) == []
    assert _denials({"sandbox": {field: ["bandit"]}}, rules, tmp_path) == [
        f"sandbox.{field}"
    ]
    # Controls: nothing listed, and a list that asks for no more than the server's.
    assert _denials({"sandbox": {field: []}}, rules, tmp_path) == []
    granting = ccp.rules_from(
        AshConfig.model_validate({"sandbox": {field: ["bandit"]}})
    )
    assert _denials({"sandbox": {field: ["bandit"]}}, granting, tmp_path) == []
    assert _denials({"sandbox": {field: []}}, granting, tmp_path) == []
    found = ccp.client_file_denials(
        {tmp_path / "delivered.yaml": {"sandbox": {field: ["bandit", "checkov"]}}},
        granting,
        scanned_root=tmp_path,
        all_delivered=True,
    )
    assert [denial.key for _, denials in found for denial in denials] == [
        f"sandbox.{field}"
    ]
    reason = found[0][1][0].reason
    assert "checkov" in reason and "bandit" not in reason


@pytest.mark.parametrize("scanner", ["opengrep", "semgrep"])
def test_a_delivered_metrics_off_is_accepted_and_on_is_refused(
    tmp_path, scanner: str
) -> None:
    """``off`` only stops the tool sending usage data."""
    rules = ccp.rules_from(AshConfig())

    def setting(value: str) -> dict:
        return {"scanners": {scanner: {"options": {"metrics": value}}}}

    assert _denials(setting("off"), rules, tmp_path) == []
    assert _denials(setting("on"), rules, tmp_path) == [
        f"scanners.{scanner}.options.metrics"
    ]


@pytest.mark.parametrize(
    "op,field",
    [
        (
            {"op": "add", "path": "/sandbox/extra_read_paths", "value": ["/etc"]},
            "sandbox.extra_read_paths",
        ),
        (
            {"op": "add", "path": "/sandbox/network-scanners", "value": ["checkov"]},
            "sandbox.network_scanners",
        ),
        (
            {"op": "add", "path": "/sandbox/read_path_scanners", "value": ["checkov"]},
            "sandbox.read_path_scanners",
        ),
        (
            {"op": "add", "path": "/sandbox/env_scanners/-", "value": "checkov"},
            "sandbox.env_scanners",
        ),
        (
            {"op": "add", "path": "/ash_plugin_modules/-", "value": "no_such_mod_9q"},
            "ash_plugin_modules",
        ),
    ],
)
def test_a_patch_op_asking_for_more_is_refused(tmp_path, op: dict, field: str) -> None:
    """The restrict-only check reads the document with its own ``patch`` applied."""
    base = AshConfig.model_validate(
        {"sandbox": {"mode": "auto", "network_scanners": ["bandit"]}}
    )
    assert field in _denials({"patch": [op]}, ccp.rules_from(base), tmp_path)


def test_a_patch_op_that_narrows_is_accepted(tmp_path) -> None:
    base = AshConfig.model_validate(
        {"sandbox": {"mode": "auto", "network_scanners": ["bandit"]}}
    )
    narrowing = {
        "patch": [{"op": "replace", "path": "/sandbox/network_scanners", "value": []}]
    }
    assert _denials(narrowing, ccp.rules_from(base), tmp_path) == []


def test_a_written_out_default_list_missing_an_entry_names_it(ash_log) -> None:
    """Removing a default entry does not lift it, and the warning says so."""
    current = list(RuntimeOverridesConfig().denied_paths)
    policy = _policy(denied_paths=[e for e in current if e != "/fail_on_findings"])

    assert "/fail_on_findings" in policy.denied_paths
    (warning,) = [r.getMessage() for r in ash_log if "leaves out" in r.getMessage()]
    assert "/fail_on_findings" in warning
    assert "replace_default_denied_paths" in warning


def test_a_list_of_extra_entries_only_is_not_warned_about(ash_log) -> None:
    _policy(denied_paths=["/project_name"])
    assert not [r for r in ash_log if "leaves out" in r.getMessage()]


@pytest.mark.parametrize(
    "entry,field,other",
    [
        (
            "/global_settings/suppressions/0",
            "/global_settings/suppressions",
            "/global_settings/ignore_paths",
        ),
        (
            "/global_settings/ignore_paths/*/reason",
            "/global_settings/ignore_paths",
            "/global_settings/suppressions",
        ),
    ],
)
def test_an_entry_inside_a_list_field_decides_the_whole_field(
    entry: str, field: str, other: str
) -> None:
    """An entry naming one item, or a key of every item, takes the list field out."""
    exempt = ccp.exempt_paths(_policy(denied_paths=[entry]))
    assert field not in exempt and f"{field}/**" not in exempt
    assert other in exempt
    assert "/sandbox" in exempt
