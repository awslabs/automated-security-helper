# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A profile can add runtime-override denials but never remove the ones trust depends on.

``runtime_overrides.denied_paths`` was a list default, so a profile that set its own list
(one entry is the natural way to customize it) replaced every shipped entry. An MCP
client could then set the detect-secrets verification filter (each candidate secret is
sent to its issuer), import a plugin from a file, switch off the scanner sandbox, or load
``ash_plugin_modules`` into ASH's own process. The client's override is then replayed as
the operator's own setting.

Those entries are now a floor: every ``RuntimeOverridesConfig`` gets them, whatever its
``denied_paths`` says, and a profile's own entries are denied as well. The reporters
that send results off the host (S3, Security Hub, CloudWatch Logs, the Bedrock
summary) are in the floor as whole sections, so a client can neither turn one on nor
choose where it sends.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml

from automated_security_helper.cli.mcp import workspace as workspace_module
from automated_security_helper.cli.mcp.profile_registry import (
    clear_profile_registry,
    clear_session_state,
    register_profiles,
    set_profile_registry,
)
from automated_security_helper.cli.mcp_tools import mcp_select_profile
from automated_security_helper.config.ash_config import RuntimeOverridesConfig
from automated_security_helper.config.runtime_patch import (
    RuntimePatchDeniedError,
    check_runtime_ops,
)

VERIFICATION_FILTER = (
    "detect_secrets.filters.common.is_ignored_due_to_verification_policies"
)

#: The floor, written out: the contract this test holds the code to.
FLOOR = [
    "/sandbox",
    "/sandbox/**",
    "/ash_plugin_modules",
    "/ash_plugin_modules/**",
    "/scanners/detect-secrets/options/scan_settings/filters_used",
    "/scanners/detect-secrets/options/scan_settings/filters_used/**",
    "/scanners/detect-secrets/options/scan_settings/plugins_used",
    "/scanners/detect-secrets/options/scan_settings/plugins_used/**",
    "/scanners/detect-secrets/options/baseline_file",
    "/converters/archive/options/max_members",
    "/converters/archive/options/max_member_bytes",
    "/converters/archive/options/max_total_bytes",
    "/converters/archive/options/max_compression_ratio",
    "/reporters/s3/**",
    "/reporters/aws-security-hub/**",
    "/reporters/cloudwatch-logs/**",
    "/reporters/bedrock-summary-reporter/**",
    "/scanners/detect-secrets/**",
    "/scanners/npm-audit/**",
    "/scanners/opengrep/**",
    "/scanners/semgrep/**",
    "/scanners/snyk-code/**",
    "/scanners/trivy-repo/**",
]

#: The reporters that send results off the host, each a whole section.
OFF_HOST_REPORTERS = [
    "s3",
    "aws-security-hub",
    "cloudwatch-logs",
    "bedrock-summary-reporter",
]

OPERATOR_ENTRY = "/scanners/*/options/extra_args"


def test_a_profile_list_keeps_every_floor_entry_and_its_own():
    policy = RuntimeOverridesConfig(enabled=True, denied_paths=[OPERATOR_ENTRY])

    missing = [entry for entry in FLOOR if entry not in policy.denied_paths]
    assert missing == [], f"a profile's own denied_paths dropped: {missing}"
    assert OPERATOR_ENTRY in policy.denied_paths


def test_an_empty_profile_list_keeps_the_floor():
    policy = RuntimeOverridesConfig(enabled=True, denied_paths=[])

    assert [entry for entry in FLOOR if entry not in policy.denied_paths] == []


def test_the_default_list_already_holds_the_floor_once():
    """Nothing is appended to a default policy, so its list is the shipped one."""
    policy = RuntimeOverridesConfig()

    for entry in FLOOR:
        assert policy.denied_paths.count(entry) == 1, entry


def test_a_floor_entry_the_profile_lists_is_not_repeated():
    policy = RuntimeOverridesConfig(denied_paths=["/sandbox", OPERATOR_ENTRY])

    assert policy.denied_paths.count("/sandbox") == 1


def test_the_floor_constant_is_the_contract():
    from automated_security_helper.config.ash_config import ALWAYS_DENIED_PATHS

    assert list(ALWAYS_DENIED_PATHS) == FLOOR


@pytest.mark.parametrize("reporter", OFF_HOST_REPORTERS)
def test_a_profile_that_drops_an_off_host_reporter_still_denies_it(reporter):
    """A client must not point an off-host reporter somewhere, or turn one on."""
    policy = RuntimeOverridesConfig(
        enabled=True, allowed_paths=["/reporters/**"], denied_paths=[OPERATOR_ENTRY]
    )

    for path, value in (
        (f"/reporters/{reporter}", {"enabled": True}),
        (f"/reporters/{reporter}/enabled", True),
        (f"/reporters/{reporter}/options/destination", "elsewhere"),
    ):
        with pytest.raises(RuntimePatchDeniedError):
            check_runtime_ops(
                [{"op": "add", "path": path, "value": value}], allowlist=policy
            )


def test_control_another_reporter_option_still_passes():
    policy = RuntimeOverridesConfig(
        enabled=True, allowed_paths=["/reporters/**"], denied_paths=[OPERATOR_ENTRY]
    )

    check_runtime_ops(
        [{"op": "add", "path": "/reporters/markdown/options/top_n", "value": 5}],
        allowlist=policy,
    )


# The two client paths, with a profile that sets its own denied_paths.


@pytest.fixture(autouse=True)
def _isolate_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    clear_profile_registry()
    clear_session_state()
    yield
    clear_profile_registry()
    clear_session_state()


def _profile(tmp_path: Path, allowed: List[str]) -> Path:
    document: Dict[str, Any] = {
        "project_name": "operator",
        "global_settings": {
            "mcp": {
                "runtime_overrides": {
                    "enabled": True,
                    "allowed_paths": allowed,
                    "denied_paths": [OPERATOR_ENTRY],
                }
            }
        },
    }
    path = tmp_path / "op.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    set_profile_registry(register_profiles([f"op={path}"]))
    return path


def test_select_profile_refuses_the_verification_filter(tmp_path):
    _profile(tmp_path, ["/scanners/**"])

    result = mcp_select_profile(
        "op",
        patch_ops=[
            {
                "op": "add",
                "path": "/scanners/detect_secrets/options/scan_settings/filters_used/-",
                "value": {"path": VERIFICATION_FILTER, "min_level": 2},
            }
        ],
        session_id="patch",
    )

    assert result["success"] is False, result
    assert "denied_paths entry" in result["error"], result["error"]


@pytest.mark.parametrize("reporter", OFF_HOST_REPORTERS)
def test_select_profile_refuses_an_off_host_reporter(tmp_path, reporter):
    _profile(tmp_path, ["/reporters/**"])

    result = mcp_select_profile(
        "op",
        patch_ops=[
            {
                "op": "add",
                "path": f"/reporters/{reporter}",
                "value": {"enabled": True, "options": {}},
            }
        ],
        session_id="patch",
    )

    assert result["success"] is False, result
    assert "denied_paths entry" in result["error"], result["error"]


def test_workspace_overrides_refuse_the_verification_filter(tmp_path):
    """The reviewer's case: accepted, then replayed as the operator's setting."""
    profile = _profile(tmp_path, ["/scanners/**"])
    override = "scanners.detect-secrets.options.scan_settings.filters_used=" + (
        json.dumps([{"path": VERIFICATION_FILTER, "min_level": 2}])
    )

    # The policy is the registered profile's, named here as a per-call profile;
    # the session config is the config the overrides apply to.
    with pytest.raises(RuntimePatchDeniedError, match="denied_paths"):
        workspace_module._gate_client_overrides([override], str(profile), profile="op")


def test_the_profile_s_own_entry_is_still_denied(tmp_path):
    profile = _profile(tmp_path, ["/scanners/**"])

    with pytest.raises(RuntimePatchDeniedError, match="denied_paths"):
        workspace_module._gate_client_overrides(
            ["scanners.bandit.options.extra_args=[]"], str(profile), profile="op"
        )


def test_control_an_allowed_option_still_passes(tmp_path):
    profile = _profile(tmp_path, ["/scanners/**"])

    workspace_module._gate_client_overrides(
        ["scanners.bandit.options.severity_threshold=HIGH"], str(profile), profile="op"
    )
