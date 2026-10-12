# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An MCP client cannot turn on detect-secrets verification through runtime overrides.

``select_profile``'s ``patch_ops`` and ``override_yaml``, and a workspace scan's
``config_overrides`` (``cli/mcp/workspace._gate_client_overrides``), are checked
against the profile's ``runtime_overrides`` allowlist and then applied as the
operator's own settings: the patched profile is materialized as the session's
config, and workspace overrides reach ``resolve_config`` as ``--config-overrides``.
So an operator who lets clients tune scanner options (``allowed_paths:
['/scanners/**']``) would also hand them secret verification, which sends each
candidate secret to its issuer, and the plugins and filters detect-secrets imports.
The shipped ``denied_paths`` deny those settings, as they deny the sandbox and
``ash_plugin_modules``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

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
from automated_security_helper.config.runtime_patch import RuntimePatchDeniedError

VERIFICATION_FILTER = (
    "detect_secrets.filters.common.is_ignored_due_to_verification_policies"
)


@pytest.fixture(autouse=True)
def _isolate_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    clear_profile_registry()
    clear_session_state()
    yield
    clear_profile_registry()
    clear_session_state()


def _profile_document() -> Dict[str, Any]:
    return {
        "project_name": "operator",
        "global_settings": {
            "mcp": {
                "runtime_overrides": {
                    "enabled": True,
                    "allowed_paths": ["/scanners/**"],
                }
            }
        },
    }


@pytest.fixture
def profile(tmp_path: Path) -> Path:
    path = tmp_path / "op.yaml"
    path.write_text(yaml.safe_dump(_profile_document()), encoding="utf-8")
    set_profile_registry(register_profiles([f"op={path}"]))
    return path


DENIED_PATCHES = {
    "verification filter": {
        "op": "add",
        "path": "/scanners/detect_secrets/options/scan_settings/filters_used/-",
        "value": {"path": VERIFICATION_FILTER, "min_level": 2},
    },
    "filter list": {
        "op": "replace",
        "path": "/scanners/detect_secrets/options/scan_settings/filters_used",
        "value": [{"path": VERIFICATION_FILTER, "min_level": 2}],
    },
    "plugin from a file": {
        "op": "add",
        "path": "/scanners/detect_secrets/options/scan_settings/plugins_used/-",
        "value": {"path": "file:///opt/any/module.py"},
    },
    "whole settings": {
        "op": "replace",
        "path": "/scanners/detect_secrets/options/scan_settings",
        "value": {"filters_used": [{"path": VERIFICATION_FILTER, "min_level": 2}]},
    },
    "baseline file": {
        "op": "replace",
        "path": "/scanners/detect_secrets/options/baseline_file",
        "value": "/srv/shared/verifying.baseline",
    },
}


@pytest.mark.parametrize("case", sorted(DENIED_PATCHES))
def test_select_profile_patch_cannot_set_detect_secrets_settings(profile, case):
    result = mcp_select_profile(
        "op", patch_ops=[DENIED_PATCHES[case]], session_id="patch"
    )

    assert result["success"] is False, result
    assert "denied_paths entry" in result["error"], result["error"]


def test_control_select_profile_patch_can_tune_another_scanner_option(profile):
    result = mcp_select_profile(
        "op",
        patch_ops=[
            {
                "op": "replace",
                "path": "/scanners/bandit/options/severity_threshold",
                "value": "HIGH",
            }
        ],
        session_id="patch",
    )

    assert result["success"] is True, result


DENIED_OVERRIDES = {
    "verification filter": (
        "scanners.detect-secrets.options.scan_settings.filters_used+="
        + json.dumps([{"path": VERIFICATION_FILTER, "min_level": 2}])
    ),
    "plugin from a file": (
        "scanners.detect-secrets.options.scan_settings.plugins_used+="
        + json.dumps([{"path": "file:///opt/any/module.py"}])
    ),
    "baseline file": (
        "scanners.detect-secrets.options.baseline_file=/srv/shared/verifying.baseline"
    ),
}


@pytest.mark.parametrize("case", sorted(DENIED_OVERRIDES))
def test_workspace_overrides_cannot_set_detect_secrets_settings(profile, case):
    # The policy is the registered profile's, named here as a per-call profile.
    with pytest.raises(RuntimePatchDeniedError, match="denied_paths"):
        workspace_module._gate_client_overrides(
            [DENIED_OVERRIDES[case]], str(profile), profile="op"
        )


def test_control_workspace_overrides_can_tune_another_scanner_option(profile):
    workspace_module._gate_client_overrides(
        ["scanners.bandit.options.severity_threshold=HIGH"], str(profile), profile="op"
    )
