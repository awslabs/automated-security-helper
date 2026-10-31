# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``select_profile(override_yaml=...)`` is held to the runtime-override rules.

``patch_ops`` and ``override_yaml`` are two ways for an MCP client to change the
config a profile binds, and both are checked against the profile's
``RuntimeOverridesConfig``. Every test here sends one change through both routes
and requires the same outcome.

The profiles allow ``/**`` and keep the shipped ``denied_paths`` wherever a test
is about one denied entry, and each override restates the profile apart from the
one change. A refusal therefore has to come from the entry under test: an
override that dropped the profile's ``mcp`` block would be refused for changing
the allowlist itself, and would pass these tests for the wrong reason. That is
also why the denial tests check the error names the entry, not just
``success: False``.
"""

from __future__ import annotations

from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Dict, List, Tuple, get_args

import pytest
import yaml

from automated_security_helper.cli.mcp.profile_registry import (
    clear_profile_registry,
    clear_all_session_state,
    get_session_state,
    register_profiles,
    resolve_session_config_path,
    set_profile_registry,
)
from automated_security_helper.cli.mcp_tools import mcp_select_profile
from automated_security_helper.config.reporter_trust import (
    REPORTER_DESTINATION_OPTIONS,
    REPORTER_ENABLED_DEFAULTS,
)
from automated_security_helper.config.ash_config import (
    RuntimeOverridesConfig,
    SandboxConfig,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _isolate_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    # Materialized session configs land under the allowed roots.
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    clear_profile_registry()
    clear_all_session_state()
    yield
    clear_profile_registry()
    clear_all_session_state()


def _profile(
    *,
    allowed_paths: List[str],
    denied_paths: List[str] | None = None,
    denied_value_patterns: Dict[str, str] | None = None,
    enabled: bool = True,
) -> Dict[str, Any]:
    """A profile document: sandboxed, failing on findings, overrides as given."""
    runtime_overrides: Dict[str, Any] = {
        "enabled": enabled,
        "allowed_paths": allowed_paths,
    }
    if denied_paths is not None:
        runtime_overrides["denied_paths"] = denied_paths
    if denied_value_patterns is not None:
        runtime_overrides["denied_value_patterns"] = denied_value_patterns
    return {
        "project_name": "operator",
        "fail_on_findings": True,
        "sandbox": {"mode": "bwrap"},
        "global_settings": {"mcp": {"runtime_overrides": runtime_overrides}},
    }


def _install(tmp_path: Path, document: Dict[str, Any], name: str = "op") -> None:
    path = tmp_path / f"{name}.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    set_profile_registry(register_profiles([f"{name}={path}"]))


def _restated(document: Dict[str, Any], **changes: Any) -> str:
    """The profile document as override YAML, with top-level keys replaced."""
    restated = dict(document)
    restated.update(changes)
    return yaml.safe_dump(restated)


def _assert_unbound(session_id: str) -> None:
    assert get_session_state(session_id) is None
    assert resolve_session_config_path(session_id) is None


def _both_routes(
    patch_op: Dict[str, Any], override_yaml: str
) -> tuple[Dict[str, Any], Dict[str, Any]]:
    patched = mcp_select_profile("op", patch_ops=[patch_op], session_id="patch")
    overridden = mcp_select_profile(
        "op", override_yaml=override_yaml, session_id="override"
    )
    return patched, overridden


# ---------------------------------------------------------------------------
# Every sandbox field
# ---------------------------------------------------------------------------

_SANDBOX_CASES = {
    "mode": (
        {"op": "replace", "path": "/sandbox/mode", "value": "off"},
        {"mode": "off"},
    ),
    "extra_read_paths": (
        {"op": "add", "path": "/sandbox/extra_read_paths/-", "value": "/"},
        {"mode": "bwrap", "extra_read_paths": ["/"]},
    ),
    "network_scanners": (
        {"op": "replace", "path": "/sandbox/network_scanners", "value": ["checkov"]},
        {"mode": "bwrap", "network_scanners": ["checkov"]},
    ),
    "read_path_scanners": (
        {"op": "add", "path": "/sandbox/read_path_scanners/-", "value": "zizmor"},
        {"mode": "bwrap", "read_path_scanners": ["zizmor"]},
    ),
    "env_scanners": (
        {"op": "add", "path": "/sandbox/env_scanners/-", "value": "zizmor"},
        {"mode": "bwrap", "env_scanners": ["zizmor"]},
    ),
    "environment": (
        {"op": "add", "path": "/sandbox/environment/-", "value": "EXTRA_VAR=1"},
        {"mode": "bwrap", "environment": ["EXTRA_VAR=1"]},
    ),
}


@pytest.mark.parametrize("field", sorted(_SANDBOX_CASES))
def test_override_yaml_cannot_change_the_sandbox(tmp_path: Path, field: str) -> None:
    document = _profile(allowed_paths=["/**"])
    _install(tmp_path, document)
    patch_op, sandbox = _SANDBOX_CASES[field]

    patched, overridden = _both_routes(patch_op, _restated(document, sandbox=sandbox))

    assert patched["success"] is False
    assert overridden["success"] is False, overridden
    for result in (patched, overridden):
        assert "denied_paths entry '/sandbox'" in result["error"], result["error"]
    assert overridden["error"].startswith("override denied: ")
    assert f"/sandbox/{field}" in overridden["error"]
    _assert_unbound("patch")
    _assert_unbound("override")


def test_every_sandbox_field_has_a_case() -> None:
    """A sandbox field added later without a case here would go untested."""
    assert sorted(_SANDBOX_CASES) == sorted(SandboxConfig.model_fields)


@pytest.mark.parametrize(
    "mode",
    sorted(
        m
        for m in get_args(SandboxConfig.model_fields["mode"].annotation)
        if m != "bwrap"
    ),
)
def test_override_yaml_cannot_move_the_sandbox_to_any_other_mode(
    tmp_path: Path, mode: str
) -> None:
    """'off' and every other backend: the profile's mode is the only one bound."""
    document = _profile(allowed_paths=["/**"])
    _install(tmp_path, document)

    patched, overridden = _both_routes(
        {"op": "replace", "path": "/sandbox/mode", "value": mode},
        _restated(document, sandbox={"mode": mode}),
    )

    for result in (patched, overridden):
        assert result["success"] is False, result
        assert "denied_paths entry '/sandbox'" in result["error"], result["error"]
    _assert_unbound("patch")
    _assert_unbound("override")


def test_override_yaml_cannot_replace_the_whole_sandbox_section(
    tmp_path: Path,
) -> None:
    """Every sandbox field changed at once, the way a client would rewrite it."""
    document = _profile(allowed_paths=["/**"])
    _install(tmp_path, document)
    section = {
        "mode": "off",
        "network_scanners": ["checkov", "grype"],
        "extra_read_paths": ["/"],
    }

    patched, overridden = _both_routes(
        {"op": "replace", "path": "/sandbox", "value": section},
        _restated(document, sandbox=section),
    )

    for result in (patched, overridden):
        assert result["success"] is False, result
        assert "denied_paths entry '/sandbox'" in result["error"], result["error"]
    _assert_unbound("patch")
    _assert_unbound("override")


def test_override_yaml_that_omits_the_sandbox_cannot_turn_it_off(
    tmp_path: Path,
) -> None:
    """override_yaml replaces the profile, so leaving a block out resets it.

    The sandbox default is 'off', so an override of a bwrap profile that never
    mentions the sandbox is a change to /sandbox/mode, and is checked as one.
    """
    document = _profile(allowed_paths=["/**"])
    _install(tmp_path, document)
    without_sandbox = {k: v for k, v in document.items() if k != "sandbox"}

    result = mcp_select_profile(
        "op", override_yaml=yaml.safe_dump(without_sandbox), session_id="override"
    )

    assert result["success"] is False
    assert "/sandbox/mode" in result["error"]
    assert "denied_paths entry '/sandbox'" in result["error"]
    _assert_unbound("override")


def test_sandbox_override_on_a_profile_without_runtime_overrides(
    tmp_path: Path,
) -> None:
    """A bwrap profile that never enabled runtime overrides, so nothing is allowed."""
    path = tmp_path / "prof.yaml"
    path.write_text("project_name: operator\nsandbox:\n  mode: bwrap\n")
    set_profile_registry(register_profiles([f"op={path}"]))

    patched = mcp_select_profile(
        "op",
        patch_ops=[{"op": "replace", "path": "/sandbox/mode", "value": "off"}],
        session_id="s1",
    )
    overridden = mcp_select_profile(
        "op",
        override_yaml="project_name: x\nsandbox:\n  mode: 'off'\n  extra_read_paths: ['/']\n",
        session_id="s2",
    )

    assert patched["success"] is False
    assert overridden["success"] is False
    _assert_unbound("s1")
    _assert_unbound("s2")


# ---------------------------------------------------------------------------
# Every shipped denied_paths entry
# ---------------------------------------------------------------------------

_SUPPRESS_ALL = {"path": "**", "reason": "silence everything"}

# Keyed by the shipped denied_paths entry each case is refused under. The value
# is the patch op and the top-level keys the override changes.

_VERIFICATION_FILTER = {
    "path": "detect_secrets.filters.common.is_ignored_due_to_verification_policies",
    "min_level": 2,
}
_PLUGIN_FROM_A_FILE = {"path": "file:///opt/any/module.py"}

_DENIED_CASES: Dict[str, tuple[Dict[str, Any], Dict[str, Any]]] = {
    "/fail_on_findings": (
        {"op": "replace", "path": "/fail_on_findings", "value": False},
        {"fail_on_findings": False},
    ),
    "/fail_on_incomplete_scanners": (
        {"op": "replace", "path": "/fail_on_incomplete_scanners", "value": False},
        {"fail_on_incomplete_scanners": False},
    ),
    "/content_db_staleness": (
        {"op": "replace", "path": "/content_db_staleness", "value": "warn"},
        {"content_db_staleness": "warn"},
    ),
    "/honor_ignore_files": (
        {"op": "replace", "path": "/honor_ignore_files", "value": False},
        {"honor_ignore_files": False},
    ),
    "/content_db_staleness_overrides": (
        {
            "op": "add",
            "path": "/content_db_staleness_overrides/-",
            "value": {
                "database": "grype-db",
                "policy": "warn",
                "expiration": "2099-01-01",
                "reason": "stale on purpose",
            },
        },
        {
            "content_db_staleness_overrides": [
                {
                    "database": "grype-db",
                    "policy": "warn",
                    "expiration": "2099-01-01",
                    "reason": "stale on purpose",
                }
            ]
        },
    ),
    # Any write is refused. The one that matters is true over an operator's false,
    # which would relax trivy-db in an offline image; false differs from the
    # profile's default, so the gate sees a change on both routes.
    "/content_db_staleness_offline_image_default": (
        {
            "op": "replace",
            "path": "/content_db_staleness_offline_image_default",
            "value": False,
        },
        {"content_db_staleness_offline_image_default": False},
    ),
    "/sandbox": (
        {"op": "replace", "path": "/sandbox", "value": {"mode": "off"}},
        {"sandbox": {"mode": "off"}},
    ),
    "/sandbox/**": (
        {"op": "add", "path": "/sandbox/extra_read_paths/-", "value": "/"},
        {"sandbox": {"mode": "bwrap", "extra_read_paths": ["/"]}},
    ),
    "/ash_plugin_modules": (
        {"op": "replace", "path": "/ash_plugin_modules", "value": ["standin_module"]},
        {"ash_plugin_modules": ["standin_module"]},
    ),
    "/ash_plugin_modules/**": (
        {"op": "add", "path": "/ash_plugin_modules/-", "value": "standin_module"},
        {"ash_plugin_modules": ["standin_module"]},
    ),
    "/global_settings/ignore_paths": (
        {
            "op": "add",
            "path": "/global_settings/ignore_paths/-",
            "value": _SUPPRESS_ALL,
        },
        {"ignore_paths": [_SUPPRESS_ALL]},
    ),
    "/global_settings/suppressions": (
        {
            "op": "add",
            "path": "/global_settings/suppressions/-",
            "value": _SUPPRESS_ALL,
        },
        {"suppressions": [_SUPPRESS_ALL]},
    ),
    "/global_settings/mcp": (
        {
            "op": "replace",
            "path": "/global_settings/mcp/runtime_overrides/denied_paths",
            "value": [],
        },
        {"global_settings": {"mcp": {"runtime_overrides": {"denied_paths": []}}}},
    ),
    "/global_settings/mcp/**": (
        {
            "op": "add",
            "path": "/global_settings/mcp/runtime_overrides/allowed_paths/-",
            "value": "/fail_on_findings",
        },
        {
            "global_settings": {
                "mcp": {
                    "runtime_overrides": {"allowed_paths": ["/**", "/fail_on_findings"]}
                }
            }
        },
    ),
    "/scanners/opengrep/options/exclude_rule": (
        {
            "op": "replace",
            "path": "/scanners/opengrep/options/exclude_rule",
            "value": ["some.rule.id"],
        },
        {"scanners": {"opengrep": {"options": {"exclude_rule": ["some.rule.id"]}}}},
    ),
    "/scanners/semgrep/options/exclude_rule": (
        {
            "op": "replace",
            "path": "/scanners/semgrep/options/exclude_rule",
            "value": ["some.rule.id"],
        },
        {"scanners": {"semgrep": {"options": {"exclude_rule": ["some.rule.id"]}}}},
    ),
    "/reporters/bedrock-summary-reporter/options/aws_*": (
        {
            "op": "add",
            "path": "/reporters/bedrock-summary-reporter",
            "value": {"enabled": True, "options": {"aws_region": "other-region-1"}},
        },
        {
            "reporters": {
                "bedrock-summary-reporter": {
                    "enabled": True,
                    "options": {"aws_region": "other-region-1"},
                }
            }
        },
    ),
    "/reporters/cloudwatch-logs/**": (
        {
            "op": "add",
            "path": "/reporters/cloudwatch-logs",
            "value": {
                "enabled": True,
                "options": {"log_group_name": "other-log-group"},
            },
        },
        {
            "reporters": {
                "cloudwatch-logs": {
                    "enabled": True,
                    "options": {"log_group_name": "other-log-group"},
                }
            }
        },
    ),
    "/reporters/aws-security-hub/**": (
        {
            "op": "add",
            "path": "/reporters/aws-security-hub",
            "value": {"enabled": True, "options": {}},
        },
        {"reporters": {"aws-security-hub": {"enabled": True, "options": {}}}},
    ),
    "/reporters/s3/**": (
        {
            "op": "add",
            "path": "/reporters/s3",
            "value": {"enabled": True, "options": {"bucket_name": "other-bucket"}},
        },
        {
            "reporters": {
                "s3": {"enabled": True, "options": {"bucket_name": "other-bucket"}}
            }
        },
    ),
    # Adding the section also writes its aws_* options, so the aws_* entry, listed
    # first, is the one named; test_a_client_cannot_turn_on_an_off_host_reporter
    # covers a write only the whole-section entry refuses.
    "/reporters/bedrock-summary-reporter/**": (
        {
            "op": "add",
            "path": "/reporters/bedrock-summary-reporter",
            "value": {"enabled": True, "options": {"model_id": "other-model"}},
        },
        {
            "reporters": {
                "bedrock-summary-reporter": {
                    "enabled": True,
                    "options": {"model_id": "other-model"},
                }
            }
        },
    ),
    # The scanners that send data off the host, each refused whole: an option the
    # narrower detect-secrets entries leave open, metrics turned on, a scanner
    # turned off, and an add-on scanner's section added.
    "/scanners/detect-secrets/**": (
        {
            "op": "replace",
            "path": "/scanners/detect_secrets/options/skip_generated_lockfiles",
            "value": False,
        },
        {
            "scanners": {
                "detect-secrets": {"options": {"skip_generated_lockfiles": False}}
            }
        },
    ),
    "/scanners/npm-audit/**": (
        {"op": "replace", "path": "/scanners/npm_audit/enabled", "value": False},
        {"scanners": {"npm-audit": {"enabled": False}}},
    ),
    "/scanners/opengrep/**": (
        {"op": "replace", "path": "/scanners/opengrep/options/metrics", "value": "on"},
        {"scanners": {"opengrep": {"options": {"metrics": "on"}}}},
    ),
    "/scanners/semgrep/**": (
        {"op": "replace", "path": "/scanners/semgrep/options/metrics", "value": "on"},
        {"scanners": {"semgrep": {"options": {"metrics": "on"}}}},
    ),
    "/scanners/snyk-code/**": (
        {
            "op": "add",
            "path": "/scanners/snyk-code",
            "value": {"enabled": True, "options": {}},
        },
        {"scanners": {"snyk-code": {"enabled": True, "options": {}}}},
    ),
    "/scanners/trivy-repo/**": (
        {
            "op": "add",
            "path": "/scanners/trivy-repo",
            "value": {"enabled": True, "options": {"disable_telemetry": False}},
        },
        {
            "scanners": {
                "trivy-repo": {"enabled": True, "options": {"disable_telemetry": False}}
            }
        },
    ),
    "/scanners/trivy/**": (
        {
            "op": "replace",
            "path": "/scanners/trivy/options/disable_telemetry",
            "value": False,
        },
        {"scanners": {"trivy": {"options": {"disable_telemetry": False}}}},
    ),
    "/scanners/zizmor/**": (
        {
            "op": "replace",
            "path": "/scanners/zizmor/options/online_audits",
            "value": True,
        },
        {"scanners": {"zizmor": {"options": {"online_audits": True}}}},
    ),
    "/scanners/detect-secrets/options/scan_settings/filters_used": (
        {
            "op": "replace",
            "path": "/scanners/detect_secrets/options/scan_settings/filters_used",
            "value": [_VERIFICATION_FILTER],
        },
        {
            "scanners": {
                "detect-secrets": {
                    "options": {
                        "scan_settings": {"filters_used": [_VERIFICATION_FILTER]}
                    }
                }
            }
        },
    ),
    "/scanners/detect-secrets/options/scan_settings/filters_used/**": (
        {
            "op": "add",
            "path": "/scanners/detect_secrets/options/scan_settings/filters_used/-",
            "value": _VERIFICATION_FILTER,
        },
        {
            "scanners": {
                "detect-secrets": {
                    "options": {
                        "scan_settings": {"filters_used": [_VERIFICATION_FILTER]}
                    }
                }
            }
        },
    ),
    "/scanners/detect-secrets/options/scan_settings/plugins_used": (
        {
            "op": "replace",
            "path": "/scanners/detect_secrets/options/scan_settings/plugins_used",
            "value": [_PLUGIN_FROM_A_FILE],
        },
        {
            "scanners": {
                "detect-secrets": {
                    "options": {
                        "scan_settings": {"plugins_used": [_PLUGIN_FROM_A_FILE]}
                    }
                }
            }
        },
    ),
    "/scanners/detect-secrets/options/scan_settings/plugins_used/**": (
        {
            "op": "add",
            "path": "/scanners/detect_secrets/options/scan_settings/plugins_used/-",
            "value": _PLUGIN_FROM_A_FILE,
        },
        {
            "scanners": {
                "detect-secrets": {
                    "options": {
                        "scan_settings": {"plugins_used": [_PLUGIN_FROM_A_FILE]}
                    }
                }
            }
        },
    ),
    "/scanners/detect-secrets/options/baseline_file": (
        {
            "op": "replace",
            "path": "/scanners/detect_secrets/options/baseline_file",
            "value": "/srv/shared/verifying.baseline",
        },
        {
            "scanners": {
                "detect-secrets": {
                    "options": {"baseline_file": "/srv/shared/verifying.baseline"}
                }
            }
        },
    ),
    **{
        f"/converters/archive/options/{limit}": (
            {
                "op": "replace",
                "path": f"/converters/archive/options/{limit}",
                "value": 10**15,
            },
            {"converters": {"archive": {"options": {limit: 10**15}}}},
        )
        for limit in (
            "max_members",
            "max_member_bytes",
            "max_total_bytes",
            "max_compression_ratio",
        )
    },
}


#: Scanner options that drop findings by category, each with a value other than
#: its default. Each is a case like those above, written at the option itself.
_CATEGORY_DENIALS: Dict[str, Any] = {
    "/scanners/bandit/options/confidence_level": "high",
    "/scanners/checkov/options/frameworks": ["terraform"],
    "/scanners/checkov/options/skip_frameworks": ["terraform"],
    "/scanners/opengrep/options/config": "p/default",
    "/scanners/opengrep/options/patterns": ["$X == $X"],
    "/scanners/opengrep/options/severity": ["ERROR"],
    "/scanners/semgrep/options/config": "p/default",
    "/scanners/semgrep/options/severity": ["ERROR"],
    "/scanners/detect-secrets/options/scan_settings": {
        "plugins_used": [{"name": "AWSKeyDetector"}]
    },
    "/scanners/cdk-nag/options/nag_packs/AwsSolutionsChecks": False,
    "/scanners/ferret-scan/options/checks": "CREDIT_CARD",
    "/scanners/ferret-scan/options/confidence_levels": "high",
    "/scanners/ferret-scan/options/disable_ip_types": "private",
    "/scanners/ferret-scan/options/enable_preprocessors": False,
    "/scanners/ferret-scan/options/finding_limit": 5,
    "/scanners/ferret-scan/options/profile": "quick",
    "/scanners/ferret-scan/options/recursive": False,
    "/scanners/ferret-scan/options/respect_gitignore": True,
    "/scanners/ferret-scan/options/use_default_config": False,
    "/scanners/ferret-scan/options/validator_budget": "all=1ms",
    "/scanners/trivy-repo/options/license_full": False,
    "/scanners/trivy-repo/options/scanners": ["vuln"],
    "/scanners/cfn-guard/options/rule_sets": [],
    "/scanners/cfn-lint/options/ignore_checks": ["W2001"],
    "/scanners/cfn-lint/options/regions": ["eu-west-1"],
    "/scanners/gitleaks/options/baseline_path": "gitleaks-baseline.json",
    "/scanners/trivy/options/scanners": ["license"],
    "/scanners/trivy/options/ignore_unfixed": True,
    "/scanners/ferret-scan/options/max_live_bytes": "1KB",
    "/scanners/gitleaks/options/max_target_megabytes": 1,
}
#: Entries with the pointer each case writes and a value other than the
#: default: a scanner's own config file, the programs it runs, whether it honors
#: the ignore comments in the files it scans, which version of a tool runs, and
#: offline. A glob entry is written at one scanner it covers.
_POINTED_DENIALS: Dict[str, Tuple[str, Any]] = {
    "/scanners/*/options/offline": (
        "/scanners/npm-audit/options/offline",
        True,
    ),
    "/scanners/bandit/options/config_file": (
        "/scanners/bandit/options/config_file",
        "/etc/other.ini",
    ),
    "/scanners/checkov/options/config_file": (
        "/scanners/checkov/options/config_file",
        "/etc/other.yaml",
    ),
    "/scanners/ferret-scan/options/config_file": (
        "/scanners/ferret-scan/options/config_file",
        "/etc/other.yaml",
    ),
    "/scanners/grype/options/config_file": (
        "/scanners/grype/options/config_file",
        "/etc/other.yaml",
    ),
    "/scanners/syft/options/config_file": (
        "/scanners/syft/options/config_file",
        "/etc/other.yaml",
    ),
    "/scanners/trivy-repo/options/secret_config_file": (
        "/scanners/trivy-repo/options/secret_config_file",
        "/etc/other.yaml",
    ),
    "/scanners/snyk-code/options/honor_tree_exclusions": (
        "/scanners/snyk-code/options/honor_tree_exclusions",
        True,
    ),
    "/scanners/cfn-lint/options/honor_inline_ignores": (
        "/scanners/cfn-lint/options/honor_inline_ignores",
        True,
    ),
    "/scanners/gitleaks/options/honor_inline_ignores": (
        "/scanners/gitleaks/options/honor_inline_ignores",
        True,
    ),
    "/scanners/zizmor/options/honor_inline_ignores": (
        "/scanners/zizmor/options/honor_inline_ignores",
        True,
    ),
    "/scanners/trivy-repo/options/config_file": (
        "/scanners/trivy-repo/options/config_file",
        "/etc/other.yaml",
    ),
    "/scanners/trivy-repo/options/module_dir": (
        "/scanners/trivy-repo/options/module_dir",
        "/etc/other-modules",
    ),
    "/scanners/trivy/options/config_file": (
        "/scanners/trivy/options/config_file",
        "/etc/other.yaml",
    ),
    "/scanners/trivy/options/secret_config_file": (
        "/scanners/trivy/options/secret_config_file",
        "/etc/other.yaml",
    ),
    "/scanners/actionlint/options/config_file": (
        "/scanners/actionlint/options/config_file",
        "/etc/other.yaml",
    ),
    "/scanners/actionlint/options/shellcheck": (
        "/scanners/actionlint/options/shellcheck",
        "/opt/other/shellcheck",
    ),
    "/scanners/actionlint/options/pyflakes": (
        "/scanners/actionlint/options/pyflakes",
        "/opt/other/pyflakes",
    ),
    "/scanners/cfn-guard/options/rules_paths": (
        "/scanners/cfn-guard/options/rules_paths",
        ["/etc/other.guard"],
    ),
    "/scanners/cfn-lint/options/config_file": (
        "/scanners/cfn-lint/options/config_file",
        "/etc/other.yaml",
    ),
    "/scanners/gitleaks/options/config_file": (
        "/scanners/gitleaks/options/config_file",
        "/etc/other.toml",
    ),
    "/scanners/zizmor/options/config_file": (
        "/scanners/zizmor/options/config_file",
        "/etc/other.yml",
    ),
    "/scanners/zizmor/options/online_audits": (
        "/scanners/zizmor/options/online_audits",
        True,
    ),
    "/scanners/*/options/tool_version": (
        "/scanners/checkov/options/tool_version",
        "==1.0.0",
    ),
    "/converters/jupyter/options/tool_version": (
        "/converters/jupyter/options/tool_version",
        "==1.0.0",
    ),
    "/scanners/opengrep/options/version": (
        "/scanners/opengrep/options/version",
        "v0.0.1",
    ),
    "/scanners/opengrep/options/sha256": (
        "/scanners/opengrep/options/sha256",
        {"linux/amd64": "0" * 64},
    ),
    "/reporters/gitlab-sast/options/exclude_suppressed": (
        "/reporters/gitlab-sast/options/exclude_suppressed",
        True,
    ),
    "/scanners/opengrep/options/metrics": (
        "/scanners/opengrep/options/metrics",
        "on",
    ),
    "/scanners/semgrep/options/metrics": (
        "/scanners/semgrep/options/metrics",
        "on",
    ),
}

#: The operator-only options of the AWS reporters that are default entries of
#: their own (config/reporter_trust.py), which the profile does not configure,
#: so each case adds the reporter's section. Derived from the table, so an
#: option added there and to the default list gets a case here.
_REPORTER_DENIALS: Dict[str, Any] = {
    pointer: "other-value"
    for reporter, names in REPORTER_DESTINATION_OPTIONS.items()
    for name in names
    if (pointer := f"/reporters/{reporter}/options/{name}")
    in RuntimeOverridesConfig().denied_paths
}
# Each off-host reporter's whole-section entry (CloudWatch Logs' has a case of
# its own above) and any enabled entry of its own.
_REPORTER_DENIALS.update(
    {
        entry: True
        for reporter in REPORTER_ENABLED_DEFAULTS
        for entry in (f"/reporters/{reporter}/**", f"/reporters/{reporter}/enabled")
        if entry in RuntimeOverridesConfig().denied_paths and entry not in _DENIED_CASES
    }
)


def _nested_at(pointer: str, value: Any) -> Dict[str, Any]:
    nested: Any = value
    for segment in reversed(pointer.split("/")[1:]):
        nested = {segment: nested}
    return nested


for _pointer, _value in _CATEGORY_DENIALS.items():
    _DENIED_CASES[_pointer] = (
        {"op": "add", "path": _pointer, "value": _value},
        _nested_at(_pointer, _value),
    )
for _entry, (_pointer, _value) in _POINTED_DENIALS.items():
    _DENIED_CASES[_entry] = (
        {"op": "add", "path": _pointer, "value": _value},
        _nested_at(_pointer, _value),
    )
for _pointer, _value in _REPORTER_DENIALS.items():
    _reporter, _option = _pointer.split("/")[2], _pointer.split("/")[-1]
    if _option == "enabled":
        _section = {"enabled": _value}
    elif _option == "**":
        _section = {"options": {REPORTER_DESTINATION_OPTIONS[_reporter][0]: _value}}
    else:
        _section = {"enabled": True, "options": {_option: _value}}
    _DENIED_CASES[_pointer] = (
        {"op": "add", "path": f"/reporters/{_reporter}", "value": _section},
        {"reporters": {_reporter: _section}},
    )


#: A change a client makes to an off-host reporter the profile configures, and the
#: entry that refuses it: for each reporter, turning it on, setting each of its
#: operator-only options, and setting an option the operator left open on the
#: CLI. Each is refused by the reporter's whole-section entry, or by the entry of
#: its own that the Bedrock reporter's options listed before it have.
_OPEN_ON_THE_CLI = {
    "s3": ("file_format", "yaml"),
    "bedrock-summary-reporter": ("temperature", 0.1),
}
_BEDROCK_OWN_ENTRIES = {
    "aws_region": "/reporters/bedrock-summary-reporter/options/aws_*",
    "aws_profile": "/reporters/bedrock-summary-reporter/options/aws_*",
    **{
        name: f"/reporters/bedrock-summary-reporter/options/{name}"
        for name in (
            "model_id",
            "output_file",
            "output_executive_file",
            "output_technical_file",
        )
    },
}
_CONFIGURED_REPORTER_CASES: Dict[str, Tuple[str, Any, str]] = {}
for _reporter in sorted(REPORTER_ENABLED_DEFAULTS):
    _entry = f"/reporters/{_reporter}/**"
    _own = _BEDROCK_OWN_ENTRIES if _reporter == "bedrock-summary-reporter" else {}
    _CONFIGURED_REPORTER_CASES[f"{_reporter} on"] = (
        f"/reporters/{_reporter}/enabled",
        True,
        _entry,
    )
    for _name in REPORTER_DESTINATION_OPTIONS[_reporter]:
        _CONFIGURED_REPORTER_CASES[f"{_reporter} {_name}"] = (
            f"/reporters/{_reporter}/options/{_name}",
            "other-value",
            _own.get(_name, _entry),
        )
    if _reporter in _OPEN_ON_THE_CLI:
        _name, _value = _OPEN_ON_THE_CLI[_reporter]
        _CONFIGURED_REPORTER_CASES[f"{_reporter} {_name}"] = (
            f"/reporters/{_reporter}/options/{_name}",
            _value,
            _entry,
        )


@pytest.mark.parametrize("case", sorted(_CONFIGURED_REPORTER_CASES))
def test_a_client_cannot_turn_on_or_feed_a_reporter_the_profile_configures(
    tmp_path: Path, case: str
) -> None:
    """Refused on both routes, by the entry the case names."""
    pointer, value, entry = _CONFIGURED_REPORTER_CASES[case]
    document = _profile(allowed_paths=["/**"])
    document["reporters"] = {
        reporter: {"enabled": False, "options": {}}
        for reporter in REPORTER_ENABLED_DEFAULTS
    }
    _install(tmp_path, document)
    restated = yaml.safe_load(yaml.safe_dump(document))
    reporter, *rest = pointer.split("/")[2:]
    node = restated["reporters"][reporter]
    for segment in rest[:-1]:
        node = node[segment]
    node[rest[-1]] = value

    patched, overridden = _both_routes(
        {"op": "add", "path": pointer, "value": value},
        yaml.safe_dump(restated),
    )

    for result in (patched, overridden):
        assert result["success"] is False, result
        assert f"denied_paths entry {entry!r}" in result["error"], result["error"]
    _assert_unbound("patch")
    _assert_unbound("override")


_OFF_HOST_REPORTERS = (
    "aws-security-hub",
    "bedrock-summary-reporter",
    "cloudwatch-logs",
    "s3",
)


@pytest.fixture
def _own_workspace_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The session configs these tests read back are written under this test's
    own directory, not the MCP cache that concurrent runs share."""
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))


def _bound_reporter_enabled(session_id: str, reporter: str) -> Any:
    from automated_security_helper.config.ash_config import AshConfig

    bound = resolve_session_config_path(session_id)
    assert bound is not None
    section = AshConfig.from_file(config_path=Path(bound)).get_plugin_config(
        "reporter", reporter
    )
    return (section or {}).get("enabled")


def _scanned_reporter_enabled(tmp_path: Path, session_id: str, reporter: str) -> Any:
    """Whether ``reporter`` runs in a scan of this session: the bound copy,
    resolved with the arguments ``mcp_tools._run_scan_async`` hands the
    orchestrator for a bound config, as the client's against the registered
    profile."""
    from automated_security_helper.cli.mcp.profile_registry import (
        resolve_session_trusted_config_path,
    )
    from automated_security_helper.cli.mcp.sandbox import (
        client_named_config_is_untrusted,
        config_base_gate,
    )
    from automated_security_helper.cli.mcp_tools import _session_client_rules
    from automated_security_helper.config.resolve_config import resolve_config

    bound = resolve_session_config_path(session_id)
    assert bound is not None
    untrusted = client_named_config_is_untrusted(bound, session_id=session_id)
    assert untrusted, bound
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    config = resolve_config(
        config_path=bound,
        source_dir=target,
        permit_base=config_base_gate(session_id),
        trusted_config_path=resolve_session_trusted_config_path(session_id),
        untrusted_config=untrusted,
        client_config_policy=_session_client_rules(session_id),
    )
    section = config.get_plugin_config("reporter", reporter) or {}
    return section.get("enabled", REPORTER_ENABLED_DEFAULTS[reporter])


@pytest.mark.parametrize("reporter", _OFF_HOST_REPORTERS)
@pytest.mark.usefixtures("_own_workspace_root")
def test_a_client_may_turn_off_a_reporter_the_profile_turns_on(
    tmp_path: Path, reporter: str
) -> None:
    """``enabled: false`` asks for nothing beyond the profile, so it is accepted on
    both routes. It is not applied (runtime_patch.apply_runtime_patch drops it with
    a warning), so the client's copy keeps the profile's value, and a scan of that
    copy runs the reporter as the profile has it."""
    document = _profile(allowed_paths=["/**"])
    document["reporters"] = {reporter: {"enabled": True}}
    _install(tmp_path, document)
    restated = yaml.safe_load(yaml.safe_dump(document))
    restated["reporters"][reporter]["enabled"] = False

    patched, overridden = _both_routes(
        {"op": "replace", "path": f"/reporters/{reporter}/enabled", "value": False},
        yaml.safe_dump(restated),
    )

    for session, result in (("patch", patched), ("override", overridden)):
        assert result["success"] is True, result
        assert _bound_reporter_enabled(session, reporter) is True
        assert _scanned_reporter_enabled(tmp_path, session, reporter) is True


@pytest.mark.parametrize("reporter", _OFF_HOST_REPORTERS)
@pytest.mark.usefixtures("_own_workspace_root")
def test_a_client_may_add_a_section_that_only_turns_a_reporter_off(
    tmp_path: Path, reporter: str
) -> None:
    """The profile has no section, so the change adds one holding only ``enabled``.
    Accepted, and not applied: the client's copy gets no section, and a scan runs
    the reporter as its default has it."""
    document = _profile(allowed_paths=["/**"])
    _install(tmp_path, document)

    patched, overridden = _both_routes(
        {"op": "add", "path": f"/reporters/{reporter}", "value": {"enabled": False}},
        _restated(document, reporters={reporter: {"enabled": False}}),
    )

    for session, result in (("patch", patched), ("override", overridden)):
        assert result["success"] is True, result
        assert _bound_reporter_enabled(session, reporter) is None
        assert (
            _scanned_reporter_enabled(tmp_path, session, reporter)
            is REPORTER_ENABLED_DEFAULTS[reporter]
        )


@pytest.mark.parametrize("reporter", _OFF_HOST_REPORTERS)
@pytest.mark.parametrize("shape", ["leaf", "section"])
def test_a_client_still_cannot_turn_a_reporter_on(
    tmp_path: Path, reporter: str, shape: str
) -> None:
    document = _profile(allowed_paths=["/**"])
    if shape == "leaf":
        document["reporters"] = {reporter: {"enabled": False}}
        patch_op = {
            "op": "replace",
            "path": f"/reporters/{reporter}/enabled",
            "value": True,
        }
    else:
        patch_op = {
            "op": "add",
            "path": f"/reporters/{reporter}",
            "value": {"enabled": True},
        }
    _install(tmp_path, document)
    restated = yaml.safe_load(yaml.safe_dump(document))
    restated.setdefault("reporters", {})[reporter] = {"enabled": True}

    patched, overridden = _both_routes(patch_op, yaml.safe_dump(restated))

    for result in (patched, overridden):
        assert result["success"] is False, result
        assert "denied_paths entry" in result["error"], result["error"]
    _assert_unbound("patch")
    _assert_unbound("override")


@pytest.mark.parametrize("value", [0, "no"])
def test_an_enabled_read_as_false_is_not_the_exemption(
    tmp_path: Path, value: Any
) -> None:
    """Only ``false`` itself is exempt from the reporter's entry; another value the
    model reads as false is refused like ``true``."""
    document = _profile(allowed_paths=["/**"])
    document["reporters"] = {"s3": {"enabled": True}}
    _install(tmp_path, document)

    patched = mcp_select_profile(
        "op",
        patch_ops=[{"op": "replace", "path": "/reporters/s3/enabled", "value": value}],
        session_id="patch",
    )

    assert patched["success"] is False, patched
    assert "denied_paths entry" in patched["error"], patched["error"]
    _assert_unbound("patch")


def test_replacing_a_reporters_options_with_false_is_refused(tmp_path: Path) -> None:
    """Only ``/reporters/<name>/enabled`` is exempt, not another field of the section."""
    document = _profile(allowed_paths=["/**"])
    document["reporters"] = {"s3": {"enabled": True, "options": {"bucket_name": "b"}}}
    _install(tmp_path, document)

    patched = mcp_select_profile(
        "op",
        patch_ops=[{"op": "replace", "path": "/reporters/s3/options", "value": False}],
        session_id="patch",
    )

    assert patched["success"] is False, patched
    assert "denied_paths entry" in patched["error"], patched["error"]
    _assert_unbound("patch")


@pytest.mark.parametrize("op", ["add", "replace"])
def test_writing_only_enabled_false_over_an_existing_section_is_refused(
    tmp_path: Path, op: str
) -> None:
    """A section holding only ``enabled: false`` is exempt where the profile has no
    section for the reporter. Written over the profile's section it drops the
    section's other settings, so it is refused."""
    document = _profile(allowed_paths=["/**"])
    document["reporters"] = {"s3": {"enabled": True, "options": {"bucket_name": "b"}}}
    _install(tmp_path, document)

    patched = mcp_select_profile(
        "op",
        patch_ops=[{"op": op, "path": "/reporters/s3", "value": {"enabled": False}}],
        session_id="patch",
    )

    assert patched["success"] is False, patched
    assert "denied_paths entry" in patched["error"], patched["error"]
    _assert_unbound("patch")


@pytest.mark.parametrize("shape", ["leaf", "section"])
def test_the_enabled_false_exemption_is_for_off_host_reporters_only(
    tmp_path: Path, shape: str
) -> None:
    """An operator who denies a local reporter's ``enabled`` has it refused,
    ``false`` included: only the off-host reporters' ``enabled: false`` is exempt."""
    document = _profile(
        allowed_paths=["/**"], denied_paths=["/reporters/sarif/enabled"]
    )
    if shape == "leaf":
        document["reporters"] = {"sarif": {"enabled": True}}
        patch_op = {"op": "replace", "path": "/reporters/sarif/enabled", "value": False}
    else:
        patch_op = {
            "op": "add",
            "path": "/reporters/sarif",
            "value": {"enabled": False},
        }
    _install(tmp_path, document)
    restated = yaml.safe_load(yaml.safe_dump(document))
    restated.setdefault("reporters", {})["sarif"] = {"enabled": False}

    patched, overridden = _both_routes(patch_op, yaml.safe_dump(restated))

    for result in (patched, overridden):
        assert result["success"] is False, result
        assert "/reporters/sarif/enabled" in result["error"], result["error"]
    _assert_unbound("patch")
    _assert_unbound("override")


def test_a_section_turning_a_reporter_off_may_not_carry_anything_else(
    tmp_path: Path,
) -> None:
    """Only ``enabled: false`` is exempt; a destination beside it is still refused."""
    document = _profile(allowed_paths=["/**"])
    _install(tmp_path, document)
    section = {"enabled": False, "options": {"bucket_name": "other-bucket"}}

    patched, overridden = _both_routes(
        {"op": "add", "path": "/reporters/s3", "value": section},
        _restated(document, reporters={"s3": section}),
    )

    for result in (patched, overridden):
        assert result["success"] is False, result
        assert "denied_paths entry" in result["error"], result["error"]


@pytest.mark.parametrize(
    "op",
    [
        {"op": "remove", "path": "/reporters/s3/enabled"},
        # A remove carrying a value is still a remove, not an enabled: false.
        {"op": "remove", "path": "/reporters/s3/enabled", "value": False},
    ],
    ids=["remove", "remove-with-value"],
)
def test_removing_a_reporters_off_is_still_refused(
    tmp_path: Path, op: Dict[str, Any]
) -> None:
    """Removing ``enabled`` returns the reporter to its own default."""
    document = _profile(allowed_paths=["/**"])
    document["reporters"] = {"s3": {"enabled": False}}
    _install(tmp_path, document)

    patched = mcp_select_profile("op", patch_ops=[op], session_id="patch")

    assert patched["success"] is False, patched
    assert "denied_paths entry" in patched["error"], patched["error"]


def test_every_shipped_denied_path_has_a_case() -> None:
    """A new shipped entry without a case here would go untested on one route."""
    shipped = RuntimeOverridesConfig().denied_paths
    assert sorted(_DENIED_CASES) == sorted(shipped)


def _override_for(document: Dict[str, Any], changes: Dict[str, Any]) -> str:
    """Apply a case's changes to a restated profile.

    ignore_paths and suppressions live under global_settings, next to the mcp
    block the restatement has to keep.
    """
    restated = yaml.safe_load(yaml.safe_dump(document))

    def merge(into: Dict[str, Any], change: Dict[str, Any]) -> None:
        for key, value in change.items():
            if isinstance(value, dict) and isinstance(into.get(key), dict):
                merge(into[key], value)
            else:
                into[key] = value

    for key, value in changes.items():
        if key in ("ignore_paths", "suppressions"):
            restated["global_settings"][key] = value
        elif key == "global_settings":
            merge(restated["global_settings"], value)
        else:
            restated[key] = value
    return yaml.safe_dump(restated)


@pytest.mark.parametrize("entry", sorted(_DENIED_CASES))
def test_override_yaml_is_refused_by_every_shipped_denied_path(
    tmp_path: Path, entry: str
) -> None:
    document = _profile(allowed_paths=["/**"])
    _install(tmp_path, document)
    patch_op, changes = _DENIED_CASES[entry]

    patched, overridden = _both_routes(patch_op, _override_for(document, changes))

    assert patched["success"] is False, patched
    assert overridden["success"] is False, overridden
    for result in (patched, overridden):
        assert "denied_paths entry" in result["error"], result["error"]
    # Both routes are refused by an entry that covers the field the case
    # changes. `/sandbox` and `/sandbox/**` both cover every sandbox write, as
    # `/ash_plugin_modules` and `/ash_plugin_modules/**` cover every module list
    # write, and the first entry in the list is the one named.
    covering = next(
        (
            prefix
            for prefix in (
                "/sandbox",
                "/ash_plugin_modules",
                "/global_settings/mcp",
                "/scanners/detect-secrets/options/scan_settings/filters_used",
                "/scanners/detect-secrets/options/scan_settings/plugins_used",
            )
            if entry.startswith(prefix)
        ),
        entry,
    )

    def first_denied_under(section: str) -> str:
        # A glob entry such as /scanners/*/options/offline is under every
        # scanner's section.
        return next(
            denied
            for denied in RuntimeOverridesConfig().denied_paths
            if fnmatchcase(section, "/".join(denied.split("/")[:3]) + "/")
        )

    # A case that adds a whole reporter section the profile does not configure
    # is refused, on both routes, by the first denied entry under that section.
    added_section = patch_op["path"] + "/"
    if entry.startswith(added_section):
        covering = first_denied_under(added_section)
    # The override restates the profile, which configures no ferret-scan,
    # snyk-code or trivy-repo section, so its patch adds that whole section and
    # the first denied entry under it is the one named.
    section = "/".join(entry.split("/")[:3]) + "/"
    plugin_section = section in (
        "/scanners/ferret-scan/",
        "/scanners/snyk-code/",
        "/scanners/trivy-repo/",
    )
    # An entry earlier in the list can cover the same write: the whole section of
    # a plugin that sends data off the host comes after its options, and an op
    # writing scan_settings writes the plugins_used and filters_used under it.
    # The first entry that covers the write is the one named.
    from automated_security_helper.config.runtime_patch import (
        _denied_path_reason,
        known_plugin_keys,
    )

    def first_covering(written: str, fallback: str) -> str:
        return next(
            (
                denied
                for denied in RuntimeOverridesConfig().denied_paths
                if _denied_path_reason(denied, written, known_plugin_keys(None))
                is not None
            ),
            fallback,
        )

    covering = first_covering(patch_op["path"], covering)
    # The override's patch is the diff against the restated profile, which can
    # write below the case's field (scan_settings' plugins_used, say): the entry
    # named is the first that covers the write the refusal quotes.
    import re

    # The refusal names the op as "Patch op '<op>' at '<path>'"
    # (runtime_patch.RuntimePatchDeniedError, _op_and_path).
    quoted = re.search(r"Patch op '[^']*' at '([^']+)'", overridden["error"])
    covering_override = (
        first_denied_under(section)
        if plugin_section
        else first_covering(quoted.group(1), covering)
        if quoted
        else covering
    )
    assert f"entry {covering!r}" in patched["error"], patched["error"]
    assert f"entry {covering_override!r}" in overridden["error"], overridden["error"]
    _assert_unbound("patch")
    _assert_unbound("override")


@pytest.mark.parametrize(
    "reporter",
    ["aws-security-hub", "bedrock-summary-reporter", "cloudwatch-logs", "s3"],
)
def test_a_client_cannot_turn_on_an_off_host_reporter(
    tmp_path: Path, reporter: str
) -> None:
    """The profile configures the reporter off; turning it on is refused on both
    routes by the reporter's whole-section entry, which no profile can drop."""
    document = _profile(allowed_paths=["/**"], denied_paths=[])
    document["reporters"] = {reporter: {"enabled": False, "options": {}}}
    _install(tmp_path, document)
    restated = yaml.safe_load(yaml.safe_dump(document))
    restated["reporters"][reporter]["enabled"] = True

    patched, overridden = _both_routes(
        {"op": "replace", "path": f"/reporters/{reporter}/enabled", "value": True},
        yaml.safe_dump(restated),
    )

    entry = f"/reporters/{reporter}/**"
    for result in (patched, overridden):
        assert result["success"] is False, result
        assert f"denied_paths entry {entry!r}" in result["error"], result["error"]
    _assert_unbound("patch")
    _assert_unbound("override")


# ---------------------------------------------------------------------------
# The other runtime-override rules
# ---------------------------------------------------------------------------


def test_override_yaml_is_refused_when_runtime_overrides_are_disabled(
    tmp_path: Path,
) -> None:
    document = _profile(allowed_paths=["/project_name"], enabled=False)
    _install(tmp_path, document)

    patched, overridden = _both_routes(
        {"op": "replace", "path": "/project_name", "value": "renamed"},
        _restated(document, project_name="renamed"),
    )

    for result in (patched, overridden):
        assert result["success"] is False
        assert "runtime overrides disabled" in result["error"], result["error"]
    _assert_unbound("patch")
    _assert_unbound("override")


def test_override_yaml_is_refused_outside_allowed_paths(tmp_path: Path) -> None:
    document = _profile(allowed_paths=["/project_name"])
    _install(tmp_path, document)
    restated = yaml.safe_load(_restated(document))
    restated["global_settings"]["severity_threshold"] = "CRITICAL"

    patched, overridden = _both_routes(
        {
            "op": "replace",
            "path": "/global_settings/severity_threshold",
            "value": "CRITICAL",
        },
        yaml.safe_dump(restated),
    )

    for result in (patched, overridden):
        assert result["success"] is False
        assert (
            "'/global_settings/severity_threshold' not in allowed_paths"
            in (result["error"])
        ), result["error"]
    _assert_unbound("patch")
    _assert_unbound("override")


def test_override_yaml_is_refused_by_denied_value_patterns(tmp_path: Path) -> None:
    document = _profile(
        allowed_paths=["/project_name"],
        denied_value_patterns={"/project_name": "^blocked"},
    )
    _install(tmp_path, document)

    patched, overridden = _both_routes(
        {"op": "replace", "path": "/project_name", "value": "blocked-name"},
        _restated(document, project_name="blocked-name"),
    )

    for result in (patched, overridden):
        assert result["success"] is False
        assert "denied_value_patterns" in result["error"], result["error"]
    _assert_unbound("patch")
    _assert_unbound("override")


# ---------------------------------------------------------------------------
# Positive controls: a permitted change still goes through override_yaml
# ---------------------------------------------------------------------------


def test_override_yaml_changing_a_permitted_key_is_bound(tmp_path: Path) -> None:
    """Shipped denied_paths kept, only /project_name allowed."""
    document = _profile(allowed_paths=["/project_name"])
    _install(tmp_path, document)
    override = _restated(document, project_name="renamed")

    patched, overridden = _both_routes(
        {"op": "replace", "path": "/project_name", "value": "renamed"}, override
    )

    assert patched["success"] is True, patched
    assert overridden["success"] is True, overridden
    assert overridden["mode"] == "override"
    state = get_session_state("override")
    assert state is not None
    assert state.override_yaml == override
    assert state.bound_config is not None
    assert state.bound_config.project_name == "renamed"
    assert state.bound_config.sandbox.mode == "bwrap"
    assert state.bound_config.fail_on_findings is True
    # The file a later scan is handed carries the change, and the sandbox.
    materialized = yaml.safe_load(Path(overridden["config_path"]).read_text())
    assert materialized["project_name"] == "renamed"
    assert materialized["sandbox"]["mode"] == "bwrap"
    # Both routes bind the same config.
    patch_state = get_session_state("patch")
    assert patch_state is not None
    assert patch_state.bound_config is not None
    assert patch_state.bound_config.model_dump(
        mode="json"
    ) == state.bound_config.model_dump(mode="json")


def test_override_yaml_identical_to_the_profile_changes_nothing(
    tmp_path: Path,
) -> None:
    """With no paths allowed, any spurious difference in the diff would be refused."""
    document = _profile(allowed_paths=[])
    _install(tmp_path, document)

    result = mcp_select_profile(
        "op", override_yaml=_restated(document), session_id="override"
    )

    assert result["success"] is True, result
    state = get_session_state("override")
    assert state is not None
    assert state.bound_config is not None
    assert state.bound_config.project_name == "operator"
    assert state.bound_config.sandbox.mode == "bwrap"


@pytest.mark.parametrize(
    "spelling", ["BedrockSummary", "bedrocksummaryreporter", "Bedrock_Summary_Reporter"]
)
def test_a_denied_plugin_section_is_refused_in_every_spelling(
    tmp_path: Path, spelling: str
) -> None:
    """get_plugin_config reads each of these as bedrock-summary-reporter's config."""
    document = _profile(allowed_paths=["/**"])
    _install(tmp_path, document)
    section = {"enabled": True, "options": {"aws_region": "other-region-1"}}

    patched, overridden = _both_routes(
        {"op": "add", "path": f"/reporters/{spelling}", "value": section},
        _override_for(document, {"reporters": {spelling: section}}),
    )

    for result in (patched, overridden):
        assert result["success"] is False, result
        assert (
            "denied_paths entry '/reporters/bedrock-summary-reporter/options/aws_*'"
            in result["error"]
        ), result["error"]
    _assert_unbound("patch")
    _assert_unbound("override")


@pytest.mark.parametrize("spelling", ["TrivyRepo", "trivyrepo", "TRIVY-REPO"])
def test_a_glob_denial_on_a_plugin_section_is_refused_in_every_spelling(
    tmp_path: Path, spelling: str
) -> None:
    denial = "/scanners/trivy-*/options/ignore_file"
    document = _profile(allowed_paths=["/**"], denied_paths=[denial])
    # This entry alone, so the one that refuses is the glob under test.
    document["global_settings"]["mcp"]["runtime_overrides"][
        "replace_default_denied_paths"
    ] = True
    _install(tmp_path, document)
    section = {"options": {"ignore_file": "standin.txt"}}

    patched, overridden = _both_routes(
        {"op": "add", "path": f"/scanners/{spelling}", "value": section},
        _override_for(document, {"scanners": {spelling: section}}),
    )

    for result in (patched, overridden):
        assert result["success"] is False, result
        assert f"denied_paths entry {denial!r}" in result["error"], result["error"]
    _assert_unbound("patch")
    _assert_unbound("override")


# ---------------------------------------------------------------------------
# A profile holding an earlier default list
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pointer,value",
    [
        ("/scanners/opengrep/options/exclude_rule", ["some.rule.id"]),
        ("/scanners/detect-secrets/options/baseline_file", ".secrets.baseline"),
    ],
)
def test_a_profile_holding_an_earlier_default_list_gets_todays_denials(
    tmp_path: Path, pointer: str, value: Any
) -> None:
    """A list an earlier ``ash config init`` wrote is the default, so it denies what today's does.

    The list is the default ASH shipped before these entries were added. Read as
    written it would let both routes change fields the current default denies.
    """
    from automated_security_helper.config.client_config_policy import (
        SHIPPED_DEFAULT_DENIED_PATHS,
    )

    earlier = next(
        shipped
        for shipped in SHIPPED_DEFAULT_DENIED_PATHS
        if "/sandbox" in shipped and pointer not in shipped
    )
    document = _profile(allowed_paths=["/**"], denied_paths=sorted(earlier))
    _install(tmp_path, document)

    patched, overridden = _both_routes(
        {"op": "add", "path": pointer, "value": value},
        _override_for(document, _nested_at(pointer, value)),
    )

    for result in (patched, overridden):
        assert result["success"] is False, result
        assert f"denied_paths entry {pointer!r}" in result["error"], result["error"]
    _assert_unbound("patch")
    _assert_unbound("override")


def test_a_replacing_list_is_used_as_written(tmp_path: Path) -> None:
    """Positive control: with replace_default_denied_paths, a dropped default applies no more.

    A local scanner's option: a plugin that sends data off the host is denied
    whole whatever the list (ALWAYS_DENIED_PATHS).
    """
    edited = [
        entry
        for entry in RuntimeOverridesConfig().denied_paths
        if entry != "/scanners/bandit/options/confidence_level"
    ]
    document = _profile(allowed_paths=["/**"], denied_paths=edited)
    document["global_settings"]["mcp"]["runtime_overrides"][
        "replace_default_denied_paths"
    ] = True
    _install(tmp_path, document)

    patched = mcp_select_profile(
        "op",
        patch_ops=[
            {
                "op": "add",
                "path": "/scanners/bandit/options/confidence_level",
                "value": "high",
            }
        ],
        session_id="patch",
    )

    assert patched["success"] is True, patched


def test_an_edited_list_does_not_lift_the_defaults(tmp_path: Path) -> None:
    """A profile that denies one more field still denies every default one."""
    document = _profile(allowed_paths=["/**"], denied_paths=["/project_name"])
    _install(tmp_path, document)

    patched, overridden = _both_routes(
        {"op": "replace", "path": "/fail_on_findings", "value": False},
        _restated(document, fail_on_findings=False),
    )

    for result in (patched, overridden):
        assert result["success"] is False, result
        assert "denied_paths entry '/fail_on_findings'" in result["error"], result
    project = mcp_select_profile(
        "op",
        patch_ops=[{"op": "replace", "path": "/project_name", "value": "renamed"}],
        session_id="named",
    )
    assert project["success"] is False
    assert "denied_paths entry '/project_name'" in project["error"], project


def _s3_uploads_with_the_bound_config(
    session_id: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> List[tuple]:
    """The S3 calls the S3 reporter makes with the config ``session_id`` bound.

    botocore's last step before the network is stood in for, so a call is
    recorded, with its bucket, and nothing leaves the host.
    """
    from unittest.mock import MagicMock

    import botocore.client

    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
        S3Reporter,
        S3ReporterConfig,
    )

    calls: List[tuple] = []

    def stand_in(client, operation_name, api_params):
        calls.append((operation_name, api_params.get("Bucket")))
        return {}

    monkeypatch.setattr(botocore.client.BaseClient, "_make_api_call", stand_in)
    state = get_session_state(session_id)
    bound = state.bound_config if state is not None else None
    section = bound.get_plugin_config("reporter", "s3") if bound is not None else None
    if not section:
        return calls
    work = tmp_path / f"s3-{session_id}"
    reporter = S3Reporter(
        context=PluginContext(
            source_dir=work, output_dir=work / "output", work_dir=work / "work"
        ),
        config=S3ReporterConfig.model_validate(section),
    )
    if reporter.config.enabled and reporter.config.options.bucket_name:
        model = MagicMock()
        model.metadata.generated_at = "20261012-000000"
        model.metadata.workspace_project = None
        model.to_simple_dict.return_value = {"findings": []}
        reporter.report(model)
    return calls


def test_a_client_cannot_send_the_findings_to_a_bucket_of_its_own(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An off-host reporter's section is the operator's, whatever the allowlist says.

    Under an allowlist of ``/reporters/**`` that denies nothing, a client enabling
    S3 with a bucket of its own is refused on both routes, and nothing is
    uploaded. S3's section is also an always-denied entry, which is checked
    first, so the refusal can name the entry instead of the section.
    """
    for name, value in {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",  # pragma: allowlist secret
        "AWS_DEFAULT_REGION": "us-east-1",
        "AWS_CONFIG_FILE": str(tmp_path / "no-aws-config"),
        "AWS_SHARED_CREDENTIALS_FILE": str(tmp_path / "no-aws-credentials"),
    }.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    document = _profile(allowed_paths=["/reporters/**"], denied_paths=[])
    _install(tmp_path, document)
    section = {
        "enabled": True,
        "options": {"bucket_name": "clients-bucket", "aws_region": "us-east-1"},
    }

    patched, overridden = _both_routes(
        {"op": "add", "path": "/reporters/s3", "value": section},
        _override_for(document, {"reporters": {"s3": section}}),
    )
    uploads = _s3_uploads_with_the_bound_config(
        "patch", tmp_path, monkeypatch
    ) + _s3_uploads_with_the_bound_config("override", tmp_path, monkeypatch)

    assert uploads == [], uploads
    for result in (patched, overridden):
        assert result["success"] is False, result
        error = result["error"]
        assert "'s3'" in error or "denied_paths entry '/reporters/s3/**'" in error, (
            error
        )
    _assert_unbound("patch")
    _assert_unbound("override")


def test_a_client_turning_the_operators_s3_reporter_off_changes_nothing(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Accepted, so a client profile that carries it does not fail; not applied,
    since whether an off-host reporter runs is the operator's to say."""
    import logging

    document = _profile(allowed_paths=["/reporters/**"], denied_paths=[])
    s3 = {"enabled": True, "options": {"bucket_name": "operators-bucket"}}
    document["reporters"] = {"s3": s3}
    _install(tmp_path, document)
    turned_off = {"enabled": False, "options": {"bucket_name": "operators-bucket"}}

    with caplog.at_level(logging.WARNING):
        patched, overridden = _both_routes(
            {"op": "replace", "path": "/reporters/s3/enabled", "value": False},
            _override_for(document, {"reporters": {"s3": turned_off}}),
        )

    for result in (patched, overridden):
        assert result["success"] is True, result
    for session_id in ("patch", "override"):
        state = get_session_state(session_id)
        assert state is not None
        bound = state.bound_config
        assert bound is not None
        section = bound.get_plugin_config("reporter", "s3")
        assert section["enabled"] is True, section
        assert section["options"]["bucket_name"] == "operators-bucket", section
    assert any(
        "/reporters/s3/enabled" in record.getMessage()
        for record in caplog.records
        if record.levelno >= logging.WARNING
    ), [record.getMessage() for record in caplog.records]


def test_a_client_turning_s3_off_with_a_bucket_of_its_own_is_refused(
    tmp_path: Path,
) -> None:
    document = _profile(allowed_paths=["/reporters/**"], denied_paths=[])
    _install(tmp_path, document)
    section = {"enabled": False, "options": {"bucket_name": "clients-bucket"}}

    patched, overridden = _both_routes(
        {"op": "add", "path": "/reporters/s3", "value": section},
        _override_for(document, {"reporters": {"s3": section}}),
    )

    for result in (patched, overridden):
        assert result["success"] is False, result
        # s3 is a built-in reporter, so the always-denied entry
        # '/reporters/s3/**' refuses the section (ash_config.ALWAYS_DENIED_PATHS)
        # before the off-host-section rule names it; the refusal quotes the path.
        assert "/reporters/s3" in result["error"], result["error"]
    _assert_unbound("patch")
    _assert_unbound("override")


def test_control_a_client_still_patches_a_built_in_reporter(tmp_path: Path) -> None:
    document = _profile(allowed_paths=["/reporters/**"], denied_paths=[])
    _install(tmp_path, document)

    patched, overridden = _both_routes(
        {"op": "replace", "path": "/reporters/markdown/enabled", "value": False},
        _override_for(document, {"reporters": {"markdown": {"enabled": False}}}),
    )

    for result in (patched, overridden):
        assert result["success"] is True, result
    for session_id in ("patch", "override"):
        state = get_session_state(session_id)
        assert state is not None
        bound = state.bound_config
        assert bound is not None
        assert bound.get_plugin_config("reporter", "markdown")["enabled"] is False
