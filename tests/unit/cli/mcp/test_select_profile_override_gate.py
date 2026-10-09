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

from pathlib import Path
from typing import Any, Dict, List, get_args

import pytest
import yaml

from automated_security_helper.cli.mcp.profile_registry import (
    clear_profile_registry,
    clear_session_state,
    get_session_state,
    register_profiles,
    resolve_session_config_path,
    set_profile_registry,
)
from automated_security_helper.cli.mcp_tools import mcp_select_profile
from automated_security_helper.config.ash_config import (
    RuntimeOverridesConfig,
    SandboxConfig,
)


@pytest.fixture(autouse=True)
def _isolate_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    # Materialized session configs land under the allowed roots.
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    clear_profile_registry()
    clear_session_state()
    yield
    clear_profile_registry()
    clear_session_state()


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
    state = get_session_state(session_id)
    assert state.bound_config is None
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
# The three sandbox fields
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
}


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
    for key, value in changes.items():
        if key in ("ignore_paths", "suppressions"):
            restated["global_settings"][key] = value
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
            for prefix in ("/sandbox", "/ash_plugin_modules")
            if entry.startswith(prefix)
        ),
        entry,
    )
    for result in (patched, overridden):
        assert f"entry {covering!r}" in result["error"], result["error"]
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
