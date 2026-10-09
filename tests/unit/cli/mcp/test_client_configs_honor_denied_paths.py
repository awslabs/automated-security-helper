# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config an MCP client delivered may not set what the runtime-override policy denies.

``global_settings.mcp.runtime_overrides.denied_paths`` (and ``denied_value_patterns``)
keep fields such as the Bedrock reporter's region out of a client's
``patch_ops``, ``override_yaml`` and workspace ``config_overrides``. A client can
also hand the server a whole config file: an upload named as ``config_path``, the
``.ash.yaml`` inside a delivered tree, or a project config inside a delivered
workspace. Those files are checked against the same policy, with the same
matcher, and a file that sets a denied field is refused with an error naming the
field rather than resolved.

The policy is the session's: the profile bound with ``select_profile`` when there
is one, else the server's default config.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import zipfile
from pathlib import Path
from typing import Any, Callable, Dict, List
from unittest.mock import patch

import pytest

from automated_security_helper.cli.mcp.profile_registry import (
    clear_profile_registry,
    clear_session_state,
    register_profiles,
    resolve_session_config_path,
    set_profile_registry,
)

SESSION = "client-1"

BEDROCK_REGION = (
    "project_name: uploaded\n"
    "reporters:\n"
    "  bedrock-summary-reporter:\n"
    "    enabled: true\n"
    "    options:\n"
    "      aws_region: us-west-2\n"
)
DENIED_KEY = "reporters.bedrock-summary-reporter.options.aws_region"


class _QuietLogger:
    def __getattr__(self, name: str) -> Callable[..., None]:
        return lambda *args, **kwargs: None


class _StopAfterResolution(Exception):
    pass


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    workspace = tmp_path / "workspaces"
    scan_root = tmp_path / "scan-root"
    target = scan_root / "target"
    target.mkdir(parents=True)
    operator = tmp_path / "operator" / "ash.yaml"
    operator.parent.mkdir()
    operator.write_text("project_name: operator\n", encoding="utf-8")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(scan_root))
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    clear_profile_registry()
    clear_session_state()
    yield {"workspace": workspace, "target": target, "tmp": tmp_path}
    clear_profile_registry()
    clear_session_state()


def _upload(files: Dict[str, str]) -> Path:
    """Deliver ``files`` through the real chunked zip upload; return the source dir."""
    from automated_security_helper.cli.mcp.source_delivery import (
        set_source_zip_chunk,
        set_source_zip_finalize,
    )

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, text in files.items():
            archive.writestr(name, text)
    data = buffer.getvalue()
    set_source_zip_chunk(
        "u1", 0, base64.b64encode(data).decode("ascii"), True, session_id=SESSION
    )
    return set_source_zip_finalize(
        "u1", hashlib.sha256(data).hexdigest(), session_id=SESSION
    )


def _bind_profile(tmp_path: Path, text: str) -> str:
    from automated_security_helper.cli.mcp_tools import mcp_select_profile

    path = tmp_path / "operator" / "profile.yaml"
    path.write_text(text, encoding="utf-8")
    set_profile_registry(register_profiles([f"op={path}"]))
    result = mcp_select_profile("op", session_id=SESSION)
    assert result["success"] is True, result
    bound = resolve_session_config_path(SESSION)
    assert bound is not None
    return bound


def _profile_denying(*denied: str) -> str:
    return (
        "project_name: profile\n"
        "global_settings:\n"
        "  mcp:\n"
        "    runtime_overrides:\n"
        f"      denied_paths: {json.dumps(list(denied))}\n"
    )


def _scan_resolution(target: Path, config_path: str | None) -> Any:
    """Start an MCP scan; return the config it resolved, or the error resolution raised."""
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.config import resolve_config as rc
    from automated_security_helper.core import orchestrator
    from automated_security_helper.core.resource_management.scan_registry import (
        ScanRegistry,
    )
    from automated_security_helper.interactions import run_ash_scan as ras

    outcomes: List[Any] = []
    real = rc.resolve_config

    def recording(*args: Any, **kwargs: Any) -> Any:
        try:
            outcomes.append(real(*args, **kwargs))
        except Exception as exc:  # noqa: BLE001 -- the outcome under test
            outcomes.append(exc)
        raise _StopAfterResolution

    output = target / ".ash" / "ash_output"
    output.mkdir(parents=True, exist_ok=True)
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(target), output_directory=str(output)
    )
    with (
        patch.object(ras, "_setup_logger", lambda opts: _QuietLogger()),
        patch.object(orchestrator, "resolve_config", recording),
        patch.object(mcp_tools, "get_scan_registry", return_value=registry),
    ):
        asyncio.run(
            mcp_tools._run_scan_async(
                scan_id=scan_id,
                directory_path=str(target),
                output_dir=str(output),
                severity_threshold="MEDIUM",
                config_path=config_path,
                session_id=SESSION,
            )
        )
    assert len(outcomes) == 1, "the scan never reached config resolution"
    return outcomes[0]


def _assert_refused(outcome: Any, key: str = DENIED_KEY) -> None:
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    assert isinstance(outcome, ASHConfigValidationError), outcome
    # Named by the denial itself, not by some other resolution failure.
    assert "denied_" in str(outcome), str(outcome)
    assert key in str(outcome), str(outcome)


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------


def test_an_uploaded_config_path_setting_a_denied_field_is_refused(_server) -> None:
    source = _upload({"ash.yaml": BEDROCK_REGION})
    _assert_refused(_scan_resolution(_server["target"], str(source / "ash.yaml")))


def test_a_delivered_trees_own_config_setting_a_denied_field_is_refused(
    _server,
) -> None:
    source = _upload({".ash/.ash.yaml": BEDROCK_REGION, "app.py": "x = 1\n"})
    _assert_refused(_scan_resolution(source, None))


@pytest.mark.parametrize(
    "section",
    ["BedrockSummary", "bedrock_summary_reporter", "BedrockSummaryReporter"],
)
def test_every_spelling_of_the_denied_plugin_section_is_refused(
    _server, section: str
) -> None:
    text = BEDROCK_REGION.replace("bedrock-summary-reporter", section)
    source = _upload({"ash.yaml": text})
    _assert_refused(
        _scan_resolution(_server["target"], str(source / "ash.yaml")),
        key=f"reporters.{section}.options.aws_region",
    )


def test_the_bound_profiles_denials_apply_including_a_wildcard(_server) -> None:
    _bind_profile(
        _server["tmp"], _profile_denying("/scanners/trivy-*/options/ignore_file")
    )
    source = _upload(
        {
            "ash.yaml": (
                "scanners:\n  TrivyRepo:\n    options:\n      ignore_file: x.txt\n"
            )
        }
    )
    _assert_refused(
        _scan_resolution(_server["target"], str(source / "ash.yaml")),
        key="scanners.TrivyRepo.options.ignore_file",
    )


def test_the_bound_profiles_denials_apply_to_a_delivered_trees_config(
    _server,
) -> None:
    _bind_profile(_server["tmp"], _profile_denying("/project_name"))
    source = _upload({".ash/.ash.yaml": "project_name: delivered\n"})
    _assert_refused(_scan_resolution(source, None), key="project_name")


def test_a_patch_in_an_uploaded_config_is_checked_too(_server) -> None:
    text = (
        "project_name: uploaded\n"
        "reporters: {}\n"
        "patch:\n"
        "  - op: add\n"
        "    path: /reporters/bedrock-summary-reporter\n"
        "    value: {options: {aws_region: us-west-2}}\n"
    )
    source = _upload({"ash.yaml": text})
    _assert_refused(
        _scan_resolution(_server["target"], str(source / "ash.yaml")),
        key="/reporters/bedrock-summary-reporter",
    )


@pytest.mark.parametrize(
    "text,key",
    [
        ("fail_on_findings: false\n", "fail_on_findings"),
        ("content_db_staleness: warn\n", "content_db_staleness"),
    ],
)
def test_the_other_default_denials_hold_for_an_upload(_server, text, key) -> None:
    """A shipped entry applies to an upload that changes the field."""
    source = _upload({"ash.yaml": text})
    _assert_refused(
        _scan_resolution(_server["target"], str(source / "ash.yaml")), key=key
    )


def test_sandbox_and_plugin_modules_in_an_upload_are_left_restrict_only(
    _server,
) -> None:
    """Not refused here: sandbox_grants and plugin_module_trust already bound them."""
    operator = _server["tmp"] / "operator" / "ash.yaml"
    operator.write_text("sandbox:\n  mode: bwrap\n", encoding="utf-8")
    source = _upload(
        {
            "ash.yaml": (
                "sandbox:\n  mode: 'off'\n  extra_read_paths: ['/']\n"
                "ash_plugin_modules: [no_such_module_anywhere]\n"
            )
        }
    )
    config = _scan_resolution(_server["target"], str(source / "ash.yaml"))
    assert not isinstance(config, Exception), config
    assert config.sandbox.mode == "bwrap"
    assert config.sandbox.extra_read_paths == []
    assert "no_such_module_anywhere" not in config.ash_plugin_modules


def test_a_default_value_in_an_upload_is_accepted(_server) -> None:
    """``fail_on_findings: true`` is the default, so it changes nothing."""
    source = _upload({".ash/.ash.yaml": "fail_on_findings: true\n"})
    config = _scan_resolution(source, None)
    assert not isinstance(config, Exception), config


_DELIVERED_SUPPRESSION = (
    "global_settings:\n  suppressions:\n    - path: app.py\n      reason: delivered\n"
)


def test_a_delivered_trees_own_suppressions_apply_and_are_marked(_server) -> None:
    source = _upload({".ash/.ash.yaml": _DELIVERED_SUPPRESSION, "app.py": "x = 1\n"})
    config = _scan_resolution(source, None)
    assert not isinstance(config, Exception), config
    [entry] = config.global_settings.suppressions
    assert entry.path == "app.py" and entry.client_supplied is True


def test_a_profile_that_denies_suppressions_still_refuses_them(_server) -> None:
    _bind_profile(_server["tmp"], _profile_denying("/global_settings/suppressions"))
    source = _upload({".ash/.ash.yaml": _DELIVERED_SUPPRESSION, "app.py": "x = 1\n"})
    _assert_refused(_scan_resolution(source, None), key="global_settings.suppressions")


def test_ashs_own_repository_config_delivered_as_a_tree_scans(_server) -> None:
    own = Path(__file__).resolve().parents[4] / ".ash" / ".ash.yaml"
    source = _upload({".ash/.ash.yaml": own.read_text(encoding="utf-8")})
    config = _scan_resolution(source, None)
    assert not isinstance(config, Exception), config


def test_an_ash_config_init_file_delivered_as_a_tree_scans(_server) -> None:
    from automated_security_helper.cli.config import init

    target = _server["tmp"] / "init" / ".ash" / ".ash.yaml"
    init(config=str(target), color=False)
    source = _upload({".ash/.ash.yaml": target.read_text(encoding="utf-8")})
    config = _scan_resolution(source, None)
    assert not isinstance(config, Exception), config


def test_positive_control_an_upload_without_denied_fields_resolves(_server) -> None:
    source = _upload(
        {"ash.yaml": "project_name: uploaded\nreporters:\n  csv:\n    enabled: false\n"}
    )
    config = _scan_resolution(_server["target"], str(source / "ash.yaml"))
    assert not isinstance(config, Exception), config
    assert config.project_name == "uploaded"


def test_positive_control_an_operator_config_may_set_the_field(
    _server, monkeypatch
) -> None:
    operator = _server["tmp"] / "operator" / "ash.yaml"
    operator.write_text(BEDROCK_REGION.replace("uploaded", "operator"))
    config = _scan_resolution(_server["target"], str(operator))
    assert not isinstance(config, Exception), config
    found = config.get_plugin_config("reporter", "bedrock-summary-reporter")
    assert found["options"]["aws_region"] == "us-west-2"


@pytest.mark.parametrize("delivered_tree", [False, True])
def test_scan_directory_refuses_before_the_scan_starts(_server, delivered_tree) -> None:
    """Refused up front with the field named; the background scan never starts."""
    from automated_security_helper.cli import mcp_tools

    if delivered_tree:
        source = _upload({".ash/.ash.yaml": BEDROCK_REGION})
        target, config_path = source, None
    else:
        source = _upload({"ash.yaml": BEDROCK_REGION})
        target, config_path = _server["target"], str(source / "ash.yaml")
    started: List[Dict[str, Any]] = []

    async def not_started(**kwargs: Any) -> None:
        started.append(kwargs)

    with patch.object(mcp_tools, "_run_scan_async", not_started):
        result = asyncio.run(
            mcp_tools.mcp_scan_directory(
                str(target), config_path=config_path, session_id=SESSION
            )
        )
    assert result["success"] is False, result
    assert result["error_type"] == "config_field_denied", result
    assert DENIED_KEY in result["error"], result
    assert started == []


# ---------------------------------------------------------------------------
# Resolve-only and validation
# ---------------------------------------------------------------------------


def test_get_config_refuses_an_upload_setting_a_denied_field(_server) -> None:
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    source = _upload({"ash.yaml": BEDROCK_REGION})
    result = mcp_get_config(config_path=str(source / "ash.yaml"), session_id=SESSION)
    assert result.get("success") is False, result
    assert DENIED_KEY in result["error"], result


def test_get_config_refuses_a_discovered_delivered_config(_server) -> None:
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    source = _upload({".ash/.ash.yaml": BEDROCK_REGION})
    result = mcp_get_config(search_dir=str(source), session_id=SESSION)
    assert result.get("success") is False, result
    assert DENIED_KEY in result["error"], result


def test_validate_config_reports_a_denied_field_in_content(_server) -> None:
    from automated_security_helper.cli.mcp_tools import mcp_validate_config

    result = mcp_validate_config(config_content=BEDROCK_REGION, session_id=SESSION)
    assert result["valid"] is False, result
    denied = [e for e in result["errors"] if e["type"] == "denied_by_runtime_policy"]
    assert denied and denied[0]["field"] == DENIED_KEY, result


def test_validate_config_reports_a_denied_field_in_an_upload(_server) -> None:
    from automated_security_helper.cli.mcp_tools import mcp_validate_config

    source = _upload({"ash.yaml": BEDROCK_REGION})
    result = mcp_validate_config(
        config_path=str(source / "ash.yaml"), session_id=SESSION
    )
    assert result["valid"] is False, result
    assert any(e["type"] == "denied_by_runtime_policy" for e in result["errors"])


# ---------------------------------------------------------------------------
# Workspaces
# ---------------------------------------------------------------------------


def test_a_delivered_workspace_projects_config_is_refused(_server) -> None:
    from automated_security_helper.cli.mcp import workspace as workspace_module

    source = _upload(
        {
            "dev.code-workspace": json.dumps({"folders": [{"path": "app"}]}),
            "app/main.py": "x = 1\n",
            "app/.ash/.ash.yaml": BEDROCK_REGION,
        }
    )
    result = asyncio.run(
        workspace_module.mcp_resolve_workspace(
            str(source / "dev.code-workspace"), session_id=SESSION
        )
    )
    assert result["success"] is False, result
    assert DENIED_KEY in result["error"], result


# ---------------------------------------------------------------------------
# Review follow-ups: what is checked, whose policy, and how a refusal surfaces
# ---------------------------------------------------------------------------


def test_the_check_reads_what_resolution_parsed_not_the_file_again(_server) -> None:
    """A file swapped after resolution read it cannot slip past the check."""
    from automated_security_helper.config import resolve_config as rc
    from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

    source = _upload({"ash.yaml": BEDROCK_REGION})
    upload = source / "ash.yaml"
    real = rc.resolve_config_document

    def read_then_swap(*args: Any, **kwargs: Any) -> Any:
        document = real(*args, **kwargs)
        upload.write_text("project_name: benign\n", encoding="utf-8")
        return document

    with patch.object(rc, "resolve_config_document", read_then_swap):
        with pytest.raises(ASHConfigFieldDeniedError, match="aws_region"):
            rc.resolve_config(
                config_path=upload,
                source_dir=_server["target"],
                untrusted_config=True,
            )


def test_delivery_is_refused_while_a_scan_of_the_session_runs(_server) -> None:
    from automated_security_helper.cli.mcp.sessions import get_default_registry
    from automated_security_helper.cli.mcp.source_delivery import (
        SourceDeliveryBusyError,
    )

    lock = get_default_registry().get_or_create(SESSION).lock
    with lock:
        with pytest.raises(SourceDeliveryBusyError):
            _upload({"ash.yaml": "project_name: x\n"})
    # And once the scan is done, delivery works.
    assert (_upload({"ash.yaml": "project_name: x\n"}) / "ash.yaml").is_file()


def test_the_policy_is_the_registered_profiles_not_the_patched_copy(_server) -> None:
    """A client that may patch global_settings still cannot lift its own denials."""
    from automated_security_helper.cli.mcp_tools import mcp_select_profile

    profile = _server["tmp"] / "operator" / "profile.yaml"
    profile.write_text(
        "project_name: profile\n"
        "global_settings:\n"
        "  mcp:\n"
        "    runtime_overrides:\n"
        "      enabled: true\n"
        "      allowed_paths: ['/global_settings/**']\n"
        "      denied_paths: ['/fail_on_findings']\n",
        encoding="utf-8",
    )
    set_profile_registry(register_profiles([f"op={profile}"]))
    bound = mcp_select_profile(
        "op",
        session_id=SESSION,
        patch_ops=[
            {
                "op": "replace",
                "path": "/global_settings/mcp/runtime_overrides/denied_paths",
                "value": [],
            }
        ],
    )
    assert bound["success"] is True, bound
    source = _upload({"ash.yaml": "fail_on_findings: false\n"})
    _assert_refused(
        _scan_resolution(_server["target"], str(source / "ash.yaml")),
        key="fail_on_findings",
    )


def test_by_default_patch_ops_cannot_change_the_policy(_server) -> None:
    from automated_security_helper.cli.mcp_tools import mcp_select_profile

    profile = _server["tmp"] / "operator" / "profile.yaml"
    profile.write_text(
        "global_settings:\n  mcp:\n    runtime_overrides:\n      enabled: true\n"
        "      allowed_paths: ['/**']\n",
        encoding="utf-8",
    )
    set_profile_registry(register_profiles([f"op={profile}"]))
    refused = mcp_select_profile(
        "op",
        session_id=SESSION,
        patch_ops=[
            {
                "op": "replace",
                "path": "/global_settings/mcp/runtime_overrides/denied_paths",
                "value": [],
            }
        ],
    )
    assert refused["success"] is False, refused
    assert "/global_settings/mcp" in refused["error"], refused


def _ctx(session: str) -> Any:
    from unittest.mock import MagicMock

    ctx = MagicMock()
    ctx.headers = {"mcp-session-id": session}

    async def anoop(*args: Any, **kwargs: Any) -> None:
        return None

    for name in ("info", "error", "debug", "warning", "report_progress"):
        setattr(ctx, name, MagicMock(side_effect=anoop))
    return ctx


def test_the_run_ash_scan_tool_keeps_the_refusals_error_type(_server) -> None:
    from automated_security_helper.cli import mcp_server, mcp_tools

    source = _upload({"ash.yaml": BEDROCK_REGION})
    started: List[Any] = []

    async def not_started(**kwargs: Any) -> None:
        started.append(kwargs)

    with patch.object(mcp_tools, "_run_scan_async", not_started):
        result = asyncio.run(
            mcp_server.run_ash_scan(
                _ctx(SESSION),
                source_dir=str(_server["target"]),
                config_path=str(source / "ash.yaml"),
            )
        )
    assert started == []
    assert result["error_type"] == "config_field_denied", result
    assert DENIED_KEY in result["error"], result


def test_validate_config_on_stdio_does_not_flag_the_callers_own_content(
    _server,
) -> None:
    from automated_security_helper.cli.mcp_tools import mcp_validate_config

    result = mcp_validate_config(config_content=BEDROCK_REGION, session_id=None)
    assert result == {"valid": True, "errors": []}, result


def test_validate_config_checks_a_delivered_base_too(_server) -> None:
    from automated_security_helper.cli.mcp_tools import mcp_validate_config

    source = _upload(
        {
            "ash.yaml": "extends: base.yaml\nproject_name: child\n",
            "base.yaml": BEDROCK_REGION,
        }
    )
    result = mcp_validate_config(
        config_path=str(source / "ash.yaml"), session_id=SESSION
    )
    assert result["valid"] is False, result
    denied = [e for e in result["errors"] if e["type"] == "denied_by_runtime_policy"]
    assert denied and denied[0]["field"] == DENIED_KEY, result
    assert "base.yaml" in denied[0]["message"], result


def test_a_local_scan_takes_the_completeness_gate_from_its_resolved_config(
    _server,
) -> None:
    """No unchecked pre-read of a delivered file decides the exit code."""
    from automated_security_helper.cli.mcp.sandbox import config_base_gate
    from automated_security_helper.interactions import run_ash_scan as ras

    source = _upload({"ash.yaml": "fail_on_incomplete_scanners: false\n"})
    calls: List[Any] = []
    real = ras._resolve_config_fail_on_incomplete_scanners

    def recording(opts: Any) -> Any:
        calls.append(opts)
        return real(opts)

    target = _server["target"]
    output = target / ".ash" / "ash_output"
    output.mkdir(parents=True, exist_ok=True)
    with (
        patch.object(ras, "_resolve_config_fail_on_incomplete_scanners", recording),
        patch.object(ras, "_setup_logger", lambda opts: _QuietLogger()),
        patch.object(ras, "_run_local_mode", side_effect=_StopAfterResolution),
    ):
        with pytest.raises(_StopAfterResolution):
            ras.run_ash_scan(
                source_dir=str(target),
                output_dir=str(output),
                config=str(source / "ash.yaml"),
                config_base_gate=config_base_gate(SESSION),
                untrusted_config=True,
                show_summary=False,
            )
    assert calls == []


def test_a_resolve_time_refusal_is_the_scans_recorded_error(_server) -> None:
    """When resolution refuses, the client sees the fields, not an exit code."""
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.core.resource_management.scan_registry import (
        ScanRegistry,
    )
    from automated_security_helper.interactions import run_ash_scan as ras

    source = _upload({"ash.yaml": BEDROCK_REGION})
    target = _server["target"]
    output = target / ".ash" / "ash_output"
    output.mkdir(parents=True, exist_ok=True)
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(target), output_directory=str(output)
    )
    with (
        patch.object(ras, "_setup_logger", lambda opts: _QuietLogger()),
        patch.object(mcp_tools, "get_scan_registry", return_value=registry),
    ):
        asyncio.run(
            mcp_tools._run_scan_async(
                scan_id=scan_id,
                directory_path=str(target),
                output_dir=str(output),
                severity_threshold="MEDIUM",
                config_path=str(source / "ash.yaml"),
                session_id=SESSION,
            )
        )
    entry = registry.get_scan(scan_id)
    assert entry.status.value == "failed", entry
    assert DENIED_KEY in str(entry.error_message), entry.error_message


def test_an_unregistered_bound_profile_fails_closed(_server) -> None:
    from automated_security_helper.cli.mcp_tools import mcp_scan_directory

    _bind_profile(_server["tmp"], "project_name: profile\n")
    clear_profile_registry()
    source = _upload({".ash/.ash.yaml": "project_name: delivered\n"})
    result = asyncio.run(
        mcp_scan_directory(str(source), config_path=None, session_id=SESSION)
    )
    assert result["success"] is False, result
    assert "not registered" in result["error"], result


# ---------------------------------------------------------------------------
# Second review: operator rules on exempt paths, marking, keys, inert sections
# ---------------------------------------------------------------------------

_TRIVY_MODULE = "automated_security_helper.plugin_modules.ash_trivy_plugins"


def _policy_profile(body: str) -> str:
    return "global_settings:\n  mcp:\n    runtime_overrides:\n" + body


def _flags(config: Any) -> list:
    return [(s.path, s.client_supplied) for s in config.global_settings.suppressions]


def test_an_operators_value_pattern_applies_to_delivered_suppressions(
    _server,
) -> None:
    _bind_profile(
        _server["tmp"],
        _policy_profile(
            "      denied_value_patterns:\n"
            "        /global_settings/suppressions/**: '^CKV_'\n"
        ),
    )
    source = _upload(
        {
            "ash.yaml": (
                "global_settings:\n  suppressions:\n"
                "    - {rule_id: CKV_AWS_1, path: app.py, reason: r}\n"
            )
        }
    )
    _assert_refused(
        _scan_resolution(_server["target"], str(source / "ash.yaml")),
        key="global_settings.suppressions",
    )


def test_an_operators_value_pattern_applies_to_delivered_plugin_modules(
    _server,
) -> None:
    _bind_profile(
        _server["tmp"],
        _policy_profile(
            "      denied_value_patterns:\n        /ash_plugin_modules/**: 'trivy'\n"
        ),
    )
    source = _upload({"ash.yaml": f"ash_plugin_modules: [{_TRIVY_MODULE}]\n"})
    _assert_refused(
        _scan_resolution(_server["target"], str(source / "ash.yaml")),
        key="ash_plugin_modules",
    )


def test_an_operators_explicit_plugin_module_denial_applies(_server) -> None:
    _bind_profile(_server["tmp"], _profile_denying("/ash_plugin_modules"))
    source = _upload({"ash.yaml": f"ash_plugin_modules: [{_TRIVY_MODULE}]\n"})
    _assert_refused(
        _scan_resolution(_server["target"], str(source / "ash.yaml")),
        key="ash_plugin_modules",
    )


def test_a_key_is_not_checked_against_patterns_bound_below_it(_server) -> None:
    _bind_profile(
        _server["tmp"],
        _policy_profile(
            "      denied_value_patterns:\n"
            "        /reporters/*/options/aws_region: '^(?!us-)'\n"
        ),
    )
    source = _upload({"ash.yaml": "project_name: plain\n"})
    config = _scan_resolution(_server["target"], str(source / "ash.yaml"))
    assert not isinstance(config, Exception), config


def test_a_patch_appended_suppression_is_marked(_server) -> None:
    source = _upload(
        {
            "ash.yaml": (
                "global_settings:\n  suppressions:\n"
                "    - {path: a.py, reason: listed}\n"
                "patch:\n  - op: add\n    path: /global_settings/suppressions/-\n"
                "    value: {path: b.py, reason: patched}\n"
            )
        }
    )
    config = _scan_resolution(_server["target"], str(source / "ash.yaml"))
    assert not isinstance(config, Exception), config
    assert _flags(config) == [("a.py", True), ("b.py", True)]


def test_a_dash_spelled_suppression_over_a_delivered_base_is_marked(_server) -> None:
    source = _upload(
        {
            "base.yaml": "global_settings:\n  suppressions: []\n",
            "ash.yaml": (
                "extends: base.yaml\n"
                "global-settings:\n  suppressions:\n"
                "    - {path: c.py, reason: dashed}\n"
            ),
        }
    )
    config = _scan_resolution(_server["target"], str(source / "ash.yaml"))
    assert not isinstance(config, Exception), config
    assert _flags(config) == [("c.py", True)]


def test_validate_content_reports_an_operators_explicit_denial(_server) -> None:
    from automated_security_helper.cli.mcp_tools import mcp_validate_config

    _bind_profile(_server["tmp"], _profile_denying("/global_settings/suppressions"))
    text = "global_settings:\n  suppressions:\n    - {path: a.py, reason: r}\n"
    source = _upload({"ash.yaml": text})
    as_content = mcp_validate_config(config_content=text, session_id=SESSION)
    as_file = mcp_validate_config(
        config_path=str(source / "ash.yaml"), session_id=SESSION
    )
    for result in (as_content, as_file):
        assert any(
            e["type"] == "denied_by_runtime_policy"
            and e["field"] == "global_settings.suppressions"
            for e in result["errors"]
        ), result


def test_an_init_file_scans_under_a_profile_whose_policy_differs(_server) -> None:
    from automated_security_helper.cli.config import init

    _bind_profile(
        _server["tmp"],
        _policy_profile(
            "      enabled: true\n      allowed_paths: ['/project_name']\n"
        ),
    )
    target = _server["tmp"] / "init" / ".ash" / ".ash.yaml"
    init(config=str(target), color=False)
    source = _upload({".ash/.ash.yaml": target.read_text(), "app.py": "x = 1\n"})
    config = _scan_resolution(source, None)
    assert not isinstance(config, Exception), config


def test_an_init_generated_profile_counts_as_the_default_policy(_server) -> None:
    from automated_security_helper.cli.config import init

    profile = _server["tmp"] / "init-profile" / "profile.yaml"
    init(config=str(profile), color=False)
    _bind_profile(_server["tmp"], profile.read_text())
    source = _upload({".ash/.ash.yaml": _DELIVERED_SUPPRESSION, "app.py": "x = 1\n"})
    config = _scan_resolution(source, None)
    assert not isinstance(config, Exception), config
    assert _flags(config) == [("app.py", True)]


def test_a_profile_with_two_sections_for_one_plugin_refuses_the_scan(_server) -> None:
    from automated_security_helper.cli.mcp_tools import mcp_scan_directory

    _bind_profile(
        _server["tmp"],
        "reporters:\n"
        "  bedrock-summary:\n    options: {aws_region: eu-west-1}\n"
        "  bedrock-summary-reporter:\n    options: {aws_region: us-east-1}\n",
    )
    source = _upload(
        {
            "ash.yaml": "reporters:\n  BedrockSummary:\n    options: {aws_region: eu-west-1}\n"
        }
    )
    result = asyncio.run(
        mcp_scan_directory(
            str(_server["target"]),
            config_path=str(source / "ash.yaml"),
            session_id=SESSION,
        )
    )
    assert result["success"] is False, result
    assert "same plugin" in result["error"], result


def test_delivery_is_refused_while_a_workspace_scan_of_the_session_runs(
    _server,
) -> None:
    from automated_security_helper.cli.mcp import workspace as workspace_module
    from automated_security_helper.cli.mcp.source_delivery import (
        SourceDeliveryBusyError,
    )

    source = _upload(
        {
            "dev.code-workspace": json.dumps({"folders": [{"path": "app"}]}),
            "app/main.py": "x = 1\n",
        }
    )
    attempts: List[Any] = []

    def deliver_during_the_scan(plan: Any, settings: Any) -> Any:
        try:
            _upload({"ash.yaml": "project_name: swapped\n"})
            attempts.append("delivered")
        except SourceDeliveryBusyError:
            attempts.append("refused")
        raise _StopAfterResolution

    with patch.object(workspace_module, "execute_workspace", deliver_during_the_scan):
        asyncio.run(
            workspace_module.mcp_scan_workspace(
                str(source / "dev.code-workspace"), session_id=SESSION
            )
        )
    assert attempts == ["refused"]


# ---------------------------------------------------------------------------
# Third review: unreadable policies refuse only delivered configs; offline env
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("profile_problem", ["clash", "unregistered"])
def test_an_unreadable_policy_does_not_refuse_a_scan_of_operator_files(
    _server, profile_problem: str
) -> None:
    from automated_security_helper.cli import mcp_tools

    if profile_problem == "clash":
        _bind_profile(
            _server["tmp"],
            "reporters:\n  bedrock-summary: {}\n  bedrock-summary-reporter: {}\n",
        )
    else:
        _bind_profile(_server["tmp"], "project_name: profile\n")
        clear_profile_registry()
    started: List[Any] = []

    async def not_started(**kwargs: Any) -> None:
        started.append(kwargs)

    with patch.object(mcp_tools, "_run_scan_async", not_started):
        result = asyncio.run(
            mcp_tools.mcp_scan_directory(
                str(_server["target"]), config_path=None, session_id=SESSION
            )
        )
    assert result["success"] is True, result
    assert len(started) == 1


def test_an_unreadable_policy_refuses_a_delivered_config_with_its_own_type(
    _server,
) -> None:
    from automated_security_helper.cli.mcp_tools import mcp_scan_directory

    _bind_profile(_server["tmp"], "project_name: profile\n")
    clear_profile_registry()
    source = _upload({".ash/.ash.yaml": "project_name: delivered\n"})
    result = asyncio.run(
        mcp_scan_directory(str(source), config_path=None, session_id=SESSION)
    )
    assert result["success"] is False, result
    assert result["error_type"] == "config_policy_unreadable", result


def test_a_waiting_workspace_scan_sets_offline_only_once_it_holds_the_lock(
    _server, monkeypatch
) -> None:
    import os
    import threading
    from types import SimpleNamespace

    from automated_security_helper.cli.mcp import workspace as workspace_module
    from automated_security_helper.cli.mcp.sessions import get_default_registry

    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    seen: List[Any] = []
    monkeypatch.setattr(
        workspace_module,
        "execute_workspace",
        lambda plan, settings: seen.append(os.environ.get("ASH_OFFLINE")),
    )
    lock = get_default_registry().get_or_create(SESSION).lock
    lock.acquire()
    worker = threading.Thread(
        target=workspace_module._under_session_lock,
        args=(SESSION, None, SimpleNamespace(offline=True)),
    )
    worker.start()
    try:
        worker.join(timeout=0.5)
        assert worker.is_alive(), "the workspace scan did not wait for the lock"
        assert "ASH_OFFLINE" not in os.environ
    finally:
        lock.release()
    worker.join(timeout=10)
    assert seen == ["YES"]
    assert "ASH_OFFLINE" not in os.environ


# ---------------------------------------------------------------------------
# Fourth review: client ignore paths reach the SARIF step; broken trusted config
# ---------------------------------------------------------------------------


def test_a_client_supplied_ignore_path_does_not_keep_files_from_the_scanners(
    tmp_path,
) -> None:
    """Scanners and converters skip only the operator's ignore paths.

    The client's are applied where results are suppressed, which keeps and marks
    each finding they hide; skipping the files first would leave nothing to keep.
    """
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator

    source = tmp_path / "src"
    source.mkdir()
    supplied = AshConfig.model_validate(
        {
            "global_settings": {
                "ignore_paths": [
                    {"path": "operator/**", "reason": "operator"},
                    {"path": "client/**", "reason": "client", "client_supplied": True},
                ]
            }
        }
    )
    orchestrator = ASHScanOrchestrator.create(
        source_dir=source,
        output_dir=tmp_path / "out",
        resolved_config=supplied,
        no_cleanup=False,
        metadata=None,
        ash_plugin_modules=[],
    )
    passed = [p.path for p in orchestrator.execution_engine._global_ignore_paths]
    assert passed == ["operator/**"]
    assert [p.path for p in orchestrator.config.global_settings.ignore_paths] == [
        "operator/**",
        "client/**",
    ]


def test_a_broken_default_config_refuses_only_a_delivered_config_and_never_hangs(
    _server,
) -> None:
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.core.resource_management.scan_registry import (
        ScanRegistry,
    )

    operator = _server["tmp"] / "operator" / "ash.yaml"
    operator.write_text("fail_on_findings: [not, a, bool]\n", encoding="utf-8")
    source = _upload({".ash/.ash.yaml": "project_name: delivered\n"})

    refused = asyncio.run(
        mcp_tools.mcp_scan_directory(str(source), config_path=None, session_id=SESSION)
    )
    assert refused["success"] is False, refused
    assert refused["error_type"] == "config_policy_unreadable", refused

    # Called directly, the scan's entry is closed rather than left PENDING.
    target = _server["target"]
    output = target / ".ash" / "ash_output"
    output.mkdir(parents=True, exist_ok=True)
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(source), output_directory=str(output)
    )
    with patch.object(mcp_tools, "get_scan_registry", return_value=registry):
        with patch.object(
            mcp_tools, "_session_client_rules", side_effect=RuntimeError("unreadable")
        ):
            asyncio.run(
                mcp_tools._run_scan_async(
                    scan_id=scan_id,
                    directory_path=str(source),
                    output_dir=str(output),
                    severity_threshold="MEDIUM",
                    config_path=None,
                    session_id=SESSION,
                )
            )
    assert registry.get_scan(scan_id).status.value == "failed"


def test_a_policy_that_cannot_be_read_refuses_only_scans_with_a_delivered_config(
    _server,
) -> None:
    from automated_security_helper.cli.mcp import profile_registry
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.core.exceptions import (
        ASHConfigPolicyUnreadableError,
    )

    source = _upload({".ash/.ash.yaml": "project_name: delivered\n"})
    with patch.object(
        profile_registry, "session_profile_entry", side_effect=OSError("gone")
    ):
        plain = _scan_resolution(_server["target"], None)
        delivered = _scan_resolution(source, None)
    assert isinstance(plain, AshConfig), plain
    assert plain.project_name == "operator"
    assert isinstance(delivered, ASHConfigPolicyUnreadableError), delivered
    assert "gone" in str(delivered)
