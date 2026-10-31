# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A value a client patched into its session profile is the client's.

``select_profile`` takes ``patch_ops`` or ``override_yaml`` for the keys the
operator's ``runtime_overrides`` allowlist permits. The allowlist decides which
keys a client may change; it does not make the client's value the operator's.
So a patched profile is written to the session's ``client-config/`` directory,
which ``config_is_client_supplied`` counts as the client's, and the trusted base
every consumer resolves it against is the registered profile, written unpatched
to the session's ``config/`` directory. A profile bound without a patch stays in
``config/`` and is the operator's, as before.

The workspace tools' ``config_overrides`` are the other way a client changes a
config under the same allowlist, and the two routes get the same rules.

Single-directory scans go through the real ``_run_scan_async``, ``run_ash_scan``
and orchestrator and stop inside ``resolve_config``. Workspace scans go through
the real ``mcp_scan_workspace`` up to ``execute_workspace``, and the project's
config is then resolved with ``execution._project_config_with_policy``, the
function ``execute_workspace`` resolves it with.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from unittest.mock import patch

import pytest
import yaml

from automated_security_helper.cli.mcp.profile_registry import (
    clear_profile_registry,
    clear_all_session_state,
    register_profiles,
    resolve_session_config_path,
    set_profile_registry,
)
from automated_security_helper.cli.mcp.sandbox import (
    config_is_client_supplied,
    session_sandbox,
)
from automated_security_helper.config.ash_config import AshConfig

pytestmark = pytest.mark.unit

SESSION = "client-1"

TRIVY_KEY = "scanners.trivy-repo.options.ignore_file"


class _QuietLogger:
    """Stands in for ``_setup_logger``'s logger, which configures global handlers."""

    def __getattr__(self, name: str) -> Callable[..., None]:
        return lambda *args, **kwargs: None


class _StopAfterResolution(Exception):
    pass


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A workspace root, a scan root, and a checkout outside both."""
    scan_root = tmp_path / "scan-root"
    target = scan_root / "target"
    target.mkdir(parents=True)
    other = tmp_path / "other-checkout"
    other.mkdir()
    (other / ".trivyignore").write_text("CVE-2020-0001\n", encoding="utf-8")
    (other / "bandit.yaml").write_text("skips: [B101]\n", encoding="utf-8")
    operator = tmp_path / "operator"
    operator.mkdir()
    (operator / "bandit.yaml").write_text("skips: []\n", encoding="utf-8")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(scan_root))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    clear_profile_registry()
    clear_all_session_state()
    yield {
        "tmp": tmp_path,
        "scan_root": scan_root,
        "target": target,
        "other": other,
        "operator": operator,
    }
    clear_profile_registry()
    clear_all_session_state()


@pytest.fixture
def isolated_registry(monkeypatch: pytest.MonkeyPatch):
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )

    fresh = scan_registry_module.ScanRegistry()
    monkeypatch.setattr(scan_registry_module, "_scan_registry", fresh)
    return fresh


@pytest.fixture
def executions(monkeypatch: pytest.MonkeyPatch) -> List[Tuple[Any, Any]]:
    """Record the plan and settings ``execute_workspace`` is handed, then stop."""
    from automated_security_helper.cli.mcp import workspace as workspace_module
    from automated_security_helper.workspace import execution as execution_module

    calls: List[Tuple[Any, Any]] = []

    def _record(plan: Any, settings: Any, **kwargs: Any) -> Any:
        calls.append((plan, settings))
        raise _StopAfterResolution

    monkeypatch.setattr(execution_module, "execute_workspace", _record)
    if hasattr(workspace_module, "execute_workspace"):
        monkeypatch.setattr(workspace_module, "execute_workspace", _record)
    return calls


def _register(_server: Dict[str, Path], document: Dict[str, Any], name: str = "op"):
    path = _server["operator"] / f"{name}.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    set_profile_registry(register_profiles([f"{name}={path}"]))


def _policy(allowed: List[str], denied: Optional[List[str]] = None) -> Dict[str, Any]:
    overrides: Dict[str, Any] = {"enabled": True, "allowed_paths": allowed}
    if denied is not None:
        # The list as written: an edited list otherwise adds to the defaults,
        # which deny the keys these tests let the client patch.
        overrides["denied_paths"] = denied
        overrides["replace_default_denied_paths"] = True
    return {"mcp": {"runtime_overrides": overrides}}


def _bind(session: str, **kwargs: Any) -> str:
    from automated_security_helper.cli.mcp_tools import mcp_select_profile

    result = mcp_select_profile("op", session_id=session, **kwargs)
    assert result["success"] is True, result
    bound = resolve_session_config_path(session)
    assert bound == result["config_path"]
    return bound


def _scan_outcome(target: Path, session: str) -> Any:
    """Resolve what a scan of ``target`` resolves, with the config the session bound.

    The config path is the one ``run_ash_scan`` (``cli/mcp_server.py``) hands the
    scan when the caller names none.
    """
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.config import resolve_config as rc
    from automated_security_helper.core import orchestrator
    from automated_security_helper.core.resource_management import (
        scan_management as management,
    )
    from automated_security_helper.core.resource_management.scan_registry import (
        ScanRegistry,
    )
    from automated_security_helper.interactions import run_ash_scan as ras

    config_path = resolve_session_config_path(session)
    assert config_path is not None
    resolved: List[Any] = []
    real = rc.resolve_config

    def recording(*args: Any, **kwargs: Any) -> AshConfig:
        try:
            resolved.append(real(*args, **kwargs))
        except Exception as exc:  # noqa: BLE001 -- the outcome under test
            resolved.append(exc)
        raise _StopAfterResolution

    output = target / ".ash" / "ash_output"
    output.mkdir(parents=True, exist_ok=True)
    registry = ScanRegistry()
    # Registered for the session, as mcp_scan_directory registers a scan
    # (session_id=_scan_owner(session_id)). The exemption for the scan's own copy
    # of the session's profile asks the registry whether THIS session holds the
    # scan (scan_management.session_holds_scan: another session's scan answers as
    # an id never issued). A scan registered with no owner belongs to the stdio
    # session, so the copy the scan loads read as the client's and the
    # registered profile's grants were dropped.
    scan_id = registry.register_scan(
        directory_path=str(target),
        output_directory=str(output),
        session_id=session,
    )
    with (
        patch.object(ras, "_setup_logger", lambda opts: _QuietLogger()),
        patch.object(orchestrator, "resolve_config", recording),
        patch.object(mcp_tools, "get_scan_registry", return_value=registry),
        # The scan's exemption for its own copy of the session's profile
        # (sandbox._is_a_live_scan_copy_of_this_sessions_file, through
        # scan_management.session_holds_scan) reads the registry through
        # scan_management, not through mcp_tools' handle. With only the
        # handle patched, the scan registered in a registry the exemption
        # never saw. Both handles are needed, and so is the owner above.
        patch.object(management, "get_scan_registry", return_value=registry),
    ):
        asyncio.run(
            mcp_tools._run_scan_async(
                scan_id=scan_id,
                directory_path=str(target),
                output_dir=str(output),
                severity_threshold="MEDIUM",
                config_path=config_path,
                session_id=session,
            )
        )
    assert len(resolved) == 1, "the scan never reached config resolution"
    return resolved[0]


def _scanned(target: Path, session: str) -> AshConfig:
    outcome = _scan_outcome(target, session)
    assert isinstance(outcome, AshConfig), outcome
    return outcome


def _workspace(scan_root: Path) -> Path:
    root = scan_root / "ws"
    (root / "app").mkdir(parents=True, exist_ok=True)
    (root / "app" / "main.py").write_text("x = 1\n", encoding="utf-8")
    definition = root / "dev.code-workspace"
    definition.write_text(json.dumps({"folders": [{"path": "app"}]}))
    return definition


def _workspace_config(
    scan_root: Path,
    session: str,
    executions: List[Tuple[Any, Any]],
    **kwargs: Any,
) -> AshConfig:
    """The config a workspace scan resolves for its one project."""
    from automated_security_helper.cli.mcp.workspace import mcp_scan_workspace
    from automated_security_helper.workspace.execution import (
        _project_config_with_policy,
    )

    before = len(executions)
    response = asyncio.run(
        mcp_scan_workspace(str(_workspace(scan_root)), session_id=session, **kwargs)
    )
    assert len(executions) == before + 1, response
    plan, settings = executions[-1]
    (project,) = plan.active_projects
    return _project_config_with_policy(project, settings)


def _resolved(
    route: str,
    _server: Dict[str, Path],
    session: str,
    executions: List[Tuple[Any, Any]],
) -> AshConfig:
    if route == "scan":
        return _scanned(_server["target"], session)
    return _workspace_config(_server["scan_root"], session, executions)


def _options(config: AshConfig, scanner: str) -> Dict[str, Any]:
    section = config.get_plugin_config("scanner", scanner) or {}
    if not isinstance(section, dict):
        section = section.model_dump()
    return dict(section.get("options") or {})


# ---------------------------------------------------------------------------
# 1. Parity: select_profile's patch and the workspace config_overrides
# ---------------------------------------------------------------------------


def _trivy_profile() -> Dict[str, Any]:
    return {
        "project_name": "operator",
        "scanners": {"trivy-repo": {"enabled": True, "options": {}}},
        "global_settings": _policy(["/scanners/trivy-repo/options/ignore_file"]),
    }


def _trivy_treatment(config: AshConfig) -> Tuple[Any, List[Any], List[str]]:
    notes = [w for w in config._resolution_warnings if TRIVY_KEY in w]
    exclusions = [e.model_dump() for e in config._client_scanner_exclusions]
    return _options(config, "trivy-repo").get("ignore_file"), exclusions, notes


def test_a_patched_tool_path_gets_the_treatment_a_config_override_gets(
    _server, isolated_registry, executions
) -> None:
    """The same allowlisted change, through each route, is the client's both times.

    The ignore file is in another checkout: outside the tree being scanned, and
    not delivered. A client's ignore file is not passed to trivy and is read only
    from inside the scanned tree, so neither route may hand it to trivy.
    """
    _register(_server, _trivy_profile())
    ignore_file = str(_server["other"] / ".trivyignore")

    _bind(
        "patched",
        patch_ops=[
            {
                "op": "add",
                "path": "/scanners/trivy-repo/options/ignore_file",
                "value": ignore_file,
            }
        ],
    )
    through_patch = _workspace_config(_server["scan_root"], "patched", executions)

    _bind("overridden")
    through_override = _workspace_config(
        _server["scan_root"],
        "overridden",
        executions,
        config_overrides=[f"{TRIVY_KEY}={ignore_file}"],
    )

    patched, overridden = (
        _trivy_treatment(through_patch),
        _trivy_treatment(through_override),
    )
    assert patched == overridden
    assert patched[0] is None, (
        "trivy was handed an ignore file a client chose from another checkout"
    )
    assert patched[2], "the scan's warnings do not say the client's file was refused"


def test_a_patched_tool_path_is_the_clients_on_a_single_directory_scan(
    _server,
) -> None:
    _register(_server, _trivy_profile())
    ignore_file = str(_server["other"] / ".trivyignore")
    _bind(
        SESSION,
        patch_ops=[
            {
                "op": "add",
                "path": "/scanners/trivy-repo/options/ignore_file",
                "value": ignore_file,
            }
        ],
    )

    value, _exclusions, notes = _trivy_treatment(_scanned(_server["target"], SESSION))

    assert value is None
    assert notes


def test_an_override_yaml_value_is_the_clients_too(_server) -> None:
    document = _trivy_profile()
    _register(_server, document)
    ignore_file = str(_server["other"] / ".trivyignore")
    restated = dict(document)
    restated["scanners"] = {
        "trivy-repo": {"enabled": True, "options": {"ignore_file": ignore_file}}
    }
    bound = _bind(SESSION, override_yaml=yaml.safe_dump(restated))

    assert config_is_client_supplied(bound)
    value, _exclusions, notes = _trivy_treatment(_scanned(_server["target"], SESSION))
    assert value is None
    assert notes


# trivy-repo and semgrep are in the always-denied floor (ALWAYS_DENIED_PATHS). On
# every client route the floor leaves their exclusion options to resolution,
# which moves them out of the options, and still refuses anything else the
# change writes in their sections.


def _off_host_profile() -> Dict[str, Any]:
    return {
        "project_name": "operator",
        "scanners": {
            "trivy-repo": {"enabled": True, "options": {}},
            "semgrep": {"enabled": True, "options": {}},
        },
        "global_settings": _policy(
            ["/scanners/trivy-repo/options/**", "/scanners/semgrep/options/**"]
        ),
    }


@pytest.mark.parametrize("change", ["patch_ops", "override_yaml", "config_overrides"])
def test_a_change_to_an_off_host_scanners_other_option_is_still_refused(
    _server, isolated_registry, executions, change: str
) -> None:
    from automated_security_helper.cli.mcp_tools import mcp_select_profile
    from automated_security_helper.cli.mcp.workspace import mcp_scan_workspace

    document = _off_host_profile()
    _register(_server, document)
    ignore_file = str(_server["other"] / ".trivyignore")
    if change == "patch_ops":
        outcome: Any = mcp_select_profile(
            "op",
            session_id=SESSION,
            patch_ops=[
                {
                    "op": "add",
                    "path": f"/{TRIVY_KEY.replace('.', '/')}",
                    "value": ignore_file,
                },
                {
                    "op": "replace",
                    "path": "/scanners/trivy-repo/options/scanners",
                    "value": ["vuln"],
                },
            ],
        )
    elif change == "override_yaml":
        restated = yaml.safe_load(yaml.safe_dump(document))
        restated["scanners"]["trivy-repo"]["options"] = {
            "ignore_file": ignore_file,
            "scanners": ["vuln"],
        }
        outcome = mcp_select_profile(
            "op", session_id=SESSION, override_yaml=yaml.safe_dump(restated)
        )
    else:
        _bind(SESSION)
        outcome = asyncio.run(
            mcp_scan_workspace(
                str(_workspace(_server["scan_root"])),
                session_id=SESSION,
                config_overrides=[
                    f"{TRIVY_KEY}={ignore_file}",
                    'scanners.trivy-repo.options.scanners=["vuln"]',
                ],
            )
        )
        assert not executions, "the workspace scan ran"

    assert outcome.get("success") is False, outcome
    assert "/scanners/trivy-repo/options/scanners" in str(outcome)
    assert "ignore_file" not in str(outcome).replace(ignore_file, "")


@pytest.mark.parametrize(
    "op",
    [
        pytest.param(
            {
                "op": "add",
                "path": "/scanners/semgrep/options/exclude/-",
                "value": {"x": 1},
            },
            id="semgrep-dict-entry",
        ),
        pytest.param(
            {
                "op": "replace",
                "path": "/scanners/semgrep/options/exclude",
                "value": "x",
            },
            id="semgrep-not-a-list",
        ),
        pytest.param(
            {
                "op": "add",
                "path": "/scanners/npm-audit/options/exclude",
                "value": ["x"],
            },
            id="npm-audit-has-no-move",
        ),
        pytest.param(
            {"op": "remove", "path": "/scanners/semgrep/options/exclude"},
            id="semgrep-remove",
        ),
    ],
)
def test_a_patch_the_move_does_not_take_is_still_refused(_server, op) -> None:
    """Only an add or replace whose value the move takes out whole is left to it."""
    from automated_security_helper.cli.mcp_tools import mcp_select_profile

    document = _off_host_profile()
    document["scanners"]["npm-audit"] = {"enabled": True, "options": {}}
    document["global_settings"] = _policy(["/scanners/**"])
    _register(_server, document)

    outcome = mcp_select_profile("op", session_id=SESSION, patch_ops=[op])

    assert outcome.get("success") is False, outcome


@pytest.mark.parametrize("change", ["patch_ops", "override_yaml", "config_overrides"])
def test_a_patched_exclusion_leaves_no_client_value_in_an_off_host_scanners_options(
    _server, isolated_registry, executions, change: str
) -> None:
    """semgrep scans what the client listed, and its findings there are marked."""
    document = _off_host_profile()
    _register(_server, document)
    if change == "patch_ops":
        _bind(
            SESSION,
            patch_ops=[
                {
                    "op": "add",
                    "path": "/scanners/semgrep/options/exclude/-",
                    "value": "client-dir",
                }
            ],
        )
        config = _scanned(_server["target"], SESSION)
    elif change == "override_yaml":
        restated = yaml.safe_load(yaml.safe_dump(document))
        restated["scanners"]["semgrep"]["options"] = {
            "exclude": ["*-converted.py", "*_report_result.txt", "client-dir"]
        }
        _bind(SESSION, override_yaml=yaml.safe_dump(restated))
        config = _scanned(_server["target"], SESSION)
    else:
        _bind(SESSION)
        config = _workspace_config(
            _server["scan_root"],
            SESSION,
            executions,
            config_overrides=['scanners.semgrep.options.exclude+=["client-dir"]'],
        )

    assert "client-dir" not in _options(config, "semgrep").get("exclude", [])
    assert [
        (item.scanner, item.option, item.pattern)
        for item in config._client_scanner_exclusions
    ] == [("semgrep", "exclude", "client-dir")]


# ---------------------------------------------------------------------------
# 2. A patched suppression or ignore path is marked client_supplied
# ---------------------------------------------------------------------------

_OPERATOR_SUPPRESSION = {
    "path": "src/vendored.py",
    "rule_id": "B101",
    "reason": "operator",
    "expiration": "2099-12-31",
}
_OPERATOR_IGNORE = {"path": "operator-ignored/**", "reason": "operator"}
_CLIENT_SUPPRESSION = {"path": "src/app.py", "rule_id": "B102", "reason": "client"}
_CLIENT_IGNORE = {"path": "client-ignored/**", "reason": "client"}


def _suppressions_profile() -> Dict[str, Any]:
    settings = _policy(
        ["/global_settings/suppressions/**", "/global_settings/ignore_paths/**"],
        denied=["/fail_on_findings"],
    )
    settings["suppressions"] = [_OPERATOR_SUPPRESSION]
    settings["ignore_paths"] = [_OPERATOR_IGNORE]
    return {"project_name": "operator", "global_settings": settings}


def _marks(config: AshConfig) -> Dict[str, bool]:
    entries = list(config.global_settings.suppressions) + list(
        config.global_settings.ignore_paths
    )
    return {entry.path: entry.client_supplied for entry in entries}


@pytest.mark.parametrize("route", ["scan", "workspace"])
def test_a_patched_suppression_and_ignore_path_are_marked(
    _server, isolated_registry, executions, route: str
) -> None:
    _register(_server, _suppressions_profile())
    _bind(
        SESSION,
        patch_ops=[
            {
                "op": "add",
                "path": "/global_settings/suppressions/-",
                "value": _CLIENT_SUPPRESSION,
            },
            {
                "op": "add",
                "path": "/global_settings/ignore_paths/-",
                "value": _CLIENT_IGNORE,
            },
        ],
    )

    marks = _marks(_resolved(route, _server, SESSION, executions))

    assert marks == {
        "src/vendored.py": False,
        "operator-ignored/**": False,
        "src/app.py": True,
        "client-ignored/**": True,
    }


@pytest.mark.parametrize("route", ["scan", "workspace"])
def test_an_unpatched_profiles_entries_are_not_marked(
    _server, isolated_registry, executions, route: str
) -> None:
    _register(_server, _suppressions_profile())
    _bind(SESSION)

    marks = _marks(_resolved(route, _server, SESSION, executions))

    assert marks == {"src/vendored.py": False, "operator-ignored/**": False}


def test_a_patched_profile_whose_policy_denies_its_own_suppressions_still_scans(
    _server,
) -> None:
    """The patched copy is checked as a client's file, and the profile's own entries pass.

    Every value the copy repeats from the registered profile equals the trusted
    base's, so only what the patch changed is the client's. A policy that denies
    suppressions must not refuse the operator's own suppressions in the copy.
    """
    document = _suppressions_profile()
    document["global_settings"]["mcp"]["runtime_overrides"] = {
        "enabled": True,
        "allowed_paths": ["/project_name"],
        "denied_paths": [
            "/fail_on_findings",
            "/global_settings/suppressions",
            "/global_settings/ignore_paths",
        ],
    }
    _register(_server, document)
    _bind(SESSION, patch_ops=[{"op": "replace", "path": "/project_name", "value": "x"}])

    config = _scanned(_server["target"], SESSION)

    assert config.project_name == "x"
    assert _marks(config) == {"src/vendored.py": False, "operator-ignored/**": False}


# ---------------------------------------------------------------------------
# 3. The trusted base is the registered profile
# ---------------------------------------------------------------------------

_GRANTS = {
    "mode": "firejail",
    "network_scanners": ["grype"],
    "extra_read_paths": ["/opt/ca"],
}


@pytest.mark.parametrize("route", ["scan", "workspace"])
def test_a_patched_profile_keeps_the_registered_profiles_sandbox_grants(
    _server, isolated_registry, executions, route: str
) -> None:
    """Restrict-only against the operator's grants, not against the defaults."""
    _register(
        _server,
        {
            "project_name": "operator",
            "sandbox": dict(_GRANTS),
            "global_settings": _policy(["/project_name"]),
        },
    )
    _bind(SESSION, patch_ops=[{"op": "replace", "path": "/project_name", "value": "x"}])

    sandbox = _resolved(route, _server, SESSION, executions).sandbox

    assert sandbox.mode == "firejail"
    assert sandbox.network_scanners == ["grype"]
    assert sandbox.extra_read_paths == ["/opt/ca"]
    # The client's copy is restrict-only: its list limits the network rather
    # than granting it.
    assert sandbox.network_limit == ["grype"]


@pytest.mark.parametrize("route", ["scan", "workspace", "get_config"])
def test_a_patched_tool_config_file_falls_back_to_the_registered_profiles(
    _server, isolated_registry, executions, route: str
) -> None:
    """The trusted base is the profile as registered, not the patched copy and not the defaults.

    The operator lifts the default denial on bandit's ``config_file`` and
    allowlists it, so the patch is accepted. The value is still the client's, so
    the scan uses the registered profile's file.
    """
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    operator_file = str(_server["operator"] / "bandit.yaml")
    _register(
        _server,
        {
            "project_name": "operator",
            "scanners": {"bandit": {"options": {"config_file": operator_file}}},
            "global_settings": _policy(
                ["/scanners/bandit/options/config_file"], denied=["/fail_on_findings"]
            ),
        },
    )
    bound = _bind(
        SESSION,
        patch_ops=[
            {
                "op": "replace",
                "path": "/scanners/bandit/options/config_file",
                "value": str(_server["other"] / "bandit.yaml"),
            }
        ],
    )

    if route == "get_config":
        shown = mcp_get_config(config_path=bound, session_id=SESSION)
        value = shown["scanners"]["bandit"]["options"]["config_file"]
    else:
        config = _resolved(route, _server, SESSION, executions)
        value = _options(config, "bandit").get("config_file")

    assert value == operator_file


def test_get_config_shows_a_patched_profile_with_the_registered_grants(
    _server,
) -> None:
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    _register(
        _server,
        {
            "project_name": "operator",
            "sandbox": dict(_GRANTS),
            "global_settings": _policy(["/project_name"]),
        },
    )
    bound = _bind(
        SESSION, patch_ops=[{"op": "replace", "path": "/project_name", "value": "x"}]
    )

    shown = mcp_get_config(config_path=bound, session_id=SESSION)

    assert shown["project_name"] == "x"
    # The full dump also shows the two scanner grants the profile leaves at
    # their defaults.
    assert shown["sandbox"] == {
        **_GRANTS,
        "read_path_scanners": [],
        "env_scanners": [],
    }


def test_the_scan_pre_checks_and_validate_config_accept_a_patched_profile(
    _server,
) -> None:
    """The copy is the client's, and what the allowlist let it change passes the client checks.

    The patched copy is a full dump, which validate_config reads as setting
    internal fields, and that is not about who wrote it. The unpatched copy holds
    only the fields the profile sets, so it reports none. What must not appear for
    either is a refusal by the client rules.
    """
    from automated_security_helper.cli import mcp_tools

    _register(_server, _suppressions_profile())
    unpatched = mcp_tools.mcp_validate_config(
        config_path=_bind("unpatched"), session_id="unpatched"
    )
    bound = _bind(
        SESSION,
        patch_ops=[
            {
                "op": "add",
                "path": "/global_settings/suppressions/-",
                "value": _CLIENT_SUPPRESSION,
            }
        ],
    )
    target = _server["target"]

    assert (
        mcp_tools._client_config_denial(bound, target, SESSION, "scan_directory")
        is None
    )
    validated = mcp_tools.mcp_validate_config(config_path=bound, session_id=SESSION)

    def kinds(result: Dict[str, Any]) -> List[Tuple[str, str]]:
        return sorted((error["type"], error["field"]) for error in result["errors"])

    assert kinds(unpatched) == []
    # Each one names an internal field the full dump writes. The validator files
    # those under the yaml reporter as yaml_parse_error, so the type is not enough.
    assert [
        error
        for error in validated["errors"]
        if "internal field" not in error["message"]
        and "internal-only field" not in error["message"]
    ] == []
    assert not {kind for kind, _field in kinds(validated)} & {
        "denied_by_runtime_policy",
        mcp_tools.CONFIG_INPUT_NOT_PERMITTED,
        mcp_tools.CONFIG_ENV_NOT_RESOLVED,
        mcp_tools.CONFIG_POLICY_UNREADABLE,
    }


# ---------------------------------------------------------------------------
# 4. Where each binding lives
# ---------------------------------------------------------------------------


def _client_copy(session: str) -> Path:
    root = session_sandbox(session).root
    assert root is not None
    return root / "client-config" / "ash.yaml"


def _operator_copy(session: str) -> Path:
    return session_sandbox(session).config_dir / "ash.yaml"


_OFF_HOST_REPORTERS = (
    "aws-security-hub",
    "bedrock-summary-reporter",
    "cloudwatch-logs",
    "s3",
)


def _reporter_enabled(config: AshConfig, reporter: str) -> Any:
    from automated_security_helper.config.reporter_trust import (
        REPORTER_ENABLED_DEFAULTS,
    )

    section = config.get_plugin_config("reporter", reporter) or {}
    if not isinstance(section, dict):
        section = section.model_dump()
    return section.get("enabled", REPORTER_ENABLED_DEFAULTS[reporter])


@pytest.mark.parametrize("change", ["patch_ops", "override_yaml", "config_overrides"])
@pytest.mark.parametrize("reporter", _OFF_HOST_REPORTERS)
def test_a_clients_enabled_false_is_accepted_and_takes_no_effect(
    _server, isolated_registry, executions, reporter: str, change: str
) -> None:
    """Whether an off-host reporter runs is the operator's in both directions. A
    client's ``enabled: false`` asks for nothing beyond the profile, so it is not
    refused on any route, but the scan runs the reporter as the profile has it:
    select_profile's patch_ops and override_yaml on a single-directory scan, and
    the workspace tools' config_overrides on a workspace scan."""
    document = {
        "project_name": "operator",
        "global_settings": _policy(["/**"]),
        "reporters": {reporter: {"enabled": True}},
    }
    _register(_server, document)
    if change == "patch_ops":
        op = {"op": "replace", "path": f"/reporters/{reporter}/enabled"}
        _bind(SESSION, patch_ops=[{**op, "value": False}])
        config = _scanned(_server["target"], SESSION)
    elif change == "override_yaml":
        restated = yaml.safe_load(yaml.safe_dump(document))
        restated["reporters"][reporter]["enabled"] = False
        _bind(SESSION, override_yaml=yaml.safe_dump(restated))
        config = _scanned(_server["target"], SESSION)
    else:
        _bind(SESSION)
        config = _workspace_config(
            _server["scan_root"],
            SESSION,
            executions,
            config_overrides=[f"reporters.{reporter}.enabled=false"],
        )

    assert _reporter_enabled(config, reporter) is True


def test_a_profile_bound_without_a_patch_is_the_operators(_server) -> None:
    _register(
        _server,
        {
            "project_name": "operator",
            "sandbox": dict(_GRANTS),
            "global_settings": _policy(["/project_name"]),
        },
    )

    bound = _bind(SESSION)

    assert bound == _operator_copy(SESSION).as_posix()
    assert not config_is_client_supplied(bound)
    assert not _client_copy(SESSION).exists()
    sandbox = _scanned(_server["target"], SESSION).sandbox
    assert sandbox.network_scanners == ["grype"]
    assert sandbox.network_limit is None


def test_an_empty_patch_is_no_patch(_server) -> None:
    _register(_server, {"global_settings": _policy(["/project_name"])})

    bound = _bind(SESSION, patch_ops=[])

    assert bound == _operator_copy(SESSION).as_posix()
    assert not _client_copy(SESSION).exists()


def test_a_patched_profile_lives_in_client_config_beside_the_registered_one(
    _server,
) -> None:
    _register(
        _server, {"project_name": "operator", "global_settings": _policy(["/**"])}
    )

    bound = _bind(
        SESSION, patch_ops=[{"op": "replace", "path": "/project_name", "value": "x"}]
    )

    assert bound == _client_copy(SESSION).as_posix()
    assert config_is_client_supplied(bound)
    assert yaml.safe_load(Path(bound).read_text("utf-8"))["project_name"] == "x"
    # The registered profile, unpatched, is the trusted base the scan reads.
    operator = yaml.safe_load(_operator_copy(SESSION).read_text("utf-8"))
    assert operator["project_name"] == "operator"
    assert not config_is_client_supplied(_operator_copy(SESSION))


def test_rebinding_without_a_patch_removes_the_clients_copy(_server) -> None:
    _register(
        _server, {"project_name": "operator", "global_settings": _policy(["/**"])}
    )
    _bind(SESSION, patch_ops=[{"op": "replace", "path": "/project_name", "value": "x"}])
    assert _client_copy(SESSION).is_file()

    bound = _bind(SESSION)

    assert bound == _operator_copy(SESSION).as_posix()
    assert not _client_copy(SESSION).exists()


def test_the_session_sandbox_permits_reading_its_own_client_copy(_server) -> None:
    from automated_security_helper.cli.mcp.sandbox import validate_config_input

    _register(
        _server, {"project_name": "operator", "global_settings": _policy(["/**"])}
    )
    bound = _bind(
        SESSION, patch_ops=[{"op": "replace", "path": "/project_name", "value": "x"}]
    )

    assert session_sandbox(SESSION).permits_config(Path(bound).resolve())
    assert validate_config_input(bound, session_id=SESSION) is None
    refusal = validate_config_input(bound, session_id="client-2")
    assert refusal is not None


def test_a_per_call_workspace_profile_leaves_the_sessions_binding_alone(
    _server, isolated_registry, executions
) -> None:
    """A ``profile`` argument is for one call, so the session's files stay as bound."""
    from automated_security_helper.cli.mcp.workspace import mcp_resolve_workspace

    lenient = _server["operator"] / "lenient.yaml"
    lenient.write_text("project_name: lenient\n", encoding="utf-8")
    strict = _server["operator"] / "op.yaml"
    strict.write_text(
        yaml.safe_dump(
            {"project_name": "operator", "global_settings": _policy(["/**"])}
        ),
        encoding="utf-8",
    )
    set_profile_registry(register_profiles([f"op={strict}", f"lenient={lenient}"]))
    bound = _bind(
        SESSION, patch_ops=[{"op": "replace", "path": "/project_name", "value": "x"}]
    )
    files = {
        path: path.read_text("utf-8") for path in {Path(bound), _operator_copy(SESSION)}
    }

    response = asyncio.run(
        mcp_resolve_workspace(
            str(_workspace(_server["scan_root"])), session_id=SESSION, profile="lenient"
        )
    )

    assert response["success"] is True, response
    assert response["session_config_path"] not in {path.as_posix() for path in files}
    assert {path: path.read_text("utf-8") for path in files} == files
    assert resolve_session_config_path(SESSION) == bound


def test_a_patched_profile_whose_own_keys_match_a_value_pattern_still_scans(
    _server,
) -> None:
    """A mapping key the registered profile has is not the client's to be refused for.

    ``denied_value_patterns`` also match mapping keys. The patched copy repeats
    every key of the registered profile, so a pattern that matches one of the
    operator's own keys must not refuse a patch that never touched it.
    """
    document = {
        "project_name": "operator",
        "global_settings": _policy(["/project_name"]),
    }
    document["global_settings"]["mcp"]["runtime_overrides"]["denied_value_patterns"] = {
        "/scanners/**": "^excluded_paths$"
    }
    _register(_server, document)
    _bind(SESSION, patch_ops=[{"op": "replace", "path": "/project_name", "value": "x"}])

    assert _scanned(_server["target"], SESSION).project_name == "x"


def test_a_failed_rebind_leaves_the_previous_binding_and_its_trusted_base(
    _server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The operator copy is replaced only after the old client copy is gone."""
    from automated_security_helper.cli.mcp_tools import mcp_select_profile

    _register(
        _server, {"project_name": "operator", "global_settings": _policy(["/**"])}
    )
    bound = _bind(
        SESSION, patch_ops=[{"op": "replace", "path": "/project_name", "value": "x"}]
    )
    before = {
        path: path.read_text("utf-8")
        for path in (_client_copy(SESSION), _operator_copy(SESSION))
    }
    _register(_server, {"project_name": "rebound", "global_settings": _policy(["/**"])})
    real_unlink = Path.unlink

    def refusing_unlink(self: Path, missing_ok: bool = False) -> None:
        if self == _client_copy(SESSION):
            raise OSError("stand-in for a file that cannot be removed")
        real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", refusing_unlink)

    result = mcp_select_profile("op", session_id=SESSION)

    assert result["success"] is False
    assert {path: path.read_text("utf-8") for path in before} == before
    assert resolve_session_config_path(SESSION) == bound


def test_session_config_was_patched_is_decided_by_location(_server) -> None:
    """True for a patched binding's file, as named or through a link, and nothing else.

    Decided from where the file is, not from the session state, so the answer
    holds after the state is cleared, and agrees with config_is_client_supplied
    for a session's profiles.
    """
    from automated_security_helper.cli.mcp.profile_registry import (
        session_config_was_patched,
    )

    _register(
        _server, {"project_name": "operator", "global_settings": _policy(["/**"])}
    )
    unpatched = _bind("unpatched")
    patched = _bind(
        SESSION, patch_ops=[{"op": "replace", "path": "/project_name", "value": "x"}]
    )
    link = _server["tmp"] / "elsewhere" / "ash.yaml"
    link.parent.mkdir()
    link.symlink_to(patched)
    arbitrary = _server["operator"] / "op.yaml"

    clear_all_session_state()

    assert session_config_was_patched(patched)
    assert session_config_was_patched(Path(patched))
    assert session_config_was_patched(link)
    assert not session_config_was_patched(unpatched)
    assert not session_config_was_patched(_operator_copy(SESSION))
    assert not session_config_was_patched(arbitrary)
    for path in (patched, unpatched):
        assert session_config_was_patched(path) == config_is_client_supplied(path)
