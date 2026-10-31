# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config an MCP client uploaded is restrict-only for sandbox grants.

A client can deliver files into its session sandbox (a zip upload or a git clone)
and then name one of them as a scan's ``config_path``. The file's author is the
client, not the operator, so the scan resolves it with ``untrusted_config``: the
server's ``network_scanners`` and ``extra_read_paths`` apply, the file's
``network_scanners`` list is kept only as a limit, and its ``sandbox.mode``
cannot turn off or replace the mode the server's own config sets (``ASH_CONFIG``,
or the profile the session bound with ``select_profile``). A file that asks for
more than the server's settings give (a network for another scanner, another
readable path, a different mode) is refused, naming each such setting, rather
than resolved with them left out.

Each scan here targets a directory outside the upload, so the uploaded file is not
in the scanned tree and nothing but the new flag confines it.

The scans go through the real ``_run_scan_async``, ``run_ash_scan`` and
orchestrator, and stop inside ``resolve_config``: the wrapper below calls the real
function, records what it returned, and raises so no scanner runs.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import zipfile
from pathlib import Path
from typing import Any, Callable, Dict, List
from unittest.mock import patch

import pytest

from automated_security_helper.cli.mcp.profile_registry import (
    clear_profile_registry,
    clear_all_session_state,
    register_profiles,
    resolve_session_config_path,
    set_profile_registry,
)
from automated_security_helper.cli.mcp.sandbox import session_sandbox
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.utils.sandbox.policy import DEFAULT_ENVIRONMENT

pytestmark = pytest.mark.unit

SESSION = "client-1"

GRANTS_AND_OFF = (
    "project_name: uploaded\n"
    "sandbox:\n"
    "  mode: 'off'\n"
    "  network_scanners: [checkov]\n"
    "  extra_read_paths: ['/']\n"
)


class _QuietLogger:
    """Stands in for ``_setup_logger``'s logger, which configures global handlers."""

    def __getattr__(self, name: str) -> Callable[..., None]:
        return lambda *args, **kwargs: None


class _StopAfterResolution(Exception):
    pass


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A server with a workspace root, a scan root, and an operator ASH_CONFIG."""
    workspace = tmp_path / "workspaces"
    scan_root = tmp_path / "scan-root"
    target = scan_root / "target"
    target.mkdir(parents=True)
    operator = tmp_path / "operator" / "ash.yaml"
    operator.parent.mkdir()
    operator.write_text("sandbox:\n  mode: bwrap\n", encoding="utf-8")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(scan_root))
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    clear_profile_registry()
    clear_all_session_state()
    yield {"workspace": workspace, "target": target, "tmp": tmp_path}
    clear_profile_registry()
    clear_all_session_state()


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
    """Register an operator profile and bind it to the session; return its path."""
    from automated_security_helper.cli.mcp_tools import mcp_select_profile

    path = tmp_path / "operator" / "profile.yaml"
    path.write_text(text, encoding="utf-8")
    set_profile_registry(register_profiles([f"op={path}"]))
    result = mcp_select_profile("op", session_id=SESSION)
    assert result["success"] is True, result
    bound = resolve_session_config_path(SESSION)
    assert bound is not None
    return bound


def _scan_outcome(target: Path, config_path: str) -> Any:
    """Start an MCP scan; return the config it resolved, or the error resolving raised."""
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.config import resolve_config as rc
    from automated_security_helper.core import orchestrator
    from automated_security_helper.core.resource_management.scan_registry import (
        ScanRegistry,
    )
    from automated_security_helper.interactions import run_ash_scan as ras

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
    assert len(resolved) == 1, "the scan never reached config resolution"
    return resolved[0]


def _resolved_by_scan(target: Path, config_path: str) -> AshConfig:
    """Start an MCP scan and return the config its orchestrator resolved."""
    outcome = _scan_outcome(target, config_path)
    assert isinstance(outcome, AshConfig), outcome
    return outcome


def _refused_by_scan(target: Path, config_path: str) -> str:
    """Start an MCP scan whose config is refused; return the refusal's text."""
    from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

    outcome = _scan_outcome(target, config_path)
    assert isinstance(outcome, ASHConfigFieldDeniedError), outcome
    return str(outcome)


# ---------------------------------------------------------------------------
# Which configs count as client-supplied
# ---------------------------------------------------------------------------


def test_uploaded_and_cloned_content_is_client_supplied(_server) -> None:
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied

    source = _upload({"ash.yaml": GRANTS_AND_OFF, "nested/other.yaml": "{}\n"})
    assert config_is_client_supplied(source / "ash.yaml")
    assert config_is_client_supplied(source / "nested" / "other.yaml")
    # Anything else a client can reach in any session sandbox counts too.
    other_session = _server["workspace"] / "client-2" / "source" / "ash.yaml"
    assert config_is_client_supplied(other_session)


def test_server_written_and_operator_configs_are_not(_server) -> None:
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied

    bound = _bind_profile(_server["tmp"], "project_name: profile\n")
    assert Path(bound).parent == session_sandbox(SESSION).config_dir
    assert not config_is_client_supplied(bound)
    assert not config_is_client_supplied(_server["tmp"] / "operator" / "ash.yaml")
    assert not config_is_client_supplied(_server["target"] / ".ash" / ".ash.yaml")


# ---------------------------------------------------------------------------
# What a scan resolves
# ---------------------------------------------------------------------------


def test_an_upload_asking_for_more_than_the_server_gives_is_refused(_server) -> None:
    source = _upload({"ash.yaml": GRANTS_AND_OFF})

    refusal = _refused_by_scan(_server["target"], str(source / "ash.yaml"))

    for field in (
        "sandbox.network_scanners",
        "sandbox.extra_read_paths",
        "sandbox.mode",
    ):
        assert field in refusal, refusal


def test_an_upload_asking_for_no_more_than_the_server_scans(_server) -> None:
    source = _upload({"ash.yaml": "sandbox:\n  mode: bwrap\n  network_scanners: []\n"})

    config = _resolved_by_scan(_server["target"], str(source / "ash.yaml"))

    assert config.sandbox.mode == "bwrap"
    assert config.sandbox.network_scanners is None
    assert config.sandbox.extra_read_paths == []
    assert config.sandbox.network_limit == []


def test_an_uploaded_empty_network_list_still_removes_network(_server) -> None:
    source = _upload({"ash.yaml": "sandbox:\n  network_scanners: []\n"})

    config = _resolved_by_scan(_server["target"], str(source / "ash.yaml"))

    assert config.sandbox.network_limit == []


def test_the_bound_profile_is_the_trusted_base_for_an_upload(_server) -> None:
    _bind_profile(
        _server["tmp"],
        "sandbox:\n  mode: firejail\n  network_scanners: [grype]\n"
        "  extra_read_paths: ['/opt/ca']\n",
    )
    within = _upload(
        {
            "ash.yaml": "sandbox:\n  network_scanners: [grype]\n  extra_read_paths: ['/opt/ca']\n"
        }
    )

    config = _resolved_by_scan(_server["target"], str(within / "ash.yaml"))

    assert config.sandbox.mode == "firejail"
    assert config.sandbox.network_scanners == ["grype"]
    assert config.sandbox.extra_read_paths == ["/opt/ca"]
    assert config.sandbox.network_limit == ["grype"]


def test_an_upload_asking_beyond_the_bound_profile_is_refused(_server) -> None:
    _bind_profile(
        _server["tmp"], "sandbox:\n  mode: firejail\n  network_scanners: [grype]\n"
    )
    source = _upload({"ash.yaml": GRANTS_AND_OFF})

    refusal = _refused_by_scan(_server["target"], str(source / "ash.yaml"))

    assert "checkov" in refusal and "sandbox.mode" in refusal, refusal


def test_positive_control_the_registered_profile_still_grants(_server) -> None:
    bound = _bind_profile(
        _server["tmp"],
        "sandbox:\n  mode: firejail\n  network_scanners: [grype]\n"
        "  extra_read_paths: ['/opt/ca']\n",
    )

    config = _resolved_by_scan(_server["target"], bound)

    assert config.sandbox.mode == "firejail"
    assert config.sandbox.network_scanners == ["grype"]
    assert config.sandbox.extra_read_paths == ["/opt/ca"]
    assert config.sandbox.network_limit is None


def test_positive_control_an_operator_config_root_file_still_grants(
    _server, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_dir = _server["tmp"] / "policy"
    policy_dir.mkdir()
    policy = policy_dir / "ash.yaml"
    policy.write_text(GRANTS_AND_OFF, encoding="utf-8")
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(policy_dir))

    config = _resolved_by_scan(_server["target"], str(policy))

    assert config.sandbox.network_scanners == ["checkov"]
    assert config.sandbox.extra_read_paths == ["/"]
    assert config.sandbox.network_limit is None


# ---------------------------------------------------------------------------
# Where the flag cannot be honored, it is refused rather than dropped
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["container", "nix"])
def test_run_ash_scan_refuses_untrusted_config_outside_local_mode(
    tmp_path: Path, mode: str
) -> None:
    from automated_security_helper.core.enums import RunMode
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    with pytest.raises(ValueError, match="untrusted_config is applied only"):
        run_ash_scan(
            source_dir=str(tmp_path),
            output_dir=str(tmp_path / "out"),
            mode=RunMode(mode),
            untrusted_config=True,
        )


def test_the_orchestrator_refuses_untrusted_config_with_a_resolved_config(
    tmp_path: Path,
) -> None:
    from pydantic import ValidationError

    from automated_security_helper.core.orchestrator import ASHScanOrchestrator

    with pytest.raises(ValidationError, match="untrusted_config"):
        ASHScanOrchestrator(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            resolved_config=AshConfig(),
            untrusted_config=True,
        )


# ---------------------------------------------------------------------------
# get_config shows the sandbox section a scan would apply
# ---------------------------------------------------------------------------

_PROFILE_WITH_GRANTS = (
    "sandbox:\n  mode: firejail\n  network_scanners: [grype]\n"
    "  extra_read_paths: ['/opt/ca']\n"
)


def _shown(config_path: str) -> Dict[str, Any]:
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    result = mcp_get_config(config_path=config_path, session_id=SESSION)
    assert "sandbox" in result, result
    return result["sandbox"]


def test_get_config_refuses_an_upload_asking_for_more(_server) -> None:
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    source = _upload({"ash.yaml": GRANTS_AND_OFF})

    result = mcp_get_config(config_path=str(source / "ash.yaml"), session_id=SESSION)

    assert result.get("error_type") == "config_field_denied", result
    assert "sandbox" not in result


def test_get_config_shows_the_bound_profile_as_the_base_for_an_upload(
    _server,
) -> None:
    _bind_profile(_server["tmp"], _PROFILE_WITH_GRANTS)
    source = _upload({"ash.yaml": "sandbox:\n  network_scanners: [grype]\n"})
    uploaded = str(source / "ash.yaml")

    shown = _shown(uploaded)

    assert shown == {
        "mode": "firejail",
        "network_scanners": ["grype"],
        "extra_read_paths": ["/opt/ca"],
        "read_path_scanners": [],
        "env_scanners": [],
        "environment": list(DEFAULT_ENVIRONMENT),
    }
    assert shown == _resolved_by_scan(_server["target"], uploaded).sandbox.model_dump()


def test_get_config_still_shows_the_operator_profiles_grants(_server) -> None:
    bound = _bind_profile(_server["tmp"], _PROFILE_WITH_GRANTS)
    _upload({"README.md": "delivered source\n"})

    shown = _shown(bound)

    assert shown == {
        "mode": "firejail",
        "network_scanners": ["grype"],
        "extra_read_paths": ["/opt/ca"],
        "read_path_scanners": [],
        "env_scanners": [],
        "environment": list(DEFAULT_ENVIRONMENT),
    }
    assert shown == _resolved_by_scan(_server["target"], bound).sandbox.model_dump()


def test_get_config_discovering_an_uploaded_config_does_not_show_its_grants(
    _server,
) -> None:
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    _bind_profile(_server["tmp"], _PROFILE_WITH_GRANTS)
    source = _upload({".ash/.ash.yaml": "sandbox:\n  network_scanners: [grype]\n"})

    result = mcp_get_config(search_dir=str(source), session_id=SESSION)

    assert result["sandbox"] == {
        "mode": "firejail",
        "network_scanners": ["grype"],
        "extra_read_paths": ["/opt/ca"],
        "read_path_scanners": [],
        "env_scanners": [],
        "environment": list(DEFAULT_ENVIRONMENT),
    }


@pytest.mark.parametrize("client", [False, True])
def test_the_orchestrator_passes_on_whose_overrides_they_are(
    tmp_path: Path, client: bool
) -> None:
    # A tool path an MCP client's overrides name is not the operator's
    # (config/path_trust.py); the single-directory scan path carries the flag to
    # resolve_config as the workspace path does.
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator

    override = "scanners.checkov.options.config_file=/ops/checkov.yaml"
    orchestrator = ASHScanOrchestrator(
        source_dir=tmp_path,
        output_dir=tmp_path / "out",
        config_overrides=[override],
        client_overrides=client,
    )
    orchestrator.initialize()
    recorded = orchestrator.config._operator_paths.overrides
    assert (recorded == []) is client
