# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A patched binding's scan fills the operator's environment values back in.

Why this file exists
--------------------
``select_profile`` with ``patch_ops`` writes the profile twice: the operator's
copy in the session's ``config/`` directory, and the client's patched copy in
``client-config/``. The client's copy holds each value the profile read from the
environment as quoted text, because ``!ENV`` is not resolved in that directory.
``resolve_config`` fills those values back in from the operator's copy, when it
is told the pair belongs together (``profile_registry.is_client_copy_of``), so
a setting the patch leaves alone keeps the value the operator's file reads.

A scan does not hand ``resolve_config`` the operator's copy as it stands. The
runner copies the registered profile for the scan and hands the copy over as
the trusted base, and a copy is named for the scan
(``.ash-scan-<scan id>-p<pid>.ash.yaml``), not ``ash.yaml``. The check required
the operator's file to be named ``ash.yaml``, so a scan's own copy never matched,
nothing was filled, and the patched copy's quoted text stood in for the value:
the scan either ran with the reference as a literal setting or was refused for
changing a setting the patch did not touch.

The check now reads the scan's own copy as the file it copies, by the same
registered-copy rule the rest of the sandbox uses
(``config_sources.original_of_scan_copy``). Only a name a live scan registered
maps, so a file a client names like a copy is still not the operator's file.

Why the cells are what they are
-------------------------------
The end-to-end cell starts the real runner through the directory tool, which
takes the real snapshot and hands the real arguments on, and replaces only
``run_ash_scan`` with a stand-in that resolves the config through
``resolve_scan_config``, the function the orchestrator resolves through. The
predicate cells pin the same decision without a scan. Each control passes
before and after the change and says which pairing is still not a copy of the
operator's file.
"""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp.profile_registry import (
    clear_all_session_state,
    clear_profile_registry,
    is_client_copy_of,
    register_profiles,
    resolve_session_config_path,
    resolve_session_trusted_config_path,
    set_profile_registry,
)
from automated_security_helper.cli.mcp_tools import mcp_select_profile
from automated_security_helper.config.config_sources import (
    SCAN_COPY_PREFIX,
    discard_scan_copy,
)
from automated_security_helper.core.resource_management.scan_registry import (
    ScanRegistry,
)
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.utils.log import ASHLogger

_TOOLS = "automated_security_helper.cli.mcp_tools"
_MGMT = "automated_security_helper.core.resource_management.scan_management"

PROBE_VAR = "ASH_FILL_PROBE"
PROBE_VALUE = "a-value-the-operators-profile-read-from-the-environment"
PATCHED_NAME = "client-patched"

#: The profile reads the environment for one setting, and the client may patch
#: its project name only.
PROFILE = (
    "project_name: operator-registered\n"
    "global_settings:\n"
    "  mcp:\n"
    "    runtime_overrides:\n"
    "      enabled: true\n"
    "      allowed_paths:\n"
    "        - /project_name\n"
    "      denied_paths: []\n"
    "reporters:\n"
    "  gitlab-cyclonedx:\n"
    "    options:\n"
    f"      language_override: !ENV ${{{PROBE_VAR}}}\n"
)
PATCH_OPS = [{"op": "replace", "path": "/project_name", "value": PATCHED_NAME}]

#: A scan id spelled as a scan spells it: ``str(uuid.uuid4())``.
SCAN_ID = str(uuid.uuid4())


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "ws"))
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    monkeypatch.setenv(PROBE_VAR, PROBE_VALUE)
    clear_profile_registry()
    clear_all_session_state()
    profile = tmp_path / "op.yaml"
    profile.write_text(PROFILE, encoding="utf-8")
    set_profile_registry(register_profiles([f"op={profile}"]))
    yield
    clear_profile_registry()
    clear_all_session_state()


@pytest.fixture
def live_copies():
    """The scan copies a cell made, discarded after."""
    made: List[Path] = []
    yield made
    for path in made:
        path.unlink(missing_ok=True)
        discard_scan_copy(path)


def _bind(session_id: str) -> tuple[Path, Path]:
    """Bind the profile with a patch; return the client's copy and the operator's."""
    result = mcp_select_profile("op", patch_ops=PATCH_OPS, session_id=session_id)
    assert result["success"] is True, result
    client = Path(resolve_session_config_path(session_id) or "")
    operator = Path(resolve_session_trusted_config_path(session_id) or "")
    # Controls: the binding holds two files, in the two directories.
    assert client.parent.name == "client-config", client
    assert operator.parent.name == "config", operator
    assert operator.name == client.name == "ash.yaml", (client, operator)
    return client, operator


def _live_copy(profile: Path, made: List[Path]) -> Path:
    """The scan's copy of ``profile``, written and registered as the runner does."""
    planned = mcp_tools._scan_snapshot_path(profile, SCAN_ID)
    copy = mcp_tools._snapshot_profile_for_scan(profile, SCAN_ID, snapshot_path=planned)
    made.append(copy)
    assert copy.name.startswith(SCAN_COPY_PREFIX), copy
    assert copy.parent == profile.parent, copy
    return copy


# -- the decision, without a scan ----------------------------------------------


def test_a_scans_own_copy_of_the_operators_file_is_the_operators_file(live_copies):
    client, operator = _bind("pair")
    # Control: the pair as the registry wrote it.
    assert is_client_copy_of(client, operator) is True
    copy = _live_copy(operator, live_copies)

    assert is_client_copy_of(client, copy) is True


def test_control_a_file_named_like_a_copy_that_no_scan_registered_is_not_the_operators(
    tmp_path,
):
    client, operator = _bind("planted")
    planted = mcp_tools._scan_snapshot_path(operator, SCAN_ID)
    planted.write_text(PROFILE, encoding="utf-8")
    try:
        assert is_client_copy_of(client, planted) is False
    finally:
        planted.unlink(missing_ok=True)


def test_control_a_scans_copy_of_another_sessions_file_is_not_this_sessions(
    live_copies,
):
    client, _operator = _bind("first")
    _other_client, other_operator = _bind("second")
    copy_of_the_other = _live_copy(other_operator, live_copies)

    assert is_client_copy_of(client, copy_of_the_other) is False


def test_control_a_scans_copy_of_the_clients_own_file_is_not_the_operators(
    live_copies,
):
    client, _operator = _bind("clients-own")
    copy_of_the_clients = _live_copy(client, live_copies)

    assert is_client_copy_of(client, copy_of_the_clients) is False


# -- the decision, end to end --------------------------------------------------


def _the_scan(tmp_path: Path, session_id: str) -> Dict[str, Any]:
    """Start the real runner through the directory tool with the session's patched
    profile as the config, and return what the scan's stand-in saw: the paths it
    was handed, and either the values resolving them gave or the refusal."""
    target = tmp_path / "ws" / session_id / "source" / "repo"
    target.mkdir(parents=True)
    bound = resolve_session_config_path(session_id)
    assert bound is not None
    seen: Dict[str, Any] = {}

    def a_scan_that_only_resolves_its_config(*args: Any, **kwargs: Any) -> Any:
        from automated_security_helper.core.orchestrator import resolve_scan_config

        seen["config"] = kwargs["config"]
        seen["trusted"] = kwargs.get("trusted_config_path")
        try:
            config = resolve_scan_config(
                config_path=kwargs["config"],
                source_dir=kwargs["source_dir"],
                config_overrides=[],
                config_base_gate=kwargs["config_base_gate"],
                trusted_config_path=kwargs["trusted_config_path"],
                untrusted_config=kwargs["untrusted_config"],
                client_config_policy=kwargs["client_config_policy"],
                remote_client=kwargs["remote_client"],
            )
        except Exception as refusal:  # noqa: BLE001 - recorded for the cell
            seen["refused"] = f"{type(refusal).__name__}: {refusal}"
        else:
            seen["project_name"] = config.project_name
            seen["language_override"] = (
                config.reporters.gitlab_cyclonedx.options.language_override
            )
        raise RuntimeError("the tool stopped")

    registry = ScanRegistry()

    async def start_and_wait_for_the_runner() -> Any:
        started = await mcp_tools.mcp_scan_directory(
            str(target), config_path=bound, session_id=session_id
        )
        pending = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        await asyncio.gather(*pending, return_exceptions=True)
        return started

    with (
        patch.object(ras, "run_ash_scan", a_scan_that_only_resolves_its_config),
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        patch(f"{_MGMT}.get_scan_registry", return_value=registry),
        patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)),
    ):
        started = asyncio.run(start_and_wait_for_the_runner())
    assert started.get("success") is True, started
    assert "config" in seen, ("control: the scan never ran", seen)
    return seen


def test_a_patched_bindings_scan_keeps_the_value_the_operators_profile_reads(
    tmp_path,
):
    _bind("scanned")

    seen = _the_scan(tmp_path, "scanned")

    # Controls: the scan's trusted base is its own copy of the operator's
    # profile, and its config is the client's patched copy.
    assert Path(seen["trusted"]).name.startswith(SCAN_COPY_PREFIX), seen
    assert Path(seen["config"]).parent.name == "client-config", seen
    assert "refused" not in seen, seen
    assert seen["project_name"] == PATCHED_NAME, seen
    assert seen["language_override"] == PROBE_VALUE, seen
