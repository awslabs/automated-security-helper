# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan's own copy of the bound profile is a file the server wrote.

Why this file exists
--------------------
A scan whose config is the session's bound profile loads a per-scan copy of it,
written beside the profile in the session's ``config/`` directory and named for
the scan: ``.ash-scan-<scan id>-p<pid>[-h<host>].ash.yaml``. The sandbox lists
the files the server writes there in ``_is_server_written_config``, and the list
named ``ash.yaml`` and the call profiles only. So the copy counted as a file a
client delivered: the default rule (``config_is_client_delivered``) and a remote
caller's rule (``client_named_config_is_untrusted``) both refused every
environment reference in it, and a bound profile that reads the environment,
which an operator may write, failed the scan with "!ENV is not resolved in a
config an MCP client delivered". The covering tests replace ``run_ash_scan``
and so never saw it. A patched binding's registered profile is copied into
``config/`` the same way, as the scan's trusted base.

The sandbox recognizes the copy by what only the server can have: the exact
prefix and a scan id in the spelling a scan gives its ids, a copied file that is
one of the names the server writes, a path a live scan of this session
registered when it created the file, and a scan id this session's registry
holds. The
prefix, the directory, or a name alone is not enough, since a client chooses
the names it can write and knows the ids of its own scans.

Why the cells are what they are
-------------------------------
The two predicate cells, the registry cell and the end-to-end cell fail on the
code before the change. The end-to-end cell starts the real runner through the directory tool,
which takes the real snapshot and hands the real arguments on, and replaces only
``run_ash_scan`` with a stand-in that resolves the config through
``resolve_scan_config``, the function the orchestrator resolves through. Every
control passes before and after: each says which file is still a delivered one.
"""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path
from typing import Any, Dict, List, Tuple
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp.profile_registry import (
    CALL_PROFILE_FILENAME,
    DEFAULT_SESSION_ID,
    SESSION_CONFIG_FILENAME,
    bind_session_config,
    clear_all_session_state,
    clear_profile_registry,
    clear_session_state,
)
from automated_security_helper.cli.mcp.sandbox import (
    client_named_config_is_untrusted,
    config_is_client_supplied,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.config_sources import (
    SCAN_COPY_PREFIX,
    discard_scan_copy,
    register_scan_copy,
)
from automated_security_helper.core.resource_management.scan_registry import (
    ScanRegistry,
)
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.utils.log import ASHLogger

_TOOLS = "automated_security_helper.cli.mcp_tools"
_MGMT = "automated_security_helper.core.resource_management.scan_management"

PROBE_VAR = "ASH_OWN_COPY_PROBE"
PROBE_VALUE = "a-value-the-operators-profile-read-from-the-environment"

#: A remote caller's session, another remote session, and the local caller's.
REMOTE = "own-copy-remote"
SIBLING = "own-copy-sibling"
LOCAL = DEFAULT_SESSION_ID

#: The profile reads the environment, as an operator's file may: the same
#: reference as a plain scalar and as the !ENV tag.
PROFILES = {
    "plain": f"project_name: ${{{PROBE_VAR}}}\n",
    "tag": f"project_name: !ENV ${{{PROBE_VAR}}}\n",
}

#: Scan ids as a scan spells them: ``str(uuid.uuid4())``.
SCAN_ID = str(uuid.uuid4())
OTHER_SCAN_ID = str(uuid.uuid4())


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "ws"))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    monkeypatch.setenv(PROBE_VAR, PROBE_VALUE)
    clear_profile_registry()
    clear_all_session_state()
    yield
    clear_profile_registry()
    clear_all_session_state()


@pytest.fixture
def live_copies():
    """The paths the cell registered as a live scan's copies, discarded after."""
    made: List[Path] = []
    yield made
    for path in made:
        discard_scan_copy(path)


def _session_file(tmp_path: Path, session_id: str, directory: str, name: str) -> Path:
    path = tmp_path / "ws" / session_id / directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _profile(tmp_path: Path, session_id: str, text: str = PROFILES["tag"]) -> Path:
    path = _session_file(tmp_path, session_id, "config", SESSION_CONFIG_FILENAME)
    path.write_text(text, encoding="utf-8")
    return path


def _hold(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *held: Tuple[str, str]
) -> ScanRegistry:
    """A scan registry holding one scan for each (session id, scan id) given."""
    registry = ScanRegistry()
    for index, (session_id, scan_id) in enumerate(held):
        directory = tmp_path / "scanned" / f"scan-{index}"
        directory.mkdir(parents=True)
        registry.register_scan(
            directory_path=str(directory),
            output_directory=str(directory / "out"),
            scan_id=scan_id,
            session_id=session_id,
        )
    monkeypatch.setattr(f"{_MGMT}.get_scan_registry", lambda: registry)
    return registry


def _live_copy(profile: Path, scan_id: str, made: List[Path]) -> Path:
    """The scan's copy of ``profile``, written and registered as the runner does."""
    planned = mcp_tools._scan_snapshot_path(profile, scan_id)
    copy = mcp_tools._snapshot_profile_for_scan(profile, scan_id, snapshot_path=planned)
    made.append(copy)
    assert copy.name.startswith(SCAN_COPY_PREFIX), copy
    assert copy.parent == profile.parent, copy
    return copy


def _planted(path: Path, made: List[Path], registered: bool) -> Path:
    """A file a client could have written, registered as live only when asked."""
    path.write_text(PROFILES["tag"], encoding="utf-8")
    if registered:
        register_scan_copy(path)
        made.append(path)
    return path


# -- the cure: the scan's own copy is the server's file ----------------------


@pytest.mark.parametrize("session_id", [REMOTE, LOCAL])
def test_config_is_client_supplied_leaves_a_live_scans_own_copy_alone(
    tmp_path, monkeypatch, live_copies, session_id
):
    profile = _profile(tmp_path, session_id)
    _hold(monkeypatch, tmp_path, (session_id, SCAN_ID))
    copy = _live_copy(profile, SCAN_ID, live_copies)
    # Controls: the profile itself is the server's, and the copy is the file the
    # scan loads in its place.
    assert config_is_client_supplied(profile) is False
    assert copy.read_text(encoding="utf-8") == profile.read_text(encoding="utf-8")

    assert config_is_client_supplied(copy) is False


@pytest.mark.parametrize("session_id", [REMOTE, LOCAL])
def test_a_live_scans_own_copy_is_not_a_config_the_client_named(
    tmp_path, monkeypatch, live_copies, session_id
):
    profile = _profile(tmp_path, session_id)
    _hold(monkeypatch, tmp_path, (session_id, SCAN_ID))
    copy = _live_copy(profile, SCAN_ID, live_copies)
    assert client_named_config_is_untrusted(profile, session_id=session_id) is False

    assert client_named_config_is_untrusted(copy, session_id=session_id) is False


def test_a_session_holds_the_scans_the_registry_holds_for_it_and_no_others(
    tmp_path, monkeypatch
):
    # Imported in the cell, so the other cells still collect on the base.
    from automated_security_helper.core.resource_management.scan_management import (
        session_holds_scan,
    )

    _hold(monkeypatch, tmp_path, (REMOTE, SCAN_ID), (LOCAL, OTHER_SCAN_ID))

    assert session_holds_scan(SCAN_ID, REMOTE) is True
    assert session_holds_scan(SCAN_ID, SIBLING) is False
    assert session_holds_scan(OTHER_SCAN_ID, LOCAL) is True
    # None names the stdio session, not every session.
    assert session_holds_scan(OTHER_SCAN_ID, None) is True
    assert session_holds_scan(SCAN_ID, None) is False
    assert session_holds_scan(str(uuid.uuid4()), REMOTE) is False


# -- the cure end to end ------------------------------------------------------


def _the_scan(
    tmp_path: Path,
    session_id: str,
    config_path: Path,
    target: Path,
) -> Dict[str, Any]:
    """Start the real runner through the directory tool and return what the
    scan's stand-in saw: the config path it was handed, and either the values
    resolving that config read or the refusal that resolution raised."""
    seen: Dict[str, Any] = {}

    def a_scan_that_only_resolves_its_config(*args: Any, **kwargs: Any) -> Any:
        from automated_security_helper.core.orchestrator import resolve_scan_config

        seen["config"] = kwargs["config"]
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
            seen["values"] = list(config._environment_values)
        raise RuntimeError("the tool stopped")

    registry = ScanRegistry()

    async def start_and_wait_for_the_runner() -> Any:
        started = await mcp_tools.mcp_scan_directory(
            str(target), config_path=str(config_path), session_id=session_id
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


def _a_bound_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, session_id: str, text: str
) -> Tuple[Path, Path]:
    """A session sandbox whose bound profile has ``text``; returns the profile
    and the scan target. The scan target is the only root the grant names."""
    target = tmp_path / "ws" / session_id / "source" / "repo"
    target.mkdir(parents=True)
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(target))
    profile = _profile(tmp_path, session_id, text)
    bind_session_config(
        session_id,
        config=AshConfig(),
        profile_name="first",
        config_path=str(profile),
    )
    return profile, target


@pytest.mark.parametrize("session_id", [REMOTE, LOCAL])
@pytest.mark.parametrize("kind", sorted(PROFILES))
def test_a_bound_profile_that_reads_the_environment_scans_under_its_own_copy(
    tmp_path, monkeypatch, session_id, kind
):
    profile, target = _a_bound_session(
        tmp_path, monkeypatch, session_id, PROFILES[kind]
    )
    try:
        seen = _the_scan(tmp_path, session_id, profile, target)
    finally:
        clear_session_state(session_id)

    # Control: the scan loaded its own copy of the profile, not the live file.
    assert Path(seen["config"]).name.startswith(SCAN_COPY_PREFIX), seen
    assert "refused" not in seen, seen
    assert seen["project_name"] == PROBE_VALUE, seen
    assert PROBE_VALUE in seen["values"], seen


# -- controls: what is still a delivered file ---------------------------------


@pytest.mark.parametrize("session_id", [REMOTE, LOCAL])
def test_control_the_profile_and_the_call_profiles_stay_the_servers(
    tmp_path, session_id
):
    names = [
        SESSION_CONFIG_FILENAME,
        CALL_PROFILE_FILENAME,
        "call-profile-" + "ab" * 8 + ".yaml",
    ]
    for name in names:
        path = _session_file(tmp_path, session_id, "config", name)
        path.write_text(PROFILES["tag"], encoding="utf-8")

        assert config_is_client_supplied(path) is False, name
        assert client_named_config_is_untrusted(path, session_id=session_id) is False


def test_control_a_file_in_the_delivered_source_named_as_a_scan_copy_is_delivered(
    tmp_path, monkeypatch, live_copies
):
    _hold(monkeypatch, tmp_path, (REMOTE, SCAN_ID))
    name = f"{SCAN_COPY_PREFIX}{SCAN_ID}-p1.{SESSION_CONFIG_FILENAME}"
    planted = _planted(
        _session_file(tmp_path, REMOTE, "source/repo", name), live_copies, True
    )

    assert config_is_client_supplied(planted) is True
    assert client_named_config_is_untrusted(planted, session_id=REMOTE) is True


def test_control_a_live_copy_outside_the_config_directory_is_delivered(
    tmp_path, monkeypatch, live_copies
):
    _hold(monkeypatch, tmp_path, (REMOTE, SCAN_ID))
    patched = _session_file(tmp_path, REMOTE, "client-config", SESSION_CONFIG_FILENAME)
    patched.write_text(PROFILES["tag"], encoding="utf-8")
    copy = _live_copy(patched, SCAN_ID, live_copies)

    assert config_is_client_supplied(copy) is True
    assert client_named_config_is_untrusted(copy, session_id=REMOTE) is True


def test_control_a_copy_that_no_live_scan_registered_is_delivered(
    tmp_path, monkeypatch, live_copies
):
    profile = _profile(tmp_path, REMOTE)
    _hold(monkeypatch, tmp_path, (REMOTE, SCAN_ID))
    name = mcp_tools._scan_snapshot_path(profile, SCAN_ID).name
    planted = _planted(
        _session_file(tmp_path, REMOTE, "config", name), live_copies, False
    )

    assert config_is_client_supplied(planted) is True
    assert client_named_config_is_untrusted(planted, session_id=REMOTE) is True


def test_control_a_live_copy_of_a_scan_the_registry_does_not_hold_is_delivered(
    tmp_path, monkeypatch, live_copies
):
    profile = _profile(tmp_path, REMOTE)
    _hold(monkeypatch, tmp_path, (REMOTE, OTHER_SCAN_ID))
    copy = _live_copy(profile, SCAN_ID, live_copies)

    assert config_is_client_supplied(copy) is True
    assert client_named_config_is_untrusted(copy, session_id=REMOTE) is True


def test_control_a_live_copy_in_another_sessions_directory_is_delivered(
    tmp_path, monkeypatch, live_copies
):
    # The scan id is held, and the copy is live, but the scan is the remote
    # session's and the directory is the sibling's.
    sibling_profile = _profile(tmp_path, SIBLING)
    _hold(monkeypatch, tmp_path, (REMOTE, SCAN_ID))
    copy = _live_copy(sibling_profile, SCAN_ID, live_copies)

    assert config_is_client_supplied(copy) is True
    assert client_named_config_is_untrusted(copy, session_id=SIBLING) is True
    assert client_named_config_is_untrusted(copy, session_id=REMOTE) is True


@pytest.mark.parametrize(
    "name",
    [
        f"{SCAN_COPY_PREFIX}not-a-scan-id.{SESSION_CONFIG_FILENAME}",
        f"{SCAN_COPY_PREFIX}{SCAN_ID.upper()}.{SESSION_CONFIG_FILENAME}",
        f"{SCAN_COPY_PREFIX}{SCAN_ID}-p0.{SESSION_CONFIG_FILENAME}",
        f"{SCAN_COPY_PREFIX}{SCAN_ID}.evil.yaml",
        f"{SCAN_COPY_PREFIX}{SCAN_ID}.{SESSION_CONFIG_FILENAME}.bak",
        f"{SCAN_COPY_PREFIX}{SCAN_ID}",
    ],
    ids=[
        "id-not-a-uuid",
        "id-uppercase",
        "pid-zero",
        "copies-a-file-the-server-does-not-write",
        "copies-a-longer-name",
        "no-copied-name",
    ],
)
def test_control_a_name_the_scan_never_writes_is_delivered_even_when_registered(
    tmp_path, monkeypatch, live_copies, name
):
    _profile(tmp_path, REMOTE)
    _hold(monkeypatch, tmp_path, (REMOTE, SCAN_ID))
    planted = _planted(
        _session_file(tmp_path, REMOTE, "config", name), live_copies, True
    )

    assert config_is_client_supplied(planted) is True
    assert client_named_config_is_untrusted(planted, session_id=REMOTE) is True


def test_control_a_delivered_config_named_as_a_scan_copy_keeps_its_environment_refused(
    tmp_path, monkeypatch
):
    session_id = REMOTE
    _profile_unused, target = _a_bound_session(
        tmp_path, monkeypatch, session_id, PROFILES["plain"]
    )
    name = f"{SCAN_COPY_PREFIX}{SCAN_ID}-p1.{SESSION_CONFIG_FILENAME}"
    delivered = target / name
    delivered.write_text(PROFILES["tag"], encoding="utf-8")
    registry = ScanRegistry()
    try:
        with (
            patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
            patch(f"{_MGMT}.get_scan_registry", return_value=registry),
            patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)),
        ):
            refused = asyncio.run(
                mcp_tools.mcp_scan_directory(
                    str(target), config_path=str(delivered), session_id=session_id
                )
            )
    finally:
        clear_session_state(session_id)

    # Refused before any scan starts, as a delivered file that reads the
    # environment always is; nothing is registered.
    assert refused["success"] is False, refused
    assert refused["error_type"] == "config_env_not_resolved", refused
    assert registry.list_scans() == []
