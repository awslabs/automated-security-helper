# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A profile rebound mid-scan cannot run the scan with unredacted values.

The runner reads the trusted profile's environment values into the redaction
set before the scan, and the scan loads the trusted profile again later,
after any wait for the session lock. select_profile rewrites the session's
file, so without protection a rebind in that window gives the scan a config
whose values the redaction set never saw. The runner therefore snapshots the
profile for the scan: the set is read from the snapshot and the scan loads
the snapshot, so the file whose values redact is the file the scan runs
under, whatever happens to the live profile meanwhile.

Driven end to end: the directory tool starts the real runner task against a
real session sandbox (the delivered config is the client's by the sandbox's
own classification, the profile is bound through the profile registry), and
only ``run_ash_scan`` is replaced, by a stand-in that performs the rebind
and then resolves its config exactly as the orchestrator would.
"""

import asyncio
import json
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp import profile_registry
from automated_security_helper.cli.mcp.scan_target import ASH_MCP_ALLOWED_ROOTS_ENV
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.previous_results import PreviousResults
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
)
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.utils.log import ASHLogger
from tests.utils.tasks import drain

_TOOLS = "automated_security_helper.cli.mcp_tools"
_MGMT = "automated_security_helper.core.resource_management.scan_management"

_SID = "rebind-session"
_PROFILE_VALUE = "a-profile-value-read-from-the-environment"
_REBOUND_VALUE = "a-rebound-value-read-from-the-environment"


def test_a_rebind_between_the_runner_start_and_the_scan_load_cannot_leak(
    tmp_path, monkeypatch
):
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied
    from automated_security_helper.config.resolve_config import (
        _load_operator_config,
        load_config_file_for_run,
        resolve_config,
    )

    ws = tmp_path / "ws"
    target = ws / _SID / "source" / "repo"
    target.mkdir(parents=True)
    config_dir = ws / _SID / "config"
    config_dir.mkdir(parents=True)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(ws))
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(target))
    monkeypatch.setenv("ASH_REBIND_PROFILE", _PROFILE_VALUE)
    monkeypatch.setenv("ASH_REBIND_SWAP", _REBOUND_VALUE)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    delivered = target / "client.ash.yaml"
    delivered.write_text("project_name: delivered\n", encoding="utf-8")
    profile = config_dir / "ash.yaml"
    profile.write_text("project_name: ${ASH_REBIND_PROFILE:unset}\n", encoding="utf-8")
    # Controls on the sandbox's own classification: the delivered file is the
    # client's and the profile is not, so the runner takes the trusted-profile
    # path without any classification stand-in.
    assert config_is_client_supplied(delivered)
    assert not config_is_client_supplied(profile)
    profile_registry.bind_session_config(
        _SID, config=AshConfig(), profile_name="first", config_path=str(profile)
    )
    assert profile_registry.resolve_session_config_path(_SID) == str(profile)

    other = tmp_path / "operator"
    other.mkdir()
    (other / "second.ash.yaml").write_text(
        "project_name: ${ASH_REBIND_SWAP:unset}\n", encoding="utf-8"
    )

    def a_rebind_of_the_sessions_profile():
        config = load_config_file_for_run(other / "second.ash.yaml")[1]
        written = profile_registry.materialize_session_config(_SID, config)
        # Control: the rebind rewrote the session's own file, the window the
        # snapshot exists to close.
        assert Path(written).resolve() == profile.resolve(), (written, profile)
        assert "ASH_REBIND_SWAP" in Path(written).read_text(encoding="utf-8")
        profile_registry.bind_session_config(
            _SID, config=config, profile_name="second", config_path=written
        )

    loaded = {}

    def a_run_that_rebinds_then_resolves(*args, **kwargs):
        a_rebind_of_the_sessions_profile()
        config = resolve_config(
            config_path=kwargs["config"],
            source_dir=kwargs["source_dir"],
            config_overrides=[],
            permit_base=kwargs["config_base_gate"],
            trusted_config_path=kwargs["trusted_config_path"],
            untrusted_config=kwargs["untrusted_config"],
        )
        operator = _load_operator_config(
            kwargs["trusted_config_path"],
            kwargs["source_dir"],
            kwargs["config_base_gate"],
        )
        loaded["values"] = list(
            dict.fromkeys(
                [
                    *config._environment_values,
                    *(operator.config._environment_values if operator else []),
                ]
            )
        )
        loaded["trusted"] = kwargs["trusted_config_path"]
        raise RuntimeError("the tool quoted: " + " | ".join(loaded["values"]))

    registry = ScanRegistry()
    logger = MagicMock(spec=ASHLogger)

    async def start_and_wait_for_the_runner():
        started = await mcp_tools.mcp_scan_directory(
            str(target), config_path=str(delivered), session_id=_SID
        )
        await drain(return_exceptions=True)
        return started

    try:
        with (
            patch.object(ras, "run_ash_scan", a_run_that_rebinds_then_resolves),
            patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
            patch(f"{_MGMT}.get_scan_registry", return_value=registry),
            patch(f"{_TOOLS}._logger", logger),
        ):
            started = asyncio.run(start_and_wait_for_the_runner())
            scans = registry.list_scans()
            if len(scans) != 1 or started.get("success") is not True:
                raise RuntimeError(("control: the scan did not start", started, scans))
            entry = registry.get_scan(scans[0]["scan_id"])
            progress = asyncio.run(
                mcp_tools.mcp_get_scan_progress(scans[0]["scan_id"], session_id=_SID)
            )
    finally:
        profile_registry.clear_session_state(_SID)

    # The scan ran under the file the runner read: the rebound profile's value
    # never reached its config, and the value it did read is the one the
    # redaction set was built from.
    assert _REBOUND_VALUE not in loaded["values"], loaded
    assert _PROFILE_VALUE in loaded["values"], loaded
    for surface, text in (
        ("the registry's error_message", entry.error_message or ""),
        ("the progress answer", json.dumps(progress, default=str)),
        ("the log", str(logger.mock_calls)),
    ):
        assert _REBOUND_VALUE not in text, (surface, text)
        assert _PROFILE_VALUE not in text, (surface, text)
    # The scan's snapshot does not outlive its run.
    leftovers = [
        p.name for p in config_dir.iterdir() if p.name.startswith(".ash-scan-")
    ]
    assert leftovers == [], leftovers


class _ARebindOnLockAcquire:
    """The session's lock, with a rebind run once just before it is taken.

    The scan's thread takes the session lock right before the scan runs, so
    an action fired at acquire lands deterministically in the window these
    cells pin: after the runner has taken its snapshot and read the redaction
    set, before the scan's own config resolution.
    """

    def __init__(self, real, rebind):
        self._real = real
        self._rebind = rebind
        self.fired = False
        self.trouble: list = []

    def _fire(self):
        if not self.fired:
            self.fired = True
            try:
                self._rebind()
            except BaseException as trouble:  # noqa: BLE001 - re-raised by the cell
                self.trouble.append(trouble)

    def __enter__(self):
        self._fire()
        self._real.acquire()
        return self

    def __exit__(self, *exc):
        self._real.release()
        return False

    def acquire(self, *args, **kwargs):
        self._fire()
        return self._real.acquire(*args, **kwargs)

    def release(self):
        self._real.release()


def _a_lock_that_rebinds_on_acquire(monkeypatch, session_id, rebind):
    from automated_security_helper.cli.mcp.sessions import get_default_registry

    session = get_default_registry().get_or_create(session_id)
    hook = _ARebindOnLockAcquire(session.lock, rebind)
    monkeypatch.setattr(session, "_lock", hook)
    assert get_default_registry().get_or_create(session_id).lock is hook
    return hook


def _a_session_whose_profile_is_the_scans_config(tmp_path, monkeypatch, session_id):
    """A real session sandbox with the profile bound and a rebind prepared.

    Returns the scan target, the bound profile's path, the session config
    directory, and a rebind callable that rewrites the session's live profile
    the way select_profile does.
    """
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied
    from automated_security_helper.config.resolve_config import load_config_file_for_run

    ws = tmp_path / "ws"
    target = ws / session_id / "source" / "repo"
    target.mkdir(parents=True)
    config_dir = ws / session_id / "config"
    config_dir.mkdir(parents=True)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(ws))
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(target))
    monkeypatch.setenv("ASH_REBIND_PROFILE", _PROFILE_VALUE)
    monkeypatch.setenv("ASH_REBIND_SWAP", _REBOUND_VALUE)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    profile = config_dir / "ash.yaml"
    profile.write_text("project_name: ${ASH_REBIND_PROFILE:unset}\n", encoding="utf-8")
    assert not config_is_client_supplied(profile)
    profile_registry.bind_session_config(
        session_id, config=AshConfig(), profile_name="first", config_path=str(profile)
    )
    assert profile_registry.resolve_session_config_path(session_id) == str(profile)
    other = tmp_path / "operator"
    other.mkdir(exist_ok=True)
    (other / "second.ash.yaml").write_text(
        "project_name: ${ASH_REBIND_SWAP:unset}\n", encoding="utf-8"
    )

    def a_rebind_of_the_sessions_profile():
        config = load_config_file_for_run(other / "second.ash.yaml")[1]
        written = profile_registry.materialize_session_config(session_id, config)
        assert Path(written).resolve() == profile.resolve(), (written, profile)
        assert "ASH_REBIND_SWAP" in Path(written).read_text(encoding="utf-8")
        profile_registry.bind_session_config(
            session_id, config=config, profile_name="second", config_path=written
        )

    return target, profile, config_dir, a_rebind_of_the_sessions_profile


def _a_run_that_resolves_the_handed_config(loaded, outcome):
    """A ``run_ash_scan`` stand-in resolving its config as the orchestrator
    does, recording what it was handed and what that resolution read, then
    ending on the given arm."""

    def run(*args, **kwargs):
        from automated_security_helper.config.resolve_config import resolve_config

        loaded["kwargs"] = {
            k: kwargs.get(k)
            for k in ("config", "trusted_config_path", "untrusted_config")
        }
        config = resolve_config(
            config_path=kwargs["config"],
            source_dir=kwargs["source_dir"],
            config_overrides=[],
            permit_base=kwargs["config_base_gate"],
            trusted_config_path=kwargs["trusted_config_path"],
            untrusted_config=kwargs["untrusted_config"],
        )
        loaded["values"] = list(dict.fromkeys(config._environment_values))
        return outcome(loaded)

    return run


def _the_scan_in_the_session(
    target, config_path, session_id, run, extra=(), clean_output=False
):
    """Start the real runner through the directory tool and gather it."""
    import contextlib

    registry = ScanRegistry()
    logger = MagicMock(spec=ASHLogger)

    async def start_and_wait_for_the_runner():
        started = await mcp_tools.mcp_scan_directory(
            str(target),
            config_path=str(config_path),
            session_id=session_id,
            clean_output=clean_output,
        )
        await drain(return_exceptions=True)
        return started

    try:
        with contextlib.ExitStack() as stack:
            for manager in (
                patch.object(ras, "run_ash_scan", run),
                patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
                patch(f"{_MGMT}.get_scan_registry", return_value=registry),
                patch(f"{_TOOLS}._logger", logger),
                *extra,
            ):
                stack.enter_context(manager)
            started = asyncio.run(start_and_wait_for_the_runner())
            scans = registry.list_scans()
            if len(scans) != 1 or started.get("success") is not True:
                raise RuntimeError(("control: the scan did not start", started, scans))
            entry = registry.get_scan(scans[0]["scan_id"])
            progress = asyncio.run(
                mcp_tools.mcp_get_scan_progress(
                    scans[0]["scan_id"], session_id=session_id
                )
            )
    finally:
        profile_registry.clear_session_state(session_id)
    return entry, str(logger.mock_calls), json.dumps(progress, default=str)


_PSID = "rebind-profile-config-session"


def test_a_rebind_at_the_lock_cannot_outrun_a_scan_whose_config_is_the_profile(
    tmp_path, monkeypatch
):
    """The session's own profile as the scan's config -- what the server
    passes when the client names none -- gets the same per-scan snapshot a
    delivered config's trusted base gets. A rebind landing while the scan
    waits at the session lock rewrites only the live file: the scan runs the
    copy, so the rebound value never reaches its config, and the value it
    does read is one its redaction set was built from."""
    target, profile, config_dir, rebind = _a_session_whose_profile_is_the_scans_config(
        tmp_path, monkeypatch, _PSID
    )
    config_path = profile_registry.resolve_session_config_path(_PSID)
    assert config_path == str(profile)
    hook = _a_lock_that_rebinds_on_acquire(monkeypatch, _PSID, rebind)
    loaded: dict = {}

    def an_error_quoting_the_values(record):
        raise RuntimeError("the tool quoted: " + " | ".join(record["values"]))

    entry, logged, progress = _the_scan_in_the_session(
        target,
        config_path,
        _PSID,
        _a_run_that_resolves_the_handed_config(loaded, an_error_quoting_the_values),
    )

    assert hook.fired, "control: the rebind at the lock never ran"
    if hook.trouble:
        raise hook.trouble[0]
    assert "values" in loaded, "control: the scan never resolved its config"
    assert _REBOUND_VALUE not in loaded["values"], loaded
    assert _PROFILE_VALUE in loaded["values"], loaded
    # The scan ran the server-written copy, not the live file the rebind
    # rewrote.
    assert Path(loaded["kwargs"]["config"]).name.startswith(".ash-scan-"), loaded
    for surface, text in (
        ("the registry's error_message", entry.error_message or ""),
        ("the progress answer", progress),
        ("the log", logged),
    ):
        assert _REBOUND_VALUE not in text, (surface, text)
        assert _PROFILE_VALUE not in text, (surface, text)
    leftovers = [
        p.name for p in config_dir.iterdir() if p.name.startswith(".ash-scan-")
    ]
    assert leftovers == [], leftovers


_ARM_SID = "rebind-profile-config-arm-session"


@pytest.mark.parametrize(
    "arm", ["error", "refused-exit", "settle", "assess", "assess-incomplete"]
)
def test_a_runner_arm_hides_the_values_when_the_profile_is_the_scans_config(
    tmp_path, monkeypatch, arm
):
    """Every reason the runner records or logs hides the values when the
    session's profile is the scan's own config and a rebind lands at the
    lock: the failure text, the refused exit's text, the settle failure's
    line, and both coverage assessment lines, as the delivered-config cells
    pin for the trusted profile."""
    from automated_security_helper.core.resource_management import (
        scan_tracking as _tracking_module,
    )
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    target, profile, config_dir, rebind = _a_session_whose_profile_is_the_scans_config(
        tmp_path, monkeypatch, _ARM_SID
    )
    config_path = profile_registry.resolve_session_config_path(_ARM_SID)
    hook = _a_lock_that_rebinds_on_acquire(monkeypatch, _ARM_SID, rebind)
    loaded: dict = {}

    def quoted(record):
        return " | ".join(record.get("values", []))

    extra = []
    clean = False
    if arm == "error":

        def outcome(record):
            raise RuntimeError(f"the tool quoted: {quoted(record)}")

        expected = (MCScanStatus.FAILED, "Error executing scan")
    elif arm == "refused-exit":

        def outcome(record):
            raise ras.ScanRefusedExit(3, f"refused because {quoted(record)}")

        expected = (MCScanStatus.FAILED, "ASH exited with code 3: refused because")
    elif arm == "settle":
        clean = True

        def outcome(record):
            raise RuntimeError("the tool crashed")

        def a_restore_quoting_the_values(*args, **kwargs):
            raise OSError(13, f"settle refused {quoted(loaded)}")

        extra.append(
            patch.object(
                PreviousResults, "restore", side_effect=a_restore_quoting_the_values
            )
        )
        expected = (MCScanStatus.FAILED, "could not settle the previous results")
    elif arm == "assess":

        def outcome(record):
            return AshAggregatedResults()

        def an_assessment_quoting_the_values(results):
            raise ValueError(f"bad coverage {quoted(loaded)}")

        extra.append(
            patch.object(
                _tracking_module,
                "assess_coverage",
                side_effect=an_assessment_quoting_the_values,
            )
        )
        expected = (MCScanStatus.COMPLETED, "could not assess coverage")
    else:

        def outcome(record):
            raise ras.ScanIncompleteExit(
                ras.ScanIncompleteness(scanners=(("bandit", "ERROR"),)),
                AshAggregatedResults(),
            )

        def an_assessment_quoting_the_values(results):
            raise ValueError(f"bad coverage {quoted(loaded)}")

        extra.append(
            patch.object(
                _tracking_module,
                "assess_coverage",
                side_effect=an_assessment_quoting_the_values,
            )
        )
        expected = (
            MCScanStatus.INCOMPLETE,
            "reporting the exit code's reasons instead",
        )

    entry, logged, progress = _the_scan_in_the_session(
        target,
        config_path,
        _ARM_SID,
        _a_run_that_resolves_the_handed_config(loaded, outcome),
        extra=extra,
        clean_output=clean,
    )

    assert hook.fired, "control: the rebind at the lock never ran"
    if hook.trouble:
        raise hook.trouble[0]
    assert entry.status == expected[0], (entry.status, entry.error_message)
    # Control: the arm's own line was written with the system's words, so the
    # assertions below measure redaction, not absence.
    assert expected[1] in (entry.error_message or "") + logged, (
        entry.error_message,
        logged,
    )
    for surface, text in (
        ("the registry's error_message", entry.error_message or ""),
        ("the progress answer", progress),
        ("the log", logged),
    ):
        assert _REBOUND_VALUE not in text, (surface, arm, text)
        assert _PROFILE_VALUE not in text, (surface, arm, text)
    leftovers = [
        p.name for p in config_dir.iterdir() if p.name.startswith(".ash-scan-")
    ]
    assert leftovers == [], leftovers


_QSID = "rebind-queued-session"


def test_a_rebind_while_the_scan_waits_for_the_session_lock_cannot_leak(
    tmp_path, monkeypatch
):
    """The queued shape: the scan's runner task has started (its snapshot is
    written and its redaction set read) but the scan itself waits behind the
    session lock, held here as a running scan would hold it. The rebind lands
    in that wait. The scan then runs under the snapshot it took at task start,
    so the rebound profile's value never reaches its config and the value it
    does read is the one its redaction set was built from."""
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied
    from automated_security_helper.config.resolve_config import (
        _load_operator_config,
        load_config_file_for_run,
        resolve_config,
    )

    ws = tmp_path / "ws"
    target = ws / _QSID / "source" / "repo"
    target.mkdir(parents=True)
    config_dir = ws / _QSID / "config"
    config_dir.mkdir(parents=True)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(ws))
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(target))
    monkeypatch.setenv("ASH_REBIND_PROFILE", _PROFILE_VALUE)
    monkeypatch.setenv("ASH_REBIND_SWAP", _REBOUND_VALUE)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    delivered = target / "client.ash.yaml"
    delivered.write_text("project_name: delivered\n", encoding="utf-8")
    profile = config_dir / "ash.yaml"
    profile.write_text("project_name: ${ASH_REBIND_PROFILE:unset}\n", encoding="utf-8")
    assert config_is_client_supplied(delivered)
    assert not config_is_client_supplied(profile)
    profile_registry.bind_session_config(
        _QSID, config=AshConfig(), profile_name="first", config_path=str(profile)
    )
    assert profile_registry.resolve_session_config_path(_QSID) == str(profile)

    other = tmp_path / "operator"
    other.mkdir()
    (other / "second.ash.yaml").write_text(
        "project_name: ${ASH_REBIND_SWAP:unset}\n", encoding="utf-8"
    )

    snapshot_taken = threading.Event()
    real_snapshot = mcp_tools._snapshot_profile_for_scan

    def a_snapshot_that_signals(profile_path, scan_id, *args, **kwargs):
        written = real_snapshot(profile_path, scan_id, *args, **kwargs)
        snapshot_taken.set()
        return written

    loaded = {}

    def a_run_that_resolves_as_the_orchestrator_would(*args, **kwargs):
        config = resolve_config(
            config_path=kwargs["config"],
            source_dir=kwargs["source_dir"],
            config_overrides=[],
            permit_base=kwargs["config_base_gate"],
            trusted_config_path=kwargs["trusted_config_path"],
            untrusted_config=kwargs["untrusted_config"],
        )
        operator = _load_operator_config(
            kwargs["trusted_config_path"],
            kwargs["source_dir"],
            kwargs["config_base_gate"],
        )
        loaded["values"] = list(
            dict.fromkeys(
                [
                    *config._environment_values,
                    *(operator.config._environment_values if operator else []),
                ]
            )
        )
        raise RuntimeError("the tool quoted: " + " | ".join(loaded["values"]))

    # Hold the session lock as a running scan in this session would, so the
    # new scan's thread queues behind it.
    from automated_security_helper.cli.mcp.sessions import get_default_registry

    session_lock = get_default_registry().get_or_create(_QSID).lock
    assert session_lock.acquire(timeout=5), "control: the session lock is taken"
    rebind_trouble: list = []

    def a_rebind_during_the_wait():
        try:
            assert snapshot_taken.wait(timeout=30), "the snapshot was never taken"
            config = load_config_file_for_run(other / "second.ash.yaml")[1]
            written = profile_registry.materialize_session_config(_QSID, config)
            # Controls: the rebind rewrote the session's own live file while
            # the scan's snapshot sat beside it, before the lock was free.
            assert Path(written).resolve() == profile.resolve(), (written, profile)
            assert "ASH_REBIND_SWAP" in Path(written).read_text(encoding="utf-8")
            snapshots = [
                p.name for p in config_dir.iterdir() if p.name.startswith(".ash-scan-")
            ]
            assert snapshots, "control: no snapshot existed at the rebind"
            profile_registry.bind_session_config(
                _QSID, config=config, profile_name="second", config_path=written
            )
        except BaseException as trouble:  # noqa: BLE001 - re-raised below
            rebind_trouble.append(trouble)
        finally:
            session_lock.release()

    rebinder = threading.Thread(target=a_rebind_during_the_wait)

    registry = ScanRegistry()
    logger = MagicMock(spec=ASHLogger)

    async def start_and_wait_for_the_runner():
        started = await mcp_tools.mcp_scan_directory(
            str(target), config_path=str(delivered), session_id=_QSID
        )
        await drain(return_exceptions=True)
        return started

    try:
        with (
            patch.object(
                ras, "run_ash_scan", a_run_that_resolves_as_the_orchestrator_would
            ),
            patch(f"{_TOOLS}._snapshot_profile_for_scan", a_snapshot_that_signals),
            patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
            patch(f"{_MGMT}.get_scan_registry", return_value=registry),
            patch(f"{_TOOLS}._logger", logger),
        ):
            rebinder.start()
            started = asyncio.run(start_and_wait_for_the_runner())
            rebinder.join(timeout=30)
            scans = registry.list_scans()
            if len(scans) != 1 or started.get("success") is not True:
                raise RuntimeError(("control: the scan did not start", started, scans))
            entry = registry.get_scan(scans[0]["scan_id"])
            progress = asyncio.run(
                mcp_tools.mcp_get_scan_progress(scans[0]["scan_id"], session_id=_QSID)
            )
    finally:
        profile_registry.clear_session_state(_QSID)

    assert not rebinder.is_alive(), "the rebind thread never finished"
    if rebind_trouble:
        raise rebind_trouble[0]
    assert "values" in loaded, "control: the scan never resolved its config"
    assert _REBOUND_VALUE not in loaded["values"], loaded
    assert _PROFILE_VALUE in loaded["values"], loaded
    for surface, text in (
        ("the registry's error_message", entry.error_message or ""),
        ("the progress answer", json.dumps(progress, default=str)),
        ("the log", str(logger.mock_calls)),
    ):
        assert _REBOUND_VALUE not in text, (surface, text)
        assert _PROFILE_VALUE not in text, (surface, text)
    leftovers = [
        p.name for p in config_dir.iterdir() if p.name.startswith(".ash-scan-")
    ]
    assert leftovers == [], leftovers


_DSID = "rebind-profile-dotdot-session"


def test_a_dotdot_spelling_of_the_profile_gets_the_scan_the_same_copy(
    tmp_path, monkeypatch
):
    """The client types the profile's path with a ``..`` in it. It is the same
    file as the registry's spelling, so the scan runs a copy of it exactly as it
    does for the registry's own spelling: a rebind landing at the session lock
    cannot give the scan the rewritten file. Which file the typed path names is
    decided by file identity, not by comparing the text."""
    target, profile, config_dir, rebind = _a_session_whose_profile_is_the_scans_config(
        tmp_path, monkeypatch, _DSID
    )
    dotdot = config_dir / ".." / config_dir.name / profile.name
    hook = _a_lock_that_rebinds_on_acquire(monkeypatch, _DSID, rebind)
    loaded: dict = {}

    def an_error_quoting_the_values(record):
        raise RuntimeError("the tool quoted: " + " | ".join(record["values"]))

    entry, logged, progress = _the_scan_in_the_session(
        target,
        dotdot,
        _DSID,
        _a_run_that_resolves_the_handed_config(loaded, an_error_quoting_the_values),
    )

    assert hook.fired, "control: the rebind at the lock never ran"
    if hook.trouble:
        raise hook.trouble[0]
    assert "values" in loaded, "control: the scan never resolved its config"
    # Controls: the typed path is not the registry's spelling, and it names the
    # same file.
    assert str(dotdot) != str(profile)
    assert dotdot.samefile(profile)
    assert _REBOUND_VALUE not in loaded["values"], loaded
    assert _PROFILE_VALUE in loaded["values"], loaded
    # The scan ran the server-written copy, not the live file the rebind
    # rewrote.
    assert Path(loaded["kwargs"]["config"]).name.startswith(".ash-scan-"), loaded
    for surface, text in (
        ("the registry's error_message", entry.error_message or ""),
        ("the progress answer", progress),
        ("the log", logged),
    ):
        assert _REBOUND_VALUE not in text, (surface, text)
        assert _PROFILE_VALUE not in text, (surface, text)
    leftovers = [
        p.name for p in config_dir.iterdir() if p.name.startswith(".ash-scan-")
    ]
    assert leftovers == [], leftovers


_LSID = "rebind-profile-off-the-loop-session"


def test_which_session_file_the_config_names_is_decided_off_the_event_loop(
    tmp_path, monkeypatch
):
    """The decision reads the filesystem (file identity), so it runs on the
    snapshot step's worker thread and never on the loop every session's tool
    calls run on."""
    target, _profile, _config_dir, _rebind = (
        _a_session_whose_profile_is_the_scans_config(tmp_path, monkeypatch, _LSID)
    )
    real = mcp_tools._session_file_named_by
    calls: list = []

    def recorded(config_path, *session_files):
        try:
            asyncio.get_running_loop()
            on_the_loop = True
        except RuntimeError:
            on_the_loop = False
        calls.append(on_the_loop)
        return real(config_path, *session_files)

    monkeypatch.setattr(mcp_tools, "_session_file_named_by", recorded)
    loaded: dict = {}

    def an_error_quoting_the_values(record):
        raise RuntimeError("the tool quoted: " + " | ".join(record["values"]))

    _the_scan_in_the_session(
        target,
        profile_registry.resolve_session_config_path(_LSID),
        _LSID,
        _a_run_that_resolves_the_handed_config(loaded, an_error_quoting_the_values),
    )

    assert "values" in loaded, "control: the scan never resolved its config"
    assert calls == [False], calls
