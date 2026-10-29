# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""One scan's copy of the profile has one name, whatever the host identity reads.

The copy's name embeds the identity of the place the process runs in. The
runner records the name before the file exists (so its cleanup covers the whole
window the copy is written in) and points the scan at it, while the writer
creates the file. If those were two separate computations, an identity that read
differently on the second call would make the scan load a file that was never
written and leave the written copy, which holds the profile's content, for the
sweep.

These cells make the identity answer differently on every call, so any second
computation of the name is a different name.
"""

import asyncio
import hashlib
import itertools
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp import profile_registry
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.resource_management.scan_registry import (
    ScanRegistry,
)
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.utils.log import ASHLogger
from tests.utils.mcp_sessions import a_session_with_a_bound_profile

_TOOLS = "automated_security_helper.cli.mcp_tools"
_MGMT = "automated_security_helper.core.resource_management.scan_management"

#: A well formed identity token, and the answer of a host that cannot read one.
_TOKEN = "0123456789abcdef"

#: A scan id as the writer spells one (``str(uuid.uuid4())``): the copy's name
#: must parse as a scan copy's (config_sources.parse_scan_copy_name), and only
#: the UUID spelling does.
_A_SCAN_ID = "4b8e6d1c-2f7a-4c3b-9e5d-8a0f6c2d7b1e"


def _an_identity_that_flips_on_every_call():
    answers = itertools.cycle([_TOKEN, None])
    return lambda: next(answers)


def _leftovers(config_dir: Path) -> List[str]:
    return sorted(
        p.name for p in config_dir.iterdir() if p.name.startswith(".ash-scan-")
    )


def _register_profiles(entries):
    """Register each ``name -> path`` as the operator's profile of that name.

    The policy a delivered config is checked against is read from the
    REGISTERED profile, never from the binding
    (profile_registry.session_profile_entry), and a bound name no profile is
    registered under refuses every config a client delivers ("is not
    registered, so the runtime-override policy it sets cannot be read"). The
    entry's config is the plain default the tests bind, so the policy is the
    default one. The tests clear the registry when they end.
    """
    profile_registry.set_profile_registry(
        {
            name: profile_registry.ProfileEntry(
                name=name,
                path=Path(path),
                config=AshConfig(),
                path_sha256=hashlib.sha256(
                    str(Path(path).resolve()).encode("utf-8")
                ).hexdigest(),
            )
            for name, path in entries.items()
        }
    )


def _bind_as_the_trusted_base(session_id, profile, profile_name="held"):
    """Register the helper's profile and bind it as the scan's trusted base.

    The runner copies the profile the binding's ``trusted_config_path`` names
    (_run_scan_async reads resolve_session_trusted_config_path, never the
    session's ``config_path``): bound without it, a delivered config runs with
    no trusted base and no snapshot is taken.
    """
    _register_profiles({profile_name: profile})
    profile_registry.bind_session_config(
        session_id,
        config=AshConfig(),
        profile_name=profile_name,
        config_path=str(profile),
        trusted_config_path=str(profile),
    )


def _a_session_with_a_bound_profile(tmp_path, monkeypatch, session_id):
    """A real session sandbox with a delivered config and a bound profile."""
    target, delivered, profile, config_dir = a_session_with_a_bound_profile(
        tmp_path / "ws", monkeypatch, session_id
    )
    _bind_as_the_trusted_base(session_id, profile)
    return target, delivered, config_dir


def test_the_writer_creates_the_file_at_the_path_it_is_given(tmp_path, monkeypatch):
    from automated_security_helper.config.config_sources import discard_scan_copy

    profile = tmp_path / "ash.yaml"
    profile.write_text("project_name: a-bound-profile\n", encoding="utf-8")
    planned = mcp_tools._scan_snapshot_path(profile, _A_SCAN_ID, writer_host=_TOKEN)
    monkeypatch.setattr(mcp_tools, "_this_host_token", lambda: None)
    # Control: asked on its own, the writer's name for the scan would differ.
    assert mcp_tools._scan_snapshot_path(profile, _A_SCAN_ID) != planned

    written = mcp_tools._snapshot_profile_for_scan(
        profile, _A_SCAN_ID, snapshot_path=planned
    )

    try:
        assert written == planned, (written, planned)
        assert planned.is_file()
        assert [p.name for p in tmp_path.iterdir() if p != profile] == [planned.name]
    finally:
        discard_scan_copy(planned)
        planned.unlink(missing_ok=True)


def test_the_scan_loads_the_copy_the_runner_wrote_when_the_identity_flips(
    tmp_path, monkeypatch
):
    """End to end through the directory tool: the config the scan is told to
    load exists, and nothing is left beside the profile afterwards."""
    session_id = "one-name-per-scan-session"
    target, delivered, config_dir = _a_session_with_a_bound_profile(
        tmp_path, monkeypatch, session_id
    )
    monkeypatch.setattr(
        mcp_tools, "_this_host_token", _an_identity_that_flips_on_every_call()
    )
    seen: Dict[str, Any] = {}

    def a_run_that_reads_its_copy(*args, **kwargs):
        seen["trusted"] = kwargs.get("trusted_config_path")
        seen["copy_on_disk"] = Path(kwargs["trusted_config_path"]).is_file()
        raise RuntimeError("the tool crashed")

    registry = ScanRegistry()

    async def start_and_wait_for_the_runner():
        started = await mcp_tools.mcp_scan_directory(
            str(target), config_path=str(delivered), session_id=session_id
        )
        pending = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        await asyncio.gather(*pending, return_exceptions=True)
        return started

    try:
        with (
            patch.object(ras, "run_ash_scan", a_run_that_reads_its_copy),
            patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
            patch(f"{_MGMT}.get_scan_registry", return_value=registry),
            patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)),
        ):
            asyncio.run(start_and_wait_for_the_runner())
    finally:
        profile_registry.clear_session_state(session_id)
        profile_registry.clear_profile_registry()

    # Controls: the scan ran, on a copy named for a scan.
    assert seen.get("trusted"), seen
    assert Path(seen["trusted"]).name.startswith(".ash-scan-"), seen
    # The scan was told to load a file that exists, and the copy is gone after.
    assert seen["copy_on_disk"], seen
    assert _leftovers(config_dir) == [], _leftovers(config_dir)
