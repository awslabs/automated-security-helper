"""A ``-=`` override from an MCP client is checked at the path of the list it edits.

A workspace scan's ``config_overrides`` come from the client, so
``cli/mcp/workspace._gate_client_overrides`` checks each one by the key it names
(``check_runtime_ops``) before any project applies it. ``KEY-=VALUE`` takes items out
of the list at KEY and writes no value, so it is checked as a ``remove`` at the
list's own pointer. There every ``denied_paths`` entry covers it, an exact entry with
no ``/**`` under it included, and it gets neither exemption meant for a written value
(an ``add`` of a reporter's ``enabled: false`` is let through as a turn-off). Checked
at a pointer that kept the trailing ``-``, an exact entry missed it, and each
project's own list could lose items the session config's list does not hold, a
change the second check, on the session config, cannot see.

The profile allows every path, so only the shipped ``denied_paths`` refuse an
override here.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import workspace as workspace_module
from automated_security_helper.config.runtime_patch import RuntimePatchDeniedError

pytestmark = pytest.mark.unit

#: A section of a converter from a module outside ASH, holding a list. No shipped
#: denied_paths entry names it, so a client may edit it.
_ACME_CONVERTER = """\
converters:
  acme-converter:
    options:
      destinations: [ops, audit]
"""


@pytest.fixture(autouse=True)
def _clear_policy_env(monkeypatch, tmp_path):
    from automated_security_helper.cli.mcp.profile_registry import (
        clear_all_session_state,
        clear_profile_registry,
    )

    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    # The session configs select_profile writes go under this test's own
    # directory, not the user's MCP cache, which concurrent runs share.
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    clear_profile_registry()
    clear_all_session_state()
    yield
    clear_profile_registry()
    clear_all_session_state()


def _profile_allowing_every_path(tmp_path: Path, extra: str = "") -> Path:
    """Register and bind a profile whose runtime overrides allow every path, and
    return its file. ``extra`` is more of the profile's top-level YAML."""
    from automated_security_helper.cli.mcp.profile_registry import (
        register_profiles,
        set_profile_registry,
    )
    from automated_security_helper.cli.mcp_tools import mcp_select_profile

    profile = tmp_path / "profile.yaml"
    profile.write_text(
        (
            "project_name: operator\n"
            f"{extra}"
            "global_settings:\n"
            "  mcp:\n"
            "    runtime_overrides:\n"
            "      enabled: true\n"
            '      allowed_paths: ["/**"]\n'
        ),
        encoding="utf-8",
    )
    set_profile_registry(register_profiles([f"op={profile}"]))
    bound = mcp_select_profile("op")
    assert bound["success"] is True, bound
    return profile


def _gate(profile: Path, override: str):
    """The gate a workspace scan's overrides go through, with the registered
    profile named as the call's own."""
    return workspace_module._gate_client_overrides(
        [override], str(profile), profile="op"
    )


def test_a_removal_from_the_plugin_module_list_is_denied_by_its_path(tmp_path):
    """``ash_plugin_modules`` lists modules ASH imports into its own process, so its
    entry is always denied. A removal is checked as a ``remove`` of the list itself
    and refused by that entry, as a replacement of the list is."""
    profile = _profile_allowing_every_path(tmp_path)

    with pytest.raises(
        RuntimePatchDeniedError,
        match=re.escape(
            "path '/ash_plugin_modules' matches denied_paths entry "
            "'/ash_plugin_modules'"
        ),
    ) as raised:
        _gate(profile, 'ash_plugin_modules-=["standin_module"]')

    assert raised.value.op == {"op": "remove", "path": "/ash_plugin_modules"}


def test_a_removal_at_a_path_an_exact_entry_denies_is_denied(tmp_path):
    """The shipped denied_paths name checkov's ``frameworks`` by its exact path,
    with no ``/**`` under it. A removal is checked at that path, so the entry denies
    it as it denies a replacement, whether or not the session config's list holds
    the items."""
    profile = _profile_allowing_every_path(tmp_path)

    with pytest.raises(
        RuntimePatchDeniedError,
        match=re.escape(
            "path '/scanners/checkov/options/frameworks' matches denied_paths "
            "entry '/scanners/checkov/options/frameworks'"
        ),
    ) as raised:
        _gate(profile, 'scanners.checkov.options.frameworks-=["terraform"]')

    assert raised.value.op == {
        "op": "remove",
        "path": "/scanners/checkov/options/frameworks",
    }


@pytest.mark.parametrize(
    "override",
    [
        'scanners.checkov.options.frameworks=["terraform"]',
        'scanners.checkov.options.frameworks+=["terraform"]',
    ],
    ids=["replace", "append"],
)
def test_a_replacement_or_an_append_at_that_path_is_denied(tmp_path, override):
    """Control for the case above: under the same profile the exact entry denies
    the two forms that write the list, so the removal is held to the rule they
    already meet."""
    profile = _profile_allowing_every_path(tmp_path)

    with pytest.raises(
        RuntimePatchDeniedError,
        match=re.escape("denied_paths entry '/scanners/checkov/options/frameworks'"),
    ):
        _gate(profile, override)


def test_a_removal_of_a_reporters_enabled_flag_gets_no_turn_off_exemption(tmp_path):
    """Control for the op shape. An ``add`` of ``enabled: false`` under a reporter
    that sends findings off the host is accepted and left out, with a warning
    (``runtime_patch._turns_an_off_host_reporter_off``). A removal writes no value,
    so it is no turn-off, and the reporter's section entry denies it. It stays green
    while the gate checks a removal as a ``remove``: checked as an ``add`` of its
    value, ``reporters.s3.enabled-=false`` would be accepted and dropped instead."""
    profile = _profile_allowing_every_path(tmp_path)

    with pytest.raises(
        RuntimePatchDeniedError,
        match=re.escape("denied_paths entry '/reporters/s3/**'"),
    ):
        _gate(profile, "reporters.s3.enabled-=false")


def test_a_removal_on_an_allowed_list_path_is_kept(tmp_path):
    """Control: under the same profile, a removal from a list the session config
    holds and no denied_paths entry covers is accepted and handed on, so the
    refusals above come from their entries, not from the removal itself."""
    profile = _profile_allowing_every_path(tmp_path, extra=_ACME_CONVERTER)
    override = 'converters.acme-converter.options.destinations-=["ops"]'

    assert _gate(profile, override) == [override]
