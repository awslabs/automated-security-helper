# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The archive extraction limits are refused to a runtime override whatever the profile lists.

The shipped ``runtime_overrides.denied_paths`` names the four limit pointers, but an
operator's profile that sets its own ``denied_paths`` replaces that list, and with it
the only thing keeping an MCP client from raising the limits. They are now refused
on top of whatever ``denied_paths`` says, on every route that applies a client's
change: ``patch_ops``, ``override_yaml`` and the workspace tools' overrides all go
through ``check_runtime_ops``.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import (
    AshConfig,
    RuntimeOverridesConfig,
)
from automated_security_helper.config.runtime_patch import (
    RuntimePatchDeniedError,
    apply_runtime_override,
    apply_runtime_patch,
)

pytestmark = pytest.mark.unit

LIMITS = ("max_members", "max_member_bytes", "max_total_bytes", "max_compression_ratio")


def own_list(denied=()) -> RuntimeOverridesConfig:
    """A profile's policy with its own denied_paths, which replaces the shipped one."""
    return RuntimeOverridesConfig(
        enabled=True, allowed_paths=["/converters/**"], denied_paths=list(denied)
    )


@pytest.mark.parametrize("denied", [[], ["/fail_on_findings"]], ids=["empty", "other"])
@pytest.mark.parametrize(
    "pointer",
    [f"/converters/archive/options/{name}" for name in LIMITS]
    + ["/converters/archive/options/max-total-bytes"],
)
def test_a_patch_of_a_limit_is_refused_under_a_profile_s_own_list(pointer, denied):
    ops = [{"op": "replace", "path": pointer, "value": 10**15}]

    with pytest.raises(RuntimePatchDeniedError):
        apply_runtime_patch(AshConfig(), ops, allowlist=own_list(denied))


@pytest.mark.parametrize(
    "pointer", ["/converters/archive/options", "/converters/archive", "/converters"]
)
def test_a_patch_of_a_section_holding_the_limits_is_refused(pointer):
    converters = AshConfig().converters.model_dump(mode="json", by_alias=True)
    converters["archive"]["options"]["max_total_bytes"] = 10**15
    value = {
        "/converters/archive/options": converters["archive"]["options"],
        "/converters/archive": converters["archive"],
        "/converters": converters,
    }[pointer]

    with pytest.raises(RuntimePatchDeniedError):
        apply_runtime_patch(
            AshConfig(),
            [{"op": "replace", "path": pointer, "value": value}],
            allowlist=own_list(),
        )


def test_an_override_of_a_limit_is_refused_under_a_profile_s_own_list():
    base = AshConfig()
    after = base.model_copy(deep=True)
    after.converters.archive.options.max_members = 10**9

    with pytest.raises(RuntimePatchDeniedError):
        apply_runtime_override(base, after, allowlist=own_list())


def test_another_converter_setting_is_still_overridable_under_a_profile_s_own_list():
    ops = [{"op": "replace", "path": "/converters/jupyter/enabled", "value": False}]

    result = apply_runtime_patch(AshConfig(), ops, allowlist=own_list())

    assert result.converters.jupyter.enabled is False
