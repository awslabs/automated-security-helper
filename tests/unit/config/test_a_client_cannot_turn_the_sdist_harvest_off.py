# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A client cannot turn the sdist lockfile harvest off.

The harvest completes syft's SBOM with the packages that the source
distributions a lockfile pins embed, and the findings are read from that SBOM.
Two settings turn it off: ``scanners.syft.options.sdist_harvest.enabled``, and
the ``sdist-lock-harvester`` converter's own ``enabled``, which decides whether
the converter runs at all.

A client has two routes to a setting: a runtime patch op, which
``check_runtime_ops`` judges, and a config file an MCP client delivers, which
``client_file_denials`` judges. The default runtime-override policy refuses both
settings on both routes. A delivered file that repeats the syft option's default,
or that writes neither setting, draws no denial at either one.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config import client_config_policy as ccp
from automated_security_helper.config.ash_config import (
    AshConfig,
    RuntimeOverridesConfig,
)
from automated_security_helper.config.runtime_patch import (
    RuntimePatchDeniedError,
    check_runtime_ops,
)

pytestmark = pytest.mark.unit

#: Each setting that turns the harvest off, by name: its JSON pointer, and a config
#: document that sets it to false.
SWITCHES: dict[str, tuple[str, dict]] = {
    "syft-option": (
        "/scanners/syft/options/sdist_harvest/enabled",
        {"scanners": {"syft": {"options": {"sdist_harvest": {"enabled": False}}}}},
    ),
    "converter": (
        "/converters/sdist-lock-harvester/enabled",
        {"converters": {"sdist-lock-harvester": {"enabled": False}}},
    ),
}


def _default_denials_policy() -> RuntimeOverridesConfig:
    """Runtime overrides on and every path allowed, with the default ``denied_paths``.

    Overrides are on and every path is allowed so that a refusal can only come
    from a ``denied_paths`` entry, and ``denied_paths`` is the default list.
    """
    return RuntimeOverridesConfig(enabled=True, allowed_paths=["/**"])


def _refused_pointers(document: dict, tmp_path) -> list[str]:
    """The pointers at which the default policy refuses a delivered ``document``.

    The file counts as client-delivered, and the rules are the default policy
    (``RuntimeOverridesConfig()``) over a default ``AshConfig``.
    """
    found = ccp.client_file_denials(
        {tmp_path / "delivered.yaml": document},
        ccp.rules_from(AshConfig()),
        scanned_root=tmp_path,
        all_delivered=True,
    )
    return [denial.pointer for _path, denials in found for denial in denials]


def _value_at(document: dict, pointer: str) -> object:
    """The value ``document`` holds at the JSON pointer ``pointer``."""
    value = document
    for segment in pointer.split("/")[1:]:
        value = value[segment]
    return value


def test_the_policy_under_test_keeps_the_default_denied_paths() -> None:
    """The policy the runtime-patch tests use holds the default ``denied_paths``.

    It adds no entry of its own and leaves none out.
    """
    shipped = RuntimeOverridesConfig().denied_paths
    assert _default_denials_policy().denied_paths == shipped


@pytest.mark.parametrize("switch", sorted(SWITCHES))
def test_a_runtime_patch_cannot_turn_the_harvest_off(switch: str) -> None:
    """The default policy refuses a patch op that sets either setting to false.

    The refusal names a ``denied_paths`` entry as its reason.
    """
    pointer, _document = SWITCHES[switch]
    ops = [{"op": "add", "path": pointer, "value": False}]
    with pytest.raises(RuntimePatchDeniedError) as excinfo:
        check_runtime_ops(ops, allowlist=_default_denials_policy(), config=AshConfig())
    assert "denied_paths entry" in excinfo.value.rule, excinfo.value.rule


def test_control_the_same_policy_accepts_a_patch_no_entry_denies() -> None:
    """An op on a field no ``denied_paths`` entry covers is accepted.

    The policy has overrides on and every path allowed, so the refusals above come
    from its ``denied_paths`` entries and not from the master switch.
    """
    check_runtime_ops(
        [{"op": "add", "path": "/project_name", "value": "renamed"}],
        allowlist=_default_denials_policy(),
        config=AshConfig(),
    )


@pytest.mark.parametrize("switch", sorted(SWITCHES))
def test_a_delivered_config_file_cannot_turn_the_harvest_off(
    tmp_path, switch: str
) -> None:
    """The default policy refuses a delivered config file that sets either setting
    to false.
    """
    pointer, document = SWITCHES[switch]
    refused = _refused_pointers(document, tmp_path)
    assert pointer in refused, f"{pointer} was not refused; refused at {refused}"


def test_control_a_delivered_file_that_keeps_the_harvest_on_is_accepted(
    tmp_path,
) -> None:
    """A delivered file that repeats the syft option's default, ``enabled: true``,
    draws no denial at its pointer, and a file that writes neither setting draws
    none at either pointer.

    The refusals above are about turning the harvest off, not about every write
    near it.
    """
    syft_pointer = SWITCHES["syft-option"][0]
    repeats_the_default = {
        "scanners": {"syft": {"options": {"sdist_harvest": {"enabled": True}}}}
    }
    # The file writes the setting the refusals above are about, at its default,
    # which is the value the trusted config holds there.
    assert _value_at(repeats_the_default, syft_pointer) is True
    refused = _refused_pointers(repeats_the_default, tmp_path)
    assert syft_pointer not in refused, f"refused at {refused}"

    pointers = [SWITCHES[switch][0] for switch in sorted(SWITCHES)]
    refused = _refused_pointers({"project_name": "renamed"}, tmp_path)
    assert [p for p in pointers if p in refused] == [], f"refused at {refused}"
