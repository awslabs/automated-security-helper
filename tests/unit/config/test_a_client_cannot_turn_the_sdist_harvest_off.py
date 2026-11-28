# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A client cannot turn the sdist lockfile harvest off.

The harvest completes syft's SBOM with the packages that the source
distributions a lockfile pins embed, and the findings are read from that SBOM.
Two settings turn it off: ``scanners.syft.options.sdist_harvest.enabled``, and
the ``sdist-lock-harvester`` converter's own ``enabled``, which decides whether
the converter runs at all. Disabling the syft scanner itself is a client's
choice: the converter then fetches nothing, and while grype or trivy runs it
names what it did not fetch in a visible skip.

A client has two routes to a setting: a runtime patch op, which
``check_runtime_ops`` judges, and a config file an MCP client delivers, which
``client_file_denials`` judges. The default runtime-override policy refuses both
settings on both routes. A delivered file that repeats the syft option's default,
or that writes neither setting, draws no denial at either one.
"""

from __future__ import annotations

from types import SimpleNamespace

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


def test_a_delivered_file_that_repeats_the_converter_default_is_accepted(
    tmp_path,
) -> None:
    """A delivered ``converters.sdist-lock-harvester.enabled: true`` is the default.

    Repeating a default is no change, as it is for a scanner option.
    """
    pointer = SWITCHES["converter"][0]
    document = {"converters": {"sdist-lock-harvester": {"enabled": True}}}
    refused = _refused_pointers(document, tmp_path)
    assert pointer not in refused, f"refused at {refused}"


def test_control_a_trusted_off_converter_still_refuses_a_delivered_on(
    tmp_path,
) -> None:
    """Where the trusted config holds ``enabled: false``, a delivered ``true`` is
    a change and is refused.
    """
    pointer = SWITCHES["converter"][0]
    base = AshConfig.model_validate(
        {"converters": {"sdist-lock-harvester": {"enabled": False}}}
    )
    delivered = {"converters": {"sdist-lock-harvester": {"enabled": True}}}
    found = ccp.client_file_denials(
        {tmp_path / "delivered.yaml": delivered},
        ccp.rules_from(base),
        scanned_root=tmp_path,
        all_delivered=True,
    )
    refused = [denial.pointer for _path, denials in found for denial in denials]
    assert pointer in refused, f"{pointer} was not refused; refused at {refused}"


def test_disabling_the_syft_scanner_is_not_refused(tmp_path) -> None:
    """Turning the syft scanner off is a client's choice and draws no denial."""
    refused = _refused_pointers({"scanners": {"syft": {"enabled": False}}}, tmp_path)
    assert "/scanners/syft/enabled" not in refused, f"refused at {refused}"


def test_the_converter_default_is_the_converters_own() -> None:
    """The table's value is the converter config's own ``enabled`` default."""
    from automated_security_helper.plugin_modules.ash_builtin.converters.sdist_lock_harvester import (
        SdistLockHarvesterConverterConfig,
    )

    assert ccp.CONVERTER_SECTION_DEFAULTS[("sdist-lock-harvester", "enabled")] == (
        SdistLockHarvesterConverterConfig().enabled
    )


# The rule that forgives a delivered converter default, read the way the scanner
# option rule is read: by JSON value, under every spelling of the section, and
# against the default only where the trusted section holds no value.


def _converter_default_written(section: str, value: object, trusted: object) -> bool:
    """Whether a delivered ``converters.<section>.enabled: <value>`` is forgiven.

    ``trusted`` is what the trusted config's ``get_plugin_config`` returns for the
    converter.
    """
    base = SimpleNamespace(get_plugin_config=lambda _kind, _name: trusted)
    document = {"converters": {section: {"enabled": value}}}
    denial = SimpleNamespace(pointer=f"/converters/{section}/enabled", from_patch=False)
    return ccp._writes_plugin_default(document, denial, base)


@pytest.mark.parametrize("value", [1, "true", 1.0, "yes"])
def test_a_value_equal_to_the_converter_default_only_in_python_is_not_it(
    value: object,
) -> None:
    """``enabled: 1`` is not the default ``true`` as JSON, and no string is."""
    assert (
        _converter_default_written("sdist-lock-harvester", value, trusted={}) is False
    )


def test_control_the_exact_converter_default_is_forgiven() -> None:
    assert _converter_default_written("sdist-lock-harvester", True, trusted={}) is True


@pytest.mark.parametrize(
    "section", ["sdist-lock-harvester", "sdist_lock_harvester", "SdistLockHarvester"]
)
def test_the_converter_default_is_read_under_each_spelling_of_its_section(
    section: str,
) -> None:
    """The section is found under each spelling ``plugin_key_lookup_names`` reads."""
    assert _converter_default_written(section, True, trusted={}) is True


def test_control_another_converters_section_is_not_forgiven() -> None:
    assert _converter_default_written("archive", True, trusted={}) is False


@pytest.mark.parametrize(("value", "forgiven"), [(True, True), (False, False)])
def test_a_trusted_section_without_enabled_is_compared_with_the_default(
    value: bool, forgiven: bool
) -> None:
    """A trusted section that holds no ``enabled`` has no value of its own there.

    The delivered value is then compared with the converter's default.
    """
    trusted = {"name": "sdist-lock-harvester"}
    assert (
        _converter_default_written("sdist-lock-harvester", value, trusted=trusted)
        is forgiven
    )


def test_control_a_trusted_enabled_leaves_the_rule_to_the_denial() -> None:
    """Where the trusted section holds ``enabled``, the denial already compared the
    delivered value with it, so this rule forgives nothing."""
    assert (
        _converter_default_written(
            "sdist-lock-harvester", True, trusted={"enabled": True}
        )
        is False
    )


@pytest.mark.parametrize("section", ["sdist_lock_harvester", "SdistLockHarvester"])
def test_a_delivered_file_cannot_turn_the_harvest_off_under_another_spelling(
    tmp_path, section: str
) -> None:
    """Another spelling of the section does not get past the default policy."""
    pointer = f"/converters/{section}/enabled"
    refused = _refused_pointers({"converters": {section: {"enabled": False}}}, tmp_path)
    assert pointer in refused, f"{pointer} was not refused; refused at {refused}"


@pytest.mark.parametrize("section", ["sdist_lock_harvester", "SdistLockHarvester"])
def test_a_delivered_file_repeating_the_default_under_another_spelling_is_accepted(
    tmp_path, section: str
) -> None:
    pointer = f"/converters/{section}/enabled"
    refused = _refused_pointers({"converters": {section: {"enabled": True}}}, tmp_path)
    assert pointer not in refused, f"refused at {refused}"
