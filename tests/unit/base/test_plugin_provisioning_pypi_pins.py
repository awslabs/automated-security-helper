"""PyPI pins in the provisioning register, and the rules that keep them honest.

``base/plugin_provisioning.py`` declares what the engine provisions for each scanner.
It now also records the PyPI distribution an alpha scanner installs (``PypiPin``), the
reason a distribution is held out of the alpha extra (``Exclusion``), and, for a content
database, the environment variable that moves its cache (``ContentDatabase.cache_env``).

The registry refuses four contradictions in pins, and each refusal here has a planted
input that must be refused and a sibling input, differing only in the flagged property,
that must be accepted. Without the sibling a pass could mean the check refuses
everything.

Every name the unit adds is read inside a test body, so the rows that exist today stay
importable and the new rows fail one by one where the names do not exist.
"""

from __future__ import annotations

import dataclasses
import re
from datetime import timedelta
from pathlib import Path

import pytest

from automated_security_helper.base import plugin_provisioning as prov
from automated_security_helper.plugin_manifests import scanner_manifests

pytestmark = pytest.mark.unit

_ROOT = Path(__file__).resolve().parents[3]
_PACKAGE = _ROOT / "automated_security_helper"


# ---------------------------------------------------------------------------
# Builders. Each reads the new names when it is called, not when this file loads.
# ---------------------------------------------------------------------------


def _pin(**changes):
    fields = {
        "distribution": "alpha-tool",
        "specifier": "==1.0.0",
        "runtime": "uv-tool",
    }
    fields.update(changes)
    return prov.PypiPin(**fields)


def _exclusion(reason="OWNER_HOLD", **changes):
    fields = {
        "reason": prov.ExclusionReason[reason],
        "detail": "a detail",
        "measured": "a measurement",
    }
    fields.update(changes)
    return prov.Exclusion(**fields)


def _block(*pins):
    return prov.Provisioning(pypi_pins=tuple(pins))


# ---------------------------------------------------------------------------
# The vocabulary and the shapes
# ---------------------------------------------------------------------------


def test_the_exclusion_reasons_are_the_six_the_register_names() -> None:
    assert [reason.value for reason in prov.ExclusionReason] == [
        "core_pin_conflict",
        "extra_conflict",
        "needs_build",
        "no_wheels",
        "cooldown",
        "owner_hold",
    ]
    assert issubclass(prov.ExclusionReason, str)


def test_a_pin_needs_only_a_distribution_a_specifier_and_a_runtime() -> None:
    pin = prov.PypiPin("tool", "==1", "uv-tool")

    assert pin.with_requirements == ()
    assert pin.python_marker == ""
    assert pin.platform_marker == ""
    assert pin.extra == ""
    assert pin.excluded is None
    assert pin.note == ""
    assert prov.Exclusion(prov.ExclusionReason.OWNER_HOLD, "d", "m").until == ""


def test_a_provisioning_block_with_no_pin_has_an_empty_tuple() -> None:
    """Every block that exists today keeps meaning what it meant."""
    assert prov.Provisioning().pypi_pins == ()
    assert prov.NO_PROVISIONING.pypi_pins == ()


def test_a_pin_and_its_exclusion_are_values() -> None:
    pin = _pin(excluded=_exclusion())

    with pytest.raises(dataclasses.FrozenInstanceError):
        pin.specifier = "==2"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        pin.excluded.detail = "another"  # type: ignore[misc]
    assert _pin() == _pin()
    assert _pin() != _pin(specifier="==2.0.0")


@pytest.mark.parametrize(
    ("name", "normalized"),
    [
        ("Foo_Bar", "foo-bar"),
        ("foo.bar", "foo-bar"),
        ("FOO--bar", "foo-bar"),
        ("a_._b", "a-b"),
        ("ferret-scan", "ferret-scan"),
        ("foobar", "foobar"),
    ],
)
def test_a_distribution_name_is_compared_the_way_pep_503_normalizes_it(
    name, normalized
) -> None:
    assert prov.normalize_distribution(name) == normalized


# ---------------------------------------------------------------------------
# The four refusals, each with a planted input and an accepted sibling
# ---------------------------------------------------------------------------


def _same_distribution_in_two_scanners():
    return {"a": _block(_pin()), "b": _block(_pin())}


def _same_distribution_twice_in_one_block():
    return {"a": _block(_pin(), _pin(specifier="==2.0.0"))}


def _same_distribution_under_two_spellings():
    return {
        "a": _block(_pin(distribution="Foo_Bar")),
        "b": _block(_pin(distribution="foo.bar")),
    }


def _a_member_that_is_also_excluded():
    return {"a": _block(_pin(extra="alpha", excluded=_exclusion()))}


def _a_specifier_with_a_marker_in_it():
    return {"a": _block(_pin(specifier=">=1.0; python_version < '3.14'"))}


def _an_empty_specifier():
    return {"a": _block(_pin(specifier=""))}


def _a_blank_specifier():
    return {"a": _block(_pin(specifier="   "))}


def _a_cooldown_with_no_date():
    return {"a": _block(_pin(excluded=_exclusion("COOLDOWN")))}


_DUPLICATE = "is pinned twice"
_BOTH = "as a member of the 'alpha' extra and also excludes it"
_SPECIFIER = "must be non-empty and hold no ';'"
_COOLDOWN = "cooldown exclusion of 'alpha-tool' carries no 'until' date"

_REFUSED = {
    "a distribution pinned by two scanners": (
        _same_distribution_in_two_scanners,
        _DUPLICATE,
    ),
    "a distribution pinned twice in one block": (
        _same_distribution_twice_in_one_block,
        _DUPLICATE,
    ),
    "a distribution under two spellings": (
        _same_distribution_under_two_spellings,
        _DUPLICATE,
    ),
    "a member that is also excluded": (_a_member_that_is_also_excluded, _BOTH),
    "a specifier holding a marker": (_a_specifier_with_a_marker_in_it, _SPECIFIER),
    "an empty specifier": (_an_empty_specifier, _SPECIFIER),
    "a blank specifier": (_a_blank_specifier, _SPECIFIER),
    "a cooldown with no date": (_a_cooldown_with_no_date, _COOLDOWN),
}


def _two_different_distributions():
    return {"a": _block(_pin()), "b": _block(_pin(distribution="other-tool"))}


def _two_distributions_that_only_look_alike():
    return {
        "a": _block(_pin(distribution="foo-bar")),
        "b": _block(_pin(distribution="foobar")),
    }


def _a_member_that_is_not_excluded():
    return {"a": _block(_pin(extra="alpha"))}


def _an_exclusion_that_is_not_a_member():
    return {"a": _block(_pin(excluded=_exclusion()))}


def _a_range_and_the_markers_in_their_own_fields():
    return {
        "a": _block(
            _pin(
                specifier=">=2.4.5,<2.7.0",
                with_requirements=("pluggy<1.7",),
                python_marker="python_version < '3.14'",
                platform_marker="sys_platform != 'win32'",
            )
        )
    }


def _a_cooldown_with_a_date():
    return {"a": _block(_pin(excluded=_exclusion("COOLDOWN", until="2026-12-01")))}


def _an_exclusion_that_needs_no_date():
    return {
        "a": _block(
            _pin(excluded=_exclusion("NEEDS_BUILD")),
            _pin(distribution="b", excluded=_exclusion("NO_WHEELS")),
        )
    }


_ACCEPTED = {
    "two different distributions": _two_different_distributions,
    "two distributions that only look alike": _two_distributions_that_only_look_alike,
    "a member that is not excluded": _a_member_that_is_not_excluded,
    "an exclusion that is not a member": _an_exclusion_that_is_not_a_member,
    "a range with its markers in their own fields": (
        _a_range_and_the_markers_in_their_own_fields
    ),
    "a cooldown with a date": _a_cooldown_with_a_date,
    "an exclusion that needs no date": _an_exclusion_that_needs_no_date,
}


@pytest.mark.parametrize("case", sorted(_REFUSED))
def test_the_registry_refuses_a_contradiction_in_pins(case: str) -> None:
    build, fragment = _REFUSED[case]

    with pytest.raises(prov.ProvisioningRegistryError, match=re.escape(fragment)):
        prov.check_registry(build())


@pytest.mark.parametrize("case", sorted(_ACCEPTED))
def test_the_registry_accepts_a_pin_that_contradicts_nothing(case: str) -> None:
    prov.check_registry(_ACCEPTED[case]())


def test_a_refusal_names_the_scanners_and_the_distribution() -> None:
    """A reader fixing the table is told which blocks to look at."""
    with pytest.raises(prov.ProvisioningRegistryError) as excinfo:
        prov.check_registry(_same_distribution_in_two_scanners())

    message = str(excinfo.value)
    assert "'alpha-tool'" in message
    assert "'a'" in message and "'b'" in message


def test_the_shipped_pins_pass_the_rules() -> None:
    prov.check_registry()


# ---------------------------------------------------------------------------
# What the register holds today
# ---------------------------------------------------------------------------

#: scanner -> (distribution, runtime). ferret-scan installs into the environment ASH
#: runs in; GuardDog is a uv tool with an environment of its own.
_SEEDS = {
    "ferret-scan": ("ferret-scan", "ash-environment"),
    "guarddog": ("guarddog", "uv-tool"),
}


@pytest.mark.parametrize("scanner", sorted(_SEEDS))
def test_an_alpha_python_package_is_pinned_and_held_for_a_maintainer_decision(
    scanner: str,
) -> None:
    distribution, runtime = _SEEDS[scanner]

    (pin,) = prov.provisioning_for(scanner).pypi_pins

    assert (pin.distribution, pin.runtime) == (distribution, runtime)
    assert pin.extra == ""
    assert pin.excluded is not None
    assert pin.excluded.reason is prov.ExclusionReason.OWNER_HOLD
    assert "maintainer" in pin.excluded.detail
    assert pin.excluded.measured.strip()
    assert pin.excluded.until == ""


def test_guarddog_is_held_for_its_python_and_platform_limits() -> None:
    """The markers record what the pin would need if the hold were lifted; the rows
    that say why are the runtime-compat row and ``unsupported_platform_reason``."""
    (pin,) = prov.provisioning_for("guarddog").pypi_pins

    assert pin.python_marker == "python_version < '3.14'"
    assert pin.platform_marker == "sys_platform != 'win32'"


def test_only_the_two_alpha_python_packages_declare_a_pin() -> None:
    declared = sorted(
        name for name, block in prov.PROVISIONING.items() if block.pypi_pins
    )

    assert declared == ["ferret-scan", "guarddog"]


def test_the_alpha_manifests_carry_the_new_blocks() -> None:
    manifests = {m.name: m for m in scanner_manifests()}

    for name in sorted(_SEEDS):
        assert manifests[name].provisioning is prov.PROVISIONING[name], name
        assert manifests[name].provisioning.pypi_pins, name


def test_a_pin_adds_no_release_pin_to_the_tool_table() -> None:
    """A PyPI pin is not a release asset: ``tool_versions`` is unchanged by it."""
    assert "ferret-scan" not in prov.tool_versions()
    assert "guarddog" not in prov.tool_versions()


# ---------------------------------------------------------------------------
# The content database's cache variable
# ---------------------------------------------------------------------------


def test_only_the_trivy_database_names_a_cache_variable() -> None:
    rows = [(db.name, db.cache_env) for db in prov.content_databases()]

    assert rows == [
        ("grype-db", None),
        ("trivy-db", "TRIVY_CACHE_DIR"),
        ("semgrep-offline-rules", None),
        ("opengrep-offline-rules", None),
    ]


def test_a_database_may_leave_its_cache_variable_out() -> None:
    database = prov.ContentDatabase(
        name="db",
        scanner="a",
        cache_path="/x",
        max_age=timedelta(hours=1),
        bound_source="s",
        bound_is_tool_default=False,
        age_source="a",
        refresh="r",
    )

    assert database.cache_env is None


def test_the_trivy_cache_variable_is_the_one_the_plugin_and_the_image_name() -> None:
    readme_path = _PACKAGE / "plugin_modules" / "ash_trivy_plugins" / "README.md"
    readme = readme_path.read_text(encoding="utf-8")
    dockerfile = (_ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "`TRIVY_CACHE_DIR`" in readme
    assert re.search(r"^ENV TRIVY_CACHE_DIR=", dockerfile, flags=re.MULTILINE)
