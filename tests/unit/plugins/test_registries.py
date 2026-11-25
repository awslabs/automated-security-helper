# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The two shipped registries: invariants, uniform mechanics, and promotion.

Membership IS the externality: "alpha" means "listed in ``ALPHA.members``",
nothing else, and the one behavioral consequence of membership is default
enablement (``plugins.enablement``). These tests pin the declarations'
invariants, the uniform-surface property (an opt-in shipped plugin's mechanics
are a custom SDK plugin's mechanics, and nothing on the record says which is
which), and the promotion differential (moving a member between the two
tuples flips enablement and grouping, and nothing on the record).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from automated_security_helper.plugins import enablement, registries
from automated_security_helper.plugins.loader import scan_plugin_filter
from automated_security_helper.plugins.plugin_manager import AshPluginRegistration
from automated_security_helper.plugins.registries import (
    ALPHA,
    CORE,
    SHIPPED_REGISTRIES,
    Registry,
    registry_of,
)

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
PLUGIN_MODULES_DIR = REPO_ROOT / "automated_security_helper" / "plugin_modules"


# ---------------------------------------------------------------------------
# Registry definition invariants (the A-1/A-2 declarations).
# ---------------------------------------------------------------------------


def test_member_lists_are_non_empty_disjoint_and_duplicate_free() -> None:
    assert CORE.members and ALPHA.members
    assert len(set(CORE.members)) == len(CORE.members)
    assert len(set(ALPHA.members)) == len(ALPHA.members)
    assert not set(CORE.members) & set(ALPHA.members), (
        "a module in both registries has two enablement defaults at once"
    )


def test_every_member_resolves_to_a_shipped_package_directory() -> None:
    prefix = "automated_security_helper.plugin_modules."
    for registry in SHIPPED_REGISTRIES:
        for member in registry.members:
            assert member.startswith(prefix), member
            package_dir = PLUGIN_MODULES_DIR.joinpath(*member[len(prefix) :].split("."))
            assert (package_dir / "__init__.py").is_file(), (
                f"{registry.name} declares {member}, which resolves to no "
                f"package directory at {package_dir}"
            )


def test_declared_alpha_members_match_the_directory_census() -> None:
    """The M1 transition pin, replacing the old E1 == E3 equality test.

    Until per-plugin manifests own file lists, the explicit declaration and
    the shipped directories must agree: a package added to or removed from
    ``plugin_modules/`` without its membership edit fails here, in whichever
    direction it drifted.
    """
    census = {
        f"automated_security_helper.plugin_modules.{package.name}"
        for package in PLUGIN_MODULES_DIR.glob("ash_*")
        if (package / "__init__.py").is_file()
        and "ASH_SCANNERS" in (package / "__init__.py").read_text(encoding="utf-8")
    }
    declared = {m for registry in SHIPPED_REGISTRIES for m in registry.members}
    assert declared == census, (
        "the registry declarations and the shipped scanner packages disagree; "
        f"declared-only: {sorted(declared - census)}, "
        f"directory-only: {sorted(census - declared)}"
    )
    # The AWS delivery reporters are the declared exception an explicit list
    # can express and a directory glob cannot: shipped, loaded only when
    # named, and in neither registry (enablement is not maturity).
    aws = "automated_security_helper.plugin_modules.ash_aws_plugins"
    assert registry_of(aws) is None and not enablement.loads_unnamed(aws)


def test_importing_registries_imports_no_plugin() -> None:
    """The declarations are side-effect-free: no plugin import, no registration."""
    code = (
        "import sys\n"
        "import automated_security_helper.plugins.registries as r\n"
        "polluted = [m for m in sys.modules if 'plugin_modules' in m]\n"
        "assert not polluted, polluted\n"
        "assert r.CORE.members and r.ALPHA.members\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr


def test_registry_of_covers_members_their_submodules_and_nothing_else() -> None:
    assert registry_of(CORE.members[0]) is CORE
    assert registry_of(f"{CORE.members[0]}.scanners.bandit_scanner") is CORE
    assert registry_of(ALPHA.members[0]) is ALPHA
    assert registry_of(f"{ALPHA.members[0]}.some_module") is ALPHA
    # A name that only shares a prefix is nobody's member.
    assert registry_of(f"{ALPHA.members[0]}_extra") is None
    assert registry_of("custom_ash_plugins") is None


# ---------------------------------------------------------------------------
# The enablement policy (A-3): the one behavioral meaning membership has.
# ---------------------------------------------------------------------------


def test_core_members_load_unnamed_and_everything_else_loads_when_named() -> None:
    assert enablement.loads_unnamed(CORE.members[0])
    assert enablement.loads_unnamed(f"{CORE.members[0]}.scanners.x")
    for member in ALPHA.members:
        assert not enablement.loads_unnamed(member)
    assert not enablement.loads_unnamed("custom_ash_plugins")
    assert set(enablement.modules_loading_unnamed()) == set(CORE.members)
    assert set(enablement.modules_needing_naming()) == set(ALPHA.members)


def test_the_shipped_scanner_index_is_built_from_membership() -> None:
    index = enablement.shipped_scanner_modules()
    assert index, "the shipped opt-in packages declare scanners"
    assert set(index.values()) <= set(ALPHA.members)
    assert enablement.shipped_module_for("snyk-code") == (
        "automated_security_helper.plugin_modules.ash_snyk_plugins"
    )
    assert enablement.shipped_module_for("no-such-scanner") is None


def test_the_unloaded_hint_names_the_module_and_no_tier_word() -> None:
    hint = enablement.unloaded_shipped_hint(
        {"snyk-code": "automated_security_helper.plugin_modules.ash_snyk_plugins"}
    )
    assert "snyk-code" in hint
    assert "ash_snyk_plugins" in hint
    assert "ash_plugin_modules" in hint
    assert "--ash-plugin-modules" in hint
    assert "alpha" not in hint.lower(), (
        "the refusal describes enablement, never maturity"
    )


def test_the_refusal_keeps_the_misspelling_clause_and_no_tier_word() -> None:
    scanner_cls = type(
        "FakeScanner",
        (),
        {"__module__": "automated_security_helper.plugin_modules.ash_builtin.x"},
    )
    refusal = enablement.unloaded_shipped_refusal(
        ["snyk-code", "bandittt"], ["bandit"], [scanner_cls]
    )
    assert "ash_snyk_plugins" in refusal
    assert "bandittt" in refusal and "check the spelling" in refusal
    assert "alpha" not in refusal.lower()
    # A selection where any name resolves is not this refusal's case.
    assert (
        enablement.unloaded_shipped_refusal(
            ["bandit", "snyk-code"], ["bandit"], [scanner_cls]
        )
        == ""
    )


# ---------------------------------------------------------------------------
# The uniform-surface differential (R2): nothing downstream can tell an
# opt-in shipped plugin from a custom SDK plugin.
# ---------------------------------------------------------------------------


def _defined_in(module: str, name: str = "Plugin") -> type:
    return type(name, (), {"__module__": module})


def test_the_registration_record_carries_no_origin_field() -> None:
    suspicious = ("tier", "origin", "registry", "maturity", "extern")
    for field_name in AshPluginRegistration.model_fields:
        assert not any(word in field_name.lower() for word in suspicious), (
            f"the plugin record grew an origin-revealing field: {field_name}"
        )
    shipped = AshPluginRegistration(name="X", plugin_module_path=ALPHA.members[0])
    custom = AshPluginRegistration(name="X", plugin_module_path="custom_ash_plugins")
    shipped_dump = shipped.model_dump()
    custom_dump = custom.model_dump()
    assert set(shipped_dump) == set(custom_dump)
    # Identity aside, the records are byte-identical: no field varies with
    # which registry (or none) the module sits in.
    del shipped_dump["plugin_module_path"], custom_dump["plugin_module_path"]
    assert shipped_dump == custom_dump


def test_selection_treats_a_shipped_optin_and_a_custom_identically() -> None:
    alpha_cls = _defined_in(ALPHA.members[0], "AlphaShipped")
    custom_cls = _defined_in("custom_ash_plugins", "Custom")
    core_cls = _defined_in(f"{CORE.members[0]}.scanners.x", "Core")

    named_both = scan_plugin_filter([ALPHA.members[0], "custom_ash_plugins"])
    assert named_both(alpha_cls) and named_both(custom_cls) and named_both(core_cls)

    named_neither = scan_plugin_filter([])
    assert not named_neither(alpha_cls)
    assert not named_neither(custom_cls), (
        "a custom plugin and a shipped opt-in plugin share one enablement rule"
    )
    assert named_neither(core_cls), "core members load unnamed"

    # The loader's submodule rule is also one rule for both: a class defined
    # only in a submodule of a named package is not selected through the
    # package (scan_plugin_filter's documented contract, unchanged here) --
    # and that answer does not depend on which registry, if any, carries the
    # package. CORE differs by design: its members load unnamed, subpackages
    # included.
    alpha_sub = _defined_in(f"{ALPHA.members[0]}.scanner", "AlphaSub")
    custom_sub = _defined_in("custom_ash_plugins.scanner", "CustomSub")
    assert named_both(alpha_sub) == named_both(custom_sub)
    assert not named_both(alpha_sub)


# ---------------------------------------------------------------------------
# The promotion differential (R7.7): a membership move flips default
# enablement and grouping, and nothing on the record.
# ---------------------------------------------------------------------------


def test_promotion_is_a_one_line_membership_move(monkeypatch) -> None:
    mover = ALPHA.members[0]
    promoted_core = Registry(name="core", members=(*CORE.members, mover))
    remaining_alpha = Registry(
        name="alpha", members=tuple(m for m in ALPHA.members if m != mover)
    )
    monkeypatch.setattr(registries, "CORE", promoted_core)
    monkeypatch.setattr(registries, "ALPHA", remaining_alpha)
    monkeypatch.setattr(
        registries, "SHIPPED_REGISTRIES", (promoted_core, remaining_alpha)
    )

    # Flip 1: default enablement.
    assert enablement.loads_unnamed(mover)
    assert mover in enablement.modules_loading_unnamed()
    assert mover not in enablement.modules_needing_naming()
    # Flip 2: grouping (what the docs generator renders).
    assert registries.registry_of(mover).name == "core"
    # And the name index no longer hints at the promoted module.
    assert mover not in set(enablement.shipped_scanner_modules().values())
    # Nothing on the record: the record model has no field to flip.
    record = AshPluginRegistration(name="X", plugin_module_path=mover)
    unchanged = AshPluginRegistration.model_fields.keys()
    assert set(record.model_dump()) == set(unchanged)


def test_a_fresh_member_tuple_is_not_served_a_stale_name_index(monkeypatch) -> None:
    before = enablement.shipped_scanner_modules()
    shrunk = Registry(name="alpha", members=ALPHA.members[:1])
    monkeypatch.setattr(registries, "ALPHA", shrunk)
    monkeypatch.setattr(registries, "SHIPPED_REGISTRIES", (registries.CORE, shrunk))
    after = enablement.shipped_scanner_modules()
    assert set(after.values()) <= set(shrunk.members)
    assert before != after
