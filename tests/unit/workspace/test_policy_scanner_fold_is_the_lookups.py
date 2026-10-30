# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The workspace policy folds a scanner name the way the plugin lookup reads a section.

``AshConfig.get_plugin_config`` reads a scanner's section under
``reduced_plugin_name``: ASCII case, the Converter/Scanner/Reporter word and every
character outside ``[a-z0-9+]`` dropped, so ``Snyk_Code``, ``snyk.code`` and
``snykcode`` are all ``snyk-code``'s. When several extra sections fold to one name
the lookup reads one of them: the key spelled as the reduced name if there is one,
else the first key written whose name without punctuation is the plugin's, else the
first whose name is the plugin's only once its Converter, Scanner or Reporter word is
removed. The plan lists the scanner only when that section is on and records that
section's pin alone; it also records every key that folds to the name as twins, a
section with no body included and the keys of both ranks (``acme`` beside
``acme-scanner``) together, because which of them the scan reads depends on the
plugin's registered name, which the plan does not know. It refuses a project that
holds twins when the workspace policy requires that scanner, naming every such
project. A pair that may be read by the plugin's exact name, such as ``Snyk_Code``
beside ``snyk-code``, cannot be resolved: it is listed only when every section of it
is on (a section with no body is off), and its pin is recorded only when the sections
agree. When they do not, each version either section may apply is held against the
pins every other project records for the scanner, under whichever spelling of it the
other project's file order gives the key its lookup reads. A declared scanner's
section is read by its exact name,
so a spelling beside it does not decide whether the policy adds the scanner.
"""

from __future__ import annotations

import json

import pytest

from automated_security_helper.config.ash_config import AshConfig, reduced_plugin_name
from automated_security_helper.config.ash_workspace_config import WorkspacePolicyConfig
from automated_security_helper.core.exceptions import WorkspaceDefinitionError
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.workspace.execution import (
    ProjectScanSettings,
    _enable_policy_scanners,
    execute_workspace,
)
from automated_security_helper.workspace.policy import (
    normalise_scanner_name,
    policy_for_project,
)
from automated_security_helper.workspace.resolver import (
    _scanner_state,
    resolve_workspace,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()

SNYK_CODE = "snyk-code"

#: Two sections of one plugin, one enabled and one not, in each order.
TWINS = [
    pytest.param(
        {"Snyk_Code": {"enabled": True}, "snyk.code": {"enabled": False}},
        id="disabled-last",
    ),
    pytest.param(
        {"snyk.code": {"enabled": False}, "Snyk_Code": {"enabled": True}},
        id="disabled-first",
    ),
]


def _config(sections: dict) -> AshConfig:
    return AshConfig.model_validate({"project_name": "t", "scanners": sections})


def _twin_names(names) -> list:
    """The names in *names* that the plugin lookup reads as snyk-code's."""
    return [
        name
        for name in names
        if normalise_scanner_name(name) == normalise_scanner_name(SNYK_CODE)
    ]


def _policy_scanners(config: AshConfig) -> tuple:
    """The scanners the policy adds for a project with ``config``."""
    enabled, _pins, _twins = _scanner_state(config)
    return policy_for_project(
        WorkspacePolicyConfig(additional_scanners=[SNYK_CODE]),
        project_prefix="api",
        project_threshold="MEDIUM",
        project_scanners=enabled,
    ).policy_scanners


@pytest.mark.parametrize(
    "spelling", ["Snyk_Code", "snyk.code", "SNYK-CODE", "snykcode", " snyk-code "]
)
def test_the_policy_folds_a_scanner_name_the_way_the_lookup_does(spelling):
    # Control: the lookup reads every one of these as snyk-code's.
    assert reduced_plugin_name(spelling) == reduced_plugin_name(SNYK_CODE)
    assert normalise_scanner_name(spelling) == normalise_scanner_name(SNYK_CODE)


@pytest.mark.parametrize("sections", TWINS)
def test_two_spellings_of_one_extra_scanner_are_recorded_as_twins(sections):
    """The lookup reads one of two sections that reduce to one name, and the plan
    must not guess which, so it records both keys and leaves the refusal to the
    policy that requires the scanner."""
    _enabled, _pins, twins = _scanner_state(_config(sections))

    assert twins == {"snykcode": list(sections)}


def test_two_spellings_that_agree_are_recorded_as_twins_as_well():
    """The rule is about which section is read, not about the two values."""
    _enabled, _pins, twins = _scanner_state(
        _config({"Snyk_Code": {"enabled": True}, "snyk.code": {"enabled": True}})
    )

    assert twins == {"snykcode": ["Snyk_Code", "snyk.code"]}


def test_control_two_different_extra_scanners_are_not_twins():
    """Two extra sections that reduce to different names are two scanners.

    Every built-in scanner is declared and on by default, so the enabled list
    includes those names too. The control reads the two extra names in it.
    """
    enabled, _pins, twins = _scanner_state(
        _config({"Snyk_Code": {"enabled": True}, "snyk-other": {"enabled": False}})
    )

    assert twins == {}
    assert "Snyk_Code" in enabled
    assert "snyk-other" not in enabled


def test_a_spelling_beside_a_declared_scanner_does_not_make_it_the_policys():
    """The lookup reads a declared scanner's section by its exact name."""
    config = _config(
        {"detect-secrets": {"enabled": True}, "detect.secrets": {"enabled": False}}
    )

    enabled, _pins, _twins = _scanner_state(config)
    resolved = policy_for_project(
        WorkspacePolicyConfig(additional_scanners=["detect-secrets"]),
        project_prefix="api",
        project_threshold="MEDIUM",
        project_scanners=enabled,
    )

    assert "detect-secrets" in enabled
    assert resolved.policy_scanners == ()


def test_an_enabled_spelling_beside_a_disabled_declared_scanner_does_not_run_it():
    config = _config(
        {"detect-secrets": {"enabled": False}, "detect.secrets": {"enabled": True}}
    )
    enabled, _pins, _twins = _scanner_state(config)
    resolved = policy_for_project(
        WorkspacePolicyConfig(additional_scanners=["detect-secrets"]),
        project_prefix="api",
        project_threshold="MEDIUM",
        project_scanners=enabled,
    )

    _enable_policy_scanners(config, resolved.policy_scanners)

    assert resolved.policy_scanners == ("detect-secrets",)
    assert config.get_plugin_config("scanner", "detect-secrets")["enabled"] is True


def test_control_one_enabled_section_is_the_projects_own_run():
    config = _config({"Snyk_Code": {"enabled": True}})

    assert _policy_scanners(config) == ()
    assert config.get_plugin_config("scanner", SNYK_CODE)["enabled"] is True


def test_control_one_disabled_section_is_switched_on_by_the_policy():
    config = _config({"snyk.code": {"enabled": False}})

    policy_scanners = _policy_scanners(config)
    _enable_policy_scanners(config, policy_scanners)

    assert policy_scanners == (SNYK_CODE,)
    assert config.get_plugin_config("scanner", SNYK_CODE)["enabled"] is True


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(False, id="bare-false"),
        pytest.param("off", id="string"),
        pytest.param([], id="list"),
    ],
)
def test_a_section_with_no_usable_body_is_replaced_when_the_policy_requires_it(
    body,
):
    """``acme: false`` (or a string, or a list) is read as off by the resolver, so
    the plan lists ``acme`` as policy-added; at scan time the section has to be
    switched on. Red at the base: the body is not a mapping or a model, and
    ``entry.enabled = True`` raised AttributeError on it."""
    config = _config({"acme": body})

    _enable_policy_scanners(config, ("acme",))

    section = config.get_plugin_config("scanner", "acme")
    assert section["enabled"] is True
    assert section["name"] == "acme"


@pytest.mark.parametrize("sections", TWINS)
def test_a_twinned_scanner_is_listed_only_when_the_lookup_reads_it_enabled(sections):
    """With no policy the scan runs the section the lookup reads, whichever of the
    two that is, so the list holds the scanner exactly when that section is on."""
    config = _config(sections)
    enabled, _pins, _twins = _scanner_state(config)

    reads_enabled = config.get_plugin_config("scanner", SNYK_CODE)["enabled"]

    assert bool(_twin_names(enabled)) is reads_enabled


def test_two_enabled_sections_of_one_scanner_list_the_one_the_lookup_reads():
    config = _config({"snyk.code": {"enabled": True}, "Snyk_Code": {"enabled": True}})

    enabled, _pins, _twins = _scanner_state(config)

    assert _twin_names(enabled) == ["snyk.code"]


def test_the_pin_of_a_twinned_scanner_is_the_pin_of_the_section_the_lookup_reads():
    config = _config(
        {
            "snyk.code": {"enabled": True, "options": {"tool_version": ">=1.0"}},
            "Snyk_Code": {"enabled": True, "options": {"tool_version": ">=2.0"}},
        }
    )

    _enabled, pins, _twins = _scanner_state(config)

    assert {n: pin for n, pin in pins.items() if n in ("snyk.code", "Snyk_Code")} == {
        "snyk.code": ">=1.0"
    }


def test_control_one_section_of_the_scanner_is_listed_once_with_its_pin():
    config = _config(
        {"Snyk_Code": {"enabled": True, "options": {"tool_version": ">=2.0"}}}
    )

    enabled, pins, _twins = _scanner_state(config)

    assert _twin_names(enabled) == ["Snyk_Code"]
    assert pins["Snyk_Code"] == ">=2.0"


def _section(enabled: bool, version: str) -> dict:
    return {"enabled": enabled, "options": {"tool_version": version}}


def _pins_of_the_twins(pins: dict) -> dict:
    return {name: pin for name, pin in pins.items() if name in _twin_names(pins)}


@pytest.mark.parametrize("read_is_on", [True, False])
def test_a_section_spelled_as_the_reduced_name_is_the_one_the_lookup_reads(read_is_on):
    """The lookup tries the reduced name as a literal key before it takes the first
    key to claim the name, so ``snykcode`` written after ``Snyk_Code`` is the
    section a lookup by ``snyk-code`` reads. The plan lists that section and records
    its pin, and does not take the pin of the key written first."""
    config = _config(
        {
            "Snyk_Code": _section(not read_is_on, ">=1.0"),
            "snykcode": _section(read_is_on, ">=2.0"),
        }
    )
    reads_enabled = config.get_plugin_config("scanner", SNYK_CODE)["enabled"]

    enabled, pins, _twins = _scanner_state(config)

    assert reads_enabled is read_is_on
    assert _twin_names(enabled) == (["snykcode"] if read_is_on else [])
    assert _pins_of_the_twins(pins) == {"snykcode": ">=2.0"}


@pytest.mark.parametrize("off", ["Snyk_Code", "snyk-code"])
def test_a_pair_the_plan_cannot_resolve_is_not_listed_while_a_section_of_it_is_off(
    off,
):
    """``snyk-code`` beside ``Snyk_Code`` is a pair a lookup by the name ``snyk-code``
    reads one way and a lookup by another spelling reads the other. The plan has no
    registered name for an extra section, so it never marks the scanner enabled
    while either section is off, and it records the pin the two share."""
    config = _config(
        {
            "Snyk_Code": _section(off != "Snyk_Code", ">=1.0"),
            "snyk-code": _section(off != "snyk-code", ">=1.0"),
        }
    )

    enabled, pins, twins = _scanner_state(config)

    assert twins == {"snykcode": ["Snyk_Code", "snyk-code"]}
    assert _twin_names(enabled) == []
    assert _pins_of_the_twins(pins) == {"Snyk_Code": ">=1.0"}


def test_a_lowercase_underscored_key_is_not_assumed_to_be_the_plugins_name():
    """The lookup by ``snyk-code`` reads ``Snyk_Code``, which is off. Taking
    ``snyk_code`` for the plugin's exact name listed the scanner as enabled."""
    config = _config(
        {
            "Snyk_Code": _section(False, ">=1.0"),
            "snyk_code": _section(True, ">=1.0"),
        }
    )
    assert config.get_plugin_config("scanner", SNYK_CODE)["enabled"] is False

    enabled, _pins, _twins = _scanner_state(config)

    assert _twin_names(enabled) == []


@pytest.mark.parametrize(
    ("other", "versions"),
    [
        pytest.param(_section(True, ">=2.0"), [">=1.0", ">=2.0"], id="two-pins"),
        pytest.param({"enabled": True}, [">=1.0"], id="pin-and-none"),
    ],
)
def test_the_versions_a_pair_the_plan_cannot_resolve_may_apply_are_held(
    other, versions
):
    """The scan may apply the pin of either section, so the plan records neither and
    holds each version the pair may apply, to be compared with the pins of the other
    projects. A section that sets none adds no version."""
    from automated_security_helper.workspace.resolver import _unresolved_pins

    config = _config({"Snyk_Code": _section(True, ">=1.0"), "snyk-code": other})

    _enabled, pins, _twins = _scanner_state(config)
    held = _unresolved_pins(config)

    assert _pins_of_the_twins(pins) == {}
    assert list(held) == ["Snyk_Code"]
    assert held["Snyk_Code"].sections == ["Snyk_Code", "snyk-code"]
    assert held["Snyk_Code"].pins == versions


def test_control_a_pair_the_plan_cannot_resolve_whose_pins_agree_holds_nothing():
    from automated_security_helper.workspace.resolver import _unresolved_pins

    config = _config(
        {"Snyk_Code": _section(True, ">=1.0"), "snyk-code": _section(True, ">=1.0")}
    )

    assert _unresolved_pins(config) == {}


def test_control_a_pair_a_lookup_resolves_holds_nothing():
    from automated_security_helper.workspace.resolver import _unresolved_pins

    config = _config(
        {"Snyk_Code": _section(True, ">=1.0"), "snyk.code": _section(True, ">=2.0")}
    )

    assert _unresolved_pins(config) == {}


def _held_pins(key: str, **pins: str):
    """A stand-in for a ProjectPlan, with only what the comparison of pins reads."""
    from types import SimpleNamespace

    return SimpleNamespace(key=key, scanner_pins=pins, _environment_values=())


def _may_apply(*versions: str):
    from automated_security_helper.workspace.resolver import _PossiblePins

    return _PossiblePins(["Snyk_Code", "snyk-code"], list(versions))


def test_a_version_a_pair_may_apply_that_clashes_with_another_projects_pin_is_refused():
    """One version either section sets is enough: the scan may apply it."""
    from automated_security_helper.workspace.resolver import _validate_unresolved_pins

    projects = [_held_pins("api"), _held_pins("web", Snyk_Code=">=2.0.0")]
    held = {"api": {"Snyk_Code": _may_apply(">=1.125.0,<2.0.0", ">=1.130.0")}}

    with pytest.raises(WorkspaceDefinitionError) as refused:
        _validate_unresolved_pins(projects, held)

    text = str(refused.value)
    assert "'api'" in text
    assert "'web'" in text
    assert ">=1.125.0,<2.0.0" in text
    assert ">=2.0.0" in text
    assert "scanners.Snyk_Code and scanners.snyk-code" in text


def test_control_versions_a_pair_may_apply_that_fit_another_projects_pin_are_accepted():
    from automated_security_helper.workspace.resolver import _validate_unresolved_pins

    projects = [_held_pins("api"), _held_pins("web", Snyk_Code=">=2.0.0")]
    held = {"api": {"Snyk_Code": _may_apply(">=1.130.0", ">=1.150.0")}}

    _validate_unresolved_pins(projects, held)


def test_control_a_pair_no_other_project_pins_has_nothing_to_compare():
    from automated_security_helper.workspace.resolver import _validate_unresolved_pins

    projects = [_held_pins("api"), _held_pins("web", semgrep=">=2.0.0")]
    held = {"api": {"Snyk_Code": _may_apply(">=1.125.0,<2.0.0")}}

    _validate_unresolved_pins(projects, held)


def test_two_pairs_the_plan_cannot_resolve_are_compared_with_each_other_once():
    from automated_security_helper.workspace.resolver import _validate_unresolved_pins

    projects = [_held_pins("api"), _held_pins("web")]
    held = {
        "api": {"Snyk_Code": _may_apply(">=1.125.0,<2.0.0")},
        "web": {"Snyk_Code": _may_apply(">=2.0.0")},
    }

    with pytest.raises(WorkspaceDefinitionError) as refused:
        _validate_unresolved_pins(projects, held)

    assert str(refused.value).count(">=2.0.0") == 1


def _project_of(key: str, order, versions: dict, scanner: str = SNYK_CODE):
    """A stand-in plan for a project, and the pairs it holds, built from its config.

    The sections are written in *order*. The pins come from ``_scanner_state`` and
    the held pairs from ``_unresolved_pins``, both run on the project's own
    configuration, so the key a pair is held under is the one the real file order
    gives it and not one written by hand. Only the pins of *scanner* are kept.
    """
    from automated_security_helper.workspace.resolver import _unresolved_pins

    config = _config({name: _section(True, versions[name]) for name in order})
    _enabled, pins, _twins = _scanner_state(config)
    kept = {
        name: pin
        for name, pin in pins.items()
        if normalise_scanner_name(name) == normalise_scanner_name(scanner)
    }
    return _held_pins(key, **kept), _unresolved_pins(config)


#: The tool version each spelling of the scanner is given, as an operator's setting
#: gives every project the same one; only the order the file writes the keys in
#: differs, and with it the key a lookup by the reduced name reads.
CLASHING_PINS = {"Snyk_Code": "<2.0.0", "snyk-code": ">=2.0.0"}
FITTING_PINS = {"Snyk_Code": ">=1.5.0", "snyk-code": ">=2.0.0"}
PAIR_FIRST = ("Snyk_Code", "snyk-code")
PAIR_LAST = ("snyk-code", "Snyk_Code")


@pytest.mark.parametrize(
    ("api_order", "web_order"),
    [
        pytest.param(PAIR_FIRST, PAIR_LAST, id="api-holds-the-pair"),
        pytest.param(PAIR_LAST, PAIR_FIRST, id="web-holds-the-pair"),
    ],
)
def test_a_version_a_pair_may_apply_is_held_against_a_pin_recorded_under_another_spelling(
    api_order, web_order
):
    """``Snyk_Code`` written before ``snyk-code`` is a pair the plan cannot resolve and
    holds as ``Snyk_Code``. The same two sections written the other way round are
    resolved: the lookup reads ``snyk-code``, which no other key can be, and the
    plan records its pin under that key. The scan reads the same scanner in both
    projects, so the versions the pair may apply are held against that pin."""
    from automated_security_helper.workspace.resolver import _validate_unresolved_pins

    api, api_held = _project_of("api", api_order, CLASHING_PINS)
    web, web_held = _project_of("web", web_order, CLASHING_PINS)
    held = {
        key: pairs for key, pairs in (("api", api_held), ("web", web_held)) if pairs
    }
    assert len(held) == 1

    with pytest.raises(WorkspaceDefinitionError) as refused:
        _validate_unresolved_pins([api, web], held)

    text = str(refused.value)
    assert "'api'" in text
    assert "'web'" in text
    assert "<2.0.0" in text
    assert ">=2.0.0" in text


def test_control_versions_a_pair_may_apply_that_fit_a_pin_recorded_under_another_spelling():
    from automated_security_helper.workspace.resolver import _validate_unresolved_pins

    api, api_held = _project_of("api", PAIR_FIRST, FITTING_PINS)
    web, web_held = _project_of("web", PAIR_LAST, FITTING_PINS)

    assert list(api_held) == ["Snyk_Code"]
    assert web_held == {}
    _validate_unresolved_pins([api, web], {"api": api_held})


def test_two_pairs_held_under_different_spellings_are_compared_with_each_other_once():
    """``snykcode`` is the reduced name itself, so a lookup reads it first and holds
    ``snyk-code`` beside it as the other candidate. The pair is the same scanner as
    ``Snyk_Code`` beside ``snyk-code`` in another project."""
    from automated_security_helper.workspace.resolver import _validate_unresolved_pins

    api, api_held = _project_of("api", PAIR_FIRST, CLASHING_PINS)
    web, web_held = _project_of(
        "web",
        ("snykcode", "snyk-code"),
        {"snykcode": ">=3.0.0", "snyk-code": ">=3.1.0"},
    )
    assert list(api_held) == ["Snyk_Code"]
    assert list(web_held) == ["snykcode"]

    with pytest.raises(WorkspaceDefinitionError) as refused:
        _validate_unresolved_pins([api, web], {"api": api_held, "web": web_held})

    assert str(refused.value).count(">=3.0.0") == 1


def test_control_a_pin_recorded_for_another_scanner_is_not_held_against_a_pair():
    from automated_security_helper.workspace.resolver import _validate_unresolved_pins

    api, api_held = _project_of("api", PAIR_FIRST, CLASHING_PINS)
    web = _held_pins("web", **{"snyk-other": ">=2.0.0", "semgrep": ">=2.0.0"})

    _validate_unresolved_pins([api, web], {"api": api_held})


#: ``acme`` and ``acme-scanner`` are two plugins by their exact names, and one name
#: once the type word is removed: the scan reads either, whichever name the plugin
#: is registered under, so a pin set on one may be the one it applies.
TYPE_WORD_PINS = {"acme": "<2.0.0", "acme-scanner": ">=2.0.0"}
TYPE_WORD_PAIR = ("acme", "acme-scanner")


def test_the_versions_a_scanner_spelled_in_both_ranks_may_apply_are_held():
    from automated_security_helper.workspace.resolver import _unresolved_pins

    config = _config(
        {name: _section(True, TYPE_WORD_PINS[name]) for name in TYPE_WORD_PAIR}
    )

    held = _unresolved_pins(config)

    assert list(held) == ["acme"]
    assert held["acme"].sections == ["acme", "acme-scanner"]
    assert held["acme"].pins == ["<2.0.0", ">=2.0.0"]


def test_a_version_a_scanner_spelled_in_both_ranks_may_apply_is_held_against_a_pin():
    """The plan lists each rank by its own section and records a pin for each, so the
    pin of ``acme`` is compared with nothing; a project that has only
    ``acme-scanner`` is read for the name ``acme`` all the same."""
    from automated_security_helper.workspace.resolver import _validate_unresolved_pins

    api, api_held = _project_of("api", TYPE_WORD_PAIR, TYPE_WORD_PINS, "acme")
    web, web_held = _project_of("web", ("acme-scanner",), TYPE_WORD_PINS, "acme")
    assert web_held == {}

    with pytest.raises(WorkspaceDefinitionError) as refused:
        _validate_unresolved_pins([api, web], {"api": api_held})

    text = str(refused.value)
    assert "'api'" in text
    assert "'web'" in text
    assert "scanners.acme and scanners.acme-scanner" in text


def test_control_versions_a_scanner_spelled_in_both_ranks_may_apply_that_fit_a_pin():
    from automated_security_helper.workspace.resolver import _validate_unresolved_pins

    fitting = {"acme": ">=1.5.0", "acme-scanner": ">=2.0.0"}
    api, api_held = _project_of("api", TYPE_WORD_PAIR, fitting, "acme")
    web, _held = _project_of("web", ("acme-scanner",), fitting, "acme")

    assert list(api_held) == ["acme"]
    _validate_unresolved_pins([api, web], {"api": api_held})


@pytest.mark.parametrize(
    "versions",
    [
        pytest.param({"acme": ">=2.0.0", "acme-scanner": ">=2.0.0"}, id="same-pin"),
        pytest.param({"acme": None, "acme-scanner": None}, id="no-pins"),
    ],
)
def test_control_a_scanner_spelled_in_both_ranks_with_one_pin_holds_nothing(versions):
    from automated_security_helper.workspace.resolver import _unresolved_pins

    sections = {
        name: {"enabled": True}
        if versions[name] is None
        else _section(True, versions[name])
        for name in TYPE_WORD_PAIR
    }

    assert _unresolved_pins(_config(sections)) == {}


def test_control_one_spelling_of_a_scanner_in_each_rank_set_in_one_project_holds_nothing():
    from automated_security_helper.workspace.resolver import _unresolved_pins

    assert _unresolved_pins(_config({"acme": _section(True, "<2.0.0")})) == {}
    assert _unresolved_pins(_config({"acme-scanner": _section(True, "<2.0.0")})) == {}


def test_a_workspace_refuses_a_version_a_pair_may_apply_that_clashes_with_a_pin(
    tmp_path, monkeypatch
):
    from automated_security_helper.workspace import resolver

    calls = iter([{"semgrep": _may_apply("<1.0.0")}, {}])
    monkeypatch.setattr(resolver, "_unresolved_pins", lambda config: next(calls))
    workspace = _workspace(
        tmp_path, {"api": _SEMGREP_ON, "web": _SEMGREP_ON}, policy_scanners=None
    )

    with pytest.raises(WorkspaceDefinitionError) as refused:
        resolve_workspace(
            workspace,
            config_overrides=("scanners.semgrep.options.tool_version=>=1.130.0",),
        )

    text = str(refused.value)
    assert "'api'" in text
    assert "'web'" in text


def test_control_a_workspace_of_one_project_plans_a_pair_whose_versions_differ(
    tmp_path, monkeypatch
):
    """With no other project to hold them against, the versions the pair may apply
    refuse nothing, and a workspace with no policy plans the project."""
    from automated_security_helper.workspace import resolver

    monkeypatch.setattr(
        resolver, "_unresolved_pins", lambda config: {"semgrep": _may_apply("<1.0.0")}
    )
    workspace = _workspace(tmp_path, {"api": _SEMGREP_ON}, policy_scanners=None)

    plan = resolve_workspace(
        workspace,
        config_overrides=("scanners.semgrep.options.tool_version=>=1.130.0",),
    )

    assert [project.key for project in plan.projects] == ["api"]


def test_a_pair_the_plan_cannot_resolve_is_listed_once_when_both_are_on():
    config = _config(
        {"Snyk_Code": _section(True, ">=1.0"), "snyk-code": _section(True, ">=1.0")}
    )

    enabled, pins, _twins = _scanner_state(config)

    assert _twin_names(enabled) == ["Snyk_Code"]
    assert _pins_of_the_twins(pins) == {"Snyk_Code": ">=1.0"}


@pytest.mark.parametrize(
    "sections",
    [
        pytest.param(
            {"Snyk_Code": None, "snyk-code": _section(True, ">=2.0")},
            id="bodiless-read-key",
        ),
        pytest.param(
            {"snyk-code": None, "snyk_code": _section(True, ">=2.0")},
            id="bodiless-first-written",
        ),
        pytest.param(
            {"Snyk_Code": _section(True, ">=2.0"), "snyk-code": None},
            id="bodiless-other-key",
        ),
    ],
)
def test_a_section_with_no_body_in_a_pair_the_plan_cannot_resolve_counts_as_off(
    sections,
):
    """``snyk-code:`` with no body is a key the lookup indexes, and the scan may read
    it as the plugin's section. It is off and sets no pin, so the pair is not listed,
    and the version the other section sets is held, not recorded."""
    from automated_security_helper.workspace.resolver import _unresolved_pins

    config = _config(sections)

    enabled, pins, _twins = _scanner_state(config)
    held = _unresolved_pins(config)

    assert _twin_names(enabled) == []
    assert _pins_of_the_twins(pins) == {}
    assert [versions.pins for versions in held.values()] == [[">=2.0"]]


#: An extra section with no body beside one that has a body, in each order.
BODILESS_TWINS = [
    pytest.param(
        {"Snyk_Code": None, "snyk.code": {"enabled": True}}, id="bodiless-first"
    ),
    pytest.param(
        {"snyk.code": {"enabled": True}, "Snyk_Code": None}, id="bodiless-last"
    ),
]


@pytest.mark.parametrize("sections", BODILESS_TWINS)
def test_an_empty_section_still_makes_the_section_beside_it_a_twin(sections):
    """``Snyk_Code:`` with no body is a key the lookup indexes, so the section beside
    it is its twin whichever is written first, and a policy that requires snyk-code
    must be refused for it. The plan lists the scanner exactly when the section the
    lookup reads is on, and an empty section is on in no way."""
    config = _config(sections)
    read = config.get_plugin_config("scanner", SNYK_CODE)

    enabled, _pins, twins = _scanner_state(config)

    assert twins == {"snykcode": list(sections)}
    assert bool(_twin_names(enabled)) is bool(read and read["enabled"])


def test_control_an_empty_section_beside_nothing_is_not_a_twin():
    config = _config({"Snyk_Code": None, "snyk-other": {"enabled": True}})

    enabled, _pins, twins = _scanner_state(config)

    assert twins == {}
    assert _twin_names(enabled) == []


# ---------------------------------------------------------------------------
# The verdict of a workspace project that spells one scanner twice
# ---------------------------------------------------------------------------

_THRESHOLD = "global_settings:\n  severity_threshold: MEDIUM\n"

#: The project's own config file: two sections of one scanner, in each order.
_TWINS_DISABLED_FIRST = (
    _THRESHOLD
    + "scanners:\n  snyk.code:\n    enabled: false\n  Snyk_Code:\n"
    + "    enabled: true\n"
)
_TWINS_DISABLED_LAST = (
    _THRESHOLD
    + "scanners:\n  Snyk_Code:\n    enabled: true\n  snyk.code:\n"
    + "    enabled: false\n"
)
TWIN_FILES = [
    pytest.param(_TWINS_DISABLED_FIRST, id="disabled-first"),
    pytest.param(_TWINS_DISABLED_LAST, id="disabled-last"),
]

_ONE_SECTION = _THRESHOLD + "scanners:\n  Snyk_Code:\n    enabled: true\n"
# The pin tests pin semgrep through an override. A pin is recorded only for a
# scanner that is on, and semgrep's own default is off on Windows (it publishes
# no Windows build), so the project turns it on in so many words: the override's
# pin is what the test is about, not the platform.
_SEMGREP_ON = _ONE_SECTION + "  semgrep:\n    enabled: true\n"


class _FindingOrchestrator:
    """Runs nothing and hands back one snyk-code finding, shaped as a scan's."""

    def __init__(self, **kwargs):
        self.kwargs = kwargs

    @classmethod
    def create(cls, **kwargs):
        return cls(**kwargs)

    def execute_scan(self, phases=None):
        from automated_security_helper.schemas.sarif_schema_model import (
            Run,
            SarifReport,
        )

        run = Run.model_validate(
            {
                "tool": {"driver": {"name": "ash"}},
                "results": [
                    {
                        "ruleId": "snyk-code-rule",
                        "level": "error",
                        "message": {"text": "a finding from snyk-code"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/app.py"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                        "properties": {
                            "scanner_name": SNYK_CODE,
                            "issue_severity": "HIGH",
                            "tags": [SNYK_CODE],
                        },
                    }
                ],
            }
        )
        results = AshAggregatedResults()
        results.sarif = SarifReport(version="2.1.0", runs=[run])
        return results


def _workspace(root, bodies, policy_scanners=(SNYK_CODE,)):
    """A workspace of the projects in *bodies* (project key -> its config file).

    The workspace policy requires *policy_scanners*; ``None`` writes no policy file.
    """
    for key, body in bodies.items():
        project = root / key
        (project / "src").mkdir(parents=True)
        (project / "src" / "app.py").write_text("print('x')\n", encoding="utf-8")
        (project / ".ash").mkdir()
        (project / ".ash" / "ash.yaml").write_text(body, encoding="utf-8")
    if policy_scanners is not None:
        (root / ".ash").mkdir()
        listed = "".join(f"    - {name}\n" for name in policy_scanners)
        (root / ".ash" / "ash-workspace.yaml").write_text(
            f"workspace:\n  additional_scanners:\n{listed}", encoding="utf-8"
        )
    path = root / "dev.code-workspace"
    path.write_text(
        json.dumps({"folders": [{"path": key} for key in bodies]}), encoding="utf-8"
    )
    return path


def _workspace_of(root, body):
    """A workspace of the one project ``api`` whose policy requires snyk-code."""
    return _workspace(root, {"api": body})


def _scan(root, plan):
    outcome = execute_workspace(
        plan,
        ProjectScanSettings(
            output_dir=root / "out", phases=("scan",), max_parallel_projects=1
        ),
        orchestrator_factory=_FindingOrchestrator.create,
    )
    entry = next(p for p in outcome.payload.projects if p.project == "api")
    written = json.loads(
        (root / "out" / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )
    runs = (written.get("sarif") or {}).get("runs") or []
    origins = [
        (result.get("properties") or {}).get("origin")
        for run in runs
        for result in (run.get("results") or [])
    ]
    return entry, origins


@pytest.mark.parametrize("body", TWIN_FILES)
def test_a_workspace_project_with_two_spellings_is_refused_by_project(tmp_path, body):
    workspace = _workspace_of(tmp_path, body)

    with pytest.raises(WorkspaceDefinitionError) as refused:
        resolve_workspace(workspace)

    text = str(refused.value)
    assert "'api'" in text
    assert "Snyk_Code" in text
    assert "snyk.code" in text


@pytest.mark.parametrize("body", TWIN_FILES)
def test_two_spellings_never_take_the_scanners_findings_out_of_the_verdict(
    tmp_path, body
):
    """Either the plan refuses the project, or its own scanner's finding counts.

    Before the plan refused, the lookup ran ``Snyk_Code`` while the plan
    recorded snyk-code as a policy scanner: the finding was tagged
    ``workspace-policy`` and left out of the verdict.
    """
    workspace = _workspace_of(tmp_path, body)
    try:
        plan = resolve_workspace(workspace)
    except WorkspaceDefinitionError as refused:
        assert "Snyk_Code" in str(refused)
        return

    entry, origins = _scan(tmp_path, plan)

    assert plan.projects[0].policy_scanners == []
    assert origins == [None]
    assert entry.actionable_finding_count == 1
    assert entry.exceeds_threshold is True


def test_control_one_section_of_the_scanner_gates_untagged(tmp_path):
    plan = resolve_workspace(_workspace_of(tmp_path, _ONE_SECTION))

    entry, origins = _scan(tmp_path, plan)

    assert plan.projects[0].policy_scanners == []
    assert origins == [None]
    assert entry.finding_count == 1
    assert entry.actionable_finding_count == 1
    assert entry.exceeds_threshold is True


# ---------------------------------------------------------------------------
# The refusal is for a scanner the policy requires
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("body", TWIN_FILES)
def test_a_workspace_with_no_policy_scans_a_project_that_spells_a_scanner_twice(
    tmp_path, body
):
    """Two spellings only matter when the policy marks a scanner as its own.

    With no policy file nothing is marked, and the project scans as it does under
    ``ash --source-dir``, where the lookup reads one of the two sections.
    """
    plan = resolve_workspace(_workspace(tmp_path, {"api": body}, policy_scanners=None))

    entry, origins = _scan(tmp_path, plan)

    assert plan.projects[0].policy_scanners == []
    assert origins == [None]
    assert entry.actionable_finding_count == 1
    assert entry.exceeds_threshold is True


#: detect-secrets is on unless a project turns it off, and the policy adds only a
#: scanner the project does not run. This section gives the policy one to add.
_DETECT_SECRETS_OFF = "  detect-secrets:\n    enabled: false\n"


@pytest.mark.parametrize("body", TWIN_FILES)
def test_a_policy_for_another_scanner_does_not_refuse_the_twins(tmp_path, body):
    """The twins are snyk-code's, so a policy that requires detect-secrets plans the
    project and adds the scanner the project switched off."""
    plan = resolve_workspace(
        _workspace(
            tmp_path,
            {"api": body + _DETECT_SECRETS_OFF},
            policy_scanners=("detect-secrets",),
        )
    )

    assert plan.projects[0].policy_scanners == ["detect-secrets"]


@pytest.mark.parametrize("body", TWIN_FILES)
def test_control_a_policy_scanner_the_project_runs_is_not_added(tmp_path, body):
    """Control for the test above: detect-secrets is on by default, so with the twins
    beside it the policy has nothing to add and the plan is still not refused."""
    plan = resolve_workspace(
        _workspace(tmp_path, {"api": body}, policy_scanners=("detect-secrets",))
    )

    assert plan.projects[0].policy_scanners == []


_TYPE_WORD_PLUGINS = (
    _THRESHOLD
    + "scanners:\n  acme:\n    enabled: false\n  acme-scanner:\n    enabled: true\n"
)


def test_two_plugins_that_differ_by_the_type_word_are_two_scanners_in_the_plan():
    """``acme`` and ``acme-scanner`` reduce to one name only once the type word is
    removed. Each is read by its own exact name, so the plan lists each by its own
    section. The scan reads either for the reduced name, depending on the plugin's
    registered name, so the plan records them as twins for a policy that requires it."""
    config = _config({"acme": {"enabled": False}, "acme-scanner": {"enabled": True}})

    enabled, _pins, twins = _scanner_state(config)

    assert twins == {"acme": ["acme", "acme-scanner"]}
    assert "acme-scanner" in enabled
    assert "acme" not in enabled


#: A project that spells one scanner in both ranks, the section the lookup reads off
#: and the other on, each with the name the policy requires and the keys it holds.
TYPE_WORD_FILES = [
    pytest.param(_TYPE_WORD_PLUGINS, "acme", ("acme", "acme-scanner"), id="acme"),
    pytest.param(
        _THRESHOLD
        + "scanners:\n  Snyk_Code:\n    enabled: false\n"
        + "  snyk-code-scanner:\n    enabled: true\n",
        SNYK_CODE,
        ("Snyk_Code", "snyk-code-scanner"),
        id="snyk-code",
    ),
    pytest.param(
        _THRESHOLD
        + "scanners:\n  snyk-code-scanner:\n    enabled: true\n"
        + "  Snyk_Code:\n    enabled: false\n",
        SNYK_CODE,
        ("Snyk_Code", "snyk-code-scanner"),
        id="snyk-code-type-word-first",
    ),
]


@pytest.mark.parametrize(("body", "required", "keys"), TYPE_WORD_FILES)
def test_a_required_scanner_is_never_left_to_a_section_the_scan_does_not_run(
    tmp_path, body, required, keys
):
    """The section a lookup by the reduced name reads is off, and a section of the
    other rank is on. Either the plan refuses the project, or the policy adds the
    scanner; it must not take the section that is on for the scanner the policy
    requires and add nothing."""
    workspace = _workspace(tmp_path, {"api": body}, policy_scanners=(required,))
    try:
        plan = resolve_workspace(workspace)
    except WorkspaceDefinitionError as refused:
        assert all(key in str(refused) for key in keys)
        return

    assert plan.projects[0].policy_scanners == [required]


@pytest.mark.parametrize(("body", "required", "keys"), TYPE_WORD_FILES)
def test_a_policy_that_requires_a_scanner_spelled_in_both_ranks_refuses_the_project(
    tmp_path, body, required, keys
):
    workspace = _workspace(tmp_path, {"api": body}, policy_scanners=(required,))

    with pytest.raises(WorkspaceDefinitionError) as refused:
        resolve_workspace(workspace)

    text = str(refused.value)
    assert "'api'" in text
    assert all(f"scanners.{key}" in text for key in keys)


@pytest.mark.parametrize(("body", "required", "keys"), TYPE_WORD_FILES)
def test_a_policy_for_another_scanner_does_not_refuse_the_two_ranks(
    tmp_path, body, required, keys
):
    """Control for the two tests above: the keys are not the policy's scanner, so the
    project is planned, and the section that is on is listed once."""
    plan = resolve_workspace(
        _workspace(
            tmp_path,
            {"api": body + _DETECT_SECRETS_OFF},
            policy_scanners=("detect-secrets",),
        )
    )

    assert plan.projects[0].policy_scanners == ["detect-secrets"]
    assert len([name for name in plan.projects[0].scanners if name in keys]) == 1


_THREE_SPELLINGS = (
    _THRESHOLD
    + "scanners:\n  acme:\n    enabled: true\n  acme-scanner:\n    enabled: false\n"
    + "  acme.scanner:\n    enabled: false\n"
)
_SECOND_RANK_PAIR = (
    _THRESHOLD
    + "scanners:\n  acme-scanner:\n    enabled: true\n  acme.scanner:\n    enabled: false\n"
)


def test_the_keys_of_the_second_rank_are_recorded_under_the_reduced_name():
    """``acme-scanner`` and ``acme.scanner`` are one plugin's spellings, read after
    ``acme`` by every lookup that names no key. They were recorded under the key
    read, ``acme-scanner``, which no policy name equals."""
    config = _config(
        {
            "acme": {"enabled": True},
            "acme-scanner": {"enabled": False},
            "acme.scanner": {"enabled": False},
        }
    )

    _enabled, _pins, twins = _scanner_state(config)

    assert twins == {"acme": ["acme", "acme-scanner", "acme.scanner"]}


def test_a_policy_refuses_a_project_whose_second_rank_keys_hold_the_name(tmp_path):
    workspace = _workspace(
        tmp_path, {"api": _THREE_SPELLINGS}, policy_scanners=("acme",)
    )

    with pytest.raises(WorkspaceDefinitionError) as refused:
        resolve_workspace(workspace)

    text = str(refused.value)
    assert "'api'" in text
    assert "scanners.acme and scanners.acme-scanner and scanners.acme.scanner" in text


def test_control_a_policy_refuses_two_second_rank_keys_with_no_first_rank_key(tmp_path):
    workspace = _workspace(
        tmp_path, {"api": _SECOND_RANK_PAIR}, policy_scanners=("acme",)
    )

    with pytest.raises(WorkspaceDefinitionError) as refused:
        resolve_workspace(workspace)

    assert "scanners.acme-scanner and scanners.acme.scanner" in str(refused.value)


def _twin_file(sections: dict) -> str:
    """A project config file with *sections* under ``scanners``, in the order given."""
    body = "".join(
        f"  {key}:\n    enabled: {str(section['enabled']).lower()}\n"
        for key, section in sections.items()
    )
    return _THRESHOLD + "scanners:\n" + body


@pytest.mark.parametrize("sections", TWINS)
def test_the_plan_lists_a_twinned_scanner_only_when_the_scan_runs_it(
    tmp_path, sections
):
    """What an operator inspects is what will run.

    With no policy the scan runs the section the lookup reads, so the plan lists
    the scanner exactly when that section is on, whichever order the file writes
    the two in.
    """
    plan = resolve_workspace(
        _workspace(tmp_path, {"api": _twin_file(sections)}, policy_scanners=None)
    )

    scan_runs_it = _config(sections).get_plugin_config("scanner", SNYK_CODE)["enabled"]

    assert bool(_twin_names(plan.projects[0].scanners)) is scan_runs_it


@pytest.mark.parametrize("policy_name", [SNYK_CODE, "snyk.code", "SnykCodeScanner"])
def test_a_policy_names_the_twinned_scanner_by_any_spelling_of_it(
    tmp_path, policy_name
):
    workspace = _workspace(
        tmp_path, {"api": _TWINS_DISABLED_LAST}, policy_scanners=(policy_name,)
    )

    with pytest.raises(WorkspaceDefinitionError) as refused:
        resolve_workspace(workspace)

    text = str(refused.value)
    assert "'api'" in text
    assert "Snyk_Code" in text
    assert "snyk.code" in text


def test_the_refusal_names_every_project_that_holds_the_twinned_scanner(tmp_path):
    workspace = _workspace(
        tmp_path,
        {
            "api": _TWINS_DISABLED_LAST,
            "web": _TWINS_DISABLED_FIRST,
            "docs": _ONE_SECTION,
        },
    )

    with pytest.raises(WorkspaceDefinitionError) as refused:
        resolve_workspace(workspace)

    text = str(refused.value)
    assert "'api'" in text
    assert "'web'" in text
    # Control: a project with one section of the scanner is not named.
    assert "'docs'" not in text
