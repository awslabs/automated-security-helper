# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The declared scanner-tag set must equal what the plugin registry reports.

Why this file exists
--------------------
``utils/scanner_names.py`` declares the scanner names ASH recognizes in SARIF
result tags. It cannot derive them from the plugin registry: importing the
registry from a module the models package reaches is a measured circular import
(the reason is recorded in that module's docstring). So the derivation happens
here instead, where importing the registry is free, and the assertion is set
equality.

The direction that matters
--------------------------
Every peripheral scanner list in the repo checks one direction only --
``missing = KNOWN_SCANNERS - observed_names`` in
``.github/actions/validate-container/action.yml``,
``.github/actions/validate-nix/action.yml`` and
``scripts/verify_workspace_policy.py``. A one-directional check passes when a
scanner is ADDED, which is precisely the event that makes a hardcoded set stale:
that is how ``opengrep`` shipped and stayed absent from both runtime copies while
every CI list was green. So the assertion here is ``==``, not ``<=``, and
:func:`test_gate_fails_when_a_scanner_is_added_and_left_out` proves the gate
actually fires in the add direction by registering a fake scanner.

Assumption, stated because a future reader will need it
-------------------------------------------------------
The authoritative spelling of a scanner's name is its **config** name
(``bandit``, ``cfn-nag``, ``detect-secrets``), because that is the exact string
``sarif_utils.attach_scanner_details`` appends to a result's tags. It is not the
class name and not the snake_case form ``core/scanner_inventory.py`` reports.
Deriving snake_case here would make three names mismatch and the test would
"fail" on correct code.

What is deliberately NOT covered: a third-party scanner plugin installed at
runtime is registered through neither ``load_internal_plugins()`` nor the
vendored package list, so neither the declared set nor this test can see it.
"""

import pytest

from automated_security_helper.core.scanner_inventory import (
    _VENDORED_SCANNER_PLUGIN_PACKAGES,
)
from automated_security_helper.models.flat_vulnerability import (
    _GENERIC_ASH_TOOL_NAME,
    _KNOWN_SCANNER_TAGS,
    _extract_scanner_name_from_result,
)
from automated_security_helper.schemas.sarif_schema_model import (
    Message,
    PropertyBag,
    Result,
)
from automated_security_helper.utils.scanner_names import SCANNER_TAG_NAMES


def _declared_config_name(cls):
    """A scanner's config name, read from its class without instantiating it.

    Instantiating is avoided on purpose: ``describe_scanner`` shells out to probe
    tool versions with a ten-second budget per scanner, and this test needs names,
    not versions. The concrete config class is found by name suffix rather than by
    position in the ``config`` field's Union, because relying on argument order
    would silently pick the shared base class whose ``name`` is not the scanner's.
    """
    field = getattr(cls, "model_fields", {}).get("config")
    annotation = getattr(field, "annotation", None)
    for arg in getattr(annotation, "__args__", None) or ():
        if isinstance(arg, type) and arg.__name__.endswith("ScannerConfig"):
            return getattr(arg(), "name", None)
    return None


def _registry_scanner_classes():
    """Every scanner class ASH ships, deterministically.

    Uses ``load_internal_plugins()`` plus the vendored package constant, and
    deliberately NOT ``scanner_inventory._loaded_scanner_classes``: that function
    also runs installed-metadata discovery, which would make this gate's answer
    depend on whether some unrelated ``ash_*_plugins`` distribution happens to be
    installed in the environment running the suite. A drift gate has to be
    deterministic or its failures are not trustworthy.
    """
    from automated_security_helper.plugins.loader import (
        load_additional_plugin_modules,
        load_internal_plugins,
    )

    internal = load_internal_plugins()
    external = load_additional_plugin_modules(list(_VENDORED_SCANNER_PLUGIN_PACKAGES))

    classes = []
    for cls in list(internal.get("scanners", [])) + list(external.get("scanners", [])):
        if cls not in classes:
            classes.append(cls)
    return classes


def _derived_scanner_names():
    """Config names for every registered scanner, skipping none silently."""
    names = set()
    unresolved = []
    for cls in _registry_scanner_classes():
        name = _declared_config_name(cls)
        if name:
            names.add(str(name))
        else:
            unresolved.append(cls.__name__)
    # A scanner whose name could not be read would shrink the derived set and make
    # the equality assertion pass for the wrong reason, so it is an error here
    # rather than a silent omission.
    assert not unresolved, (
        f"could not read a config name for {unresolved}; the derived set is "
        "incomplete, so this gate cannot be trusted until that is fixed"
    )
    return names


def test_declared_scanner_names_equal_the_registry():
    """Set equality, so the gate fails when a scanner is added OR removed."""
    derived = _derived_scanner_names()

    assert SCANNER_TAG_NAMES == derived, (
        "utils/scanner_names.py has drifted from the plugin registry.\n"
        f"  registered but not declared: {sorted(derived - SCANNER_TAG_NAMES)}\n"
        f"  declared but not registered: {sorted(SCANNER_TAG_NAMES - derived)}"
    )


def test_gate_fails_when_a_scanner_is_added_and_left_out(monkeypatch):
    """The add direction, proved rather than assumed.

    Registers a fake scanner the declared set does not name and asserts the gate
    fails. Without this, a gate that only ever ran against an already-consistent
    repo would look identical to one that cannot fail -- and the one-directional
    peripheral lists are exactly that shape.
    """
    import automated_security_helper.plugins.loader as loader

    class _FakeConfig:
        name = "totally-new-scanner"

        def __init__(self):
            pass

    class _FakeScannerConfig(_FakeConfig):
        """Named with the ScannerConfig suffix so _declared_config_name finds it."""

    class _FakeScanner:
        model_fields = {
            "config": type(
                "_Field",
                (),
                {"annotation": type("_U", (), {"__args__": (_FakeScannerConfig,)})},
            )()
        }

    real_load_internal = loader.load_internal_plugins

    def fake_load_internal():
        loaded = real_load_internal()
        scanners = list(loaded.get("scanners", []))
        scanners.append(_FakeScanner)
        return {**loaded, "scanners": scanners}

    monkeypatch.setattr(loader, "load_internal_plugins", fake_load_internal)

    derived = _derived_scanner_names()
    assert "totally-new-scanner" in derived, "fixture did not reach the derivation"

    with pytest.raises(AssertionError, match="registered but not declared"):
        test_declared_scanner_names_equal_the_registry()


def test_opengrep_resolves_through_the_tag_fallback():
    """Regression for the defect this set was consolidated to fix.

    An opengrep result reaching the generic-tool-name fallback used to keep the
    aggregate name ``AWS Labs - Automated Security Helper`` while a bandit result
    resolved to ``bandit``. Both now resolve.

    This calls the helper DIRECTLY and on purpose. The fallback is unreachable
    through the full pipeline -- ``attach_scanner_details`` sets ``scanner_name``
    on every result before it reaches the aggregate SARIF, so the first precedence
    arm always wins (the reasoning is recorded in ``utils/scanner_names.py``). So
    the defect is latent, and a test routed through the pipeline would pass no
    matter what this set contained, which makes it worthless as a regression test.
    Testing the helper at its own contract is the only level at which the
    assertion can fail.
    """
    for name in ("opengrep", "bandit"):
        result = Result(
            ruleId=f"{name}.rule.1",
            level="warning",
            message=Message(text=f"a finding reported by {name}"),
            properties=PropertyBag(tags=[name]),
        )
        resolved = _extract_scanner_name_from_result(
            result, _GENERIC_ASH_TOOL_NAME, [name]
        )
        assert resolved == name, (
            f"{name} tag did not resolve; got {resolved!r}. A scanner name absent "
            "from SCANNER_TAG_NAMES falls through to the aggregate run name."
        )


def test_both_runtime_consumers_read_one_set():
    """No second longhand copy anywhere in the runtime path.

    ``models/flat_vulnerability.py`` and
    ``core/scanner_statistics_calculator.py`` each used to carry their own copy.
    Asserting identity (not equality) is the point: an equal-but-separate copy is
    the state this consolidation removed, and it would pass an equality check on
    the day it was written and drift the day after.
    """
    from automated_security_helper.core import scanner_statistics_calculator

    assert _KNOWN_SCANNER_TAGS is SCANNER_TAG_NAMES
    assert scanner_statistics_calculator.SCANNER_TAG_NAMES is SCANNER_TAG_NAMES


def test_hyphenated_names_are_present_in_the_spelling_tags_use():
    """Guards the assumption in this module's docstring.

    If someone regenerates the set in snake_case, the three hyphenated names stop
    matching real tags and every one of those scanners silently reverts to the
    aggregate name. That failure is invisible without this assertion, because a
    snake_cased set is still internally consistent.
    """
    for name in ("cfn-nag", "cdk-nag", "detect-secrets", "npm-audit"):
        assert name in SCANNER_TAG_NAMES
        assert name.replace("-", "_") not in SCANNER_TAG_NAMES
