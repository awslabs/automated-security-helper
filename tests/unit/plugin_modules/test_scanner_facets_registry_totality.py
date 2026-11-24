# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Registry totality: every registered scanner declares its facets.

The facets register (automated_security_helper/base/scanner_facets.py) is a
contract only while no registered scanner can skip it. This module iterates
the loaded plugin registry -- the builtin package's derived inventory
(plugin_modules/ash_builtin/__init__.py ``ASH_SCANNERS``, derived from the
scanners package's ``__all__``) and every community plugin package's own
``ASH_SCANNERS`` -- and FAILS, naming the scanner, for each class without its
own ``ScannerFacets`` declaration. A scanner added to any in-repo plugin
package without a declaration fails here on the pull request that adds it;
the complementary direction (a declaration with no scanner) cannot exist by
construction, since the declaration is a class attribute.

Deliberate choices, said out loud:

- The enumeration walks ``pkgutil.iter_modules`` over the plugin_modules
  package rather than a hand-written package list, so a new community plugin
  package is swept in without editing this file -- the hand-written second
  inventory is the drift class ash_builtin's own docstring records.
- The declaration must sit in the class's OWN ``vars()``: an inherited one
  does not count, because a subclass (trivy-repo over the shared trivy base,
  say) has its own native output to classify.
- The enumeration itself is guarded by planted controls (one builtin and one
  community scanner by name, and an empty builtin load-error map), because a
  silently shrunken universe would pass this suite vacuously.
"""

from __future__ import annotations

import importlib
import pkgutil

import pytest

from automated_security_helper import plugin_modules
from automated_security_helper.base.scanner_facets import (
    SCANNER_FACETS_ATTR,
    ScannerFacets,
)
from automated_security_helper.plugin_modules import ash_builtin

pytestmark = pytest.mark.unit

#: Import-order cycles can cost ash_builtin a plugin group on first import
#: (its own docstring measures which orders); the retry recovers every such
#: order and returns what is still lost. Anything still lost fails the
#: enumeration-guard test below rather than silently shrinking the universe.
_REMAINING_LOAD_ERRORS = ash_builtin.retry_failed_plugin_groups()


def _registered_scanner_classes() -> list[type]:
    """Every scanner class the in-repo plugin packages register.

    Package order is alphabetical and classes keep each package's own order,
    so parametrized ids are stable run to run.
    """
    classes: list[type] = []
    seen: set[type] = set()
    modules = sorted(
        pkgutil.iter_modules(plugin_modules.__path__), key=lambda m: m.name
    )
    for info in modules:
        if not info.ispkg:
            continue
        package = importlib.import_module(f"{plugin_modules.__name__}.{info.name}")
        for cls in getattr(package, "ASH_SCANNERS", []):
            if cls not in seen:
                seen.add(cls)
                classes.append(cls)
    return classes


SCANNER_CLASSES = _registered_scanner_classes()


def test_the_enumeration_sees_builtin_and_community_scanners() -> None:
    """Planted controls: a shrunken universe fails loudly, never vacuously."""
    assert not _REMAINING_LOAD_ERRORS, (
        "builtin plugin groups failed to import, so the scanner universe "
        f"below is incomplete: {_REMAINING_LOAD_ERRORS}"
    )
    names = {cls.__name__ for cls in SCANNER_CLASSES}
    assert "CdkNagScanner" in names, (
        "the builtin package contributed no scanners; the totality sweep "
        f"below is vacuous. Saw: {sorted(names)}"
    )
    assert "TrivyRepoScanner" in names, (
        "no community package contributed scanners; the totality sweep "
        f"below is vacuous. Saw: {sorted(names)}"
    )


@pytest.mark.parametrize(
    "scanner_cls", SCANNER_CLASSES, ids=lambda cls: cls.__name__
)
def test_every_registered_scanner_declares_its_facets(scanner_cls: type) -> None:
    """Fail closed: an undeclared registered scanner is a failure naming it."""
    declared = vars(scanner_cls).get(SCANNER_FACETS_ATTR)
    assert declared is not None, (
        f"{scanner_cls.__module__}.{scanner_cls.__qualname__} is registered "
        f"with no ScannerFacets declaration (a {SCANNER_FACETS_ATTR!r} class "
        "attribute of its own). Read a record of this scanner's output and "
        "classify every facet; an unread facet is n/a with the reason "
        "'output not read; a sample run would settle it'. An inherited "
        "declaration does not count: a subclass classifies its own output."
    )
    assert isinstance(declared, ScannerFacets), (
        f"{scanner_cls.__module__}.{scanner_cls.__qualname__}."
        f"{SCANNER_FACETS_ATTR} is {type(declared).__name__}, not "
        "ScannerFacets; declare through the register so the vocabulary "
        "totality holds"
    )
