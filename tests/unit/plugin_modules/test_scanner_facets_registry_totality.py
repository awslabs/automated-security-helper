# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Registry totality: every registered scanner declares its facets.

The facets register (automated_security_helper/base/scanner_facets.py) is a
contract only while no registered scanner can skip it. This module iterates
the loaded plugin registry -- the builtin package's derived inventory
(plugin_modules/ash_builtin/__init__.py ``ASH_SCANNERS``, derived from the
scanners package's ``__all__``) and every alpha plugin package's own
``ASH_SCANNERS`` -- and FAILS, naming the scanner, for each class without its
own ``ScannerFacets`` declaration. A scanner added to any in-repo plugin
package without a declaration fails here on the pull request that adds it;
the complementary direction (a declaration with no scanner) cannot exist by
construction, since the declaration is a class attribute.

Deliberate choices, said out loud:

- The enumeration walks ``pkgutil.iter_modules`` over the plugin_modules
  package rather than a hand-written package list, so a new alpha plugin
  package is swept in without editing this file -- the hand-written second
  inventory is the drift class ash_builtin's own docstring records.
- The declaration must sit in the class's OWN ``vars()``: an inherited one
  does not count, because a subclass (trivy-repo over the shared trivy base,
  say) has its own native output to classify.
- The enumeration itself is guarded by planted controls (one builtin and one
  alpha scanner by name, and an empty builtin load-error map), because a
  silently shrunken universe would pass this suite vacuously.
"""

from __future__ import annotations

import pytest

from automated_security_helper.base.scanner_facets import (
    SCANNER_FACETS_ATTR,
    ScannerFacets,
)
from automated_security_helper.base.scanner_operational_facets import (
    OPERATIONAL_FACETS_ATTR,
    ScannerOperationalFacets,
)
from automated_security_helper.core.enums import OfflineStrategy
from tests.utils.scanner_enumeration import load_scanner_universe

pytestmark = pytest.mark.unit

#: The shared enumeration (tests/utils/scanner_enumeration.py): the retry of any
#: plugin group an import-order cycle cost, then the walk over every in-repo
#: plugin package. Anything still lost fails the enumeration-guard test below
#: rather than silently shrinking the universe.
SCANNER_CLASSES, _REMAINING_LOAD_ERRORS = load_scanner_universe()


def test_the_enumeration_sees_builtin_and_alpha_scanners() -> None:
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
        "no alpha package contributed scanners; the totality sweep "
        f"below is vacuous. Saw: {sorted(names)}"
    )


@pytest.mark.parametrize("scanner_cls", SCANNER_CLASSES, ids=lambda cls: cls.__name__)
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


# ---------------------------------------------------------------------------
# The operational register (base/scanner_operational_facets.py): one totality
# test over the same enumeration, so one sweep covers both descriptors.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scanner_cls", SCANNER_CLASSES, ids=lambda cls: cls.__name__)
def test_every_registered_scanner_declares_its_operational_facets(
    scanner_cls: type,
) -> None:
    """Fail closed: an undeclared registered scanner is a failure naming it."""
    declared = vars(scanner_cls).get(OPERATIONAL_FACETS_ATTR)
    assert declared is not None, (
        f"{scanner_cls.__module__}.{scanner_cls.__qualname__} is registered "
        f"with no ScannerOperationalFacets declaration (an "
        f"{OPERATIONAL_FACETS_ATTR!r} class attribute of its own). Read the "
        "scanner's adapter and classify every operational dimension "
        "(base/scanner_operational_facets.py); an unread value is an explicit "
        "unconfirmed state with its reason, never a default. An inherited "
        "declaration does not count: a subclass classifies its own behavior."
    )
    assert isinstance(declared, ScannerOperationalFacets), (
        f"{scanner_cls.__qualname__}.{OPERATIONAL_FACETS_ATTR} is "
        f"{type(declared).__name__}, not ScannerOperationalFacets"
    )


@pytest.mark.parametrize("scanner_cls", SCANNER_CLASSES, ids=lambda cls: cls.__name__)
def test_no_registered_scanner_rests_on_the_unknown_offline_strategy(
    scanner_cls: type,
) -> None:
    """UNKNOWN is the base default, so a new scanner inherits it silently.

    The enum value is a work item, not a resting state: read what the scanner
    does offline and declare BUNDLED, CACHE_FLAGS or SKIP_OFFLINE.
    """
    assert scanner_cls.offline_strategy is not OfflineStrategy.UNKNOWN, (
        f"{scanner_cls.__qualname__}.offline_strategy is still the base "
        "default UNKNOWN; read a record of how it behaves offline and classify it"
    )


def test_the_enumeration_holds_all_twenty_three_shipped_scanners() -> None:
    """The planted-control count: a shrunken universe fails here, not silently."""
    assert len(SCANNER_CLASSES) == 23, sorted(c.__name__ for c in SCANNER_CLASSES)
