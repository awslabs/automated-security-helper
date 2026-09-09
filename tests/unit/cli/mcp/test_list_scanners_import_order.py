# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests that mcp_list_scanners() does not depend on what ran before it.

The mechanism these guard
-------------------------
``ash_plugin_manager.plugin_modules()`` memoises its resolved class list and never
invalidates it, so the first resolve in a process decides the answer for every
later one. ``mcp_list_scanners()`` has to account for the vendored
ferret/snyk/trivy scanners, which ``load_internal_plugins()`` does not load; when
it read them back through that memo, and anything had resolved earlier, those
three were absent from what it returned. A caller asking a security scanner which
scanners it has got an answer three short, with nothing logged and no error
raised.

Why these tests provoke the memo through the public API only
-----------------------------------------------------------
The tests in ``test_list_scanners.py`` call ``mcp_list_scanners()`` on a process
whose history they do not control, which is why they failed at some pytest-xdist
worker counts and passed at others on identical code. Reproducing the poisoning
by hand is what makes these deterministic instead.

They go through ``plugin_modules()`` rather than touching ``plugin_library`` or
``_resolved_plugins``, because the sweep in
``tests/unit/workspace/test_project_isolation.py`` forbids reaching into the
manager's registry from outside the class that owns it -- in a new test as much as
in production. An earlier draft of this file did reach in, and that sweep is what
caught it.

What is deliberately not asserted here
-------------------------------------
That ``mcp_list_scanners()`` leaves ``plugin_modules()`` returning the full set.
It does not, and is not meant to: the memo is repaired for nobody, because
workspace mode depends on it holding still. The scope of this fix is that *this*
function answers completely; every other consumer of the memo is unchanged, and a
test asserting otherwise passed only when no prior resolve had happened, which is
the same worker-count nondeterminism these tests exist to remove.
"""

from automated_security_helper.cli.mcp_tools import (
    _VENDORED_SCANNER_PLUGIN_PACKAGES,
    _loaded_scanner_classes,
    mcp_list_scanners,
)
from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.plugins.loader import (
    load_additional_plugin_modules,
    load_internal_plugins,
)

VENDORED_SCANNER_NAMES = {"ferret_scan", "snyk_code", "trivy_repo"}
VENDORED_SCANNER_CLASSES = {"FerretScanScanner", "SnykCodeScanner", "TrivyRepoScanner"}


def _resolve_without_the_vendored_packages() -> set:
    """Make the process look like something resolved before we were called.

    Loads the internal plugins only, then resolves, which is what a CLI command or
    an earlier test does. The returned names are the memo's contents, so a caller
    can assert the memo really is short before trusting a test that depends on it
    being short -- otherwise, on a worker where another test already loaded the
    vendored packages, the test would pass while exercising nothing.
    """
    load_internal_plugins()
    return {cls.__name__ for cls in ash_plugin_manager.plugin_modules("scanner")}


class TestListScannersIsImportOrderIndependent:
    def test_complete_after_a_prior_resolve(self):
        """The core guarantee: a resolve before us must not shorten our answer."""
        _resolve_without_the_vendored_packages()

        names = {entry["name"] for entry in mcp_list_scanners()}

        missing = VENDORED_SCANNER_NAMES - names
        assert not missing, f"mcp_list_scanners() lost {missing} to a stale resolve"
        assert len(names) >= 13

    def test_complete_when_the_memo_is_demonstrably_short(self):
        """Same guarantee, with the memo's shortness asserted rather than assumed.

        Skips rather than passes when the worker's history already loaded the
        vendored packages, because a green result in that state would prove
        nothing. The test above covers the outcome unconditionally; this one
        exists to pin the mechanism when it can be observed.
        """
        import pytest

        memoised = _resolve_without_the_vendored_packages()
        if VENDORED_SCANNER_CLASSES & memoised:
            pytest.skip(
                "this worker had already loaded the vendored packages, so the "
                "memo is complete and there is no staleness to observe"
            )

        names = {entry["name"] for entry in mcp_list_scanners()}
        assert VENDORED_SCANNER_NAMES <= names

    def test_complete_when_vendored_packages_already_loaded(self):
        """Order-independence in the other direction.

        Loading the vendored packages before the call must not change the result
        either. This is the case metadata discovery used to shadow: the old code
        chose discovery over the vendored list whenever discovery returned
        anything, so whichever set the winner did not cover simply vanished.
        """
        load_additional_plugin_modules(list(_VENDORED_SCANNER_PLUGIN_PACKAGES))

        names = {entry["name"] for entry in mcp_list_scanners()}
        assert VENDORED_SCANNER_NAMES <= names

    def test_repeated_calls_agree(self):
        """Idempotent: calling it again must not add or drop scanners."""
        first = sorted(e["name"] for e in mcp_list_scanners())
        second = sorted(e["name"] for e in mcp_list_scanners())
        assert first == second

    def test_names_are_unique(self):
        """One entry per scanner.

        A scanner reported twice would double-count for any caller that sizes or
        shards work from this list.
        """
        names = [e["name"] for e in mcp_list_scanners()]
        assert len(names) == len(set(names)), f"duplicate entries in {sorted(names)}"


class TestLoadedScannerClasses:
    def test_finds_every_scanner_regardless_of_the_memo(self):
        _resolve_without_the_vendored_packages()

        resolved = _loaded_scanner_classes()

        names = {cls.__name__ for cls in resolved}
        assert VENDORED_SCANNER_CLASSES <= names, (
            f"resolved from the memo rather than the loaders; got {sorted(names)}"
        )
        assert len(resolved) >= 13

    def test_returns_no_duplicates(self):
        """The internal and vendored lists overlap in principle; dedupe anyway.

        Without this, a scanner declared by two packages would be reported twice.
        """
        classes = _loaded_scanner_classes()
        names = [cls.__name__ for cls in classes]
        assert len(names) == len(set(names)), f"duplicates in {sorted(names)}"

    def test_repeated_calls_return_the_same_set(self):
        assert {c.__name__ for c in _loaded_scanner_classes()} == {
            c.__name__ for c in _loaded_scanner_classes()
        }

    def test_vendored_packages_are_package_paths_not_module_paths(self):
        """Guards the subtlety that makes this work.

        ``ASH_SCANNERS`` is declared in each package's ``__init__``, so the
        loaders return the three vendored scanners only when handed the package
        path. Pointing at ``ash_ferret_plugins.ferret_scanner`` imports the
        scanner but reports nothing, and the resulting list would be silently
        short again. Measured both ways: leaf paths yield 0, package paths yield 3.
        """
        leaf_paths = [
            f"{package}.{leaf}"
            for package, leaf in zip(
                _VENDORED_SCANNER_PLUGIN_PACKAGES,
                ("ferret_scanner", "snyk_code_scanner", "trivy_repo_scanner"),
            )
        ]

        via_leaves = load_additional_plugin_modules(leaf_paths)
        via_packages = load_additional_plugin_modules(
            list(_VENDORED_SCANNER_PLUGIN_PACKAGES)
        )

        assert via_leaves["scanners"] == [], (
            "leaf module paths now report scanners; if ASH_SCANNERS moved into "
            "the leaf modules this guard is stale, but check the package paths "
            "still work before deleting it"
        )
        assert len(via_packages["scanners"]) == 3
