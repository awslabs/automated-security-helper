# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Probe: mcp_list_scanners() does not depend on what ran before it.

Run by test_list_scanners_import_order.py in a pytest process of its own,
never collected by the main run (the file name is no test module's). Every
cell here loads plugin packages, and a load registers classes in the
process-global plugin registry for the rest of the worker: the registry
offers no unregister a test may use (the project-isolation sweep forbids
reaching into it), restoring sys.modules cannot take a registration back,
and a re-import would mint second-generation classes that compare unequal
to the first. Run in the main process, these cells changed what every
later test on their xdist worker resolved; in their own interpreter the
registrations die with it.

The mechanism these guard
-------------------------
``ash_plugin_manager.plugin_modules()`` memoising its resolved class list
keyed only on the plugin kind would let the first resolve in a process decide the
answer for every later one; it follows the registrations instead (see
tests/unit/plugins/test_plugin_modules_follows_the_registry.py).
``mcp_list_scanners()`` has to account for the vendored ferret/snyk/trivy
scanners, which ``load_internal_plugins()`` does not load; were it to read them
back through such a memo after anything had resolved earlier, those three would
be absent from what it returned: a caller asking a security scanner which
scanners it has would get an answer three short, with nothing logged and no
error raised.

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
Anything about what ``plugin_modules()`` returns afterwards. That belongs to the
plugin manager's own tests; these check that *this* function answers completely
whatever ran before it.
"""

import pytest

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
from tests.utils.tool_guard import stub_tool_probes

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _no_tool_probe(monkeypatch):
    """list_scanners runs every scanner's dependency check, which ran ``uv tool list``
    and ``uv tool run --offline ... --version`` for bandit, checkov, detect-secrets
    and semgrep; these tests are about which scanners it lists, and answer the probes
    as a host without uv would."""
    stub_tool_probes(monkeypatch)


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
        """The outcome, whatever the memo holds when this test runs.

        A sibling test may already have loaded the vendored packages into this
        worker, which makes the memo complete; this test does not control that
        state, so a red here names what is missing and not why (the
        memo-shortness mechanism is pinned, when observable, by
        ``test_complete_when_the_memo_is_demonstrably_short``).
        """
        _resolve_without_the_vendored_packages()

        resolved = _loaded_scanner_classes()

        names = {cls.__name__ for cls in resolved}
        missing = VENDORED_SCANNER_CLASSES - names
        assert not missing, (
            f"_loaded_scanner_classes() is missing {sorted(missing)}; "
            f"got {sorted(names)}"
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


def test_this_child_imported_the_checkout_under_test():
    """The child-process guard lists this launch on the stated reason that
    the parent puts the checkout first on the child's path; a reason
    nothing reads is documentation, so this cell checks the substance.
    The check runs HERE because captured terminal output masks
    environment values, the checkout path among them, so the parent can
    only read back a verdict line, never the path itself."""
    from pathlib import Path

    import automated_security_helper

    checkout = Path(__file__).resolve().parents[4]
    package_file = Path(automated_security_helper.__file__).resolve()
    verdict = package_file.is_relative_to(checkout)
    print(f"probe-package-in-checkout={verdict}")
    assert verdict, package_file
