# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``plugin_modules`` answers for the plugins registered now, not at its first call.

The defect
----------
Were ``AshPluginManager.plugin_modules`` to memoise its resolved class list per
plugin kind, keyed only on the kind, and never look again, the first resolution
in a process would decide the answer for every later one. A config that loaded
more plugin modules after that (``ash_plugin_modules: [...ash_aws_plugins]``,
say) would register them, but the resolution would return the old list. So
``ash report`` would say "Reporter plugin 'aws-security-hub' not found" whenever
anything in the process had resolved reporters before, such as another test or an
earlier request to a long-lived MCP server, and one session's plugin list would
hold for every later session.

The memo is kept with the registrations it was resolved from (name, module
and enabled flag, in order), and a resolution whose registry no longer matches
resolves again.

What the tests do
-----------------
On a manager with its own registry: a reporter registered after the first
resolution is in the second one, a disabled registration drops out, and an
unchanged registry is answered from the memo without importing anything. In a
child interpreter, with the process-wide manager and ASH's own loaders: resolve
the reporters, load the AWS plugin module, resolve again, and the AWS reporter is
there. A child because the process-wide registry is what the defect lived in, and
this test process has resolved it many times already.
"""

from __future__ import annotations

import json
import subprocess  # nosec B404 - a fresh interpreter is the property under test
import sys
import textwrap
from typing import List
from unittest.mock import patch

import pytest

from automated_security_helper.plugins.plugin_manager import (
    AshPluginLibrary,
    AshPluginManager,
)
from tests.utils.helpers import importing_this_checkout

CSV_REPORTER = (
    "automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter"
)
SECURITY_HUB_REPORTER = (
    "automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter"
)


def _manager() -> AshPluginManager:
    manager = AshPluginManager(
        plugin_library=AshPluginLibrary(converters={}, scanners={}, reporters={})
    )
    manager.register_plugin_module("reporter", "CsvReporter", CSV_REPORTER)
    return manager


def _names(classes) -> List[str]:
    return [cls.__name__ for cls in classes]


@pytest.mark.unit
def test_a_reporter_registered_after_the_first_resolution_is_resolved():
    manager = _manager()
    first = _names(manager.plugin_modules("reporter"))
    assert first == ["CsvReporter"]

    manager.register_plugin_module(
        "reporter", "SecurityHubReporter", SECURITY_HUB_REPORTER
    )
    second = _names(manager.plugin_modules("reporter"))

    assert second == ["CsvReporter", "SecurityHubReporter"]


@pytest.mark.unit
def test_a_disabled_registration_drops_out_of_the_next_resolution():
    manager = _manager()
    manager.register_plugin_module(
        "reporter", "SecurityHubReporter", SECURITY_HUB_REPORTER
    )
    assert "SecurityHubReporter" in _names(manager.plugin_modules("reporter"))

    manager.plugin_library.reporters["SecurityHubReporter"].enabled = False

    assert _names(manager.plugin_modules("reporter")) == ["CsvReporter"]


@pytest.mark.unit
def test_a_removed_registration_drops_out_and_a_second_removal_finds_nothing():
    """``remove_plugin_module_registration`` is ``register_plugin_module``'s
    inverse, the route a test takes to put the registry back: the first removal
    reports the entry was there and the next resolution no longer has it, and a
    second removal reports there was nothing to remove. A removal that removed
    nothing would leave a test's registration in every later test in the worker,
    and fail none of them."""
    manager = _manager()
    manager.register_plugin_module(
        "reporter", "SecurityHubReporter", SECURITY_HUB_REPORTER
    )
    assert "SecurityHubReporter" in _names(manager.plugin_modules("reporter"))

    assert manager.remove_plugin_module_registration("reporter", "SecurityHubReporter")

    assert _names(manager.plugin_modules("reporter")) == ["CsvReporter"]
    assert (
        manager.remove_plugin_module_registration("reporter", "SecurityHubReporter")
        is False
    )


@pytest.mark.unit
def test_an_unchanged_registry_is_answered_from_the_memo():
    """The memo saves the import work while nothing new is registered."""
    import importlib

    manager = _manager()
    first = manager.plugin_modules("reporter")
    imported: List[str] = []
    real_import = importlib.import_module

    def counting_import(name, *args, **kwargs):
        imported.append(name)
        return real_import(name, *args, **kwargs)

    with patch.object(importlib, "import_module", counting_import):
        again = manager.plugin_modules("reporter")

    assert imported == []
    assert again == first


@pytest.mark.unit
def test_each_kind_follows_its_own_registrations():
    """A new reporter does not cost the scanner resolution its memo."""
    import importlib

    manager = _manager()
    manager.register_plugin_module(
        "scanner",
        "BanditScanner",
        "automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner",
    )
    scanners = manager.plugin_modules("scanner")
    manager.register_plugin_module(
        "reporter", "SecurityHubReporter", SECURITY_HUB_REPORTER
    )
    imported: List[str] = []
    real_import = importlib.import_module

    def counting_import(name, *args, **kwargs):
        imported.append(name)
        return real_import(name, *args, **kwargs)

    with patch.object(importlib, "import_module", counting_import):
        again = manager.plugin_modules("scanner")

    assert imported == []
    assert _names(again) == _names(scanners) == ["BanditScanner"]


DRIVER = textwrap.dedent(
    """
    import json

    from automated_security_helper.plugins import ash_plugin_manager
    from automated_security_helper.plugins.loader import (
        load_additional_plugin_modules,
        load_internal_plugins,
    )

    load_internal_plugins()
    first = [cls.__name__ for cls in ash_plugin_manager.plugin_modules("reporter")]
    load_additional_plugin_modules(
        ["automated_security_helper.plugin_modules.ash_aws_plugins"]
    )
    second = [cls.__name__ for cls in ash_plugin_manager.plugin_modules("reporter")]
    print(json.dumps({"first": first, "second": second}))
    """
)


@pytest.mark.integration
def test_a_module_loaded_after_resolving_is_found_by_the_process_wide_manager():
    """The `ash report` case: resolve, then a config's ash_plugin_modules load."""
    completed = subprocess.run(  # nosec B603 - fixed argv, the test's own interpreter
        [sys.executable, "-I", "-c", importing_this_checkout(DRIVER)],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert completed.returncode == 0, completed.stderr[-3000:]
    resolved = json.loads(completed.stdout.strip().splitlines()[-1])

    # The premise: the first resolution ran before the AWS module was loaded.
    assert "SecurityHubReporter" not in resolved["first"], resolved
    assert "SecurityHubReporter" in resolved["second"], resolved
    assert set(resolved["first"]) <= set(resolved["second"]), resolved
