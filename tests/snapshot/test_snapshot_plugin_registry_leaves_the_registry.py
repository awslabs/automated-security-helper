# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""test_snapshot_plugin_registry.py leaves the global plugin registry as it found it.

Its tests import plugin modules they write under tmp_path, register a reporter
and an event handler, and replace a registration, inside the registry copy
tests/snapshot/conftest.py gives each snapshot test. That fixture merges back,
on teardown, what a module first imported during the test registered, so a
probe module a test left in ``sys.modules`` stayed registered in the one
registry a worker shares, and a later test ran with a plugin whose module no
fresh process could import. Each test undoes its imports and registrations;
nothing checked that it did.

Run here in one pytest process: the built-ins loaded first, as an earlier test
would load them, and the registry recorded; then test_snapshot_plugin_registry.py;
then a check of what changed since. The record and the check are that file's
own registry_state and registry_changes_since, so the registry is read only in
the file whose tests change it.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import defusedxml.ElementTree as ET

from tests.utils.helpers import checkout_env

REPOSITORY = Path(__file__).resolve().parents[2]

# Shadows tests/snapshot/conftest.py's autouse fixture of the same name, so
# the probes read the REAL registry wherever tmp_path lives. When a probe's
# directory has a pytest ini file anywhere in its ancestry (any basetemp under
# a HOME that holds a pyproject.toml, say), pytest applies the collected
# snapshot directory's autouse fixtures to the probe too; under an ini-free
# ancestry it does not. Without the shadow, the leaked fixture gave each probe
# a per-test COPY of the registry: the record wrote the copy's state, the
# built-ins the record loaded went into that copy and left with it, and the
# check then reported the built-in handlers as unsubscribed -- a verdict about
# the tmp directory's placement, not about the file under test. The shadow is
# autouse so both placements run the same no-op.
_PLACEMENT_SHADOW = """\
import pytest


@pytest.fixture(autouse=True)
def _builtin_plugins_only():
    yield


"""

# The module pytest imports test_snapshot_plugin_registry.py as, at collection,
# before either probe runs.
BEFORE = (
    _PLACEMENT_SHADOW
    + """\
import json
from pathlib import Path

from automated_security_helper.plugins.loader import load_internal_plugins
from test_snapshot_plugin_registry import registry_state


def test_the_registry_is_recorded():
    load_internal_plugins()
    Path(__file__).with_name("before.json").write_text(
        json.dumps(registry_state()), encoding="utf-8"
    )
"""
)

AFTER = (
    _PLACEMENT_SHADOW
    + """\
import json
from pathlib import Path

from test_snapshot_plugin_registry import registry_changes_since


def test_the_registry_is_as_it_was():
    before = json.loads(
        Path(__file__).with_name("before.json").read_text(encoding="utf-8")
    )
    left = registry_changes_since(before)
    assert left == [], left
"""
)

#: A test of test_snapshot_plugin_registry.py, which the run must include.
A_TEST_OF_THE_FILE = "test_a_plugin_registered_under_another_name"


def test_the_tests_restore_the_registry(tmp_path):
    (tmp_path / "test_probe_before.py").write_text(BEFORE, encoding="utf-8")
    (tmp_path / "test_probe_after.py").write_text(AFTER, encoding="utf-8")
    report = tmp_path / "report.xml"
    # The child imports ASH from this checkout: it runs without -I, which would
    # ignore PYTHONPATH, and checkout_env puts the checkout first on it.
    run = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-p",
            "no:cacheprovider",
            "-p",
            "no:randomly",
            "-n",
            "0",
            "-q",
            "-o",
            "addopts=",
            f"--basetemp={tmp_path / 'child'}",
            f"--junitxml={report}",
            str(tmp_path / "test_probe_before.py"),
            "tests/snapshot/test_snapshot_plugin_registry.py",
            str(tmp_path / "test_probe_after.py"),
        ],
        cwd=REPOSITORY,
        env=checkout_env(),
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    cases = ET.parse(report).getroot().iter("testcase")
    outcomes = [
        (case.get("name"), case.find("failure") is None and case.find("error") is None)
        for case in cases
    ]
    # The control: the record ran first and the check last, the file's tests
    # ran between them, and everything before the check passed.
    names = [name for name, _ in outcomes]
    ran = (
        len(outcomes) >= 3
        and names[0] == "test_the_registry_is_recorded"
        and names[-1] == "test_the_registry_is_as_it_was"
        and A_TEST_OF_THE_FILE in names[1:-1]
        and all(passed for _, passed in outcomes[:-1])
    )
    assert ran, run.stdout[-3000:]
    # What test_snapshot_plugin_registry.py left behind, as the check found it.
    restored = outcomes[-1][1]
    assert restored, run.stdout[-3000:]


def test_a_registration_changed_in_place_is_listed():
    """registry_changes_since compares each registration whole, its fields too:
    one a test disabled in place and left is listed."""
    from tests.snapshot.test_snapshot_plugin_registry import (
        a_scanner_registration,
        registry_changes_since,
        registry_state,
    )

    name, registration = a_scanner_registration()
    before = registry_state()
    enabled = registration.enabled
    registration.enabled = not enabled
    try:
        left = registry_changes_since(before)
    finally:
        registration.enabled = enabled
    # Only the fields changed, and the line says so.
    assert left == [
        f"scanners: {name} from {registration.plugin_module_path} changed: fields"
    ], left


def test_a_registration_whose_module_holds_another_class_is_listed(monkeypatch):
    """A registration names its class by module and name. When the module holds
    another class under that name, a replacement a test left, it is listed."""
    import sys

    from tests.snapshot.test_snapshot_plugin_registry import (
        a_scanner_registration,
        registry_changes_since,
        registry_state,
    )

    name, registration = a_scanner_registration()
    module = sys.modules[registration.plugin_module_path]
    assert getattr(module, name, None) is not None, (name, module)
    before = registry_state()

    class Replacement:
        pass

    monkeypatch.setattr(module, name, Replacement)
    left = registry_changes_since(before)

    # The registration's class differs by names and identity, and the
    # replacement carries no ash_plugin_type, so the module no longer holds a
    # plugin class under the original's name.
    path = registration.plugin_module_path
    assert left == [
        f"scanners: {name} from {path} changed: class, class_id",
        f"{path}: plugin class {name} is gone",
    ], left


def test_a_replacement_with_the_same_qualified_name_is_listed(monkeypatch):
    """A registration's class is recorded by where it is defined as well as by
    its name: a replacement left in the module whose __qualname__ matches the
    original's is listed too.

    The replacement carries the original's ash_plugin_type, so the module's
    recorded plugin-class names do not change. Its record differs by the
    "class" string's defining-module part, asserted below so a record that
    dropped the module part is caught here, and by its identity (class_id),
    which test_a_replacement_subclass_with_the_originals_names_is_listed pins
    on its own."""
    import sys

    from tests.snapshot.test_snapshot_plugin_registry import (
        a_scanner_registration,
        registry_changes_since,
        registry_state,
    )

    name, registration = a_scanner_registration()
    module = sys.modules[registration.plugin_module_path]
    original = getattr(module, name)
    before = registry_state()

    class Replacement:
        pass

    Replacement.__name__ = original.__name__
    Replacement.__qualname__ = original.__qualname__
    Replacement.ash_plugin_type = original.ash_plugin_type
    monkeypatch.setattr(module, name, Replacement)
    # The docstring's precondition: the recorded "class" string tells the
    # replacement apart by its defining module.
    assert (
        registry_state()["scanners"][name]["class"] != before["scanners"][name]["class"]
    )
    left = registry_changes_since(before)

    assert left == [
        (
            f"scanners: {name} from {registration.plugin_module_path} "
            "changed: class, class_id"
        )
    ], left


def test_a_replacement_subclass_with_the_originals_names_is_listed(monkeypatch):
    """A registration's class is recorded by identity as well as by its names:
    a replacement left in the module that carries the original's module and
    qualified name, a subclass built with type(), is listed too. The recorded
    "class" string is unchanged, asserted below, so its identity (class_id) is
    the one part of the record that lists it."""
    import sys

    from tests.snapshot.test_snapshot_plugin_registry import (
        a_scanner_registration,
        registry_changes_since,
        registry_state,
    )

    name, registration = a_scanner_registration()
    module = sys.modules[registration.plugin_module_path]
    original = getattr(module, name)
    before = registry_state()

    replacement = type(
        name,
        (original,),
        {"__module__": original.__module__, "__qualname__": original.__qualname__},
    )
    monkeypatch.setattr(module, name, replacement)
    # The docstring's precondition: the names match, so nothing but the
    # identity tells the subclass apart.
    assert (
        registry_state()["scanners"][name]["class"] == before["scanners"][name]["class"]
    )
    left = registry_changes_since(before)

    # The one changed field is named, so this line is also the record that
    # nothing but the identity lists the subclass.
    assert left == [
        f"scanners: {name} from {registration.plugin_module_path} changed: class_id"
    ], left


def test_a_module_that_grows_while_being_read_is_still_read(monkeypatch):
    """Reading one module attribute can run code (a metaclass property, a lazy
    import) that adds a name to the module. The read works from a snapshot of
    the module's names, so it reports the plugin classes instead of raising on
    the changed module. The attribute sits on a class through its metaclass,
    because the read checks classes only: an instance's property is never
    run."""
    import sys
    import types

    from tests.snapshot.test_snapshot_plugin_registry import _plugin_classes

    module_name = "registry_probe_growing_module"
    module = types.ModuleType(module_name)

    class Plugin:
        ash_plugin_type = "scanner"

    class _AddsANameMeta(type):
        @property
        def ash_plugin_type(cls):
            module.added_while_read = None
            return None

    class _AddsAName(metaclass=_AddsANameMeta):
        pass

    module.Plugin = Plugin
    module.adds_a_name = _AddsAName
    module.read_after_the_add = object()
    monkeypatch.setitem(sys.modules, module_name, module)

    assert _plugin_classes({module_name}) == {module_name: ["Plugin"]}


def test_an_instance_with_a_plugin_type_is_not_a_plugin_class(monkeypatch):
    """The loader registers classes only, so the read counts classes only: an
    instance whose class carries ash_plugin_type, or a MagicMock, which answers
    any attribute read with a truthy child mock, left in a module is not listed
    as a plugin class the loader would never register."""
    import sys
    import types
    from unittest import mock

    from tests.snapshot.test_snapshot_plugin_registry import _plugin_classes

    module_name = "registry_probe_instances_module"
    module = types.ModuleType(module_name)

    class Plugin:
        ash_plugin_type = "scanner"

    module.Plugin = Plugin
    module.an_instance = Plugin()
    module.a_mock = mock.MagicMock()
    monkeypatch.setitem(sys.modules, module_name, module)

    assert _plugin_classes({module_name}) == {module_name: ["Plugin"]}


def test_an_extra_plugin_class_left_in_a_module_is_listed(monkeypatch):
    """A plugin class a test left in a registration's module without
    registering it is listed: the next run that loads plugins from the module
    would register it."""
    import sys

    from tests.snapshot.test_snapshot_plugin_registry import (
        a_scanner_registration,
        registry_changes_since,
        registry_state,
    )

    _, registration = a_scanner_registration()
    module = sys.modules[registration.plugin_module_path]
    before = registry_state()

    class ProbeLeftBehind:
        ash_plugin_type = "scanner"

    monkeypatch.setattr(module, "ProbeLeftBehind", ProbeLeftBehind, raising=False)
    left = registry_changes_since(before)

    path = registration.plugin_module_path
    assert left == [f"{path}: plugin class ProbeLeftBehind is still defined"], left
