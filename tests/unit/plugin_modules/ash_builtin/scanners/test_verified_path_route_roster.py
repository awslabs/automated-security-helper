# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which scanners honor the verified-PATH record, pinned against the fallback shape.

``_select_tool_execution`` records the PATH copy it verified on every scanner
that calls it; what differs is who must CONSULT the record. The defect shape is
a validation that, entered with ``use_uv_tool`` False (the record's own
decision), falls into a ``get_uv_tool_command`` fallback -- paying the
resolver's cold ``uv tool run ... --version`` probe per re-check and, where the
fallback re-points the route from the resolver's answer, flipping the scan back
through uv so the verified copy never runs.

At the bytes today:

* checkov (checkov_scanner.py), cfn-lint (cfn_lint_scanner.py) and guarddog
  (ash_guarddog_plugins/guarddog_scanner.py) carry the flip
  (``uses_uv = is_uv_form(resolved)``, then ``use_uv_tool = uses_uv``) and
  consult the record;
* bandit (bandit_scanner.py) routes its fallback through
  ``_take_resolved_command`` -- a uv answer keeps the route, so no flip, but
  the cold probe is paid -- and consults the record;
* semgrep (semgrep_scanner.py) needs no consult: entered with ``use_uv_tool``
  False and uv available, ``_validate_tool_dependencies`` ends in its final
  ``dependencies_satisfied = True`` arm with no probe;
* zizmor (zizmor_scanner.py) re-decides from scratch by design (it sets
  ``use_uv_tool = True`` at the top of its tool check, around its
  rejected-executable logic), and the jupyter converter records its route in
  its own ``_nbconvert_route``; both re-verifications answer from the memoized
  or persisted verdict instead.

The second test is the drift guard: a scanner that grows the fallback shape
without consulting the record reintroduces the measured defect, and fails
here until it joins the roster. It reads every module under ``plugin_modules``
that calls ``get_uv_tool_command``, not only the builtin scanners' directory:
guarddog lives in a plugin package of its own, and a guard scoped to the
builtin directory never read its file.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

import automated_security_helper.plugin_modules as plugin_modules_pkg
import automated_security_helper.plugin_modules.ash_builtin.scanners as scanners_pkg
from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    BanditScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_lint_scanner import (
    CfnLintScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
)
from automated_security_helper.plugin_modules.ash_guarddog_plugins.guarddog_scanner import (
    GuardDogScanner,
)

pytestmark = pytest.mark.unit

HONORING = (BanditScanner, CheckovScanner, CfnLintScanner, GuardDogScanner)

#: The spellings of the fallback shape: a route re-pointed from the resolver's
#: answer, or bandit's route-keeping wrapper around the same cold probe.
_FALLBACK_MARKS = ("uses_uv = is_uv_form(resolved)", "_take_resolved_command")

_RESOLVER = "get_uv_tool_command"


def _calls_the_resolver(source: str) -> bool:
    """Whether a module's code uses ``get_uv_tool_command``: calls it by its name,
    through the module that defines it, or under another name it was imported as.

    Read from the syntax tree, so a comment, a docstring or a string that only
    names it does not count. A use that is not a call (the name bound to another,
    or handed on) counts as well: a route can be taken from the answer of either.
    """
    if _RESOLVER not in source:
        return False
    tree = ast.parse(source)
    names = {_RESOLVER}
    names.update(
        alias.asname
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
        if alias.name == _RESOLVER and alias.asname
    )
    return any(
        (isinstance(node, ast.Name) and node.id in names)
        or (isinstance(node, ast.Attribute) and node.attr == _RESOLVER)
        for node in ast.walk(tree)
    )


def _scanned_modules() -> list[Path]:
    """The modules the drift guard reads: every file of the builtin scanners'
    directory, as it always read, and every module anywhere under
    ``plugin_modules`` that calls the resolver."""
    builtin_dir = Path(scanners_pkg.__file__).parent
    plugin_modules_dir = Path(plugin_modules_pkg.__file__).parent
    found = set(builtin_dir.glob("*.py"))
    found.update(
        module_path
        for module_path in plugin_modules_dir.rglob("*.py")
        if _calls_the_resolver(module_path.read_text(encoding="utf-8"))
    )
    return sorted(found)


def test_every_honoring_scanner_consults_the_record():
    for scanner_cls in HONORING:
        source = inspect.getsource(scanner_cls.validate_plugin_dependencies)
        assert "_honored_verified_pre_installed" in source, scanner_cls.__name__


def test_every_fallback_shape_is_on_the_roster():
    """Any scanner module carrying the fallback shape must consult the record."""
    carriers = []
    for module_path in _scanned_modules():
        source = module_path.read_text(encoding="utf-8")
        if any(mark in source for mark in _FALLBACK_MARKS):
            carriers.append(module_path.name)
            assert "_honored_verified_pre_installed" in source, (
                f"{module_path.name} carries the consolidated-resolver fallback "
                "shape but never consults the verified-PATH record: entered "
                "with use_uv_tool False it re-pays the cold uv probe per "
                "re-validation (and may flip the route), the measured defect. "
                "Consult _honored_verified_pre_installed before the fallback, "
                "or rework the fallback, and update this roster's docstring."
            )
    # The control: the shape detector still matches the known carriers, so a
    # renamed spelling cannot make this guard silently vacuous.
    assert set(carriers) >= {
        "bandit_scanner.py",
        "checkov_scanner.py",
        "cfn_lint_scanner.py",
        "guarddog_scanner.py",
    }


def test_the_drift_guard_reads_every_module_that_calls_the_resolver():
    """The control for the guard's file set: the six scanners that take a route
    from ``get_uv_tool_command`` are all read, guarddog's file among them. A module
    that calls it from a seventh place is read too, by the same detector."""
    assert {module_path.name for module_path in _scanned_modules()} >= {
        "bandit_scanner.py",
        "cfn_lint_scanner.py",
        "checkov_scanner.py",
        "guarddog_scanner.py",
        "semgrep_scanner.py",
        "zizmor_scanner.py",
    }


@pytest.mark.parametrize(
    ("source", "calls"),
    [
        ("from x import get_uv_tool_command\nget_uv_tool_command('t')\n", True),
        (
            "from x import get_uv_tool_command as resolve\nresolve('t')\n",
            True,
        ),
        ("import x\nx.get_uv_tool_command('t')\n", True),
        (
            "from x import get_uv_tool_command\nresolve = get_uv_tool_command\n",
            True,
        ),
        ("from x import get_uv_tool_command\n", False),
        ("# get_uv_tool_command('t')\nx = 1\n", False),
        ('"""get_uv_tool_command(\'t\')"""\nx = 1\n', False),
        ("name = 'get_uv_tool_command('\n", False),
    ],
    ids=[
        "by-name",
        "under-an-alias",
        "through-the-module",
        "bound-to-another-name",
        "imported-only",
        "in-a-comment",
        "in-a-docstring",
        "in-a-string",
    ],
)
def test_a_module_that_calls_the_resolver_is_told_from_one_that_names_it(source, calls):
    """The must-flag and must-not-flag inputs of the detector the guard's file set
    rests on: without them an empty set would pass every check above."""
    assert _calls_the_resolver(source) is calls
