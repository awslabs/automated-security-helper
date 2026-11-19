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

* checkov (checkov_scanner.py) and cfn-lint (cfn_lint_scanner.py) carry the
  flip (``use_uv_tool = resolved[:1] == ["uv"]``) and consult the record;
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
here until it joins the roster.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

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

pytestmark = pytest.mark.unit

HONORING = (BanditScanner, CheckovScanner, CfnLintScanner)

#: The spellings of the fallback shape: a route re-pointed from the resolver's
#: answer, or bandit's route-keeping wrapper around the same cold probe.
_FALLBACK_MARKS = ('use_uv_tool = resolved[:1] == ["uv"]', "_take_resolved_command")


def test_every_honoring_scanner_consults_the_record():
    for scanner_cls in HONORING:
        source = inspect.getsource(scanner_cls.validate_plugin_dependencies)
        assert "_honored_verified_pre_installed" in source, scanner_cls.__name__


def test_every_fallback_shape_is_on_the_roster():
    """Any scanner module carrying the fallback shape must consult the record."""
    package_dir = Path(scanners_pkg.__file__).parent
    carriers = []
    for module_path in sorted(package_dir.glob("*.py")):
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
    }
