# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Each CI cell that asserts an opt-in scanner ran names one the manifests say is opt-in.

``.github/actions/run-scan-test/assert_alpha_scanner_ran.py`` proves that a
scanner that loads only when its module is named ran in a scan that named it. The
script runs in a bare interpreter on the runner (``python3``, with no ASH on its
path), so it cannot read the manifests itself; this gate reads them instead, at
unit time, and fails when a cell names a scanner the manifests enable by default
or do not know. The cell and the manifests therefore cannot drift apart.

The read of the action file is guarded by planted controls, because a regex that
matched nothing would pass every row vacuously.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from automated_security_helper.plugin_manifests import opt_in_module_for

pytestmark = pytest.mark.unit

ACTION = (
    Path(__file__).resolve().parents[2]
    / ".github"
    / "actions"
    / "run-scan-test"
    / "action.yml"
)

_SCRIPT = "assert_alpha_scanner_ran.py"
#: The scanner argument follows the results path in every invocation shape
#: (bash ``"$out/ash_aggregated_results.json" hadolint`` and PowerShell
#: ``(Join-Path $Out "ash_aggregated_results.json") hadolint``).
_SCANNER_AFTER_RESULTS = re.compile(
    r'ash_aggregated_results\.json"\)?\s+([a-z][a-z0-9-]*)'
)


def scanners_asserted(text: str) -> list[str]:
    """The scanner each ``assert_alpha_scanner_ran.py`` invocation in *text* names."""
    found = []
    for hit in re.finditer(re.escape(_SCRIPT) + r'"?', text):
        match = _SCANNER_AFTER_RESULTS.search(text, hit.end(), hit.end() + 300)
        if match:
            found.append(match.group(1))
    return found


def test_every_cell_names_a_scanner_the_manifests_say_is_opt_in() -> None:
    names = scanners_asserted(ACTION.read_text(encoding="utf-8"))
    assert len(names) >= 2, (
        "the read of action.yml went dead: expected the Unix and the Windows "
        f"hadolint cells, found {names}"
    )
    not_opt_in = [name for name in names if opt_in_module_for(name) is None]
    assert not not_opt_in, (
        f"{not_opt_in} named by an assert_alpha_scanner_ran.py cell is not an opt-in "
        "scanner in plugin_manifests (default_enabled is true, or no manifest "
        "names it): update the cell or the manifest"
    )


_PLANTED_UNIX = (
    f'"$PY" "${{{{ github.action_path }}}}/{_SCRIPT}" \\\n'
    '  "$out/ash_aggregated_results.json" bandit --exit-code "$rc"\n'
)
_PLANTED_WINDOWS = (
    f'& $Python "${{{{ github.action_path }}}}/{_SCRIPT}" `\n'
    '  (Join-Path $Out "ash_aggregated_results.json") bandit --exit-code $Rc\n'
)


@pytest.mark.parametrize(
    "planted", [_PLANTED_UNIX, _PLANTED_WINDOWS], ids=["unix", "windows"]
)
def test_a_planted_cell_naming_a_default_scanner_is_read_and_flagged(planted) -> None:
    """The must-flag control: both invocation shapes parse, and a built-in fails."""
    names = scanners_asserted(planted)
    assert names == ["bandit"], names
    assert opt_in_module_for(names[0]) is None


def test_a_planted_cell_naming_an_opt_in_scanner_passes() -> None:
    """The must-not-flag control: the same shape naming hadolint is admitted."""
    names = scanners_asserted(_PLANTED_UNIX.replace("bandit", "hadolint"))
    assert names == ["hadolint"]
    assert opt_in_module_for(names[0])
