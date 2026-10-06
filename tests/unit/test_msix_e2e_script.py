# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Static checks on the MSIX e2e leg that keep it on the shared contract.

packaging/msix/verify-on-windows.ps1 only runs on a Windows runner, so a regression in
it surfaces one CI round trip late. These pin the parts that can be read off the files:
the leg judges its scans with the shared scripts rather than a copy, it has no fallback
to "any *.sarif", and the launcher and the script agree on the marker that records
which wheel a venv was built from. If those two drift, the upgrade check reads a line
the launcher no longer writes and fails for a reason that has nothing to do with the
upgrade.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "packaging" / "msix" / "verify-on-windows.ps1"
LAUNCHER = REPO_ROOT / "packaging" / "msix" / "AshLauncher.cs"


def _script() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def _cs_constant(name: str) -> str:
    match = re.search(
        rf'private const string {name} = "([^"]*)";',
        LAUNCHER.read_text(encoding="utf-8"),
    )
    assert match, f"AshLauncher.cs no longer declares {name}"
    return match.group(1)


def _ps_variable(name: str) -> str:
    match = re.search(rf"^\${name} = '([^']*)'$", _script(), re.MULTILINE)
    assert match, f"verify-on-windows.ps1 no longer assigns ${name}"
    return match.group(1)


def test_marker_name_and_wheel_prefix_match_the_launcher() -> None:
    assert _ps_variable("completionMarker") == _cs_constant("CompletionMarker")
    assert _ps_variable("markerWheelPrefix") == _cs_constant("MarkerWheelPrefix")


def test_the_launcher_writes_the_wheel_line_first() -> None:
    text = LAUNCHER.read_text(encoding="utf-8")
    write = text.index("Path.Combine(venvDirectory, CompletionMarker),")
    assert (
        text[write:]
        .lstrip()
        .split("\n", 2)[1]
        .strip()
        .startswith("MarkerWheelPrefix + wheelName")
    ), (
        "the marker's first line must be the wheel line the script and IsBootstrapped read"
    )


def test_all_three_cases_run_through_the_shared_runner() -> None:
    text = _script()
    assert "scripts/e2e/run_case.py" in text
    loop = re.search(r"foreach \(\$case in @\(([^)]*)\)\)", text)
    assert loop, "the scan loop over the cases is gone"
    assert {c.strip().strip("'") for c in loop.group(1).split(",")} == {
        "findings",
        "clean",
        "incomplete",
    }


def test_no_report_path_fallback() -> None:
    # assert_outcome.py requires reports/ash.sarif at exactly that path. A glob here would
    # be a second, looser verdict.
    assert "*.sarif" not in _script()


def test_cli_name_comes_from_the_shared_file() -> None:
    text = _script()
    assert "scripts/e2e/cli_name.json" in text
    assert "'ashx'" not in text and '"ashx"' not in text


def test_negative_controls_are_present() -> None:
    text = _script()
    assert "--no-fail-on-findings" in text
    assert "exit code 0 (nothing actionable), expected exactly 2" in text
    assert "New-TamperedZip" in text
    # The quoted end-of-options marker; a bare -- is eaten by PowerShell's binder.
    assert "'--' --no-fail-on-findings" in text
