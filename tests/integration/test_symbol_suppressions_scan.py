# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash scan`` end to end with a suppression scoped by ``symbol``.

bandit reports B602 three times in the fixture: inside ``risky``, inside its
sibling ``also_risky``, and at module level. One suppression names ``risky``.
Only that finding may come back suppressed; the other two are the same rule in
the same file and must stay visible, which is the narrowness this feature
exists for. A second entry names a function that does not exist, and must land
in the unused-suppressions report.

The scan runs as a subprocess of the installed ``ash`` entry point, so the
config is read, validated and applied by the same code a user runs.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

FIXTURE = """\
import subprocess

CMD = "ls"

subprocess.call(CMD, shell=True)  # module level


def risky(cmd):
    return subprocess.call(cmd, shell=True)  # inside risky


def also_risky(cmd):
    return subprocess.call(cmd, shell=True)  # inside also_risky
"""


def _require_symbols_extra() -> None:
    try:
        import tree_sitter  # noqa: F401
        import tree_sitter_python  # noqa: F401
    except ImportError as exc:  # pragma: no cover - environment-dependent
        if os.environ.get("ASH_REQUIRE_SYMBOLS_EXTRA", "").strip().upper() in (
            "1",
            "YES",
            "TRUE",
        ):
            pytest.fail(
                "ASH_REQUIRE_SYMBOLS_EXTRA is set but the [symbols] extra is not "
                f"importable ({exc}). This test must run in CI, not skip."
            )
        pytest.skip(f"[symbols] extra not installed ({exc})")


def _line(marker: str) -> int:
    hits = [i for i, t in enumerate(FIXTURE.splitlines(), 1) if marker in t]
    assert len(hits) == 1
    return hits[0]


def test_symbol_suppression_in_a_real_bandit_scan(tmp_path):
    _require_symbols_extra()
    source = tmp_path / "project"
    source.mkdir()
    (source / "app.py").write_text(FIXTURE, encoding="utf-8")
    output = tmp_path / "out"
    config_path = tmp_path / "ash.yaml"
    live = {
        "rule_id": "B602",
        "path": "app.py",
        "symbol": "risky",
        "reason": "cmd is a constant at every call site",
    }
    gone = {
        "rule_id": "B602",
        "path": "app.py",
        "symbol": "deleted_function",
        "reason": "kept to prove an entry for a removed symbol is reported unused",
    }
    config_path.write_text(
        yaml.safe_dump(
            {
                "project_name": "symbol-suppression-e2e",
                "fail_on_findings": False,
                "global_settings": {"suppressions": [live, gone]},
            }
        ),
        encoding="utf-8",
    )

    ash = shutil.which("ash", path=str(Path(sys.executable).parent))
    assert ash, f"no ash entry point beside {sys.executable}"
    proc = subprocess.run(
        [
            ash,
            "scan",
            "--mode",
            "local",
            "--source-dir",
            str(source),
            "--output-dir",
            str(output),
            "--config",
            str(config_path),
            "--scanners",
            "bandit",
            "--no-progress",
            "--no-fail-on-findings",
        ],
        capture_output=True,
        text=True,
        timeout=600,
    )
    log = f"exit {proc.returncode}\nSTDOUT:\n{proc.stdout[-4000:]}\nSTDERR:\n{proc.stderr[-4000:]}"

    sarif_path = output / "reports" / "ash.sarif"
    assert sarif_path.exists(), log
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    b602 = {}
    for run in sarif["runs"]:
        for result in run.get("results", []):
            if result.get("ruleId") != "B602":
                continue
            region = result["locations"][0]["physicalLocation"]["region"]
            b602[region["startLine"]] = bool(result.get("suppressions"))

    inside = _line("# inside risky")
    sibling = _line("# inside also_risky")
    module_level = _line("# module level")
    # All three findings are present, or the assertions below prove nothing.
    assert set(b602) == {inside, sibling, module_level}, (b602, log)
    assert b602[inside] is True, log
    assert b602[sibling] is False, log
    assert b602[module_level] is False, log

    unused = json.loads(
        (output / "reports" / "ash.unused-suppressions.json").read_text(
            encoding="utf-8"
        )
    )
    assert [u.get("symbol") for u in unused["unused_suppressions"]] == [
        "deleted_function"
    ], unused
