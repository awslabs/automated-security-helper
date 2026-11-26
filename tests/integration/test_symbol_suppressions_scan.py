# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash scan`` end to end with a suppression scoped by ``symbol``.

bandit reports B602 three times in the fixture: inside ``risky``, inside its
sibling ``also_risky``, and at module level. One suppression names ``risky``.
Only that finding may come back suppressed; the other two are the same rule in
the same file and must stay visible, which is the narrowness this feature
exists for. A second entry names a function that does not exist, and must land
in the unused-suppressions report.

The fixture is scanned in three copies: ``app.py`` is locked at file scope and
``app_symbol.py`` and ``app_symbol_edit.py`` at symbol scope. After an appended
comment the file-scope suppression stops applying and the symbol-scope one does
not; after an edit inside ``risky`` the symbol-scope suppression stops too.

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

from tests.utils.helpers import checkout_env

pytestmark = pytest.mark.integration

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


#: The fixture's copies and the invalidation scope each one's risky is locked at.
FILES = {"app.py": "file", "app_symbol.py": "symbol", "app_symbol_edit.py": "symbol"}


def _line(marker: str) -> int:
    hits = [i for i, t in enumerate(FIXTURE.splitlines(), 1) if marker in t]
    assert len(hits) == 1
    return hits[0]


def _b602(sarif_path: Path) -> dict:
    """{file: {line: suppressed}} for every B602 result of the report."""
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    found: dict = {}
    for run in sarif["runs"]:
        for result in run.get("results", []):
            if result.get("ruleId") != "B602":
                continue
            location = result["locations"][0]["physicalLocation"]
            uri = location["artifactLocation"]["uri"]
            found.setdefault(uri, {})[location["region"]["startLine"]] = bool(
                result.get("suppressions")
            )
    return found


def test_symbol_suppression_in_a_real_bandit_scan(tmp_path):
    _require_symbols_extra()
    source = tmp_path / "project"
    source.mkdir()
    # app.py is locked at file scope; app_symbol.py and app_symbol_edit.py, the
    # same code, at symbol scope.
    for name in FILES:
        (source / name).write_text(FIXTURE, encoding="utf-8")
    # A symbol suppression needs its (rule_id, symbol) scope recorded on its
    # file's .ash.lock entry; the scan refuses the config otherwise. Every
    # config entry below is bound, and the key is built with lock_key, the
    # normalization `ash suppress add` and the scan's resolver share.
    from automated_security_helper.utils.ash_lock import AshLock, LockScope, lock_key

    lock = AshLock(source_dir=source)
    for name, kind in FILES.items():
        key = lock_key(name)
        assert key is not None
        lock.bind(key, LockScope("B602", "risky"), invalidation_scope=kind)
    lock.bind("app.py", LockScope("B602", "deleted_function"))
    lock.save()
    output = tmp_path / "out"
    config_path = tmp_path / "ash.yaml"
    live = [
        {
            "rule_id": "B602",
            "path": name,
            "symbol": "risky",
            "reason": "cmd is a constant at every call site",
        }
        for name in FILES
    ]
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
                "global_settings": {"suppressions": [*live, gone]},
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
        env=checkout_env(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
    )
    log = f"exit {proc.returncode}\nSTDOUT:\n{proc.stdout[-4000:]}\nSTDERR:\n{proc.stderr[-4000:]}"

    sarif_path = output / "reports" / "ash.sarif"
    assert sarif_path.exists(), log
    b602 = _b602(sarif_path)

    inside = _line("# inside risky")
    sibling = _line("# inside also_risky")
    module_level = _line("# module level")
    for name in FILES:
        found = b602.get(name, {})
        # All three findings are present, and the one inside risky is
        # suppressed in every file, or the second scan proves nothing.
        assert set(found) == {inside, sibling, module_level}, (name, b602, log)
        assert found[inside] is True, (name, log)
        assert found[sibling] is False, (name, log)
        assert found[module_level] is False, (name, log)

    unused = json.loads(
        (output / "reports" / "ash.unused-suppressions.json").read_text(
            encoding="utf-8"
        )
    )
    assert [u.get("symbol") for u in unused["unused_suppressions"]] == [
        "deleted_function"
    ], unused

    # The guarantee the lock exists for: after an edit to the locked file the
    # suppression stops applying and the finding inside `risky` comes back.
    # Under symbol scope only an edit inside `risky` does that: the same
    # appended comment leaves app_symbol.py's suppression applying.
    for name in ("app.py", "app_symbol.py"):
        (source / name).write_text(
            FIXTURE + "# edited after review\n", encoding="utf-8"
        )
    edited = FIXTURE.replace(
        "return subprocess.call(cmd, shell=True)  # inside risky",
        "return subprocess.call(cmd.strip(), shell=True)  # inside risky",
    )
    assert edited != FIXTURE
    (source / "app_symbol_edit.py").write_text(edited, encoding="utf-8")
    second_output = tmp_path / "out-after-edit"
    second = subprocess.run(
        [
            ash,
            "scan",
            "--mode",
            "local",
            "--source-dir",
            str(source),
            "--output-dir",
            str(second_output),
            "--config",
            str(config_path),
            "--scanners",
            "bandit",
            "--no-progress",
            "--no-fail-on-findings",
        ],
        env=checkout_env(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
    )
    second_log = (
        f"exit {second.returncode}\nSTDOUT:\n{second.stdout[-4000:]}"
        f"\nSTDERR:\n{second.stderr[-4000:]}"
    )
    second_sarif_path = second_output / "reports" / "ash.sarif"
    assert second_sarif_path.exists(), second_log
    after = _b602(second_sarif_path)
    assert after.get("app.py", {}).get(inside) is False, (after, second_log)
    assert after.get("app_symbol.py", {}).get(inside) is True, (after, second_log)
    assert after.get("app_symbol_edit.py", {}).get(inside) is False, (
        after,
        second_log,
    )
