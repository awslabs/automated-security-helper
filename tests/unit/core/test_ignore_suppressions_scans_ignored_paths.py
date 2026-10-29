# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--ignore-suppressions`` lifts ignore paths for every scanner.

An ignore path is a suppression. Without the flag, a file under one is not handed
to the scanners that ASH gives a file list, and a finding any scanner reports
there is dropped from the results. With the flag, every scanner reads those files
and their findings are reported.

The pre-scan step used to apply ignore paths whatever the flag said, while the
post-scan step honored it. So with the flag set, a scanner that reads the whole
directory (bandit) reported a finding under an ignore path, and a scanner that is
handed ASH's file list (detect-secrets) did not. These tests run detect-secrets
for real, in process, because it is the scanner that list decided for. bandit
needs a tool install, so the two-scanner comparison is in
tests/integration/test_ignore_suppressions_ignore_paths.py.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional, Tuple

import pytest
import yaml

from automated_security_helper.core.enums import RunMode
from automated_security_helper.interactions.run_ash_scan import run_ash_scan
from automated_security_helper.models.core import (
    IgnorePathWithReason,
    ignore_paths_that_skip_scanning,
)

pytestmark = pytest.mark.unit

# Built at runtime so this file holds no secret-shaped literal. AWS's documented
# example key, which detect-secrets reports.
PLANTED_KEY = "".join(["AKIA", "IOSFODNN7", "EXAMPLE"])  # noqa: FLY002

APP_PY = f'AWS_ACCESS_KEY_ID = "{PLANTED_KEY}"\n'

RESULTS_FILE = "ash_aggregated_results.json"


def _tree(root: Path) -> Path:
    """A checkout with one secret in app.py and an ignore path naming app.py."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "app.py").write_text(APP_PY, encoding="utf-8")
    (root / ".ash").mkdir(exist_ok=True)
    (root / ".ash" / ".ash.yaml").write_text(
        yaml.safe_dump(
            {
                "project_name": "ignore-paths",
                "global_settings": {
                    "ignore_paths": [{"path": "app.py", "reason": "test fixture"}]
                },
            }
        ),
        encoding="utf-8",
    )
    return root


def _exit_code(**kwargs) -> int:
    """Run ``run_ash_scan`` and return the status the CLI would exit with."""
    try:
        run_ash_scan(
            mode=RunMode.local,
            progress=False,
            show_summary=False,
            color=False,
            fail_on_findings=True,
            **kwargs,
        )
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


def _findings(results_path: Path, scanner: str) -> List[Tuple[str, bool]]:
    """``(uri, suppressed)`` for every SARIF result ``scanner`` reported."""
    document = json.loads(results_path.read_text(encoding="utf-8"))
    found = []
    for run in document["sarif"]["runs"]:
        for result in run.get("results") or []:
            if (result.get("properties") or {}).get("scanner_name") != scanner:
                continue
            uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            found.append((uri, bool(result.get("suppressions"))))
    return found


def _app_py_findings(results_path: Path) -> List[Tuple[str, bool]]:
    return [
        item
        for item in _findings(results_path, "detect-secrets")
        if Path(item[0]).name == "app.py"
    ]


class TestThePreScanList:
    def test_it_is_empty_under_ignore_suppressions(self):
        paths = [IgnorePathWithReason(path="app.py", reason="operator")]

        assert ignore_paths_that_skip_scanning(paths, ignore_suppressions=True) == []

    def test_it_keeps_the_operators_paths_without_the_flag(self):
        operator = IgnorePathWithReason(path="app.py", reason="operator")
        client = IgnorePathWithReason(
            path="vendor/**", reason="client", client_supplied=True
        )

        kept = ignore_paths_that_skip_scanning(
            [operator, client], ignore_suppressions=False
        )

        assert kept == [operator]


class TestASingleDirectoryScan:
    def test_without_the_flag_the_ignored_file_is_not_scanned(self, tmp_path):
        source = _tree(tmp_path / "src")
        output = tmp_path / "out"

        code = _exit_code(
            source_dir=source,
            output_dir=output,
            scanners=["detect-secrets"],
            ignore_suppressions=False,
        )

        assert code == 0
        assert _app_py_findings(output / RESULTS_FILE) == []

    def test_with_the_flag_detect_secrets_reports_the_ignored_file(self, tmp_path):
        source = _tree(tmp_path / "src")
        output = tmp_path / "out"

        code = _exit_code(
            source_dir=source,
            output_dir=output,
            scanners=["detect-secrets"],
            ignore_suppressions=True,
        )

        assert code == 2
        findings = _app_py_findings(output / RESULTS_FILE)
        assert findings, "detect-secrets reported nothing for the ignored app.py"
        assert not any(suppressed for _, suppressed in findings)


def _workspace(root: Path) -> Path:
    """A workspace whose one project is the fixture tree."""
    _tree(root / "api")
    workspace_file = root / "dev.code-workspace"
    workspace_file.write_text(
        json.dumps({"folders": [{"path": "api"}]}), encoding="utf-8"
    )
    return workspace_file


def _project_results(output: Path) -> Optional[Path]:
    matches = sorted(output.rglob(RESULTS_FILE))
    projects = [path for path in matches if path.parent != output]
    return projects[0] if projects else None


class TestAWorkspaceScan:
    """Each project is scanned by its own orchestrator, the same code path."""

    @pytest.mark.parametrize(
        ("ignore_suppressions", "expected"), [(False, 0), (True, 2)]
    )
    def test_the_flag_reaches_each_projects_pre_scan_step(
        self, tmp_path, ignore_suppressions, expected
    ):
        from automated_security_helper.workspace.resolver import resolve_workspace

        root = tmp_path / "workspace"
        workspace_file = _workspace(root)
        output = tmp_path / "out"

        code = _exit_code(
            source_dir=root,
            output_dir=output,
            workspace_plan=resolve_workspace(workspace_file),
            scanners=["detect-secrets"],
            ignore_suppressions=ignore_suppressions,
        )

        assert code == expected
        project_results = _project_results(output)
        assert project_results is not None, sorted(output.rglob("*.json"))
        findings = _app_py_findings(project_results)
        assert bool(findings) is ignore_suppressions, findings
