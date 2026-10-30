# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Merging several lockfiles' audit metadata must combine, never raise or overwrite.

npm 7+ counts its dependencies in a dict (``"dependencies": {"prod": 1, ...}``)
where pnpm's v1 report counts them in an integer (``"dependencies": 5``). The merge
read the incoming value's type alone: a dict was ``update``d into whatever was
there, a number was ``+=``d onto it. With one lockfile of each kind in a scan the
second merge raised (``dict.update`` on an integer, ``int += dict``), the raise was
recorded as a failed audit, and two valid reports failed the whole scan. Keeping
the first of the pair instead made the saved shape depend on the walk order:
pnpm's count was dropped, or a bare integer stood where the map's readers look
for ``["dependencies"]["total"]``. The integer is read as the map's total, so
the two merge whichever lockfile comes first.

The per-severity ``vulnerabilities`` counters are dicts on both sides, and
``dict.update`` kept only the last lockfile's counts, so the merged run's metrics
reported one lockfile where two were audited.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    npm_audit_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScanner,
    NpmAuditScannerConfig,
)

pytestmark = pytest.mark.unit

PNPM_CAPTURE = (
    Path(__file__).resolve().parents[4]
    / "test_data"
    / "scanners"
    / "npmaudit"
    / "pnpm"
    / "vuln.json"
)


def _npm_report(high: int, moderate: int, prod: int) -> dict:
    """An npm 7+ report with ``high + moderate`` advisories against one package."""
    via = []
    for index in range(high):
        via.append(
            {
                "source": 1000 + index,
                "name": "left-pad",
                "title": f"High advisory {index}",
                "url": f"https://github.com/advisories/GHSA-high-{index:04d}",
                "severity": "high",
                "cwe": [],
                "cvss": {"score": 7.5, "vectorString": "CVSS:3.1/AV:N"},
                "range": "<1.3.0",
            }
        )
    for index in range(moderate):
        via.append(
            {
                "source": 2000 + index,
                "name": "left-pad",
                "title": f"Moderate advisory {index}",
                "url": f"https://github.com/advisories/GHSA-mod-{index:04d}",
                "severity": "moderate",
                "cwe": [],
                "cvss": {"score": 5.3, "vectorString": "CVSS:3.1/AV:N"},
                "range": "<1.3.0",
            }
        )
    return {
        "auditReportVersion": 2,
        "vulnerabilities": {
            "left-pad": {
                "name": "left-pad",
                "severity": "high" if high else "moderate",
                "isDirect": True,
                "via": via,
                "effects": [],
                "range": "<1.3.0",
                "nodes": ["node_modules/left-pad"],
                "fixAvailable": True,
            }
        },
        "metadata": {
            "vulnerabilities": {
                "info": 0,
                "low": 0,
                "moderate": moderate,
                "high": high,
                "critical": 0,
                "total": high + moderate,
            },
            "dependencies": {
                "prod": prod,
                "dev": 0,
                "optional": 0,
                "peer": 0,
                "peerOptional": 0,
                "total": prod,
            },
        },
    }


@pytest.fixture
def plugin_context(tmp_path):
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    for d in (context.source_dir, context.output_dir, context.work_dir):
        d.mkdir(parents=True)
    return context


@pytest.fixture(autouse=True)
def tools_on_path(monkeypatch, tmp_path):
    monkeypatch.setattr(
        npm_audit_scanner, "find_executable", lambda name: str(tmp_path / name)
    )


def _package(root: Path, lock_name: str) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text('{"name": "app"}\n', encoding="utf-8")
    (root / lock_name).write_text("{}\n", encoding="utf-8")


def _answers(by_binary: dict, order: list | None = None):
    """A ``_run_subprocess`` side effect answering each tool with its document.

    ``order``, when given, records the binary of each audit as it is started."""

    def _side_effect(self, command, **kwargs):
        if "--version" in command:
            return {"stdout": "10.9.4\n", "stderr": "", "returncode": 0}
        if order is not None:
            order.append(command[0])
        response = dict(by_binary[command[0]])
        self._process_command_response(response)
        return response

    return _side_effect


def _scan(context, by_binary, order: list | None = None):
    scanner = NpmAuditScanner(context=context, config=NpmAuditScannerConfig())
    with patch.object(
        NpmAuditScanner,
        "_run_subprocess",
        autospec=True,
        side_effect=_answers(by_binary, order),
    ):
        report = scanner.scan(target=context.work_dir, target_type="converted")
    return scanner, report


def test_an_npm_and_a_pnpm_lockfile_in_one_scan_both_report(plugin_context):
    """pnpm's integer ``dependencies`` meets npm's dict: the scan used to fail
    over the merge, discarding both reports' findings."""
    pnpm = json.loads(PNPM_CAPTURE.read_text(encoding="utf-8"))
    _package(plugin_context.work_dir / "api", "package-lock.json")
    _package(plugin_context.work_dir / "web", "pnpm-lock.yaml")

    scanner, report = _scan(
        plugin_context,
        {
            "npm": {
                "stdout": json.dumps(_npm_report(high=1, moderate=0, prod=3)),
                "stderr": "",
                "returncode": 1,
            },
            "pnpm": {
                "stdout": pnpm["stdout"],
                "stderr": pnpm["stderr"],
                "returncode": pnpm["returncode"],
            },
        },
    )

    assert scanner.errors == [], scanner.errors
    packages = {
        r.properties.model_extra["package_name"] for r in report.runs[0].results
    }
    assert {"left-pad", "lodash", "minimist"} <= packages, packages
    # Each side's counts combine: pnpm's one integer is read as npm's map's
    # total, so the saved shape is the map whichever lockfile came first.
    saved = json.loads(
        scanner.results_dir.joinpath("converted", "results.json").read_text()
    )
    metadata = saved["metadata"]
    pnpm_metadata = json.loads(pnpm["stdout"])["metadata"]
    vulnerabilities = pnpm_metadata["vulnerabilities"]
    assert metadata["vulnerabilities"]["high"] == 1 + vulnerabilities["high"]
    assert metadata["vulnerabilities"]["critical"] == vulnerabilities["critical"]
    # pnpm writes no total; the merged total is the sum of the merged
    # counters, not npm's own total carried over.
    merged = metadata["vulnerabilities"]
    assert merged["total"] == sum(
        merged[name] for name in ("info", "low", "moderate", "high", "critical")
    ), merged
    assert merged["total"] == 1 + sum(
        vulnerabilities.get(name, 0)
        for name in ("info", "low", "moderate", "high", "critical")
    ), merged
    assert metadata["dependencies"]["prod"] == 3
    assert metadata["dependencies"]["total"] == 3 + pnpm_metadata["dependencies"]


@pytest.mark.parametrize("first", ["npm", "pnpm"])
def test_the_merge_combines_whichever_report_comes_first(plugin_context, first):
    """The order the lockfiles are found in decides which type is merged into
    which; both orders have to survive. The converted tree is walked in the
    filesystem's order, so the walk is pinned here to list package ``a``, which
    holds ``first``'s lockfile, before ``b``, and the audits are recorded as
    they start: each case then audits in the order it is named for, instead of
    the two cases quietly repeating one order."""
    pnpm = json.loads(PNPM_CAPTURE.read_text(encoding="utf-8"))
    names = {"npm": "package-lock.json", "pnpm": "pnpm-lock.yaml"}
    second = "pnpm" if first == "npm" else "npm"
    _package(plugin_context.work_dir / "a", names[first])
    _package(plugin_context.work_dir / "b", names[second])
    walk = NpmAuditScanner._package_manifests

    def a_first(self, *args, **kwargs):
        found = walk(self, *args, **kwargs)
        return sorted(found, key=lambda m: 0 if Path(m).parent.name == "a" else 1)

    order: list = []
    with patch.object(NpmAuditScanner, "_package_manifests", a_first):
        scanner, report = _scan(
            plugin_context,
            {
                "npm": {
                    "stdout": json.dumps(_npm_report(high=1, moderate=0, prod=3)),
                    "stderr": "",
                    "returncode": 1,
                },
                "pnpm": {
                    "stdout": pnpm["stdout"],
                    "stderr": pnpm["stderr"],
                    "returncode": pnpm["returncode"],
                },
            },
            order,
        )

    assert order == [first, second], order
    assert scanner.errors == [], scanner.errors
    assert (scanner.targets_attempted, scanner.targets_failed) == (2, 0)
    assert len(report.runs[0].results) > 1


def test_merged_metrics_sum_every_lockfiles_counters(plugin_context):
    """Two npm lockfiles: the run's metrics are the sum of both reports'
    per-severity counters, not the last report's."""
    _package(plugin_context.work_dir / "a", "package-lock.json")
    _package(plugin_context.work_dir / "b", "package-lock.json")
    reports = iter(
        [
            _npm_report(high=2, moderate=1, prod=4),
            _npm_report(high=1, moderate=3, prod=6),
        ]
    )

    def _side_effect(self, command, **kwargs):
        if "--version" in command:
            return {"stdout": "10.9.4\n", "stderr": "", "returncode": 0}
        response = {"stdout": json.dumps(next(reports)), "stderr": "", "returncode": 1}
        self._process_command_response(response)
        return response

    scanner = NpmAuditScanner(context=plugin_context, config=NpmAuditScannerConfig())
    with patch.object(
        NpmAuditScanner, "_run_subprocess", autospec=True, side_effect=_side_effect
    ):
        report = scanner.scan(target=plugin_context.work_dir, target_type="converted")

    metrics = report.runs[0].properties.model_extra["metrics"]
    assert metrics == {
        "info": 0,
        "low": 0,
        "moderate": 4,
        "high": 3,
        "critical": 0,
        "total": 7,
    }, metrics
    saved = json.loads(
        scanner.results_dir.joinpath("converted", "results.json").read_text()
    )
    assert saved["metadata"]["dependencies"]["prod"] == 10
    assert saved["metadata"]["dependencies"]["total"] == 10


def test_merge_metadata_by_type():
    """The unit itself: dicts recurse, numbers add, lists join, a number that
    meets a dict is read as the dict's total, the rest keeps the first value,
    and a bool is never added as a number."""
    into = {
        "vulnerabilities": {"high": 1, "total": 1},
        "dependencies": {"prod": 2},
        "flags": ["a"],
        "ok": True,
        "note": "first",
    }
    NpmAuditScanner._merge_metadata(
        into,
        {
            "vulnerabilities": {"high": 2, "moderate": 1, "total": 3},
            "dependencies": 5,
            "flags": ["a", "b"],
            "ok": False,
            "note": "second",
            "devDependencies": 0,
        },
        "pnpm-lock.yaml",
    )

    assert into == {
        "vulnerabilities": {"high": 3, "moderate": 1, "total": 4},
        "dependencies": {"prod": 2, "total": 5},
        "flags": ["a", "b"],
        "ok": True,
        "note": "first",
        "devDependencies": 0,
    }, into


def test_merge_metadata_recounts_the_total_from_the_severity_counters():
    """npm writes a total beside its counters, pnpm writes the counters only;
    adding what both carry kept npm's total under the summed counters."""
    into = {"vulnerabilities": {"high": 1, "moderate": 0, "total": 1}}

    NpmAuditScanner._merge_metadata(
        into,
        {"vulnerabilities": {"high": 3, "critical": 3, "moderate": 4}},
        "pnpm-lock.yaml",
    )

    assert into["vulnerabilities"] == {
        "high": 4,
        "moderate": 4,
        "critical": 3,
        "total": 11,
    }, into


def test_merge_metadata_reads_an_integer_as_the_map_s_total_when_a_dict_arrives():
    """The other direction of the npm/pnpm pair: pnpm's integer was merged
    first, and npm's dict arrives second. ``int.update`` raised here, and
    keeping the integer left a reader of ``["dependencies"]["total"]`` with a
    TypeError whenever pnpm's lockfile was walked first."""
    into = {"dependencies": 5, "vulnerabilities": {"high": 3}}

    NpmAuditScanner._merge_metadata(
        into,
        {"dependencies": {"prod": 2, "total": 2}, "vulnerabilities": {"high": 1}},
        "package-lock.json",
    )

    assert into == {
        "dependencies": {"total": 7, "prod": 2},
        "vulnerabilities": {"high": 4},
    }, into
