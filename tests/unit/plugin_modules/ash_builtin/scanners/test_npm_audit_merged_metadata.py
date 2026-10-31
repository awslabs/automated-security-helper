# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Merging several lockfiles' audit metadata must combine, never raise or overwrite.

npm 7+ counts its dependencies in a dict (``"dependencies": {"prod": 1, ...}``)
where pnpm's v1 report counts them in four integers: ``"dependencies": 5`` is the
PRODUCTION count, with ``devDependencies``, ``optionalDependencies`` and
``totalDependencies`` beside it. The merge read the incoming value's type alone:
a dict was ``update``d into whatever was there, a number was ``+=``d onto it.
With one lockfile of each kind in a scan the second merge raised (``dict.update``
on an integer, ``int += dict``), the raise was recorded as a failed audit, and
two valid reports failed the whole scan. Keeping the first of the pair instead
made the saved shape depend on the walk order: pnpm's count was dropped, or a
bare integer stood where the map's readers look for ``["dependencies"]["total"]``.
Reading the integer as the map's ``total`` merged the two, but counted pnpm's
production dependencies as its total (its dev and optional counts gone), left
pnpm out of ``prod``, and kept the other three integers as top-level keys beside
the map, two "total" counts in one document. The four v1 integers are read into
npm's map first (``prod``, ``dev``, ``optional``, ``total``), so the two merge
whichever lockfile comes first, key for key.

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
    # Each side's counts combine key for key: pnpm's four v1 integers are read
    # into npm's map, so the saved shape is the map whichever lockfile came
    # first, and no v1 integer is left beside it.
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
    # The fixture's v1 counts: dependencies (production) 5, devDependencies 0,
    # optionalDependencies 0, totalDependencies 5.
    assert pnpm_metadata["dependencies"] == 5
    assert pnpm_metadata["totalDependencies"] == 5
    assert metadata["dependencies"] == {
        "prod": 3 + pnpm_metadata["dependencies"],
        "dev": pnpm_metadata["devDependencies"],
        "optional": pnpm_metadata["optionalDependencies"],
        "peer": 0,
        "peerOptional": 0,
        "total": 3 + pnpm_metadata["totalDependencies"],
    }, metadata["dependencies"]
    for v1_key in ("devDependencies", "optionalDependencies", "totalDependencies"):
        assert v1_key not in metadata, metadata


def _saved_metadata(scanner) -> dict:
    return json.loads(
        scanner.results_dir.joinpath("converted", "results.json").read_text()
    )["metadata"]


def test_a_single_pnpm_lockfile_saves_the_dependency_counts_as_the_map(plugin_context):
    """The v1 integers were read into npm's map only when a second lockfile was
    merged; the first report became the saved results as it came, so a scan of
    one pnpm lockfile wrote ``"dependencies": 5`` and three integers beside it,
    where the merge's own docstring (and every reader of
    ``["dependencies"]["total"]``) expects the map."""
    pnpm = json.loads(PNPM_CAPTURE.read_text(encoding="utf-8"))
    _package(plugin_context.work_dir / "web", "pnpm-lock.yaml")

    scanner, _ = _scan(
        plugin_context,
        {
            "pnpm": {
                "stdout": pnpm["stdout"],
                "stderr": pnpm["stderr"],
                "returncode": pnpm["returncode"],
            },
        },
    )

    assert scanner.errors == [], scanner.errors
    metadata = _saved_metadata(scanner)
    assert metadata["dependencies"] == {
        "prod": 5,
        "dev": 0,
        "optional": 0,
        "total": 5,
    }, metadata
    for v1_key in ("devDependencies", "optionalDependencies", "totalDependencies"):
        assert v1_key not in metadata, metadata


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
    # The saved shape is the same in both orders: the map, with both sides'
    # counts in it, and the severity counters summed. A "keep the first value"
    # merge raises nothing, so the assertions above held for it in both orders;
    # these do not.
    metadata = _saved_metadata(scanner)
    pnpm_metadata = json.loads(pnpm["stdout"])["metadata"]
    assert isinstance(metadata["dependencies"], dict), metadata
    assert metadata["dependencies"]["prod"] == 3 + pnpm_metadata["dependencies"]
    assert metadata["dependencies"]["total"] == (3 + pnpm_metadata["totalDependencies"])
    counters = metadata["vulnerabilities"]
    assert counters["high"] == 1 + pnpm_metadata["vulnerabilities"]["high"]
    assert counters["total"] == sum(
        counters[name] for name in ("info", "low", "moderate", "high", "critical")
    ), counters


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
    """The unit itself: dicts recurse, numbers add, lists join, a v1 report's
    dependency integers are read into the map by key (``dependencies`` is the
    production count, not the total), the rest keeps the first value, and a
    bool is never added as a number."""
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
            "devDependencies": 1,
            "optionalDependencies": 0,
            "totalDependencies": 6,
        },
        "pnpm-lock.yaml",
    )

    assert into == {
        "vulnerabilities": {"high": 3, "moderate": 1, "total": 4},
        "dependencies": {"prod": 7, "dev": 1, "optional": 0, "total": 8},
        "flags": ["a", "b"],
        "ok": True,
        "note": "first",
    }, into


def test_a_v1_report_s_dependency_counts_are_read_into_the_map():
    """The reading itself, on the captured pnpm report: the four integers
    become npm's map, the rest of the metadata is kept, and a metadata dict
    already in npm's shape comes back as the same object."""
    pnpm = json.loads(PNPM_CAPTURE.read_text(encoding="utf-8"))
    v1 = json.loads(pnpm["stdout"])["metadata"]
    assert v1["dependencies"] == 5 and v1["totalDependencies"] == 5

    shaped = NpmAuditScanner._npm_dependency_counts(v1)

    assert shaped["dependencies"] == {"prod": 5, "dev": 0, "optional": 0, "total": 5}
    assert shaped["vulnerabilities"] == v1["vulnerabilities"]
    for v1_key in ("devDependencies", "optionalDependencies", "totalDependencies"):
        assert v1_key not in shaped, shaped
    npm_shaped = _npm_report(high=1, moderate=0, prod=3)["metadata"]
    assert NpmAuditScanner._npm_dependency_counts(npm_shaped) is npm_shaped


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


def test_merge_metadata_reads_a_v1_report_s_counts_into_the_map_when_a_dict_arrives():
    """The other direction of the npm/pnpm pair: pnpm's v1 integers were merged
    first, and npm's dict arrives second. ``int.update`` raised here, and
    keeping the integer left a reader of ``["dependencies"]["total"]`` with a
    TypeError whenever pnpm's lockfile was walked first. The merged side is
    read into the map before the dict is folded in, key for key. The
    vulnerability counters come back with a recounted ``total`` beside them:
    the merge recounts it from the severity counters once any counter is
    present."""
    into = {
        "dependencies": 5,
        "devDependencies": 1,
        "optionalDependencies": 0,
        "totalDependencies": 6,
        "vulnerabilities": {"high": 3},
    }

    NpmAuditScanner._merge_metadata(
        into,
        {
            "dependencies": {"prod": 2, "dev": 0, "total": 2},
            "vulnerabilities": {"high": 1},
        },
        "package-lock.json",
    )

    assert into == {
        "dependencies": {"prod": 7, "dev": 1, "optional": 0, "total": 8},
        "vulnerabilities": {"high": 4, "total": 4},
    }, into


def test_a_bare_dependency_integer_alone_is_the_production_count():
    """A v1 metadata dict whose only count is ``dependencies`` (the other three
    absent) reads as ``{"prod": 5}``: each of the four keys crosses only when it
    is present and numeric, and nothing is invented for the rest."""
    assert NpmAuditScanner._npm_dependency_counts({"dependencies": 5}) == {
        "dependencies": {"prod": 5}
    }


@pytest.mark.parametrize("integer_first", [True, False])
def test_a_bare_dependency_integer_merges_with_a_map_in_either_direction(
    integer_first,
):
    """The reading of the bare integer as ``prod`` is the same whichever side it
    arrives on, so the merged map does not depend on the walk order. The bare
    side gives no ``total``, so the merged one is recounted from the merged
    parts: keeping the map side's 2 beside a ``prod`` of 7 left a total smaller
    than one of its own parts."""
    bare = {"dependencies": 5}
    mapped = {"dependencies": {"prod": 2, "total": 2}}
    into, incoming = (bare, mapped) if integer_first else (mapped, bare)

    NpmAuditScanner._merge_metadata(into, incoming, "pnpm-lock.yaml")

    assert into == {"dependencies": {"prod": 7, "total": 7}}, into


def test_a_total_one_side_does_not_give_is_recounted_from_the_merged_parts():
    """The same shape with the gap on the v1 side: a pnpm report that carries
    ``dependencies`` and ``devDependencies`` but no ``totalDependencies`` meets
    an npm map that has a total. Adding only the map's total left it under the
    sum of the parts both sides contributed to."""
    into = {"dependencies": {"prod": 2, "dev": 1, "total": 3}}

    NpmAuditScanner._merge_metadata(
        into, {"dependencies": 4, "devDependencies": 1}, "pnpm-lock.yaml"
    )

    assert into == {"dependencies": {"prod": 6, "dev": 2, "total": 8}}, into


def test_two_totals_are_still_added_like_the_other_counts():
    """Control: when both sides give a total, the merged total is their sum,
    which is also the sum of the merged parts."""
    into = {"dependencies": {"prod": 2, "dev": 1, "total": 3}}

    NpmAuditScanner._merge_metadata(
        into,
        {"dependencies": {"prod": 4, "dev": 0, "optional": 2, "total": 6}},
        "package-lock.json",
    )

    assert into == {"dependencies": {"prod": 6, "dev": 1, "optional": 2, "total": 9}}, (
        into
    )
