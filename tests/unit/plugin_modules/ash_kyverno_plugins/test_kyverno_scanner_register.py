# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""KyvernoScanner: per-chunk exit judgment, sandbox requirements, the captured report
and the facets register row.

The captured files are in tests/test_data/scanners/kyverno/captured/ (see its README).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.base.scanner_facets import (
    FACET_NAMES,
    SCANNER_FACETS_ATTR,
    FacetState,
    ScannerFacets,
)
from automated_security_helper.base.scanner_operational_facets import (
    OPERATIONAL_FACETS_ATTR,
    ScannerOperationalFacets,
)
from automated_security_helper.core.enums import OfflineStrategy
from automated_security_helper.plugin_modules.ash_kyverno_plugins import (
    kyverno_scanner as ks,
)
from automated_security_helper.plugin_modules.ash_kyverno_plugins.kyverno_scanner import (
    KyvernoScanner,
    ManifestIndex,
    convert_report_results,
    parse_policy_report_output,
)
from automated_security_helper.utils.sandbox.policy import SandboxRequirements

from .test_kyverno_scanner_behavior import (  # noqa: F401  (fixtures)
    CLEAN_REPORT,
    CLUSTER_REPORT,
    _run,
    _scanner,
    on_path,
    tree,
)

pytestmark = pytest.mark.unit

_CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "kyverno"
    / "captured"
)
_REPORT = _CAPTURED / "kyverno-1.19.2-high.report.yaml"
_SARIF = _CAPTURED / "kyverno-1.19.2-high.sarif"


class FoldingKyverno:
    """Stands in for _run_subprocess the way the base behaves: every run's code is
    folded into the worst code seen, and the response carries the run's own code."""

    def __init__(self, runs: List[tuple]):
        self.runs = list(runs)
        self.calls: List[List[str]] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, timeout=None, **kwargs):
            self.calls.append(list(command))
            stdout, code = self.runs[len(self.calls) - 1]
            scanner.exit_code = scanner._worse_exit_code(scanner.exit_code, code)
            return {"returncode": code, "stdout": stdout, "stderr": ""}

        return run


@pytest.mark.usefixtures("on_path")
class TestEachChunkIsJudgedOnItsOwnExitCode:
    def test_a_clean_chunk_after_a_violating_chunk_is_not_a_failed_load(
        self, request, tmp_path, monkeypatch
    ):
        # One manifest per command line: the first chunk finds the violation and
        # exits 1; the second is clean and exits 0 with no results to print.
        monkeypatch.setattr(ks, "_MAX_COMMAND_LINE_CHARS", 1)
        scanner = _scanner(
            request.getfixturevalue("tree"), tmp_path, policy_paths=["policies"]
        )
        fake = FoldingKyverno([(CLUSTER_REPORT, 1), ("", 0)])
        report = _run(scanner, fake, monkeypatch)
        assert len(fake.calls) == 2
        assert len(report.get_all_results()) == 1

    def test_a_chunk_that_exits_one_without_a_report_still_fails_the_scan(
        self, request, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(ks, "_MAX_COMMAND_LINE_CHARS", 1)
        scanner = _scanner(
            request.getfixturevalue("tree"), tmp_path, policy_paths=["policies"]
        )
        fake = FoldingKyverno([(CLEAN_REPORT, 0), ("", 1)])
        from automated_security_helper.core.exceptions import ScannerError

        with pytest.raises(ScannerError, match="without printing a report"):
            _run(scanner, fake, monkeypatch)


class TestSandboxRequirements:
    def test_the_scanner_declares_the_strict_default(self):
        assert KyvernoScanner.sandbox_requirements == SandboxRequirements()

    def test_no_network_no_env_no_extra_paths(self):
        requirements = KyvernoScanner.sandbox_requirements
        assert requirements.network is False
        assert requirements.network_requires_grant is False
        assert tuple(requirements.env_prefixes) == ()
        assert tuple(requirements.env_names) == ()
        assert tuple(requirements.read_paths) == ()
        assert tuple(requirements.cache_paths) == ()

    def test_the_offline_strategy_agrees_with_the_missing_network_grant(self):
        assert KyvernoScanner.offline_strategy is OfflineStrategy.BUNDLED


def _captured_report_results() -> List[Dict[str, Any]]:
    return parse_policy_report_output(_REPORT.read_text(encoding="utf-8"))


def _captured_index() -> ManifestIndex:
    index = ManifestIndex()
    index.add(
        {
            "kind": "Pod",
            "metadata": {"name": "bad-pod", "namespace": "default"},
        },
        "k8s/bad.yaml",
        1,
    )
    return index


class TestCapturedReport:
    def test_the_capture_has_the_one_failed_result_the_readme_says(self):
        results = _captured_report_results()
        assert [(r["result"], r["severity"]) for r in results] == [
            ("fail", "high"),
            ("pass", "high"),
        ]

    def test_high_maps_to_a_high_error_finding_at_the_manifest_line(self):
        results, rules, failed = convert_report_results(
            _captured_report_results(), _captured_index()
        )
        assert failed == []
        (result,) = results
        assert result.ruleId == "require-team-label/check-team-label"
        assert str(getattr(result.level, "value", result.level)) == "error"
        dumped_props = json.loads(
            result.model_dump_json(exclude_none=True, by_alias=True)
        )["properties"]
        assert dumped_props["issue_severity"] == "HIGH"
        dumped = json.loads(result.model_dump_json(exclude_none=True, by_alias=True))
        physical = dumped["locations"][0]["physicalLocation"]
        assert physical["artifactLocation"]["uri"] == "k8s/bad.yaml"
        assert physical["region"]["startLine"] == 1
        assert [r.id for r in rules] == ["require-team-label/check-team-label"]

    def test_the_committed_sarif_is_what_the_adapter_makes_of_the_capture(self):
        results, _, _ = convert_report_results(
            _captured_report_results(), _captured_index()
        )
        committed = json.loads(_SARIF.read_text(encoding="utf-8"))
        committed_results = committed["runs"][0]["results"]
        made = [
            json.loads(r.model_dump_json(exclude_none=True, by_alias=True))
            for r in results
        ]
        assert made == committed_results
        assert len(committed_results) == 1


class TestFacetsRegisterRow:
    def test_the_scanner_declares_both_rows_in_its_own_class_dict(self):
        assert isinstance(vars(KyvernoScanner)[SCANNER_FACETS_ATTR], ScannerFacets)
        assert isinstance(
            vars(KyvernoScanner)[OPERATIONAL_FACETS_ATTR], ScannerOperationalFacets
        )
        assert KyvernoScanner.operational_facets.scanner_name == "kyverno"

    def test_every_facet_is_classified(self):
        row = vars(KyvernoScanner)[SCANNER_FACETS_ATTR]
        assert [getattr(row, name).state for name in FACET_NAMES]

    def test_the_cells_the_adapter_fills_are_mapped(self):
        row = vars(KyvernoScanner)[SCANNER_FACETS_ATTR]
        for name in (
            "rule_id",
            "severity",
            "file_path",
            "line_range",
            "message",
            "fingerprints",
            "tags",
        ):
            assert getattr(row, name).state is FacetState.MAPPED, name

    def test_no_resource_id_is_claimed_while_the_adapter_writes_none(self):
        # The report names the object (kind, namespace, name), so the cell is not
        # N/A: it is carried natively and discarded by the adapter, which is DROPPED,
        # and it is never MAPPED while no ash_resource_id is written.
        row = vars(KyvernoScanner)[SCANNER_FACETS_ATTR]
        assert row.resource_id.state is FacetState.DROPPED
        assert row.resource_type.state is FacetState.DROPPED
        source = Path(ks.__file__).read_text(encoding="utf-8")
        assert '"ash_resource_id"' not in source
        assert "ASH_RESOURCE_ID_KEY" not in source
