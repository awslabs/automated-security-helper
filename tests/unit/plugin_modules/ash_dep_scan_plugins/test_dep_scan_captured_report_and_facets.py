# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""dep-scan over a real captured VDR: the severity rows, the facets and the sandbox.

``tests/test_data/scanners/dep-scan/captured`` holds a real VDR written by dep-scan
(see its README for where it came from and what was trimmed). The expected findings
below are written out by hand from that file, not derived from the converter. The
``positive.sarif`` beside it is the converter's own output for that VDR, which the
register's corpus gate reads; the regeneration test keeps the two equal.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict

import pytest

from automated_security_helper.base.scanner_facets import (
    FACET_NAMES,
    FacetState,
)
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.plugin_modules.ash_dep_scan_plugins.dep_scan_scanner import (
    DepScanScanner,
    convert_vdr,
    sarif_document,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.sandbox.policy import (
    SandboxRequirements,
    build_scanner_policy,
)

pytestmark = pytest.mark.unit

CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "dep-scan"
    / "captured"
)

_NETTY = "pkg:maven/io.netty/netty-codec-http2@4.1.94.Final?type=jar"
_PARSSON = "pkg:maven/org.eclipse.parsson/parsson@1.1.2?type=jar"


def _load(name: str) -> Dict[str, Any]:
    return json.loads((CAPTURED / name).read_text(encoding="utf-8"))


def _sarif(document: Dict[str, Any]) -> SarifReport:
    return SarifReport.model_validate(sarif_document(*convert_vdr(document)))


class TestCapturedReport:
    def test_the_captures_are_the_documents_the_readme_describes(self):
        positive = _load("positive.vdr.json")
        assert positive["bomFormat"] == "CycloneDX"
        assert [v["id"] for v in positive["vulnerabilities"]] == [
            "BIT-apisix-2023-44487",
            "CVE-2023-4043",
        ]
        assert _load("negative.vdr.json")["vulnerabilities"] == []

    def test_the_positive_capture_gives_the_two_findings_written_out_by_hand(self):
        results, rules = convert_vdr(_load("positive.vdr.json"))
        assert [r["ruleId"] for r in results] == [
            "BIT-apisix-2023-44487",
            "CVE-2023-4043",
        ]
        first, second = results
        assert (first["level"], first["properties"]["issue_severity"]) == (
            "error",
            "HIGH",
        )
        assert (second["level"], second["properties"]["issue_severity"]) == (
            "error",
            "HIGH",
        )
        assert first["properties"]["package_name"] == "io.netty/netty-codec-http2"
        assert first["properties"]["package_version"] == "4.1.94.Final"
        assert first["properties"]["purl"] == _NETTY
        assert first["properties"]["fixed_versions"] == ["4.1.100.Final"]
        assert first["properties"]["fix_available"] is True
        assert first["properties"]["tags"] == [
            "vulnerability",
            "dependency",
            "CWE-400",
        ]
        assert second["properties"]["package_name"] == "org.eclipse.parsson/parsson"
        assert second["properties"]["purl"] == _PARSSON
        assert second["properties"]["tags"][-1] == "CWE-834"
        assert "Fixed in 1.1.4." in second["message"]["text"]
        # The captured BOM records no file for these components: the scan root.
        for result in results:
            uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            assert uri == "."
        # Only the osv-served id gets a help link; BIT- ids have none.
        assert "helpUri" not in rules["BIT-apisix-2023-44487"]
        assert (
            rules["CVE-2023-4043"]["helpUri"]
            == "https://osv.dev/vulnerability/CVE-2023-4043"
        )

    def test_negative_control_the_clean_capture_has_no_findings(self):
        results, rules = convert_vdr(_load("negative.vdr.json"))
        assert results == [] and rules == {}

    @pytest.mark.parametrize(
        "word, severity, level",
        [
            ("critical", "CRITICAL", "error"),
            ("high", "HIGH", "error"),
            ("medium", "MEDIUM", "warning"),
            ("low", "LOW", "note"),
            ("info", "INFO", "none"),
            ("none", "INFO", "none"),
            ("unknown", "MEDIUM", "warning"),
        ],
    )
    def test_every_severity_row_over_the_captured_report(self, word, severity, level):
        """The capture only holds ``high`` ratings, so each other word is set on its
        real vulnerability record and the document is converted whole."""
        document = copy.deepcopy(_load("positive.vdr.json"))
        for vuln in document["vulnerabilities"]:
            vuln["ratings"][0]["severity"] = word
        results, _ = convert_vdr(document)
        assert {(r["properties"]["issue_severity"], r["level"]) for r in results} == {
            (severity, level)
        }

    def test_the_converted_capture_is_valid_sarif(self):
        report = _sarif(_load("positive.vdr.json"))
        assert len(report.runs[0].results or []) == 2

    def test_the_committed_sarif_is_what_the_converter_writes(self):
        """The corpus gate reads positive.sarif, so it must be the scanner's own output."""
        committed = _load("positive.sarif")
        assert committed == sarif_document(*convert_vdr(_load("positive.vdr.json")))
        assert committed["runs"][0]["tool"]["driver"]["name"] == "dep-scan"

    def test_negative_control_the_committed_sarif_is_not_the_clean_conversion(self):
        """The regeneration check can fail: the clean capture converts to no results."""
        clean = sarif_document(*convert_vdr(_load("negative.vdr.json")))
        assert clean["runs"][0]["results"] == []
        assert _load("positive.sarif") != clean


# ---------------------------------------------------------------------------
# The facets register against the capture
# ---------------------------------------------------------------------------

#: facet -> (flat columns, populated predicate), as the corpus consistency gate reads
#: them; facets with no flat column are not observed.
_COLUMNS = {
    "rule_id": (("rule_id",), lambda v: bool(str(v or "").strip())),
    "severity": (("severity",), lambda v: bool(str(v or "").strip())),
    "file_path": (("file_path",), lambda v: bool(str(v or "").strip())),
    "message": (("description",), lambda v: bool(str(v or "").strip())),
    "resource_id": (("resource_id",), lambda v: bool(str(v or "").strip())),
    "resource_type": (("resource_type",), lambda v: bool(str(v or "").strip())),
    "package_name": (("package_name",), lambda v: bool(str(v or "").strip())),
    "package_version": (("package_version",), lambda v: bool(str(v or "").strip())),
    "package_path": (("package_path",), lambda v: bool(str(v or "").strip())),
    "taxonomy_cve": (("cve_id",), lambda v: bool(str(v or "").strip())),
    "taxonomy_cwe": (("cwe_id",), lambda v: bool(str(v or "").strip())),
    "fix_available": (("fix_available",), lambda v: v is not None),
    "snippet": (("code_snippet",), lambda v: bool(str(v or "").strip())),
    "references": (("references",), lambda v: bool(str(v or "").strip())),
    "tags": (("tags",), lambda v: bool(str(v or "").strip())),
}


def _flat_rows():
    report = _sarif(_load("positive.vdr.json"))
    run = report.runs[0]
    return [
        FlatVulnerability.from_sarif_result(result, "dep-scan", "SCA", run)
        for result in run.results or []
    ]


class TestFacets:
    def test_the_row_is_declared_on_the_class_itself(self):
        assert "facets" in vars(DepScanScanner)
        assert "operational_facets" in vars(DepScanScanner)
        assert set(FACET_NAMES) == set(type(DepScanScanner.facets).model_fields)

    @pytest.mark.parametrize("facet", sorted(_COLUMNS))
    def test_a_declared_facet_agrees_with_the_observed_column(self, facet):
        columns, populated = _COLUMNS[facet]
        rows = _flat_rows()
        assert rows, "the capture produced no flat rows"
        count = sum(1 for row in rows if populated(*[getattr(row, c) for c in columns]))
        state = getattr(DepScanScanner.facets, facet).state
        if state is FacetState.MAPPED:
            # Not every row: the capture's first id is a Bitnami BIT- id, so only
            # the second row names a CVE, and only that id's rule carries the
            # osv.dev link the flat row reads as its reference.
            assert count > 0, f"{facet} is MAPPED but empty in the capture"
            if facet not in ("taxonomy_cve", "references"):
                assert count == len(rows), f"{facet} is MAPPED but sparse"
            else:
                assert count == 1 == len(rows) - 1, facet
        else:
            assert count == 0, f"{facet} is {state.value} but populated"

    def test_no_resource_id_is_written(self):
        for result in _sarif(_load("positive.vdr.json")).runs[0].results or []:
            bag = result.properties.model_dump() if result.properties else {}
            assert not any("resource" in key.lower() for key in bag)

    def test_the_operational_row_names_the_scanner(self):
        assert DepScanScanner.operational_facets.scanner_name == "dep-scan"
        assert DepScanScanner.operational_facets.exit_codes.success_exit_codes == tuple(
            sorted(DepScanScanner.success_exit_codes)
        )


# ---------------------------------------------------------------------------
# The sandbox declaration, through the policy every sandboxed spawn uses
# ---------------------------------------------------------------------------


@pytest.fixture
def layout(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    source = tmp_path / "src"
    source.mkdir()
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True)
    return SimpleNamespace(home=home, source=source, output=output, tmp=tmp_path)


def _policy(layout, requirements, *, offline=False):
    return build_scanner_policy(
        "dep-scan",
        requirements,
        argv0=sys.executable,
        source_dir=layout.source,
        output_dir=layout.output,
        results_dir=layout.output / "scanners" / "dep-scan",
        scan_target=layout.source,
        cwd=layout.source,
        offline=offline,
        network_scanners=None,
    )


class TestSandboxRequirements:
    def test_the_declaration_is_a_network_and_the_database_caches(self):
        declared = DepScanScanner.sandbox_requirements
        assert declared.network is True
        assert declared.network_requires_grant is False
        assert declared.cache_paths == (
            "$VDB_HOME",
            "~/.local/share/vdb",
            "~/Library/Application Support/vdb",
        )
        assert declared.env_prefixes == () and declared.env_names == ()

    def test_online_the_policy_grants_a_network_and_offline_it_does_not(self, layout):
        declared = DepScanScanner.sandbox_requirements
        assert _policy(layout, declared).network is True
        assert _policy(layout, declared, offline=True).network is False
        assert _policy(layout, SandboxRequirements()).network is False

    def test_an_existing_database_cache_is_mounted_and_a_missing_one_is_skipped(
        self, layout
    ):
        absent = _policy(layout, DepScanScanner.sandbox_requirements)
        vdb = layout.home / ".local" / "share" / "vdb"
        vdb.mkdir(parents=True)
        present = _policy(layout, DepScanScanner.sandbox_requirements)
        assert vdb.resolve() not in {p.resolve() for p in absent.cache}
        assert vdb.resolve() in {p.resolve() for p in present.cache}

    def test_no_tool_environment_is_passed_through(self, layout):
        policy = _policy(layout, DepScanScanner.sandbox_requirements)
        assert policy.filter_env(
            {"VDB_HOME": "/x", "GITHUB_TOKEN": "t", "DEPSCAN_X": "1"}
        ).keys() == {"HOME"} | set(policy.extra_env)
