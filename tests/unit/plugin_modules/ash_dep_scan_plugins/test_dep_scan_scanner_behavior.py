# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""DepScanScanner: the invocation, the exit status and the VDR conversion.

The documents below follow the shape of a real dep-scan 6.3.2 VDR (CycloneDX 1.5
JSON with a ``vulnerabilities`` array; see the module docstring of the scanner for
where that shape was read). They are written out inline, and the expected findings
are written out by hand beside them, not derived from the code under test. The
scan() tests replace the subprocess with a fake that writes one of them where the
argv says, so they run on every platform without dep-scan, cdxgen or a database.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_dep_scan_plugins
from automated_security_helper.plugin_modules.ash_dep_scan_plugins import (
    dep_scan_scanner as ds,
)
from automated_security_helper.plugin_modules.ash_dep_scan_plugins.dep_scan_scanner import (
    DepScanScanner,
    DepScanScannerConfig,
    DepScanScannerConfigOptions,
    convert_vdr,
    rate_vulnerability,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.config_trust import record_provenance
from automated_security_helper.utils.sandbox.policy import SandboxRequirements

pytestmark = pytest.mark.unit

_LOG4J = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar"
_NETTY = "pkg:maven/io.netty/netty-codec-http2@4.1.94.Final?type=jar"
_LODASH = "pkg:npm/lodash@4.17.20"
_REQUESTS = "pkg:pypi/requests@2.19.0"
_OLD = "pkg:pypi/oldlib@0.1"


def _vuln(
    vuln_id: str,
    ref: str,
    ratings: Optional[List[Dict[str, Any]]],
    *,
    installed: str,
    fixed: Optional[str] = None,
    description: str = "",
    insights: str = "Direct dependency",
) -> Dict[str, Any]:
    versions = [{"version": installed, "status": "affected"}]
    if fixed:
        versions.append({"version": fixed, "status": "unaffected"})
    entry: Dict[str, Any] = {
        "bom-ref": f"{vuln_id}/{ref}",
        "id": vuln_id,
        "source": {},
        "cwes": [400],
        "description": description,
        "recommendation": f"Update to {fixed} or later" if fixed else "",
        "advisories": [],
        "analysis": {"state": "in_triage", "detail": "Dependency Tree: []"},
        "affects": [{"ref": ref, "versions": versions}],
        "properties": [
            {"name": "depscan:insights", "value": insights},
            {"name": "depscan:prioritized", "value": "false"},
        ],
    }
    if ratings is not None:
        entry["ratings"] = ratings
    return entry


def _component(
    purl: str, name: str, version: str, group: Optional[str] = None, **extra: Any
) -> Dict[str, Any]:
    component: Dict[str, Any] = {
        "name": name,
        "version": version,
        "purl": purl,
        "bom-ref": purl,
        "type": "library",
    }
    if group:
        component["group"] = group
    component.update(extra)
    return component


def _src_file(value: str) -> Dict[str, Any]:
    return {"properties": [{"name": "SrcFile", "value": value}]}


def _document(
    vulns: List[Dict[str, Any]], components: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {},
        "components": components or [],
        "dependencies": [],
        "vulnerabilities": vulns,
    }


def _positive() -> Dict[str, Any]:
    return _document(
        [
            _vuln(
                "CVE-2021-44228",
                _LOG4J,
                [
                    {"score": 7.5, "severity": "high", "method": "CVSSv31"},
                    {"score": 10.0, "severity": "critical", "method": "CVSSv31"},
                ],
                installed="2.14.1",
                fixed="2.17.1",
                description="# Remote code execution in log4j-core\nJNDI lookups...",
                insights="Reachable and Exploitable",
            ),
            _vuln(
                "GHSA-qppj-fm5r-hxr3",
                _NETTY,
                [{"score": 7.5, "severity": "high", "method": "CVSSv31"}],
                installed="4.1.94.Final",
                fixed="4.1.100.Final",
                description="HTTP/2 Rapid Reset",
            ),
            _vuln(
                "CVE-2020-8203",
                _LODASH,
                [{"score": 5.0, "severity": "medium", "method": "CVSSv31"}],
                installed="4.17.20",
            ),
            _vuln(
                "CVE-2018-18074",
                _REQUESTS,
                [{"score": 3.1, "severity": "low", "method": "CVSSv31"}],
                installed="2.19.0",
            ),
            _vuln("CVE-2019-0001", _OLD, None, installed="0.1"),
        ],
        [
            _component(
                _LOG4J,
                "log4j-core",
                "2.14.1",
                "org.apache.logging.log4j",
                **_src_file("services/pom.xml"),
            ),
            _component(_NETTY, "netty-codec-http2", "4.1.94.Final", "io.netty"),
            _component(_LODASH, "lodash", "4.17.20", **_src_file("web/package.json")),
            _component(_REQUESTS, "requests", "2.19.0", **_src_file("../escape.txt")),
            _component(_OLD, "oldlib", "0.1"),
        ],
    )


#: Written by hand from the document above: (ruleId, SARIF level, ASH severity, uri).
#: Two ratings give the higher one (critical, not high); the log4j and lodash
#: components carry a source file; a path with ``..`` and a component with no file
#: both fall back to the scan root; a vulnerability with no rating is MEDIUM.
POSITIVE_EXPECTED = [
    ("CVE-2021-44228", "error", "CRITICAL", "services/pom.xml"),
    ("GHSA-qppj-fm5r-hxr3", "error", "HIGH", "."),
    ("CVE-2020-8203", "warning", "MEDIUM", "web/package.json"),
    ("CVE-2018-18074", "note", "LOW", "."),
    ("CVE-2019-0001", "warning", "MEDIUM", "."),
]


def _findings(report: SarifReport) -> List[tuple]:
    out = []
    for r in report.get_all_results():
        loc = r.locations[0].physicalLocation.root
        out.append(
            (
                r.ruleId,
                getattr(r.level, "value", r.level),
                getattr(r.properties, "issue_severity", None),
                loc.artifactLocation.uri,
            )
        )
    return out


class FakeDepScan:
    """Stands in for _run_subprocess: records argv, writes VDR files."""

    def __init__(
        self,
        documents: Optional[Dict[str, Any]] = None,
        exit_code: int = 0,
        raw: Optional[Dict[str, str]] = None,
        timed_out: bool = False,
    ):
        self.documents = (
            {"sbom-universal.vdr.json": _positive()} if documents is None else documents
        )
        self.raw = raw or {}
        self.exit_code = exit_code
        self.timed_out = timed_out
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, cwd=None, **_):
            self.calls.append(
                {"argv": list(command), "env": env, "timeout": timeout, "cwd": cwd}
            )
            reports = Path(_flag(command, "--reports-dir="))
            reports.mkdir(parents=True, exist_ok=True)
            for name, document in self.documents.items():
                (reports / name).write_text(json.dumps(document), encoding="utf-8")
            for name, text in self.raw.items():
                (reports / name).write_text(text, encoding="utf-8")
            scanner.exit_code = self.exit_code
            response: Dict[str, Any] = {
                "returncode": self.exit_code,
                "stdout": "",
                "stderr": "",
            }
            if self.timed_out:
                response["timed_out"] = True
            return response

        return run

    @property
    def argv(self) -> List[str]:
        return self.calls[0]["argv"]


def _scanner(source: Path, tmp_path: Path, **options) -> DepScanScanner:
    config = get_default_config()
    record_provenance(config, in_tree=[], trusted=AshConfig())
    output = tmp_path / "out"
    return DepScanScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=config,
        ),
        config=DepScanScannerConfig(
            enabled=True, options=DepScanScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    (src / "services").mkdir(parents=True)
    (src / "services" / "pom.xml").write_text("<project/>\n")
    (src / "web").mkdir()
    (src / "web" / "package.json").write_text("{}\n")
    return src


@pytest.fixture(autouse=True)
def tools_present(monkeypatch):
    """The dependency probe is not what these tests measure; see TestDependencyCheck."""
    monkeypatch.setattr(
        DepScanScanner, "validate_plugin_dependencies", lambda self: True
    )


def _run(
    scanner: DepScanScanner,
    fake: FakeDepScan,
    monkeypatch,
    target: Optional[Path] = None,
    target_type: str = "source",
):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=Path(target or scanner.context.source_dir), target_type=target_type
    )


def _flag(argv: List[str], prefix: str) -> Optional[str]:
    for token in argv:
        if token.startswith(prefix):
            return token[len(prefix) :]
    return None


class TestCommunityPlugin:
    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert DepScanScannerConfig().enabled is True
        assert DepScanScannerConfig().name == "dep-scan"

    def test_the_builtin_config_does_not_declare_it(self):
        assert not hasattr(get_default_config().scanners, "dep-scan")
        assert not hasattr(get_default_config().scanners, "dep_scan")

    def test_the_module_exports_the_scanner(self):
        assert ash_dep_scan_plugins.ASH_SCANNERS == [DepScanScanner]
        assert ash_dep_scan_plugins.ASH_REPORTERS == []

    def test_the_scanner_is_declared_as_it_behaves(self):
        assert DepScanScanner.python_only is False
        assert DepScanScanner.success_exit_codes == {0}
        assert DepScanScanner.offline_strategy.value == "skip_offline"

    def test_the_sandbox_declares_a_network_for_the_database_download(self):
        requirements = DepScanScanner.sandbox_requirements
        assert isinstance(requirements, SandboxRequirements)
        assert requirements.network is True
        assert "$VDB_HOME" in requirements.cache_paths


class TestInvocation:
    def test_every_fixed_flag_and_the_scan_path(self, tree, tmp_path, monkeypatch):
        scanner = _scanner(tree, tmp_path)
        fake = FakeDepScan()
        _run(scanner, fake, monkeypatch)
        argv = fake.argv
        assert argv[0] == "depscan"
        for expected in (
            "--no-banner",
            "--no-suggest",
            "--no-vuln-table",
            "--quiet",
            "--fail-on-error",
            "--reachability-analyzer=FrameworkReachability",
            "--src=.",
        ):
            assert expected in argv
        assert fake.calls[0]["cwd"] is None, "the run starts in the source directory"

    def test_every_valued_option_is_one_token(self, tree, tmp_path, monkeypatch):
        """``--src .`` as two tokens would let a path be read as a flag."""
        scanner = _scanner(tree, tmp_path)
        fake = FakeDepScan()
        _run(scanner, fake, monkeypatch)
        for flag in ("--src", "--reports-dir", "--config", "--reachability-analyzer"):
            assert flag not in fake.argv
            assert _flag(fake.argv, f"{flag}=") is not None

    def test_reports_go_to_a_directory_under_the_results_directory(
        self, tree, tmp_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeDepScan()
        _run(scanner, fake, monkeypatch)
        reports = Path(_flag(fake.argv, "--reports-dir="))
        assert reports.name == ds.REPORTS_DIR_NAME
        assert reports.parent.name == "source"
        assert (tmp_path / "out") in reports.parents

    def test_the_config_is_an_empty_file_outside_the_scanned_tree(
        self, tree, tmp_path, monkeypatch
    ):
        """dep-scan reads ./.config/depscan.toml from its working directory."""
        (tree / ".config").mkdir()
        (tree / ".config" / "depscan.toml").write_text('severity = "critical"\n')
        scanner = _scanner(tree, tmp_path)
        fake = FakeDepScan()
        _run(scanner, fake, monkeypatch)
        config = Path(_flag(fake.argv, "--config="))
        assert tree.resolve() not in config.resolve().parents
        assert config.name == "depscan-empty.toml"

    @pytest.mark.parametrize(
        "forbidden",
        [
            "--severity",
            "--custom-data",
            "--report-template",
            "--bom",
            "--bom-dir",
            "--purl",
            "--server",
            "--cdxgen-server",
            "--cdxgen-args",
            "--risk-audit",
            "--vdb-image",
            "--explain",
        ],
    )
    def test_flags_that_read_the_tree_or_reach_the_network_are_never_passed(
        self, tree, tmp_path, monkeypatch, forbidden
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeDepScan()
        _run(scanner, fake, monkeypatch)
        assert not any(
            a == forbidden or a.startswith(f"{forbidden}=") for a in fake.argv
        )

    def test_the_converted_target_is_passed_as_an_absolute_path(
        self, tree, tmp_path, monkeypatch
    ):
        converted = tmp_path / "out" / "converted"
        converted.mkdir(parents=True)
        (converted / "package.json").write_text("{}\n")
        scanner = _scanner(tree, tmp_path)
        fake = FakeDepScan()
        _run(scanner, fake, monkeypatch, target=converted, target_type="converted")
        assert _flag(fake.argv, "--src=") == converted.absolute().as_posix()

    def test_the_reachability_option_is_passed_through(
        self, tree, tmp_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, reachability_analyzer="off")
        fake = FakeDepScan()
        _run(scanner, fake, monkeypatch)
        assert "--reachability-analyzer=off" in fake.argv

    def test_a_missing_target_never_reaches_the_tool(self, tree, tmp_path, monkeypatch):
        scanner = _scanner(tree, tmp_path)
        fake = FakeDepScan()
        _run(scanner, fake, monkeypatch, target=tmp_path / "nope")
        assert fake.calls == []


class TestReport:
    def test_the_positive_document_is_rated_and_located(
        self, tree, tmp_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeDepScan(), monkeypatch)
        assert _findings(report) == POSITIVE_EXPECTED

    def test_negative_control_a_clean_vdr_has_no_findings(
        self, tree, tmp_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        clean = {"sbom-universal.vdr.json": _document([])}
        report = _run(scanner, FakeDepScan(documents=clean), monkeypatch)
        assert isinstance(report, SarifReport)
        assert _findings(report) == []

    def test_a_vdr_with_no_vulnerabilities_key_is_clean(
        self, tree, tmp_path, monkeypatch
    ):
        document = _document([])
        del document["vulnerabilities"]
        scanner = _scanner(tree, tmp_path)
        report = _run(
            scanner,
            FakeDepScan(documents={"sbom-universal.vdr.json": document}),
            monkeypatch,
        )
        assert _findings(report) == []

    def test_every_vdr_in_the_directory_is_read(self, tree, tmp_path, monkeypatch):
        second = _document(
            [
                _vuln(
                    "CVE-2020-8203",
                    _LODASH,
                    [{"severity": "high"}],
                    installed="4.17.20",
                )
            ]
        )
        scanner = _scanner(tree, tmp_path)
        report = _run(
            scanner,
            FakeDepScan(
                documents={
                    "sbom-java.vdr.json": _positive(),
                    "sbom-js.vdr.json": second,
                }
            ),
            monkeypatch,
        )
        assert len(_findings(report)) == len(POSITIVE_EXPECTED) + 1

    def test_package_identity_fix_and_reachability_are_recorded(
        self, tree, tmp_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeDepScan(), monkeypatch)
        first = report.get_all_results()[0]
        properties = first.properties
        assert (
            getattr(properties, "package_name") == "org.apache.logging.log4j/log4j-core"
        )
        assert getattr(properties, "package_version") == "2.14.1"
        assert getattr(properties, "fixed_versions") == ["2.17.1"]
        assert "reachable" in properties.tags
        assert "Fixed in 2.17.1." in first.message.root.text
        assert first.partialFingerprints["depscan/v1"]

    def test_the_same_vulnerability_on_two_components_is_two_findings(self):
        document = _document(
            [
                _vuln("CVE-1", _LODASH, [{"severity": "low"}], installed="4.17.20"),
                _vuln("CVE-1", _REQUESTS, [{"severity": "low"}], installed="2.19.0"),
                _vuln("CVE-1", _REQUESTS, [{"severity": "low"}], installed="2.19.0"),
            ]
        )
        results, rules = convert_vdr(document)
        assert len(results) == 2, "an exact duplicate is reported once"
        assert list(rules) == ["CVE-1"]

    def test_an_absolute_path_inside_the_tree_is_made_relative(self, tmp_path):
        inside = tmp_path / "src" / "app" / "go.mod"
        document = _document(
            [_vuln("CVE-9", _LODASH, [{"severity": "low"}], installed="1")],
            [_component(_LODASH, "lodash", "1", **_src_file(inside.as_posix()))],
        )
        results, _ = convert_vdr(document, source_root=tmp_path / "src")
        uri = results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "app/go.mod"

    def test_an_absolute_path_outside_the_tree_is_never_named(self, tmp_path):
        document = _document(
            [_vuln("CVE-9", _LODASH, [{"severity": "low"}], installed="1")],
            [_component(_LODASH, "lodash", "1", **_src_file("/etc/passwd"))],
        )
        results, _ = convert_vdr(document, source_root=tmp_path / "src")
        uri = results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "."


class TestSeverity:
    @pytest.mark.parametrize(
        "ratings,expected",
        [
            ([{"severity": "critical"}], ("CRITICAL", "error")),
            ([{"severity": "high"}], ("HIGH", "error")),
            ([{"severity": "medium"}], ("MEDIUM", "warning")),
            ([{"severity": "low"}], ("LOW", "note")),
            ([{"severity": "info"}], ("INFO", "none")),
            ([{"severity": "none"}], ("INFO", "none")),
            ([{"severity": "Critical"}], ("CRITICAL", "error")),
            ([{"severity": "low"}, {"severity": "high"}], ("HIGH", "error")),
            ([{"severity": "unknown"}], ("MEDIUM", "warning")),
            ([{"score": 5.0}], ("MEDIUM", "warning")),
            ([], ("MEDIUM", "warning")),
            (None, ("MEDIUM", "warning")),
            ("high", ("MEDIUM", "warning")),
        ],
    )
    def test_each_rating_maps_to_one_severity_and_level(self, ratings, expected):
        assert rate_vulnerability(ratings) == expected

    def test_an_unrated_vulnerability_is_not_hidden_and_not_critical(self):
        severity, level = rate_vulnerability(None)
        assert (severity, level) == ("MEDIUM", "warning")

    def test_issue_severity_and_level_agree_on_every_result(
        self, tree, tmp_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeDepScan(), monkeypatch)
        level_of = dict(ds._SEVERITIES.values())
        for result in report.get_all_results():
            severity = result.properties.issue_severity
            assert getattr(result.level, "value", result.level) == level_of[severity]


class TestExitStatus:
    def test_zero_is_a_success_and_findings_do_not_change_it(
        self, tree, tmp_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeDepScan(exit_code=0), monkeypatch)
        assert scanner.exit_code == 0
        assert scanner._exit_code_accepted()

    @pytest.mark.parametrize("code", [1, 2, 126, 137])
    def test_any_other_exit_fails_the_scan_even_with_a_report_on_disk(
        self, tree, tmp_path, monkeypatch, code
    ):
        """Exit 1 is dep-scan's --fail-on-error abort; the VDR beside it is not graded."""
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeDepScan(exit_code=code), monkeypatch)

    def test_a_clean_exit_that_wrote_no_vdr_fails_the_scan(
        self, tree, tmp_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError, match="no \\*.vdr.json"):
            _run(scanner, FakeDepScan(documents={}), monkeypatch)

    def test_a_report_left_by_an_earlier_run_is_removed_before_the_next_one(
        self, tree, tmp_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        first = FakeDepScan()
        _run(scanner, first, monkeypatch)
        stale = Path(_flag(first.argv, "--reports-dir=")) / "sbom-universal.vdr.json"
        assert stale.exists(), "the first run left its report"
        with pytest.raises(ScannerError):
            _run(scanner, FakeDepScan(documents={}), monkeypatch)
        assert not stale.exists()

    def test_a_timeout_fails_the_scan_and_says_so(self, tree, tmp_path, monkeypatch):
        scanner = _scanner(tree, tmp_path, scan_timeout=30)
        fake = FakeDepScan(documents={}, exit_code=124, timed_out=True)
        with pytest.raises(ScannerError, match="timed out"):
            _run(scanner, fake, monkeypatch)
        assert 0 < fake.calls[0]["timeout"] <= 30

    def test_the_tools_stderr_is_not_copied_into_the_scans_errors(self, tree, tmp_path):
        scanner = _scanner(tree, tmp_path)
        scanner._process_command_response(
            {"returncode": 0, "stdout": "", "stderr": "ERROR reading PLANTED-PACKAGE"}
        )
        assert not any("PLANTED-PACKAGE" in line for line in scanner.errors)

    def test_the_failure_message_names_the_log_and_does_not_quote_it(
        self, tree, tmp_path
    ):
        scanner = _scanner(tree, tmp_path)
        scanner.exit_code = 1
        results = tmp_path / "out" / "source" / "dep-scan.sarif"
        message = scanner._describe_scan_failure(ScannerError("boom"), results)
        assert "stderr.log" in message
        assert "exit code 1" in message
        assert "not quoted" in message

    def test_a_failure_before_the_tool_started_has_no_exit_code(self, tree, tmp_path):
        scanner = _scanner(tree, tmp_path)
        message = scanner._describe_scan_failure(
            ScannerError("boom"), None, tool_started=False
        )
        assert "was not started" in message
        assert "exit code" not in message


class TestMalformedOutput:
    @pytest.mark.parametrize(
        "text",
        [
            "",
            "not json",
            '{"bomFormat": "CycloneDX", "vulnerabilities": [',
            "[]",
            '"a string"',
            "null",
            "{}",
            '{"bomFormat": "SPDX", "vulnerabilities": []}',
            '{"bomFormat": "CycloneDX", "vulnerabilities": {"id": "CVE-1"}}',
            '{"bomFormat": "CycloneDX", "vulnerabilities": ["CVE-1"]}',
            '{"bomFormat": "CycloneDX", "vulnerabilities": [{"ratings": []}]}',
            '{"bomFormat": "CycloneDX", "vulnerabilities": [{"id": "  "}]}',
        ],
    )
    def test_output_that_is_not_a_usable_vdr_fails_the_scan(
        self, tree, tmp_path, monkeypatch, text
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeDepScan(documents={}, raw={"sbom-universal.vdr.json": text})
        with pytest.raises(ScannerError):
            _run(scanner, fake, monkeypatch)

    def test_one_bad_document_fails_the_scan_even_beside_a_good_one(
        self, tree, tmp_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeDepScan(
            documents={"sbom-a.vdr.json": _positive()},
            raw={"sbom-b.vdr.json": "not json"},
        )
        with pytest.raises(ScannerError):
            _run(scanner, fake, monkeypatch)

    def test_a_mutated_capture_does_not_match_the_expectation(
        self, tree, tmp_path, monkeypatch
    ):
        """Negative control: the positive assertion depends on the severity field."""
        mutated = copy.deepcopy(_positive())
        mutated["vulnerabilities"][0]["ratings"] = [{"severity": "low"}]
        scanner = _scanner(tree, tmp_path)
        report = _run(
            scanner,
            FakeDepScan(documents={"sbom-universal.vdr.json": mutated}),
            monkeypatch,
        )
        assert _findings(report) != POSITIVE_EXPECTED


class TestDependencyCheck:
    """The class-level fixture is undone here: these tests run the real check."""

    @pytest.fixture(autouse=True)
    def real_check(self, monkeypatch):
        monkeypatch.undo()
        monkeypatch.setattr(
            DepScanScanner, "resolve_deferred_tool_version", lambda s: None
        )

    def test_missing_cdxgen_is_unsatisfied_dependencies(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(ds, "find_executable", lambda cmd: None)
        scanner = _scanner(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is False

    def test_missing_depscan_is_unsatisfied_dependencies(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(ds, "find_executable", lambda cmd: f"/fake/bin/{cmd}")
        monkeypatch.setattr(
            DepScanScanner, "_validate_uv_tool_availability", lambda self: False
        )
        monkeypatch.setattr(ds, "get_uv_tool_command", lambda name: None)
        scanner = _scanner(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is False

    def test_a_depscan_on_path_satisfies_them_without_uv(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(ds, "find_executable", lambda cmd: f"/fake/bin/{cmd}")
        monkeypatch.setattr(
            DepScanScanner, "_validate_uv_tool_availability", lambda self: False
        )
        monkeypatch.setattr(
            ds, "get_uv_tool_command", lambda name: ["/fake/bin/depscan"]
        )
        scanner = _scanner(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is True
        assert scanner.use_uv_tool is False


class TestInstall:
    def test_install_commands_cover_every_platform(self, tree, tmp_path):
        scanner = _scanner(tree, tmp_path)
        for platform, arch in [
            ("linux", "amd64"),
            ("linux", "arm64"),
            ("darwin", "amd64"),
            ("darwin", "arm64"),
            ("windows", "amd64"),
        ]:
            assert scanner.get_installation_commands(platform, arch), (
                f"no install command for {platform}/{arch}"
            )

    def test_the_install_is_the_pinned_pypi_package(self, tree, tmp_path):
        scanner = _scanner(tree, tmp_path)
        assert ds.DEP_SCAN_DEFAULT_VERSION_CONSTRAINT == "==6.3.2"
        assert len(scanner.uv_tool_install_commands) == 1
        assert "owasp-depscan==6.3.2" in scanner.uv_tool_install_commands[0]
        assert scanner.command == "depscan"

    def test_the_version_can_be_overridden_by_an_operator_constraint(
        self, tree, tmp_path
    ):
        scanner = _scanner(tree, tmp_path, tool_version=">=6.3,<7")
        assert "owasp-depscan>=6.3,<7" in scanner.uv_tool_install_commands[0]
