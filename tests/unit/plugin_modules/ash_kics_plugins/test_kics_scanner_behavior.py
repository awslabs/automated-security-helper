# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""KicsScanner: the invocation, the severity mapping, the exit status and the install.

The report tests read output shaped like what KICS v2.1.20 (the pinned release)
wrote for a one-file Terraform tree that declares a public-read S3 bucket
(``kics scan --report-formats=json,sarif --output-name=kics``). The SARIF and JSON
documents below are that output with the taxonomies, relationships and help links
removed; the expected findings are written out by hand from it, not derived from the
code under test. The scan() tests replace the subprocess with a fake that serves
those documents, so they run on every platform without the binary.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import OfflineStrategy
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_kics_plugins
from automated_security_helper.plugin_modules.ash_kics_plugins import (
    kics_scanner as ks,
)
from automated_security_helper.plugin_modules.ash_kics_plugins.kics_scanner import (
    KicsScanner,
    KicsScannerConfig,
    KicsScannerConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.sandbox.policy import SandboxRequirements

pytestmark = pytest.mark.unit

#: (query id, name, KICS severity, rule level in the SARIF, kind in the SARIF, line).
#: The five queries KICS v2.1.20 reported for the captured tree, in its order.
CAPTURED_QUERIES = [
    (
        "38c5ee0d-7f22-4260-ab72-5073048df100",
        "S3 Bucket ACL Allows Read Or Write to All Users",
        "CRITICAL",
        "error",
        "fail",
        3,
    ),
    (
        "f861041c-8c9f-4156-acfc-5e6e524f5884",
        "S3 Bucket Logging Disabled",
        "MEDIUM",
        "warning",
        "fail",
        1,
    ),
    (
        "568a4d22-3517-44a6-a7ad-6a7eed88722c",
        "S3 Bucket Without Versioning",
        "MEDIUM",
        "warning",
        "fail",
        1,
    ),
    (
        "e592a0c5-5bdb-414c-9066-5dba7cdea370",
        "IAM Access Analyzer Not Enabled",
        "LOW",
        "note",
        "fail",
        1,
    ),
    (
        "e38a8e0a-b88b-4902-b3fe-b0fcb17d5c10",
        "Resource Not Using Tags",
        "INFO",
        "none",
        "informational",
        1,
    ),
]

#: What the positive capture must produce: (ruleId, SARIF level, ASH severity, uri, line).
POSITIVE_EXPECTED = [
    ("38c5ee0d-7f22-4260-ab72-5073048df100", "error", "CRITICAL", "main.tf", 3),
    ("f861041c-8c9f-4156-acfc-5e6e524f5884", "warning", "MEDIUM", "main.tf", 1),
    ("568a4d22-3517-44a6-a7ad-6a7eed88722c", "warning", "MEDIUM", "main.tf", 1),
    ("e592a0c5-5bdb-414c-9066-5dba7cdea370", "note", "LOW", "main.tf", 1),
    ("e38a8e0a-b88b-4902-b3fe-b0fcb17d5c10", "none", "INFO", "main.tf", 1),
]


def _sarif_document(queries=CAPTURED_QUERIES, uri: str = "main.tf") -> Dict[str, Any]:
    """The SARIF KICS writes: levels on the rules, none on the results."""
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "KICS",
                        "version": "2.1.20",
                        "fullName": "Keeping Infrastructure as Code Secure",
                        "informationUri": "https://www.kics.io/",
                        "rules": [
                            {
                                "id": query_id,
                                "name": name,
                                "shortDescription": {"text": name},
                                "defaultConfiguration": {"level": level},
                            }
                            for query_id, name, _sev, level, _kind, _line in queries
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": query_id,
                        "ruleIndex": index,
                        "kind": kind,
                        "message": {
                            "text": "a captured message",
                            "properties": {"platform": "Terraform"},
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": uri},
                                    "region": {"startLine": line},
                                }
                            }
                        ],
                    }
                    for index, (query_id, _n, _s, _lv, kind, line) in enumerate(queries)
                ],
            }
        ],
    }


def _json_document(queries=CAPTURED_QUERIES) -> Dict[str, Any]:
    """The part of KICS' JSON report ASH reads: each query's id and severity."""
    return {
        "kics_version": "2.1.20",
        "files_scanned": 1,
        "queries": [
            {"query_id": query_id, "query_name": name, "severity": severity}
            for query_id, name, severity, _lv, _k, _ln in queries
        ],
    }


NEGATIVE_SARIF = _sarif_document(queries=[])
NEGATIVE_JSON = _json_document(queries=[])


def _findings(report: SarifReport) -> List[tuple]:
    """(ruleId, SARIF level, ASH severity, uri, line) for every result, in order."""
    out = []
    for r in report.get_all_results():
        loc = r.locations[0].physicalLocation.root
        out.append(
            (
                r.ruleId,
                getattr(r.level, "value", r.level),
                getattr(r.properties, "issue_severity", None),
                loc.artifactLocation.uri,
                loc.region.startLine,
            )
        )
    return out


class FakeKics:
    """Stands in for _run_subprocess: records argv, writes the two reports."""

    def __init__(
        self,
        sarif: Optional[Dict[str, Any]] | str = None,
        json_report: Optional[Dict[str, Any]] | str = None,
        exit_code: int = 0,
        write_sarif: bool = True,
        write_json: bool = True,
        timed_out: bool = False,
        stderr: str = "",
    ):
        self.sarif = _sarif_document() if sarif is None else sarif
        self.json_report = _json_document() if json_report is None else json_report
        self.exit_code, self.timed_out, self.stderr = exit_code, timed_out, stderr
        self.write_sarif, self.write_json = write_sarif, write_json
        self.calls: List[Dict[str, Any]] = []

    @staticmethod
    def _text(value: Any) -> str:
        return value if isinstance(value, str) else json.dumps(value)

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, cwd=None, **_):
            self.calls.append(
                {"argv": list(command), "env": env, "timeout": timeout, "cwd": cwd}
            )
            out = Path(_flag(command, "--output-path="))
            out.mkdir(parents=True, exist_ok=True)
            if self.write_sarif:
                (out / "kics.sarif").write_text(
                    self._text(self.sarif), encoding="utf-8"
                )
            if self.write_json:
                (out / "kics.json").write_text(
                    self._text(self.json_report), encoding="utf-8"
                )
            scanner.exit_code = self.exit_code
            return {
                "returncode": self.exit_code,
                "stdout": "",
                "stderr": self.stderr,
                "timed_out": self.timed_out,
            }

        return run

    @property
    def argv(self) -> List[str]:
        return self.calls[0]["argv"]


def _flag(argv: List[str], prefix: str) -> Optional[str]:
    """The value of the ``--flag=value`` token starting ``prefix``, or None."""
    for token in argv:
        if token.startswith(prefix):
            return token[len(prefix) :]
    return None


def _scanner(
    source: Path,
    tmp_path: Path,
    *,
    output_dir: Optional[Path] = None,
    **options,
) -> KicsScanner:
    output = output_dir or tmp_path / "out"
    return KicsScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=get_default_config(),
        ),
        config=KicsScannerConfig(
            enabled=True, options=KicsScannerConfigOptions(**options)
        ),
    )


def _run(
    scanner: KicsScanner,
    fake: FakeKics,
    monkeypatch,
    target: Optional[Path] = None,
    target_type: str = "source",
):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=Path(target or scanner.context.source_dir), target_type=target_type
    )


@pytest.fixture(autouse=True)
def no_install_table(monkeypatch):
    """The scanner builds without the download table's ``kics`` rows.

    TestPinnedRelease below exercises the real table.
    """
    monkeypatch.setattr(ks, "pinned_tool_install_commands", lambda tool: {})


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n')
    return src


@pytest.fixture
def kics_install(tmp_path, monkeypatch) -> Path:
    """A ``kics`` on PATH with the pinned assets beside it."""
    bin_dir = tmp_path / "kicsbin"
    (bin_dir / "assets" / "queries").mkdir(parents=True)
    (bin_dir / "assets" / "libraries").mkdir(parents=True)
    binary = bin_dir / "kics"
    binary.write_text("#!/bin/sh\n")
    monkeypatch.setattr(ks, "find_executable", lambda cmd: binary.as_posix())
    return bin_dir


class TestCommunityPlugin:
    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert KicsScannerConfig().enabled is True
        assert KicsScannerConfig().name == "kics"

    def test_the_builtin_config_does_not_declare_it(self):
        assert not hasattr(get_default_config().scanners, "kics")

    def test_the_module_exports_the_scanner(self):
        assert ash_kics_plugins.ASH_SCANNERS == [KicsScanner]
        assert ash_kics_plugins.ASH_REPORTERS == []

    def test_there_is_no_option_the_scanned_tree_could_use_to_hide_findings(self):
        """The queries, config and ignore handling are fixed by ASH."""
        own = set(KicsScannerConfigOptions.model_fields) - set(
            ks.ScannerOptionsBase.model_fields
        )
        assert own == set()

    def test_class_variables(self):
        assert KicsScanner.python_only is False
        assert KicsScanner.success_exit_codes == {0}
        # The enum values are lowercase, so a comparison with "UNKNOWN" could not fail.
        assert KicsScanner.offline_strategy is OfflineStrategy.BUNDLED
        assert KicsScanner.offline_strategy is not OfflineStrategy.UNKNOWN

    def test_the_sandbox_requirements_are_the_strict_default(self):
        assert KicsScanner.sandbox_requirements == SandboxRequirements()


class TestInvocation:
    def test_every_fixed_flag_and_the_scan_path(
        self, tree, tmp_path, kics_install, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeKics()
        _run(scanner, fake, monkeypatch)
        argv = fake.argv
        assert argv[:2] == ["kics", "scan"]
        for expected in (
            "--no-progress",
            "--no-color",
            "--silent",
            "--disable-secrets",
            "--ignore-on-exit=results",
            "--exclude-gitignore",
            "--report-formats=json,sarif",
            "--output-name=kics",
        ):
            assert expected in argv
        # The source target is "." from the source dir (the working directory).
        assert argv[-1] == "--path=."
        assert fake.calls[0]["cwd"] is None, "the run starts in the source directory"

    def test_every_option_is_one_token(self, tree, tmp_path, kics_install, monkeypatch):
        """A value in its own token would be read as the next flag or a path."""
        scanner = _scanner(tree, tmp_path)
        fake = FakeKics()
        _run(scanner, fake, monkeypatch)
        assert all(a.startswith("--") for a in fake.argv[2:])

    @pytest.mark.parametrize(
        "forbidden",
        [
            "--terraform-vars-path",
            "--secrets-regexes-path",
            "--input-data",
            "--payload-path",
            "--enable-openapi-refs",
            "--include-queries",
            "--exclude-queries",
            "--exclude-results",
            "--exclude-severities",
            "--fail-on",
        ],
    )
    def test_flags_that_read_the_tree_or_reach_the_network_are_never_passed(
        self, tree, tmp_path, kics_install, monkeypatch, forbidden
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeKics()
        _run(scanner, fake, monkeypatch)
        assert not any(
            a == forbidden or a.startswith(f"{forbidden}=") for a in fake.argv
        )

    def test_the_config_is_an_empty_stub_outside_the_tree(
        self, tree, tmp_path, kics_install, monkeypatch
    ):
        """KICS loads a kics.config from the scanned directory unless told a config."""
        (tree / "kics.config").write_text('{"exclude-paths": ["main.tf"]}')
        scanner = _scanner(tree, tmp_path)
        fake = FakeKics()
        _run(scanner, fake, monkeypatch)
        stub = Path(_flag(fake.argv, "--config="))
        assert stub.read_text(encoding="utf-8").strip() == "{}"
        assert not stub.resolve().is_relative_to(tree.resolve())

    def test_the_queries_come_from_the_assets_beside_the_binary(
        self, tree, tmp_path, kics_install, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeKics()
        _run(scanner, fake, monkeypatch)
        assert (
            _flag(fake.argv, "--queries-path=")
            == (kics_install / "assets" / "queries").as_posix()
        )
        assert (
            _flag(fake.argv, "--libraries-path=")
            == (kics_install / "assets" / "libraries").as_posix()
        )

    def test_the_share_directory_layout_is_found_too(
        self, tree, tmp_path, kics_install, monkeypatch
    ):
        root = tmp_path / "prefix"
        (root / "bin").mkdir(parents=True)
        (root / "share" / "kics" / "assets" / "queries").mkdir(parents=True)
        (root / "share" / "kics" / "assets" / "libraries").mkdir(parents=True)
        (root / "bin" / "kics").write_text("#!/bin/sh\n")
        monkeypatch.setattr(
            ks, "find_executable", lambda cmd: (root / "bin" / "kics").as_posix()
        )
        scanner = _scanner(tree, tmp_path)
        fake = FakeKics()
        _run(scanner, fake, monkeypatch)
        assert (
            _flag(fake.argv, "--queries-path=")
            == (root / "share" / "kics" / "assets" / "queries").as_posix()
        )

    def test_a_binary_with_no_assets_fails_the_scan_and_says_why(
        self, tree, tmp_path, monkeypatch
    ):
        bare = tmp_path / "bare"
        bare.mkdir()
        (bare / "kics").write_text("#!/bin/sh\n")
        monkeypatch.setattr(
            ks, "find_executable", lambda cmd: (bare / "kics").as_posix()
        )
        scanner = _scanner(tree, tmp_path)
        fake = FakeKics()
        with pytest.raises(ScannerError, match="queries"):
            _run(scanner, fake, monkeypatch)
        assert fake.calls == []

    def test_an_absent_binary_never_reaches_the_tool(self, tree, tmp_path, monkeypatch):
        """The base scan() stops at the dependency check, so nothing is started."""
        monkeypatch.setattr(ks, "find_executable", lambda cmd: None)
        scanner = _scanner(tree, tmp_path)
        fake = FakeKics()
        assert _run(scanner, fake, monkeypatch) is False
        assert fake.calls == []

    def test_the_assets_lookup_names_a_missing_binary(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(ks, "find_executable", lambda cmd: None)
        with pytest.raises(ScannerError, match="not found"):
            _scanner(tree, tmp_path)._assets_dir()

    def test_the_converted_target_is_an_absolute_path(
        self, tree, tmp_path, kics_install, monkeypatch
    ):
        converted = tmp_path / "out" / "converted"
        converted.mkdir(parents=True)
        (converted / "x.tf").write_text('resource "aws_s3_bucket" "b" {}\n')
        scanner = _scanner(tree, tmp_path)
        fake = FakeKics(sarif=NEGATIVE_SARIF, json_report=NEGATIVE_JSON)
        _run(scanner, fake, monkeypatch, target=converted, target_type="converted")
        assert fake.argv[-1] == f"--path={converted.absolute().as_posix()}"

    def test_ashs_output_directory_inside_the_tree_is_excluded_by_absolute_path(
        self, tree, tmp_path, kics_install, monkeypatch
    ):
        output = tree / ".ash" / "ash_output"
        scanner = _scanner(tree, tmp_path, output_dir=output)
        fake = FakeKics()
        _run(scanner, fake, monkeypatch)
        assert f"--exclude-paths={output.absolute().as_posix()}" in fake.argv

    def test_nothing_is_excluded_when_the_output_directory_is_outside_the_tree(
        self, tree, tmp_path, kics_install, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeKics()
        _run(scanner, fake, monkeypatch)
        assert _flag(fake.argv, "--exclude-paths=") is None

    def test_a_missing_target_never_reaches_the_tool(
        self, tree, tmp_path, kics_install, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeKics()
        _run(scanner, fake, monkeypatch, target=tmp_path / "gone")
        assert fake.calls == []


class TestReport:
    def test_the_positive_capture_is_rated_per_query_and_located(
        self, tree, tmp_path, kics_install, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeKics(), monkeypatch)
        assert _findings(report) == POSITIVE_EXPECTED

    def test_negative_control_the_clean_capture_has_no_findings(
        self, tree, tmp_path, kics_install, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(
            scanner,
            FakeKics(sarif=NEGATIVE_SARIF, json_report=NEGATIVE_JSON),
            monkeypatch,
        )
        assert _findings(report) == []

    @pytest.mark.parametrize(
        "kics_severity,rule_level,ash_severity,level",
        [
            ("CRITICAL", "error", "CRITICAL", "error"),
            ("HIGH", "error", "HIGH", "error"),
            ("MEDIUM", "warning", "MEDIUM", "warning"),
            ("LOW", "note", "LOW", "note"),
            ("INFO", "none", "INFO", "none"),
            ("TRACE", "none", "INFO", "none"),
        ],
    )
    def test_every_kics_severity_row(
        self,
        tree,
        tmp_path,
        kics_install,
        monkeypatch,
        kics_severity,
        rule_level,
        ash_severity,
        level,
    ):
        """HIGH and CRITICAL share the SARIF ``error``; the JSON report tells them apart."""
        queries = [("q-1", "Q", kics_severity, rule_level, "fail", 7)]
        scanner = _scanner(tree, tmp_path)
        report = _run(
            scanner,
            FakeKics(
                sarif=_sarif_document(queries), json_report=_json_document(queries)
            ),
            monkeypatch,
        )
        assert _findings(report) == [("q-1", level, ash_severity, "main.tf", 7)]

    def test_level_and_severity_agree_on_every_result(
        self, tree, tmp_path, kics_install, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeKics(), monkeypatch)
        expected = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "INFO": "none",
        }
        for result in report.get_all_results():
            severity = result.properties.issue_severity
            assert getattr(result.level, "value", result.level) == expected[severity]

    def test_results_are_marked_as_iac_findings_and_info_is_informational(
        self, tree, tmp_path, kics_install, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeKics(), monkeypatch)
        kinds = [getattr(r.kind, "value", r.kind) for r in report.get_all_results()]
        assert kinds == ["fail", "fail", "fail", "fail", "informational"]
        for result in report.get_all_results():
            assert "iac" in result.properties.tags

    def test_the_report_survives_a_round_trip_through_the_sarif_model(
        self, tree, tmp_path, kics_install, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeKics(), monkeypatch)
        again = SarifReport.model_validate_json(
            report.model_dump_json(exclude_none=True, by_alias=True)
        )
        assert _findings(again) == POSITIVE_EXPECTED

    @pytest.mark.parametrize(
        "broken",
        [
            pytest.param("not json", id="not-json"),
            pytest.param("[1, 2]", id="not-an-object"),
            pytest.param({"queries": "x"}, id="queries-not-a-list"),
        ],
    )
    def test_an_unreadable_json_report_rates_each_result_from_its_rule_level(
        self, tree, tmp_path, kics_install, monkeypatch, caplog, broken
    ):
        """``error`` cannot tell CRITICAL from HIGH, so it errs to CRITICAL."""
        scanner = _scanner(tree, tmp_path)
        with caplog.at_level("WARNING"):
            report = _run(scanner, FakeKics(json_report=broken), monkeypatch)
        assert [f[2] for f in _findings(report)] == [
            "CRITICAL",
            "MEDIUM",
            "MEDIUM",
            "LOW",
            "INFO",
        ]
        if isinstance(broken, str):
            assert "JSON report" in caplog.text

    def test_a_missing_json_report_falls_back_the_same_way(
        self, tree, tmp_path, kics_install, monkeypatch, caplog
    ):
        scanner = _scanner(tree, tmp_path)
        with caplog.at_level("WARNING"):
            report = _run(scanner, FakeKics(write_json=False), monkeypatch)
        assert _findings(report)[0][2] == "CRITICAL"
        assert "JSON report" in caplog.text

    def test_a_query_missing_from_the_json_report_uses_its_rule_level(
        self, tree, tmp_path, kics_install, monkeypatch
    ):
        partial = _json_document(CAPTURED_QUERIES[1:])
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeKics(json_report=partial), monkeypatch)
        # The first query is absent from the table: its rule says ``error``.
        assert _findings(report)[0][2] == "CRITICAL"
        assert _findings(report)[1][2] == "MEDIUM"

    def test_a_malformed_sarif_report_fails_the_scan(
        self, tree, tmp_path, kics_install, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeKics(sarif="this is not json"), monkeypatch)

    def test_an_empty_sarif_report_fails_the_scan(
        self, tree, tmp_path, kics_install, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeKics(sarif=""), monkeypatch)


class TestExitStatus:
    def test_zero_is_a_success_with_findings(
        self, tree, tmp_path, kics_install, monkeypatch
    ):
        """--ignore-on-exit=results makes "found something" exit 0."""
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeKics(exit_code=0), monkeypatch)
        assert scanner._exit_code_accepted()

    @pytest.mark.parametrize("code", [1, 20, 50, 60, 70, 126, 130, 137])
    def test_any_other_exit_fails_the_scan_even_with_a_report_on_disk(
        self, tree, tmp_path, kics_install, monkeypatch, code
    ):
        """126 is KICS' engine error; 20 to 60 would mean the flag was lost."""
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeKics(exit_code=code), monkeypatch)

    def test_a_run_that_wrote_no_report_fails_the_scan(
        self, tree, tmp_path, kics_install, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeKics(write_sarif=False), monkeypatch)

    def test_a_report_left_by_an_earlier_run_is_removed_before_the_next_one(
        self, tree, tmp_path, kics_install, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        first = FakeKics()
        _run(scanner, first, monkeypatch)
        out = Path(_flag(first.argv, "--output-path="))
        assert (out / "kics.sarif").exists() and (out / "kics.json").exists()
        with pytest.raises(ScannerError):
            _run(scanner, FakeKics(write_sarif=False, write_json=False), monkeypatch)
        assert not (out / "kics.sarif").exists()
        assert not (out / "kics.json").exists()

    def test_a_timeout_fails_the_scan_and_says_so(
        self, tree, tmp_path, kics_install, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, scan_timeout=17)
        fake = FakeKics(
            exit_code=124, timed_out=True, write_sarif=False, write_json=False
        )
        with pytest.raises(ScannerError, match="timed out"):
            _run(scanner, fake, monkeypatch)
        assert 0 < fake.calls[0]["timeout"] <= 17

    def test_the_tools_stderr_is_not_copied_into_the_scans_errors(
        self, tree, tmp_path, kics_install
    ):
        scanner = _scanner(tree, tmp_path)
        scanner._process_command_response(
            {
                "returncode": 0,
                "stdout": "",
                "stderr": "PLANTED-LINE from a scanned file",
            }
        )
        assert not any("PLANTED-LINE" in line for line in scanner.errors)

    def test_the_failure_message_names_the_log_and_does_not_quote_it(
        self, tree, tmp_path, kics_install
    ):
        scanner = _scanner(tree, tmp_path)
        scanner.exit_code = 126
        results = tmp_path / "out" / "source" / "kics.sarif"
        message = scanner._describe_scan_failure(ScannerError("boom"), results)
        assert "stderr.log" in message
        assert "exit code 126" in message
        assert "not quoted" in message

    def test_a_failure_before_the_tool_started_has_no_exit_code(
        self, tree, tmp_path, kics_install
    ):
        scanner = _scanner(tree, tmp_path)
        message = scanner._describe_scan_failure(
            ScannerError("boom"), None, tool_started=False
        )
        assert "was not started" in message
        assert "exit code" not in message


class TestDependencyCheck:
    def test_a_missing_binary_is_reported_not_found(self, tree, tmp_path, monkeypatch):
        monkeypatch.setattr(ks, "find_executable", lambda cmd: None)
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is False

    def test_a_binary_on_the_path_is_found(self, tree, tmp_path, kics_install):
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is True

    def test_the_install_hint_names_the_module_and_the_tool(
        self, tree, tmp_path, monkeypatch, caplog
    ):
        monkeypatch.setattr(ks, "find_executable", lambda cmd: None)
        with caplog.at_level("WARNING"):
            _scanner(tree, tmp_path).validate_plugin_dependencies()
        assert "ash_kics_plugins" in caplog.text
        assert "--tool kics" in caplog.text


def _download_rows_exist() -> bool:
    from automated_security_helper.core.exceptions import ToolNotProvisionableError
    from automated_security_helper.utils.tool_downloads import supported_platforms

    try:
        supported_platforms("kics")
    except ToolNotProvisionableError:
        return False
    return True


class TestPinnedRelease:
    """The ``kics`` rows live in ``utils/tool_downloads.py``, a shared file an
    integrator edits (see the plugin's README). The first test holds either way; the
    rest read the rows and skip, naming why, until they exist."""

    PLATFORMS = [
        ("darwin", "amd64"),
        ("darwin", "arm64"),
        ("linux", "amd64"),
        ("linux", "arm64"),
        ("windows", "amd64"),
        ("windows", "arm64"),
    ]

    @pytest.fixture(autouse=True)
    def no_install_table(self):
        """Override the module fixture: these tests read the real download table."""

    def test_the_scanner_constructs_with_or_without_the_download_rows(
        self, tree, tmp_path
    ):
        scanner = _scanner(tree, tmp_path)
        assert scanner.command == "kics"
        assert bool(scanner.custom_install_commands) is _download_rows_exist()

    def test_a_missing_download_row_is_not_an_error(self, tree, tmp_path, monkeypatch):
        from automated_security_helper.core.exceptions import (
            ToolNotProvisionableError,
        )

        def refuse(tool):
            raise ToolNotProvisionableError(f"{tool} has no release-asset table")

        monkeypatch.setattr(ks, "pinned_tool_install_commands", refuse)
        assert _scanner(tree, tmp_path).custom_install_commands == {}

    @pytest.mark.skipif(
        not _download_rows_exist(),
        reason="the kics rows in utils/tool_downloads.py are not in this tree yet",
    )
    def test_the_pin_is_a_stable_release_with_published_binaries(self):
        from automated_security_helper.utils.tool_downloads import TOOL_VERSIONS

        # v2.1.21 and later publish no binary archives.
        assert TOOL_VERSIONS["kics"] == "v2.1.20"

    @pytest.mark.skipif(
        not _download_rows_exist(),
        reason="the kics rows in utils/tool_downloads.py are not in this tree yet",
    )
    def test_install_commands_cover_every_published_platform(self):
        from automated_security_helper.utils.download_utils import (
            pinned_tool_install_commands,
        )
        from automated_security_helper.utils.tool_downloads import (
            supported_platforms,
        )

        assert sorted(tuple(p) for p in supported_platforms("kics")) == self.PLATFORMS
        table = pinned_tool_install_commands("kics")
        for platform, arch in self.PLATFORMS:
            assert table[platform][arch], f"no install command for {platform}/{arch}"


CAPTURED_DIR = (
    Path(__file__).resolve().parents[3] / "test_data" / "scanners" / "kics" / "captured"
)


class TestCapturedReports:
    """The reports a real ``kics scan`` (v2.1.20) wrote, committed as captured.

    ``captured/README.md`` records the exact argv, the tool version and how to
    refresh them. Unlike the synthetic documents above, these were not shaped by
    this test file.
    """

    def test_the_captures_exist_and_name_the_pinned_version(self):
        for name in ("positive.sarif", "positive.json", "negative.sarif"):
            assert (CAPTURED_DIR / name).is_file(), name
        assert (CAPTURED_DIR / "README.md").is_file()
        document = json.loads((CAPTURED_DIR / "positive.json").read_text("utf-8"))
        assert document["kics_version"] == "2.1.20"
        sarif = json.loads((CAPTURED_DIR / "positive.sarif").read_text("utf-8"))
        assert sarif["runs"][0]["tool"]["driver"]["version"] == "2.1.20"

    def test_the_real_positive_capture_is_rated_from_its_json_severities(
        self, tree, tmp_path, kics_install, monkeypatch
    ):
        fake = FakeKics(
            sarif=(CAPTURED_DIR / "positive.sarif").read_text("utf-8"),
            json_report=(CAPTURED_DIR / "positive.json").read_text("utf-8"),
        )
        report = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert _findings(report) == POSITIVE_EXPECTED

    def test_the_real_capture_carries_a_critical_the_sarif_level_cannot_name(self):
        """CRITICAL and HIGH are both ``error`` in the SARIF; only the JSON separates them."""
        sarif = json.loads((CAPTURED_DIR / "positive.sarif").read_text("utf-8"))
        levels = {
            rule["id"]: rule["defaultConfiguration"]["level"]
            for rule in sarif["runs"][0]["tool"]["driver"]["rules"]
        }
        assert levels["38c5ee0d-7f22-4260-ab72-5073048df100"] == "error"
        document = json.loads((CAPTURED_DIR / "positive.json").read_text("utf-8"))
        severities = {q["query_id"]: q["severity"] for q in document["queries"]}
        assert severities["38c5ee0d-7f22-4260-ab72-5073048df100"] == "CRITICAL"

    def test_negative_control_the_real_clean_capture_has_no_findings(
        self, tree, tmp_path, kics_install, monkeypatch
    ):
        fake = FakeKics(
            sarif=(CAPTURED_DIR / "negative.sarif").read_text("utf-8"),
            json_report=(CAPTURED_DIR / "negative.json").read_text("utf-8"),
        )
        report = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert _findings(report) == []

    def test_the_captured_json_holds_no_host_path(self):
        text = (CAPTURED_DIR / "positive.json").read_text("utf-8")
        assert "/run/user" not in text and "/home/" not in text


class TestFacetsDeclaration:
    def test_the_register_row_is_the_classes_own(self):
        from automated_security_helper.base.scanner_facets import (
            SCANNER_FACETS_ATTR,
            ScannerFacets,
        )
        from automated_security_helper.base.scanner_operational_facets import (
            OPERATIONAL_FACETS_ATTR,
            ScannerOperationalFacets,
        )

        assert isinstance(vars(KicsScanner)[SCANNER_FACETS_ATTR], ScannerFacets)
        ops = vars(KicsScanner)[OPERATIONAL_FACETS_ATTR]
        assert isinstance(ops, ScannerOperationalFacets)
        assert ops.scanner_name == "kics"

    def test_the_operational_row_mirrors_the_class_declarations(self):
        ops = vars(KicsScanner)["operational_facets"]
        assert ops.network.offline_strategy is KicsScanner.offline_strategy
        assert tuple(ops.exit_codes.success_exit_codes) == tuple(
            sorted(KicsScanner.success_exit_codes)
        )

    def test_the_severity_the_register_calls_mapped_is_read_from_the_json(self):
        from automated_security_helper.base.scanner_facets import FacetState

        facets = vars(KicsScanner)["facets"]
        assert facets.severity.state is FacetState.MAPPED
        assert "queries[].severity" in (facets.severity.native_field or "")
