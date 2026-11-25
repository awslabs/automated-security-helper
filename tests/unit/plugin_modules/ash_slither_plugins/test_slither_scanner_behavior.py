# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""SlitherScanner: the invocation, the JSON -> SARIF conversion and the failure cases.

The subprocess is replaced by a fake, so the tests run on every platform without
Slither. The JSON the fake writes has the shape ``slither --json`` documents in
``slither/utils/output.py`` (``success``, ``error``, ``results.detectors[]`` with
``check``, ``impact``, ``confidence``, ``description``, ``id`` and ``elements[]`` whose
``source_mapping`` has ``filename_relative`` and ``lines``). The row-by-row documents
are written by hand from that source; ``TestCaptured`` and ``TestAnalyzedNothing`` run
the files captured from slither 0.11.6 (tests/test_data/scanners/slither/captured).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_slither_plugins
from automated_security_helper.plugin_modules.ash_slither_plugins.slither_scanner import (
    INSTALL_HINT,
    SLITHER_IMPACT_MAP,
    SlitherScanner,
    SlitherScannerConfig,
    SlitherScannerConfigOptions,
    convert_slither_json,
    holds_solidity,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.sandbox.policy import SandboxRequirements

pytestmark = pytest.mark.unit


def _detector(
    check: str = "reentrancy-eth",
    impact: Optional[str] = "High",
    confidence: str = "Medium",
    path: Optional[str] = "contracts/Vault.sol",
    lines: Optional[List[int]] = None,
    ident: str = "a1b2c3",
) -> Dict[str, Any]:
    elements: List[Dict[str, Any]] = []
    if path is not None:
        elements = [
            {
                "type": "function",
                "name": "withdraw",
                "source_mapping": {
                    "filename_relative": path,
                    "filename_absolute": f"/work/{path}",
                    "lines": lines if lines is not None else [10, 11, 12],
                },
            }
        ]
    detector: Dict[str, Any] = {
        "elements": elements,
        "description": f"{check} in Vault.withdraw()",
        "check": check,
        "confidence": confidence,
        "id": ident,
    }
    if impact is not None:
        detector["impact"] = impact
    return detector


def _document(*detectors: Dict[str, Any], **extra: Any) -> Dict[str, Any]:
    return {
        "success": True,
        "error": None,
        "results": {"detectors": list(detectors)},
        **extra,
    }


#: Hand-written from the Slither detector classification: one finding per impact.
POSITIVE = _document(
    _detector("reentrancy-eth", "High", ident="h1", lines=[10, 11, 12]),
    _detector(
        "timestamp", "Medium", ident="m1", path="contracts/Auction.sol", lines=[7]
    ),
    _detector("calls-loop", "Low", ident="l1", path="contracts/Pool.sol", lines=[3]),
    _detector("naming-convention", "Informational", ident="i1", lines=[1]),
    _detector("cache-array-length", "Optimization", ident="o1", lines=[2]),
)
#: (ruleId, SARIF level, ASH severity, uri, start line), written out by hand.
POSITIVE_EXPECTED = [
    ("reentrancy-eth", "error", "HIGH", "contracts/Vault.sol", 10),
    ("timestamp", "warning", "MEDIUM", "contracts/Auction.sol", 7),
    ("calls-loop", "note", "LOW", "contracts/Pool.sol", 3),
    ("naming-convention", "none", "INFO", "contracts/Vault.sol", 1),
    ("cache-array-length", "none", "INFO", "contracts/Vault.sol", 2),
]
NEGATIVE = _document()
#: The summary line Slither's log ends with after an analysis (real text: see
#: tests/test_data/scanners/slither/captured/clean.stderr.txt).
ANALYZED_LOG = (
    "contracts analyzed (3 contracts with 102 detectors), 5 result(s) found\n"
)
CAPTURED = Path(__file__).resolve().parents[3] / "test_data/scanners/slither/captured"


class FakeSlither:
    """Stands in for _run_subprocess: records argv, writes a JSON report."""

    def __init__(
        self,
        document: Any = POSITIVE,
        exit_code: int = 0,
        text: Optional[str] = None,
        write: bool = True,
        response_extra: Optional[Dict[str, Any]] = None,
        stderr: str = "",
        log: Optional[str] = ANALYZED_LOG,
    ):
        self.document, self.exit_code, self.text = document, exit_code, text
        self.write, self.response_extra = write, response_extra or {}
        self.stderr = stderr
        #: What the run writes to its stderr log; None writes no log file.
        self.log = log
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, cwd=None, **_):
            self.calls.append(
                {"argv": list(command), "env": env, "timeout": timeout, "cwd": cwd}
            )
            report_arg = next(a for a in command if a.startswith("--json="))
            path = Path(report_arg.split("=", 1)[1])
            assert not path.exists(), "slither never overwrites; the path must be clear"
            if self.log is not None:
                path.parent.mkdir(parents=True, exist_ok=True)
                (path.parent / "SlitherScanner.stderr.log").write_text(
                    self.log, encoding="utf-8"
                )
            if self.write:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    self.text if self.text is not None else json.dumps(self.document),
                    encoding="utf-8",
                )
            scanner.exit_code = self.exit_code
            return {
                "returncode": self.exit_code,
                "stdout": "",
                "stderr": self.stderr,
                **self.response_extra,
            }

        return run

    @property
    def argv(self) -> List[str]:
        return self.calls[0]["argv"]


def _scanner(source: Path, tmp_path: Path, **options) -> SlitherScanner:
    config = get_default_config()
    output = tmp_path / "out"
    return SlitherScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=config,
        ),
        config=SlitherScannerConfig(
            enabled=True, options=SlitherScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    (src / "contracts").mkdir(parents=True)
    (src / "contracts" / "Vault.sol").write_text("contract Vault {}\n")
    return src


@pytest.fixture
def on_path(monkeypatch):
    from automated_security_helper.base import scanner_plugin

    monkeypatch.setattr(scanner_plugin, "find_executable", lambda cmd: f"/fake/{cmd}")


def _run(scanner, fake, monkeypatch, target=None, target_type="source"):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=Path(target or scanner.context.source_dir), target_type=target_type
    )


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
                loc.region.startLine,
            )
        )
    return out


class TestCommunityPlugin:
    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert SlitherScannerConfig().enabled is True
        assert SlitherScannerConfig().name == "slither"

    def test_the_builtin_config_does_not_declare_it(self):
        assert not hasattr(get_default_config().scanners, "slither")

    def test_the_module_exports_the_scanner(self):
        assert ash_slither_plugins.ASH_SCANNERS == [SlitherScanner]
        assert ash_slither_plugins.ASH_REPORTERS == []

    def test_the_declared_class_variables(self):
        assert SlitherScanner.python_only is False
        assert SlitherScanner.success_exit_codes == {0}
        assert SlitherScanner.sandbox_requirements == SandboxRequirements()


class TestInvocation:
    def test_every_fixed_flag_and_the_scan_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeSlither()
        _run(scanner, fake, monkeypatch)
        argv = fake.argv
        assert argv[0] == "slither"
        report = Path(argv[1].split("=", 1)[1])
        assert argv[1] == f"--json={report.as_posix()}"
        assert (
            argv[2]
            == f"--config-file={(report.parent / 'slither-config.json').as_posix()}"
        )
        assert argv[3] == (
            f"--triage-database={(report.parent / 'slither-triage.db.json').as_posix()}"
        )
        assert argv[4:] == ["--fail-none", "--exclude-dependencies", "--", "."]
        assert fake.calls[0]["cwd"] is None  # the base runs it in the source directory

    def test_a_converted_target_is_an_absolute_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        converted = tmp_path / "out" / "converted"
        converted.mkdir(parents=True)
        (converted / "Token.sol").write_text("contract Token {}\n")
        scanner = _scanner(tree, tmp_path)
        fake = FakeSlither(NEGATIVE)
        _run(scanner, fake, monkeypatch, target=converted, target_type="converted")
        assert fake.argv[-2:] == ["--", converted.absolute().as_posix()]

    @pytest.mark.parametrize(
        "flag", ["--sarif", "--json=-", "--no-fail", "--compile-force-framework"]
    )
    def test_flags_that_change_the_output_or_the_build_are_never_passed(
        self, tree, tmp_path, on_path, monkeypatch, flag
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeSlither()
        _run(scanner, fake, monkeypatch)
        assert not any(a == flag or a.startswith(flag + "=") for a in fake.argv[2:])

    def test_a_tree_with_no_solidity_never_starts_slither(
        self, tmp_path, on_path, monkeypatch
    ):
        src = tmp_path / "src"
        src.mkdir()
        (src / "app.py").write_text("print(1)\n")
        scanner = _scanner(src, tmp_path)
        fake = FakeSlither()
        result = _run(scanner, fake, monkeypatch)
        assert result is True
        assert fake.calls == []
        assert "no Solidity" in (scanner._nothing_scanned_reason or "")
        assert scanner.nothing_to_scan_reason() is not None

    def test_a_solidity_file_only_under_node_modules_is_not_a_target(self, tmp_path):
        src = tmp_path / "src"
        (src / "node_modules" / "dep").mkdir(parents=True)
        (src / "node_modules" / "dep" / "Dep.sol").write_text("contract Dep {}\n")
        assert holds_solidity(src) is False

    def test_a_linked_solidity_file_is_not_counted(self, tmp_path):
        outside = tmp_path / "outside.sol"
        outside.write_text("contract X {}\n")
        src = tmp_path / "src"
        src.mkdir()
        (src / "link.sol").symlink_to(outside)
        assert holds_solidity(src) is False

    def test_a_missing_target_never_reaches_the_tool(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeSlither()
        _run(scanner, fake, monkeypatch, target=tmp_path / "gone")
        assert fake.calls == []


class TestReport:
    def test_the_positive_document_is_rated_and_located(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeSlither(), monkeypatch)
        assert isinstance(report, SarifReport)
        assert _findings(report) == POSITIVE_EXPECTED

    def test_negative_control_a_clean_document_has_no_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeSlither(NEGATIVE), monkeypatch)
        assert isinstance(report, SarifReport)
        assert _findings(report) == []
        assert report.runs

    def test_level_and_severity_agree_for_every_impact(self):
        for impact, (severity, level) in SLITHER_IMPACT_MAP.items():
            sarif, _ = convert_slither_json(_document(_detector(impact=impact)))
            result = sarif["runs"][0]["results"][0]
            assert (result["properties"]["issue_severity"], result["level"]) == (
                severity,
                level,
            )

    def test_a_result_without_an_impact_is_medium(self):
        sarif, _ = convert_slither_json(_document(_detector(impact=None)))
        result = sarif["runs"][0]["results"][0]
        assert (result["properties"]["issue_severity"], result["level"]) == (
            "MEDIUM",
            "warning",
        )

    def test_an_unknown_impact_is_high(self):
        sarif, _ = convert_slither_json(_document(_detector(impact="Catastrophic")))
        result = sarif["runs"][0]["results"][0]
        assert (result["properties"]["issue_severity"], result["level"]) == (
            "HIGH",
            "error",
        )

    def test_confidence_and_fingerprint_are_kept(self):
        sarif, _ = convert_slither_json(_document(_detector(confidence="Low")))
        result = sarif["runs"][0]["results"][0]
        assert result["properties"]["slither_confidence"] == "Low"
        assert result["partialFingerprints"] == {"slither/v1": "a1b2c3"}

    def test_a_finding_without_a_location_is_counted_not_reported(self):
        sarif, unplaced = convert_slither_json(
            _document(_detector(path=None), _detector(check="timestamp", ident="x"))
        )
        assert unplaced == 1
        assert [r["ruleId"] for r in sarif["runs"][0]["results"]] == ["timestamp"]

    def test_the_unplaced_count_is_logged_by_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        logged: List[str] = []
        monkeypatch.setattr(
            scanner, "_plugin_log", lambda message, *a, **k: logged.append(message)
        )
        _run(scanner, FakeSlither(_document(_detector(path=None))), monkeypatch)
        assert any("no source location" in m for m in logged)

    def test_the_report_survives_a_round_trip(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeSlither(), monkeypatch)
        again = SarifReport.model_validate_json(
            report.model_dump_json(exclude_none=True, by_alias=True)
        )
        assert _findings(again) == POSITIVE_EXPECTED


class TestFailures:
    def test_zero_is_the_only_success_code(self, tree, tmp_path, on_path, monkeypatch):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeSlither(exit_code=0), monkeypatch)
        assert scanner._exit_code_accepted()

    @pytest.mark.parametrize("code", [1, 255, 126, 137])
    def test_any_other_exit_fails_the_scan_even_with_a_report_on_disk(
        self, tree, tmp_path, on_path, monkeypatch, code
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeSlither(exit_code=code), monkeypatch)

    def test_a_timeout_fails_the_scan_and_says_so(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, scan_timeout=45)
        fake = FakeSlither(write=False, response_extra={"timed_out": True})
        with pytest.raises(ScannerError, match="timed out"):
            _run(scanner, fake, monkeypatch)
        assert 0 < fake.calls[0]["timeout"] <= 45

    @pytest.mark.parametrize(
        "text",
        [
            "this is not json",
            "[]",
            json.dumps({"success": True, "error": None}),
            json.dumps({"success": True, "results": {"detectors": "oops"}}),
            json.dumps({"success": True, "results": {"detectors": ["oops"]}}),
        ],
    )
    def test_malformed_output_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch, text
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeSlither(text=text), monkeypatch)

    def test_an_empty_report_file_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeSlither(text=""), monkeypatch)

    def test_a_document_slither_marked_failed_is_not_a_clean_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        failed = {"success": False, "error": "compilation failed", "results": {}}
        with pytest.raises(ScannerError, match="failed"):
            _run(scanner, FakeSlither(failed), monkeypatch)

    def test_a_run_that_wrote_no_report_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeSlither(write=False), monkeypatch)

    def test_a_report_left_by_an_earlier_run_is_removed_before_the_next_one(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        first = FakeSlither()
        _run(scanner, first, monkeypatch)
        report = Path(first.argv[1].split("=", 1)[1])
        assert report.exists()
        # The fake asserts the path is clear when the second run starts.
        with pytest.raises(ScannerError):
            _run(scanner, FakeSlither(write=False), monkeypatch)
        assert not report.exists()

    def test_the_tools_stderr_is_not_copied_into_the_scans_errors(
        self, tree, tmp_path, on_path
    ):
        scanner = _scanner(tree, tmp_path)
        scanner._process_command_response(
            {"returncode": 0, "stdout": "", "stderr": "PLANTED-SOURCE-LINE"}
        )
        assert not any("PLANTED-SOURCE-LINE" in line for line in scanner.errors)

    def test_the_failure_message_names_the_log_and_does_not_quote_it(
        self, tree, tmp_path, on_path
    ):
        scanner = _scanner(tree, tmp_path)
        scanner.exit_code = 255
        message = scanner._describe_scan_failure(
            ScannerError("boom"), tmp_path / "out" / "source" / "slither.json"
        )
        assert "stderr.log" in message
        assert "exit code 255" in message
        assert "not quoted" in message


class TestDependencyCheck:
    def test_slither_absent_is_missing_and_the_reason_names_the_install(
        self, tree, tmp_path, monkeypatch
    ):
        from automated_security_helper.base import scanner_plugin

        monkeypatch.setattr(scanner_plugin, "find_executable", lambda cmd: None)
        scanner = _scanner(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is False
        assert scanner.missing_dependency_reason() == INSTALL_HINT
        assert "uv tool install slither-analyzer" in INSTALL_HINT
        assert "AGPL" in INSTALL_HINT

    def test_slither_present_passes(self, tree, tmp_path, on_path):
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is True


class TestLicenseGate:
    def test_no_install_command_exists_for_any_platform(self, tree, tmp_path):
        """AGPL-3.0: ASH never installs Slither, on any platform."""
        scanner = _scanner(tree, tmp_path)
        assert scanner.custom_install_commands == {}
        assert not scanner.use_uv_tool
        for platform in ("linux", "darwin", "windows"):
            for arch in ("x86_64", "arm64"):
                assert scanner.get_installation_commands(platform, arch) == []


class TestTreeConfiguration:
    """The scanned tree must not be able to hide findings (measured on slither 0.11.6)."""

    def test_an_empty_config_file_replaces_the_trees_own(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        (tree / "slither.config.json").write_text(
            json.dumps({"detectors_to_exclude": "reentrancy-eth"})
        )
        (tree / "slither.db.json").write_text("[]")
        scanner = _scanner(tree, tmp_path)
        fake = FakeSlither()
        _run(scanner, fake, monkeypatch)
        config_arg = next(a for a in fake.argv if a.startswith("--config-file="))
        config = Path(config_arg.split("=", 1)[1])
        assert json.loads(config.read_text()) == {}
        assert tree not in config.parents, "the config must not come from the tree"

    def test_the_triage_database_path_is_one_that_does_not_exist(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeSlither()
        _run(scanner, fake, monkeypatch)
        triage_arg = next(a for a in fake.argv if a.startswith("--triage-database="))
        triage = Path(triage_arg.split("=", 1)[1])
        assert not triage.exists()
        assert tree not in triage.parents

    def test_a_stale_triage_database_in_the_results_directory_is_removed(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        first = FakeSlither()
        _run(scanner, first, monkeypatch)
        triage_arg = next(a for a in first.argv if a.startswith("--triage-database="))
        triage = Path(triage_arg.split("=", 1)[1])
        triage.write_text("[]")
        _run(scanner, FakeSlither(), monkeypatch)
        assert not triage.exists()


class TestAnalyzedNothing:
    """``results: {}`` reads the same for a clean scan and one that compiled nothing."""

    def test_a_run_that_analyzed_no_contract_is_an_error_not_a_clean_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeSlither(
            json.loads((CAPTURED / "no-contract-analyzed.json").read_text()),
            log=(CAPTURED / "no-contract-analyzed.stderr.txt").read_text(),
        )
        with pytest.raises(ScannerError, match="analyzed 0 contracts"):
            _run(scanner, fake, monkeypatch)

    def test_negative_control_the_captured_clean_run_is_a_clean_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeSlither(
            json.loads((CAPTURED / "clean.json").read_text()),
            log=(CAPTURED / "clean.stderr.txt").read_text(),
        )
        report = _run(scanner, fake, monkeypatch)
        assert isinstance(report, SarifReport)
        assert _findings(report) == []

    def test_the_two_captured_documents_are_identical(self):
        """The reason the log is read: the document cannot tell them apart."""
        assert (CAPTURED / "clean.json").read_text() == (
            CAPTURED / "no-contract-analyzed.json"
        ).read_text()

    @pytest.mark.parametrize("log", [None, "", "some unrelated line\n"])
    def test_a_missing_or_unrecognized_log_is_an_error(
        self, tree, tmp_path, on_path, monkeypatch, log
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError, match="unknown"):
            _run(scanner, FakeSlither(NEGATIVE, log=log), monkeypatch)


class TestCaptured:
    """The real ``slither --json`` document of the pinned argv, end to end."""

    def test_the_captured_positive_run_is_rated_and_located(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeSlither(json.loads((CAPTURED / "positive.json").read_text()))
        report = _run(scanner, fake, monkeypatch)
        assert _findings(report) == [
            ("reentrancy-eth", "error", "HIGH", "contracts/Vault.sol", 11),
            ("suicidal", "error", "HIGH", "contracts/Vault.sol", 18),
            ("solc-version", "none", "INFO", "contracts/Vault.sol", 2),
            ("low-level-calls", "none", "INFO", "contracts/Vault.sol", 11),
        ]

    def test_the_committed_sarif_fixture_is_what_the_converter_makes(self):
        document = json.loads((CAPTURED / "positive.json").read_text())
        sarif, unplaced = convert_slither_json(document)
        assert unplaced == 0
        assert json.loads((CAPTURED / "positive.sarif").read_text()) == sarif

    def test_the_multi_line_region_keeps_both_ends(self):
        document = json.loads((CAPTURED / "positive.json").read_text())
        sarif, _ = convert_slither_json(document)
        region = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
            "region"
        ]
        assert region == {"startLine": 11, "endLine": 16}
