# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ScanCodeScanner: the invocation, the report conversion and the failure cases.

The ScanCode documents at the top are built by hand from the fields ScanCode's own
source documents for ``--json`` output (``headers``, ``files``, ``license_detections``,
``matches``); they probe the converter's edge cases. ``TestCapturedReports`` runs the
converter, and ``scan()`` end to end, over real ScanCode 32.5.0 captures. ``scan()``
runs against a fake subprocess that writes the document where the argv's ``--json=``
names, so the tests run on every platform without ScanCode installed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_scancode_plugins
from automated_security_helper.plugin_modules.ash_scancode_plugins.scancode_scanner import (
    LICENSE_LEVEL,
    LICENSE_SEVERITY,
    ScanCodeScanner,
    ScanCodeScannerConfig,
    ScanCodeScannerConfigOptions,
    convert_scancode_result,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport

pytestmark = pytest.mark.unit


def _match(
    expression: Optional[str], start: int, end: int, score: float = 100.0
) -> Dict[str, Any]:
    return {
        "license_expression": (expression or "").lower(),
        "license_expression_spdx": expression,
        "from_file": "src/app.py",
        "start_line": start,
        "end_line": end,
        "matcher": "2-aho",
        "score": score,
        "matched_length": 10,
        "match_coverage": 100.0,
        "rule_relevance": 100,
        "rule_identifier": "x.RULE",
        "rule_url": "",
    }


def _file(path: str, *matches: Dict[str, Any], kind: str = "file") -> Dict[str, Any]:
    return {
        "path": path,
        "type": kind,
        "license_detections": [{"license_expression": "x", "matches": list(matches)}]
        if matches
        else [],
        "scan_errors": [],
    }


#: Two licenses in two files, a file with none and a directory entry. The paths begin
#: with the name of the directory ScanCode was given ("src"), as ScanCode writes them.
POSITIVE: Dict[str, Any] = {
    "headers": [{"tool_name": "scancode-toolkit", "tool_version": "32.5.0"}],
    "files": [
        _file("src", kind="directory"),
        _file("src/app.py", _match("MIT", 1, 3)),
        _file("src/services/lib.py", _match("GPL-2.0-only", 2, 20, 98.5)),
        _file("src/README.txt"),
    ],
}
NEGATIVE: Dict[str, Any] = {
    "headers": [{"tool_version": "32.5.0"}],
    "files": [_file("src", kind="directory"), _file("src/app.py")],
}

POSITIVE_EXPECTED = [
    ("MIT", "none", "INFO", "app.py", 1),
    ("GPL-2.0-only", "none", "INFO", "services/lib.py", 2),
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
                loc.region.startLine,
            )
        )
    return out


class FakeScanCode:
    """Stands in for _run_subprocess: records argv, writes a ScanCode document."""

    def __init__(
        self,
        document: Optional[Dict[str, Any]] = None,
        exit_code: int = 0,
        text: Optional[str] = None,
        stderr: str = "",
        timed_out: bool = False,
        write: bool = True,
    ):
        self.document = POSITIVE if document is None else document
        self.exit_code, self.text, self.stderr = exit_code, text, stderr
        self.timed_out, self.write = timed_out, write
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, cwd=None, **_):
            self.calls.append(
                {"argv": list(command), "env": env, "timeout": timeout, "cwd": cwd}
            )
            json_arg = next(a for a in command if a.startswith("--json="))
            path = Path(json_arg.split("=", 1)[1])
            if self.write:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    self.text if self.text is not None else json.dumps(self.document),
                    encoding="utf-8",
                )
            scanner.exit_code = self.exit_code
            response: Dict[str, Any] = {
                "returncode": self.exit_code,
                "stdout": "",
                "stderr": self.stderr,
            }
            if self.timed_out:
                response["timed_out"] = True
            return response

        return run

    @property
    def argv(self) -> List[str]:
        return self.calls[0]["argv"]


def _scanner(source: Path, tmp_path: Path, **options) -> ScanCodeScanner:
    output = tmp_path / "out"
    return ScanCodeScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=get_default_config(),
        ),
        config=ScanCodeScannerConfig(
            enabled=True, options=ScanCodeScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    # The directory is named "src", matching the first path segment of the documents.
    src = tmp_path / "src"
    (src / "services").mkdir(parents=True)
    (src / "app.py").write_text("print(1)\n")
    (src / "services" / "lib.py").write_text("X = 1\n")
    return src


@pytest.fixture
def tool_present(monkeypatch):
    monkeypatch.setattr(ScanCodeScanner, "validate_plugin_dependencies", lambda s: True)


def _run(scanner, fake, monkeypatch):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(target=Path(scanner.context.source_dir), target_type="source")


def _flag(argv: List[str], prefix: str) -> Optional[str]:
    for token in argv:
        if token.startswith(prefix):
            return token[len(prefix) :]
    return None


class TestCommunityPlugin:
    def test_scanner_is_enabled_once_its_module_is_listed(self):
        # `--scanners scancode` runs a scanner only when it is in the allowlist AND
        # enabled, so the documented one-run form needs the default to be True.
        assert ScanCodeScannerConfig().enabled is True
        assert ScanCodeScannerConfig().name == "scancode"

    def test_the_builtin_config_does_not_declare_it(self):
        assert not hasattr(get_default_config().scanners, "scancode")

    def test_the_module_exports_the_scanner(self):
        assert ash_scancode_plugins.ASH_SCANNERS == [ScanCodeScanner]
        assert ash_scancode_plugins.ASH_REPORTERS == []

    def test_class_declarations(self):
        assert ScanCodeScanner.python_only is False
        assert ScanCodeScanner.success_exit_codes == {0}


class TestInvocation:
    def test_every_fixed_flag_and_the_scan_path(
        self, tree, tmp_path, tool_present, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeScanCode()
        _run(scanner, fake, monkeypatch)
        argv = fake.argv
        assert argv[0] == "scancode"
        assert "--license" in argv
        assert "--quiet" in argv
        assert _flag(argv, "--json=").endswith("/source/scancode.json")
        # The path follows "--" so it cannot be read as a flag.
        assert argv[-2:] == ["--", tree.absolute().as_posix()]
        assert not any(a.startswith("--license-score") for a in argv)

    def test_license_score_is_one_flag_token(
        self, tree, tmp_path, tool_present, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, license_score=40)
        fake = FakeScanCode()
        _run(scanner, fake, monkeypatch)
        assert "--license-score=40" in fake.argv

    @pytest.mark.parametrize(
        "forbidden", ["--license-text", "--from-json", "--ignore", "--reindex-licenses"]
    )
    def test_flags_that_copy_text_or_change_the_input_are_never_passed(
        self, forbidden, tree, tmp_path, tool_present, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeScanCode()
        _run(scanner, fake, monkeypatch)
        assert not any(a.split("=", 1)[0] == forbidden for a in fake.argv)

    def test_a_missing_target_never_reaches_the_tool(
        self, tree, tmp_path, tool_present, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeScanCode()
        monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
        scanner.scan(target=tmp_path / "nope", target_type="source")
        assert fake.calls == []


class TestReport:
    def test_positive_is_located_and_rated_info(
        self, tree, tmp_path, tool_present, monkeypatch
    ):
        report = _run(_scanner(tree, tmp_path), FakeScanCode(), monkeypatch)
        assert _findings(report) == POSITIVE_EXPECTED

    def test_negative_control_has_no_findings(
        self, tree, tmp_path, tool_present, monkeypatch
    ):
        report = _run(
            _scanner(tree, tmp_path), FakeScanCode(document=NEGATIVE), monkeypatch
        )
        assert _findings(report) == []

    def test_level_and_severity_agree_on_every_result(self):
        sarif = convert_scancode_result(POSITIVE, strip_first_segment="src")
        for result in sarif["runs"][0]["results"]:
            assert result["level"] == LICENSE_LEVEL == "none"
            assert result["properties"]["issue_severity"] == LICENSE_SEVERITY == "INFO"

    def test_the_tool_version_comes_from_the_header(self):
        sarif = convert_scancode_result(POSITIVE, strip_first_segment="src")
        assert sarif["runs"][0]["tool"]["driver"]["version"] == "32.5.0"

    def test_no_matched_text_is_carried(self):
        match = _match("MIT", 1, 1)
        match["matched_text"] = "COPY OF THE FILE"
        doc = {"files": [_file("src/a.py", match)]}
        assert "COPY OF THE FILE" not in json.dumps(
            convert_scancode_result(doc, strip_first_segment="src")
        )

    def test_a_target_below_the_source_dir_keeps_its_prefix(self):
        sarif = convert_scancode_result(
            POSITIVE, uri_prefix="vendor", strip_first_segment="src"
        )
        uris = [
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in sarif["runs"][0]["results"]
        ]
        assert uris == ["vendor/app.py", "vendor/services/lib.py"]

    def test_a_match_with_no_expression_is_still_reported(self):
        doc = {"files": [_file("src/a.py", _match(None, 4, 4))]}
        doc["files"][0]["license_detections"][0]["matches"][0]["license_expression"] = (
            ""
        )
        sarif = convert_scancode_result(doc, strip_first_segment="src")
        assert sarif["runs"][0]["results"][0]["ruleId"] == "unknown-license"

    def test_a_repeated_match_is_reported_once(self):
        doc = {"files": [_file("src/a.py", _match("MIT", 1, 2), _match("MIT", 1, 2))]}
        assert len(convert_scancode_result(doc)["runs"][0]["results"]) == 1

    def test_results_under_the_output_dir_are_dropped(
        self, tree, tmp_path, tool_present, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        monkeypatch.setattr(scanner, "_output_dir_inside", lambda t: Path("out"))
        monkeypatch.setattr(scanner, "_ash_output_dirs_inside", lambda t: [])
        doc = {
            "headers": [],
            "files": [
                _file("src/app.py", _match("MIT", 1, 1)),
                _file("src/out/copy.py", _match("MIT", 1, 1)),
            ],
        }
        report = _run(scanner, FakeScanCode(document=doc), monkeypatch)
        assert [f[3] for f in _findings(report)] == ["app.py"]


class TestExitStatusAndFailures:
    def test_exit_one_fails_even_with_a_report_on_disk(
        self, tree, tmp_path, tool_present, monkeypatch
    ):
        with pytest.raises(ScannerError, match="exit"):
            _run(_scanner(tree, tmp_path), FakeScanCode(exit_code=1), monkeypatch)

    def test_a_run_that_wrote_no_report_fails(
        self, tree, tmp_path, tool_present, monkeypatch
    ):
        with pytest.raises(ScannerError):
            _run(_scanner(tree, tmp_path), FakeScanCode(write=False), monkeypatch)

    def test_a_timeout_fails_the_scan_and_says_so(
        self, tree, tmp_path, tool_present, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeScanCode(exit_code=124, timed_out=True, write=False)
        with pytest.raises(ScannerError, match="timed out"):
            _run(scanner, fake, monkeypatch)
        timeout = fake.calls[0]["timeout"]
        assert timeout is not None and 0 < timeout <= scanner._opts.scan_timeout

    @pytest.mark.parametrize(
        "text",
        [
            "not json at all",
            "[1, 2, 3]",
            '{"headers": []}',
            '{"files": "nope"}',
        ],
    )
    def test_malformed_output_fails_instead_of_reading_as_clean(
        self, text, tree, tmp_path, tool_present, monkeypatch
    ):
        with pytest.raises(ScannerError):
            _run(_scanner(tree, tmp_path), FakeScanCode(text=text), monkeypatch)

    def test_a_report_left_by_an_earlier_run_is_removed_first(
        self, tree, tmp_path, tool_present, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        stale = Path(scanner.results_dir) / "source" / "scancode.json"
        stale.parent.mkdir(parents=True, exist_ok=True)
        stale.write_text(json.dumps(POSITIVE))
        with pytest.raises(ScannerError):
            _run(scanner, FakeScanCode(write=False), monkeypatch)

    def test_stderr_is_not_copied_into_errors(self, tree, tmp_path):
        # Through the real base-class response handler: the fake subprocess of the
        # other tests replaces it and so cannot see stderr handling.
        response = {"returncode": 1, "stdout": "", "stderr": "secret-file.txt failed"}
        scanner = _scanner(tree, tmp_path)
        scanner._process_command_response(dict(response))
        assert not any("secret-file" in e for e in scanner.errors)

    def test_the_stderr_check_can_fail(self, tree, tmp_path, monkeypatch):
        # Planted control: with quoting on, the same response reaches the errors.
        monkeypatch.setattr(ScanCodeScanner, "quote_tool_stderr", True)
        response = {"returncode": 1, "stdout": "", "stderr": "secret-file.txt failed"}
        scanner = _scanner(tree, tmp_path)
        scanner._process_command_response(dict(response))
        assert any("secret-file" in e for e in scanner.errors)

    def test_the_failure_text_names_the_log_without_quoting_it(self, tree, tmp_path):
        scanner = _scanner(tree, tmp_path)
        scanner.exit_code = 1
        text = scanner._describe_scan_failure(
            ScannerError("boom"), tmp_path / "scancode.json", tool_started=True
        )
        assert "scancode" in text and "stderr.log" in text
        assert "boom" in text

    def test_the_converter_refuses_a_non_result(self):
        with pytest.raises(ScannerError):
            convert_scancode_result(["x"])


class TestDependencyCheck:
    def test_tool_absent_fails_validation_and_the_scan_does_not_run(
        self, tree, tmp_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        monkeypatch.setattr(scanner, "_validate_uv_tool_availability", lambda: False)
        monkeypatch.setattr(
            "automated_security_helper.plugin_modules.ash_scancode_plugins."
            "scancode_scanner.get_uv_tool_command",
            lambda name: None,
        )
        assert scanner.validate_plugin_dependencies() is False
        fake = FakeScanCode()
        monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
        scanner.scan(target=tree, target_type="source")
        assert fake.calls == []

    def test_a_recorded_unavailable_reason_wins(self, tree, tmp_path):
        scanner = _scanner(tree, tmp_path)
        scanner.dependency_unavailable_reason = "offline"
        assert scanner.validate_plugin_dependencies() is False


class TestInstall:
    def test_the_default_constraint_is_an_exact_pin(self, tree, tmp_path):
        scanner = _scanner(tree, tmp_path)
        assert scanner._get_tool_version_constraint() == "==32.5.0"

    def test_the_option_overrides_the_pin(self, tree, tmp_path):
        scanner = _scanner(tree, tmp_path, tool_version=">=32.0,<33")
        assert scanner._get_tool_version_constraint() == ">=32.0,<33"

    def test_pluggy_is_held_below_the_release_that_breaks_scancode(
        self, tree, tmp_path
    ):
        scanner = _scanner(tree, tmp_path)
        assert scanner._get_tool_with_dependencies() == ["pluggy<1.7"]

    def test_the_stored_install_command_carries_the_pin_python_and_pluggy_hold(
        self, tree, tmp_path
    ):
        scanner = _scanner(tree, tmp_path)
        expected = (
            "uv tool install --python >=3.10,<3.14 --with pluggy<1.7 "
            "scancode-toolkit==32.5.0"
        )
        assert scanner.uv_tool_install_commands == [expected]

    def test_platform_coverage_is_declared_as_uv_run_not_a_download_table(self):
        # Row 11: no per-platform download table exists for a PyPI tool run through
        # uv, so the declaration says so, and the install command is the same
        # string on every platform.
        platforms = ScanCodeScanner.operational_facets.platforms
        assert platforms.provisionable == ()
        assert "uv" in platforms.note and "unsupported platform" in platforms.note
        assert ScanCodeScanner.operational_facets.runtime.use_uv_tool is True

    def test_the_package_is_scancode_toolkit(self, tree, tmp_path):
        scanner = _scanner(tree, tmp_path)
        assert scanner.uv_tool_package_name == "scancode-toolkit"
        assert scanner.command == "scancode"


CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "scancode"
    / "captured"
)


class TestCapturedReports:
    """The converter over real ScanCode 32.5.0 output (captured/README.md)."""

    def _convert(self, name: str, first_segment: str) -> List[Dict[str, Any]]:
        document = json.loads((CAPTURED / name).read_text(encoding="utf-8"))
        sarif = convert_scancode_result(document, strip_first_segment=first_segment)
        return sarif["runs"][0]["results"]

    def test_positive_capture_is_located_and_rated_info(self):
        results = self._convert("positive.json", "pos")
        found = sorted(
            (
                r["ruleId"],
                r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                r["locations"][0]["physicalLocation"]["region"]["startLine"],
                r["locations"][0]["physicalLocation"]["region"]["endLine"],
                r["level"],
                r["properties"]["issue_severity"],
            )
            for r in results
        )
        assert found == [
            ("Apache-2.0", "src/app.py", 1, 1, "none", "INFO"),
            (
                "LicenseRef-scancode-warranty-disclaimer",
                "LICENSE",
                15,
                16,
                "none",
                "INFO",
            ),
            ("MIT", "LICENSE", 1, 1, "none", "INFO"),
            ("MIT", "LICENSE", 5, 13, "none", "INFO"),
        ]

    def test_negative_capture_has_no_findings(self):
        assert self._convert("negative.json", "neg") == []

    def test_the_capture_version_reaches_the_driver(self):
        document = json.loads((CAPTURED / "positive.json").read_text(encoding="utf-8"))
        sarif = convert_scancode_result(document, strip_first_segment="pos")
        assert sarif["runs"][0]["tool"]["driver"]["version"] == "32.5.0"

    def test_the_converted_capture_validates_as_sarif(self):
        document = json.loads((CAPTURED / "positive.json").read_text(encoding="utf-8"))
        sarif = convert_scancode_result(document, strip_first_segment="pos")
        report = SarifReport.model_validate(sarif)
        assert len(report.get_all_results()) == 4

    @pytest.mark.parametrize(
        ("name", "dirname", "expected"),
        [
            (
                "positive.json",
                "pos",
                [
                    ("Apache-2.0", "none", "INFO", "src/app.py", 1),
                    ("MIT", "none", "INFO", "LICENSE", 1),
                    ("MIT", "none", "INFO", "LICENSE", 5),
                    (
                        "LicenseRef-scancode-warranty-disclaimer",
                        "none",
                        "INFO",
                        "LICENSE",
                        15,
                    ),
                ],
            ),
            ("negative.json", "neg", []),
        ],
    )
    def test_scan_over_a_real_capture_anchors_paths_to_the_target(
        self, name, dirname, expected, tmp_path, tool_present, monkeypatch
    ):
        # End to end through scan(): the capture's paths begin with the directory
        # name ScanCode was given, and the scanner derives that name from the target
        # itself (no hand-passed strip), so a wrong anchor reads as moved findings.
        target = tmp_path / dirname
        target.mkdir()
        document = json.loads((CAPTURED / name).read_text(encoding="utf-8"))
        scanner = _scanner(target, tmp_path)
        report = _run(scanner, FakeScanCode(document=document), monkeypatch)
        assert sorted(_findings(report)) == sorted(expected)

    def test_a_capture_scanned_under_the_wrong_directory_name_is_not_silently_moved(
        self, tmp_path, tool_present, monkeypatch
    ):
        # Planted control for the test above: with a target whose name differs from
        # the capture's first segment, nothing is stripped and the URIs keep "pos/".
        target = tmp_path / "other"
        target.mkdir()
        document = json.loads((CAPTURED / "positive.json").read_text(encoding="utf-8"))
        report = _run(
            _scanner(target, tmp_path), FakeScanCode(document=document), monkeypatch
        )
        assert {f[3] for f in _findings(report)} == {"pos/LICENSE", "pos/src/app.py"}


class TestPinIsAStableRelease:
    def test_the_default_pin_is_one_exact_final_release(self):
        from automated_security_helper.plugin_modules.ash_scancode_plugins.scancode_scanner import (  # noqa: E501
            SCANCODE_DEFAULT_VERSION_CONSTRAINT,
        )

        assert SCANCODE_DEFAULT_VERSION_CONSTRAINT.startswith("==")
        version = SCANCODE_DEFAULT_VERSION_CONSTRAINT[2:]
        assert version.replace(".", "").isdigit(), "a pre or dev release is not a pin"
