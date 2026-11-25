# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""PsalmScanner: the invocation, the exit status, and the report.

No PHP runtime was available when the plugin was written, so the SARIF below is not a
capture: it is written by hand to the shape of Psalm's own SARIF writer
(``Psalm\\Report\\SarifReport``, 6.x): SARIF 2.1.0, rules keyed by the numeric issue
shortcode with ``properties.tags`` ``security`` for ``Tainted*`` types and
``maintainability`` for the rest, ``level`` ``error`` or ``note`` only, a bare
``artifactLocation.uri``, no result ``properties`` and no ``partialFingerprints``. The
scan() tests replace the subprocess with a fake that writes it, so they run on every
platform without PHP or Psalm. Expected findings are written out by hand below.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_psalm_plugins
from automated_security_helper.plugin_modules.ash_psalm_plugins import (
    psalm_scanner as ps,
)
from automated_security_helper.plugin_modules.ash_psalm_plugins.psalm_scanner import (
    PSALM_SEVERITY,
    PsalmScanner,
    PsalmScannerConfig,
    PsalmScannerConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import Level, SarifReport
from automated_security_helper.utils.sandbox.policy import SandboxRequirements

pytestmark = pytest.mark.unit


def _result(rule_id: str, level: Optional[str], uri: str, line: int) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "ruleId": rule_id,
        "message": {"text": f"finding for rule {rule_id}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {
                        "startLine": line,
                        "endLine": line,
                        "startColumn": 1,
                        "endColumn": 10,
                    },
                }
            }
        ],
    }
    if level is not None:
        result["level"] = level
    return result


def _rule(rule_id: str, name: str, tag: str) -> Dict[str, Any]:
    return {
        "id": rule_id,
        "name": name,
        "shortDescription": {"text": name},
        "properties": {"tags": [tag]},
        "helpUri": f"https://psalm.dev/{rule_id}",
    }


def _sarif(results: List[Dict[str, Any]], rules: List[Dict[str, Any]]) -> str:
    driver: Dict[str, Any] = {
        "name": "Psalm",
        "informationUri": "https://psalm.dev",
        "version": "6.20.13",
    }
    if rules:
        driver["rules"] = rules
    return json.dumps(
        {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": driver}, "results": results}],
        }
    )


TREE_ROOT_PLACEHOLDER = "@ROOT@"

RULES = [
    _rule("201", "TaintedSql", "security"),
    _rule("205", "TaintedHtml", "security"),
    _rule("1", "UndefinedVariable", "maintainability"),
]

#: Two taint findings (one absolute path, as Psalm writes a file outside its base
#: directory, one relative), one type issue and one taint finding at ``note``.
POSITIVE = _sarif(
    [
        _result("201", "error", f"{TREE_ROOT_PLACEHOLDER}/src/db.php", 12),
        _result("205", "error", "src/view.php", 7),
        _result("1", "error", "src/other.php", 3),
        _result("205", "note", "src/legacy.php", 9),
    ],
    RULES,
)

#: A clean run: Psalm adds no ``rules`` key when there are no issues.
NEGATIVE = _sarif([], [])

#: (ruleId, SARIF level, ASH severity, uri, line) with the type issue dropped.
POSITIVE_EXPECTED = [
    ("201", "error", "HIGH", "src/db.php", 12),
    ("205", "error", "HIGH", "src/view.php", 7),
    ("205", "note", "LOW", "src/legacy.php", 9),
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


class FakePsalm:
    """Stands in for _run_subprocess: records the call, writes the report."""

    def __init__(
        self,
        sarif_text: Optional[str] = POSITIVE,
        exit_code: int = 2,
        timed_out: bool = False,
    ):
        self.sarif_text, self.exit_code, self.timed_out = (
            sarif_text,
            exit_code,
            timed_out,
        )
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, scanner: PsalmScanner):
        def run(command, results_dir=None, env=None, timeout=None, cwd=None, **_):
            self.calls.append(
                {"argv": list(command), "env": env, "timeout": timeout, "cwd": cwd}
            )
            report_arg = next(a for a in command if a.startswith("--report="))
            path = Path(report_arg.split("=", 1)[1])
            if self.sarif_text is not None and not self.timed_out:
                text = self.sarif_text.replace(
                    TREE_ROOT_PLACEHOLDER,
                    Path(scanner.context.source_dir).absolute().as_posix(),
                )
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
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


def _scanner(source: Path, tmp_path: Path, **options) -> PsalmScanner:
    config = get_default_config()
    output = tmp_path / "out"
    return PsalmScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=config,
        ),
        config=PsalmScannerConfig(
            enabled=True, options=PsalmScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    (src / "src").mkdir(parents=True)
    (src / "src" / "db.php").write_text("<?php\necho 1;\n")
    return src


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(ps, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


def _run(scanner, fake, monkeypatch, target_type: str = "source"):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=Path(scanner.context.source_dir), target_type=target_type
    )


def _flag(argv: List[str], prefix: str) -> Optional[str]:
    for token in argv:
        if token.startswith(prefix):
            return token[len(prefix) :]
    return None


class TestCommunityPlugin:
    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert PsalmScannerConfig().enabled is True
        assert PsalmScannerConfig().name == "psalm"

    def test_the_builtin_config_does_not_declare_it(self):
        assert not hasattr(get_default_config().scanners, "psalm")

    def test_the_module_exports_the_scanner(self):
        assert ash_psalm_plugins.ASH_SCANNERS == [PsalmScanner]
        assert ash_psalm_plugins.ASH_REPORTERS == []

    def test_declared_execution_properties(self):
        assert PsalmScanner.python_only is False
        assert PsalmScanner.success_exit_codes == {0, 2}
        assert PsalmScanner.sandbox_requirements == SandboxRequirements()

    def test_taint_only_is_the_default(self):
        assert PsalmScannerConfigOptions().include_type_issues is False


class TestInvocation:
    def test_every_fixed_flag(self, tree, tmp_path, on_path, monkeypatch):
        scanner = _scanner(tree, tmp_path)
        fake = FakePsalm()
        _run(scanner, fake, monkeypatch)
        argv = fake.argv
        assert argv[0] == "psalm"
        for flag in ("--taint-analysis", "--no-cache", "--no-progress", "--monochrome"):
            assert flag in argv
        assert _flag(argv, "--report=").endswith("source/psalm.sarif")
        config = _flag(argv, "--config=")
        assert config.endswith("source/psalm-config/psalm.xml")
        assert _flag(argv, "--root=") == str(Path(config).parent.as_posix())

    @pytest.mark.parametrize(
        "forbidden",
        [
            "--init",
            "--plugin",
            "--alter",
            "--shepherd",
            "--language-server",
            "--use-baseline",
        ],
    )
    def test_flags_that_read_the_tree_or_reach_the_network_are_never_passed(
        self, tree, tmp_path, on_path, monkeypatch, forbidden
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakePsalm()
        _run(scanner, fake, monkeypatch)
        assert not any(
            t == forbidden or t.startswith(forbidden + "=") for t in fake.argv
        )

    def test_the_config_names_the_target_and_lives_outside_it(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakePsalm()
        _run(scanner, fake, monkeypatch)
        config = Path(_flag(fake.argv, "--config="))
        assert tree.absolute() not in config.parents
        xml = config.read_text(encoding="utf-8")
        assert 'runTaintAnalysis="true"' in xml
        assert f'<directory name="{tree.absolute().as_posix()}" />' in xml
        assert f"{tree.absolute().as_posix()}/vendor" in xml

    def test_a_psalm_xml_in_the_tree_is_not_what_is_passed(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        (tree / "psalm.xml").write_text("<psalm><plugins/></psalm>")
        scanner = _scanner(tree, tmp_path)
        fake = FakePsalm()
        _run(scanner, fake, monkeypatch)
        assert _flag(fake.argv, "--config=") != str(tree / "psalm.xml")
        assert "plugins" not in Path(_flag(fake.argv, "--config=")).read_text()

    def test_the_timeout_reaches_the_subprocess(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, scan_timeout=77)
        fake = FakePsalm()
        _run(scanner, fake, monkeypatch)
        assert fake.calls[0]["timeout"] == 77

    def test_the_working_directory_is_the_source_directory(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakePsalm()
        _run(scanner, fake, monkeypatch)
        assert Path(fake.calls[0]["cwd"]) == Path(tree)


class TestReport:
    def test_taint_findings_are_rated_and_located(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(_scanner(tree, tmp_path), FakePsalm(), monkeypatch)
        assert _findings(report) == POSITIVE_EXPECTED

    def test_negative_control_a_clean_run_has_no_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(
            _scanner(tree, tmp_path),
            FakePsalm(sarif_text=NEGATIVE, exit_code=0),
            monkeypatch,
        )
        assert _findings(report) == []

    def test_a_type_issue_is_dropped_unless_asked_for(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(
            _scanner(tree, tmp_path, include_type_issues=True), FakePsalm(), monkeypatch
        )
        assert ("1", "warning", "MEDIUM", "src/other.php", 3) in _findings(report)
        assert len(_findings(report)) == 4

    @pytest.mark.parametrize(
        ("is_taint", "level", "severity", "sarif_level"),
        [
            (True, "error", "HIGH", Level.error),
            (True, "note", "LOW", Level.note),
            (False, "error", "MEDIUM", Level.warning),
            (False, "note", "INFO", Level.none),
        ],
    )
    def test_the_severity_table_row_by_row(
        self, is_taint, level, severity, sarif_level
    ):
        assert PSALM_SEVERITY[(is_taint, level)] == (severity, sarif_level)

    @pytest.mark.parametrize("level", [None, "warning", "none"])
    def test_a_level_psalm_does_not_write_is_rated_as_an_error(
        self, tree, tmp_path, on_path, monkeypatch, level
    ):
        text = _sarif([_result("201", level, "src/db.php", 1)], RULES)
        report = _run(_scanner(tree, tmp_path), FakePsalm(sarif_text=text), monkeypatch)
        assert _findings(report) == [("201", "error", "HIGH", "src/db.php", 1)]

    def test_severity_and_sarif_level_agree_on_every_result(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(
            _scanner(tree, tmp_path, include_type_issues=True), FakePsalm(), monkeypatch
        )
        agreed = dict(PSALM_SEVERITY.values())
        for result in report.get_all_results():
            assert agreed[result.properties.issue_severity] == result.level

    def test_the_security_tag_is_set_on_taint_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(_scanner(tree, tmp_path), FakePsalm(), monkeypatch)
        for result in report.get_all_results():
            assert "security" in result.properties.tags


class TestExitStatus:
    @pytest.mark.parametrize("code", [0, 2])
    def test_zero_and_two_succeed(self, tree, tmp_path, on_path, monkeypatch, code):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakePsalm(exit_code=code), monkeypatch)
        assert scanner._exit_code_accepted()

    @pytest.mark.parametrize("code", [1, 3, 126, 137])
    def test_any_other_exit_fails_the_scan_even_with_a_report_on_disk(
        self, tree, tmp_path, on_path, monkeypatch, code
    ):
        with pytest.raises(ScannerError):
            _run(_scanner(tree, tmp_path), FakePsalm(exit_code=code), monkeypatch)

    def test_a_run_that_wrote_no_report_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        with pytest.raises(ScannerError):
            _run(
                _scanner(tree, tmp_path),
                FakePsalm(sarif_text=None, exit_code=0),
                monkeypatch,
            )

    def test_a_timeout_fails_the_scan_and_says_so(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, scan_timeout=45)
        with pytest.raises(ScannerError) as raised:
            _run(scanner, FakePsalm(exit_code=124, timed_out=True), monkeypatch)
        assert "timed out" in str(raised.value)

    def test_a_report_left_by_an_earlier_run_is_removed_before_the_next_one(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakePsalm(), monkeypatch)
        stale = Path(scanner.results_dir) / "source" / "psalm.sarif"
        assert stale.exists()
        with pytest.raises(ScannerError):
            _run(scanner, FakePsalm(sarif_text=None, exit_code=0), monkeypatch)


class TestMalformedOutput:
    @pytest.mark.parametrize(
        "text",
        ["not json at all", "[1, 2, 3]", '{"version": "2.1.0"}', '{"runs": []}'],
    )
    def test_output_that_is_not_a_sarif_report_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch, text
    ):
        with pytest.raises(ScannerError):
            _run(
                _scanner(tree, tmp_path),
                FakePsalm(sarif_text=text, exit_code=2),
                monkeypatch,
            )

    def test_an_empty_report_file_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        with pytest.raises(ScannerError):
            _run(
                _scanner(tree, tmp_path),
                FakePsalm(sarif_text="", exit_code=0),
                monkeypatch,
            )


class TestToolAbsent:
    def test_missing_psalm_is_reported_as_unsatisfied_dependencies(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(ps, "find_executable", lambda cmd: None)
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is False

    def test_missing_php_alone_is_also_unsatisfied(self, tree, tmp_path, monkeypatch):
        monkeypatch.setattr(
            ps, "find_executable", lambda cmd: None if cmd == "php" else f"/x/{cmd}"
        )
        scanner = _scanner(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is False
        assert "php" in scanner.missing_dependency_reason()

    def test_both_present_satisfies_them(self, tree, tmp_path, on_path):
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is True

    def test_a_recorded_unavailable_reason_wins(self, tree, tmp_path, on_path):
        scanner = _scanner(tree, tmp_path)
        scanner.dependency_unavailable_reason = "not offered here"
        assert scanner.validate_plugin_dependencies() is False


class TestNothingToScan:
    def test_a_tree_without_php_has_a_reason(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "a.py").write_text("print(1)\n")
        assert "no PHP files" in _scanner(src, tmp_path).nothing_to_scan_reason()

    def test_a_php_file_means_there_is_something_to_scan(self, tree, tmp_path):
        assert _scanner(tree, tmp_path).nothing_to_scan_reason() is None

    def test_php_only_under_vendor_does_not_count(self, tmp_path):
        src = tmp_path / "src"
        (src / "vendor" / "pkg").mkdir(parents=True)
        (src / "vendor" / "pkg" / "x.php").write_text("<?php\n")
        assert _scanner(src, tmp_path).nothing_to_scan_reason() is not None


class TestInstall:
    def test_install_commands_cover_every_published_platform(self, tmp_path):
        from automated_security_helper.utils import tool_downloads

        if "psalm" not in tool_downloads.downloadable_tools():
            pytest.skip("the psalm download table is added with the registration")
        scanner = _scanner(tmp_path, tmp_path)
        for platform, arch in tool_downloads.supported_platforms("psalm"):
            commands = scanner.get_installation_commands(platform, arch)
            assert commands, f"no install command for {platform}/{arch}"
            assert "psalm" in commands[0]
