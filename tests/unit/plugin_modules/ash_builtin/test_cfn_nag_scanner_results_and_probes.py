"""cfn-nag: the install probe, the grade of a run, and what the report carries.

Pinned here against ``CfnNagScanner`` with only its dependency probe and
subprocess boundary faked, as ``test_cfn_nag_scanner_per_template_failures.py``
does:

* on macOS the ``cc``/``gcc``/``clang`` stubs that offer to install the Command
  Line Tools passed the compiler probe, so the gem install was declared and failed
  building psych; the probe asks for the developer directory now;
* with ``cfn_nag_scan`` already on PATH the "cannot be installed here" line was
  logged at WARNING on every scanner construction (the official image purges its
  compiler after installing the gem); it is DEBUG then;
* a template with exactly 127 (mod 256) failing violations made the recorded exit
  code equal ASH's spawn-failure marker and graded a complete run unsuccessful;
  the grade reads the recorded spawn failure instead;
* a damaged template (a YAML syntax error) was skipped at TRACE and never named in
  the results; it is named on the scanner's error stream;
* two templates whose paths normalize to one name shared a results directory, so
  the later one's logs overwrote the earlier one's;
* under a relative ``--output-dir`` the staged copy's path was relative too, and
  cfn_nag_scan, run in the source directory, could not find it;
* the merged report never carried cfn_nag's rule definitions (the branch meant to
  keep the first report's driver was dead);
* a scan that aborted through the outer handler recorded no end time, so the
  executor computed its duration from the previous target's;
* the module's ``__main__`` block called ``scan()`` without a target type and
  dereferenced a possible ``False``; it is gone.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    cfn_nag_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner import (
    CfnNagScanner,
    CfnNagScannerConfig,
    _unique_name,
)

pytestmark = pytest.mark.unit

CFN_TEMPLATE = """Resources:
  MyRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: placeholder-role
"""

DAMAGED_TEMPLATE = "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  Q: [\n"


def _sarif(rule_id="F38", uri="template.yaml") -> str:
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "cfn_nag",
                            "rules": [
                                {"id": rule_id, "shortDescription": {"text": "a rule"}}
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": rule_id,
                            "level": "error",
                            "message": {"text": f"{rule_id} triggered"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": uri},
                                        "region": {"startLine": 3},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    )


@pytest.fixture
def plugin_context(tmp_path):
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    context.source_dir.mkdir(parents=True)
    context.output_dir.mkdir(parents=True)
    context.work_dir.mkdir(parents=True)
    return context


@pytest.fixture
def scanner(plugin_context):
    return CfnNagScanner(context=plugin_context, config=CfnNagScannerConfig())


@pytest.fixture
def deps_available():
    with patch.object(
        CfnNagScanner, "validate_plugin_dependencies", autospec=True, return_value=True
    ) as probe:
        yield probe


@pytest.fixture
def subprocess_double():
    with patch.object(CfnNagScanner, "_run_subprocess", autospec=True) as double:
        double.return_value = {"stdout": _sarif(), "stderr": "", "returncode": 0}
        yield double


def test_the_macos_probe_asks_for_the_developer_tools_not_the_stubs():
    with (
        patch.object(cfn_nag_scanner.platform, "system", return_value="Darwin"),
        patch.object(cfn_nag_scanner, "find_executable", return_value="/usr/bin/cc"),
        patch.object(
            cfn_nag_scanner, "_macos_developer_tools_present", return_value=False
        ),
    ):
        missing = CfnNagScanner._missing_gem_prerequisites()
    assert any("Command Line Tools" in line for line in missing), missing
    with (
        patch.object(cfn_nag_scanner.platform, "system", return_value="Darwin"),
        patch.object(cfn_nag_scanner, "find_executable", return_value="/usr/bin/cc"),
        patch.object(
            cfn_nag_scanner, "_macos_developer_tools_present", return_value=True
        ),
    ):
        assert CfnNagScanner._missing_gem_prerequisites() == []


def test_the_developer_tools_probe_reads_the_developer_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("DEVELOPER_DIR", str(tmp_path))
    # The fixed locations are taken out of the probe, so only DEVELOPER_DIR decides.
    monkeypatch.setattr(cfn_nag_scanner, "_MACOS_DEVELOPER_DIRS", ())
    assert cfn_nag_scanner._macos_developer_tools_present() is False
    (tmp_path / "usr" / "bin").mkdir(parents=True)
    (tmp_path / "usr" / "bin" / "clang").write_text("", encoding="utf-8")
    assert cfn_nag_scanner._macos_developer_tools_present() is True


def test_the_install_warning_is_debug_when_cfn_nag_is_already_installed(
    plugin_context, caplog
):
    def found(name):
        return "/opt/ash/bin/cfn_nag_scan" if name == "cfn_nag_scan" else None

    with (
        patch.object(cfn_nag_scanner, "find_executable", side_effect=found),
        caplog.at_level(logging.DEBUG, logger="ash"),
    ):
        CfnNagScanner(context=plugin_context, config=CfnNagScannerConfig())
    lines = [r for r in caplog.records if "cannot be installed here" in r.getMessage()]
    assert lines, "the probe should still say the prerequisites are missing"
    assert all(r.levelno == logging.DEBUG for r in lines), [r.levelno for r in lines]
    assert "already on PATH" in lines[0].getMessage()


def test_the_install_warning_stays_a_warning_when_cfn_nag_is_absent(
    plugin_context, caplog
):
    with (
        patch.object(cfn_nag_scanner, "find_executable", return_value=None),
        caplog.at_level(logging.DEBUG, logger="ash"),
    ):
        CfnNagScanner(context=plugin_context, config=CfnNagScannerConfig())
    lines = [r for r in caplog.records if "cannot be installed here" in r.getMessage()]
    assert lines and lines[0].levelno == logging.WARNING


def test_a_violation_count_of_127_is_a_completed_run(scanner):
    scanner.exit_code = 127
    assert scanner._sarif_exit_code_accepted() is True
    scanner._scan_spawn_failure = "the command never ran"
    assert scanner._sarif_exit_code_accepted() is False


def test_a_damaged_template_is_named_in_the_results(
    scanner, deps_available, subprocess_double
):
    (scanner.context.work_dir / "broken.yaml").write_text(DAMAGED_TEMPLATE)
    scanner.scan(target=scanner.context.work_dir, target_type="converted")
    assert any("could not be parsed" in line for line in scanner.errors), scanner.errors
    assert any("broken.yaml" in line for line in scanner.errors)
    assert subprocess_double.call_count == 0


def test_unique_name_numbers_a_repeated_name():
    used: dict = {}
    assert _unique_name("a__b__yaml", used) == "a__b__yaml"
    assert _unique_name("a__b__yaml", used) == "a__b__yaml-2"
    assert _unique_name("a__b__yaml", used) == "a__b__yaml-3"
    assert _unique_name("other", used) == "other"


def test_two_templates_with_one_normalized_name_get_two_results_directories(
    scanner, deps_available, subprocess_double
):
    (scanner.context.work_dir / "a").mkdir()
    (scanner.context.work_dir / "a" / "b.yaml").write_text(CFN_TEMPLATE)
    (scanner.context.work_dir / "a__b.yaml").write_text(CFN_TEMPLATE)
    scanner.scan(target=scanner.context.work_dir, target_type="converted")
    dirs = [call.kwargs["results_dir"] for call in subprocess_double.call_args_list]
    assert len(dirs) == 2 and len(set(map(str, dirs))) == 2, dirs


def test_the_staged_copy_is_absolute_under_a_relative_output_directory(
    tmp_path, monkeypatch, deps_available, subprocess_double
):
    monkeypatch.chdir(tmp_path)
    context = PluginContext(
        source_dir=Path("src"),
        output_dir=Path("rel-out"),
        work_dir=Path("rel-out") / "work",
        config=get_default_config(),
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "stack.yaml").write_text(CFN_TEMPLATE)
    scanner = CfnNagScanner(context=context, config=CfnNagScannerConfig())
    scanner.scan(target=Path("src"), target_type="source")
    command = subprocess_double.call_args.kwargs["command"]
    staged = command[command.index("--input-path") + 1]
    assert os.path.isabs(staged), command


def test_the_merged_report_carries_the_rule_definitions(
    scanner, deps_available, subprocess_double
):
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)
    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")
    rules = report.runs[0].tool.driver.rules or []
    assert [rule.id for rule in rules] == ["F38"]


def test_an_aborted_scan_records_its_end_time(scanner, deps_available):
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)
    assert scanner.end_time is None
    with (
        patch.object(
            cfn_nag_scanner,
            "cloudformation_candidate_files",
            side_effect=RuntimeError("walk failed"),
        ),
        pytest.raises(ScannerError, match="walk failed"),
    ):
        scanner.scan(target=scanner.context.work_dir, target_type="converted")
    assert scanner.end_time is not None


def test_the_module_has_no_main_block():
    source = Path(cfn_nag_scanner.__file__).read_text(encoding="utf-8")
    assert '__name__ == "__main__"' not in source
