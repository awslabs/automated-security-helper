# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""TflintScanner: the invocation, exit status, and the SARIF it reads.

The SARIF below is built by hand to the shape TFLint's formatter writes
(``formatter/sarif.go`` in terraform-linters/tflint): a ``tflint`` run holding lint
issues and a ``tflint-errors`` run holding diagnostics. It covers severities the
captured fixtures (tests/test_data/scanners/tflint/captured, a real 0.66.0 run) did
not produce, and the expected findings are written out here, not derived from the
code under test. The scan() tests replace the subprocess with a fake, so they run on
every platform without the binary.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_tflint_plugins
from automated_security_helper.plugin_modules.ash_tflint_plugins import (
    tflint_scanner as ts,
)
from automated_security_helper.plugin_modules.ash_tflint_plugins.tflint_scanner import (
    TflintScanner,
    TflintScannerConfig,
    TflintScannerConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.sandbox.policy import (
    SandboxRequirements,
    build_scanner_policy,
)
from automated_security_helper.utils.tool_downloads import downloadable_tools

pytestmark = pytest.mark.unit

_CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "tflint"
    / "captured"
)


def _result(rule: str, level: Optional[str], uri: str, line: int) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "ruleId": rule,
        "message": {"text": f"{rule} message"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {
                        "startLine": line,
                        "startColumn": 1,
                        "endLine": line,
                        "endColumn": 10,
                    },
                }
            }
        ],
    }
    if level is not None:
        out["level"] = level
    return out


def _sarif(
    results: List[Dict[str, Any]], errors: Optional[List[Dict[str, Any]]] = None
) -> str:
    """Two runs, as TFLint's SARIF formatter writes them."""
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "tflint",
                            "version": "0.66.0",
                            "informationUri": "https://github.com/terraform-linters/tflint",
                        }
                    },
                    "results": results,
                },
                {
                    "tool": {
                        "driver": {
                            "name": "tflint-errors",
                            "version": "0.66.0",
                            "informationUri": "https://github.com/terraform-linters/tflint",
                        }
                    },
                    "results": errors or [],
                },
            ],
        }
    )


#: One finding per TFLint severity, in two files.
POSITIVE = _sarif(
    [
        _result("terraform_unused_declarations", "warning", "main.tf", 3),
        _result("terraform_deprecated_index", "error", "modules/net/main.tf", 7),
        _result("terraform_required_version", "note", "modules/net/main.tf", 1),
    ]
)
#: What POSITIVE must produce, written by hand: (rule, level, ASH severity, uri, line).
POSITIVE_EXPECTED = [
    ("terraform_unused_declarations", "warning", "MEDIUM", "main.tf", 3),
    ("terraform_deprecated_index", "error", "HIGH", "modules/net/main.tf", 7),
    ("terraform_required_version", "note", "LOW", "modules/net/main.tf", 1),
]
#: The negative control: the same two runs, nothing found.
NEGATIVE = _sarif([])


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


class FakeTflint:
    """Stands in for _run_subprocess: records argv, writes TFLint's stdout log."""

    def __init__(
        self,
        stdout: Optional[str] = POSITIVE,
        exit_code: int = 2,
        extra: Optional[Dict[str, Any]] = None,
    ):
        self.stdout, self.exit_code, self.extra = stdout, exit_code, extra or {}
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, cwd=None, **_):
            self.calls.append(
                {"argv": list(command), "env": env, "timeout": timeout, "cwd": cwd}
            )
            if self.stdout is not None:
                path = Path(results_dir) / f"{scanner.__class__.__name__}.stdout.log"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(self.stdout, encoding="utf-8")
            scanner.exit_code = self.exit_code
            response = {"returncode": self.exit_code, "stdout": "", "stderr": ""}
            response.update(self.extra)
            return response

        return run

    @property
    def argv(self) -> List[str]:
        return self.calls[0]["argv"]


def _scanner(source: Path, tmp_path: Path, **options) -> TflintScanner:
    output = tmp_path / "out"
    return TflintScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=get_default_config(),
        ),
        config=TflintScannerConfig(
            enabled=True, options=TflintScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    (src / "modules" / "net").mkdir(parents=True)
    (src / "main.tf").write_text('variable "unused" {}\n')
    (src / "modules" / "net" / "main.tf").write_text("# module\n")
    return src


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(ts, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


def _run(scanner, fake, monkeypatch, target=None, target_type="source"):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=Path(target or scanner.context.source_dir), target_type=target_type
    )


class TestCommunityPlugin:
    def test_on_by_default_once_its_module_is_listed(self):
        assert TflintScannerConfig().enabled is True
        assert TflintScannerConfig().name == "tflint"

    def test_the_module_exports_the_scanner(self):
        assert ash_tflint_plugins.ASH_SCANNERS == [TflintScanner]
        assert ash_tflint_plugins.ASH_REPORTERS == []

    def test_execution_declarations(self):
        assert TflintScanner.python_only is False
        assert TflintScanner.success_exit_codes == {0, 2}
        assert TflintScanner.offline_strategy.name == "BUNDLED"


class TestInvocation:
    def test_every_fixed_flag(self, tree, tmp_path, monkeypatch, on_path):
        fake = FakeTflint()
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        argv = fake.argv
        assert argv[0] == "tflint"
        assert "--format=sarif" in argv
        assert "--recursive" in argv
        assert "--chdir=." in argv
        assert "--no-color" in argv
        config = next(a for a in argv if a.startswith("--config="))
        assert Path(config.split("=", 1)[1]).is_absolute()

    def test_every_option_is_one_flag_equals_value_token(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        fake = FakeTflint()
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        for token in fake.argv[1:]:
            assert token.startswith("--")
        assert "--init" not in fake.argv

    def test_the_config_is_empty_and_outside_the_tree(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        (tree / ".tflint.hcl").write_text(
            'rule "terraform_unused_declarations" {\n  enabled = false\n}\n'
        )
        seen: Dict[str, str] = {}

        class Spy(FakeTflint):
            def __call__(self, scanner):
                inner = super().__call__(scanner)

                def run(command, **kw):
                    cfg = next(a for a in command if a.startswith("--config="))
                    path = Path(cfg.split("=", 1)[1])
                    seen["path"] = str(path)
                    seen["text"] = path.read_text(encoding="utf-8")
                    return inner(command, **kw)

                return run

        _run(_scanner(tree, tmp_path), Spy(), monkeypatch)
        assert not Path(seen["path"]).is_relative_to(tree)
        assert "enabled" not in seen["text"]
        assert seen["text"].lstrip().startswith("#")

    @pytest.mark.parametrize(
        "flag",
        [
            "--init",
            "--force",
            "--minimum-failure-severity",
            "--enable-plugin",
            "--call-module-type=all",
        ],
    )
    def test_flags_that_hide_findings_or_reach_the_network_are_never_passed(
        self, flag, tree, tmp_path, monkeypatch, on_path
    ):
        fake = FakeTflint()
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert not any(a.startswith(flag) for a in fake.argv)

    def test_converted_target_is_an_absolute_chdir(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        converted = tmp_path / "converted"
        converted.mkdir()
        (converted / "x.tf").write_text("# x\n")
        fake = FakeTflint()
        _run(
            _scanner(tree, tmp_path),
            fake,
            monkeypatch,
            target=converted,
            target_type="converted",
        )
        assert f"--chdir={converted.absolute().as_posix()}" in fake.argv

    def test_a_missing_target_never_reaches_the_tool(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        fake = FakeTflint()
        _run(
            _scanner(tree, tmp_path),
            fake,
            monkeypatch,
            target=tmp_path / "does-not-exist",
        )
        assert fake.calls == []

    def test_stale_report_is_removed_before_the_run(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        scanner = _scanner(tree, tmp_path)
        stale = (
            Path(scanner.results_dir).absolute() / "source" / "TflintScanner.stdout.log"
        )
        stale.parent.mkdir(parents=True, exist_ok=True)
        stale.write_text(POSITIVE)
        with pytest.raises(ScannerError):
            _run(scanner, FakeTflint(stdout=None, exit_code=0), monkeypatch)


class TestReport:
    def test_positive_is_rated_and_located(self, tree, tmp_path, monkeypatch, on_path):
        report = _run(_scanner(tree, tmp_path), FakeTflint(), monkeypatch)
        assert _findings(report) == POSITIVE_EXPECTED

    def test_negative_control_has_no_findings(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        report = _run(
            _scanner(tree, tmp_path),
            FakeTflint(stdout=NEGATIVE, exit_code=0),
            monkeypatch,
        )
        assert _findings(report) == []

    def test_the_error_run_is_not_kept_when_empty(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        report = _run(_scanner(tree, tmp_path), FakeTflint(), monkeypatch)
        names = [r.tool.driver.name for r in report.runs]
        assert names == ["tflint"]

    def test_tags_kind_and_levels_agree_with_severity(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        report = _run(_scanner(tree, tmp_path), FakeTflint(), monkeypatch)
        for result in report.get_all_results():
            assert "terraform" in result.properties.tags
            assert getattr(result.kind, "value", result.kind) == "fail"
            level = getattr(result.level, "value", result.level)
            severity = result.properties.issue_severity
            assert (level, severity) in {
                ("error", "HIGH"),
                ("warning", "MEDIUM"),
                ("note", "LOW"),
            }

    def test_a_result_without_a_level_is_medium(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        sarif = _sarif([_result("terraform_x", None, "main.tf", 2)])
        report = _run(_scanner(tree, tmp_path), FakeTflint(stdout=sarif), monkeypatch)
        assert _findings(report) == [("terraform_x", "warning", "MEDIUM", "main.tf", 2)]

    def test_an_absolute_uri_is_made_relative_to_the_target(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        uri = (tree / "main.tf").absolute().as_posix()
        sarif = _sarif([_result("terraform_x", "warning", uri, 2)])
        report = _run(_scanner(tree, tmp_path), FakeTflint(stdout=sarif), monkeypatch)
        assert _findings(report)[0][3] == "main.tf"

    def test_error_run_results_fail_the_scan_without_quoting_them(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        sarif = _sarif(
            [],
            errors=[
                {
                    "ruleId": "Unsupported argument",
                    "level": "error",
                    "message": {"text": "SECRET-LOOKING-TEXT-FROM-THE-TREE"},
                }
            ],
        )
        with pytest.raises(ScannerError) as err:
            _run(
                _scanner(tree, tmp_path),
                FakeTflint(stdout=sarif, exit_code=2),
                monkeypatch,
            )
        assert "SECRET-LOOKING-TEXT" not in str(err.value)
        assert "tflint-errors" in str(err.value)


class TestExitStatus:
    @pytest.mark.parametrize("code,stdout", [(0, NEGATIVE), (2, POSITIVE)])
    def test_zero_and_two_succeed(
        self, code, stdout, tree, tmp_path, monkeypatch, on_path
    ):
        report = _run(
            _scanner(tree, tmp_path),
            FakeTflint(stdout=stdout, exit_code=code),
            monkeypatch,
        )
        assert isinstance(report, SarifReport)

    @pytest.mark.parametrize("code", [1, 126, 137])
    def test_other_codes_fail_even_with_a_report_on_disk(
        self, code, tree, tmp_path, monkeypatch, on_path
    ):
        with pytest.raises(ScannerError):
            _run(
                _scanner(tree, tmp_path),
                FakeTflint(stdout=POSITIVE, exit_code=code),
                monkeypatch,
            )

    def test_a_timeout_fails_the_scan_and_says_so(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        fake = FakeTflint(stdout=None, exit_code=124, extra={"timed_out": True})
        scanner = _scanner(tree, tmp_path, scan_timeout=17)
        with pytest.raises(ScannerError) as err:
            _run(scanner, fake, monkeypatch)
        assert "timed out" in str(err.value).lower()
        assert 0 < fake.calls[0]["timeout"] <= 17

    def test_tool_stderr_is_not_copied_into_errors(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeTflint(extra={"stderr": "line from the scanned file"})
        _run(scanner, fake, monkeypatch)
        assert not any("scanned file" in e for e in scanner.errors)


class TestMalformedOutput:
    @pytest.mark.parametrize(
        "text",
        ["not json at all", '{"version": "2.1.0", "runs": [', "", "{}", '{"runs": []}'],
    )
    def test_unusable_output_fails_the_scan(
        self, text, tree, tmp_path, monkeypatch, on_path
    ):
        with pytest.raises(ScannerError):
            _run(
                _scanner(tree, tmp_path),
                FakeTflint(stdout=text, exit_code=0),
                monkeypatch,
            )

    def test_no_output_file_fails_the_scan(self, tree, tmp_path, monkeypatch, on_path):
        with pytest.raises(ScannerError):
            _run(
                _scanner(tree, tmp_path),
                FakeTflint(stdout=None, exit_code=0),
                monkeypatch,
            )


class TestToolAbsent:
    def test_missing_binary_is_reported_unavailable(self, tree, tmp_path, monkeypatch):
        monkeypatch.setattr(ts, "find_executable", lambda cmd: None)
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is False

    def test_present_binary_is_available(self, tree, tmp_path, on_path):
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is True


class TestNothingToScan:
    def test_a_tree_without_terraform_files_has_a_reason(self, tmp_path):
        src = tmp_path / "plain"
        src.mkdir()
        (src / "a.py").write_text("x = 1\n")
        assert "no Terraform files" in _scanner(src, tmp_path).nothing_to_scan_reason()

    def test_a_tree_with_terraform_files_has_none(self, tree, tmp_path):
        assert _scanner(tree, tmp_path).nothing_to_scan_reason() is None

    def test_terraform_json_counts(self, tmp_path):
        src = tmp_path / "j"
        src.mkdir()
        (src / "main.tf.json").write_text("{}")
        assert _scanner(src, tmp_path).nothing_to_scan_reason() is None

    def test_hidden_directories_do_not_count(self, tmp_path):
        src = tmp_path / "h"
        (src / ".hidden").mkdir(parents=True)
        (src / ".hidden" / "x.tf").write_text("# x\n")
        assert _scanner(src, tmp_path).nothing_to_scan_reason() is not None


_PINNED = "tflint" in downloadable_tools()


class TestInstall:
    @pytest.mark.skipif(
        _PINNED,
        reason="only meaningful while utils/tool_downloads.py has no tflint rows",
    )
    def test_without_pin_rows_the_scanner_still_builds_and_cannot_install(
        self, tree, tmp_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        assert scanner.custom_install_commands == {}
        monkeypatch.setattr(ts, "find_executable", lambda cmd: None)
        assert scanner.validate_plugin_dependencies() is False

    @pytest.mark.skipif(
        not _PINNED,
        reason="needs the tflint rows in utils/tool_downloads.py (PR notes)",
    )
    def test_install_commands_cover_every_published_platform(self, tree, tmp_path):
        commands = _scanner(tree, tmp_path).custom_install_commands
        published = {
            ("linux", "amd64"),
            ("linux", "arm64"),
            ("darwin", "amd64"),
            ("darwin", "arm64"),
            ("windows", "amd64"),
        }
        for platform_name, arch in published:
            assert commands[platform_name][arch], (platform_name, arch)
        # tflint publishes no windows arm64 asset: absent, not an empty list.
        assert "arm64" not in commands["windows"]


class TestCapturedReport:
    """The adapter over output a real TFLint 0.66.0 wrote."""

    @staticmethod
    def _captured(name: str) -> str:
        return (_CAPTURED / name).read_text(encoding="utf-8")

    def test_the_captured_positive_is_rated_and_located(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        fake = FakeTflint(stdout=self._captured("positive.sarif"))
        report = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert _findings(report) == [
            ("terraform_required_version", "warning", "MEDIUM", "main.tf", 3),
            ("terraform_typed_variables", "warning", "MEDIUM", "main.tf", 1),
            ("terraform_unused_declarations", "warning", "MEDIUM", "main.tf", 1),
        ]
        for result in report.get_all_results():
            assert {"terraform", "lint"} <= set(result.properties.tags)

    def test_the_captured_negative_has_no_findings(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        fake = FakeTflint(stdout=self._captured("negative.sarif"), exit_code=0)
        report = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert _findings(report) == []

    def test_every_documented_level_maps_and_an_unknown_one_is_high(
        self, tree, tmp_path
    ):
        # The captured run produced warnings only; the other levels are hand-built.
        assert ts.TFLINT_LEVEL_MAP["error"][0] == "HIGH"
        assert ts.TFLINT_LEVEL_MAP["warning"][0] == "MEDIUM"
        assert ts.TFLINT_LEVEL_MAP["note"][0] == "LOW"
        sarif = _sarif([_result("terraform_x", "none", "main.tf", 2)])
        report = _scanner(tree, tmp_path)._post_process_sarif(
            SarifReport.model_validate(json.loads(sarif)), [], tree
        )
        severity = [r.properties.issue_severity for r in report.get_all_results()]
        assert severity == ["HIGH"]


class TestFacetsDeclaration:
    def test_the_register_rows_are_declared_on_the_class_itself(self):
        assert "facets" in vars(TflintScanner)
        assert "operational_facets" in vars(TflintScanner)
        assert TflintScanner.operational_facets.scanner_name == "tflint"
        assert TflintScanner.operational_facets.exit_codes.success_exit_codes == (0, 2)


class TestSandboxRequirements:
    def test_the_strict_default_is_declared_and_the_policy_has_no_network(
        self, tmp_path
    ):
        assert TflintScanner.sandbox_requirements == SandboxRequirements()
        source = tmp_path / "src"
        output = source / ".ash" / "ash_output"
        output.mkdir(parents=True)
        policy = build_scanner_policy(
            "tflint",
            TflintScanner.sandbox_requirements,
            argv0=sys.executable,
            source_dir=source,
            output_dir=output,
            results_dir=output / "scanners" / "tflint",
            scan_target=source,
            cwd=source,
            offline=False,
            network_scanners=None,
        )
        assert policy.network is False
