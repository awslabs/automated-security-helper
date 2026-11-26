# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""SecretlintScanner: the invocation, the exit status, and the report.

The subprocess is replaced by a fake that writes SARIF in the shape the
``@secretlint/secretlint-formatter-sarif`` source produces (read from its repository
at v14.0.1; the expected findings below are written out by hand from that shape).
The tests run on every platform without Node.js or Secretlint installed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_secretlint_plugins
from automated_security_helper.plugin_modules.ash_secretlint_plugins import (
    secretlint_scanner as ss,
)
from automated_security_helper.plugin_modules.ash_secretlint_plugins.secretlint_scanner import (
    SecretlintScanner,
    SecretlintScannerConfig,
    SecretlintScannerConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.sandbox.policy import SandboxRequirements

pytestmark = pytest.mark.unit


def _result(rule: str, level: str, uri: str, line: int, text: str) -> Dict[str, Any]:
    return {
        "level": level,
        "message": {"text": text},
        "ruleId": rule,
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {
                        "startLine": line,
                        "startColumn": 8,
                        "endLine": line,
                        "endColumn": 48,
                    },
                }
            }
        ],
    }


def _sarif(results: List[Dict[str, Any]]) -> str:
    rule_ids = []
    for r in results:
        if r["ruleId"] not in rule_ids:
            rule_ids.append(r["ruleId"])
    return json.dumps(
        {
            "version": "2.1.0",
            "$schema": "http://json.schemastore.org/sarif-2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "secretlint",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/secretlint/secretlint",
                            "rules": [
                                {
                                    "id": rid,
                                    "shortDescription": {
                                        "text": f"secretlint rule({rid}) error"
                                    },
                                }
                                for rid in rule_ids
                            ],
                        }
                    },
                    "results": results,
                }
            ],
        }
    )


AWS_RULE = (
    "@secretlint/secretlint-rule-preset-recommend > @secretlint/secretlint-rule-aws"
)
GH_RULE = (
    "@secretlint/secretlint-rule-preset-recommend > @secretlint/secretlint-rule-github"
)
PRIVKEY_RULE = (
    "@secretlint/secretlint-rule-preset-recommend > "
    "@secretlint/secretlint-rule-privatekey"
)

POSITIVE = _sarif(
    [
        _result(AWS_RULE, "error", "app.py", 4, "found AWS Access Key ID: AKIA****"),
        _result(
            GH_RULE, "error", "services/settings.py", 3, "found GitHub Token: ghp_****"
        ),
        _result(PRIVKEY_RULE, "warning", "keys/dev.pem", 1, "found private key"),
        _result(AWS_RULE, "note", "notes.txt", 2, "found AWS Account ID"),
    ]
)
NEGATIVE = _sarif([])

#: Written out by hand from POSITIVE: (ruleId, SARIF level, ASH severity, uri, line).
POSITIVE_EXPECTED = [
    (AWS_RULE, "error", "CRITICAL", "app.py", 4),
    (GH_RULE, "error", "CRITICAL", "services/settings.py", 3),
    (PRIVKEY_RULE, "warning", "MEDIUM", "keys/dev.pem", 1),
    (AWS_RULE, "note", "LOW", "notes.txt", 2),
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


class FakeSecretlint:
    """Stands in for _run_subprocess: records argv, writes the --output file."""

    def __init__(
        self,
        sarif_text: Optional[str] = POSITIVE,
        exit_code: int = 0,
        extra: Optional[Dict[str, Any]] = None,
        stderr: str = "",
    ):
        self.sarif_text, self.exit_code = sarif_text, exit_code
        self.extra, self.stderr = extra or {}, stderr
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, cwd=None, **_):
            self.calls.append(
                {"argv": list(command), "env": env, "timeout": timeout, "cwd": cwd}
            )
            output_arg = next(a for a in command if a.startswith("--output="))
            path = Path(output_arg.split("=", 1)[1])
            if self.sarif_text is not None:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(self.sarif_text, encoding="utf-8")
            scanner.exit_code = self.exit_code
            return {
                "returncode": self.exit_code,
                "stdout": "",
                "stderr": self.stderr,
                **self.extra,
            }

        return run

    @property
    def argv(self) -> List[str]:
        return self.calls[0]["argv"]


def _scanner(source: Path, tmp_path: Path) -> SecretlintScanner:
    output = tmp_path / "out"
    return SecretlintScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=get_default_config(),
        ),
        config=SecretlintScannerConfig(
            enabled=True, options=SecretlintScannerConfigOptions()
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    (src / "services").mkdir(parents=True)
    (src / "app.py").write_text("print(1)\n")
    (src / "services" / "settings.py").write_text("DEBUG = False\n")
    return src


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(ss, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


def _run(scanner, fake, monkeypatch, target=None, target_type="source"):
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
        assert SecretlintScannerConfig().enabled is True
        assert SecretlintScannerConfig().name == "secretlint"

    def test_the_builtin_config_does_not_declare_it(self):
        assert not hasattr(get_default_config().scanners, "secretlint")

    def test_the_module_exports_the_scanner(self):
        assert ash_secretlint_plugins.ASH_SCANNERS == [SecretlintScanner]
        assert ash_secretlint_plugins.ASH_REPORTERS == []

    def test_the_sandbox_declaration_is_the_strict_default(self):
        assert SecretlintScanner.sandbox_requirements == SandboxRequirements()
        assert SecretlintScanner.sandbox_requirements.network is False


class TestInvocation:
    def test_every_fixed_flag_and_the_scan_glob(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeSecretlint()
        _run(scanner, fake, monkeypatch)
        argv = fake.argv
        assert argv[0] == "secretlint"
        for expected in (
            f"--format={ss.SARIF_FORMATTER}",
            f"--secretlintrcJSON={ss.RC_JSON}",
            "--no-gitignore",
            "--no-color",
            "--no-terminalLink",
        ):
            assert expected in argv
        assert argv[-1] == "**/*"
        assert fake.calls[0]["cwd"] is None, "the run starts in the source directory"

    def test_the_rc_is_the_recommended_preset_and_nothing_from_the_tree(self):
        assert json.loads(ss.RC_JSON) == {
            "rules": [{"id": "@secretlint/secretlint-rule-preset-recommend"}]
        }

    def test_a_converted_target_is_given_as_an_absolute_glob(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        converted = tmp_path / "out" / "converted"
        converted.mkdir(parents=True)
        (converted / "a.txt").write_text("x\n")
        scanner = _scanner(tree, tmp_path)
        fake = FakeSecretlint(sarif_text=NEGATIVE)
        _run(scanner, fake, monkeypatch, target=converted, target_type="converted")
        assert fake.argv[-1] == f"{converted.absolute().as_posix()}/**/*"

    @pytest.mark.parametrize(
        "forbidden", ["--no-maskSecrets", "--secretlintrc", "--secretlintignore"]
    )
    def test_flags_that_unmask_or_read_tree_config_are_never_passed(
        self, tree, tmp_path, on_path, monkeypatch, forbidden
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeSecretlint()
        _run(scanner, fake, monkeypatch)
        assert not any(
            a == forbidden or a.startswith(f"{forbidden}=") for a in fake.argv
        )

    def test_a_missing_target_never_reaches_the_tool(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeSecretlint()
        _run(scanner, fake, monkeypatch, target=tmp_path / "gone")
        assert fake.calls == []

    def test_a_tree_ignore_file_is_logged_as_a_warning(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        (tree / ".secretlintignore").write_text("secrets/\n")
        scanner = _scanner(tree, tmp_path)
        logged: List[str] = []
        monkeypatch.setattr(
            scanner,
            "_plugin_log",
            lambda *msgs, **kw: logged.append(" ".join(str(m) for m in msgs)),
        )
        _run(scanner, FakeSecretlint(), monkeypatch)
        assert any(".secretlintignore" in m and "not reported" in m for m in logged)


class TestReport:
    def test_the_positive_capture_is_rated_and_located(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(_scanner(tree, tmp_path), FakeSecretlint(), monkeypatch)
        assert _findings(report) == POSITIVE_EXPECTED

    def test_negative_control_the_clean_capture_has_no_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(
            _scanner(tree, tmp_path), FakeSecretlint(sarif_text=NEGATIVE), monkeypatch
        )
        assert _findings(report) == []

    def test_results_are_marked_as_secret_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(_scanner(tree, tmp_path), FakeSecretlint(), monkeypatch)
        for result in report.get_all_results():
            assert getattr(result.kind, "value", result.kind) == "fail"
            assert {"secret", "security"} <= set(result.properties.tags)

    def test_a_result_with_no_level_reads_as_the_sarif_default_warning(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        # SARIF's default level is warning and ASH's SARIF model applies it on
        # parse, so an unlevelled result is MEDIUM, as for every other scanner.
        bare = _result(AWS_RULE, "error", "app.py", 4, "found")
        del bare["level"]
        report = _run(
            _scanner(tree, tmp_path),
            FakeSecretlint(sarif_text=_sarif([bare])),
            monkeypatch,
        )
        assert _findings(report) == [(AWS_RULE, "warning", "MEDIUM", "app.py", 4)]

    def test_a_level_outside_the_table_is_rated_critical_error(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        odd = _result(AWS_RULE, "none", "app.py", 4, "found")
        report = _run(
            _scanner(tree, tmp_path),
            FakeSecretlint(sarif_text=_sarif([odd])),
            monkeypatch,
        )
        assert _findings(report) == [(AWS_RULE, "error", "CRITICAL", "app.py", 4)]

    def test_level_and_severity_agree_on_every_result(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(_scanner(tree, tmp_path), FakeSecretlint(), monkeypatch)
        expected = {"error": "CRITICAL", "warning": "MEDIUM", "note": "LOW"}
        for _, level, severity, _, _ in _findings(report):
            assert expected[level] == severity

    def test_the_formatters_constant_version_is_not_reported(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(_scanner(tree, tmp_path), FakeSecretlint(), monkeypatch)
        driver = report.runs[0].tool.driver
        assert driver.semanticVersion is None
        assert driver.version is None

    def test_results_under_ashs_output_directory_are_dropped(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        out = tree / ".ash" / "ash_output"
        out.mkdir(parents=True)
        sarif = _sarif(
            [
                _result(AWS_RULE, "error", "app.py", 4, "found"),
                _result(AWS_RULE, "error", ".ash/ash_output/copy.py", 4, "found"),
            ]
        )
        scanner = SecretlintScanner(
            context=PluginContext(
                source_dir=tree,
                output_dir=out,
                work_dir=out / "converted",
                config=get_default_config(),
            ),
            config=SecretlintScannerConfig(),
        )
        report = _run(scanner, FakeSecretlint(sarif_text=sarif), monkeypatch)
        assert [f[3] for f in _findings(report)] == ["app.py"]


_CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "secretlint"
    / "captured"
)


class TestCapturedReports:
    """The same conversion over reports Secretlint 14.0.1 really wrote.

    See tests/test_data/scanners/secretlint/captured/README.md for how they were
    made. These are the oracle for the report shape; the hand-built documents
    above add the warning and note levels, which the recommended preset never
    produced in the capture.
    """

    def test_the_positive_capture_is_rated_located_and_marked(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        text = (_CAPTURED / "positive.sarif").read_text(encoding="utf-8")
        report = _run(
            _scanner(tree, tmp_path), FakeSecretlint(sarif_text=text), monkeypatch
        )
        assert _findings(report) == [
            (
                GH_RULE,
                "error",
                "CRITICAL",
                "app.yml",
                1,
            )
        ]
        result = report.get_all_results()[0]
        assert getattr(result.kind, "value", result.kind) == "fail"
        assert {"secret", "security"} <= set(result.properties.tags)

    def test_the_captured_message_holds_no_secret_value(self):
        text = (_CAPTURED / "positive.sarif").read_text(encoding="utf-8")
        assert "ghp_" not in text
        assert "*****" in text

    def test_the_formatters_constant_version_is_dropped_from_the_capture(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        text = (_CAPTURED / "positive.sarif").read_text(encoding="utf-8")
        assert json.loads(text)["runs"][0]["tool"]["driver"]["version"] == "1.0.0"
        report = _run(
            _scanner(tree, tmp_path), FakeSecretlint(sarif_text=text), monkeypatch
        )
        assert report.runs[0].tool.driver.version is None

    def test_negative_control_the_clean_capture_has_no_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        text = (_CAPTURED / "negative.sarif").read_text(encoding="utf-8")
        assert json.loads(text)["runs"][0]["results"] == []
        report = _run(
            _scanner(tree, tmp_path), FakeSecretlint(sarif_text=text), monkeypatch
        )
        assert _findings(report) == []


class TestExitStatus:
    def test_zero_is_a_success_even_with_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        """With --output Secretlint exits 0 when it found errors."""
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeSecretlint(exit_code=0), monkeypatch)
        assert scanner._exit_code_accepted()

    @pytest.mark.parametrize("code", [1, 2, 126, 137])
    def test_any_other_exit_fails_the_scan_even_with_a_report_on_disk(
        self, tree, tmp_path, on_path, monkeypatch, code
    ):
        with pytest.raises(ScannerError):
            _run(_scanner(tree, tmp_path), FakeSecretlint(exit_code=code), monkeypatch)

    def test_a_run_that_wrote_no_report_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        with pytest.raises(ScannerError):
            _run(_scanner(tree, tmp_path), FakeSecretlint(sarif_text=None), monkeypatch)

    def test_a_report_left_by_an_earlier_run_is_removed_before_the_next_one(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        first = FakeSecretlint()
        _run(scanner, first, monkeypatch)
        report = Path(_flag(first.argv, "--output="))
        assert report.exists()
        with pytest.raises(ScannerError):
            _run(scanner, FakeSecretlint(sarif_text=None), monkeypatch)
        assert not report.exists()

    def test_a_timeout_fails_the_scan_and_says_so(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeSecretlint(sarif_text=None, exit_code=124, extra={"timed_out": True})
        with pytest.raises(ScannerError, match="timed out"):
            _run(scanner, fake, monkeypatch)
        timeout = fake.calls[0]["timeout"]
        assert (
            timeout is not None and 0 < timeout <= scanner.config.options.scan_timeout
        )

    @pytest.mark.parametrize(
        "text",
        [
            "this is not json",
            '{"version": "2.1.0", "runs"',
            "[]",
            '{"hello": "world"}',
            '"a string"',
        ],
    )
    def test_malformed_output_fails_the_scan_and_is_never_clean(
        self, tree, tmp_path, on_path, monkeypatch, text
    ):
        with pytest.raises(Exception) as caught:
            _run(
                _scanner(tree, tmp_path),
                FakeSecretlint(sarif_text=text),
                monkeypatch,
            )
        assert caught.type is not AssertionError

    def test_an_empty_report_is_not_a_clean_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        with pytest.raises(ScannerError):
            _run(_scanner(tree, tmp_path), FakeSecretlint(sarif_text=""), monkeypatch)

    def test_the_tools_stderr_is_not_copied_into_the_scans_errors(
        self, tree, tmp_path, on_path
    ):
        scanner = _scanner(tree, tmp_path)
        scanner._process_command_response(
            {"returncode": 0, "stdout": "", "stderr": "PLANTED-LINE quoted from a file"}
        )
        assert not any("PLANTED-LINE" in line for line in scanner.errors)

    def test_the_failure_message_names_the_log_and_does_not_quote_it(
        self, tree, tmp_path, on_path
    ):
        scanner = _scanner(tree, tmp_path)
        scanner.exit_code = 2
        results = tmp_path / "out" / "source" / "secretlint.sarif"
        message = scanner._describe_scan_failure(ScannerError("boom"), results)
        assert "stderr.log" in message
        assert "exit code 2" in message
        assert "not quoted" in message

    def test_a_failure_before_the_tool_started_has_no_exit_code(
        self, tree, tmp_path, on_path
    ):
        message = _scanner(tree, tmp_path)._describe_scan_failure(
            ScannerError("boom"), None, tool_started=False
        )
        assert "was not started" in message
        assert "exit code" not in message


class TestDependencyCheck:
    def test_tool_absent_is_reported_as_unsatisfied_dependencies(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(ss, "find_executable", lambda cmd: None)
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is False

    def test_tool_absent_and_node_absent_names_node(self, tree, tmp_path, monkeypatch):
        monkeypatch.setattr(ss, "find_executable", lambda cmd: None)
        warnings: List[str] = []
        monkeypatch.setattr(
            ss.ASH_LOGGER, "warning", lambda m, *a, **k: warnings.append(m)
        )
        _scanner(tree, tmp_path).validate_plugin_dependencies()
        assert any("Node.js 22" in w for w in warnings)

    def test_tool_absent_with_node_present_gives_the_install_hint(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(
            ss, "find_executable", lambda cmd: "/fake/node" if cmd == "node" else None
        )
        warnings: List[str] = []
        monkeypatch.setattr(
            ss.ASH_LOGGER, "warning", lambda m, *a, **k: warnings.append(m)
        )
        _scanner(tree, tmp_path).validate_plugin_dependencies()
        assert any("--tool secretlint" in w for w in warnings)

    def test_a_present_binary_satisfies_them(self, tree, tmp_path, on_path):
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is True

    def test_an_unavailable_reason_wins_over_a_binary_on_path(
        self, tree, tmp_path, on_path
    ):
        scanner = _scanner(tree, tmp_path)
        scanner.dependency_unavailable_reason = "refused"
        assert scanner.validate_plugin_dependencies() is False


class TestInstall:
    def test_install_commands_cover_every_platform(self, tmp_path):
        scanner = _scanner(tmp_path, tmp_path)
        for platform in ("linux", "darwin", "windows"):
            for arch in ("amd64", "arm64"):
                commands = scanner.get_installation_commands(platform, arch)
                assert commands, f"no install command for {platform}/{arch}"
                assert commands[0] == [
                    "npm",
                    "install",
                    "-g",
                    f"secretlint@{ss.SECRETLINT_VERSION}",
                ]
                assert (
                    commands[1][-1] == f"{ss.SARIF_FORMATTER}@{ss.SECRETLINT_VERSION}"
                )

    def test_the_pin_is_an_exact_release(self):
        parts = ss.SECRETLINT_VERSION.split(".")
        assert len(parts) == 3 and all(p.isdigit() for p in parts)
