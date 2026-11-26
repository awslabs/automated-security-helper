# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ConftestScanner: the policy gate, the invocation, the exit status and the report.

The positive and negative reports are real Conftest 0.62.0 output, committed under
``tests/test_data/scanners/conftest/captured/``; the fake subprocess serves them, so
the tests run on every platform without Conftest installed. The ``allow``, ``skip`` and
``note`` results no run of that policy produced are built by hand to the shape
Conftest's ``output/sarif.go`` writes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.utils.config_trust import record_provenance
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_conftest_plugins
from automated_security_helper.plugin_modules.ash_conftest_plugins import (
    conftest_scanner as cs,
)
from automated_security_helper.plugin_modules.ash_conftest_plugins.conftest_scanner import (
    ConftestScanner,
    ConftestScannerConfig,
    ConftestScannerConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport

pytestmark = pytest.mark.unit


def _result(rule: str, level: str, message: str, uri: str, line: Optional[int]):
    result: Dict[str, Any] = {
        "ruleId": rule,
        "ruleIndex": 0,
        "level": level,
        "message": {"text": message},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
    }
    if line is not None:
        result["locations"][0]["physicalLocation"]["region"] = {
            "startLine": line,
            "endLine": line,
        }
    return result


def _sarif(results: List[Dict[str, Any]]) -> str:
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "conftest",
                            "version": "0.71.1",
                            "informationUri": "https://github.com/open-policy-agent/conftest",
                            "rules": [],
                        }
                    },
                    "results": results,
                    "invocations": [{"executionSuccessful": True, "exitCode": 0}],
                }
            ],
        }
    )


CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "conftest"
    / "captured"
)

#: Real Conftest 0.62.0 output (see captured/README.md): one deny and one warn on
#: deploy/bad.yaml, and a success result for deploy/good.yaml. No result has a region.
POSITIVE = (CAPTURED / "positive.sarif").read_text(encoding="utf-8")
NEGATIVE = (CAPTURED / "negative.sarif").read_text(encoding="utf-8")

#: Hand-built, for the shapes no run produced: the allow, skip and note results.
EXTRA_NON_FINDINGS = [
    _result("main/allow", "note", "excepted", "deploy/app.yaml", None),
    _result("main/skip", "none", "Policy check was skipped", "b.toml", None),
]

POSITIVE_EXPECTED = [
    ("main/deny", "error", "HIGH", "deploy/bad.yaml", None),
    ("main/warn", "warning", "MEDIUM", "deploy/bad.yaml", None),
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
                loc.region.startLine if loc.region else None,
            )
        )
    return out


class FakeConftest:
    """Stands in for _run_subprocess: records argv, writes the stdout it is given."""

    def __init__(
        self,
        stdout: Optional[str] = POSITIVE,
        exit_code: int = 0,
        extra: Optional[Dict[str, Any]] = None,
    ):
        self.stdout, self.exit_code, self.extra = stdout, exit_code, extra or {}
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, cwd=None, **_):
            self.calls.append(
                {"argv": list(command), "env": env, "timeout": timeout, "cwd": cwd}
            )
            if self.stdout is not None and not self.extra.get("timed_out"):
                path = scanner._results_file
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(self.stdout, encoding="utf-8")
            scanner.exit_code = self.exit_code
            return {
                "returncode": self.exit_code,
                "stdout": self.stdout or "",
                "stderr": "",
                **self.extra,
            }

        return run

    @property
    def argv(self) -> List[str]:
        return self.calls[0]["argv"]


def _scanner(
    source: Path, tmp_path: Path, *, operator: bool = True, **options
) -> ConftestScanner:
    """``operator``: the options came from the operator, or from the scanned tree."""
    config = get_default_config()
    record_provenance(
        config,
        in_tree=[] if operator else [source / ".ash" / ".ash.yaml"],
        trusted=AshConfig(),
    )
    output = tmp_path / "out"
    return ConftestScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=config,
        ),
        config=ConftestScannerConfig(
            enabled=True, options=ConftestScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    (src / "policy").mkdir(parents=True)
    (src / "policy" / "base.rego").write_text("package main\n")
    (src / "deploy").mkdir()
    (src / "deploy" / "app.yaml").write_text("kind: Pod\n")
    (src / "ok.json").write_text("{}\n")
    (src / "Dockerfile").write_text("FROM scratch\n")
    (src / "app.py").write_text("print(1)\n")
    return src


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(cs, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


def _run(scanner, fake, monkeypatch, target_type="source"):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=Path(scanner.context.source_dir), target_type=target_type
    )


class TestAlphaPlugin:
    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert ConftestScannerConfig().enabled is True
        assert ConftestScannerConfig().name == "conftest"

    def test_the_builtin_config_does_not_declare_it(self):
        assert not hasattr(get_default_config().scanners, "conftest")

    def test_the_module_exports_the_scanner(self):
        assert ash_conftest_plugins.ASH_SCANNERS == [ConftestScanner]
        assert ash_conftest_plugins.ASH_REPORTERS == []

    def test_exit_codes_and_sandbox_are_declared(self):
        assert ConftestScanner.success_exit_codes == {0}
        assert ConftestScanner.python_only is False


class TestPolicyGate:
    def test_no_policy_directory_skips_without_starting_the_tool(
        self, tmp_path, on_path, monkeypatch
    ):
        src = tmp_path / "src"
        src.mkdir()
        (src / "a.yaml").write_text("a: 1\n")
        scanner = _scanner(src, tmp_path)
        fake = FakeConftest()
        assert _run(scanner, fake, monkeypatch) is True
        assert fake.calls == []
        assert "no .rego file" in (scanner._nothing_scanned_reason or "")

    def test_a_policy_directory_without_rego_skips(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        (tree / "policy" / "base.rego").unlink()
        (tree / "policy" / "notes.txt").write_text("x")
        scanner = _scanner(tree, tmp_path)
        fake = FakeConftest()
        _run(scanner, fake, monkeypatch)
        assert fake.calls == []

    def test_the_reason_is_offered_when_the_tool_is_missing(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        assert "no .rego file" in _scanner(src, tmp_path).nothing_to_scan_reason()

    def test_a_present_policy_dir_runs_the_tool(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        assert scanner.nothing_to_scan_reason() is None
        fake = FakeConftest()
        _run(scanner, fake, monkeypatch)
        assert len(fake.calls) == 1

    def test_policy_dir_option_is_honored(self, tree, tmp_path, on_path, monkeypatch):
        (tree / "rules").mkdir()
        (tree / "rules" / "x.rego").write_text("package main\n")
        scanner = _scanner(tree, tmp_path, policy_dir="rules")
        fake = FakeConftest()
        _run(scanner, fake, monkeypatch)
        assert f"--policy={(tree / 'rules').resolve().as_posix()}" in fake.argv

    def test_a_policy_dir_the_scanned_tree_set_is_not_used(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        # Rego is code Conftest evaluates: which directory it comes from is the
        # operator's choice, not a setting the scanned repository can make.
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "x.rego").write_text("package main\n")
        scanner = _scanner(tree, tmp_path, operator=False, policy_dir=str(elsewhere))
        fake = FakeConftest()
        _run(scanner, fake, monkeypatch)
        assert f"--policy={(tree / 'policy').as_posix()}" in fake.argv
        assert not any(str(elsewhere) in a for a in fake.argv)

    def test_a_policy_dir_leading_out_through_a_link_is_not_used(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "x.rego").write_text("package main\n")
        (tree / "rules").symlink_to(outside, target_is_directory=True)
        scanner = _scanner(tree, tmp_path, policy_dir="rules")
        fake = FakeConftest()
        _run(scanner, fake, monkeypatch)
        assert f"--policy={(tree / 'policy').as_posix()}" in fake.argv

    def test_the_default_policy_dir_leading_out_through_a_link_skips(
        self, tmp_path, on_path, monkeypatch
    ):
        src = tmp_path / "src"
        src.mkdir()
        (src / "a.yaml").write_text("a: 1\n")
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "x.rego").write_text("package main\n")
        (src / "policy").symlink_to(outside, target_is_directory=True)
        scanner = _scanner(src, tmp_path)
        fake = FakeConftest()
        assert _run(scanner, fake, monkeypatch) is True
        assert fake.calls == []
        assert "symbolic link" in (scanner._nothing_scanned_reason or "")


class TestInvocation:
    def test_every_fixed_flag_and_the_file_list(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeConftest()
        _run(scanner, fake, monkeypatch)
        argv = fake.argv
        assert argv[:2] == ["conftest", "test"]
        for flag in ("--output=sarif", "--no-fail", "--no-color", "--all-namespaces"):
            assert flag in argv
        assert f"--policy={(tree / 'policy').as_posix()}" in argv
        files = argv[argv.index("--") + 1 :]
        assert files == ["Dockerfile", "deploy/app.yaml", "ok.json"]

    def test_all_namespaces_can_be_turned_off(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, all_namespaces=False)
        fake = FakeConftest()
        _run(scanner, fake, monkeypatch)
        assert "--all-namespaces" not in fake.argv

    @pytest.mark.parametrize("flag", ["--update", "--data", "--capabilities", "-u"])
    def test_flags_that_reach_the_network_are_never_passed(
        self, tree, tmp_path, on_path, monkeypatch, flag
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeConftest()
        _run(scanner, fake, monkeypatch)
        assert not any(a == flag or a.startswith(flag + "=") for a in fake.argv)

    def test_unparsable_extensions_and_links_are_not_listed(self, tree, tmp_path):
        (tree / "link.yaml").symlink_to(tree / "ok.json")
        (tree / "node_modules").mkdir()
        (tree / "node_modules" / "p.json").write_text("{}")
        (tree / "policy" / "data.yaml").write_text("a: 1\n")
        files = _scanner(tree, tmp_path)._config_files(tree)
        assert files == ["Dockerfile", "deploy/app.yaml", "ok.json"]

    def test_a_tree_with_nothing_parsable_is_skipped_not_failed(
        self, tmp_path, on_path, monkeypatch
    ):
        # A tree (or the converted tree) with a policy and no configuration file is
        # a scan with nothing to evaluate, not a failed scan.
        src = tmp_path / "src"
        (src / "policy").mkdir(parents=True)
        (src / "policy" / "p.rego").write_text("package main\n")
        (src / "app.py").write_text("print(1)\n")
        scanner = _scanner(src, tmp_path)
        assert "no file Conftest can parse" in scanner.nothing_to_scan_reason()
        fake = FakeConftest()
        assert _run(scanner, fake, monkeypatch) is True
        assert fake.calls == []
        assert "no file Conftest can parse" in (scanner._nothing_scanned_reason or "")

    def test_the_converted_tree_without_configuration_is_skipped(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        converted = tmp_path / "converted"
        converted.mkdir()
        (converted / "nb.py").write_text("print(1)\n")
        scanner = _scanner(tree, tmp_path)
        fake = FakeConftest()
        monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
        assert scanner.scan(target=converted, target_type="converted") is True
        assert fake.calls == []
        assert scanner.nothing_to_scan_reason() is None  # the source tree has files

    def test_too_many_files_for_one_command_line_fail_clearly(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        monkeypatch.setattr(cs, "MAX_ARGV_CHARS", 10)
        with pytest.raises(ScannerError, match="do not fit on one command line"):
            _run(_scanner(tree, tmp_path), FakeConftest(), monkeypatch)


class TestReport:
    def test_findings_are_rated_and_located(self, tree, tmp_path, on_path, monkeypatch):
        report = _run(_scanner(tree, tmp_path), FakeConftest(), monkeypatch)
        assert _findings(report) == POSITIVE_EXPECTED

    def test_negative_control_has_no_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(
            _scanner(tree, tmp_path), FakeConftest(stdout=NEGATIVE), monkeypatch
        )
        assert _findings(report) == []

    def test_allow_skip_and_note_results_are_not_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        data = json.loads(POSITIVE)
        data["runs"][0]["results"].extend(EXTRA_NON_FINDINGS)
        report = _run(
            _scanner(tree, tmp_path), FakeConftest(stdout=json.dumps(data)), monkeypatch
        )
        assert _findings(report) == POSITIVE_EXPECTED

    def test_results_without_a_level_are_medium_and_unknown_levels_high(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        text = _sarif([_result("main/deny", "error", "m", "a.yaml", 1)])
        data = json.loads(text)
        data["runs"][0]["results"].append(
            {"ruleId": "x/deny", "message": {"text": "n"}}
        )
        report = _run(
            _scanner(tree, tmp_path), FakeConftest(stdout=json.dumps(data)), monkeypatch
        )
        severities = [r.properties.issue_severity for r in report.get_all_results()]
        assert severities == ["HIGH", "MEDIUM"]

    def test_level_and_severity_agree_and_tags_are_added(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(_scanner(tree, tmp_path), FakeConftest(), monkeypatch)
        for r in report.get_all_results():
            level = getattr(r.level, "value", r.level)
            assert (level, r.properties.issue_severity) in {
                ("error", "HIGH"),
                ("warning", "MEDIUM"),
            }
            assert {"policy", "conftest"} <= set(r.properties.tags)


class TestFailures:
    @pytest.mark.parametrize("code", [1, 2, 126, 137])
    def test_a_nonzero_exit_fails_even_with_findings_on_disk(
        self, tree, tmp_path, on_path, monkeypatch, code
    ):
        """With --no-fail a failed policy exits 0, so nonzero is a tool failure."""
        with pytest.raises(ScannerError):
            _run(_scanner(tree, tmp_path), FakeConftest(exit_code=code), monkeypatch)

    def test_findings_exit_zero_is_success(self, tree, tmp_path, on_path, monkeypatch):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeConftest(exit_code=0), monkeypatch)
        assert scanner._exit_code_accepted()

    def test_a_timeout_fails_the_scan_and_says_so(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, scan_timeout=30)
        fake = FakeConftest(
            stdout=None, exit_code=124, extra={"timed_out": True, "returncode": 124}
        )
        with pytest.raises(ScannerError, match="timed out"):
            _run(scanner, fake, monkeypatch)
        assert fake.calls[0]["timeout"] == 30

    @pytest.mark.parametrize(
        "text",
        ["", "not json at all", "[1, 2]", "{}", '{"version": "2.1.0", "runs": []}'],
    )
    def test_malformed_or_empty_output_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch, text
    ):
        with pytest.raises(ScannerError):
            _run(_scanner(tree, tmp_path), FakeConftest(stdout=text), monkeypatch)

    def test_a_report_left_by_an_earlier_run_is_removed(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeConftest(), monkeypatch)
        stale = scanner._results_file
        assert stale.exists()
        with pytest.raises(ScannerError):
            _run(scanner, FakeConftest(stdout=None), monkeypatch)
        assert not stale.exists()

    def test_stderr_is_not_copied_into_the_errors(self, tree, tmp_path, on_path):
        scanner = _scanner(tree, tmp_path)
        scanner._process_command_response(
            {"returncode": 0, "stdout": "", "stderr": "parse error: PLANTED-LINE"}
        )
        assert not any("PLANTED-LINE" in line for line in scanner.errors)

    def test_failure_message_names_the_log_and_does_not_quote_it(
        self, tree, tmp_path, on_path
    ):
        scanner = _scanner(tree, tmp_path)
        scanner.exit_code = 1
        message = scanner._describe_scan_failure(
            ScannerError("boom"), tmp_path / "out" / "source" / "conftest.sarif"
        )
        assert "stderr.log" in message and "not quoted" in message
        assert "was not started" in scanner._describe_scan_failure(
            ScannerError("boom"), None, tool_started=False
        )


class TestStdoutBecomesTheReport:
    def test_run_subprocess_writes_stdout_to_the_results_file(
        self, tree, tmp_path, monkeypatch
    ):
        seen: Dict[str, Any] = {}

        def fake_super(self, command, results_dir=None, **kwargs):
            seen.update(kwargs)
            return {"returncode": 0, "stdout": POSITIVE, "stderr": ""}

        monkeypatch.setattr(ScannerPluginBase, "_run_subprocess", fake_super)
        scanner = _scanner(tree, tmp_path)
        scanner._results_file = tmp_path / "res" / "conftest.sarif"
        scanner._results_file.parent.mkdir()
        scanner._run_subprocess(["conftest"], results_dir=tmp_path / "res")
        assert seen["stdout_preference"] == "return"
        assert scanner._results_file.read_text(encoding="utf-8") == POSITIVE


class TestInstall:
    def test_the_scanner_installs_the_pinned_release_on_every_platform(
        self, tree, tmp_path
    ):
        """The pin in tool_downloads gives one install command per platform pair."""
        from automated_security_helper.utils.tool_downloads import TOOL_VERSIONS

        assert TOOL_VERSIONS["conftest"] == "v0.62.0"
        commands = _scanner(tree, tmp_path).custom_install_commands
        pairs = {(p, a) for p, arches in commands.items() for a in arches}
        assert pairs == {
            (platform, arch)
            for platform in ("linux", "darwin", "windows")
            for arch in ("amd64", "arm64")
        }
        assert all(len(commands[p][a]) == 1 for p, a in pairs), (
            "one verified download per platform pair"
        )

    def test_a_pinned_release_yields_commands_when_one_exists(
        self, tree, tmp_path, monkeypatch
    ):
        from automated_security_helper.utils.download_utils import CustomCommand

        sentinel = {"linux": {"amd64": [CustomCommand(args=["true"], shell=False)]}}
        monkeypatch.setattr(cs, "pinned_tool_install_commands", lambda tool: sentinel)
        scanner = _scanner(tree, tmp_path)
        assert (
            scanner.custom_install_commands["linux"]["amd64"]
            == sentinel["linux"]["amd64"]
        )

    def test_a_build_without_the_pin_still_constructs_with_no_install(
        self, tree, tmp_path, monkeypatch
    ):
        """A table with no conftest row raises; the scanner offers no install."""
        from automated_security_helper.core.exceptions import ToolNotProvisionableError

        def unpinned(tool):
            raise ToolNotProvisionableError(f"{tool} has no release-asset table")

        monkeypatch.setattr(cs, "pinned_tool_install_commands", unpinned)
        scanner = _scanner(tree, tmp_path)
        assert not any(scanner.custom_install_commands.values())

    def test_the_dependency_hint_names_the_pinned_install(
        self, tree, tmp_path, monkeypatch
    ):
        from automated_security_helper.utils.log import ASH_LOGGER

        messages: List[str] = []
        monkeypatch.setattr(cs, "find_executable", lambda cmd: None)
        monkeypatch.setattr(
            ASH_LOGGER, "warning", lambda m, *a, **k: messages.append(m)
        )
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is False
        assert messages and "ash dependencies install" in messages[0]
        assert "--tool conftest" in messages[0]
        assert "ash_conftest_plugins" in messages[0]

    def test_the_dependency_hint_names_no_install_when_the_pin_is_absent(
        self, tree, tmp_path, monkeypatch
    ):
        from automated_security_helper.utils.log import ASH_LOGGER

        messages: List[str] = []
        monkeypatch.setattr(cs, "find_executable", lambda cmd: None)
        monkeypatch.setattr(cs, "downloadable_tools", list)
        monkeypatch.setattr(
            ASH_LOGGER, "warning", lambda m, *a, **k: messages.append(m)
        )
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is False
        assert messages and "ash dependencies install" not in messages[0]
        assert "pins no conftest release" in messages[0]


class TestRegister:
    def test_the_facets_declare_what_the_captured_report_carries(self):
        from automated_security_helper.base.scanner_facets import FacetState

        facets = ConftestScanner.facets
        assert facets.rule_id.state is FacetState.MAPPED
        assert facets.file_path.state is FacetState.MAPPED
        # No region in the captured report, so no line or column is claimed.
        assert facets.line_range.state is FacetState.NA
        assert facets.column.state is FacetState.NA
        # A policy result names a file, not a deployable resource.
        assert facets.resource_id.state is FacetState.NA

    def test_the_operational_row_mirrors_the_class(self):
        row = ConftestScanner.operational_facets
        assert row.scanner_name == ConftestScannerConfig().name
        assert row.exit_codes.success_exit_codes == tuple(
            sorted(ConftestScanner.success_exit_codes)
        )
        assert row.network.offline_strategy is ConftestScanner.offline_strategy


class TestDependencyCheck:
    def test_a_missing_binary_is_unsatisfied(self, tree, tmp_path, monkeypatch):
        monkeypatch.setattr(cs, "find_executable", lambda cmd: None)
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is False

    def test_a_present_binary_satisfies_them(self, tree, tmp_path, on_path):
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is True

    def test_an_unavailable_reason_wins_over_a_binary_on_path(
        self, tree, tmp_path, on_path
    ):
        scanner = _scanner(tree, tmp_path)
        scanner.dependency_unavailable_reason = "refused"
        assert scanner.validate_plugin_dependencies() is False
