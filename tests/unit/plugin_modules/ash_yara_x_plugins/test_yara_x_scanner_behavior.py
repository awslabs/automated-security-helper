# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""YaraXScanner: severity mapping, invocation, output conversion and failures.

The output the tests convert is a line ``yr 1.23.0`` (the pinned release, ``yr
--version`` prints ``yara-x-cli 1.23.0``) wrote for this command, run in a directory
holding ``src/a.txt`` and ``b.txt``, with two rules that both match ``src/a.txt``:

    yr scan --output-format=ndjson --print-meta --print-tags --disable-console-logs \\
        --recursive -- rules .

where the first rule has ``meta: severity = "high"`` and ``description = "demo
marker"`` and the tag ``sample``, and the second has neither. The same run over a tree
that holds no match wrote nothing to standard output and exited 0, which is the
negative control here. The scan() tests replace the subprocess with a fake, so they
run on every platform without the binary.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules import ash_yara_x_plugins
from automated_security_helper.plugin_modules.ash_yara_x_plugins import (
    yara_x_scanner as ys,
)
from automated_security_helper.plugin_modules.ash_yara_x_plugins.yara_x_scanner import (
    YARA_SEVERITY_MAP,
    YaraXScanner,
    YaraXScannerConfig,
    YaraXScannerConfigOptions,
    convert_ndjson,
    parse_ndjson,
    severity_for,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.config_trust import record_provenance

pytestmark = pytest.mark.unit

_CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "yara_x"
    / "captured"
)

#: One line of ``yr scan --output-format=ndjson --print-meta --print-tags`` output,
#: as the release binary wrote it (captured/positive.ndjson; captured/README.md
#: records the argv, version and inputs). ``meta`` is a list of [key, value] pairs.
CAPTURED_POSITIVE = (_CAPTURED / "positive.ndjson").read_text(encoding="utf-8")

#: What a run over a tree with no match wrote to standard output
#: (captured/negative.ndjson).
CAPTURED_NEGATIVE = (_CAPTURED / "negative.ndjson").read_text(encoding="utf-8")

#: What the positive capture must produce, written out by hand:
#: (ruleId, SARIF level, ASH severity, uri, message).
POSITIVE_EXPECTED = [
    ("demo_marker", "error", "HIGH", "src/a.txt", "demo marker"),
    ("no_sev", "none", "INFO", "src/a.txt", "YARA rule no_sev matched"),
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
                r.message.root.text,
            )
        )
    return out


class FakeYr:
    """Stands in for _run_subprocess: records argv, serves captured stdout."""

    def __init__(
        self,
        stdout: str = CAPTURED_POSITIVE,
        exit_code: int = 0,
        stderr: str = "",
        timed_out: bool = False,
    ):
        self.stdout, self.exit_code, self.stderr = stdout, exit_code, stderr
        self.timed_out = timed_out
        self.calls: List[dict] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, cwd=None, **kw):
            self.calls.append(
                {
                    "argv": list(command),
                    "timeout": timeout,
                    "cwd": cwd,
                    "stdout_preference": kw.get("stdout_preference"),
                }
            )
            if self.timed_out:
                scanner.exit_code = -9
                return {"timed_out": True}
            scanner.exit_code = self.exit_code
            return {
                "returncode": self.exit_code,
                "stdout": self.stdout,
                "stderr": self.stderr,
            }

        return run


def _scanner(
    source: Path, tmp_path: Path, *, operator: bool = True, **options
) -> YaraXScanner:
    """``operator``: the options came from the operator, or from the scanned tree."""
    config = get_default_config()
    record_provenance(
        config,
        in_tree=[] if operator else [source / ".ash" / ".ash.yaml"],
        trusted=AshConfig(),
    )
    return YaraXScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=tmp_path / "out",
            work_dir=tmp_path / "out" / "converted",
            config=config,
        ),
        config=YaraXScannerConfig(
            enabled=True, options=YaraXScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    (src / "src").mkdir(parents=True)
    (src / "src" / "a.txt").write_text("hello\n")
    (src / "b.txt").write_text("clean\n")
    return src


@pytest.fixture
def rules(tmp_path) -> Path:
    path = tmp_path / "shared" / "rules"
    path.mkdir(parents=True)
    (path / "r.yar").write_text("rule demo_marker { condition: false }\n")
    return path


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(ys, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


def _run(scanner: YaraXScanner, fake: FakeYr, monkeypatch, target=None, **kw):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=target or Path(scanner.context.source_dir),
        target_type="source",
        **kw,
    )


class TestAlphaPlugin:
    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert YaraXScannerConfig().enabled is True
        assert YaraXScannerConfig().name == "yara-x"

    def test_the_builtin_config_does_not_declare_it(self):
        scanners = get_default_config().scanners
        assert not hasattr(scanners, "yara-x")
        assert not hasattr(scanners, "yara_x")

    def test_the_module_exports_the_scanner(self):
        assert ash_yara_x_plugins.ASH_SCANNERS == [YaraXScanner]
        assert ash_yara_x_plugins.ASH_REPORTERS == []

    def test_the_rules_path_is_the_only_option_of_its_own(self):
        own = set(YaraXScannerConfigOptions.model_fields) - set(
            ys.ScannerOptionsBase.model_fields
        )
        assert own == {"rules_path"}

    def test_class_variables_are_set_deliberately(self):
        from automated_security_helper.core.enums import OfflineStrategy
        from automated_security_helper.utils.sandbox.policy import (
            SandboxRequirements,
        )

        assert YaraXScanner.offline_strategy is OfflineStrategy.BUNDLED
        assert YaraXScanner.python_only is False
        assert YaraXScanner.success_exit_codes == {0}
        assert YaraXScanner.sandbox_requirements == SandboxRequirements()


class TestSeverity:
    @pytest.mark.parametrize(
        "value, expected",
        [
            ("critical", ("CRITICAL", "error")),
            ("high", ("HIGH", "error")),
            ("medium", ("MEDIUM", "warning")),
            ("low", ("LOW", "note")),
            ("info", ("INFO", "none")),
            ("HIGH", ("HIGH", "error")),
            (" Low ", ("LOW", "note")),
        ],
    )
    def test_each_documented_value(self, value, expected):
        severity, level = severity_for({"severity": value})
        assert (severity, level.value) == expected

    def test_a_rule_with_no_severity_is_info(self):
        severity, level = severity_for({"description": "x"})
        assert (severity, level.value) == ("INFO", "none")

    @pytest.mark.parametrize("value", ["urgent", "", 7, None, ["high"]])
    def test_an_unrecognized_severity_is_medium_not_info(self, value):
        severity, level = severity_for({"severity": value})
        assert (severity, level.value) == ("MEDIUM", "warning")

    def test_every_mapped_severity_agrees_with_its_sarif_level(self):
        # error for CRITICAL and HIGH, warning MEDIUM, note LOW, none INFO.
        by_severity = {sev: lvl.value for sev, lvl in YARA_SEVERITY_MAP.values()}
        assert by_severity == {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "INFO": "none",
        }

    def test_meta_pairs_take_the_first_value_of_a_repeated_key(self):
        document = {
            "path": "x",
            "rules": [
                {
                    "identifier": "r",
                    "meta": [["severity", "low"], ["severity", "critical"]],
                }
            ],
        }
        report = convert_ndjson([document], source_dir=Path("/s"), tool_version=None)
        assert report["runs"][0]["results"][0]["properties"]["issue_severity"] == "LOW"


class TestReport:
    def test_captured_positive_is_rated_and_located(self, tmp_path):
        document = convert_ndjson(
            parse_ndjson(CAPTURED_POSITIVE), source_dir=tmp_path, tool_version=None
        )
        report = SarifReport.model_validate(document)
        assert _findings(report) == POSITIVE_EXPECTED

    def test_the_captures_are_present_and_not_vacuous(self):
        assert CAPTURED_POSITIVE.strip(), "the positive capture is empty"
        assert CAPTURED_NEGATIVE == "", "the negative capture must be empty output"
        assert (_CAPTURED / "README.md").is_file()

    def test_negative_control_is_clean_but_is_a_report(self, tmp_path):
        assert parse_ndjson(CAPTURED_NEGATIVE) == []
        document = convert_ndjson([], source_dir=tmp_path, tool_version=None)
        report = SarifReport.model_validate(document)
        assert report.runs and _findings(report) == []

    def test_rules_tags_and_fingerprints_are_carried(self, tmp_path):
        document = convert_ndjson(
            parse_ndjson(CAPTURED_POSITIVE), source_dir=tmp_path, tool_version="1.23.0"
        )
        driver = document["runs"][0]["tool"]["driver"]
        assert driver["name"] == "yara-x" and driver["version"] == "1.23.0"
        assert [r["id"] for r in driver["rules"]] == ["demo_marker", "no_sev"]
        assert driver["rules"][0]["properties"]["tags"] == ["yara-x", "sample"]
        fingerprints = {
            r["partialFingerprints"]["yara_x/v1"]
            for r in document["runs"][0]["results"]
        }
        assert len(fingerprints) == 2
        props = [r["properties"] for r in document["runs"][0]["results"]]
        assert [p["tags"] for p in props] == [["sample"], []]
        assert [p["yara_tags"] for p in props] == [["sample"], []]

    @pytest.mark.parametrize(
        "reported, expected",
        [
            ("./src/a.txt", "src/a.txt"),
            ("src\\a.txt", "src/a.txt"),
            ("././a", "a"),
        ],
    )
    def test_paths_are_made_source_relative(self, reported, expected, tmp_path):
        document = {"path": reported, "rules": [{"identifier": "r"}]}
        out = convert_ndjson([document], source_dir=tmp_path, tool_version=None)
        uri = out["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
            "artifactLocation"
        ]["uri"]
        assert uri == expected

    def test_an_absolute_path_inside_the_source_is_made_relative(self, tmp_path):
        document = {
            "path": str(tmp_path / "x" / "y.bin"),
            "rules": [{"identifier": "r"}],
        }
        out = convert_ndjson([document], source_dir=tmp_path, tool_version=None)
        loc = out["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "x/y.bin"


class TestInvocation:
    def test_every_fixed_flag_and_the_paths_after_double_dash(
        self, tree, rules, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, rules_path=str(rules))
        fake = FakeYr()
        report = _run(scanner, fake, monkeypatch)
        call = fake.calls[0]
        assert call["argv"] == [
            "yr",
            "scan",
            "--output-format=ndjson",
            "--print-meta",
            "--print-tags",
            "--disable-console-logs",
            "--recursive",
            "--",
            rules.resolve().as_posix(),
            ".",
        ]
        # Standard output is the report, and the tool runs in the source directory.
        assert call["stdout_preference"] == "return"
        assert call["cwd"] is None
        assert scanner.targets_attempted == 1
        assert _findings(report) == POSITIVE_EXPECTED

    @pytest.mark.parametrize(
        "flag",
        [
            "--print-strings",
            "-s",
            "--scan-list",
            "--module-data",
            "-x",
            "--compiled-rules",
            "-C",
            "--include-dir",
            "--ignore-invalid-rules",
        ],
    )
    def test_flags_that_read_the_tree_or_print_matched_bytes_are_never_passed(
        self, flag, tree, rules, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, rules_path=str(rules))
        fake = FakeYr()
        _run(scanner, fake, monkeypatch)
        assert flag not in fake.calls[0]["argv"]
        assert not any(a.startswith(flag + "=") for a in fake.calls[0]["argv"])

    def test_the_converted_target_is_passed_by_absolute_path(
        self, tree, rules, tmp_path, on_path, monkeypatch
    ):
        converted = tmp_path / "out" / "converted"
        converted.mkdir(parents=True)
        (converted / "c.txt").write_text("x\n")
        scanner = _scanner(tree, tmp_path, rules_path=str(rules))
        fake = FakeYr()
        _run(scanner, fake, monkeypatch, target=converted)
        assert fake.calls[0]["argv"][-1] == converted.absolute().as_posix()

    def test_a_file_target_is_not_scanned_recursively(
        self, tree, rules, tmp_path, on_path
    ):
        scanner = _scanner(tree, tmp_path, rules_path=str(rules))
        argv = scanner._argv(rules, tree / "b.txt")
        assert "--recursive" not in argv

    def test_the_scan_timeout_reaches_the_subprocess(
        self, tree, rules, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, rules_path=str(rules), scan_timeout=42)
        fake = FakeYr()
        _run(scanner, fake, monkeypatch)
        assert fake.calls[0]["timeout"] == 42

    def test_a_missing_target_never_reaches_the_tool(
        self, tree, rules, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, rules_path=str(rules))
        fake = FakeYr()
        result = _run(scanner, fake, monkeypatch, target=tmp_path / "nope")
        assert result is True and fake.calls == []


class TestTheRulesGate:
    def test_no_rules_path_is_a_no_op_that_says_nothing_was_scanned(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeYr()
        assert _run(scanner, fake, monkeypatch) is True
        assert fake.calls == []
        assert scanner.targets_attempted == 0
        assert scanner._nothing_scanned_reason
        assert "scanners.yara-x.options.rules_path" in scanner._nothing_scanned_reason

    def test_a_blank_rules_path_is_the_same_no_op(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, rules_path="  ")
        fake = FakeYr()
        assert _run(scanner, fake, monkeypatch) is True
        assert fake.calls == []

    def test_a_rules_path_set_from_the_scanned_tree_is_ignored(
        self, tree, rules, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, operator=False, rules_path=str(rules))
        fake = FakeYr()
        assert _run(scanner, fake, monkeypatch) is True
        assert fake.calls == []
        assert scanner.targets_attempted == 0

    def test_an_operator_rules_path_that_is_missing_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, rules_path=str(tmp_path / "shared" / "no"))
        fake = FakeYr()
        with pytest.raises(ScannerError, match="does not exist"):
            _run(scanner, fake, monkeypatch)
        assert fake.calls == []

    def test_a_rules_path_with_a_colon_is_refused(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        odd = tmp_path / "shared" / "ns:rules"
        odd.mkdir(parents=True)
        scanner = _scanner(tree, tmp_path, rules_path=str(odd))
        fake = FakeYr()
        with pytest.raises(ScannerError, match="colon"):
            _run(scanner, fake, monkeypatch)
        assert fake.calls == []


class TestExitStatusAndOutput:
    def test_a_non_zero_exit_fails_even_with_output(
        self, tree, rules, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, rules_path=str(rules))
        fake = FakeYr(exit_code=1)
        with pytest.raises(ScannerError):
            _run(scanner, fake, monkeypatch)

    def test_a_timeout_fails_the_scan_and_says_so(
        self, tree, rules, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, rules_path=str(rules), scan_timeout=5)
        fake = FakeYr(timed_out=True)
        with pytest.raises(ScannerError, match=r"timed out after '5' s and was killed"):
            _run(scanner, fake, monkeypatch)
        assert 0 < fake.calls[0]["timeout"] <= 5

    @pytest.mark.parametrize(
        "stdout, match",
        [
            ("not json at all\n", "not JSON on line 1"),
            ("[1, 2]\n", "not a file result"),
            ('{"path": "a"}\n', "not a file result"),
            ('{"rules": []}\n', "not a file result"),
            ('{"path": 3, "rules": []}\n', "not a file result"),
            (CAPTURED_POSITIVE + "{broken\n", "not JSON on line 2"),
        ],
    )
    def test_malformed_output_fails_the_scan_and_is_not_quoted(
        self, stdout, match, tree, rules, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, rules_path=str(rules))
        fake = FakeYr(stdout=stdout)
        with pytest.raises(ScannerError, match=match) as raised:
            _run(scanner, fake, monkeypatch)
        assert "broken" not in str(raised.value)
        assert "not json at all" not in str(raised.value)

    def test_empty_output_with_exit_zero_is_a_clean_scan(
        self, tree, rules, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, rules_path=str(rules))
        report = _run(scanner, FakeYr(stdout=CAPTURED_NEGATIVE), monkeypatch)
        assert isinstance(report, SarifReport)
        assert _findings(report) == []
        assert scanner.targets_attempted == 1

    def test_missing_binary_is_reported_as_unsatisfied_dependencies(
        self, tree, rules, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(ys, "find_executable", lambda cmd: None)
        scanner = _scanner(tree, tmp_path, rules_path=str(rules))
        fake = FakeYr()
        assert _run(scanner, fake, monkeypatch) is False
        assert scanner.dependencies_satisfied is False
        assert fake.calls == []

    def test_dependency_check_reports_presence(self, tree, tmp_path, monkeypatch):
        scanner = _scanner(tree, tmp_path)
        monkeypatch.setattr(ys, "find_executable", lambda cmd: None)
        assert scanner.validate_plugin_dependencies() is False
        monkeypatch.setattr(ys, "find_executable", lambda cmd: "/fake/bin/yr")
        assert scanner.validate_plugin_dependencies() is True


class TestExclusions:
    def test_results_under_an_ash_output_directory_are_dropped(
        self, tree, rules, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, rules_path=str(rules))
        monkeypatch.setattr(
            scanner, "_ash_output_dirs_inside", lambda target: [Path(".ash/ash_output")]
        )
        stdout = (
            json.dumps(
                {
                    "path": "./.ash/ash_output/old.json",
                    "rules": [{"identifier": "demo_marker"}],
                }
            )
            + "\n"
            + CAPTURED_POSITIVE
        )
        report = _run(scanner, FakeYr(stdout=stdout), monkeypatch)
        assert [f[3] for f in _findings(report)] == ["src/a.txt", "src/a.txt"]

    def test_a_global_ignore_path_drops_its_results(
        self, tree, rules, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, rules_path=str(rules))
        report = _run(
            scanner,
            FakeYr(),
            monkeypatch,
            global_ignore_paths=[IgnorePathWithReason(path="src/**", reason="test")],
        )
        assert _findings(report) == []


class TestInstall:
    _PUBLISHED = [
        ("linux", "amd64"),
        ("linux", "arm64"),
        ("darwin", "amd64"),
        ("darwin", "arm64"),
        ("windows", "amd64"),
    ]

    def test_install_commands_cover_every_published_platform(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
        scanner = _scanner(tmp_path, tmp_path)
        for platform, arch in self._PUBLISHED:
            commands = scanner.get_installation_commands(platform, arch)
            assert commands, f"no install command for {platform}/{arch}"
            # A command is a CustomCommand whose argv runs the module-local installer.
            argv = " ".join(str(a) for a in commands[0].args)
            assert "yara_x_install" in argv and platform in argv and arch in argv

    def test_an_unpublished_platform_gets_no_install_command(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
        scanner = _scanner(tmp_path, tmp_path)
        assert scanner.get_installation_commands("windows", "arm64") == []
