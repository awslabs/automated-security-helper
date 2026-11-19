# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""SpotBugsScanner: the invocation, the input discovery, the report and the install.

The report tests read SARIF in the shape SpotBugs 4.10.5 with Find Security Bugs 1.14.0
wrote when run over the dom4j 2.2.0 jar (2026-11-19): ``level`` is ``error``,
``warning`` or ``note`` per result, the rule's category is in
``tool.driver.rules[].properties.tags``, the locations are source-style paths, and
Find Security Bugs is listed under ``tool.extensions``. The four results below are
rows of that run, with the rule ids, levels, paths and lines it wrote. The scan()
tests replace the subprocess with a fake, so they run on every platform without Java.
"""

from __future__ import annotations

import json
import struct
import sys
import tarfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_spotbugs_plugins
from automated_security_helper.plugin_modules.ash_spotbugs_plugins import (
    spotbugs_scanner as ss,
)
from automated_security_helper.plugin_modules.ash_spotbugs_plugins.spotbugs_scanner import (
    SpotBugsScanner,
    SpotBugsScannerConfig,
    SpotBugsScannerConfigOptions,
    class_root_of,
    discover_jvm_inputs,
    install_pinned_spotbugs,
    resolve_source_uri,
    spotbugs_install_commands,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.download_utils import NO_BIN_DIRECTORY

pytestmark = pytest.mark.unit

#: (rule id, rule category, SARIF level, uri, start line): rows of the dom4j run.
CAPTURED_RESULTS: List[Tuple[str, str, str, str, int]] = [
    (
        "EI_EXPOSE_REP",
        "MALICIOUS_CODE",
        "note",
        "org/dom4j/DocumentFactory.java",
        333,
    ),
    (
        "USO_UNSAFE_METHOD_SYNCHRONIZATION",
        "SECURITY",
        "error",
        "org/dom4j/DocumentFactory.java",
        89,
    ),
    (
        "OBJECT_DESERIALIZATION",
        "SECURITY",
        "warning",
        "org/dom4j/io/SAXEventRecorder.java",
        464,
    ),
    (
        "XXE_XMLREADER",
        "SECURITY",
        "warning",
        "org/dom4j/io/SAXValidator.java",
        67,
    ),
]

#: What the default options keep of CAPTURED_RESULTS (the SECURITY rules), written out
#: by hand: (rule, SARIF level, ASH severity, start line), in report order.
SECURITY_EXPECTED = [
    ("USO_UNSAFE_METHOD_SYNCHRONIZATION", "error", "HIGH", 89),
    ("OBJECT_DESERIALIZATION", "warning", "MEDIUM", 464),
    ("XXE_XMLREADER", "warning", "MEDIUM", 67),
]


def sarif_text(
    results: Optional[List[Tuple[str, str, Optional[str], str, int]]] = None,
    *,
    findsecbugs: bool = True,
) -> str:
    """SARIF as SpotBugs writes it, for ``(rule, category, level, uri, line)`` rows."""
    rows = CAPTURED_RESULTS if results is None else results
    rule_ids: List[str] = []
    categories: Dict[str, str] = {}
    for rule, category, _level, _uri, _line in rows:
        if rule not in categories:
            rule_ids.append(rule)
            categories[rule] = category
    rules = [
        {
            "id": rule,
            "shortDescription": {"text": f"{rule} short description."},
            "properties": {"tags": [categories[rule]]},
        }
        for rule in rule_ids
    ]
    extensions = [
        {"name": "edu.umd.cs.findbugs.plugins.core", "version": "4.10.5"},
    ]
    if findsecbugs:
        extensions.append({"name": "com.h3xstream.findsecbugs", "version": ""})
    out_results = []
    for rule, _category, level, uri, line in rows:
        result: Dict[str, Any] = {
            "ruleId": rule,
            "ruleIndex": rule_ids.index(rule),
            "message": {"text": f"{rule} message"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": line},
                    }
                }
            ],
        }
        if level is not None:
            result["level"] = level
        out_results.append(result)
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SpotBugs",
                            "version": "4.10.5",
                            "rules": rules,
                        },
                        "extensions": extensions,
                    },
                    "results": out_results,
                }
            ],
        }
    )


def class_bytes(internal_name: str) -> bytes:
    """The smallest class file holding ``internal_name``: a constant pool, no members."""

    def utf8(text: str) -> bytes:
        raw = text.encode("utf-8")
        return b"\x01" + struct.pack(">H", len(raw)) + raw

    pool = (
        utf8(internal_name)
        + b"\x07"
        + struct.pack(">H", 1)
        + utf8("java/lang/Object")
        + b"\x07"
        + struct.pack(">H", 3)
    )
    return (
        b"\xca\xfe\xba\xbe"
        + struct.pack(">HH", 0, 52)
        + struct.pack(">H", 5)
        + pool
        + struct.pack(">HHH", 0x21, 2, 4)
    )


def _findings(report: SarifReport) -> List[tuple]:
    """(ruleId, SARIF level, ASH severity, start line) for every result, in order."""
    out = []
    for r in report.get_all_results():
        loc = r.locations[0].physicalLocation.root
        out.append(
            (
                r.ruleId,
                getattr(r.level, "value", r.level),
                getattr(r.properties, "issue_severity", None),
                loc.region.startLine,
            )
        )
    return out


def _uris(report: SarifReport) -> List[str]:
    return [
        r.locations[0].physicalLocation.root.artifactLocation.uri
        for r in report.get_all_results()
    ]


class FakeSpotBugs:
    """Stands in for _run_subprocess: records argv, writes a SARIF report."""

    def __init__(
        self,
        text: Optional[str] = None,
        exit_code: int = 3,
        write_report: bool = True,
        timed_out: bool = False,
        stderr: str = "",
    ):
        self.text = sarif_text() if text is None else text
        self.exit_code, self.write_report = exit_code, write_report
        self.timed_out, self.stderr = timed_out, stderr
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, cwd=None, **_):
            self.calls.append(
                {"argv": list(command), "env": env, "timeout": timeout, "cwd": cwd}
            )
            if self.timed_out:
                scanner.exit_code = -9
                return {"timed_out": True}
            report_arg = next(a for a in command if a.startswith("-sarif="))
            path = Path(report_arg.split("=", 1)[1])
            if self.write_report:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(self.text, encoding="utf-8")
            scanner.exit_code = self.exit_code
            return {"returncode": self.exit_code, "stdout": "", "stderr": self.stderr}

        return run

    @property
    def argv(self) -> List[str]:
        return self.calls[0]["argv"]


def _scanner(
    source: Path,
    tmp_path: Path,
    *,
    output_dir: Optional[Path] = None,
    **options,
) -> SpotBugsScanner:
    output = output_dir or tmp_path / "out"
    return SpotBugsScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=get_default_config(),
        ),
        config=SpotBugsScannerConfig(
            enabled=True, options=SpotBugsScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    """A Maven-shaped tree: compiled classes, a jar, and the sources they came from."""
    src = tmp_path / "src"
    classes = src / "target" / "classes" / "org" / "dom4j" / "io"
    classes.mkdir(parents=True)
    (classes / "SAXValidator.class").write_bytes(
        class_bytes("org/dom4j/io/SAXValidator")
    )
    (src / "target" / "app.jar").write_bytes(b"PK\x03\x04")
    sources = src / "src" / "main" / "java" / "org" / "dom4j" / "io"
    sources.mkdir(parents=True)
    (sources / "SAXValidator.java").write_text("class SAXValidator {}\n")
    return src


@pytest.fixture
def sources_only(tmp_path) -> Path:
    src = tmp_path / "sources"
    (src / "src" / "main" / "java").mkdir(parents=True)
    (src / "src" / "main" / "java" / "App.java").write_text("class App {}\n")
    return src


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(ss, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


def _run(
    scanner: SpotBugsScanner,
    fake: FakeSpotBugs,
    monkeypatch,
    target: Optional[Path] = None,
    target_type: str = "source",
):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=Path(target or scanner.context.source_dir), target_type=target_type
    )


class TestCommunityPlugin:
    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert SpotBugsScannerConfig().enabled is True
        assert SpotBugsScannerConfig().name == "spotbugs"

    def test_the_builtin_config_does_not_declare_it(self):
        assert not hasattr(get_default_config().scanners, "spotbugs")

    def test_the_module_exports_the_scanner(self):
        assert ash_spotbugs_plugins.ASH_SCANNERS == [SpotBugsScanner]
        assert ash_spotbugs_plugins.ASH_REPORTERS == []

    def test_the_class_states_how_it_runs(self):
        assert SpotBugsScanner.python_only is False
        assert SpotBugsScanner.success_exit_codes == {0, 1, 2, 3}
        assert SpotBugsScanner.offline_strategy.value == "bundled"

    def test_no_option_takes_a_path_from_the_scanned_tree(self):
        assert set(SpotBugsScannerConfigOptions.model_fields) >= {
            "confidence",
            "effort",
            "security_only",
        }
        assert not [
            name
            for name in SpotBugsScannerConfigOptions.model_fields
            if "file" in name or "path" in name or "filter" in name
        ]


class TestInputDiscovery:
    def test_the_class_name_is_read_from_the_constant_pool(self):
        assert ss._parse_this_class(class_bytes("org/x/Foo")) == "org/x/Foo"

    @pytest.mark.parametrize(
        "data",
        [b"", b"not a class file", b"\xca\xfe\xba\xbe", class_bytes("a/B")[:14]],
        ids=["empty", "text", "magic only", "truncated pool"],
    )
    def test_a_file_that_is_not_a_whole_class_has_no_name(self, data):
        assert ss._parse_this_class(data) is None

    def test_the_class_root_is_the_path_minus_the_package(self, tree):
        file = (
            tree / "target" / "classes" / "org" / "dom4j" / "io" / "SAXValidator.class"
        )
        assert class_root_of(file) == tree / "target" / "classes"

    def test_a_class_at_the_wrong_path_has_no_root(self, tmp_path):
        stray = tmp_path / "elsewhere" / "Foo.class"
        stray.parent.mkdir()
        stray.write_bytes(class_bytes("org/x/Foo"))
        assert class_root_of(stray) is None

    def test_archives_and_class_roots_are_found(self, tree):
        found = discover_jvm_inputs(tree)
        assert found.class_roots == [tree / "target" / "classes"]
        assert found.archives == [tree / "target" / "app.jar"]
        assert found.paths() == [
            tree / "target" / "classes",
            tree / "target" / "app.jar",
        ]

    def test_a_tree_of_sources_has_none(self, sources_only):
        assert discover_jvm_inputs(sources_only).empty

    def test_a_link_is_never_an_input_and_never_followed(self, tree, tmp_path):
        outside = tmp_path / "outside"
        (outside / "p").mkdir(parents=True)
        (outside / "p" / "Foo.class").write_bytes(class_bytes("p/Foo"))
        (outside / "other.jar").write_bytes(b"PK")
        links = tmp_path / "links"
        links.mkdir()
        (links / "dir").symlink_to(outside, target_is_directory=True)
        (links / "file.jar").symlink_to(outside / "other.jar")
        assert discover_jvm_inputs(links).empty
        # A link added beside a tree's own inputs adds nothing to them.
        before = discover_jvm_inputs(tree)
        (tree / "linked").symlink_to(outside, target_is_directory=True)
        assert discover_jvm_inputs(tree) == before

    def test_a_skipped_directory_is_not_entered(self, tree):
        skipped = tree / "target"
        assert discover_jvm_inputs(tree, [skipped]).empty

    def test_an_unambiguous_source_path_replaces_the_class_style_one(self, tree):
        index = ss._source_index(tree)
        assert (
            resolve_source_uri("org/dom4j/io/SAXValidator.java", index)
            == "src/main/java/org/dom4j/io/SAXValidator.java"
        )

    def test_an_ambiguous_or_unknown_source_path_is_left_alone(self, tmp_path):
        for module in ("a", "b"):
            path = tmp_path / module / "org" / "X.java"
            path.parent.mkdir(parents=True)
            path.write_text("class X {}")
        index = ss._source_index(tmp_path)
        assert resolve_source_uri("org/X.java", index) == "org/X.java"
        assert resolve_source_uri("org/Missing.java", index) == "org/Missing.java"


class TestInvocation:
    def test_every_fixed_flag_and_the_inputs(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeSpotBugs()
        _run(scanner, fake, monkeypatch)
        argv = fake.argv
        report = next(a for a in argv if a.startswith("-sarif="))
        assert argv[:6] == [
            "spotbugs",
            "-textui",
            "-exitcode",
            "-medium",
            "-effort:default",
            report,
        ]
        assert report.endswith("/source/spotbugs.sarif")
        assert argv[6:] == [
            (tree / "target" / "classes").as_posix(),
            (tree / "target" / "app.jar").as_posix(),
        ]
        assert all(Path(a).is_absolute() for a in argv[6:])

    def test_options_become_one_token_each(self, tree, tmp_path, on_path, monkeypatch):
        scanner = _scanner(tree, tmp_path, confidence="high", effort="max")
        fake = FakeSpotBugs()
        _run(scanner, fake, monkeypatch)
        assert "-high" in fake.argv and "-effort:max" in fake.argv
        assert "-medium" not in fake.argv

    @pytest.mark.parametrize(
        "flag",
        [
            "-include",
            "-exclude",
            "-excludeBugs",
            "-userPrefs",
            "-auxclasspath",
            "-pluginList",
            "-onlyAnalyze",
            "-xml",
        ],
    )
    def test_flags_that_read_the_tree_or_name_a_path_are_never_passed(
        self, tree, tmp_path, on_path, monkeypatch, flag
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeSpotBugs()
        _run(scanner, fake, monkeypatch)
        assert not [a for a in fake.argv if a == flag or a.startswith(flag + "=")]

    def test_a_tree_without_compiled_code_never_reaches_the_tool(
        self, sources_only, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(sources_only, tmp_path)
        fake = FakeSpotBugs()
        assert _run(scanner, fake, monkeypatch) is True
        assert fake.calls == []
        assert "no compiled JVM code" in scanner._nothing_scanned_reason
        assert scanner.errors == []

    def test_the_skip_is_not_an_error_on_the_converted_target_either(
        self, sources_only, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(sources_only, tmp_path)
        fake = FakeSpotBugs()
        assert _run(scanner, fake, monkeypatch, target_type="converted") is True
        assert fake.calls == []

    def test_ashs_output_directory_inside_the_tree_is_not_scanned(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        output = tree / ".ash" / "ash_output"
        (output / "p").mkdir(parents=True)
        (output / "p" / "Foo.class").write_bytes(class_bytes("p/Foo"))
        (output / "old.jar").write_bytes(b"PK")
        scanner = _scanner(tree, tmp_path, output_dir=output)
        fake = FakeSpotBugs()
        _run(scanner, fake, monkeypatch)
        inputs = [a for a in fake.argv if not a.startswith(("-", "spotbugs"))]
        assert inputs and not [a for a in inputs if ".ash" in a]

    def test_too_many_inputs_for_one_command_line_fail_the_scan(
        self, tmp_path, on_path, monkeypatch
    ):
        src = tmp_path / "big"
        src.mkdir()
        for number in range(400):
            (src / f"{'x' * 80}-{number}.jar").write_bytes(b"PK")
        scanner = _scanner(src, tmp_path)
        fake = FakeSpotBugs()
        with pytest.raises(ScannerError, match="do not fit one SpotBugs command"):
            _run(scanner, fake, monkeypatch)
        assert fake.calls == []


class TestReport:
    def test_security_results_are_rated_and_located(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeSpotBugs(), monkeypatch)
        assert _findings(report) == SECURITY_EXPECTED

    def test_the_level_and_the_severity_agree_on_every_row(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        rows = [
            ("R_ERR", "SECURITY", "error", "a/A.java", 1),
            ("R_WARN", "SECURITY", "warning", "a/A.java", 2),
            ("R_NOTE", "SECURITY", "note", "a/A.java", 3),
            ("R_NONE", "SECURITY", "none", "a/A.java", 4),
        ]
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeSpotBugs(sarif_text(rows)), monkeypatch)
        assert _findings(report) == [
            ("R_ERR", "error", "HIGH", 1),
            ("R_WARN", "warning", "MEDIUM", 2),
            ("R_NOTE", "note", "LOW", 3),
            ("R_NONE", "none", "INFO", 4),
        ]

    def test_a_result_without_a_level_is_medium(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        rows = [("R_X", "SECURITY", None, "a/A.java", 1)]
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeSpotBugs(sarif_text(rows)), monkeypatch)
        assert _findings(report) == [("R_X", "warning", "MEDIUM", 1)]

    def test_results_are_tagged_and_failing(self, tree, tmp_path, on_path, monkeypatch):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeSpotBugs(), monkeypatch)
        for result in report.get_all_results():
            assert {"security", "jvm"} <= set(result.properties.tags)
            assert getattr(result.kind, "value", result.kind) == "fail"

    def test_the_non_security_rules_are_kept_when_asked(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, security_only=False)
        report = _run(scanner, FakeSpotBugs(), monkeypatch)
        assert [f[0] for f in _findings(report)] == [r[0] for r in CAPTURED_RESULTS]
        assert _findings(report)[0] == ("EI_EXPOSE_REP", "note", "LOW", 333)

    def test_negative_control_a_clean_run_has_no_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeSpotBugs(sarif_text([]), exit_code=0), monkeypatch)
        assert report.get_all_results() == []
        assert scanner.errors == []

    def test_only_non_security_findings_leave_nothing_by_default(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        rows = [CAPTURED_RESULTS[0]]
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeSpotBugs(sarif_text(rows)), monkeypatch)
        assert report.get_all_results() == []

    def test_a_source_file_in_the_tree_gives_the_result_its_repository_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeSpotBugs(), monkeypatch)
        assert _uris(report) == [
            "org/dom4j/DocumentFactory.java",
            "org/dom4j/io/SAXEventRecorder.java",
            "src/main/java/org/dom4j/io/SAXValidator.java",
        ]

    def test_the_report_round_trips_as_sarif(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeSpotBugs(), monkeypatch)
        again = SarifReport.model_validate_json(
            report.model_dump_json(exclude_none=True, by_alias=True)
        )
        assert _findings(again) == SECURITY_EXPECTED

    def test_a_run_without_find_security_bugs_fails(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeSpotBugs(sarif_text(findsecbugs=False))
        with pytest.raises(
            ScannerError, match="Find Security Bugs plugin was not loaded"
        ):
            _run(scanner, fake, monkeypatch)


class TestExitStatus:
    @pytest.mark.parametrize("code", [0, 1, 2, 3])
    def test_the_documented_finished_codes_succeed(
        self, tree, tmp_path, on_path, monkeypatch, code
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeSpotBugs(exit_code=code), monkeypatch)
        assert isinstance(report, SarifReport)

    @pytest.mark.parametrize("code", [4, 5, 7, 126, 137])
    def test_an_error_flag_or_any_other_code_fails_even_with_a_report_on_disk(
        self, tree, tmp_path, on_path, monkeypatch, code
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeSpotBugs(exit_code=code)
        with pytest.raises(ScannerError, match=f"spotbugs exited {code}"):
            _run(scanner, fake, monkeypatch)

    def test_a_run_that_wrote_no_report_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeSpotBugs(write_report=False, exit_code=0)
        with pytest.raises(ScannerError):
            _run(scanner, fake, monkeypatch)

    def test_a_report_left_by_an_earlier_run_is_removed_before_the_next_one(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeSpotBugs(), monkeypatch)
        stale = Path(scanner.results_dir) / "source" / "spotbugs.sarif"
        assert stale.is_file()
        second = _scanner(tree, tmp_path)
        fake = FakeSpotBugs(write_report=False, exit_code=0)
        with pytest.raises(ScannerError):
            _run(second, fake, monkeypatch)

    def test_a_timeout_fails_the_scan_and_says_so(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, scan_timeout=5)
        fake = FakeSpotBugs(timed_out=True)
        with pytest.raises(ScannerError, match="timed out"):
            _run(scanner, fake, monkeypatch)
        assert 0 < fake.calls[0]["timeout"] <= 5

    @pytest.mark.parametrize(
        "text",
        ["this is not json", "[1, 2, 3", "{}", '{"version": "2.1.0", "runs": []}'],
        ids=["not json", "truncated json", "no sarif run", "empty runs"],
    )
    def test_malformed_output_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch, text
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeSpotBugs(text, exit_code=0), monkeypatch)

    def test_an_empty_report_file_is_not_a_clean_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError, match="empty"):
            _run(scanner, FakeSpotBugs("", exit_code=0), monkeypatch)

    def test_the_failure_names_the_log_and_does_not_quote_it(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeSpotBugs(exit_code=4, stderr="Missing class org.secret.Internal")
        with pytest.raises(ScannerError) as raised:
            _run(scanner, fake, monkeypatch)
        assert "log is not quoted here" in str(raised.value)
        assert "org.secret.Internal" not in str(raised.value)


class TestDependencyCheck:
    def test_missing_binary_is_reported_as_unsatisfied_dependencies(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(ss, "find_executable", lambda cmd: None)
        scanner = _scanner(tree, tmp_path)
        fake = FakeSpotBugs()
        assert _run(scanner, fake, monkeypatch) is False
        assert scanner.dependencies_satisfied is False
        assert fake.calls == []

    def test_the_binary_on_path_is_accepted(self, tree, tmp_path, on_path):
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is True

    def test_a_recorded_reason_refuses_before_the_path_is_read(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(ss, "find_executable", lambda cmd: "/fake/bin/spotbugs")
        scanner = _scanner(tree, tmp_path)
        scanner.dependency_unavailable_reason = "a copy inside the tree was refused"
        assert scanner.validate_plugin_dependencies() is False


class TestInstall:
    def test_install_commands_cover_every_published_platform(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(ss, "current_bin_path", lambda: tmp_path / "bin")
        table = spotbugs_install_commands()
        for platform, arch in ss.INSTALL_PLATFORMS:
            (command,) = table[platform][arch]
            assert command.args[:2] == [sys.executable, "-c"]
            assert command.args[3] == (tmp_path / "bin").as_posix()
            assert command.shell is False
        assert "windows" not in table

    def test_without_a_bin_directory_the_command_refuses_and_says_why(
        self, monkeypatch
    ):
        monkeypatch.setattr(ss, "current_bin_path", lambda: None)
        table = spotbugs_install_commands()
        assert table["linux"]["amd64"][0].args[3] == NO_BIN_DIRECTORY

    def test_the_pins_are_stable_releases_with_full_digests(self):
        assert ss.SPOTBUGS_VERSION == "4.10.5"
        assert ss.FINDSECBUGS_VERSION == "1.14.0"
        for digest in (ss.SPOTBUGS_SHA256, ss.FINDSECBUGS_SHA256):
            assert len(digest) == 64 and int(digest, 16) >= 0
        assert ss.SPOTBUGS_URL.endswith("/4.10.5/spotbugs-4.10.5.tgz")
        assert ss.FINDSECBUGS_URL.endswith("/1.14.0/findsecbugs-plugin-1.14.0.jar")

    def _fake_download(self, tmp_path, calls):
        release = tmp_path / "release"
        release.mkdir()
        archive = release / "spotbugs-4.10.5.tgz"
        staging = tmp_path / "staging" / "spotbugs-4.10.5"
        (staging / "bin").mkdir(parents=True)
        (staging / "lib").mkdir()
        (staging / "bin" / "spotbugs").write_text("#!/bin/sh\n")
        (staging / "lib" / "spotbugs.jar").write_bytes(b"jar")
        with tarfile.open(archive, "w:gz") as tar:
            tar.add(staging, arcname="spotbugs-4.10.5")
        jar = release / "findsecbugs-plugin-1.14.0.jar"
        jar.write_bytes(b"findsecbugs")

        def download(url, destination, rename_to=None, expected_sha256=None, **_):
            calls.append((url, expected_sha256))
            source = archive if url.endswith(".tgz") else jar
            landed = Path(destination) / source.name
            landed.write_bytes(source.read_bytes())
            return landed

        return download

    def test_install_extracts_the_release_and_links_the_launcher(
        self, tmp_path, monkeypatch
    ):
        calls: List[tuple] = []
        monkeypatch.setattr(ss, "download_file", self._fake_download(tmp_path, calls))
        bin_dir = tmp_path / "bin"
        link = install_pinned_spotbugs(bin_dir)
        home = bin_dir / "spotbugs-4.10.5"
        assert link == bin_dir / "spotbugs" and link.is_symlink()
        assert link.resolve() == (home / "bin" / "spotbugs").resolve()
        assert (home / "bin" / "spotbugs").stat().st_mode & 0o100
        plugin = home / "plugin" / "findsecbugs-plugin-1.14.0.jar"
        assert plugin.read_bytes() == b"findsecbugs"
        assert calls == [
            (ss.SPOTBUGS_URL, ss.SPOTBUGS_SHA256),
            (ss.FINDSECBUGS_URL, ss.FINDSECBUGS_SHA256),
        ]

    def test_a_download_that_fails_its_digest_installs_nothing(
        self, tmp_path, monkeypatch
    ):
        def refuse(url, destination, rename_to=None, expected_sha256=None, **_):
            raise RuntimeError("SHA256 mismatch")

        monkeypatch.setattr(ss, "download_file", refuse)
        bin_dir = tmp_path / "bin"
        with pytest.raises(RuntimeError, match="SHA256 mismatch"):
            install_pinned_spotbugs(bin_dir)
        assert list(bin_dir.iterdir()) == []

    def test_an_existing_installation_is_not_overwritten(self, tmp_path, monkeypatch):
        monkeypatch.setattr(ss, "download_file", self._fake_download(tmp_path, []))
        bin_dir = tmp_path / "bin"
        install_pinned_spotbugs(bin_dir)
        with pytest.raises(ScannerError, match="already exists"):
            install_pinned_spotbugs(bin_dir)
