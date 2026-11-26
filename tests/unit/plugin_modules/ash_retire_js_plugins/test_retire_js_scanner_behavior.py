# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""RetireJsScanner: the invocation, the JSON-to-SARIF conversion and failure handling.

The subprocess is replaced by a fake that writes a retire.js JSON report in the shape
read from retire.js 6.1.1's ``reporters/json.ts`` and ``types.ts``
(``{version, start, data: [{file, results: [{component, version, detection,
vulnerabilities: [...]}]}], messages, errors, time}``), with each ``file`` the absolute
path under ``--path`` that retire.js writes. Most reports below are written by hand
from that shape so the tests run on every platform without Node. The
``TestCapturedReport`` rows read the output of real retire 6.1.1 runs, committed under
``tests/test_data/scanners/retire-js/captured`` (see its README), and the severity
mapping is checked over that capture as well as row by row.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import OfflineStrategy
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_retire_js_plugins
from automated_security_helper.plugin_modules.ash_retire_js_plugins import (
    retire_js_scanner as rs,
)
from automated_security_helper.plugin_modules.ash_retire_js_plugins.retire_js_scanner import (
    INSTALL_PLATFORMS,
    RETIRE_VERSION,
    RetireJsScanner,
    RetireJsScannerConfig,
    RetireJsScannerConfigOptions,
    convert_retire_report,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.sandbox.policy import SandboxRequirements

pytestmark = pytest.mark.unit


def _vuln(severity: Optional[str], cve: str, below: str = "3.5.0") -> Dict[str, Any]:
    vuln: Dict[str, Any] = {
        "below": below,
        "atOrAbove": "1.0.0",
        "cwe": ["CWE-79"],
        "identifiers": {"CVE": [cve], "summary": f"summary of {cve}"},
        "info": [f"https://example.invalid/{cve}"],
    }
    if severity is not None:
        vuln["severity"] = severity
    return vuln


def _report(data: List[Dict[str, Any]], errors: Optional[list] = None) -> str:
    return json.dumps(
        {
            "version": "6.1.1",
            "start": "2026-11-18T00:00:00.000Z",
            "data": data,
            "messages": [],
            "errors": errors or [],
            "time": 1.5,
        }
    )


#: Hand-written from the retire.js type definitions: one vulnerable jQuery with a
#: critical, a medium and an unrated vulnerability, and a vulnerable lodash. The
#: ``./`` paths are placeholders the fake joins to ``--path``, as retire.js reports.
POSITIVE = _report(
    [
        {
            "file": "./static/jquery-3.4.1.min.js",
            "results": [
                {
                    "component": "jquery",
                    "version": "3.4.1",
                    "detection": "filecontent",
                    "vulnerabilities": [
                        _vuln("critical", "CVE-2099-0001"),
                        _vuln("medium", "CVE-2099-0002"),
                        _vuln(None, "CVE-2099-0003"),
                    ],
                }
            ],
        },
        {
            "file": "./static/lodash.min.js",
            "results": [
                {
                    "component": "lodash",
                    "version": "4.17.4",
                    "detection": "filecontent",
                    "vulnerabilities": [_vuln("high", "CVE-2099-0004", "4.17.12")],
                }
            ],
        },
    ]
)

POSITIVE_EXPECTED = [
    ("CVE-2099-0001", "error", "CRITICAL", "static/jquery-3.4.1.min.js"),
    ("CVE-2099-0002", "warning", "MEDIUM", "static/jquery-3.4.1.min.js"),
    # No rating: critical, as retire.js's own exit logic counts it.
    ("CVE-2099-0003", "error", "CRITICAL", "static/jquery-3.4.1.min.js"),
    ("CVE-2099-0004", "error", "HIGH", "static/lodash.min.js"),
]

NEGATIVE = _report([])


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
            )
        )
    return out


def _flag(argv: List[str], prefix: str) -> Optional[str]:
    for token in argv:
        if token.startswith(prefix):
            return token[len(prefix) :]
    return None


def _as_reported(text: str, scan_path: str) -> str:
    """``text`` with every ``./`` file placeholder joined to ``scan_path``."""
    document = json.loads(text)
    if isinstance(document, dict) and isinstance(document.get("data"), list):
        for entry in document["data"]:
            name = entry.get("file") if isinstance(entry, dict) else None
            if isinstance(name, str) and name.startswith("./"):
                entry["file"] = os.path.join(scan_path, *name[2:].split("/"))
    return json.dumps(document)


class FakeRetire:
    """Stands in for _run_subprocess: records argv, writes a retire.js JSON report.

    The report's ``./`` placeholders become absolute paths under ``--path``, the form
    retire.js 6.1.1 writes (tests/test_data/scanners/retire-js/captured).
    """

    def __init__(
        self,
        text: Optional[str] = POSITIVE,
        exit_code: int = 13,
        timed_out: bool = False,
    ):
        self.text, self.exit_code, self.timed_out = text, exit_code, timed_out
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, cwd=None, **_):
            self.calls.append(
                {"argv": list(command), "env": env, "timeout": timeout, "cwd": cwd}
            )
            out = next(a for a in command if a.startswith("--outputpath="))
            path = Path(out.split("=", 1)[1])
            if self.text is not None and not self.timed_out:
                path.parent.mkdir(parents=True, exist_ok=True)
                text = self.text
                try:
                    text = _as_reported(text, _flag(command, "--path=") or ".")
                except ValueError:
                    pass
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


def _scanner(
    source: Path, tmp_path: Path, output: Optional[Path] = None, **options
) -> RetireJsScanner:
    config = get_default_config()
    output = output if output is not None else tmp_path / "out"
    return RetireJsScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=config,
        ),
        config=RetireJsScannerConfig(
            enabled=True, options=RetireJsScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    (src / "static").mkdir(parents=True)
    (src / "static" / "jquery-3.4.1.min.js").write_text("/*! jQuery v3.4.1 */\n")
    (src / "static" / "lodash.min.js").write_text("/*! lodash 4.17.4 */\n")
    return src


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(rs, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


def _run(scanner, fake, monkeypatch, target=None, target_type="source"):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=Path(target or scanner.context.source_dir), target_type=target_type
    )


class TestAlphaPlugin:
    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert RetireJsScannerConfig().enabled is True
        assert RetireJsScannerConfig().name == "retire-js"

    def test_the_builtin_config_does_not_declare_it(self):
        assert not hasattr(get_default_config().scanners, "retire-js")

    def test_the_module_exports_the_scanner(self):
        assert ash_retire_js_plugins.ASH_SCANNERS == [RetireJsScanner]
        assert ash_retire_js_plugins.ASH_REPORTERS == []

    def test_class_declarations(self):
        assert RetireJsScanner.python_only is False
        assert RetireJsScanner.offline_strategy is OfflineStrategy.SKIP_OFFLINE
        assert RetireJsScanner.success_exit_codes == {0, 13}
        assert RetireJsScanner.sandbox_requirements == SandboxRequirements(network=True)
        assert RetireJsScanner.quote_tool_stderr is False
        assert RetireJsScanner.unquoted_failure_tool_name == "retire"


class TestInvocation:
    def test_every_fixed_flag_and_the_scan_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeRetire()
        _run(scanner, fake, monkeypatch)
        argv = fake.argv
        assert argv[0] == "retire"
        for expected in (
            "--outputformat=json",
            "--exitwith=13",
            "--nocache",
            f"--path={tree.absolute()}",
        ):
            assert expected in argv
        assert fake.calls[0]["cwd"] is None, "the run starts in the source directory"
        # Every value is attached to its flag, so none can be read as another option.
        assert all(a.startswith("--") for a in argv[1:])

    def test_the_converted_target_is_an_absolute_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        converted = tmp_path / "out" / "converted"
        converted.mkdir(parents=True)
        (converted / "x.js").write_text("var a = 1;\n")
        scanner = _scanner(tree, tmp_path)
        fake = FakeRetire(text=NEGATIVE, exit_code=0)
        _run(scanner, fake, monkeypatch, target=converted, target_type="converted")
        assert f"--path={converted.absolute()}" in fake.argv

    @pytest.mark.parametrize(
        "forbidden",
        [
            "--ignore",
            "--jsrepo",
            "--proxy",
            "--cacert",
            "--insecure",
            "--deep",
            "--includeOsv",
        ],
    )
    def test_flags_that_pick_the_rules_or_widen_network_use_are_never_passed(
        self, tree, tmp_path, on_path, monkeypatch, forbidden
    ):
        """``--ignore`` among them: retire.js resolves its entries against the
        working directory, never against ``--path``."""
        scanner = _scanner(tree, tmp_path)
        fake = FakeRetire()
        _run(scanner, fake, monkeypatch)
        assert not any(
            a == forbidden or a.startswith(f"{forbidden}=") for a in fake.argv
        )

    def test_the_ignore_file_is_ashs_own_and_never_the_trees(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        """The argv names ASH's ignore file, outside the tree, holding only path
        entries ASH wrote; the tree's planted ignore files are never named. The
        capture rows below show retire.js 6.1.1 then reads neither planted file."""
        (tree / ".retireignore.json").write_text(
            '[{"component": "jquery", "justification": "planted"}]\n'
        )
        (tree / ".retireignore").write_text("static\n")
        scanner = _scanner(tree, tmp_path)
        fake = FakeRetire()
        _run(scanner, fake, monkeypatch)
        ignore_file = Path(_flag(fake.argv, "--ignorefile="))
        assert not ignore_file.resolve().is_relative_to(tree.resolve())
        entries = json.loads(ignore_file.read_text(encoding="utf-8"))
        assert isinstance(entries, list)
        assert all(set(entry) == {"path", "justification"} for entry in entries)
        assert not any(".retireignore" in a for a in fake.argv)

    def test_ash_own_output_directories_are_listed_absolute_with_a_separator(
        self, tree, tmp_path
    ):
        scanner = _scanner(tree, tmp_path)
        entries = scanner._ignore_entries(
            tree,
            [PurePosixPath(".ash/ash_output"), PurePosixPath("odd*name")],
        )
        # A path holding `*`, a glob to retire.js, is left to the post-scan drop.
        assert [e["path"] for e in entries] == [
            str(tree.absolute() / ".ash" / "ash_output") + os.sep
        ]
        assert all(e["justification"] for e in entries)

    def test_the_output_directory_inside_the_tree_reaches_the_ignore_file(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        output = tree / ".ash" / "ash_output"
        output.mkdir(parents=True)
        scanner = _scanner(tree, tmp_path, output=output)
        fake = FakeRetire()
        _run(scanner, fake, monkeypatch)
        ignore_file = Path(_flag(fake.argv, "--ignorefile="))
        paths = [e["path"] for e in json.loads(ignore_file.read_text("utf-8"))]
        assert str(tree.absolute() / ".ash" / "ash_output") + os.sep in paths

    def test_what_still_arrives_from_ash_output_is_dropped_after_the_scan(self):
        sarif = convert_retire_report(
            json.loads(POSITIVE),
            drop_under=[PurePosixPath("static/jquery-3.4.1.min.js")],
        )
        assert [r["ruleId"] for r in sarif["runs"][0]["results"]] == ["CVE-2099-0004"]

    @pytest.mark.skipif(
        sys.platform == "win32", reason="a backslash is a separator on Windows"
    )
    def test_a_backslash_in_a_posix_file_name_is_not_a_separator(self, tmp_path):
        """A file named ``.ash\\ash_output\\x.js`` at the root of a POSIX tree is the
        tree's own file, not one under ASH's output directory."""
        src = tmp_path / "src"
        document = json.loads(
            _report(
                [
                    {
                        "file": f"{src.as_posix()}/.ash\\ash_output\\x.js",
                        "results": [
                            {
                                "component": "x",
                                "version": "1",
                                "vulnerabilities": [_vuln("low", "CVE-2099-6")],
                            }
                        ],
                    }
                ]
            )
        )
        sarif = convert_retire_report(
            document, source_root=src, drop_under=[PurePosixPath(".ash/ash_output")]
        )
        (result,) = sarif["runs"][0]["results"]
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == ".ash\\ash_output\\x.js"

    def test_a_missing_target_never_reaches_the_tool(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeRetire()
        _run(scanner, fake, monkeypatch, target=tmp_path / "gone")
        assert fake.calls == []


class TestReport:
    def test_the_positive_report_is_rated_and_located(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeRetire(), monkeypatch)
        assert _findings(report) == POSITIVE_EXPECTED

    def test_negative_control_the_clean_report_has_no_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeRetire(text=NEGATIVE, exit_code=0), monkeypatch)
        assert _findings(report) == []

    def test_results_are_marked_as_failures_with_tags(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeRetire(), monkeypatch)
        for result in report.get_all_results():
            assert getattr(result.kind, "value", result.kind) == "fail"
            assert {"sca", "vulnerable-javascript"} <= set(result.properties.tags)

    @pytest.mark.parametrize(
        "rating, level, severity",
        [
            ("critical", "error", "CRITICAL"),
            ("high", "error", "HIGH"),
            ("medium", "warning", "MEDIUM"),
            ("low", "note", "LOW"),
            # retire.js's own lowest level (severityLevels.none is 0).
            ("none", "note", "INFO"),
            (None, "error", "CRITICAL"),
            ("catastrophic", "error", "HIGH"),
        ],
    )
    def test_each_severity_row_sets_level_and_issue_severity_together(
        self, rating, level, severity
    ):
        doc = json.loads(
            _report(
                [
                    {
                        "file": "a.js",
                        "results": [
                            {
                                "component": "x",
                                "version": "1",
                                "vulnerabilities": [_vuln(rating, "CVE-2099-9")],
                            }
                        ],
                    }
                ]
            )
        )
        sarif = convert_retire_report(doc)
        result = sarif["runs"][0]["results"][0]
        assert (result["level"], result["properties"]["issue_severity"]) == (
            level,
            severity,
        )

    @staticmethod
    def _ids(vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        doc = {
            "data": [
                {
                    "file": "a.js",
                    "results": [
                        {
                            "component": "x",
                            "version": "1",
                            "vulnerabilities": vulnerabilities,
                        }
                    ],
                }
            ]
        }
        return [r["ruleId"] for r in convert_retire_report(doc)["runs"][0]["results"]]

    @pytest.mark.parametrize(
        "identifiers, expected",
        [
            ({"issue": "42"}, "RETIREJS-x-issue-42"),
            # An integer identifier is read as its number, not skipped.
            ({"issue": 42}, "RETIREJS-x-issue-42"),
            ({"bug": "7"}, "RETIREJS-x-bug-7"),
            ({"PR": "4333"}, "RETIREJS-x-PR-4333"),
            ({"retid": "73"}, "RETIREJS-x-retid-73"),
            ({"issue": "162", "retid": "73"}, "RETIREJS-x-issue-162"),
            ({"githubID": "GHSA-aaaa-bbbb-cccc", "issue": "1"}, "GHSA-aaaa-bbbb-cccc"),
        ],
    )
    def test_a_vulnerability_without_a_cve_takes_the_next_identifier(
        self, identifiers, expected
    ):
        assert self._ids([{"severity": "low", "identifiers": identifiers}]) == [
            expected
        ]

    def test_two_vulnerabilities_named_by_no_identifier_keep_apart(self):
        """With identity positional (rule, file, line 1), a shared rule id would
        merge the two findings and let one suppression hide both."""
        first = {"severity": "low", "identifiers": {"summary": "one"}, "below": "2"}
        second = {"severity": "low", "identifiers": {"summary": "two"}, "below": "2"}
        ids = self._ids([first, second])
        assert len(set(ids)) == 2
        assert all(re.fullmatch(r"RETIREJS-x-[0-9a-f]{12}", i) for i in ids)
        # Stable: the same vulnerability reads the same id on the next run.
        assert self._ids([first]) == ids[:1]

    def test_each_rule_keeps_its_own_description(self):
        first = {"severity": "low", "identifiers": {"summary": "one"}}
        second = {"severity": "low", "identifiers": {"summary": "two", "PR": "9"}}
        doc = {
            "data": [
                {
                    "file": "a.js",
                    "results": [
                        {
                            "component": "x",
                            "version": "1",
                            "vulnerabilities": [first, second],
                        }
                    ],
                }
            ]
        }
        rules = convert_retire_report(doc)["runs"][0]["tool"]["driver"]["rules"]
        assert sorted(r["shortDescription"]["text"] for r in rules) == ["one", "two"]

    def test_an_absolute_file_path_is_made_relative_to_the_source(self, tmp_path):
        src = tmp_path / "src"
        doc = json.loads(
            _report(
                [
                    {
                        "file": str(src / "js" / "a.js"),
                        "results": [
                            {
                                "component": "x",
                                "version": "1",
                                "vulnerabilities": [_vuln("low", "CVE-2099-8")],
                            }
                        ],
                    }
                ]
            )
        )
        sarif = convert_retire_report(doc, source_root=src)
        loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "js/a.js"

    def test_the_sarif_round_trips_through_the_schema_model(self):
        sarif = convert_retire_report(json.loads(POSITIVE))
        assert SarifReport.model_validate(sarif).runs


class TestExitStatus:
    def test_thirteen_means_vulnerable_libraries_and_is_a_success(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeRetire(exit_code=13), monkeypatch)
        assert scanner._exit_code_accepted()

    def test_zero_means_clean_and_is_a_success(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeRetire(text=NEGATIVE, exit_code=0), monkeypatch)
        assert scanner._exit_code_accepted()

    @pytest.mark.parametrize("code", [1, 2, 126, 137])
    def test_any_other_exit_fails_the_scan_even_with_a_report_on_disk(
        self, tree, tmp_path, on_path, monkeypatch, code
    ):
        """Exit 1 is retire.js's error exit and wins over a finding."""
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeRetire(exit_code=code), monkeypatch)

    def test_a_timeout_fails_the_scan_and_says_so(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, scan_timeout=5)
        fake = FakeRetire(timed_out=True, exit_code=124)
        with pytest.raises(ScannerError, match="timed out after '5' s"):
            _run(scanner, fake, monkeypatch)
        assert 0 < fake.calls[0]["timeout"] <= 5

    def test_a_run_that_wrote_no_report_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeRetire(text=None, exit_code=0), monkeypatch)

    def test_a_report_left_by_an_earlier_run_is_removed_before_the_next_one(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        first = FakeRetire()
        _run(scanner, first, monkeypatch)
        report = Path(_flag(first.argv, "--outputpath="))
        assert report.exists()
        with pytest.raises(ScannerError):
            _run(scanner, FakeRetire(text=None, exit_code=0), monkeypatch)
        assert not report.exists()

    def test_the_tools_stderr_is_not_copied_into_the_scans_errors(
        self, tree, tmp_path, on_path
    ):
        scanner = _scanner(tree, tmp_path)
        scanner._process_command_response(
            {"returncode": 0, "stdout": "", "stderr": "Could not scan PLANTED-PATH.js"}
        )
        assert not any("PLANTED-PATH" in line for line in scanner.errors)


class TestMalformedOutput:
    @pytest.mark.parametrize(
        "text",
        [
            "this is not json",
            "{",
            "[]",
            '"a string"',
            "{}",
            '{"data": "not a list"}',
            '{"data": ["not an object"]}',
            '{"data": [{"results": []}]}',
        ],
    )
    def test_output_that_is_not_a_retire_report_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch, text
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeRetire(text=text, exit_code=13), monkeypatch)

    def test_an_empty_report_file_is_not_a_clean_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeRetire(text="", exit_code=0), monkeypatch)


class TestDependencyCheck:
    def test_a_missing_binary_is_reported_as_unsatisfied_dependencies(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(rs, "find_executable", lambda cmd: None)
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is False

    def test_a_present_binary_satisfies_them(self, tree, tmp_path, on_path):
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is True


class TestInstall:
    def test_install_commands_cover_every_platform(self, tmp_path):
        scanner = _scanner(tmp_path, tmp_path)
        for platform, arch in INSTALL_PLATFORMS:
            commands = scanner.get_installation_commands(platform, arch)
            assert commands == [["npm", "install", "-g", f"retire@{RETIRE_VERSION}"]], (
                f"wrong install command for {platform}/{arch}"
            )

    def test_the_pin_is_a_stable_release(self):
        assert RETIRE_VERSION == "6.1.1"
        assert RETIRE_VERSION.count(".") == 2
        assert all(part.isdigit() for part in RETIRE_VERSION.split("."))

    def test_the_register_citation_names_the_pinned_release(self):
        citation = RetireJsScanner.operational_facets.provenance.upstream_license
        assert citation.startswith("Apache-2.0 (source: the LICENSE.md file inside ")
        assert f"retire@{RETIRE_VERSION}" in citation


_CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "retire-js"
    / "captured"
)
#: The root the captures' absolute ``file`` paths were rewritten to. Given in POSIX
#: form, which the adapter matches as written on every platform.
_CAPTURED_ROOT = Path("/scan/src")

#: Read from the real retire 6.1.1 run in ``captured/positive.json``: the rule id, the
#: SARIF level and the issue severity of each vulnerability of jquery 1.6.1.
CAPTURED_EXPECTED = [
    ("CVE-2011-4969", "warning", "MEDIUM"),
    ("CVE-2012-6708", "warning", "MEDIUM"),
    ("CVE-2020-7656", "warning", "MEDIUM"),
    ("CVE-2015-9251", "warning", "MEDIUM"),
    # No CVE or GitHub id in the capture: the id is made from the issue number.
    ("RETIREJS-jquery-issue-162", "note", "LOW"),
    ("CVE-2019-11358", "warning", "MEDIUM"),
    ("CVE-2020-11023", "warning", "MEDIUM"),
]


def _captured(name: str) -> Any:
    return json.loads((_CAPTURED / name).read_text(encoding="utf-8"))


def _uris(sarif: Dict[str, Any]) -> set:
    return {
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for r in sarif["runs"][0]["results"]
    }


class TestCapturedReport:
    """The adapter over the output of real retire 6.1.1 runs."""

    def test_the_real_report_is_graded_row_by_row(self):
        sarif = convert_retire_report(
            _captured("positive.json"), source_root=_CAPTURED_ROOT
        )
        results = sarif["runs"][0]["results"]
        assert [
            (r["ruleId"], r["level"], r["properties"]["issue_severity"])
            for r in results
        ] == CAPTURED_EXPECTED
        assert _uris(sarif) == {"static/jquery-1.6.1.min.js"}

    def test_the_real_report_carries_the_library_and_its_cwes(self):
        sarif = convert_retire_report(
            _captured("positive.json"), source_root=_CAPTURED_ROOT
        )
        first, second = sarif["runs"][0]["results"][:2]
        assert first["properties"]["package_name"] == "jquery"
        assert first["properties"]["package_version"] == "1.6.1"
        assert first["properties"]["detection"] == "filename"
        assert "CWE-79" in first["properties"]["tags"]
        assert {"CWE-64", "CWE-79"} <= set(second["properties"]["tags"])
        assert "fixed in 1.6.3" in first["message"]["text"]

    def test_negative_control_the_real_clean_report_has_no_findings(self):
        sarif = convert_retire_report(
            _captured("negative.json"), source_root=_CAPTURED_ROOT
        )
        assert sarif["runs"][0]["results"] == []

    def test_a_package_json_naming_a_vulnerable_dependency_is_not_a_finding(self):
        """retire 6.1.1 reads no package.json: the capture of a tree holding only one
        naming lodash 4.17.4 has an empty ``data`` list, so the scanner claims nothing
        for manifests, and its documentation says so."""
        assert _captured("negative.json")["data"] == []
        assert "does not read ``package.json`` or a lockfile" in " ".join(
            (rs.__doc__ or "").split()
        )

    def test_the_real_reports_name_absolute_paths(self):
        """retire.js writes absolute paths, whatever ``--path`` was, so the adapter
        relativizes rather than trusting the path to arrive relative."""
        for name in ("positive.json", "ignores.json"):
            files = [entry["file"] for entry in _captured(name)["data"]]
            assert files and all(f.startswith("/scan/src/") for f in files), name

    def test_ashs_ignore_file_keeps_its_directory_out_and_the_trees_files_unread(self):
        """The capture of the argv the scanner builds (README): the ASH output
        directory copy is not reported, a sibling whose name only starts the same way
        is, and the planted .retireignore files, which hide findings when read, were
        not read (the static/ copy is reported)."""
        sarif = convert_retire_report(
            _captured("ignores.json"), source_root=_CAPTURED_ROOT
        )
        assert _uris(sarif) == {
            "static/jquery-1.6.1.min.js",
            ".ash/ash_output_other/jquery-1.6.1.min.js",
        }
        assert len(sarif["runs"][0]["results"]) == 2 * len(CAPTURED_EXPECTED)

    def test_the_committed_sarif_is_what_the_converter_writes(self):
        expected = convert_retire_report(
            _captured("positive.json"), source_root=_CAPTURED_ROOT
        )
        assert _captured("positive.sarif") == expected

    def test_the_committed_sarif_validates_against_the_schema_model(self):
        report = SarifReport.model_validate(_captured("positive.sarif"))
        assert len(report.get_all_results()) == len(CAPTURED_EXPECTED)

    @pytest.mark.skipif(
        sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
    )
    def test_a_source_directory_behind_a_symlink_still_gets_relative_paths(
        self, tmp_path
    ):
        real = tmp_path / "real"
        (real / "js").mkdir(parents=True)
        link = tmp_path / "link"
        link.symlink_to(real, target_is_directory=True)
        document = json.loads(
            _report(
                [
                    {
                        # retire.js run from the directory reports the resolved path.
                        "file": (real / "js" / "a.js").resolve().as_posix(),
                        "results": [
                            {
                                "component": "x",
                                "version": "1",
                                "vulnerabilities": [_vuln("low", "CVE-2099-7")],
                            }
                        ],
                    }
                ]
            )
        )
        sarif = convert_retire_report(document, source_root=link)
        loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "js/a.js"


class TestRegisterDeclarations:
    """The facets register rows (base/scanner_facets.py, scanner_operational_facets.py)
    against what the scanner and its committed capture say.

    The shared registry tests enumerate scanners, so they see this one through its
    module; these rows hold the declarations to the same contracts from inside the
    module.
    """

    def test_both_rows_are_declared_on_the_class_itself(self):
        from automated_security_helper.base import scanner_operational_facets as opsf
        from automated_security_helper.base.scanner_facets import (
            SCANNER_FACETS_ATTR,
            ScannerFacets,
        )

        assert isinstance(vars(RetireJsScanner)[SCANNER_FACETS_ATTR], ScannerFacets)
        assert isinstance(
            vars(RetireJsScanner)[opsf.OPERATIONAL_FACETS_ATTR],
            opsf.ScannerOperationalFacets,
        )

    def test_the_resource_identity_disposition_is_not_applicable_with_reasons(self):
        from automated_security_helper.base.scanner_facets import FacetState

        facets = RetireJsScanner.facets
        for name in ("resource_id", "resource_type"):
            cell = getattr(facets, name)
            assert cell.state is FacetState.NA and cell.reason
        assert facets.package_name.state is FacetState.MAPPED
        assert facets.package_version.state is FacetState.MAPPED

    def test_each_cell_agrees_with_the_flat_row_of_the_committed_capture(self):
        """MAPPED cells are populated across the capture; N/A and DROPPED are not."""
        from automated_security_helper.base.scanner_facets import (
            FACET_NAMES,
            FacetState,
        )
        from automated_security_helper.models.flat_vulnerability import (
            FlatVulnerability,
        )

        columns = {
            "rule_id": ("rule_id",),
            "severity": ("severity",),
            "file_path": ("file_path",),
            "line_range": ("line_start",),
            "message": ("description",),
            "resource_id": ("resource_id",),
            "resource_type": ("resource_type",),
            "package_name": ("package_name",),
            "package_version": ("package_version",),
            "package_path": ("package_path",),
            "taxonomy_cve": ("cve_id",),
            "taxonomy_cwe": ("cwe_id",),
            "fix_available": ("fix_available",),
            "snippet": ("code_snippet",),
            "references": ("references",),
            "tags": ("tags",),
        }
        report = SarifReport.model_validate(_captured("positive.sarif"))
        run = report.runs[0]
        flats = [
            FlatVulnerability.from_sarif_result(r, "retire-js", "SCA", run)
            for r in report.get_all_results()
        ]
        assert len(flats) == len(CAPTURED_EXPECTED)

        def populated(flat, column):
            value = getattr(flat, column)
            if isinstance(value, str):
                return value.strip() not in ("", "[]", "{}", "null")
            return value is not None

        no_flat_column = {"column", "remediation_text", "extras", "fingerprints"}
        for facet in FACET_NAMES:
            if facet in no_flat_column:
                continue
            seen = any(populated(f, c) for f in flats for c in columns[facet])
            state = getattr(RetireJsScanner.facets, facet).state
            if state is FacetState.MAPPED:
                assert seen, (
                    f"{facet} is declared mapped but the capture never fills it"
                )
            else:
                assert not seen, f"{facet} is declared {state.value} but is filled"

    def test_the_operational_row_mirrors_the_production_declarations(self, tmp_path):
        from automated_security_helper.base import scanner_operational_facets as opsf
        from automated_security_helper.core.enums import ScannerToolType

        ops = RetireJsScanner.operational_facets
        scanner = _scanner(tmp_path, tmp_path)
        assert ops.scanner_name == scanner.config.name == "retire-js"
        assert ops.network.offline_strategy is RetireJsScanner.offline_strategy
        assert ops.network.sandbox_network is opsf.SandboxNetwork.ONLINE
        assert RetireJsScanner.sandbox_requirements.network is True
        assert ops.network.offline_outcome is opsf.OfflineOutcome.NOT_RUN
        assert ops.targets.tool_type is scanner.tool_type is ScannerToolType.SCA
        assert ops.exit_codes.success_exit_codes == tuple(
            sorted(RetireJsScanner.success_exit_codes)
        )
        assert ops.runtime.python_only is bool(scanner.is_python_only())
        assert ops.runtime.use_uv_tool is bool(scanner.use_uv_tool)
        assert "node" in ops.runtime.external_programs
        assert ops.runtime_compat.rows == ()
        assert ops.extensibility.env_prefixes == tuple(
            scanner.sandbox_requirements.env_prefixes
        )
        assert "(source: " in ops.provenance.upstream_license

    def test_the_repository_ignore_files_are_declared_unhonored(self):
        from automated_security_helper.base import scanner_operational_facets as opsf

        (layer,) = RetireJsScanner.operational_facets.silencing.tool_side
        assert layer.honored is opsf.Honored.NO
        assert layer.writer is opsf.SilencingWriter.REPOSITORY
