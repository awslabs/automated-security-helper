# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""CapaScanner: capability conversion, target selection and failure handling.

Two kinds of document are used. ``TestCapturedReports`` reads real capa 10.0.0 output
from ``tests/test_data/scanners/capa/captured`` (see its README). The hand-written
documents elsewhere follow the shape of ``capa.render.result_document.ResultDocument``
(``meta`` and ``rules``) and exercise shapes a capture does not hold. scan() runs with
the subprocess replaced by a fake, so the tests need no binary and run on every
platform.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_facets import FacetState, ScannerFacets
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_capa_plugins
from automated_security_helper.plugin_modules.ash_capa_plugins import (
    capa_install as ci,
)
from automated_security_helper.plugin_modules.ash_capa_plugins import (
    capa_scanner as cs,
)
from automated_security_helper.plugin_modules.ash_capa_plugins.capa_scanner import (
    CapaScanner,
    CapaScannerConfig,
    convert_capa_document,
    is_supported_executable,
)

pytestmark = pytest.mark.unit

_CAPTURED = (
    Path(__file__).resolve().parents[3] / "test_data" / "scanners" / "capa" / "captured"
)


def _captured(name: str) -> Dict[str, Any]:
    return json.loads((_CAPTURED / f"{name}.json").read_text(encoding="utf-8"))


ELF = b"\x7fELF" + b"\x00" * 60
PE = b"MZ" + b"\x00" * 62


def _rule(name: str, *, attack=(), mbc=(), lib=False, matches=1, namespace="host/x"):
    return {
        "meta": {
            "name": name,
            "namespace": namespace,
            "lib": lib,
            "att&ck": [{"id": i, "tactic": "T", "technique": "Tech"} for i in attack],
            "mbc": [{"id": i} for i in mbc],
        },
        "source": "rule: ...",
        "matches": [
            [{"type": "absolute", "value": 0x401000 + n}, {"success": True}]
            for n in range(matches)
        ],
    }


def _document() -> Dict[str, Any]:
    return {
        "meta": {"version": "10.0.0", "sample": {"path": "x"}},
        "rules": {
            "create process": _rule("create process", attack=("T1106",), matches=2),
            "get hostname": _rule("get hostname", namespace="host-interaction/os"),
            "internal helper": _rule("internal helper", lib=True),
            "no matches": _rule("no matches", matches=0),
        },
    }


def _scanner(source: Path, tmp_path: Path) -> CapaScanner:
    return CapaScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=tmp_path / "out",
            work_dir=tmp_path / "out" / "converted",
            config=get_default_config(),
        ),
        config=CapaScannerConfig(enabled=True),
    )


class FakeCapa:
    """Stands in for _run_subprocess: records argv, serves a document per file."""

    def __init__(
        self,
        stdout: Optional[str] = None,
        exit_code: int = 0,
        timed_out: bool = False,
        per_file_exit: Optional[Dict[str, int]] = None,
    ):
        self.stdout = json.dumps(_document()) if stdout is None else stdout
        self.exit_code = exit_code
        self.timed_out = timed_out
        self.per_file_exit = per_file_exit or {}
        self.calls: List[dict] = []

    def __call__(self, scanner: CapaScanner):
        def run(command, results_dir=None, timeout=None, **_):
            self.calls.append({"argv": list(command), "timeout": timeout})
            if self.timed_out:
                scanner.exit_code = -9
                return {"timed_out": True}
            code = self.per_file_exit.get(command[-1], self.exit_code)
            # The real _run_subprocess folds each run's code into the accumulated
            # one (the worst wins); a fake that overwrote it would hide a scan that
            # reads the accumulated value as the current file's.
            scanner.exit_code = scanner._worse_exit_code(scanner.exit_code, code)
            return {
                "returncode": code,
                "stdout": self.stdout if code == 0 else "",
                "stderr": "stderr naming a file in the tree",
            }

        return run


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    (src / "bin").mkdir(parents=True)
    (src / "bin" / "tool").write_bytes(ELF)
    (src / "win.exe").write_bytes(PE)
    (src / "notes.txt").write_text("not an executable\n")
    (src / "script.py").write_text("print(1)\n")
    return src


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(cs, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


def _run(scanner: CapaScanner, fake: FakeCapa, monkeypatch):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(target=Path(scanner.context.source_dir), target_type="source")


def _findings(report) -> List[tuple]:
    return [
        (
            r.ruleId,
            getattr(r.level, "value", r.level),
            getattr(r.properties, "issue_severity", None),
        )
        for r in report.get_all_results()
    ]


class TestAlphaPlugin:
    def test_the_module_exports_the_scanner(self):
        assert ash_capa_plugins.ASH_SCANNERS == [CapaScanner]
        assert ash_capa_plugins.ASH_REPORTERS == []

    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert CapaScannerConfig().enabled is True
        assert CapaScannerConfig().name == "capa"


class TestConversion:
    def test_capabilities_are_rated_info_or_low_and_never_higher(self):
        results = convert_capa_document(_document(), "bin/tool")
        by_rule = {r["ruleId"]: r for r in results}
        assert by_rule["create process"]["level"] == "note"
        assert by_rule["create process"]["properties"]["issue_severity"] == "LOW"
        assert by_rule["get hostname"]["level"] == "none"
        assert by_rule["get hostname"]["properties"]["issue_severity"] == "INFO"

    def test_library_and_empty_rules_are_not_reported(self):
        names = {r["ruleId"] for r in convert_capa_document(_document(), "x")}
        assert names == {"create process", "get hostname"}

    def test_the_message_names_the_capability_and_its_technique(self):
        results = convert_capa_document(_document(), "x")
        text = next(r for r in results if r["ruleId"] == "create process")["message"][
            "text"
        ]
        assert "create process" in text and "T1106" in text and "2 match" in text

    def test_match_addresses_are_kept(self):
        result = convert_capa_document(_document(), "x")[0]
        assert result["properties"]["match_addresses"] == [0x401000, 0x401001]

    def test_every_result_is_located_at_line_one_of_the_file(self):
        # The register declares line_range MAPPED to this constant: a binary has no
        # source line, and the result needs a region.
        for result in convert_capa_document(_document(), "bin/tool"):
            (location,) = result["locations"]
            assert location["physicalLocation"] == {
                "artifactLocation": {"uri": "bin/tool"},
                "region": {"startLine": 1},
            }

    def test_an_mbc_only_rule_is_low(self):
        doc = {"rules": {"r": _rule("r", mbc=("C0001",))}}
        assert (
            convert_capa_document(doc, "x")[0]["properties"]["issue_severity"] == "LOW"
        )

    def test_a_document_with_no_matched_rules_has_no_findings(self):
        assert convert_capa_document({"meta": {}, "rules": {}}, "x") == []

    @pytest.mark.parametrize(
        "document", [[], "text", {"meta": {}}, {"rules": []}, {"rules": {"r": 1}}]
    )
    def test_a_document_that_is_not_a_capa_result_is_refused(self, document):
        with pytest.raises(ValueError):
            convert_capa_document(document, "x")


class TestTargets:
    def test_only_pe_and_elf_files_are_recognised(self, tree):
        assert is_supported_executable(tree / "bin" / "tool")
        assert is_supported_executable(tree / "win.exe")
        assert not is_supported_executable(tree / "notes.txt")
        assert not is_supported_executable(tree / "missing")


class TestScan:
    def test_happy_path_one_run_per_executable_with_the_path_after_double_dash(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeCapa()
        report = _run(scanner, fake, monkeypatch)
        argvs = [c["argv"] for c in fake.calls]
        assert argvs == [
            ["capa", "-q", "-j", "--", "bin/tool"],
            ["capa", "-q", "-j", "--", "win.exe"],
        ]
        assert scanner.targets_attempted == 2 and scanner.targets_failed == 0
        # Two files, two capabilities each.
        assert sorted(_findings(report)) == sorted(
            [
                ("create process", "note", "LOW"),
                ("get hostname", "none", "INFO"),
            ]
            * 2
        )
        uris = {
            r.locations[0].physicalLocation.root.artifactLocation.uri
            for r in report.get_all_results()
        }
        assert uris == {"bin/tool", "win.exe"}

    def test_rules_and_signatures_of_the_tree_are_never_passed(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeCapa()
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        for call in fake.calls:
            flags = [a for a in call["argv"] if a.startswith("-") and a != "--"]
            assert flags == ["-q", "-j"]

    def test_a_tree_with_no_executable_is_not_run(self, tmp_path, on_path, monkeypatch):
        src = tmp_path / "src"
        src.mkdir()
        (src / "a.txt").write_text("x\n")
        fake = FakeCapa()
        report = _run(_scanner(src, tmp_path), fake, monkeypatch)
        assert fake.calls == [] and _findings(report) == []

    def test_negative_control_a_clean_document_has_no_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        clean = json.dumps({"meta": {"version": "10.0.0"}, "rules": {}})
        report = _run(_scanner(tree, tmp_path), FakeCapa(stdout=clean), monkeypatch)
        assert _findings(report) == []

    def test_nonzero_exit_on_one_file_fails_that_target_and_keeps_the_others(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeCapa(per_file_exit={"win.exe": 14})
        report = _run(scanner, fake, monkeypatch)
        assert scanner.targets_failed == 1 and scanner.targets_attempted == 2
        assert {f[0] for f in _findings(report)} == {"create process", "get hostname"}
        assert any("win.exe" in e and "14" in e for e in scanner.errors)

    def test_a_failure_on_an_early_file_does_not_fail_the_files_after_it(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        # bin/tool sorts first and fails; win.exe (exit 0) must still be read.
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeCapa(per_file_exit={"bin/tool": 13}), monkeypatch)
        assert scanner.targets_failed == 1
        assert {f[0] for f in _findings(report)} == {"create process", "get hostname"}
        assert not any("win.exe" in e for e in scanner.errors)
        assert scanner.exit_code in scanner.success_exit_codes

    def test_stderr_is_not_copied_into_errors(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        # Through the base class's own response handling, which the fake bypasses.
        scanner = _scanner(tree, tmp_path)
        assert CapaScanner.quote_tool_stderr is False
        scanner._process_command_response(
            {"returncode": 13, "stderr": "stderr naming a file in the tree"}
        )
        assert not any("stderr naming a file" in e for e in scanner.errors)

    def test_the_failure_text_names_the_tool_not_its_stderr(self, tree, tmp_path):
        scanner = _scanner(tree, tmp_path)
        scanner.exit_code = 13
        text = scanner._describe_scan_failure(RuntimeError("boom"), None)
        assert "capa" in text

    def test_every_target_failing_makes_the_scan_exit_nonzero(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeCapa(exit_code=16), monkeypatch)
        assert scanner.targets_failed == 2
        assert scanner.exit_code not in scanner.success_exit_codes

    def test_a_timeout_fails_the_scan_and_says_so(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError, match="timed out after"):
            _run(scanner, FakeCapa(timed_out=True), monkeypatch)

    def test_the_remaining_time_budget_reaches_the_subprocess(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeCapa()
        _run(scanner, fake, monkeypatch)
        timeout = scanner._effective_scan_timeout()
        assert timeout is not None
        assert all(0 < c["timeout"] <= timeout for c in fake.calls)

    @pytest.mark.parametrize("stdout", ["", "not json", "[]", '{"meta": {}}'])
    def test_malformed_output_fails_the_scan(
        self, stdout, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeCapa(stdout=stdout), monkeypatch)

    def test_symlink_out_of_the_tree_is_not_analyzed(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        outside = tmp_path / "outside.elf"
        outside.write_bytes(ELF)
        (tree / "link").symlink_to(outside)
        fake = FakeCapa()
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert all(c["argv"][-1] != "link" for c in fake.calls)


class TestDependencyCheck:
    def test_tool_absent_is_reported_missing_with_the_install_command(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(cs, "find_executable", lambda cmd: None)
        warnings: List[str] = []
        monkeypatch.setattr(cs.ASH_LOGGER, "warning", warnings.append)
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is False
        assert any("ash_capa_plugins" in w and "--tool capa" in w for w in warnings)

    def test_tool_present(self, tree, tmp_path, on_path):
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is True

    def test_offline_and_exit_codes_are_declared(self):
        assert CapaScanner.success_exit_codes == {0}
        assert CapaScanner.python_only is False
        assert CapaScanner.offline_strategy.name == "BUNDLED"


class TestInstall:
    def test_constructing_the_scanner_installs_from_the_module_pin(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
        scanner = _scanner(tree, tmp_path)
        pairs = {
            (platform, arch)
            for platform, arches in scanner.custom_install_commands.items()
            for arch in arches
        }
        assert pairs == set(ci.ASSETS)
        (command,) = scanner.custom_install_commands["linux"]["amd64"]
        assert "install_capa" in " ".join(command.args)


class TestCapturedReports:
    """The pinned capa 10.0.0 JSON, captured (see the fixtures' README)."""

    def test_mapped_rules_are_low_and_unmapped_are_info_over_a_real_report(self):
        results = convert_capa_document(_captured("mapped"), "sample.elf")
        by_rule = {r["ruleId"]: r for r in results}
        # ATT&CK and MBC mapped, ATT&CK only (via mbc empty), MBC only, unmapped.
        assert by_rule["encode data using XOR"]["properties"]["issue_severity"] == "LOW"
        assert by_rule["get current user on Linux"]["level"] == "note"
        assert by_rule["write file on Linux"]["properties"]["mbc_ids"] == ["C0052"]
        assert by_rule["get password database entry on Linux"]["level"] == "none"
        assert (
            by_rule["get password database entry on Linux"]["properties"][
                "issue_severity"
            ]
            == "INFO"
        )
        assert {r["properties"]["issue_severity"] for r in results} <= {"LOW", "INFO"}

    def test_the_library_rule_in_the_capture_is_not_reported(self):
        document = _captured("mapped")
        assert document["rules"]["contain loop"]["meta"]["lib"] is True
        names = {r["ruleId"] for r in convert_capa_document(document, "x")}
        assert "contain loop" not in names
        assert len(names) == len(document["rules"]) - 1

    def test_match_counts_and_addresses_follow_the_capture(self):
        document = _captured("mapped")
        env = next(
            r
            for r in convert_capa_document(document, "x")
            if r["ruleId"] == "query environment variable"
        )
        assert env["properties"]["match_count"] == 3
        assert len(env["properties"]["match_addresses"]) == 3
        assert env["properties"]["attack_ids"] == ["T1082"]

    def test_the_smaller_capture_converts_to_mbc_only_lows(self):
        results = convert_capa_document(_captured("positive"), "clean.elf")
        assert {r["ruleId"] for r in results} == {
            "write file on Linux",
            "terminate process",
        }
        assert {r["level"] for r in results} == {"note"}

    def test_scan_over_a_captured_report(self, tree, tmp_path, on_path, monkeypatch):
        stdout = json.dumps(_captured("positive"))
        report = _run(_scanner(tree, tmp_path), FakeCapa(stdout=stdout), monkeypatch)
        assert {f[0] for f in _findings(report)} == {
            "write file on Linux",
            "terminate process",
        }


class TestFacetsDeclared:
    def test_the_register_row_is_declared_and_names_the_scanner(self):
        assert isinstance(CapaScanner.facets, ScannerFacets)
        assert CapaScanner.operational_facets.scanner_name == "capa"
        assert CapaScanner.operational_facets.exit_codes.success_exit_codes == (0,)
        assert CapaScanner.facets.resource_id.state is FacetState.NA
        assert CapaScanner.facets.resource_id.reason

    def test_the_constant_line_is_declared_as_what_the_adapter_writes(self):
        cell = CapaScanner.facets.line_range
        assert cell.state is FacetState.MAPPED
        assert "constant startLine 1" in (cell.native_field or "")

    def test_the_platforms_note_names_the_installer_and_the_glibc_floor(self):
        platforms = CapaScanner.operational_facets.platforms
        assert platforms.provisionable == ()
        assert "capa_install.py" in platforms.note
        assert f"glibc {ci.LINUX_GLIBC_FLOOR}" in platforms.note
