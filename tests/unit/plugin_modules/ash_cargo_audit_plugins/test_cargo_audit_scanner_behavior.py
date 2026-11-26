# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""CargoAuditScanner: invocation, severity mapping and failure handling.

The subprocess is replaced by a fake, so these run on every platform without the
binary. The JSON documents are written by hand from the rustsec ``Report`` types
(``vulnerabilities.list[]`` and ``warnings.<kind>[]``, each with ``advisory`` and
``package``); they are not captures of a real run, and the advisory ids and crate
names are made up. The converter is checked against a real report in
``test_cargo_audit_captured_report.py``, over a capture from cargo-audit 0.23.0. The
exit codes and their stderr lines here are the ones cargo-audit 0.23.0's source writes
(``commands/audit.rs`` and ``auditor.rs``).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_cargo_audit_plugins
from automated_security_helper.plugin_modules.ash_cargo_audit_plugins import (
    cargo_audit_scanner as cas,
)
from automated_security_helper.plugin_modules.ash_cargo_audit_plugins.cargo_audit_scanner import (
    CargoAuditScanner,
    CargoAuditScannerConfig,
    CargoAuditScannerConfigOptions,
    convert_cargo_audit_report,
    cvss3_base_score,
    vulnerability_severity,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.config_trust import record_provenance

pytestmark = pytest.mark.unit

CRITICAL_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8
MEDIUM_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"  # 6.5
LOW_VECTOR = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"  # 1.8


def _vuln(advisory_id: str, name: str, version: str, cvss: Optional[str] = None):
    advisory = {"id": advisory_id, "package": name, "title": f"title of {advisory_id}"}
    if cvss is not None:
        advisory["cvss"] = cvss
    return {
        "advisory": advisory,
        "versions": {"patched": [">=9.9.9"], "unaffected": []},
        "affected": None,
        "package": {"name": name, "version": version},
    }


def _warning(kind: str, name: str, version: str, advisory_id: Optional[str] = None):
    advisory = (
        {"id": advisory_id, "package": name, "title": f"title of {advisory_id}"}
        if advisory_id
        else None
    )
    return {
        "kind": kind,
        "package": {"name": name, "version": version},
        "advisory": advisory,
        "affected": None,
        "versions": None,
    }


def _document(vulns=(), warnings: Optional[Dict[str, list]] = None) -> dict:
    return {
        "settings": {"target_arch": [], "target_os": [], "ignore": []},
        "lockfile": {"dependency-count": 3},
        "vulnerabilities": {
            "found": bool(vulns),
            "count": len(vulns),
            "list": list(vulns),
        },
        "warnings": warnings or {},
    }


POSITIVE = _document(
    vulns=[
        _vuln("RUSTSEC-0000-0001", "fakecrate", "1.0.0", CRITICAL_VECTOR),
        _vuln("RUSTSEC-0000-0002", "othercrate", "2.1.0", MEDIUM_VECTOR),
        _vuln("RUSTSEC-0000-0003", "lowcrate", "0.3.0", LOW_VECTOR),
        _vuln("RUSTSEC-0000-0004", "noscore", "0.1.0"),
    ],
    warnings={
        "unsound": [_warning("unsound", "soundless", "1.2.3", "RUSTSEC-0000-0005")],
        "unmaintained": [
            _warning("unmaintained", "oldcrate", "0.9.0", "RUSTSEC-0000-0006")
        ],
        "yanked": [_warning("yanked", "gonecrate", "0.2.0")],
    },
)
NEGATIVE = _document()


class FakeCargoAudit:
    """Stands in for _run_subprocess: records argv, serves a canned stdout."""

    def __init__(
        self,
        stdout: str | None = None,
        exit_code: int = 1,
        stderr: str = "",
        timed_out: bool = False,
    ):
        self.stdout = json.dumps(POSITIVE) if stdout is None else stdout
        self.exit_code, self.stderr, self.timed_out = exit_code, stderr, timed_out
        self.calls: List[dict] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, cwd=None, **kw):
            self.calls.append(
                {"argv": list(command), "timeout": timeout, "kw": kw, "cwd": cwd}
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


def _scanner(source: Path, tmp_path: Path, **options) -> CargoAuditScanner:
    config = get_default_config()
    record_provenance(config, in_tree=[], trusted=AshConfig())
    return CargoAuditScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=tmp_path / "out",
            work_dir=tmp_path / "out" / "converted",
            config=config,
        ),
        config=CargoAuditScannerConfig(
            enabled=True, options=CargoAuditScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    (src / "crates" / "inner").mkdir(parents=True)
    (src / "target" / "debug").mkdir(parents=True)
    (src / "Cargo.lock").write_text("version = 3\n")
    (src / "crates" / "inner" / "Cargo.lock").write_text("version = 3\n")
    (src / "target" / "debug" / "Cargo.lock").write_text("version = 3\n")
    (src / "Cargo.toml").write_text("[package]\nname = 'x'\n")
    return src


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(cas, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


def _run(scanner, fake, monkeypatch, **kw):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=Path(scanner.context.source_dir), target_type="source", **kw
    )


def _findings(report: SarifReport):
    out = []
    for r in report.get_all_results():
        out.append(
            (
                r.ruleId,
                getattr(r.level, "value", r.level),
                getattr(r.properties, "issue_severity", None),
                r.locations[0].physicalLocation.root.artifactLocation.uri,
            )
        )
    return out


class TestAlphaPlugin:
    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert CargoAuditScannerConfig().enabled is True

    def test_module_exports_the_scanner(self):
        assert ash_cargo_audit_plugins.ASH_SCANNERS == [CargoAuditScanner]
        assert ash_cargo_audit_plugins.ASH_REPORTERS == []

    def test_declared_class_variables(self):
        from automated_security_helper.core.enums import OfflineStrategy

        assert CargoAuditScanner.python_only is False
        # Offline the database on disk has no age bound, so the scanner is skipped.
        assert CargoAuditScanner.offline_strategy is OfflineStrategy.SKIP_OFFLINE
        assert CargoAuditScanner.success_exit_codes == {0, 1}
        assert CargoAuditScanner.sandbox_requirements.network is True


class TestSeverity:
    @pytest.mark.parametrize(
        "vector,score,severity",
        [
            (CRITICAL_VECTOR, 9.8, "CRITICAL"),
            (MEDIUM_VECTOR, 6.5, "MEDIUM"),
            (LOW_VECTOR, 1.8, "LOW"),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "CRITICAL"),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1, "CRITICAL"),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8, "HIGH"),
        ],
    )
    def test_cvss_vectors_are_scored_and_rated(self, vector, score, severity):
        assert cvss3_base_score(vector) == score
        assert vulnerability_severity({"cvss": vector}) == severity

    @pytest.mark.parametrize(
        "cvss",
        [
            None,
            "",
            "AV:N/AC:L",
            "CVSS:2.0/AV:N",
            "CVSS:3.1/AV:N",
            7,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        ],
    )
    def test_an_unscorable_vulnerability_is_high(self, cvss):
        assert vulnerability_severity({"cvss": cvss}) == "HIGH"

    def test_each_row_over_the_report(self, tree, tmp_path, on_path, monkeypatch):
        (tree / "crates" / "inner" / "Cargo.lock").unlink()
        report = _run(_scanner(tree, tmp_path), FakeCargoAudit(), monkeypatch)
        assert _findings(report) == [
            ("RUSTSEC-0000-0001", "error", "CRITICAL", "Cargo.lock"),
            ("RUSTSEC-0000-0002", "warning", "MEDIUM", "Cargo.lock"),
            ("RUSTSEC-0000-0003", "note", "LOW", "Cargo.lock"),
            ("RUSTSEC-0000-0004", "error", "HIGH", "Cargo.lock"),
            ("RUSTSEC-0000-0005", "warning", "MEDIUM", "Cargo.lock"),
            ("RUSTSEC-0000-0006", "note", "LOW", "Cargo.lock"),
            ("yanked", "note", "LOW", "Cargo.lock"),
        ]

    def test_unknown_warning_kind_is_low_note(self):
        doc = _document(
            warnings={"future-kind": [_warning("future-kind", "a", "1.0.0")]}
        )
        (result,) = convert_cargo_audit_report(doc, uri="Cargo.lock")
        assert result["level"] == "note"
        assert result["properties"]["issue_severity"] == "LOW"

    def test_level_and_severity_agree_for_every_result(self):
        for result in convert_cargo_audit_report(POSITIVE, uri="Cargo.lock"):
            expected = {
                "CRITICAL": "error",
                "HIGH": "error",
                "MEDIUM": "warning",
                "LOW": "note",
            }[result["properties"]["issue_severity"]]
            assert result["level"] == expected

    def test_fingerprint_names_advisory_package_and_version(self):
        first = convert_cargo_audit_report(POSITIVE, uri="Cargo.lock")[0]
        assert first["partialFingerprints"] == {
            "cargo-audit/advisory-fingerprint": "RUSTSEC-0000-0001:fakecrate:1.0.0"
        }


class TestInvocation:
    def test_every_fixed_flag_and_the_lockfile_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeCargoAudit(stdout=json.dumps(NEGATIVE), exit_code=0)
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        argvs = [c["argv"] for c in fake.calls]
        root = tree.absolute().as_posix()
        assert argvs == [
            ["cargo-audit", "audit", "--json", f"--file={root}/Cargo.lock"],
            [
                "cargo-audit",
                "audit",
                "--json",
                f"--file={root}/crates/inner/Cargo.lock",
            ],
        ]

    def test_the_lockfile_is_one_token_so_it_cannot_read_as_a_flag(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeCargoAudit(stdout=json.dumps(NEGATIVE), exit_code=0)
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        for call in fake.calls:
            assert "--file" not in call["argv"]
            assert sum(a.startswith("--file=") for a in call["argv"]) == 1

    def test_a_build_directory_lockfile_is_never_scanned(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeCargoAudit(stdout=json.dumps(NEGATIVE), exit_code=0)
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert not any("/target/" in c["argv"][-1] for c in fake.calls)

    @pytest.mark.parametrize("ancestor", ["target", ".git"])
    def test_a_tree_inside_a_directory_with_a_skipped_name_is_scanned(
        self, ancestor, tmp_path, on_path, monkeypatch
    ):
        """Only the directories below the scanned one are judged.

        The scan set names files by absolute path, so a tree at
        ``<somewhere>/target/app`` lost every lockfile to the build-directory rule,
        and the scanner reported that there was nothing to scan. Its own ``target/``
        below the tree is still skipped.
        """
        src = tmp_path / ancestor / "app"
        (src / "target" / "debug").mkdir(parents=True)
        (src / "Cargo.lock").write_text("version = 3\n")
        (src / "target" / "debug" / "Cargo.lock").write_text("version = 3\n")
        scanner = _scanner(src, tmp_path)
        assert scanner.nothing_to_scan_reason() is None
        fake = FakeCargoAudit(stdout=json.dumps(NEGATIVE), exit_code=0)
        _run(scanner, fake, monkeypatch)
        assert [c["argv"][-1] for c in fake.calls] == [
            f"--file={src.absolute().as_posix()}/Cargo.lock"
        ]

    def test_the_tool_runs_where_a_tree_supplied_audit_toml_is_not_read(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        """cargo-audit reads ./.cargo/audit.toml of its working directory, and a
        project file can ignore advisories, so the run starts outside the tree
        (and the repository's own file is in the tree, not in that directory)."""
        (tree / ".cargo").mkdir()
        (tree / ".cargo" / "audit.toml").write_text(
            '[advisories]\nignore = ["RUSTSEC-0000-0001"]\n'
        )
        fake = FakeCargoAudit(stdout=json.dumps(NEGATIVE), exit_code=0)
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert fake.calls
        for call in fake.calls:
            cwd = Path(call["cwd"]).resolve()
            assert not cwd.is_relative_to(tree.resolve())
            assert not (cwd / ".cargo" / "audit.toml").exists()

    def test_scan_set_exclusions_are_honored(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        from automated_security_helper.models.core import IgnorePathWithReason

        fake = FakeCargoAudit(stdout=json.dumps(NEGATIVE), exit_code=0)
        scanner = _scanner(tree, tmp_path)
        _run(
            scanner,
            fake,
            monkeypatch,
            global_ignore_paths=[
                IgnorePathWithReason(path="crates/**", reason="vendored")
            ],
        )
        assert [c["argv"][-1] for c in fake.calls] == [
            f"--file={tree.absolute().as_posix()}/Cargo.lock"
        ]

    @pytest.mark.parametrize(
        "forbidden", ["--format", "--db", "--url", "--deny", "--ignore", "--stale"]
    )
    def test_flags_that_change_the_database_or_the_rules_are_never_passed(
        self, forbidden, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeCargoAudit(stdout=json.dumps(NEGATIVE), exit_code=0)
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert all(forbidden not in c["argv"] for c in fake.calls)

    def test_an_online_scan_fetches_the_database(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        # cargo-audit's own fetch is the path that holds the database to its age rule.
        monkeypatch.delenv("ASH_OFFLINE", raising=False)
        fake = FakeCargoAudit(stdout=json.dumps(NEGATIVE), exit_code=0)
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert fake.calls
        assert all("--no-fetch" not in c["argv"] for c in fake.calls)

    def test_an_offline_scan_never_reaches_the_tool(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        monkeypatch.setenv("ASH_OFFLINE", "1")
        fake = FakeCargoAudit(stdout=json.dumps(NEGATIVE), exit_code=0)
        scanner = _scanner(tree, tmp_path)
        assert _run(scanner, fake, monkeypatch) is False
        assert fake.calls == []
        assert "does not run offline" in scanner.missing_dependency_reason()

    def test_the_scanners_own_offline_option_skips_it_too(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        monkeypatch.delenv("ASH_OFFLINE", raising=False)
        fake = FakeCargoAudit(stdout=json.dumps(NEGATIVE), exit_code=0)
        scanner = _scanner(tree, tmp_path, offline=True)
        assert scanner.validate_plugin_dependencies() is False
        assert _run(scanner, fake, monkeypatch) is False
        assert fake.calls == []

    def test_no_lockfile_means_no_run_and_an_empty_report(
        self, tmp_path, on_path, monkeypatch
    ):
        src = tmp_path / "src"
        src.mkdir()
        (src / "main.rs").write_text("fn main() {}\n")
        fake = FakeCargoAudit()
        scanner = _scanner(src, tmp_path)
        report = _run(scanner, fake, monkeypatch)
        assert fake.calls == []
        assert report.get_all_results() == []
        assert scanner.targets_attempted == 0

    def test_a_missing_target_never_reaches_the_tool(
        self, tmp_path, on_path, monkeypatch
    ):
        fake = FakeCargoAudit()
        scanner = _scanner(tmp_path / "missing", tmp_path)
        monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
        scanner.scan(target=tmp_path / "missing", target_type="source")
        assert fake.calls == []


class TestReport:
    def test_negative_control_has_no_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeCargoAudit(stdout=json.dumps(NEGATIVE), exit_code=0)
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, fake, monkeypatch)
        assert report.get_all_results() == []
        assert scanner.targets_attempted == 2

    def test_report_round_trips_as_sarif(self, tree, tmp_path, on_path, monkeypatch):
        report = _run(_scanner(tree, tmp_path), FakeCargoAudit(), monkeypatch)
        again = SarifReport.model_validate(
            json.loads(report.model_dump_json(exclude_none=True, by_alias=True))
        )
        assert len(again.get_all_results()) == len(report.get_all_results())

    def test_results_of_each_lockfile_carry_their_own_uri(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(_scanner(tree, tmp_path), FakeCargoAudit(), monkeypatch)
        uris = {f[3] for f in _findings(report)}
        assert uris == {"Cargo.lock", "crates/inner/Cargo.lock"}

    def test_report_is_written_and_a_stale_one_removed(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        stale = Path(scanner.results_dir) / "source" / "cargo-audit.sarif"
        stale.parent.mkdir(parents=True, exist_ok=True)
        stale.write_text("STALE")
        _run(
            scanner,
            FakeCargoAudit(stdout=json.dumps(NEGATIVE), exit_code=0),
            monkeypatch,
        )
        assert "STALE" not in stale.read_text()


class TestExitStatusAndFailures:
    @pytest.mark.parametrize("code", [0, 1])
    def test_success_codes_pass(self, code, tree, tmp_path, on_path, monkeypatch):
        fake = FakeCargoAudit(stdout=json.dumps(NEGATIVE), exit_code=code)
        assert _run(_scanner(tree, tmp_path), fake, monkeypatch) is not False

    @pytest.mark.parametrize(
        "code,stderr",
        [
            # 2: the lockfile could not be located, or the audit failed.
            (2, "error: Couldn't load /src/Cargo.lock: parse error"),
            # 101: a Rust panic.
            (101, "thread 'main' panicked at src/auditor.rs:1:1"),
            (126, ""),
            (137, ""),
        ],
    )
    def test_other_codes_fail_even_with_a_report_on_stdout(
        self, code, stderr, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeCargoAudit(exit_code=code, stderr=stderr)
        with pytest.raises(ScannerError, match=f"exited {code}") as raised:
            _run(_scanner(tree, tmp_path), fake, monkeypatch)
        if stderr:
            assert stderr in str(raised.value)

    @pytest.mark.parametrize(
        "stderr,reason",
        [
            # update_db in auditor.rs: a fetch that failed, the network case.
            (
                (
                    "error: couldn't fetch advisory database: git operation failed: "
                    "failed to connect to github.com"
                ),
                "failed to connect to github.com",
            ),
            # Repository::fetch refuses a database whose newest commit is over 90
            # days old, and update_db turns that into exit 1.
            (
                (
                    "error: couldn't fetch advisory database: repository is stale "
                    "(last commit: 2026-01-01T00:00:00Z)"
                ),
                "repository is stale",
            ),
            # The database lock still held when the wait ended.
            (
                (
                    "warning: directory /home/u/.cargo/advisory-db is locked, waiting "
                    "for up to 300 seconds for it to become available\nerror: "
                    "couldn't fetch advisory database: lock timeout"
                ),
                "lock timeout",
            ),
            # update_db again: the fetched database could not be loaded.
            (
                "error: error loading advisory database: parse error",
                "error loading advisory database",
            ),
        ],
    )
    def test_exit_1_with_no_report_is_a_failed_database_fetch_with_its_reason(
        self, stderr, reason, tree, tmp_path, on_path, monkeypatch
    ):
        """1 is also cargo-audit's exit for a database it could not fetch or load.

        Auditor::new opens the database before any audit, and update_db exits 1 on
        every failure there, with nothing on stdout. Read as the "vulnerabilities
        found" 1, such a run failed only as "wrote no report", and the reason
        cargo-audit gave was dropped.
        """
        fake = FakeCargoAudit(stdout="", exit_code=1, stderr=stderr)
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError) as raised:
            _run(scanner, fake, monkeypatch)
        message = str(raised.value)
        assert "exited 1 on Cargo.lock with no report on stdout" in message
        assert "advisory database could not be fetched or loaded" in message
        assert reason in message
        # The first lockfile's failure stops the run: the second is never audited.
        assert len(fake.calls) == 1

    def test_exit_1_with_no_report_and_no_stderr_still_fails_and_says_so(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeCargoAudit(stdout="", exit_code=1, stderr="")
        with pytest.raises(ScannerError, match="wrote nothing on stderr either"):
            _run(_scanner(tree, tmp_path), fake, monkeypatch)

    def test_exit_1_with_a_report_is_vulnerabilities_found(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        """Control: the same code with the report on stdout is a complete scan."""
        fake = FakeCargoAudit(exit_code=1, stderr="Fetching advisory database")
        report = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert report.get_all_results(), "the findings of the report on stdout"

    def test_exit_0_with_no_report_fails_with_the_stderr(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeCargoAudit(stdout="", exit_code=0, stderr="error: something odd")
        with pytest.raises(ScannerError, match="wrote no report") as raised:
            _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert "error: something odd" in str(raised.value)

    def test_a_timeout_fails_the_scan_and_says_so(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeCargoAudit(timed_out=True)
        scanner = _scanner(tree, tmp_path, scan_timeout=30)
        with pytest.raises(ScannerError, match="timed out after"):
            _run(scanner, fake, monkeypatch)

    def test_the_scan_timeout_reaches_the_subprocess(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeCargoAudit(stdout=json.dumps(NEGATIVE), exit_code=0)
        _run(_scanner(tree, tmp_path, scan_timeout=30), fake, monkeypatch)
        assert all(
            c["timeout"] is not None and 0 < c["timeout"] <= 30 for c in fake.calls
        )

    @pytest.mark.parametrize(
        "stdout,message",
        [
            ("", "wrote no report"),
            ("not json at all", "not JSON"),
            ("[1, 2]", "not a report"),
            ('{"vulnerabilities": 3}', "not a report"),
            ('{"vulnerabilities": {"found": false}}', "no vulnerabilities list"),
            (
                json.dumps({"vulnerabilities": {"list": [3]}}),
                "malformed vulnerability",
            ),
            (
                json.dumps({"vulnerabilities": {"list": [{"package": {"name": "a"}}]}}),
                "no advisory id",
            ),
            (
                json.dumps({"vulnerabilities": {"list": []}, "warnings": []}),
                "warnings entry",
            ),
        ],
    )
    def test_malformed_output_fails_the_scan(
        self, stdout, message, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeCargoAudit(stdout=stdout, exit_code=0)
        with pytest.raises(ScannerError, match=message):
            _run(_scanner(tree, tmp_path), fake, monkeypatch)

    def test_failure_before_start_has_no_tool_call(self, tree, tmp_path, monkeypatch):
        # Tool absent: the dependency check fails and the tool is never started.
        monkeypatch.setattr(cas, "find_executable", lambda cmd: None)
        scanner = _scanner(tree, tmp_path)
        fake = FakeCargoAudit()
        monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
        result = scanner.scan(target=tree, target_type="source")
        assert result is False
        assert fake.calls == []


class TestDependencyCheck:
    def test_missing_binary_is_reported_missing(self, monkeypatch, tmp_path):
        monkeypatch.setattr(cas, "find_executable", lambda cmd: None)
        assert _scanner(tmp_path, tmp_path).validate_plugin_dependencies() is False

    def test_present_binary_passes(self, monkeypatch, tmp_path):
        monkeypatch.setattr(cas, "find_executable", lambda cmd: "/fake/cargo-audit")
        assert _scanner(tmp_path, tmp_path).validate_plugin_dependencies() is True


class TestInstall:
    def test_construction_registers_the_pinned_installer(self, tmp_path, monkeypatch):
        """The install table comes from the module's own pin, never from the shared one.

        A construction-time lookup of a shared pin used to raise ToolNotProvisionable
        before any test could run; the module-local table never raises.
        """
        monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
        scanner = _scanner(tmp_path, tmp_path)
        commands = scanner.custom_install_commands
        assert {(p, a) for p, arches in commands.items() for a in arches} == {
            ("darwin", "amd64"),
            ("darwin", "arm64"),
            ("linux", "amd64"),
            ("linux", "arm64"),
            ("windows", "amd64"),
        }
        (command,) = commands["linux"]["amd64"]
        assert "install_cargo_audit" in " ".join(command.args)

    def test_the_missing_tool_hint_names_both_installs(
        self, monkeypatch, tmp_path, caplog
    ):
        monkeypatch.delenv("ASH_OFFLINE", raising=False)
        monkeypatch.setattr(cas, "find_executable", lambda cmd: None)
        seen: List[str] = []
        monkeypatch.setattr(
            cas.ASH_LOGGER, "warning", lambda msg, *a, **k: seen.append(msg)
        )
        _scanner(tmp_path, tmp_path).validate_plugin_dependencies()
        assert any(
            "ash dependencies install" in m and "--tool cargo-audit" in m for m in seen
        )
        assert any(
            "cargo install cargo-audit --version 0.23.0 --locked" in m for m in seen
        )


class TestNothingToScan:
    def test_reason_when_no_lockfile(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "main.rs").write_text("fn main() {}\n")
        reason = _scanner(src, tmp_path).nothing_to_scan_reason()
        assert reason and "Cargo.lock" in reason

    def test_none_when_a_lockfile_exists(self, tree, tmp_path):
        assert _scanner(tree, tmp_path).nothing_to_scan_reason() is None

    def test_a_build_directory_lockfile_alone_is_nothing(self, tmp_path):
        src = tmp_path / "src"
        (src / "target").mkdir(parents=True)
        (src / "target" / "Cargo.lock").write_text("version = 3\n")
        assert _scanner(src, tmp_path).nothing_to_scan_reason() is not None


class TestSandboxRequirements:
    """The declaration, through the function every sandboxed spawn goes through."""

    def _policy(self, tmp_path, monkeypatch, *, offline):
        import sys

        from automated_security_helper.utils.sandbox.policy import build_scanner_policy

        home = tmp_path / "home"
        (home / ".cargo" / "advisory-db").mkdir(parents=True)
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setenv("USERPROFILE", str(home))
        source = tmp_path / "src"
        source.mkdir()
        output = source / ".ash" / "ash_output"
        output.mkdir(parents=True)
        policy = build_scanner_policy(
            "cargo-audit",
            CargoAuditScanner.sandbox_requirements,
            argv0=sys.executable,
            source_dir=source,
            output_dir=output,
            results_dir=output / "scanners" / "cargo-audit",
            scan_target=source,
            cwd=source,
            offline=offline,
            network_scanners=None,
        )
        return policy, home

    def test_online_grants_the_network_and_the_database_directory(
        self, tmp_path, monkeypatch
    ):
        policy, home = self._policy(tmp_path, monkeypatch, offline=False)
        assert policy.network is True
        assert (home / ".cargo" / "advisory-db").resolve() in {
            p.resolve() for p in policy.cache
        }

    def test_offline_is_never_granted_the_network(self, tmp_path, monkeypatch):
        policy, _ = self._policy(tmp_path, monkeypatch, offline=True)
        assert policy.network is False

    def test_cargo_home_is_the_declared_cache_variable(self, tmp_path, monkeypatch):
        """cargo-audit writes its lock, its database and the yanked check's index
        under cargo's home on every online run, so that is the cache it declares."""
        assert CargoAuditScanner.sandbox_requirements.cache_env == ("CARGO_HOME",)
        policy, _ = self._policy(tmp_path, monkeypatch, offline=False)
        assert "CARGO_HOME" in policy.cache_env

    def _plan(self, name, tmp_path, monkeypatch, overlay=False):
        from automated_security_helper.utils.sandbox import backends as backends_module
        from automated_security_helper.utils.sandbox import policy as policy_module
        from automated_security_helper.utils.sandbox.backends import BACKENDS

        # The passwd entry's home is the HOME set below, as the sandbox's own tests
        # make it, so no backend reads the home of the account running the tests.
        for module in (policy_module, backends_module):
            monkeypatch.setattr(module, "_passwd_home", Path.home, raising=False)
        monkeypatch.delenv("CARGO_HOME", raising=False)
        policy, home = self._policy(tmp_path, monkeypatch, offline=False)
        Path(policy.results_dir).mkdir(parents=True, exist_ok=True)
        backend = BACKENDS[name]()
        if hasattr(backend, "_executable"):
            backend._executable = f"/usr/bin/{name}"
        if name == "bwrap":
            backend._overlay = overlay
        plan = backend.plan(["/usr/bin/true"], {"PATH": "/usr/bin"}, policy)
        return plan, policy, home

    @pytest.mark.parametrize("name", ["firejail", "landlock", "sandbox-exec", "bwrap"])
    def test_where_caches_are_read_only_cargo_home_is_private_and_writable(
        self, name, tmp_path, monkeypatch
    ):
        """The backends that cannot discard a write mount the database read-only.

        A fetch into the host's ~/.cargo/advisory-db could not write there, and
        cargo-audit exited 1 with no report; with CARGO_HOME pointing at a private,
        empty directory under the results directory, cargo-audit clones the
        database, takes its lock and caches the index there, and the directory is
        removed after the run. (bwrap here is bwrap without overlay support.)
        """
        plan, policy, home = self._plan(name, tmp_path, monkeypatch, overlay=False)
        private = Path(plan.env["CARGO_HOME"])
        assert private.is_dir() and not any(private.iterdir())
        assert private.parent.name.startswith(".sandbox-cache-")
        assert private.parent.parent.resolve() == Path(policy.results_dir).resolve()
        assert not private.resolve().is_relative_to(home.resolve())
        plan.run_cleanup()
        assert not private.parent.exists()

    def test_firejail_keeps_the_hosts_database_read_only(self, tmp_path, monkeypatch):
        """The redirect does not open the host's database to the write instead."""
        plan, _policy, home = self._plan("firejail", tmp_path, monkeypatch)
        database = Path(os.path.realpath(home / ".cargo" / "advisory-db")).as_posix()
        assert f"--read-only={database}" in plan.argv
        assert f"--read-write={database}" not in plan.argv
        plan.run_cleanup()

    def test_bwrap_with_an_overlay_leaves_cargo_home_alone(self, tmp_path, monkeypatch):
        """Control: through the overlay the database is written and the writes are
        discarded, so cargo's home is not redirected there."""
        from automated_security_helper.utils.sandbox import backends as backends_module

        # The plan probes the cache's filesystem with the real bwrap; answered here,
        # as the sandbox's own overlay test does, so the plan's shape is what is read.
        monkeypatch.setattr(backends_module, "_probe_run", lambda argv, env=None: None)
        plan, _policy, home = self._plan("bwrap", tmp_path, monkeypatch, overlay=True)
        database = Path(os.path.realpath(home / ".cargo" / "advisory-db")).as_posix()
        overlay = ["--overlay-src", database, "--tmp-overlay", database]
        assert any(plan.argv[i : i + 4] == overlay for i in range(len(plan.argv))), (
            plan.argv
        )
        assert "CARGO_HOME" not in plan.env
        plan.run_cleanup()


class TestFacetRegisters:
    def test_both_registers_are_declared_on_the_class_itself(self):
        from automated_security_helper.base.scanner_facets import (
            SCANNER_FACETS_ATTR,
            ScannerFacets,
        )
        from automated_security_helper.base.scanner_operational_facets import (
            OPERATIONAL_FACETS_ATTR,
            ScannerOperationalFacets,
        )

        assert isinstance(vars(CargoAuditScanner)[SCANNER_FACETS_ATTR], ScannerFacets)
        ops = vars(CargoAuditScanner)[OPERATIONAL_FACETS_ATTR]
        assert isinstance(ops, ScannerOperationalFacets)
        assert ops.scanner_name == CargoAuditScannerConfig().name

    def test_operational_mirrors_agree_with_the_class(self, tmp_path):
        from automated_security_helper.core.enums import ScannerToolType

        ops = vars(CargoAuditScanner)["operational_facets"]
        scanner = _scanner(tmp_path, tmp_path)
        assert ops.network.offline_strategy is CargoAuditScanner.offline_strategy
        assert ops.network.offline_outcome.value == "not_run"
        assert ops.network.content_database is None
        assert ops.runtime_compat.rows == ()
        assert ops.network.sandbox_network.value == "online"
        assert CargoAuditScanner.sandbox_requirements.network is True
        assert ops.exit_codes.success_exit_codes == tuple(
            sorted(CargoAuditScanner.success_exit_codes)
        )
        # 1 is also the exit of a database that could not be fetched or loaded.
        assert "1 with no report" in ops.exit_codes.semantics
        assert ops.targets.tool_type is scanner.tool_type is ScannerToolType.SCA
        assert ops.runtime.use_uv_tool is bool(scanner.use_uv_tool)
        assert ops.runtime.python_only is bool(scanner.is_python_only())
        assert "cargo-audit" in ops.runtime.external_programs

    def test_mapped_facets_land_in_the_flat_row(self):
        """Over the converter's own output: each MAPPED column is populated, and
        each DROPPED or N/A column is empty (the corpus gate's judgment, run
        here over a document written from the rustsec Report types)."""
        from automated_security_helper.base.scanner_facets import FacetState
        from automated_security_helper.models.flat_vulnerability import (
            FlatVulnerability,
        )

        results = convert_cargo_audit_report(POSITIVE, uri="Cargo.lock")
        report = SarifReport.model_validate(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "cargo-audit"}},
                        "results": results,
                    }
                ],
            }
        )
        rows = [
            FlatVulnerability.from_sarif_result(
                result, "cargo-audit", "SCA", report.runs[0]
            )
            for result in report.runs[0].results
        ]
        assert rows
        facets = vars(CargoAuditScanner)["facets"]
        column = {
            "rule_id": "rule_id",
            "severity": "severity",
            "file_path": "file_path",
            "line_range": "line_start",
            "message": "description",
        }
        for facet, attr in column.items():
            assert getattr(facets, facet).state is FacetState.MAPPED
            assert all(getattr(row, attr) not in (None, "", 0) for row in rows), facet
        # DROPPED and N/A cells must read empty: a populated column means the
        # declaration is out of date.
        for facet in (
            "resource_id",
            "resource_type",
            "package_name",
            "package_version",
            "taxonomy_cve",
            "fix_available",
            "references",
        ):
            assert getattr(facets, facet).state is not FacetState.MAPPED
            assert all(not getattr(row, facet, None) for row in rows), facet
