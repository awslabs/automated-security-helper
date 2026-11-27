"""ferret-scan, hadolint, snyk-code and trivy-repo keep a report's findings when one part of its SARIF is out of spec.

Each of the four read the SARIF a tool wrote with the model alone, so one value it
refuses (a region that starts at line 0, a byte-order mark, a byte that is not UTF-8)
cost the scanner every finding in the report. Three of them also logged the cause and
returned no report, so the row read only "returned no result", and hadolint read every
argv chunk in one try, so one unreadable chunk failed the scan for the others' findings.

They now read through the shared ingest step. The smallest out-of-spec part is dropped
or rewritten, the other findings are kept, and each repair is counted on the scanner's
record, said once in the log, and carried as a warning notification on the invocation,
which fails no run. A report the step cannot repair is refused with the reason, as a
ScannerError, where it used to be returned as no result. hadolint reads each chunk in
its own try: an unreadable chunk records each of its Dockerfiles as one the tool never
evaluated, and the other chunks' findings are kept.
"""

from __future__ import annotations

import copy
import json
import logging
import traceback
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_ferret_plugins import ferret_scanner
from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
    FerretScannerConfig,
    FerretScannerConfigOptions,
    FerretScanScanner,
)
from automated_security_helper.plugin_modules.ash_hadolint_plugins import (
    hadolint_scanner as hs,
)
from automated_security_helper.plugin_modules.ash_hadolint_plugins.hadolint_scanner import (
    HadolintScanner,
    HadolintScannerConfig,
    HadolintScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_snyk_plugins import snyk_code_scanner
from automated_security_helper.plugin_modules.ash_snyk_plugins.snyk_code_scanner import (
    SnykCodeScanner,
    SnykCodeScannerConfig,
)
from automated_security_helper.plugin_modules.ash_trivy_plugins import (
    trivy_repo_scanner,
)
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
    TrivyRepoScannerConfig,
    TrivyRepoScannerConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.config_trust import record_provenance

pytestmark = pytest.mark.unit

# The forward references the plugin context's model holds are resolved before a
# context is built from it.
AshConfig.model_rebuild()

_FIRST_REGION = "runs/0/results/0/locations/0/physicalLocation/region"
_SECOND_REGION = "runs/0/results/1/locations/0/physicalLocation/region"

_LINE = "a region with no readable line"
_BOM = "a byte-order mark before the document"
_NOT_UTF8 = "bytes that are not valid UTF-8"
_CONTROL = "a control character inside a string"


def _sentence(name: str, phrase: str, count: int = 1) -> str:
    """The one line a repair is said in: counts and kinds, no value, no path."""
    parts = "part" if count == 1 else "parts"
    return (
        f"ASH repaired {count} {parts} of {name}'s report that SARIF does not "
        f"allow ({phrase})."
    )


def _result(rule: str, line: int, uri: str = "a.txt", *, index: int | None = None):
    result = {
        "ruleId": rule,
        "level": "warning",
        "message": {"text": f"{rule} was found"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line, "startColumn": 1},
                }
            }
        ],
    }
    if index is not None:
        result["ruleIndex"] = index
    return result


def _without_message(result: dict) -> dict:
    """A result the step cannot repair: SARIF requires its message."""
    broken = copy.deepcopy(result)
    del broken["message"]
    return broken


def _document(tool: dict, *results: dict) -> dict:
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": tool}, "results": list(results)}],
    }


def _encoded(document: dict) -> bytes:
    return json.dumps(document).encode("utf-8")


def _warnings(report) -> list[str]:
    """The warning notifications on the report's invocations, as text."""
    return [
        note.message.root.text
        for invocation in report.runs[0].invocations
        for note in invocation.toolExecutionNotifications or []
        if getattr(note.level, "value", note.level) == "warning"
    ]


def _seen(scanner) -> list[tuple]:
    """(code, pointer, rule id) of each element the scanner's record names."""
    return [
        (e["code"], e["pointer"], e["rule_id"])
        for e in scanner.output_ingest_record["elements"]
    ]


def _rule_ids(report) -> list[str]:
    return [result.ruleId for result in report.runs[0].results]


def _strict(raw, record):
    """Reading as it was before the repair: the model alone, and nothing noted."""
    return SarifReport.model_validate(raw)


# --------------------------------------------------------------------------- #
# ferret-scan
# --------------------------------------------------------------------------- #

_FERRET_TOOL = {"name": "ferret-scan", "version": "2.5.3"}


@pytest.fixture
def ferret(tmp_path) -> FerretScanScanner:
    context = MagicMock(spec=PluginContext)
    context.source_dir = tmp_path / "source"
    context.output_dir = tmp_path / "output"
    context.work_dir = tmp_path / "work"
    for directory in (context.source_dir, context.output_dir, context.work_dir):
        directory.mkdir(exist_ok=True)
    context.global_ignore_paths = []
    (context.source_dir / "a.txt").write_text("hello\n", encoding="utf-8")
    scanner = FerretScanScanner(
        context=context,
        config=FerretScannerConfig(options=FerretScannerConfigOptions()),
    )
    scanner.dependencies_satisfied = True
    return scanner


def _ferret_scan(scanner: FerretScanScanner, written: bytes):
    """scan() with a ferret-scan that writes *written* as its SARIF file.

    Returns the report and the scanner's log calls.
    """

    def run(command, results_dir, **kwargs):
        Path(results_dir, "ferret-scan.sarif").write_bytes(written)
        return {"stdout": "", "stderr": "", "returncode": 0}

    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch.object(scanner, "_run_subprocess", side_effect=run),
        patch.object(scanner, "_plugin_log") as log,
    ):
        report = scanner.scan(target=scanner.context.source_dir, target_type="source")
    return report, log


def test_ferret_keeps_a_reports_findings_when_one_region_is_out_of_spec(ferret):
    document = _document(_FERRET_TOOL, _result("SSN", 0), _result("EMAIL", 3))

    report, log = _ferret_scan(ferret, _encoded(document))

    assert _rule_ids(report) == ["SSN", "EMAIL"]
    assert _seen(ferret) == [("region_line_unreadable", _FIRST_REGION, "SSN")]
    sentence = _sentence("ferret-scan", _LINE)
    assert _warnings(report) == [sentence]
    said = [c for c in log.call_args_list if c.args and c.args[0] == sentence]
    assert len(said) == 1
    assert said[0].kwargs["level"] == logging.WARNING


def test_ferret_names_the_place_of_a_repair_by_its_index_and_never_its_file(ferret):
    document = _document(_FERRET_TOOL, _result("SSN", 3), _result("EMAIL", 0, "a.txt"))

    report, _ = _ferret_scan(ferret, _encoded(document))

    assert _seen(ferret) == [("region_line_unreadable", _SECOND_REGION, "EMAIL")]
    assert "a.txt" not in json.dumps(ferret.output_ingest_record)
    assert all("a.txt" not in text for text in _warnings(report))


def test_ferret_reads_a_report_that_starts_with_a_byte_order_mark(ferret):
    written = b"\xef\xbb\xbf" + _encoded(_document(_FERRET_TOOL, _result("SSN", 3)))

    report, _ = _ferret_scan(ferret, written)

    assert _rule_ids(report) == ["SSN"]
    assert _seen(ferret) == [("bom", "(document)", None)]
    assert _warnings(report) == [_sentence("ferret-scan", _BOM)]


def test_ferret_reads_a_report_with_a_byte_that_is_not_utf8(ferret):
    document = _document(_FERRET_TOOL, _result("SSN", 3), _result("EMAIL", 4))
    written = _encoded(document).replace(b"SSN was found", b"SSN \xff was found")
    assert b"\xff" in written, "the planted byte is in the file"

    report, _ = _ferret_scan(ferret, written)

    assert _rule_ids(report) == ["SSN", "EMAIL"]
    assert _seen(ferret) == [("bytes_not_utf8", "(document)", None)]
    assert _warnings(report) == [_sentence("ferret-scan", _NOT_UTF8)]


def test_ferret_reads_a_control_character_inside_a_string(ferret):
    text = json.dumps(_document(_FERRET_TOOL, _result("SSN", 3)))
    written = text.replace("SSN was found", "SSN was\nfound").encode("utf-8")

    report, _ = _ferret_scan(ferret, written)

    assert _rule_ids(report) == ["SSN"]
    assert _seen(ferret) == [("control_character", "(document)", None)]
    assert _warnings(report) == [_sentence("ferret-scan", _CONTROL)]


def test_ferret_says_nothing_of_a_report_that_needed_no_repair(ferret):
    report, log = _ferret_scan(
        ferret, _encoded(_document(_FERRET_TOOL, _result("SSN", 3)))
    )

    assert _rule_ids(report) == ["SSN"]
    assert ferret.output_ingest_record is None
    assert _warnings(report) == []
    assert not [c for c in log.call_args_list if "ASH repaired" in str(c.args)]


def test_ferret_refuses_a_file_that_is_not_json_and_says_why(ferret):
    """It used to be logged and returned as no result, so the row read only
    "returned no result"."""
    with pytest.raises(ScannerError) as raised:
        _ferret_scan(ferret, b"{not json")

    assert "not SARIF ASH can read" in str(raised.value)
    assert "not valid JSON" in str(raised.value)


def test_ferret_refuses_a_report_the_step_cannot_repair_with_its_refusal_wording(
    ferret,
):
    document = _document(
        _FERRET_TOOL, _result("SSN", 0), _without_message(_result("EMAIL", 3))
    )

    with pytest.raises(ScannerError) as raised:
        _ferret_scan(ferret, _encoded(document))

    message = str(raised.value)
    assert "not SARIF ASH can read" in message
    assert "validation error" in message


def test_the_control_ferret_without_the_step_loses_the_report(ferret, monkeypatch):
    monkeypatch.setattr(ferret_scanner, "ingest_sarif", _strict)
    document = _document(_FERRET_TOOL, _result("SSN", 0), _result("EMAIL", 3))

    with pytest.raises(ScannerError, match="not SARIF ASH can read"):
        _ferret_scan(ferret, _encoded(document))


# --------------------------------------------------------------------------- #
# snyk-code
# --------------------------------------------------------------------------- #

_SNYK_TOOL = {
    "name": "SnykCode",
    "rules": [{"id": "SnykRuleA"}, {"id": "SnykRuleB"}],
}
_SNYK_FLAG = "--sarif-file-output="


@pytest.fixture
def snyk(tmp_path, monkeypatch) -> SnykCodeScanner:
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    for directory in (context.source_dir, context.output_dir, context.work_dir):
        directory.mkdir(parents=True)
    (context.source_dir / "app.js").write_text(
        "const token = 'placeholder';\n", encoding="utf-8"
    )
    binary = tmp_path / "bin" / "snyk"
    binary.parent.mkdir(parents=True, exist_ok=True)
    binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    monkeypatch.setattr(snyk_code_scanner, "find_executable", lambda name: str(binary))
    monkeypatch.setenv("SNYK_TOKEN", "placeholder-token")
    return SnykCodeScanner(context=context, config=SnykCodeScannerConfig())


def _snyk_scan(scanner: SnykCodeScanner, written: bytes, exit_code: int = 1):
    """scan() with a snyk that writes *written* where it is told to and exits with
    *exit_code* (1 is what snyk exits with when it found issues)."""

    def run(self, command, **kwargs):
        destination = next(
            arg.split("=", 1)[1] for arg in command if arg.startswith(_SNYK_FLAG)
        )
        Path(destination).write_bytes(written)
        self.exit_code = max(self.exit_code or 0, exit_code)
        return {"stdout": "", "stderr": "", "returncode": exit_code}

    with patch.object(
        SnykCodeScanner, "_run_subprocess", autospec=True, side_effect=run
    ):
        return scanner.scan(target=scanner.context.source_dir, target_type="source")


def test_snyk_keeps_a_reports_findings_when_one_region_is_out_of_spec(snyk):
    document = _document(
        _SNYK_TOOL, _result("SnykRuleA", 0, "app.js"), _result("SnykRuleB", 7, "app.js")
    )

    report = _snyk_scan(snyk, _encoded(document))

    assert _rule_ids(report) == ["SnykRuleA", "SnykRuleB"]
    assert _seen(snyk) == [("region_line_unreadable", _FIRST_REGION, "SnykRuleA")]
    assert _warnings(report) == [_sentence("snyk-code", _LINE)]


def test_snyk_reads_a_report_that_starts_with_a_byte_order_mark(snyk):
    written = b"\xef\xbb\xbf" + _encoded(
        _document(_SNYK_TOOL, _result("SnykRuleA", 7, "app.js"))
    )

    report = _snyk_scan(snyk, written)

    assert _rule_ids(report) == ["SnykRuleA"]
    assert _seen(snyk) == [("bom", "(document)", None)]
    assert _warnings(report) == [_sentence("snyk-code", _BOM)]


def test_snyk_reads_a_report_with_a_byte_that_is_not_utf8(snyk):
    document = _document(_SNYK_TOOL, _result("SnykRuleA", 7, "app.js"))
    written = _encoded(document).replace(b"SnykRuleA was found", b"Snyk \xff was found")
    assert b"\xff" in written, "the planted byte is in the file"

    report = _snyk_scan(snyk, written)

    assert _rule_ids(report) == ["SnykRuleA"]
    assert _seen(snyk) == [("bytes_not_utf8", "(document)", None)]
    assert _warnings(report) == [_sentence("snyk-code", _NOT_UTF8)]


def test_snyk_says_nothing_of_a_report_that_needed_no_repair(snyk):
    document = _document(_SNYK_TOOL, _result("SnykRuleA", 7, "app.js"))

    report = _snyk_scan(snyk, _encoded(document), exit_code=0)

    assert _rule_ids(report) == ["SnykRuleA"]
    assert snyk.output_ingest_record is None
    assert _warnings(report) == []


def test_snyk_refuses_a_report_the_step_cannot_repair_and_says_so(snyk):
    """It used to be logged and returned as no result, so the row read only
    "returned no result"."""
    document = _document(
        _SNYK_TOOL,
        _result("SnykRuleA", 7, "app.js"),
        _without_message(_result("SnykRuleB", 8, "app.js")),
    )

    with pytest.raises(ScannerError) as raised:
        _snyk_scan(snyk, _encoded(document))

    assert "Snyk Code scan failed" in str(raised.value)
    assert "not SARIF ASH can read" in str(raised.value)


def test_the_control_snyk_without_the_step_loses_the_report(snyk, monkeypatch):
    monkeypatch.setattr(snyk_code_scanner, "ingest_sarif", _strict)
    document = _document(
        _SNYK_TOOL, _result("SnykRuleA", 0, "app.js"), _result("SnykRuleB", 7, "app.js")
    )

    with pytest.raises(ScannerError, match="not SARIF ASH can read"):
        _snyk_scan(snyk, _encoded(document))


# --------------------------------------------------------------------------- #
# trivy-repo
# --------------------------------------------------------------------------- #

_TRIVY_TOOL = {
    "name": "Trivy",
    "rules": [{"id": "CVE-2026-1"}, {"id": "CVE-2026-2"}],
}


@pytest.fixture
def trivy(tmp_path, monkeypatch) -> TrivyRepoScanner:
    for name in (
        "ASH_OFFLINE",
        "TRIVY_CONFIG",
        "TRIVY_IGNOREFILE",
        "TRIVY_SECRET_CONFIG",
    ):
        monkeypatch.delenv(name, raising=False)
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    for directory in (context.source_dir, context.output_dir, context.work_dir):
        directory.mkdir(parents=True, exist_ok=True)
    (context.source_dir / "requirements.txt").write_text("requests==2.19.0\n")
    scanner = TrivyRepoScanner(
        context=context,
        config=TrivyRepoScannerConfig(
            options=TrivyRepoScannerConfigOptions(ignore_unfixed=False)
        ),
    )
    scanner.dependencies_satisfied = True
    return scanner


def _trivy_scan(scanner: TrivyRepoScanner, written: bytes):
    """scan() with a trivy that writes *written* to its ``--output`` path."""

    def run(command, results_dir=None, env=None, timeout=None, **kwargs):
        out = Path(command[command.index("--output") + 1])
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(written)
        return {"returncode": 0}

    def post(target=None, target_type=None, **kwargs):
        scanner.end_time = datetime.now(timezone.utc)

    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan", side_effect=post),
        patch.object(scanner, "_run_subprocess", side_effect=run),
    ):
        return scanner.scan(
            target=Path(scanner.context.source_dir), target_type="source"
        )


def _two_trivy_results(first_line: int = 1) -> dict:
    return _document(
        _TRIVY_TOOL,
        _result("CVE-2026-1", first_line, "requirements.txt", index=0),
        _result("CVE-2026-2", 1, "requirements.txt", index=1),
    )


def test_trivy_repo_keeps_a_reports_findings_when_one_region_is_out_of_spec(trivy):
    report = _trivy_scan(trivy, _encoded(_two_trivy_results(first_line=0)))

    assert _rule_ids(report) == ["CVE-2026-1", "CVE-2026-2"]
    assert _seen(trivy) == [("region_line_unreadable", _FIRST_REGION, "CVE-2026-1")]
    assert _warnings(report) == [_sentence("trivy-repo", _LINE)]


def test_trivy_repo_reads_a_report_that_starts_with_a_byte_order_mark(trivy):
    written = b"\xef\xbb\xbf" + _encoded(_two_trivy_results())

    report = _trivy_scan(trivy, written)

    assert _rule_ids(report) == ["CVE-2026-1", "CVE-2026-2"]
    assert _seen(trivy) == [("bom", "(document)", None)]
    assert _warnings(report) == [_sentence("trivy-repo", _BOM)]


def test_trivy_repo_reads_a_report_with_a_byte_that_is_not_utf8(trivy):
    written = _encoded(_two_trivy_results()).replace(
        b"CVE-2026-2 was found", b"CVE \xff was found"
    )
    assert b"\xff" in written, "the planted byte is in the file"

    report = _trivy_scan(trivy, written)

    assert _rule_ids(report) == ["CVE-2026-1", "CVE-2026-2"]
    assert _seen(trivy) == [("bytes_not_utf8", "(document)", None)]
    assert _warnings(report) == [_sentence("trivy-repo", _NOT_UTF8)]


def test_trivy_repo_says_nothing_of_a_report_that_needed_no_repair(trivy):
    report = _trivy_scan(trivy, _encoded(_two_trivy_results()))

    assert _rule_ids(report) == ["CVE-2026-1", "CVE-2026-2"]
    assert trivy.output_ingest_record is None
    assert _warnings(report) == []


def test_trivy_repo_refuses_a_report_the_step_cannot_repair_and_says_so(trivy):
    """It used to be logged and returned as no result, so the row read only
    "returned no result"."""
    document = _document(
        _TRIVY_TOOL,
        _result("CVE-2026-1", 1, "requirements.txt", index=0),
        _without_message(_result("CVE-2026-2", 1, "requirements.txt", index=1)),
    )

    with pytest.raises(ScannerError) as raised:
        _trivy_scan(trivy, _encoded(document))

    assert "Trivy scan failed" in str(raised.value)
    assert "not SARIF ASH can read" in str(raised.value)


def test_trivy_repo_reports_an_error_after_the_sarif_validated_as_what_it_is(trivy):
    """Only the validation is a results file that is not SARIF. An error in ASH's own
    handling of a report that validated used to be logged as one and returned as no
    result; it is raised under its own text."""
    with (
        patch.object(trivy, "_values_to_redact", return_value=()),
        patch.object(
            trivy, "_attach_trivy_severity", side_effect=RuntimeError("planted failure")
        ),
    ):
        with pytest.raises(ScannerError) as raised:
            _trivy_scan(trivy, _encoded(_two_trivy_results()))

    assert "Trivy scan failed" in str(raised.value)
    assert "planted failure" in str(raised.value)
    assert "not SARIF ASH can read" not in str(raised.value)


def test_the_control_trivy_repo_without_the_step_loses_the_report(trivy, monkeypatch):
    monkeypatch.setattr(trivy_repo_scanner, "ingest_sarif", _strict)

    with pytest.raises(ScannerError, match="not SARIF ASH can read"):
        _trivy_scan(trivy, _encoded(_two_trivy_results(first_line=0)))


# --------------------------------------------------------------------------- #
# hadolint
# --------------------------------------------------------------------------- #

_HADOLINT_TOOL = {"name": "Hadolint", "version": "2.15.1"}


@pytest.fixture
def dockerfiles(tmp_path) -> Path:
    source = tmp_path / "src"
    (source / "services").mkdir(parents=True)
    (source / "Dockerfile").write_text("FROM ubuntu:latest\n", encoding="utf-8")
    (source / "services" / "api.Dockerfile").write_text(
        "FROM python:3.12\n", encoding="utf-8"
    )
    return source


@pytest.fixture
def hadolint_on_path(monkeypatch):
    monkeypatch.setattr(hs, "find_executable", lambda command: f"/fake/bin/{command}")


@pytest.fixture
def hadolint(dockerfiles, tmp_path, hadolint_on_path) -> HadolintScanner:
    config = get_default_config()
    record_provenance(config, in_tree=[], trusted=AshConfig())
    return HadolintScanner(
        context=PluginContext(
            source_dir=dockerfiles,
            output_dir=tmp_path / "out",
            work_dir=tmp_path / "out" / "converted",
            config=config,
        ),
        config=HadolintScannerConfig(
            enabled=True, options=HadolintScannerConfigOptions()
        ),
    )


def _hadolint_text(*results: dict) -> str:
    return json.dumps(_document(_HADOLINT_TOOL, *results))


def _hadolint_scan(scanner: HadolintScanner, monkeypatch, *stdouts: str):
    """scan() with one hadolint run per Dockerfile (so one argv chunk each), each run
    answering the next of *stdouts* as its SARIF report."""
    pending = list(stdouts)

    def run(command, results_dir=None, env=None, timeout=None, **kwargs):
        scanner.exit_code = 0
        fmt = command[command.index("--format") + 1]
        stdout = pending.pop(0) if fmt == "sarif" else "[]"
        return {"returncode": 0, "stdout": stdout, "stderr": ""}

    monkeypatch.setattr(scanner, "_run_subprocess", run)
    monkeypatch.setattr(hs, "_argv_chunks", lambda base, paths: [[p] for p in paths])
    return scanner.scan(target=Path(scanner.context.source_dir), target_type="source")


_FIRST_FILE = "Dockerfile"
_SECOND_FILE = "services/api.Dockerfile"


def test_hadolint_keeps_every_finding_when_one_chunks_region_is_out_of_spec(
    hadolint, monkeypatch
):
    report = _hadolint_scan(
        hadolint,
        monkeypatch,
        _hadolint_text(_result("DL3007", 0, _FIRST_FILE)),
        _hadolint_text(_result("DL3008", 3, _SECOND_FILE)),
    )

    assert _rule_ids(report) == ["DL3007", "DL3008"]
    assert hadolint.targets_attempted == 2 and hadolint.targets_failed == 0
    assert hadolint.unevaluated_targets == []
    assert _seen(hadolint) == [
        ("region_line_unreadable", f"chunk 1: {_FIRST_REGION}", "DL3007")
    ]
    assert _warnings(report) == [_sentence("hadolint", _LINE)]


def test_hadolint_names_a_repair_by_its_chunks_ordinal_and_never_its_files(
    hadolint, monkeypatch
):
    report = _hadolint_scan(
        hadolint,
        monkeypatch,
        _hadolint_text(_result("DL3007", 2, _FIRST_FILE)),
        _hadolint_text(_result("DL3008", 0, _SECOND_FILE)),
    )

    assert _rule_ids(report) == ["DL3007", "DL3008"]
    assert _seen(hadolint) == [
        ("region_line_unreadable", f"chunk 2: {_FIRST_REGION}", "DL3008")
    ]
    assert "Dockerfile" not in json.dumps(hadolint.output_ingest_record)
    assert all("Dockerfile" not in text for text in _warnings(report))


def test_hadolint_reads_a_chunk_that_starts_with_a_byte_order_mark(
    hadolint, monkeypatch
):
    report = _hadolint_scan(
        hadolint,
        monkeypatch,
        chr(0xFEFF) + _hadolint_text(_result("DL3007", 2, _FIRST_FILE)),
        _hadolint_text(_result("DL3008", 3, _SECOND_FILE)),
    )

    assert _rule_ids(report) == ["DL3007", "DL3008"]
    assert hadolint.targets_failed == 0
    assert _seen(hadolint) == [("bom", "chunk 1: (document)", None)]
    assert _warnings(report) == [_sentence("hadolint", _BOM)]


def test_hadolint_reads_a_control_character_inside_a_string(hadolint, monkeypatch):
    first = _hadolint_text(_result("DL3007", 2, _FIRST_FILE)).replace(
        "DL3007 was found", "DL3007 was\nfound"
    )

    report = _hadolint_scan(
        hadolint,
        monkeypatch,
        first,
        _hadolint_text(_result("DL3008", 3, _SECOND_FILE)),
    )

    assert _rule_ids(report) == ["DL3007", "DL3008"]
    assert _seen(hadolint) == [("control_character", "chunk 1: (document)", None)]
    assert _warnings(report) == [_sentence("hadolint", _CONTROL)]


def test_hadolint_says_nothing_of_reports_that_needed_no_repair(hadolint, monkeypatch):
    report = _hadolint_scan(
        hadolint,
        monkeypatch,
        _hadolint_text(_result("DL3007", 2, _FIRST_FILE)),
        _hadolint_text(_result("DL3008", 3, _SECOND_FILE)),
    )

    assert _rule_ids(report) == ["DL3007", "DL3008"]
    assert hadolint.output_ingest_record is None
    assert _warnings(report) == []


_UNREADABLE_CHUNKS = [
    pytest.param("{not json", id="not-json"),
    pytest.param("", id="empty"),
    pytest.param(json.dumps({"version": "2.1.0", "runs": []}), id="no-runs"),
    pytest.param(
        _hadolint_text(_without_message(_result("DL3007", 2, _FIRST_FILE))),
        id="unrepairable",
    ),
]


@pytest.mark.parametrize("unreadable", _UNREADABLE_CHUNKS)
def test_hadolint_keeps_the_other_chunks_findings_when_one_chunk_is_unreadable(
    hadolint, monkeypatch, unreadable
):
    report = _hadolint_scan(
        hadolint,
        monkeypatch,
        unreadable,
        _hadolint_text(_result("DL3008", 3, _SECOND_FILE)),
    )

    assert _rule_ids(report) == ["DL3008"]
    assert hadolint.targets_attempted == 2
    assert hadolint.targets_failed == 1
    # The unreadable chunk's Dockerfile is named as one the tool never evaluated, so
    # the run is not graded as a clean one.
    assert hadolint.unevaluated_targets == [_FIRST_FILE]
    assert any(
        "hadolint did not evaluate 1 Dockerfile (chunk 1 of 2)" in line
        for line in hadolint.errors
    )


def test_hadolint_names_every_input_of_an_unreadable_chunk(hadolint, monkeypatch):
    """A chunk holds many Dockerfiles when the argv allows: each is recorded."""
    answers = iter(["{not json", _hadolint_text(_result("DL3008", 3, _SECOND_FILE))])

    def run(command, results_dir=None, env=None, timeout=None, **kwargs):
        hadolint.exit_code = 0
        fmt = command[command.index("--format") + 1]
        return {
            "returncode": 0,
            "stdout": next(answers) if fmt == "sarif" else "[]",
            "stderr": "",
        }

    third = Path(hadolint.context.source_dir) / "tools.Dockerfile"
    third.write_text("FROM alpine:3.20\n", encoding="utf-8")
    monkeypatch.setattr(hadolint, "_run_subprocess", run)
    given: dict[str, list[str]] = {}

    def two_then_one(base, paths):
        """The first two Dockerfiles together, the last alone."""
        given["paths"] = list(paths)
        return [list(paths[:2]), list(paths[2:])]

    monkeypatch.setattr(hs, "_argv_chunks", two_then_one)

    hadolint.scan(target=Path(hadolint.context.source_dir), target_type="source")

    assert len(given["paths"]) == 3
    assert hadolint.targets_attempted == 3
    assert hadolint.targets_failed == 2
    assert hadolint.unevaluated_targets == given["paths"][:2]
    assert any(
        "hadolint did not evaluate 2 Dockerfiles (chunk 1 of 2)" in line
        for line in hadolint.errors
    )


def test_hadolint_forgets_what_it_repaired_in_a_chunk_it_then_refused(
    hadolint, monkeypatch
):
    """The chunk's region at line 0 could be repaired, its other result could not:
    the chunk is refused as a whole, so the repair changed nothing the report holds
    and is not counted."""
    unreadable = _hadolint_text(
        _result("DL3007", 0, _FIRST_FILE),
        _without_message(_result("DL3009", 4, _FIRST_FILE)),
    )

    report = _hadolint_scan(
        hadolint,
        monkeypatch,
        unreadable,
        _hadolint_text(_result("DL3008", 3, _SECOND_FILE)),
    )

    assert _rule_ids(report) == ["DL3008"]
    assert hadolint.unevaluated_targets == [_FIRST_FILE]
    assert hadolint.output_ingest_record is None
    assert _warnings(report) == []


def test_hadolint_fails_the_scan_when_no_chunk_can_be_read(hadolint, monkeypatch):
    """With nothing read there is no report to keep: the scan fails as it did when any
    one chunk's report was refused, and records no input as unevaluated."""
    with pytest.raises(ScannerError):
        _hadolint_scan(hadolint, monkeypatch, "{not json", "{not json")

    assert hadolint.unevaluated_targets == []


def test_hadolint_still_fails_the_scan_when_a_run_did_not_complete(
    hadolint, monkeypatch
):
    """Reading a chunk's report in its own try does not widen it to the chunk's run:
    a run that did not complete is still the scan's failure."""

    def run(command, results_dir=None, env=None, timeout=None, **kwargs):
        hadolint.exit_code = 1
        return {"returncode": 1, "stdout": "", "stderr": ""}

    monkeypatch.setattr(hadolint, "_run_subprocess", run)

    with pytest.raises(ScannerError, match="did not complete"):
        hadolint.scan(target=Path(hadolint.context.source_dir), target_type="source")

    assert hadolint.unevaluated_targets == []


def test_the_control_hadolint_without_the_step_loses_the_chunk(hadolint, monkeypatch):
    """With the model alone the line-0 region costs the chunk its finding and its
    Dockerfile is not evaluated; the other chunk's finding is all that is left."""
    monkeypatch.setattr(hs, "ingest_sarif", _strict)

    report = _hadolint_scan(
        hadolint,
        monkeypatch,
        _hadolint_text(_result("DL3007", 0, _FIRST_FILE)),
        _hadolint_text(_result("DL3008", 3, _SECOND_FILE)),
    )

    assert _rule_ids(report) == ["DL3008"]
    assert hadolint.unevaluated_targets == [_FIRST_FILE]


# --------------------------------------------------------------------------- #
# The four single-document readers, side by side
# --------------------------------------------------------------------------- #

_PLANTED = "planted-results-value-not-sarif"


# Each entry is (fixture name, a function that scans with the scanner and the bytes
# the tool wrote). snyk is scanned at exit 0, so the run is read and refused by the
# reader and not first by the check that a run which exits 1 holds a result;
# hadolint runs one chunk per Dockerfile, so both chunks answer the same bytes.
def _scan_ferret(scanner, _monkeypatch, written):
    return _ferret_scan(scanner, written)[0]


def _scan_snyk(scanner, _monkeypatch, written):
    return _snyk_scan(scanner, written, exit_code=0)


def _scan_trivy(scanner, _monkeypatch, written):
    return _trivy_scan(scanner, written)


def _scan_hadolint(scanner, monkeypatch, written):
    return _hadolint_scan(scanner, monkeypatch, written.decode(), written.decode())


# The third value is whether the error the refusal was raised from stays in the chain
# a traceback prints. trivy's refusal is raised outside the handler that caught it,
# so its chain ends at the refusal and nothing behind it can print an input.
_READERS = [
    pytest.param("ferret", _scan_ferret, True, id="ferret"),
    pytest.param("snyk", _scan_snyk, True, id="snyk"),
    pytest.param("trivy", _scan_trivy, False, id="trivy"),
    pytest.param("hadolint", _scan_hadolint, True, id="hadolint"),
]
_NO_HADOLINT = _READERS[:3]


def _everything_a_log_would_print(error: BaseException) -> str:
    """The error as an uncaught traceback prints it, every chained error included."""
    return "".join(traceback.format_exception(type(error), error, error.__traceback__))


@pytest.mark.parametrize(("fixture", "scan", "chained"), _READERS)
def test_no_reader_prints_an_input_value_in_a_refusal_or_in_the_error_behind_it(
    request, monkeypatch, fixture, scan, chained
):
    """pydantic's own text for a refused value quotes it (``input_value=...``). The
    models hide it, so neither the refusal nor the error it was raised from, which
    a traceback in a log prints too, carries what the tool wrote."""
    scanner = request.getfixturevalue(fixture)
    document = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": _SNYK_TOOL}, "results": [_PLANTED]}],
    }

    with pytest.raises(ScannerError) as raised:
        scan(scanner, monkeypatch, _encoded(document))

    printed = _everything_a_log_would_print(raised.value)
    if chained:
        assert "validation error for" in printed, (
            "the error behind the refusal is in the chain this test reads"
        )
    assert _PLANTED not in str(raised.value)
    assert _PLANTED not in printed


_NO_RUN_AFTER_A_REPAIR = {"version": "2.1.0", "tool_note": "x"}


@pytest.mark.parametrize(("fixture", "scan", "chained"), _NO_HADOLINT)
def test_a_document_that_the_repair_left_with_no_run_is_refused_not_graded_clean(
    request, monkeypatch, fixture, scan, chained
):
    """``tool_note`` is a key SARIF does not define, so the step drops it and the
    document is left with no run. Returned, it would be graded as a scan that found
    nothing, and the repair would only be logged."""
    scanner = request.getfixturevalue(fixture)

    with pytest.raises(ScannerError, match="holds no SARIF run") as raised:
        scan(scanner, monkeypatch, _encoded(_NO_RUN_AFTER_A_REPAIR))

    assert "tool_note" not in str(raised.value)


@pytest.mark.parametrize(("fixture", "scan", "chained"), _NO_HADOLINT)
def test_a_document_that_names_no_run_and_needed_no_repair_is_still_returned(
    request, monkeypatch, fixture, scan, chained
):
    """The refusal is for what the repair emptied. A report the tool wrote with an
    empty ``runs`` list is its own statement and is read as it was."""
    scanner = request.getfixturevalue(fixture)

    report = scan(scanner, monkeypatch, _encoded({"version": "2.1.0", "runs": []}))

    assert not report.runs
    assert scanner.output_ingest_record is None
