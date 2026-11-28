"""cfn-guard, cfn-lint and cfn-nag keep a template's findings when one part of its SARIF is out of spec.

Each of the three reads the SARIF a tool writes for a template, or for a batch of
templates, and used to refuse the whole document for one value the SARIF model
does not accept: a region that starts at line 0, a byte-order mark, a byte that is
not UTF-8, and for cfn-nag a lone-surrogate escape anywhere in the text (its JSON
parse refused that at once). The template or the batch then counted as a target
the tool never evaluated, and none of its findings reached the report.

They now read through the shared ingest step. The smallest out-of-spec part is
dropped or rewritten, the other findings are kept, and each repair is counted on
the scanner's record, said once in the log, and carried as a warning notification
on the invocation. A template the step cannot repair is still a failed target,
recorded by name as one the tool never evaluated, and keeps none of its repairs in
the count.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Callable
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    cfn_guard_scanner,
    cfn_lint_scanner,
    cfn_nag_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_guard_scanner import (
    CfnGuardScanner,
    CfnGuardScannerConfig,
    CfnGuardScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_lint_scanner import (
    CfnLintScanner,
    CfnLintScannerConfig,
    CfnLintScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner import (
    CfnNagScanner,
    CfnNagScannerConfig,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.schemas.scanner_output_ingest import IngestRecord
from automated_security_helper.utils.cfn_template_discovery import TemplateDiscovery
from automated_security_helper.utils.config_trust import record_provenance
from tests.unit.base.scanner_support import is_resource_run

pytestmark = pytest.mark.unit

_TEMPLATE = "Resources:\n  Q:\n    Type: AWS::SQS::Queue\n"
_ROLE_TEMPLATE = (
    "Resources:\n  MyRole:\n    Type: AWS::IAM::Role\n"
    "    Properties:\n      RoleName: placeholder-role\n"
)
_QUEUE_TEMPLATE = (
    "Resources:\n  MyQueue:\n    Type: AWS::SQS::Queue\n"
    "    Properties:\n      QueueName: placeholder-queue\n"
)

_FIRST_REGION = "runs/0/results/0/locations/0/physicalLocation/region"
_SENTENCE = (
    "ASH repaired {n} {parts} of {name}'s report that SARIF does not allow "
    "(a region with no readable line)."
)

_GUARD_TOOL = {"name": "cfn-guard", "semanticVersion": "3.3.0"}
_LINT_TOOL = {
    "name": "cfn-lint",
    "version": "1.57.2",
    "rules": [{"id": "W2001", "shortDescription": {"text": "unused"}}],
}
_NAG_TOOL = {
    "name": "cfn_nag",
    "rules": [
        {"id": "F38", "shortDescription": {"text": "IAM policy should not allow *"}},
        {"id": "W48", "shortDescription": {"text": "another rule"}},
    ],
}


def _result(rule: str, line: int, uri: str = "template.yaml") -> dict:
    return {
        "ruleId": rule,
        "level": "error",
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


def _bytes(document: dict) -> bytes:
    return json.dumps(document).encode("utf-8")


def _warnings(report) -> list:
    return [
        note.message.root.text
        for invocation in report.runs[0].invocations
        for note in invocation.toolExecutionNotifications or []
        if getattr(note.level, "value", note.level) == "warning"
    ]


def _seen(scanner) -> list:
    return [
        (e["code"], e["pointer"], e["rule_id"])
        for e in scanner.output_ingest_record["elements"]
    ]


# --------------------------------------------------------------------------- #
# The record forgets what it noted on a document that was then refused
# --------------------------------------------------------------------------- #


def test_a_record_goes_back_to_its_checkpoint():
    record = IngestRecord()
    record.note("dropped", "region_line_unreadable", ("runs", 0), rule_id="r-one")
    checkpoint = record.checkpoint()

    with record.scoped("template 2"):
        record.note("dropped", "unknown_key", ("runs", 0, "results", 1, "x"))
    record.results_read += 3
    assert record.repaired == 2

    record.rollback(checkpoint)

    assert record.repaired == 1 and record.results_read == 0 and record.left_out == 0
    assert record.summary()["changes"] == [
        {"action": "dropped", "code": "region_line_unreadable", "count": 1}
    ]
    assert [e["rule_id"] for e in record.summary()["elements"]] == ["r-one"]


def test_what_is_noted_after_a_rollback_does_not_reach_the_checkpoint():
    record = IngestRecord()
    checkpoint = record.checkpoint()
    record.rollback(checkpoint)

    record.note("dropped", "unknown_key", ("runs", 0, "x"))
    record.rollback(checkpoint)

    assert record.is_empty and record.summary() is None


def test_a_checkpoint_taken_with_nothing_noted_empties_the_record():
    record = IngestRecord()
    checkpoint = record.checkpoint()
    record.note("rewritten", "bom")
    record.note("left_out", "result_unreadable", ("runs", 0, "results", 2))

    record.rollback(checkpoint)

    assert record.is_empty
    assert record.repaired == 0 and record.left_out == 0
    assert record.sentence("cfn-guard") is None


# --------------------------------------------------------------------------- #
# cfn-guard: one SARIF document per template, on stdout
# --------------------------------------------------------------------------- #


@pytest.fixture
def source(tmp_path) -> Path:
    directory = tmp_path / "src"
    directory.mkdir()
    (directory / "one.yaml").write_text(_TEMPLATE, encoding="utf-8")
    (directory / "two.yaml").write_text(_TEMPLATE, encoding="utf-8")
    return directory


@pytest.fixture
def faked_guard():
    """Rule selection empty, dependencies present; only the process is left."""
    with (
        patch.object(CfnGuardScanner, "_selected_rules", return_value=[]),
        patch.object(
            CfnGuardScanner, "validate_plugin_dependencies", return_value=True
        ),
    ):
        yield


def _guard(source: Path) -> CfnGuardScanner:
    config = get_default_config()
    record_provenance(config, in_tree=[], trusted=AshConfig())
    context = PluginContext(
        source_dir=source,
        output_dir=source / ".ash" / "ash_output",
        work_dir=source / ".ash" / "ash_output" / "converted",
        config=config,
    )
    return CfnGuardScanner(
        context=context,
        config=CfnGuardScannerConfig(
            enabled=True, options=CfnGuardScannerConfigOptions()
        ),
    )


def _guard_scan(scanner: CfnGuardScanner, source: Path, *answers):
    """One cfn-guard answer per template, in the order the templates are scanned.

    A dict is written as JSON; a string is the answer's text as it is.
    """
    found = TemplateDiscovery(templates=[source / "one.yaml", source / "two.yaml"])
    texts = [a if isinstance(a, str) else json.dumps(a) for a in answers]

    def run(self_, **kwargs):
        return {"returncode": 19, "stdout": texts.pop(0), "stderr": ""}

    with (
        patch.object(cfn_guard_scanner, "discover_templates", return_value=found),
        patch.object(
            CfnGuardScanner, "_run_subprocess", autospec=True, side_effect=run
        ),
    ):
        return scanner.scan(target=source, target_type="source")


def test_cfn_guard_keeps_a_templates_findings_when_one_region_is_out_of_spec(
    source, faked_guard
):
    scanner = _guard(source)

    report = _guard_scan(
        scanner,
        source,
        _document(_GUARD_TOOL, _result("RULE_A", 0), _result("RULE_B", 7)),
        _document(_GUARD_TOOL, _result("RULE_C", 2)),
    )

    assert [r.ruleId for r in report.runs[0].results] == ["RULE_A", "RULE_B", "RULE_C"]
    assert scanner.targets_attempted == 2 and scanner.targets_failed == 0
    assert list(scanner.unevaluated_targets) == []
    summary = scanner.output_ingest_record
    assert summary["repaired"] == 1 and summary["results_read"] == 3
    assert _seen(scanner) == [
        ("region_line_unreadable", f"template 1: {_FIRST_REGION}", "RULE_A")
    ]
    assert _warnings(report) == [_SENTENCE.format(n=1, parts="part", name="cfn-guard")]


def test_cfn_guard_names_the_template_by_its_ordinal_and_never_by_its_path(
    source, faked_guard
):
    scanner = _guard(source)

    report = _guard_scan(
        scanner,
        source,
        _document(_GUARD_TOOL, _result("RULE_A", 3)),
        _document(_GUARD_TOOL, _result("RULE_B", 0)),
    )

    assert scanner.targets_failed == 0
    assert _seen(scanner) == [
        ("region_line_unreadable", f"template 2: {_FIRST_REGION}", "RULE_B")
    ]
    assert "two.yaml" not in json.dumps(scanner.output_ingest_record)
    assert all("two.yaml" not in text for text in _warnings(report))


def test_cfn_guard_reads_stdout_that_starts_with_a_byte_order_mark(source, faked_guard):
    scanner = _guard(source)
    marked = chr(0xFEFF) + json.dumps(_document(_GUARD_TOOL, _result("RULE_A", 3)))

    report = _guard_scan(
        scanner, source, marked, _document(_GUARD_TOOL, _result("RULE_B", 4))
    )

    assert [r.ruleId for r in report.runs[0].results] == ["RULE_A", "RULE_B"]
    assert scanner.targets_failed == 0
    assert _seen(scanner) == [("bom", "template 1: (document)", None)]
    assert len(_warnings(report)) == 1


def test_cfn_guard_still_records_a_template_it_cannot_repair_as_unevaluated(
    source, faked_guard
):
    scanner = _guard(source)

    report = _guard_scan(
        scanner,
        source,
        _document(_GUARD_TOOL, _result("RULE_A", 3)),
        _document(_GUARD_TOOL, _result("RULE_B", 0), _without_message(_result("C", 5))),
    )

    assert [r.ruleId for r in report.runs[0].results] == ["RULE_A"]
    assert scanner.targets_attempted == 2 and scanner.targets_failed == 1
    assert sorted(scanner.unevaluated_targets) == ["two.yaml"]
    assert any(
        "did not evaluate two.yaml" in line and "not valid SARIF" in line
        for line in scanner.errors
    ), scanner.errors
    # The region it repaired on the way to the refusal changed nothing the report
    # holds, so it is not counted.
    assert scanner.output_ingest_record is None
    assert _warnings(report) == []


def test_cfn_guard_counts_the_repairs_of_the_templates_it_read_beside_a_refused_one(
    source, faked_guard
):
    scanner = _guard(source)

    report = _guard_scan(
        scanner,
        source,
        _document(_GUARD_TOOL, _result("RULE_A", 0)),
        _document(_GUARD_TOOL, _result("RULE_B", 0), _without_message(_result("C", 5))),
    )

    assert [r.ruleId for r in report.runs[0].results] == ["RULE_A"]
    assert sorted(scanner.unevaluated_targets) == ["two.yaml"]
    assert scanner.output_ingest_record["repaired"] == 1
    assert _seen(scanner) == [
        ("region_line_unreadable", f"template 1: {_FIRST_REGION}", "RULE_A")
    ]


def test_cfn_guard_parse_response_repairs_with_no_record_given():
    failure, report = CfnGuardScanner._parse_response(
        {
            "returncode": 19,
            "stdout": json.dumps(_document(_GUARD_TOOL, _result("RULE_A", 0))),
            "stderr": "",
        },
        values=(),
    )

    assert failure is None
    assert [r.ruleId for r in report.runs[0].results] == ["RULE_A"]


def test_control_cfn_guard_with_the_model_alone_the_template_is_lost(
    source, faked_guard
):
    scanner = _guard(source)

    with patch.object(
        cfn_guard_scanner,
        "ingest_sarif",
        side_effect=lambda raw, record: SarifReport.model_validate(raw),
    ):
        report = _guard_scan(
            scanner,
            source,
            _document(_GUARD_TOOL, _result("RULE_A", 0)),
            _document(_GUARD_TOOL, _result("RULE_B", 3)),
        )

    assert [r.ruleId for r in report.runs[0].results] == ["RULE_B"]
    assert scanner.targets_failed == 1
    assert sorted(scanner.unevaluated_targets) == ["one.yaml"]


# --------------------------------------------------------------------------- #
# cfn-lint: one SARIF file per batch of templates
# --------------------------------------------------------------------------- #


class _WritesTheBatch:
    """cfn-lint standing in: each invocation's SARIF is ``make(files)``, as bytes.

    The scanner's own second run, which asks the tool for JSON to name each
    result's resource, is answered with an empty report.
    """

    def __init__(self, make: Callable[[list], bytes]):
        self.make = make
        self.calls: list = []

    def __call__(self, command, **kwargs):
        output = next(
            a.split("=", 1)[1] for a in command if a.startswith("--output-file=")
        )
        if is_resource_run(command):
            Path(output).write_text("[]", encoding="utf-8")
            return {"stdout": "", "stderr": "", "returncode": 4}
        self.calls.append(list(command))
        files = command[command.index("--") + 1 :]
        Path(output).write_bytes(self.make(files))
        return {"stdout": "", "stderr": "", "returncode": 4}


def _lint_repo(tmp_path: Path, *names: str) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    for name in names:
        (repo / name).write_text(_TEMPLATE, encoding="utf-8")
    return repo


def _lint(repo: Path) -> CfnLintScanner:
    config = get_default_config()
    record_provenance(config, in_tree=[], trusted=AshConfig(), config_overrides=[])
    context = PluginContext(
        source_dir=repo,
        output_dir=repo / ".ash" / "ash_output",
        work_dir=repo / ".ash" / "ash_output" / "converted",
        config=config,
    )
    return CfnLintScanner(
        context=context,
        config=CfnLintScannerConfig(
            enabled=True, options=CfnLintScannerConfigOptions()
        ),
    )


def _lint_scan(scanner: CfnLintScanner, fake, repo: Path):
    with (
        patch.object(CfnLintScanner, "validate_plugin_dependencies", return_value=True),
        patch.object(CfnLintScanner, "_run_subprocess", side_effect=fake),
    ):
        return scanner.scan(target=repo, target_type="source")


def _one_result_per_file(files: list, *, first_line: int = 0) -> bytes:
    """A batch's SARIF with a result for each file; the first at ``first_line``."""
    results = [
        _result("W2001", first_line if index == 0 else 4, name)
        for index, name in enumerate(files)
    ]
    return _bytes(_document(_LINT_TOOL, *results))


def test_cfn_lint_keeps_a_batchs_findings_when_one_region_is_out_of_spec(tmp_path):
    repo = _lint_repo(tmp_path, "a.yaml", "b.yaml")
    fake = _WritesTheBatch(_one_result_per_file)
    scanner = _lint(repo)

    report = _lint_scan(scanner, fake, repo)

    assert len(fake.calls) == 1, "the two templates did not run as one batch"
    assert len(report.runs[0].results) == 2
    assert scanner.targets_attempted == 2 and scanner.targets_failed == 0
    assert list(scanner.unevaluated_targets) == []
    summary = scanner.output_ingest_record
    assert summary["repaired"] == 1 and summary["results_read"] == 2
    assert _seen(scanner) == [
        ("region_line_unreadable", f"batch 1: {_FIRST_REGION}", "W2001")
    ]
    assert _warnings(report) == [_SENTENCE.format(n=1, parts="part", name="cfn-lint")]


def test_cfn_lint_reads_a_batch_file_that_starts_with_a_byte_order_mark(tmp_path):
    repo = _lint_repo(tmp_path, "a.yaml", "b.yaml")
    fake = _WritesTheBatch(
        lambda files: b"\xef\xbb\xbf" + _one_result_per_file(files, first_line=3)
    )
    scanner = _lint(repo)

    report = _lint_scan(scanner, fake, repo)

    assert len(report.runs[0].results) == 2
    assert scanner.targets_failed == 0
    assert _seen(scanner) == [("bom", "batch 1: (document)", None)]
    assert len(_warnings(report)) == 1


def test_cfn_lint_reads_a_batch_file_with_a_byte_that_is_not_utf8(tmp_path):
    repo = _lint_repo(tmp_path, "a.yaml", "b.yaml")

    def make(files):
        document = json.loads(_one_result_per_file(files, first_line=3))
        document["runs"][0]["results"][0]["message"]["text"] = "a PLACEHOLDER byte"
        return json.dumps(document).encode("utf-8").replace(b"PLACEHOLDER", b"\xe9")

    scanner = _lint(repo)

    report = _lint_scan(scanner, _WritesTheBatch(make), repo)

    assert len(report.runs[0].results) == 2
    assert scanner.targets_failed == 0
    assert _seen(scanner) == [("bytes_not_utf8", "batch 1: (document)", None)]


def test_cfn_lint_loses_only_the_template_it_cannot_repair_and_counts_the_other(
    tmp_path,
):
    """The batch is refused whole, so each template is linted on its own: the
    repair of the one that reads is counted, the partial repair of the batch is
    not, and the one that does not read is recorded unevaluated."""
    repo = _lint_repo(tmp_path, "a.yaml", "b.yaml")

    def make(files):
        results = []
        for name in files:
            result = _result("W2001", 0, name)
            if name.endswith("b.yaml"):
                del result["message"]
            results.append(result)
        return _bytes(_document(_LINT_TOOL, *results))

    fake = _WritesTheBatch(make)
    scanner = _lint(repo)

    report = _lint_scan(scanner, fake, repo)

    assert [len(call[call.index("--") + 1 :]) for call in fake.calls] == [2, 1, 1]
    assert scanner.targets_attempted == 2 and scanner.targets_failed == 1
    assert sorted(scanner.unevaluated_targets) == ["b.yaml"]
    assert [r.ruleId for r in report.runs[0].results] == ["W2001"]
    summary = scanner.output_ingest_record
    assert summary["repaired"] == 1
    (code, pointer, rule) = _seen(scanner)[0]
    assert code == "region_line_unreadable" and rule == "W2001"
    assert pointer.startswith("batch 1.") and pointer.endswith(_FIRST_REGION)


def test_cfn_lint_records_every_template_of_a_batch_it_cannot_repair(tmp_path):
    """Two templates, and every run of them is refused: the batch of two, then each
    template on its own. Both are unevaluated and the repairs made on the way to the
    refusals are counted for none."""
    repo = _lint_repo(tmp_path, "a.yaml", "b.yaml")

    def make(files):
        return _bytes(
            _document(
                _LINT_TOOL,
                _result("W2001", 0, files[0]),
                _without_message(_result("W2001", 4, files[0])),
            )
        )

    fake = _WritesTheBatch(make)
    scanner = _lint(repo)

    report = _lint_scan(scanner, fake, repo)

    assert [len(call[call.index("--") + 1 :]) for call in fake.calls] == [2, 1, 1]
    assert report.runs[0].results == []
    assert scanner.targets_attempted == 2 and scanner.targets_failed == 2
    assert sorted(scanner.unevaluated_targets) == ["a.yaml", "b.yaml"]
    assert scanner.output_ingest_record is None


def test_control_cfn_lint_with_the_model_alone_the_batch_is_lost(tmp_path):
    repo = _lint_repo(tmp_path, "a.yaml", "b.yaml")
    scanner = _lint(repo)

    with patch.object(
        cfn_lint_scanner,
        "ingest_sarif",
        side_effect=lambda raw, record: SarifReport.model_validate(raw),
    ):
        report = _lint_scan(scanner, _WritesTheBatch(_one_result_per_file), repo)

    assert report.runs[0].results == []
    assert scanner.targets_failed == 2
    assert sorted(scanner.unevaluated_targets) == ["a.yaml", "b.yaml"]


def test_control_cfn_lint_with_the_model_alone_a_batch_with_a_clean_region_is_kept(
    tmp_path,
):
    """The twin of the control above. The patch is not what empties the report: the
    same two templates with a region the model reads are kept, so the line-0
    region is the one thing the control above takes away."""
    repo = _lint_repo(tmp_path, "a.yaml", "b.yaml")
    scanner = _lint(repo)

    with patch.object(
        cfn_lint_scanner,
        "ingest_sarif",
        side_effect=lambda raw, record: SarifReport.model_validate(raw),
    ) as the_model_alone:
        report = _lint_scan(
            scanner,
            _WritesTheBatch(lambda files: _one_result_per_file(files, first_line=3)),
            repo,
        )

    the_model_alone.assert_called_once()
    assert len(report.runs[0].results) == 2
    assert scanner.targets_failed == 0
    assert list(scanner.unevaluated_targets) == []


# --------------------------------------------------------------------------- #
# cfn-nag: one SARIF document per template, on stdout
# --------------------------------------------------------------------------- #


@pytest.fixture
def nag(tmp_path) -> CfnNagScanner:
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    context.source_dir.mkdir(parents=True)
    context.output_dir.mkdir(parents=True)
    context.work_dir.mkdir(parents=True)
    return CfnNagScanner(context=context, config=CfnNagScannerConfig())


@pytest.fixture
def nag_dependencies():
    """Report the Ruby cfn_nag binary as present without installing it."""
    with patch.object(
        CfnNagScanner, "validate_plugin_dependencies", autospec=True, return_value=True
    ):
        yield


def _nag_scan(scanner: CfnNagScanner, *answers, templates=("role.yaml",)):
    """Scan a work directory holding ``templates``; the tool answers one text each."""
    texts = [a if isinstance(a, str) else json.dumps(a) for a in answers]
    for name in templates:
        text = _QUEUE_TEMPLATE if name.startswith("queue") else _ROLE_TEMPLATE
        (scanner.context.work_dir / name).write_text(text, encoding="utf-8")

    def run(self_, **kwargs):
        return {"stdout": texts.pop(0) if texts else "", "stderr": "", "returncode": 0}

    with patch.object(CfnNagScanner, "_run_subprocess", autospec=True, side_effect=run):
        return scanner.scan(target=scanner.context.work_dir, target_type="converted")


def test_cfn_nag_keeps_a_templates_findings_when_one_region_is_out_of_spec(
    nag, nag_dependencies
):
    report = _nag_scan(
        nag,
        _document(
            _NAG_TOOL, _result("F38", 0, "role.yaml"), _result("W48", 5, "role.yaml")
        ),
    )

    assert [r.ruleId for r in report.runs[0].results] == ["F38", "W48"]
    assert nag.targets_attempted == 1 and nag.targets_failed == 0
    assert not nag.unevaluated_targets
    summary = nag.output_ingest_record
    assert summary["repaired"] == 1 and summary["results_read"] == 2
    assert _seen(nag) == [
        ("region_line_unreadable", f"template 1: {_FIRST_REGION}", "F38")
    ]
    assert _warnings(report) == [_SENTENCE.format(n=1, parts="part", name="cfn-nag")]


def _a_surrogate_as_a_json_escape(document: dict) -> str:
    """``json.dumps`` writes the lone surrogate as the six characters ``\\udc80``,
    as a tool's JSON writer does."""
    text = json.dumps(document)
    assert "\\udc80" in text
    return text


def _a_surrogate_as_a_raw_character(document: dict) -> str:
    """The text a tool's stdout decodes to with ``errors="surrogateescape"`` when it
    wrote the byte 0x80: the lone surrogate is itself in the string."""
    text = json.dumps(document, ensure_ascii=False)
    assert chr(0xDC80) in text
    return text


@pytest.mark.parametrize(
    "written",
    [_a_surrogate_as_a_json_escape, _a_surrogate_as_a_raw_character],
    ids=["json-escape", "raw-character"],
)
def test_cfn_nag_keeps_a_finding_whose_message_holds_a_lone_surrogate(
    nag, nag_dependencies, written
):
    """Read as JSON by the model, one such escape anywhere refused the document.

    The text is kept in record form (the six characters ``\\udc80``), so the report
    still serializes to UTF-8, and nothing is repaired: no note, no warning.
    """
    result = _result("F38", 3, "role.yaml")
    result["message"]["text"] = "a name with " + chr(0xDC80) + " in it"

    report = _nag_scan(nag, written(_document(_NAG_TOOL, result)))

    assert [r.ruleId for r in report.runs[0].results] == ["F38"]
    assert nag.targets_failed == 0
    assert not nag.unevaluated_targets
    assert report.runs[0].results[0].message.root.text == "a name with \\udc80 in it"
    assert report.model_dump_json().encode("utf-8")
    assert nag.output_ingest_record is None
    assert _warnings(report) == []


def test_cfn_nag_reads_stdout_that_starts_with_a_byte_order_mark(nag, nag_dependencies):
    marked = chr(0xFEFF) + json.dumps(
        _document(_NAG_TOOL, _result("F38", 3, "role.yaml"))
    )

    report = _nag_scan(nag, marked)

    assert [r.ruleId for r in report.runs[0].results] == ["F38"]
    assert nag.targets_failed == 0
    assert _seen(nag) == [("bom", "template 1: (document)", None)]


def test_cfn_nag_still_records_a_template_it_cannot_repair_as_unevaluated(
    nag, nag_dependencies
):
    report = _nag_scan(
        nag,
        _document(
            _NAG_TOOL,
            _result("F38", 0, "role.yaml"),
            _without_message(_result("W48", 5, "role.yaml")),
        ),
    )

    assert report.runs[0].results == []
    assert nag.targets_attempted == 1 and nag.targets_failed == 1
    assert len(list(nag.unevaluated_targets)) == 1
    assert any("role.yaml" in name for name in nag.unevaluated_targets)
    assert any("role.yaml" in line for line in nag.errors), nag.errors
    # The region repaired on the way to the refusal is not counted.
    assert nag.output_ingest_record is None
    assert _warnings(report) == []


def test_cfn_nag_counts_the_repair_of_the_template_it_read_beside_a_refused_one(
    nag, nag_dependencies
):
    """Which of the two templates is scanned first is not asserted: either way the
    one answer repairs a region, and the other is refused after a repair of its
    own that is not counted."""
    readable = _document(_NAG_TOOL, _result("F38", 0, "role.yaml"))
    refused = _document(
        _NAG_TOOL,
        _result("W48", 0, "queue.yaml"),
        _without_message(_result("W48", 5, "queue.yaml")),
    )

    report = _nag_scan(nag, readable, refused, templates=("role.yaml", "queue.yaml"))

    assert nag.targets_attempted == 2 and nag.targets_failed == 1
    assert len(list(nag.unevaluated_targets)) == 1
    assert nag.output_ingest_record["repaired"] == 1
    assert len(report.runs[0].results) == 1


def test_control_cfn_nag_with_the_model_alone_the_template_is_lost(
    nag, nag_dependencies
):
    with patch.object(
        cfn_nag_scanner,
        "ingest_sarif",
        side_effect=lambda raw, record: SarifReport.model_validate(raw),
    ):
        report = _nag_scan(nag, _document(_NAG_TOOL, _result("F38", 0, "role.yaml")))

    assert report.runs[0].results == []
    assert nag.targets_failed == 1
    assert any("role.yaml" in name for name in nag.unevaluated_targets)


def test_control_cfn_nag_with_the_model_alone_a_template_with_a_clean_region_is_kept(
    nag, nag_dependencies
):
    """The twin of the control above: the same template with a region the model
    reads keeps its finding, so only the line-0 region is lost to the patch."""
    with patch.object(
        cfn_nag_scanner,
        "ingest_sarif",
        side_effect=lambda raw, record: SarifReport.model_validate(raw),
    ) as the_model_alone:
        report = _nag_scan(nag, _document(_NAG_TOOL, _result("F38", 3, "role.yaml")))

    the_model_alone.assert_called_once()
    assert [r.ruleId for r in report.runs[0].results] == ["F38"]
    assert nag.targets_failed == 0
    assert not nag.unevaluated_targets
