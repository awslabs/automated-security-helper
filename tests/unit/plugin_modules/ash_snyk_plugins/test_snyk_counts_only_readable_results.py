"""snyk-code counts only the results it can read when it decides a run found nothing.

snyk exits 1 when it found issues. A run that exits 1 and holds no results has not
shown what it scanned, so ``scan()`` refuses it instead of reading it as a clean
scan. That check counted with ``len()`` of whatever sat where a ``results`` list
should be, so:

- a ``results`` that was a string counted as many results as it had characters;
- a ``results`` that was an object counted as many as it had keys;
- a ``runs`` that was a number or ``true`` raised a ``TypeError`` out of the check,
  which the scan then reported as "Snyk Code scan failed: 'int' object is not
  iterable".

Each of those passed the check or failed it for a reason that had nothing to do with
the findings, and none of them said which part of the report was out of place. Now a
result counts only when it is an object inside a ``results`` list inside a run that
is an object inside the ``runs`` list. A container of any other kind counts for none
and is noted on the scanner's record, by where it sits and never by what it holds.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_snyk_plugins import snyk_code_scanner
from automated_security_helper.plugin_modules.ash_snyk_plugins.snyk_code_scanner import (
    SnykCodeScanner,
    SnykCodeScannerConfig,
    _sarif_result_count,
    normalize_rule_cwe_into_tags,
)
from automated_security_helper.schemas.scanner_output_ingest import IngestRecord

pytestmark = pytest.mark.unit

_SARIF_OUTPUT_FLAG = "--sarif-file-output="


def _result(rule: str = "SnykRuleA") -> dict:
    return {
        "ruleId": rule,
        "level": "error",
        "message": {"text": f"{rule} was found"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "app.js"},
                    "region": {"startLine": 7},
                }
            }
        ],
    }


def _run(results) -> dict:
    return {
        "tool": {
            "driver": {
                "name": "SnykCode",
                "rules": [{"id": "SnykRuleA"}, {"id": "SnykRuleB"}],
            }
        },
        "results": results,
    }


def _noted(record: IngestRecord) -> list[tuple[str, str, str]]:
    """(action, code, pointer) of each element the record names."""
    summary = record.summary()
    if summary is None:
        return []
    return [(e["action"], e["code"], e["pointer"]) for e in summary["elements"]]


# --------------------------------------------------------------------------- #
# The count, on its own
# --------------------------------------------------------------------------- #


def test_a_results_field_that_is_a_string_counts_for_none_and_is_noted():
    """Two readable results and one run whose ``results`` is the text ``abc``: 2,
    not 5 (``len("abc")`` is 3, and the old count added it)."""
    record = IngestRecord()
    document = {"runs": [_run([_result(), _result("SnykRuleB")]), _run("abc")]}

    assert _sarif_result_count(document, record) == 2

    assert _noted(record) == [("dropped", "results_not_a_list", "runs/1/results")]


def test_a_results_field_that_is_an_object_counts_for_none_and_is_noted():
    """An object where the list belongs: 0, not the number of its keys."""
    record = IngestRecord()
    document = {"runs": [_run({"one": _result(), "two": _result("SnykRuleB")})]}

    assert _sarif_result_count(document, record) == 0

    assert _noted(record) == [("dropped", "results_not_a_list", "runs/0/results")]


@pytest.mark.parametrize(
    "runs",
    [
        pytest.param(5, id="number"),
        pytest.param(True, id="true"),
        pytest.param("abc", id="string"),
        pytest.param({"results": []}, id="object"),
    ],
)
def test_a_runs_field_that_is_not_a_list_counts_for_none_and_raises_nothing(runs):
    """``runs: 5`` and ``runs: true`` raised a TypeError out of the count; a string
    was walked one character at a time and an object one key at a time."""
    record = IngestRecord()

    assert _sarif_result_count({"runs": runs}, record) == 0

    assert _noted(record) == [("dropped", "runs_not_a_list", "runs")]


def test_a_run_that_is_not_an_object_counts_for_none_and_is_noted():
    record = IngestRecord()
    document = {"runs": [5, _run([_result()]), "abc", None]}

    assert _sarif_result_count(document, record) == 1

    assert _noted(record) == [
        ("dropped", "run_not_an_object", "runs/0"),
        ("dropped", "run_not_an_object", "runs/2"),
        ("dropped", "run_not_an_object", "runs/3"),
    ]


def test_only_a_result_that_is_an_object_counts():
    """A string, a number and ``null`` inside a ``results`` list are not results."""
    record = IngestRecord()
    document = {"runs": [_run([_result(), "abc", 3, None, [_result()]])]}

    assert _sarif_result_count(document, record) == 1

    assert record.summary() is None


def test_a_suppressed_result_counts_as_one():
    """The count is of what snyk reported, suppressed or not."""
    suppressed = _result()
    suppressed["suppressions"] = [{"kind": "external", "status": "accepted"}]

    assert _sarif_result_count({"runs": [_run([suppressed])]}) == 1


@pytest.mark.parametrize(
    "document",
    [
        pytest.param({}, id="empty-object"),
        pytest.param({"runs": None}, id="runs-null"),
        pytest.param({"runs": []}, id="runs-empty"),
        pytest.param({"runs": [_run(None)]}, id="results-null"),
        pytest.param({"runs": [_run([])]}, id="results-empty"),
        pytest.param({"version": "2.1.0"}, id="version-only"),
        pytest.param([], id="list"),
        pytest.param("abc", id="string"),
        pytest.param(None, id="null"),
        pytest.param(7, id="number"),
    ],
)
def test_what_holds_no_result_is_zero_and_notes_nothing(document):
    """Absent, null and empty containers are valid SARIF and say nothing; a document
    that is not an object is not read here at all (``ingest_sarif`` refuses it)."""
    record = IngestRecord()

    assert _sarif_result_count(document, record) == 0

    assert record.summary() is None


def test_the_count_works_without_a_record():
    """``record`` is optional: a caller that keeps none gets the same counts."""
    assert _sarif_result_count({"runs": [_run([_result()]), _run("abc")]}) == 1
    assert _sarif_result_count({"runs": 5}) == 0
    assert _sarif_result_count({"runs": [5]}) == 0


def test_the_notes_hold_no_value_from_the_report():
    """A container is named by where it sits. Its content, which can be a path or a
    secret the tool printed, is not copied into the record."""
    record = IngestRecord()
    planted = "planted-value-that-must-not-be-recorded"
    document = {"runs": [_run(planted), planted, {"results": [_result()]}]}

    _sarif_result_count(document, record)

    assert planted not in json.dumps(record.summary())


def _the_old_count(document):
    """The count as it was: ``len()`` of whatever sat where the list belongs."""
    if not isinstance(document, dict):
        return 0
    return sum(
        len(run.get("results") or [])
        for run in document.get("runs") or []
        if isinstance(run, dict)
    )


def test_the_control_the_old_count_gets_the_seed_cases_wrong():
    """The seed cases are red on the count as it was, and green on the new one. This
    runs the old count beside the new one so the cases cannot go green by a count
    that has stopped looking."""
    with_a_string = {"runs": [_run([_result(), _result("SnykRuleB")]), _run("abc")]}
    with_an_object = {"runs": [_run({"one": _result(), "two": _result("SnykRuleB")})]}

    assert _the_old_count(with_a_string) == 5
    assert _sarif_result_count(with_a_string) == 2
    assert _the_old_count(with_an_object) == 2
    assert _sarif_result_count(with_an_object) == 0
    for not_a_list in (5, True):
        with pytest.raises(TypeError):
            _the_old_count({"runs": not_a_list})
        assert _sarif_result_count({"runs": not_a_list}) == 0


# --------------------------------------------------------------------------- #
# The count in a scan
# --------------------------------------------------------------------------- #


@pytest.fixture
def snyk(tmp_path, monkeypatch) -> SnykCodeScanner:
    """A snyk-code scanner on a small tree, with the binary present and the process
    left to the test (the same two seams the scanner's other unit tests patch)."""
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


def _scan(scanner: SnykCodeScanner, document, exit_code: int):
    """Run scan() with a snyk that writes *document* where it is told to and exits
    with *exit_code*."""

    def run(self, command, **kwargs):
        destination = next(
            arg.split("=", 1)[1]
            for arg in command
            if arg.startswith(_SARIF_OUTPUT_FLAG)
        )
        Path(destination).write_text(json.dumps(document), encoding="utf-8")
        self.exit_code = max(self.exit_code or 0, exit_code)
        return {"stdout": "", "stderr": "", "returncode": exit_code}

    with patch.object(
        SnykCodeScanner, "_run_subprocess", autospec=True, side_effect=run
    ):
        return scanner.scan(target=scanner.context.source_dir, target_type="source")


@pytest.mark.parametrize(
    "document",
    [
        pytest.param({"version": "2.1.0", "runs": [_run("abc")]}, id="results-string"),
        pytest.param(
            {"version": "2.1.0", "runs": [_run({"one": _result(), "two": _result()})]},
            id="results-object",
        ),
        pytest.param({"version": "2.1.0", "runs": 5}, id="runs-number"),
        pytest.param({"version": "2.1.0", "runs": True}, id="runs-true"),
        pytest.param({"version": "2.1.0", "runs": [_run([])]}, id="results-empty"),
    ],
)
def test_exit_one_with_no_readable_result_still_holds_no_results(snyk, document):
    """The check keeps doing its work: snyk said it found issues and the file holds
    none ASH can read, so the scan is refused with that reason. A ``TypeError`` or a
    count of characters used to stand in for it."""
    with pytest.raises(ScannerError, match="holds no results"):
        _scan(snyk, document, exit_code=1)


def test_a_report_with_one_unreadable_container_is_refused_with_its_place_noted(snyk):
    """Two readable results and a run whose ``results`` is text pass the count (2)
    and are then refused by the reader, which cannot repair a field of the wrong
    type. The record says where the field sat."""
    document = {
        "version": "2.1.0",
        "runs": [_run([_result(), _result("SnykRuleB")]), _run("abc")],
    }

    with pytest.raises(ScannerError, match="not SARIF ASH can read"):
        _scan(snyk, document, exit_code=1)

    summary = snyk.output_ingest_record
    assert summary is not None
    assert summary["changes"] == [
        {"action": "dropped", "code": "results_not_a_list", "count": 1}
    ]
    assert [e["pointer"] for e in summary["elements"]] == ["runs/1/results"]


def test_exit_one_with_a_readable_result_is_a_completed_scan(snyk):
    """The count did not become stricter than the reader: one result is enough."""
    document = {"version": "2.1.0", "runs": [_run([_result()])]}

    report = _scan(snyk, document, exit_code=1)

    assert [r.ruleId for r in report.runs[0].results] == ["SnykRuleA"]
    assert snyk.output_ingest_record is None


# --------------------------------------------------------------------------- #
# The pass before the reader holds the same line
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "runs",
    [
        pytest.param(5, id="number"),
        pytest.param(True, id="true"),
        pytest.param("abc", id="string"),
        pytest.param({"results": []}, id="object"),
        pytest.param(None, id="null"),
    ],
)
def test_the_cwe_pass_leaves_a_document_whose_runs_is_not_a_list_as_it_came(runs):
    """``runs: 5`` raised a ``TypeError`` out of the pass that adds a rule's native CWE
    to its tags, before the reader could refuse the document with its own reason."""
    document = {"version": "2.1.0", "runs": runs}

    assert normalize_rule_cwe_into_tags(document) == {"version": "2.1.0", "runs": runs}


@pytest.mark.parametrize(
    "runs", [pytest.param(5, id="number"), pytest.param(True, id="true")]
)
def test_a_runs_field_that_is_not_a_list_is_refused_by_the_reader_with_its_reason(
    snyk, runs
):
    """Exit 0, so the count is not asked: the reader refuses the document and says
    so, where a ``TypeError`` from the CWE pass was logged as no result."""
    with pytest.raises(ScannerError, match="not SARIF ASH can read"):
        _scan(snyk, {"version": "2.1.0", "runs": runs}, exit_code=0)
