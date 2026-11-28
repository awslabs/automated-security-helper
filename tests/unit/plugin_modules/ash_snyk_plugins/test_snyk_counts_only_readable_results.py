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
and is not recorded: the count only counts, and what the reader repairs or refuses is
the reader's to note.
"""

from __future__ import annotations

import inspect
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


# --------------------------------------------------------------------------- #
# The count, on its own
# --------------------------------------------------------------------------- #


def test_a_results_field_that_is_a_string_counts_for_none():
    """Two readable results and one run whose ``results`` is the text ``abc``: 2,
    not 5 (``len("abc")`` is 3, and the old count added it)."""
    document = {"runs": [_run([_result(), _result("SnykRuleB")]), _run("abc")]}

    assert _sarif_result_count(document) == 2


def test_a_results_field_that_is_an_object_counts_for_none():
    """An object where the list belongs: 0, not the number of its keys."""
    document = {"runs": [_run({"one": _result(), "two": _result("SnykRuleB")})]}

    assert _sarif_result_count(document) == 0


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
    assert _sarif_result_count({"runs": runs}) == 0


def test_a_run_that_is_not_an_object_counts_for_none():
    document = {"runs": [5, _run([_result()]), "abc", None]}

    assert _sarif_result_count(document) == 1


def test_only_a_result_that_is_an_object_counts():
    """A string, a number and ``null`` inside a ``results`` list are not results."""
    document = {"runs": [_run([_result(), "abc", 3, None, [_result()]])]}

    assert _sarif_result_count(document) == 1


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
def test_what_holds_no_result_is_zero(document):
    """Absent, null and empty containers are valid SARIF and say nothing; a document
    that is not an object is not read here at all (``ingest_sarif`` refuses it)."""
    assert _sarif_result_count(document) == 0


def test_the_count_only_counts_and_takes_no_record():
    """What the reader repairs or refuses is the reader's to note. A count that also
    noted the shapes the reader cannot repair recorded drops that never happened."""
    assert list(inspect.signature(_sarif_result_count).parameters) == ["document"]


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


_NOT_SARIF = "not SARIF ASH can read"
_NO_RESULTS = "holds no results"


@pytest.mark.parametrize("exit_code", [0, 1])
@pytest.mark.parametrize(
    ("document", "refused_as"),
    [
        pytest.param(
            {"version": "2.1.0", "runs": [_run("abc")]}, _NOT_SARIF, id="results-string"
        ),
        pytest.param(
            {"version": "2.1.0", "runs": [_run({"one": _result(), "two": _result()})]},
            _NOT_SARIF,
            id="results-object",
        ),
        pytest.param({"version": "2.1.0", "runs": 5}, _NOT_SARIF, id="runs-number"),
        pytest.param({"version": "2.1.0", "runs": True}, _NOT_SARIF, id="runs-true"),
        pytest.param(
            {"version": "2.1.0", "runs": [_run([])]}, None, id="results-empty"
        ),
    ],
)
def test_a_document_the_reader_refuses_is_refused_as_that_at_either_exit_code(
    snyk, document, refused_as, exit_code
):
    """A shape the reader cannot read is refused as not SARIF, at exit 0 and at exit
    1 alike, and leaves nothing on the record. Only a document that reads and holds
    no result is refused by the exit-1 count; at exit 0 it is a clean scan."""
    if refused_as is None and exit_code == 0:
        report = _scan(snyk, document, exit_code=0)
        assert report.runs[0].results == []
        assert snyk.output_ingest_record is None
        return
    expected = refused_as or _NO_RESULTS
    with pytest.raises(ScannerError, match=expected):
        _scan(snyk, document, exit_code=exit_code)
    assert snyk.output_ingest_record is None


def _scan_the_bytes(scanner: SnykCodeScanner, written: bytes, exit_code: int):
    """scan() with a snyk that writes exactly *written* where it is told to."""

    def run(self, command, **kwargs):
        destination = next(
            arg.split("=", 1)[1]
            for arg in command
            if arg.startswith(_SARIF_OUTPUT_FLAG)
        )
        Path(destination).write_bytes(written)
        self.exit_code = max(self.exit_code or 0, exit_code)
        return {"stdout": "", "stderr": "", "returncode": exit_code}

    with patch.object(
        SnykCodeScanner, "_run_subprocess", autospec=True, side_effect=run
    ):
        return scanner.scan(target=scanner.context.source_dir, target_type="source")


@pytest.mark.parametrize("exit_code", [0, 1])
@pytest.mark.parametrize(
    "written",
    [b"", b"  \n", b"\xef\xbb\xbf", b"\xef\xbb\xbf \n"],
    ids=["empty", "blank", "bom-only", "bom-and-blank"],
)
def test_a_file_with_nothing_in_it_is_said_to_be_empty_and_notes_nothing(
    snyk, written, exit_code
):
    """A byte-order mark with nothing after it is an empty file, not a repair, and
    the refusal says the file was empty rather than that it was not SARIF."""
    with pytest.raises(ScannerError, match="results file is empty"):
        _scan_the_bytes(snyk, written, exit_code)

    assert snyk.output_ingest_record is None


def test_a_report_with_one_unreadable_container_is_refused_and_records_no_drop(snyk):
    """Two readable results and a run whose ``results`` is text are refused by the
    reader, which cannot repair a field of the wrong type. Nothing was dropped, so
    the record holds no drop, and no value from the report."""
    planted = "planted-value-that-must-not-be-recorded"
    document = {
        "version": "2.1.0",
        "runs": [_run([_result(), _result("SnykRuleB")]), _run(planted)],
    }

    with pytest.raises(ScannerError, match=_NOT_SARIF) as refused:
        _scan(snyk, document, exit_code=1)

    assert snyk.output_ingest_record is None
    assert planted not in str(refused.value)


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
