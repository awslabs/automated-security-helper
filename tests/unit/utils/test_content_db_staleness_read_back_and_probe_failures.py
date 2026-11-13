# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Staleness records keep their decision on read-back, and a probe failure grades only
the databases the scan read.

Properties of utils/content_db_staleness.py pinned here:

- a record read back from a results file keeps the ``stale`` the scan decided,
  whatever bound this ASH declares for the database and however the second-truncated
  timestamps compare;
- a build time before year 1000 (Go's zero time) round-trips through the record;
- when the scanner says it read no database, a failure to build the probe context
  grades nothing; when it read some, only those are graded, and a record of that
  failure is unmeasured, not absent, so the policy still decides;
- a scanner in ERROR for a stale database AND another cause (a tool that could not
  be stopped, a timeout, an unevaluated target) is not read as "ERROR only for its
  stale database".
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from automated_security_helper.schemas.sarif_schema_model import (
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils import content_db_staleness as staleness
from automated_security_helper.utils.content_databases import (
    CONTENT_DATABASES,
    STALENESS_FAIL,
)

pytestmark = pytest.mark.unit

_NOW = datetime(2026, 10, 29, 12, 0, 0, tzinfo=timezone.utc)


def _entry(name: str):
    return next(entry for entry in CONTENT_DATABASES if entry.name == name)


def _record(name="grype-db", scanner="grype", *, built, max_age, measured_at=_NOW):
    return staleness.ContentDbAgeRecord(
        name=name,
        scanner=scanner,
        built=built,
        measured_by="a test",
        max_age=max_age,
        measured_at=measured_at,
        policy=STALENESS_FAIL,
        bound_source="a test",
        bound_is_tool_default=False,
        refresh="refresh it",
    )


def _sarif(driver: str) -> SarifReport:
    return SarifReport(
        version="2.1.0",
        runs=[Run(tool=Tool(driver=ToolComponent(name=driver)), results=[])],
    )


def test_a_record_stale_under_a_narrower_recorded_bound_reads_back_stale():
    # Recorded under a one-hour bound, two hours old: stale when written. The
    # registry's bound for the same name is wider, and must not relax it on read.
    record = _record(built=_NOW - timedelta(hours=2), max_age=timedelta(hours=1))
    assert record.stale
    assert _entry("grype-db").max_age > timedelta(hours=2)
    read_back = staleness.ContentDbAgeRecord.from_dict(record.to_dict())
    assert read_back.stale is True
    assert read_back.enforced is True


def test_a_record_stale_by_a_fraction_of_a_second_reads_back_stale():
    bound = timedelta(hours=1)
    built = _NOW - bound - timedelta(milliseconds=500)
    record = _record(built=built, max_age=bound)
    assert record.stale
    read_back = staleness.ContentDbAgeRecord.from_dict(record.to_dict())
    assert read_back.stale is True


def test_a_record_written_before_the_verdict_was_recorded_is_measured_again():
    record = _record(built=_NOW - timedelta(hours=2), max_age=timedelta(hours=1))
    data = record.to_dict()
    del data["stale"]
    read_back = staleness.ContentDbAgeRecord.from_dict(data)
    assert read_back.recorded_stale is None
    assert read_back.stale is True


def test_a_build_time_before_year_1000_round_trips():
    zero_time = datetime(1, 1, 1, tzinfo=timezone.utc)
    record = _record(built=zero_time, max_age=timedelta(days=1))
    data = record.to_dict()
    assert data["built"] == "0001-01-01T00:00:00Z"
    assert staleness.ContentDbAgeRecord.from_dict(data).built == zero_time


class _Scanner:
    def __init__(self, name, entries, probe_error):
        self.config = SimpleNamespace(name=name)
        self._entries = entries
        self._probe_error = probe_error

    def content_databases_in_use(self):
        return list(self._entries)

    def content_database_probe_context(self):
        raise self._probe_error


def test_a_scan_that_read_no_database_is_graded_against_none_when_the_probe_fails():
    scanner = _Scanner("semgrep", [], RuntimeError("no context"))
    records = staleness.assess_scanner(scanner, _sarif("semgrep"), STALENESS_FAIL)
    assert records == []


def test_a_probe_failure_grades_only_the_databases_the_scan_read_as_unmeasured():
    entry = _entry("semgrep-offline-rules")
    scanner = _Scanner("semgrep", [entry], RuntimeError("no context"))
    records = staleness.assess_scanner(
        scanner, _sarif("semgrep"), STALENESS_FAIL, now=_NOW
    )
    assert [record.name for record in records] == [entry.name]
    (record,) = records
    assert record.built is None
    assert record.stale is True
    assert record.absent is False
    assert "no context" in (record.error or "")


def test_a_probe_failure_runs_no_measurer(monkeypatch):
    # The record of a database the scanner could not describe is built without a
    # probe: measuring a fabricated empty context ran a real measurer against
    # nothing and then overwrote its answer. A call of measure here is the defect.
    def _no_probe(*args, **kwargs):
        raise AssertionError(
            "a measurer ran for a database the scanner could not describe"
        )

    monkeypatch.setattr(staleness, "measure", _no_probe)
    entry = _entry("semgrep-offline-rules")
    scanner = _Scanner("semgrep", [entry], RuntimeError("no context"))
    records = staleness.assess_scanner(
        scanner, _sarif("semgrep"), STALENESS_FAIL, now=_NOW
    )
    (record,) = records
    assert record.built is None
    assert record.absent is False
    assert record.measured_by == entry.age_source
    assert record.scanner == "semgrep"
    assert record.stale is True


def _results_with_stale_grype(reports):
    sarif = _sarif("grype")
    record = _record(built=_NOW - timedelta(days=30), max_age=timedelta(days=1))
    staleness.attach_records(sarif, [record])
    return SimpleNamespace(sarif=sarif, additional_reports={"grype": reports})


def _report(errors, **extra):
    return {
        "status": "ERROR",
        "rejected_content_databases": ["grype-db"],
        "errors": list(errors),
        **extra,
    }


def test_an_error_for_the_stale_database_alone_counts_as_having_run():
    results = _results_with_stale_grype({"source": _report(["grype-db is stale"])})
    assert staleness.scanners_in_error_for_a_stale_database(results) == {"grype"}


def test_an_error_that_also_carries_a_timeout_line_stays_incomplete():
    results = _results_with_stale_grype(
        {"source": _report(["grype-db is stale", "grype timed out after 30s"])}
    )
    assert staleness.scanners_in_error_for_a_stale_database(results) == set()


def test_an_error_whose_tool_could_not_be_stopped_stays_incomplete():
    results = _results_with_stale_grype(
        {"source": _report(["grype-db is stale"], could_not_stop="a tool, pid 1")}
    )
    assert staleness.scanners_in_error_for_a_stale_database(results) == set()


def test_a_read_back_record_keeps_the_age_the_scan_measured():
    """The file carries timestamps to the second and the age in whole seconds. An
    age recomputed from the timestamps can differ from the scan's by a second (here
    the fractions push the difference up by one), so the message and the decision
    disagreed at the bound; the read-back record carries the scan's own age."""
    built = datetime(2026, 10, 29, 10, 0, 0, 900000, tzinfo=timezone.utc)
    measured_at = datetime(2026, 10, 29, 12, 0, 0, 100000, tzinfo=timezone.utc)
    record = _record(built=built, max_age=timedelta(hours=1), measured_at=measured_at)
    data = record.to_dict()
    assert data["age_seconds"] == 7199
    read_back = staleness.ContentDbAgeRecord.from_dict(data)
    assert read_back.age == timedelta(seconds=7199)
    assert read_back.recorded_age_seconds == 7199
    # The hour the message prints is the scan's ("1h"), not the recomputed "2h".
    assert staleness.format_age(read_back.age) == data["age"]
