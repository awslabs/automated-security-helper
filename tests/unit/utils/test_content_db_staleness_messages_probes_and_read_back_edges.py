# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The staleness check never raises, names the right remedy, and loses no record.

Properties of ``utils/content_db_staleness.py`` that nothing else pins:

- a build time at the edge of datetime's range with a non-UTC offset is written
  without an OverflowError out of the "never raises" callers;
- a database an override entry holds to fail names that entry as the remedy,
  not the scan-wide setting that may already be warn;
- an override's reason is cleaned of terminal escapes before it is logged, and a
  probe's output quoted in an absence error is cleaned the same way;
- grype's absence is read before its build time, so a zero-time build time on a
  missing database is absent, not merely stale;
- trivy's missing UpdatedAt with a metadata file in the cache is unknown age,
  not absence;
- an offline rules directory holding the fetch-time manifest and no rules files
  is absent, and a manifest that is no timestamp is not quoted whole;
- a probe context of None is named in the unmeasurable record;
- one record whose notification cannot be built does not keep the others out of
  the report;
- a stale record that does not parse back still fails the scan.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from automated_security_helper.utils import content_db_staleness as staleness
from automated_security_helper.utils.content_databases import (
    STALENESS_FAIL,
    get,
)

pytestmark = pytest.mark.unit

#: trivy's probe as the module defines it, read at import, before the autouse
#: unit tool guard replaces the module attribute for each test.
_REAL_TRIVY_PROBE = staleness._built_from_trivy

NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def _record(**overrides) -> staleness.ContentDbAgeRecord:
    values = {
        "name": "grype-db",
        "scanner": "grype",
        "built": NOW - timedelta(days=10),
        "measured_by": "a probe",
        "max_age": timedelta(hours=120),
        "measured_at": NOW,
        "policy": STALENESS_FAIL,
        "bound_source": "the test",
        "bound_is_tool_default": True,
        "refresh": "run the refresh",
    }
    values.update(overrides)
    return staleness.ContentDbAgeRecord(**values)


def test_a_time_at_the_edge_of_the_range_is_written_without_raising():
    edge = datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone(timedelta(hours=-1)))
    assert staleness._iso(edge).startswith("9999-12-31T23:59:59")
    record = _record(built=edge)
    # message() quotes the time: the "never raises" callers print it.
    assert "9999-12-31T23:59:59" in record.message()


def test_a_database_held_to_fail_by_an_override_names_the_entry_as_the_remedy():
    source = "content_db_staleness_overrides entry for grype-db, which expires at X"
    message = _record(policy_source=source).message()
    assert "content_db_staleness: warn" not in message
    assert "held to fail by the " + source in message
    # The flag outranks every override entry for its scan, so it stays a remedy.
    assert "--allow-stale-content-db" in message
    # The control: without an override the scan-wide hint stands.
    assert "content_db_staleness: warn" in _record().message()


def test_an_overrides_reason_is_cleaned_before_it_is_logged(caplog):
    override = SimpleNamespace(
        database="grype-db",
        policy="warn",
        reason="see \x1b[2J\x1b[31mthe ticket\x1b[0m\x07",
        expires_at=NOW + timedelta(days=1),
        is_expired=lambda now: False,
    )
    with caplog.at_level(logging.INFO):
        chosen, _ = staleness._policy_for(
            get("grype-db"), STALENESS_FAIL, [override], NOW
        )
    assert chosen == "warn"
    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert "the ticket" in logged
    assert "\x1b" not in logged and "\x07" not in logged


def _grype_context(monkeypatch, status):
    monkeypatch.setattr(staleness, "_run_json", lambda *args, **kwargs: status)
    return staleness.ProbeContext(env={}, executable="/bin/grype", values=())


def test_grype_reads_absence_before_the_build_time(monkeypatch):
    status = {
        "built": "0001-01-01T00:00:00Z",
        "error": "the database does not exist",
        "path": "/no/such/db",
    }
    with pytest.raises(staleness.ContentDatabaseAbsent):
        staleness._built_from_grype(_grype_context(monkeypatch, status))


def test_grype_reads_a_zero_time_as_no_build_time(monkeypatch, tmp_path):
    """The unset time value is a non-empty string, so it passed the checks of a
    build time: a database that is missing, with an error lacking the exact words
    "does not exist", was graded stale (a grade that warn relaxes) instead of absent."""
    zero = "0001-01-01T00:00:00Z"
    missing = {"built": zero, "error": "", "path": str(tmp_path / "no" / "db")}
    with pytest.raises(staleness.ContentDatabaseAbsent):
        staleness._built_from_grype(_grype_context(monkeypatch, missing))
    # A zero time beside a path that exists is a database of unknown age.
    present = {"built": zero, "error": "", "path": str(tmp_path)}
    with pytest.raises(ValueError) as raised:
        staleness._built_from_grype(_grype_context(monkeypatch, present))
    assert not isinstance(raised.value, staleness.ContentDatabaseAbsent)
    # The control: a real build time with a path this process cannot see is a
    # build time, as before.
    real = {"built": "2026-10-01T00:00:00Z", "path": "/no/such/db"}
    built, _ = staleness._built_from_grype(_grype_context(monkeypatch, real))
    assert built.year == 2026


def test_grypes_output_quoted_in_an_absence_error_has_no_control_characters(
    monkeypatch,
):
    status = {"error": "x\x1b[2Jdoes not exist\x07", "path": "/no/such/db"}
    with pytest.raises(staleness.ContentDatabaseAbsent) as raised:
        staleness._built_from_grype(_grype_context(monkeypatch, status))
    assert "\x1b" not in str(raised.value) and "\x07" not in str(raised.value)
    assert "does not exist" in str(raised.value)


def test_trivy_with_a_metadata_file_but_no_updated_at_is_unknown_age(
    monkeypatch, tmp_path
):
    (tmp_path / "db").mkdir()
    (tmp_path / "db" / "metadata.json").write_text("{", encoding="utf-8")
    monkeypatch.setattr(staleness, "_run_json", lambda *args, **kwargs: {})
    ctx = staleness.ProbeContext(
        env={}, executable="/bin/trivy", cache_dir=str(tmp_path), values=()
    )
    # The probe as written, not the stand-in the unit tool guard puts on the
    # module for every test (tests/utils/tool_guard.py): this test reads the
    # probe's own answers, with its one command stubbed above.
    probe = _REAL_TRIVY_PROBE
    with pytest.raises(ValueError) as raised:
        probe(ctx)
    assert not isinstance(raised.value, staleness.ContentDatabaseAbsent)
    # The control: with no metadata file the database is absent.
    (tmp_path / "db" / "metadata.json").unlink()
    with pytest.raises(staleness.ContentDatabaseAbsent):
        probe(ctx)


def test_a_rules_directory_with_a_manifest_and_no_rules_is_absent(tmp_path):
    (tmp_path / staleness.RULESET_FETCHED_AT_FILE).write_text(
        "2026-01-01T00:00:00Z", encoding="utf-8"
    )
    ctx = staleness.ProbeContext(env={}, cache_dir=str(tmp_path))
    with pytest.raises(staleness.ContentDatabaseAbsent):
        staleness._built_from_ruleset_dir(ctx)


def test_a_manifest_that_is_no_timestamp_is_not_quoted_whole(tmp_path):
    (tmp_path / "rule.yml").write_text("rules: []\n", encoding="utf-8")
    junk = "x" * 500
    (tmp_path / staleness.RULESET_FETCHED_AT_FILE).write_text(junk, encoding="utf-8")
    ctx = staleness.ProbeContext(env={}, cache_dir=str(tmp_path))
    with pytest.raises(ValueError) as raised:
        staleness._built_from_ruleset_dir(ctx)
    assert junk not in str(raised.value)
    assert len(str(raised.value)) < 200


def test_a_probe_context_of_none_is_named_in_the_record():
    scanner = SimpleNamespace(
        config=SimpleNamespace(name="grype"),
        content_databases_in_use=lambda: [get("grype-db")],
        content_database_probe_context=lambda: None,
    )
    report = SimpleNamespace(runs=[])
    records = staleness.assess_scanner(scanner, report, STALENESS_FAIL, now=NOW)
    assert len(records) == 1
    assert records[0].stale is True
    assert "returned None" in (records[0].error or "")


def test_one_record_that_cannot_be_rendered_does_not_drop_the_others(monkeypatch):
    real = staleness._notification

    def failing_for_trivy(record):
        if record.name == "trivy-db":
            raise RuntimeError("cannot build this one")
        return real(record)

    monkeypatch.setattr(staleness, "_notification", failing_for_trivy)
    report = SimpleNamespace(runs=[])
    records = [_record(), _record(name="trivy-db", scanner="trivy-repo")]
    with pytest.raises(RuntimeError):
        staleness.attach_records(report, records)
    invocation = report.runs[0].invocations[0]
    attached = invocation.toolConfigurationNotifications
    assert len(attached) == 1
    recorded = attached[0].properties.model_extra["content_database"]
    assert recorded["name"] == "grype-db"


def test_a_stale_record_that_does_not_parse_back_still_fails_the_scan():
    descriptor = SimpleNamespace(
        root=SimpleNamespace(id=staleness.STALE_NOTIFICATION_ID)
    )
    notification = SimpleNamespace(
        descriptor=descriptor,
        level="error",
        timeUtc=NOW,
        properties={
            "content_database": {
                "name": "grype-db",
                "scanner": "grype",
                "measured_at": "not a timestamp",
            }
        },
    )
    results = SimpleNamespace(
        sarif=SimpleNamespace(
            runs=[
                SimpleNamespace(
                    invocations=[
                        SimpleNamespace(toolConfigurationNotifications=[notification])
                    ]
                )
            ]
        )
    )
    enforced = staleness.stale_content_databases(results, enforced_only=True)
    assert [(record.name, record.scanner) for record in enforced] == [
        ("grype-db", "grype")
    ]
    assert enforced[0].stale is True
    assert "could not be read back" in (enforced[0].error or "")
