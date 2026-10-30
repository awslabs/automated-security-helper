# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan against a content database past its declared bound fails by default.

Why this file exists
--------------------
Measured with real grype v0.111.0 under ASH's offline settings, a vulnerability database built
10 days earlier scanned with exit 0 and no warning; trivy's ``--skip-db-update`` and the
offline semgrep/opengrep rulesets behaved the same way. ``utils/content_db_staleness.py``
now reads each database's own build time after its scanner runs and holds it to the bound in
``utils/content_databases.py``. These tests hold:

* every declared database has a bound, a cited source for it, a refresh procedure and a way
  to read its age; every scanner with an offline cache is either declared or listed as
  reading no database, so a new database-reading scanner cannot arrive unbounded;
* for each database type, a stale fixture fails the scan by default, passes with the opt-out
  while the warning appears in the SARIF, the markdown and text summaries and the flat JSON,
  and a fresh fixture passes with no warning;
* the offline grype case end to end through ``GrypeScanner`` and the scanner executor, with
  a fake grype that answers ``db status`` with the JSON grype v0.111.0 prints;
* the flag via the CLI and via config, and that the CLI wins.

The fake tools are faithful to what the real ones print. The grype payload is the shape
``grype db status -o json`` printed at v0.111.0 for a database rewritten to be built 10
days ago, including the non-zero exit it uses for a database past grype's own bound; the
trivy payload is ``trivy version --format json`` at v0.69.3 against a month-old database.
Each fake is a Python script behind the launcher a real install leaves on PATH: an
executable file on POSIX, a ``.cmd`` shim on Windows, where a shebang script cannot be
started. They are not skipped on any platform.
"""

from __future__ import annotations

import json
import os
import platform
import re
import stat
import sys
import typing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.config.resolve_config import apply_config_overrides
from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    _compute_exit_code,
    incomplete_scanners,
    unevaluated_rules,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import (
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils import content_databases as cdb
from automated_security_helper.utils import content_db_staleness as staleness


@pytest.mark.unit
def test_a_probes_stderr_excerpt_hides_a_value_straddling_its_cut(monkeypatch):
    """A status probe's stderr is redacted BEFORE the 300-character cut.

    The 292 filler characters put the cut inside the value: cut first, the
    error would keep the fragment ``EDGE-SEC``, which the downstream
    whole-spelling redaction cannot match.
    """
    from types import SimpleNamespace

    value = "EDGE-SECRET-3317"

    def _probe(command, **kwargs):
        return SimpleNamespace(
            returncode=1, stdout="", stderr="s" * 292 + value + " tail"
        )

    monkeypatch.setattr(staleness, "spawn_run", _probe)

    with pytest.raises(ValueError) as raised:
        staleness._run_json(
            ["grype", "db", "status", "-o", "json"],
            {},
            ctx=staleness.ProbeContext(env={}, values=(value,)),
        )

    message = str(raised.value)
    assert "printed nothing" in message, message
    assert value not in message, message
    assert "EDGE-SEC" not in message, message


UTC = timezone.utc
REPO_ROOT = Path(__file__).resolve().parents[3]
_MODULE = "automated_security_helper.interactions.run_ash_scan"


# --------------------------------------------------------------------------- fake tools


def _executable(bin_dir: Path, name: str, source: str) -> Path:
    """Install a fake ``name`` in ``bin_dir`` that runs ``source`` with this interpreter.

    The behaviour lives in a Python script so that it is the same program on every
    platform; what differs is the launcher, which is shaped like the one a real install
    would leave on PATH. On POSIX that is an executable file named ``name``. On Windows a
    shebang script cannot be started at all -- ``CreateProcess`` rejects it with
    ``[WinError 193] %1 is not a valid Win32 application`` -- so the launcher is a
    ``name.cmd`` shim, the same form npm installs. ``find_executable`` tries ``.exe``,
    ``.bat`` and ``.cmd`` before the bare name on Windows, and ``subprocess.run`` with a
    list starts a ``.cmd`` directly, so the scanner's own lookup and invocation are the
    ones under test rather than a patched-out subprocess call.

    Returns the launcher's path, which is what a scanner's ``find_executable`` would return.
    """
    script = bin_dir / f"_fake_{name}.py"
    script.write_text(source, encoding="utf-8")
    if platform.system().lower() == "windows":
        launcher = bin_dir / f"{name}.cmd"
        launcher.write_text(f'@"{sys.executable}" "{script}" %*\n', encoding="utf-8")
        return launcher
    launcher = bin_dir / name
    launcher.write_text(
        f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n', encoding="utf-8"
    )
    launcher.chmod(launcher.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return launcher


def _ts(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def fake_grype(bin_dir: Path, built: datetime) -> Path:
    """``grype`` answering ``db status -o json`` like v0.111.0, and writing an empty SARIF.

    Past grype's own bound, the real status command prints the JSON with ``valid: false``
    and an error, and exits 1. The measurement must read ``built`` regardless.
    """
    stale = datetime.now(UTC) - built > cdb.get("grype-db").max_age
    status = {
        "schemaVersion": "v6.1.9",
        "from": "https://grype.anchore.io/databases/v6/vulnerability-db_v6.1.9.tar.zst",
        "built": _ts(built),
        "path": "/deps/.grype/6/vulnerability.db",
        "valid": not stale,
    }
    if stale:
        status["error"] = (
            "the vulnerability database was built 1 week ago (max allowed age is 5 days)"
        )
    sarif = {
        "version": "2.1.0",
        "runs": [
            {"tool": {"driver": {"name": "grype", "version": "0.111.0"}}, "results": []}
        ],
    }
    return _executable(
        bin_dir,
        "grype",
        "import sys\n"
        "args = sys.argv[1:]\n"
        'if args[:2] == ["db", "status"]:\n'
        f"    print({json.dumps(status)!r})\n"
        f"    sys.exit({1 if stale else 0})\n"
        'if args[:1] == ["version"]:\n'
        '    print("Version: 0.111.0")\n'
        "    sys.exit(0)\n"
        'out = ""\n'
        "for i, arg in enumerate(args):\n"
        '    if arg == "--file" and i + 1 < len(args):\n'
        "        out = args[i + 1]\n"
        'with open(out, "w", encoding="utf-8") as f:\n'
        f"    f.write({json.dumps(sarif)!r})\n",
    )


def fake_trivy(bin_dir: Path, updated: datetime | None) -> Path:
    """``trivy version --format json`` like v0.69.3; no VulnerabilityDB when none is cached."""
    payload: dict = {"Version": "0.69.3"}
    if updated is not None:
        payload["VulnerabilityDB"] = {
            "Version": 2,
            "NextUpdate": _ts(updated + cdb.get("trivy-db").max_age),
            "UpdatedAt": _ts(updated),
            "DownloadedAt": _ts(updated + timedelta(hours=6)),
        }
    return _executable(bin_dir, "trivy", f"print({json.dumps(payload)!r})\n")


def ruleset_dir(root: Path, fetched: datetime | None, mtime: datetime | None = None):
    root.mkdir(parents=True, exist_ok=True)
    rules = root / "ci.yml"
    rules.write_text("rules: []\n", encoding="utf-8")
    if mtime is not None:
        os.utime(rules, (mtime.timestamp(), mtime.timestamp()))
    if fetched is not None:
        (root / cdb.RULESET_FETCHED_AT_FILE).write_text(_ts(fetched) + "\n")
    return root


# --------------------------------------------------------------------------- a stub scanner


class StubScanner:
    """The two hooks the assessment calls, and nothing else a mock could fake past."""

    def __init__(self, name: str, ctx: staleness.ProbeContext, entries=None):
        self.config = type("Config", (), {"name": name})()
        self._ctx = ctx
        self._entries = entries

    def content_databases_in_use(self):
        if self._entries is not None:
            return self._entries
        return [e for e in cdb.CONTENT_DATABASES if self.config.name in e.readers]

    def content_database_probe_context(self):
        return self._ctx


def _sarif(driver: str) -> SarifReport:
    return SarifReport(
        version="2.1.0",
        runs=[Run(tool=Tool(driver=ToolComponent(name=driver)), results=[])],
    )


def _model(sarif: SarifReport) -> AshAggregatedResults:
    model = AshAggregatedResults(ash_config=get_default_config())
    model.sarif = sarif
    return model


def _aggregate(*reports: SarifReport) -> AshAggregatedResults:
    """Merge the way the scan phase does: into the aggregate's own seeded ASH run."""
    model = AshAggregatedResults(ash_config=get_default_config())
    for report in reports:
        model.sarif.merge_sarif_report(report)
    return model


def _notifications(sarif_json: str) -> list:
    doc = json.loads(sarif_json)
    return [
        note
        for run in doc.get("runs") or []
        for inv in run.get("invocations") or []
        for note in inv.get("toolConfigurationNotifications") or []
    ]


def _exit_code(tmp_path: Path, model: AshAggregatedResults, **opt_kwargs) -> int:
    opts = ScanOptions(
        source_dir=tmp_path / "src", output_dir=tmp_path / "out", **opt_kwargs
    )
    with patch(f"{_MODULE}.get_unified_scanner_metrics", return_value=[]):
        return _compute_exit_code(model, opts)


def _reports(model: AshAggregatedResults) -> dict[str, str]:
    """Every report this change writes the fact into, rendered from the model."""
    from automated_security_helper.plugin_modules.ash_builtin.reporters.flatjson_reporter import (
        FlatJSONReporter,
    )
    from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
        MarkdownReporter,
    )
    from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
        TextReporter,
    )
    from automated_security_helper.base.plugin_context import PluginContext

    ctx = PluginContext(
        source_dir=Path("."), output_dir=Path("."), config=get_default_config()
    )
    return {
        "sarif": model.sarif.model_dump_json(by_alias=True, exclude_none=True),
        "markdown": MarkdownReporter(context=ctx).report(model),
        "text": TextReporter(context=ctx).report(model),
        "flat": FlatJSONReporter(context=ctx).report(model),
    }


# --------------------------------------------------------------------------- per database


def _grype_case(bin_dir: Path, age: timedelta):
    exe = fake_grype(bin_dir, datetime.now(UTC) - age)
    return StubScanner(
        "grype", staleness.ProbeContext(env=dict(os.environ), executable=str(exe))
    )


def _trivy_case(bin_dir: Path, age: timedelta):
    exe = fake_trivy(bin_dir, datetime.now(UTC) - age)
    return StubScanner(
        "trivy-repo", staleness.ProbeContext(env=dict(os.environ), executable=str(exe))
    )


def _ruleset_case(scanner: str):
    def make(bin_dir: Path, age: timedelta):
        cache = ruleset_dir(bin_dir / f"{scanner}-rules", datetime.now(UTC) - age)
        return StubScanner(
            scanner, staleness.ProbeContext(env={}, cache_dir=str(cache))
        )

    return make


CASES = {
    "grype-db": _grype_case,
    "trivy-db": _trivy_case,
    "semgrep-offline-rules": _ruleset_case("semgrep"),
    "opengrep-offline-rules": _ruleset_case("opengrep"),
}
# The one place a case's tier is written. CASES and CASE_TIERS are two dicts
# because the suite's static tier check follows `marks=CASE_TIERS[name]` only over
# a dict literal of marks; the assertion below names a case one of them lacks
# instead of letting a bare KeyError error the module's collection.
CASE_TIERS = {
    "grype-db": pytest.mark.integration,
    "trivy-db": pytest.mark.integration,
    "semgrep-offline-rules": pytest.mark.unit,
    "opengrep-offline-rules": pytest.mark.unit,
}
assert CASES.keys() == CASE_TIERS.keys(), (
    "every database case needs a factory in CASES and a tier in CASE_TIERS",
    sorted(CASES.keys() ^ CASE_TIERS.keys()),
)
TIERED_CASES = [pytest.param(name, marks=CASE_TIERS[name]) for name in sorted(CASES)]
# Every case but trivy-db, whose offline default is the subject of
# TestTheOfflineImageDefault; the tiers come from CASE_TIERS, not a second list.
_EVERY_OTHER_DATABASE = sorted(set(CASES) - {"trivy-db"})
EVERY_OTHER_TIERED_CASE = [
    pytest.param(name, marks=CASE_TIERS[name]) for name in _EVERY_OTHER_DATABASE
]


def _over(name: str) -> timedelta:
    return cdb.get(name).max_age + timedelta(hours=1)


def _under(name: str) -> timedelta:
    return cdb.get(name).max_age - timedelta(hours=1)


@pytest.mark.parametrize("name", TIERED_CASES)
class TestEachDatabaseType:
    def test_stale_fails_the_scan_by_default(self, tmp_path, name):
        scanner = CASES[name](tmp_path, _over(name))
        sarif = _sarif(scanner.config.name)
        records = staleness.assess_scanner(scanner, sarif, cdb.DEFAULT_STALENESS_POLICY)
        assert [r.name for r in records] == [name]
        assert records[0].stale and records[0].enforced

        model = _model(sarif)
        assert _exit_code(tmp_path, model) == 1
        # Ahead of findings-gating, like the unevaluated-rule gate.
        assert _exit_code(tmp_path, model, fail_on_findings=False) == 1
        message = records[0].message()
        for part in (
            name,
            records[0].timestamp_label,
            staleness.format_age(records[0].age),
            cdb.go_duration(cdb.get(name).max_age),
            "--allow-stale-content-db",
            "To refresh it",
        ):
            assert part in message, (part, message)

    def test_stale_passes_under_warn_with_the_warning_in_every_report(
        self, tmp_path, name
    ):
        scanner = CASES[name](tmp_path, _over(name))
        sarif = _sarif(scanner.config.name)
        staleness.assess_scanner(scanner, sarif, cdb.STALENESS_WARN)
        model = _model(sarif)
        assert _exit_code(tmp_path, model) == 0

        reports = _reports(model)
        notes = _notifications(reports["sarif"])
        assert [n["level"] for n in notes] == ["warning"]
        assert notes[0]["descriptor"]["id"] == staleness.STALE_NOTIFICATION_ID
        assert "### Stale content databases" in reports["markdown"]
        assert name in reports["markdown"].split("### Stale content databases", 1)[1]
        assert "STALE CONTENT DATABASES" in reports["text"]
        assert "[WARNING]" in reports["text"]
        flat = json.loads(reports["flat"])["content_databases"]
        assert [(d["name"], d["stale"], d["enforced"], d["policy"]) for d in flat] == [
            (name, True, False, "warn")
        ]

    def test_fresh_passes_with_no_warning(self, tmp_path, name):
        scanner = CASES[name](tmp_path, _under(name))
        sarif = _sarif(scanner.config.name)
        records = staleness.assess_scanner(scanner, sarif, cdb.DEFAULT_STALENESS_POLICY)
        assert records and not records[0].stale
        model = _model(sarif)
        assert _exit_code(tmp_path, model) == 0
        assert staleness.stale_content_databases(model) == []
        reports = _reports(model)
        assert _notifications(reports["sarif"]) == []
        assert "Stale content databases" not in reports["markdown"]
        assert "STALE CONTENT DATABASES" not in reports["text"]
        flat = json.loads(reports["flat"])["content_databases"]
        assert [(d["name"], d["stale"]) for d in flat] == [(name, False)]


# --------------------------------------------------------------------------- measurement


class TestMeasurement:
    @pytest.mark.integration
    def test_grype_built_is_read_even_when_grype_exits_nonzero(self, tmp_path):
        built = datetime.now(UTC) - timedelta(days=10)
        exe = fake_grype(tmp_path, built)
        record = staleness.measure(
            cdb.get("grype-db"),
            staleness.ProbeContext(env=dict(os.environ), executable=str(exe)),
            cdb.STALENESS_FAIL,
        )
        assert record.error is None
        assert record.built == built.replace(microsecond=0)
        assert "grype db status" in record.measured_by

    @pytest.mark.integration
    def test_trivy_without_a_database_is_absent_and_counts_as_stale(self, tmp_path):
        """No database at all is more than an unread age: the record says absent."""
        exe = fake_trivy(tmp_path, None)
        record = staleness.measure(
            cdb.get("trivy-db"),
            staleness.ProbeContext(env=dict(os.environ), executable=str(exe)),
            cdb.STALENESS_FAIL,
        )
        assert record.built is None and record.stale and record.enforced
        assert record.absent
        assert "does not exist" in record.message()
        assert staleness.ContentDbAgeRecord.from_dict(record.to_dict()).absent

    @pytest.mark.integration
    def test_grype_reporting_no_database_is_absent(self, tmp_path):
        status = {
            "schemaVersion": "",
            "path": str(tmp_path / "cache" / "6" / "vulnerability.db"),
            "valid": False,
            "error": "database does not exist",
        }
        exe = _executable(
            tmp_path,
            "grype",
            f"import sys\nprint({json.dumps(status)!r})\nsys.exit(1)\n",
        )
        record = staleness.measure(
            cdb.get("grype-db"),
            staleness.ProbeContext(env=dict(os.environ), executable=str(exe)),
            cdb.STALENESS_WARN,
        )
        assert record.absent and record.stale
        assert "does not exist" in record.message()

    @pytest.mark.integration
    def test_a_database_grype_cannot_date_but_that_exists_is_not_absent(self, tmp_path):
        """Unreadable is stale, not absent: the file is there and grype says why not."""
        database = tmp_path / "cache" / "6" / "vulnerability.db"
        database.parent.mkdir(parents=True)
        database.write_bytes(b"not sqlite")
        status = {
            "schemaVersion": "",
            "path": str(database),
            "valid": False,
            "error": "unable to open database: file is not a database",
        }
        exe = _executable(
            tmp_path,
            "grype",
            f"import sys\nprint({json.dumps(status)!r})\nsys.exit(1)\n",
        )
        record = staleness.measure(
            cdb.get("grype-db"),
            staleness.ProbeContext(env=dict(os.environ), executable=str(exe)),
            cdb.STALENESS_WARN,
        )
        assert record.stale and not record.absent
        assert "absent" not in record.to_dict()

    @pytest.mark.unit
    def test_a_missing_executable_is_unknown_not_fresh(self):
        record = staleness.measure(
            cdb.get("grype-db"),
            staleness.ProbeContext(env={}, executable=None),
            cdb.STALENESS_FAIL,
        )
        assert record.stale and "not found" in (record.error or "")

    @pytest.mark.integration
    def test_grype_reporting_a_database_path_that_does_not_exist_is_absent(
        self, tmp_path
    ):
        """No build time, an error that does not say so, and no file at the path."""
        status = {
            "schemaVersion": "",
            "path": str(tmp_path / "cache" / "6" / "vulnerability.db"),
            "valid": False,
            "error": "unable to load the database",
        }
        exe = _executable(
            tmp_path,
            "grype",
            f"import sys\nprint({json.dumps(status)!r})\nsys.exit(1)\n",
        )
        record = staleness.measure(
            cdb.get("grype-db"),
            staleness.ProbeContext(env=dict(os.environ), executable=str(exe)),
            cdb.STALENESS_WARN,
        )
        assert record.absent, record.error

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "name", ["semgrep-offline-rules", "opengrep-offline-rules"]
    )
    def test_a_ruleset_with_no_directory_configured_is_absent(self, name):
        record = staleness.measure(
            cdb.get(name), staleness.ProbeContext(env={}), cdb.STALENESS_WARN
        )
        assert record.absent and "no offline rules cache directory" in record.error

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "name", ["semgrep-offline-rules", "opengrep-offline-rules"]
    )
    def test_a_ruleset_directory_without_rules_files_is_absent(self, tmp_path, name):
        cache = tmp_path / "rules"
        cache.mkdir()
        (cache / "README.txt").write_text("not a rule\n")
        record = staleness.measure(
            cdb.get(name),
            staleness.ProbeContext(env={}, cache_dir=str(cache)),
            cdb.STALENESS_WARN,
        )
        assert record.absent and "no rules files found" in record.error

    @pytest.mark.unit
    def test_ruleset_manifest_wins_over_a_fresh_mtime(self, tmp_path):
        """A copy resets mtime to now; the recorded download time still says 40 days."""
        fetched = datetime.now(UTC) - timedelta(days=40)
        cache = ruleset_dir(tmp_path / "rules", fetched)
        record = staleness.measure(
            cdb.get("semgrep-offline-rules"),
            staleness.ProbeContext(env={}, cache_dir=str(cache)),
            cdb.STALENESS_FAIL,
        )
        assert record.stale
        assert cdb.RULESET_FETCHED_AT_FILE in record.measured_by

    @pytest.mark.unit
    def test_ruleset_without_a_manifest_falls_back_to_mtime_and_says_so(self, tmp_path):
        old = datetime.now(UTC) - timedelta(days=45)
        cache = ruleset_dir(tmp_path / "rules", None, mtime=old)
        record = staleness.measure(
            cdb.get("opengrep-offline-rules"),
            staleness.ProbeContext(env={}, cache_dir=str(cache)),
            cdb.STALENESS_FAIL,
        )
        assert record.stale
        assert "mtime" in record.measured_by and "weaker" in record.measured_by

    @pytest.mark.unit
    def test_a_scanner_that_cannot_describe_its_database_is_recorded_not_skipped(self):
        class Broken(StubScanner):
            def content_database_probe_context(self):
                raise RuntimeError("boom")

        sarif = _sarif("grype")
        records = staleness.assess_scanner(
            Broken("grype", staleness.ProbeContext(env={})), sarif, cdb.STALENESS_FAIL
        )
        assert len(records) == 1 and records[0].enforced
        assert "boom" in (records[0].error or "")
        assert staleness.stale_content_databases(_model(sarif), enforced_only=True)

    @pytest.mark.integration
    def test_a_report_with_no_runs_still_carries_the_record(self, tmp_path):
        """merge_sarif_report drops a runless report, so the record must create a run."""
        scanner = _grype_case(tmp_path, timedelta(days=10))
        sarif = SarifReport(version="2.1.0", runs=[])
        staleness.assess_scanner(scanner, sarif, cdb.STALENESS_FAIL)
        assert staleness.stale_content_databases(_aggregate(sarif), enforced_only=True)


# --------------------------------------------------------------------------- reading it back


@pytest.mark.integration
class TestTheRecordTravelsWithTheResults:
    def test_it_survives_a_merge_behind_another_scanner(self, tmp_path):
        """The aggregate keeps the FIRST run's properties; the record is on the invocation."""
        from automated_security_helper.schemas.sarif_schema_model import Invocation

        first = _sarif("bandit")
        first.runs[0].invocations = [Invocation(executionSuccessful=True)]
        second = _sarif("grype")
        staleness.assess_scanner(
            _grype_case(tmp_path, timedelta(days=10)), second, cdb.STALENESS_FAIL
        )
        model = _aggregate(first, second)
        stale = staleness.stale_content_databases(model, enforced_only=True)
        assert [r.name for r in stale] == ["grype-db"]
        assert _exit_code(tmp_path, model) == 1

    def test_it_survives_a_json_round_trip(self, tmp_path):
        """Container mode's host reads ash_aggregated_results.json, not the live model."""
        sarif = _sarif("grype")
        staleness.assess_scanner(
            _grype_case(tmp_path, timedelta(days=10)), sarif, cdb.STALENESS_FAIL
        )
        reloaded = AshAggregatedResults.model_validate_json(
            _model(sarif).model_dump_json()
        )
        assert _exit_code(tmp_path, reloaded) == 1

    def test_it_is_not_mistaken_for_an_unevaluated_rule(self, tmp_path):
        sarif = _sarif("grype")
        staleness.assess_scanner(
            _grype_case(tmp_path, timedelta(days=10)), sarif, cdb.STALENESS_FAIL
        )
        assert unevaluated_rules(_model(sarif)) == []

    def test_the_stale_scanner_is_listed_as_incomplete_only_when_enforced(
        self, tmp_path
    ):
        from automated_security_helper.core.unified_metrics import ScannerMetrics

        metric = ScannerMetrics(scanner_name="grype", status="PASSED")
        for policy, listed in ((cdb.STALENESS_FAIL, True), (cdb.STALENESS_WARN, False)):
            sarif = _sarif("grype")
            staleness.assess_scanner(
                _grype_case(tmp_path, timedelta(days=10)), sarif, policy
            )
            with patch(f"{_MODULE}.get_unified_scanner_metrics", return_value=[metric]):
                got = incomplete_scanners(_model(sarif))
            if listed:
                assert got == [("grype", "PASSED (stale content database: grype-db)")]
            else:
                assert got == []


# --------------------------------------------------------------------------- offline grype


@pytest.fixture
def offline_grype(tmp_path, monkeypatch, test_plugin_context):
    """A real GrypeScanner in offline mode, with a fake grype on PATH."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
        GrypeScanner,
        GrypeScannerConfig,
        GrypeScannerConfigOptions,
    )

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    cache = tmp_path / "grype-cache"
    (cache / "6").mkdir(parents=True)
    # Fresh mtime on purpose: the old validator read this and called it "0 days old".
    (cache / "6" / "vulnerability.db").write_text("db")
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setenv("GRYPE_DB_CACHE_DIR", str(cache))
    # find_executable memoises per process, so without this a worker that ran another
    # test first resolves `grype` to THAT test's fake, with that test's build time.
    from automated_security_helper.utils import subprocess_utils

    monkeypatch.setattr(subprocess_utils, "_find_executable_cache", {})

    def make(age: timedelta, policy: str = cdb.DEFAULT_STALENESS_POLICY):
        launcher = fake_grype(bin_dir, datetime.now(UTC) - age)
        # The scanner must find THIS fake by its own lookup, not some other grype on PATH.
        found = subprocess_utils.find_executable("grype")
        assert found and Path(found).samefile(launcher), (found, launcher)
        config = GrypeScannerConfig(options=GrypeScannerConfigOptions(offline=True))
        test_plugin_context.config = apply_config_overrides(
            get_default_config(), [f"content_db_staleness={policy}"]
        )
        scanner = GrypeScanner(context=test_plugin_context, config=config)
        return scanner

    return make


def _run_through_executor(scanner, context) -> AshAggregatedResults:
    """The scanner executor's own path: scan, then the staleness assessment, then merge."""
    from automated_security_helper.core.phases.scanner_executor import ScannerExecutor

    # The tool runs with cwd=source_dir, so the target is the context's own source dir.
    source = Path(context.source_dir)
    source.mkdir(parents=True, exist_ok=True)
    (source / "requirements.txt").write_text("six==1.17.0\n")
    executor = ScannerExecutor(
        plugin_context=context,
        progress_display=None,
        scanner_tasks=[],
    )
    containers = executor._execute_scanner(
        "grype", scanner, [{"path": source, "type": "source"}]
    )
    assert containers and isinstance(containers[0].raw_results, SarifReport), containers
    return _aggregate(containers[0].raw_results)


@pytest.mark.integration
class TestOfflineGrypeTenDaysOld:
    """The measured silent case: offline, validate-age off, a database built 10 days ago."""

    def test_offline_still_disables_grypes_own_age_check(self, offline_grype):
        scanner = offline_grype(timedelta(days=10))
        scanner._process_config_options()
        assert scanner.extra_env.get("GRYPE_DB_VALIDATE_AGE") == "false"

    def test_a_ten_day_old_database_fails_the_scan(
        self, tmp_path, offline_grype, test_plugin_context
    ):
        scanner = offline_grype(timedelta(days=10))
        model = _run_through_executor(scanner, test_plugin_context)
        stale = staleness.stale_content_databases(model, enforced_only=True)
        assert [r.name for r in stale] == ["grype-db"]
        assert _exit_code(tmp_path, model) == 1

    def test_with_the_opt_out_it_passes_and_says_so(
        self, tmp_path, offline_grype, test_plugin_context
    ):
        scanner = offline_grype(timedelta(days=10), cdb.STALENESS_WARN)
        model = _run_through_executor(scanner, test_plugin_context)
        assert _exit_code(tmp_path, model) == 0
        assert "### Stale content databases" in _reports(model)["markdown"]

    def test_a_fresh_database_passes_silently(
        self, tmp_path, offline_grype, test_plugin_context
    ):
        scanner = offline_grype(timedelta(hours=2))
        model = _run_through_executor(scanner, test_plugin_context)
        assert staleness.stale_content_databases(model) == []
        assert _exit_code(tmp_path, model) == 0


# --------------------------------------------------------------------------- the flag


@pytest.mark.unit
class TestTheFlag:
    def test_the_config_default_is_fail(self):
        assert AshConfig(project_name="x").content_db_staleness == "fail"
        assert staleness.resolve_policy(AshConfig(project_name="x")) == "fail"

    def test_the_config_field_accepts_exactly_the_declared_policies(self):
        annotation = AshConfig.model_fields["content_db_staleness"].annotation
        assert set(typing.get_args(annotation)) == set(cdb.STALENESS_POLICIES)

    def test_config_warn_is_honoured(self):
        config = AshConfig(project_name="x", content_db_staleness="warn")
        assert staleness.resolve_policy(config) == "warn"

    def test_the_cli_override_wins_over_the_config_file(self):
        from_file = AshConfig(project_name="x", content_db_staleness="warn")
        overridden = apply_config_overrides(
            from_file, [cdb.content_db_staleness_override(allow_stale=False)]
        )
        assert staleness.resolve_policy(overridden) == "fail"
        overridden = apply_config_overrides(
            AshConfig(project_name="x"),
            [cdb.content_db_staleness_override(allow_stale=True)],
        )
        assert staleness.resolve_policy(overridden) == "warn"

    @pytest.mark.parametrize(
        "argv,expected",
        [
            ([], None),
            (
                ["--allow-stale-content-db"],
                [
                    "content_db_staleness=warn",
                    "content_db_staleness_overrides=[]",
                    "content_db_staleness_offline_image_default=false",
                ],
            ),
            (
                ["--no-allow-stale-content-db"],
                [
                    "content_db_staleness=fail",
                    "content_db_staleness_overrides=[]",
                    "content_db_staleness_offline_image_default=false",
                ],
            ),
        ],
    )
    def test_the_cli_flag_becomes_the_override(self, tmp_path, argv, expected):
        from typer.testing import CliRunner

        from automated_security_helper.cli.main import app

        with patch("automated_security_helper.cli.scan.run_ash_scan") as run:
            result = CliRunner().invoke(
                app,
                [
                    "scan",
                    "--source-dir",
                    str(tmp_path),
                    "--output-dir",
                    str(tmp_path / "out"),
                    *argv,
                ],
            )
        assert result.exit_code == 0, result.output
        overrides = list(run.call_args.kwargs["config_overrides"])
        staleness_overrides = [
            o for o in overrides if o.startswith("content_db_staleness")
        ]
        assert staleness_overrides == (expected or [])

    def test_a_runtime_patch_cannot_downgrade_the_policy(self):
        from automated_security_helper.config.ash_config import RuntimeOverridesConfig

        assert "/content_db_staleness" in RuntimeOverridesConfig().denied_paths


# --------------------------------------------------------------------------- per database


def _overrides(*entries: dict) -> list:
    """Validated ``content_db_staleness_overrides`` entries, as a loaded config holds them."""
    return AshConfig(
        project_name="x", content_db_staleness_overrides=list(entries)
    ).content_db_staleness_overrides


def _relax(database: str, expiration: str = "2999-01-01", policy: str = "warn") -> dict:
    return {
        "database": database,
        "policy": policy,
        "expiration": expiration,
        "reason": "upstream stopped publishing",
    }


class TestPerDatabaseOverrides:
    @pytest.mark.integration
    def test_the_default_has_no_overrides_and_still_fails_a_stale_database(
        self, tmp_path
    ):
        config = AshConfig(project_name="x")
        assert config.content_db_staleness_overrides == []
        assert get_default_config().content_db_staleness_overrides == []
        scanner = _trivy_case(tmp_path, _over("trivy-db"))
        sarif = _sarif(scanner.config.name)
        records = staleness.assess_scanner(
            scanner,
            sarif,
            staleness.resolve_policy(config),
            overrides=staleness.resolve_overrides(config),
        )
        assert [(r.name, r.enforced, r.policy_source) for r in records] == [
            ("trivy-db", True, None)
        ]
        assert "policy_source" not in records[0].to_dict()
        assert _exit_code(tmp_path, _model(sarif)) == 1

    @pytest.mark.integration
    def test_an_override_relaxes_only_the_database_it_names(self, tmp_path):
        overrides = _overrides(_relax("trivy-db"))
        trivy = _trivy_case(tmp_path, _over("trivy-db"))
        grype = _grype_case(tmp_path, _over("grype-db"))
        trivy_sarif, grype_sarif = _sarif("trivy-repo"), _sarif("grype")
        (trivy_record,) = staleness.assess_scanner(
            trivy, trivy_sarif, cdb.STALENESS_FAIL, overrides=overrides
        )
        (grype_record,) = staleness.assess_scanner(
            grype, grype_sarif, cdb.STALENESS_FAIL, overrides=overrides
        )

        assert trivy_record.stale and not trivy_record.enforced
        assert trivy_record.policy == "warn"
        assert "2999-01-01T00:00:00Z" in (trivy_record.policy_source or "")
        assert "content_db_staleness_overrides entry" in trivy_record.message()
        assert grype_record.stale and grype_record.enforced
        assert grype_record.policy_source is None

        # Alone, the relaxed database passes and still carries the warning.
        relaxed = _model(trivy_sarif)
        assert _exit_code(tmp_path, relaxed) == 0
        notes = _notifications(_reports(relaxed)["sarif"])
        assert [n["level"] for n in notes] == ["warning"]
        flat = json.loads(_reports(relaxed)["flat"])["content_databases"]
        assert [(d["name"], d["policy"], d["enforced"]) for d in flat] == [
            ("trivy-db", "warn", False)
        ]
        assert "policy_source" in flat[0]
        # Together, the database it does not name still fails the scan.
        both = _aggregate(trivy_sarif, grype_sarif)
        assert [r.name for r in staleness.stale_content_databases(both, True)] == [
            "grype-db"
        ]
        assert _exit_code(tmp_path, both) == 1

    @pytest.mark.integration
    def test_an_expired_override_is_ignored_with_a_warning(self, tmp_path, caplog):
        overrides = _overrides(_relax("trivy-db", expiration="2020-01-01"))
        scanner = _trivy_case(tmp_path, _over("trivy-db"))
        sarif = _sarif(scanner.config.name)
        with caplog.at_level("WARNING"):
            (record,) = staleness.assess_scanner(
                scanner, sarif, cdb.STALENESS_FAIL, overrides=overrides
            )
        assert record.enforced and record.policy_source is None
        assert _exit_code(tmp_path, _model(sarif)) == 1
        assert any(
            "expired at 2020-01-01T00:00:00Z and is ignored" in m
            for m in caplog.messages
        ), caplog.messages

    @pytest.mark.unit
    def test_expiry_is_midnight_utc_on_the_expiration_date(self):
        (entry,) = _overrides(_relax("trivy-db", expiration="2026-10-11"))
        assert entry.expires_at == datetime(2026, 10, 11, tzinfo=UTC)
        assert not entry.is_expired(datetime(2026, 10, 10, 23, 59, 59, tzinfo=UTC))
        assert entry.is_expired(datetime(2026, 10, 11, 0, 0, 0, tzinfo=UTC))
        assert entry.is_expired(datetime(2026, 10, 12, tzinfo=UTC))

    @pytest.mark.integration
    def test_an_override_can_also_tighten(self, tmp_path):
        overrides = _overrides(_relax("trivy-db", policy="fail"))
        scanner = _trivy_case(tmp_path, _over("trivy-db"))
        sarif = _sarif(scanner.config.name)
        (record,) = staleness.assess_scanner(
            scanner, sarif, cdb.STALENESS_WARN, overrides=overrides
        )
        assert record.enforced
        assert _exit_code(tmp_path, _model(sarif)) == 1

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "entry,needle",
        [
            ({**_relax("trivy-db"), "database": "trivy"}, "unknown content database"),
            ({**_relax("trivy-db"), "expiration": "10/11/2026"}, "YYYY-MM-DD"),
            ({**_relax("trivy-db"), "policy": "ignore"}, "policy"),
            ({**_relax("trivy-db"), "reason": ""}, "reason"),
            ({**_relax("trivy-db"), "until": "never"}, "until"),
        ],
    )
    def test_an_invalid_entry_is_rejected(self, entry, needle):
        with pytest.raises(ValueError) as raised:
            _overrides(entry)
        assert needle in str(raised.value)

    @pytest.mark.unit
    @pytest.mark.parametrize("missing", ["expiration", "reason", "database", "policy"])
    def test_every_field_is_required(self, missing):
        entry = _relax("trivy-db")
        del entry[missing]
        with pytest.raises(ValueError) as raised:
            _overrides(entry)
        assert missing in str(raised.value)

    @pytest.mark.unit
    def test_one_entry_per_database(self):
        with pytest.raises(ValueError) as raised:
            _overrides(_relax("trivy-db"), _relax("trivy-db", policy="fail"))
        assert "more than one" in str(raised.value)

    @pytest.mark.unit
    @pytest.mark.parametrize("allow_stale,expected", [(False, "fail"), (True, "warn")])
    def test_either_form_of_the_flag_clears_the_overrides(self, allow_stale, expected):
        from_file = AshConfig(
            project_name="x",
            content_db_staleness_overrides=[_relax("trivy-db"), _relax("grype-db")],
        )
        overridden = apply_config_overrides(
            from_file, cdb.content_db_staleness_flag_overrides(allow_stale=allow_stale)
        )
        assert overridden.content_db_staleness_overrides == []
        assert staleness.resolve_policy(overridden) == expected

    @pytest.mark.unit
    def test_a_runtime_patch_cannot_add_an_override(self):
        from automated_security_helper.config.ash_config import RuntimeOverridesConfig

        assert (
            "/content_db_staleness_overrides" in RuntimeOverridesConfig().denied_paths
        )

    @pytest.mark.unit
    def test_the_config_validator_accepts_the_key(self):
        from automated_security_helper.config.config_validator import ConfigValidator

        assert (
            "content_db_staleness_overrides" in ConfigValidator.VALID_TOP_LEVEL_FIELDS
        )

    @pytest.mark.integration
    @pytest.mark.parametrize("relaxed,exit_code", [("trivy-db", 1), ("grype-db", 0)])
    def test_the_executor_applies_the_overrides_from_the_config(
        self, tmp_path, offline_grype, test_plugin_context, relaxed, exit_code
    ):
        scanner = offline_grype(timedelta(days=10))
        test_plugin_context.config = AshConfig(
            project_name="x", content_db_staleness_overrides=[_relax(relaxed)]
        )
        model = _run_through_executor(scanner, test_plugin_context)
        assert _exit_code(tmp_path, model) == exit_code
        assert [r.name for r in staleness.stale_content_databases(model)] == [
            "grype-db"
        ]


# --------------------------------------------------------------------------- offline image


def _offline_image_env(monkeypatch, value: str | None = "YES") -> None:
    """The variable the image sets from its OFFLINE build argument, as an image has it."""
    if value is None:
        monkeypatch.delenv(cdb.OFFLINE_IMAGE_ENV, raising=False)
    else:
        monkeypatch.setenv(cdb.OFFLINE_IMAGE_ENV, value)


class TestTheOfflineImageDefault:
    """An image built with OFFLINE=YES holds trivy-db, and only trivy-db, to warn.

    Such an image carries the trivy database it was built with, and trivy's own 24h
    bound would fail every scan from a day after the build. The rule: the
    scan stays green and every report records the stale database; grype-db and the
    offline rulesets keep ``fail``. The scope is fixed in code, the trigger is the
    image's own environment, and the config can only turn it off.
    """

    @pytest.mark.unit
    def test_it_names_exactly_trivy_db(self):
        assert dict(cdb.OFFLINE_IMAGE_POLICIES) == {"trivy-db": cdb.STALENESS_WARN}
        assert cdb.OFFLINE_IMAGE_ENV == "ASH_OFFLINE_AT_BUILD_TIME"

    @pytest.mark.integration
    def test_a_stale_trivy_db_warns_and_every_report_says_why(self, tmp_path):
        scanner = _trivy_case(tmp_path, _over("trivy-db"))
        sarif = _sarif(scanner.config.name)
        (record,) = staleness.assess_scanner(
            scanner, sarif, cdb.STALENESS_FAIL, offline_image=True
        )
        assert record.stale and not record.enforced
        assert record.policy == cdb.STALENESS_WARN
        assert "OFFLINE=YES" in (record.policy_source or "")
        assert "OFFLINE=YES" in record.message()
        assert "ash build-image --offline" in record.message()

        model = _model(sarif)
        assert _exit_code(tmp_path, model) == 0
        reports = _reports(model)
        notes = _notifications(reports["sarif"])
        assert [n["level"] for n in notes] == ["warning"]
        assert "OFFLINE=YES" in notes[0]["message"]["text"]
        assert "### Stale content databases" in reports["markdown"]
        assert "OFFLINE=YES" in reports["markdown"]
        assert "OFFLINE=YES" in reports["text"]
        (flat,) = json.loads(reports["flat"])["content_databases"]
        assert (flat["name"], flat["policy"], flat["enforced"]) == (
            "trivy-db",
            "warn",
            False,
        )
        assert "OFFLINE=YES" in flat["policy_source"]

    @pytest.mark.parametrize("name", EVERY_OTHER_TIERED_CASE)
    def test_every_other_database_still_fails(self, tmp_path, name):
        scanner = CASES[name](tmp_path, _over(name))
        sarif = _sarif(scanner.config.name)
        (record,) = staleness.assess_scanner(
            scanner, sarif, cdb.STALENESS_FAIL, offline_image=True
        )
        assert record.enforced and record.policy_source is None
        assert _exit_code(tmp_path, _model(sarif)) == 1

    @pytest.mark.integration
    def test_outside_an_offline_image_trivy_db_still_fails(self, tmp_path):
        scanner = _trivy_case(tmp_path, _over("trivy-db"))
        sarif = _sarif(scanner.config.name)
        (record,) = staleness.assess_scanner(scanner, sarif, cdb.STALENESS_FAIL)
        assert record.enforced and record.policy_source is None
        assert _exit_code(tmp_path, _model(sarif)) == 1

    @pytest.mark.integration
    def test_a_fresh_trivy_db_is_not_reported(self, tmp_path):
        scanner = _trivy_case(tmp_path, _under("trivy-db"))
        sarif = _sarif(scanner.config.name)
        (record,) = staleness.assess_scanner(
            scanner, sarif, cdb.STALENESS_FAIL, offline_image=True
        )
        assert not record.stale
        assert staleness.stale_content_databases(_model(sarif)) == []

    @pytest.mark.integration
    def test_an_override_entry_outranks_it(self, tmp_path):
        overrides = _overrides(_relax("trivy-db", policy="fail"))
        scanner = _trivy_case(tmp_path, _over("trivy-db"))
        sarif = _sarif(scanner.config.name)
        (record,) = staleness.assess_scanner(
            scanner,
            sarif,
            cdb.STALENESS_FAIL,
            overrides=overrides,
            offline_image=True,
        )
        assert record.enforced
        assert "content_db_staleness_overrides entry" in (record.policy_source or "")

    @pytest.mark.integration
    def test_an_expired_override_falls_back_to_it_and_says_so(self, tmp_path, caplog):
        overrides = _overrides(
            _relax("trivy-db", policy="fail", expiration="2020-01-01")
        )
        scanner = _trivy_case(tmp_path, _over("trivy-db"))
        sarif = _sarif(scanner.config.name)
        with caplog.at_level("WARNING"):
            (record,) = staleness.assess_scanner(
                scanner,
                sarif,
                cdb.STALENESS_FAIL,
                overrides=overrides,
                offline_image=True,
            )
        assert not record.enforced and "OFFLINE=YES" in (record.policy_source or "")
        (expired,) = [m for m in caplog.messages if "expired at" in m]
        assert "OFFLINE=YES" in expired
        assert "content_db_staleness (fail)" not in expired

    @pytest.mark.integration
    def test_under_warn_it_changes_nothing(self, tmp_path):
        scanner = _trivy_case(tmp_path, _over("trivy-db"))
        sarif = _sarif(scanner.config.name)
        (record,) = staleness.assess_scanner(
            scanner, sarif, cdb.STALENESS_WARN, offline_image=True
        )
        assert record.policy == cdb.STALENESS_WARN and record.policy_source is None

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "env,field,expected",
        [
            (None, True, False),
            ("NO", True, False),
            ("", True, False),
            ("YES", True, True),
            ("yes", True, True),
            ("YES", False, False),
        ],
    )
    def test_only_the_image_turns_it_on_and_the_config_can_only_turn_it_off(
        self, monkeypatch, env, field, expected
    ):
        _offline_image_env(monkeypatch, env)
        config = AshConfig(
            project_name="x", content_db_staleness_offline_image_default=field
        )
        assert staleness.resolve_offline_image_default(config) is expected

    @pytest.mark.unit
    def test_the_config_default_leaves_it_on(self, monkeypatch):
        _offline_image_env(monkeypatch)
        assert AshConfig(project_name="x").content_db_staleness_offline_image_default
        assert get_default_config().content_db_staleness_offline_image_default
        assert staleness.resolve_offline_image_default(AshConfig(project_name="x"))

    @pytest.mark.unit
    @pytest.mark.parametrize("allow_stale", [False, True])
    def test_either_form_of_the_flag_turns_it_off(self, monkeypatch, allow_stale):
        _offline_image_env(monkeypatch)
        overridden = apply_config_overrides(
            AshConfig(project_name="x"),
            cdb.content_db_staleness_flag_overrides(allow_stale=allow_stale),
        )
        assert overridden.content_db_staleness_offline_image_default is False
        assert staleness.resolve_offline_image_default(overridden) is False

    @pytest.mark.unit
    def test_a_runtime_patch_cannot_turn_it_back_on(self):
        from automated_security_helper.config.ash_config import RuntimeOverridesConfig

        assert (
            "/content_db_staleness_offline_image_default"
            in RuntimeOverridesConfig().denied_paths
        )

    @pytest.mark.unit
    def test_the_config_validator_accepts_the_key(self):
        from automated_security_helper.config.config_validator import ConfigValidator

        assert (
            "content_db_staleness_offline_image_default"
            in ConfigValidator.VALID_TOP_LEVEL_FIELDS
        )

    @pytest.mark.integration
    @pytest.mark.parametrize("env,enforced", [("YES", False), (None, True)])
    def test_the_executor_applies_it_from_the_environment(
        self, tmp_path, monkeypatch, test_plugin_context, env, enforced
    ):
        from automated_security_helper.core.phases.scanner_executor import (
            ScannerExecutor,
        )

        _offline_image_env(monkeypatch, env)
        test_plugin_context.config = get_default_config()
        scanner = _trivy_case(tmp_path, _over("trivy-db"))
        sarif = _sarif(scanner.config.name)
        executor = ScannerExecutor(
            plugin_context=test_plugin_context, progress_display=None, scanner_tasks=[]
        )
        executor._assess_content_databases(scanner, sarif)
        (record,) = staleness.content_db_records(_model(sarif))
        assert record.stale and record.enforced is enforced

    @pytest.mark.unit
    def test_the_image_sets_it_from_its_offline_build_argument_only(self):
        dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
        assignments = re.findall(
            rf"^\s*ENV\s+{cdb.OFFLINE_IMAGE_ENV}=(\S+)", dockerfile, re.MULTILINE
        )
        assert assignments == ['"${OFFLINE}"'], assignments
        assert re.search(r'^ARG OFFLINE="NO"$', dockerfile, re.MULTILINE)


# --------------------------------------------------------------------------- the registry


@pytest.mark.unit
class TestEveryDatabaseIsBoundedAndMeasurable:
    def test_every_entry_declares_a_bound_its_source_and_a_refresh(self):
        for entry in cdb.CONTENT_DATABASES:
            assert entry.max_age > timedelta(0), entry.name
            assert entry.bound_source and entry.refresh and entry.age_source, entry.name

    def test_tool_defaults_and_ash_choices_are_told_apart(self):
        assert cdb.get("grype-db").bound_is_tool_default
        assert cdb.get("trivy-db").bound_is_tool_default
        for name in ("semgrep-offline-rules", "opengrep-offline-rules"):
            entry = cdb.get(name)
            assert not entry.bound_is_tool_default
            assert "ASH's own choice" in entry.bound_source

    def test_every_entry_has_a_measurer_and_nothing_else_does(self):
        assert set(staleness.MEASURERS) == {e.name for e in cdb.CONTENT_DATABASES}

    def test_only_grype_is_cacheable_in_ci(self):
        assert [e.name for e in cdb.CONTENT_DATABASES if e.cacheable] == ["grype-db"]

    def test_the_dockerfile_records_the_ruleset_download_time_for_both_caches(self):
        dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
        for env in ("SEMGREP_RULES_CACHE_DIR", "OPENGREP_RULES_CACHE_DIR"):
            assert f'"${{{env}}}/{cdb.RULESET_FETCHED_AT_FILE}"' in dockerfile, env


@pytest.mark.unit
class TestNoSecondLiteral:
    """The new bounds are declared once, like grype's (see test_content_databases.py)."""

    SECOND_COPY = re.compile(
        r"hours\s*=\s*24\b|days\s*=\s*30\b|\b720h\b|days\s*=\s*7\b|timedelta\(days=1\)"
    )

    def test_no_file_restates_the_trivy_or_ruleset_bound(self):
        registry = (
            REPO_ROOT / "automated_security_helper" / "utils" / "content_databases.py"
        )
        offenders = []
        for root in ("automated_security_helper", ".github", "scripts"):
            for path in (REPO_ROOT / root).rglob("*"):
                if not path.is_file() or path.suffix not in {
                    ".py",
                    ".yml",
                    ".yaml",
                    ".sh",
                }:
                    continue
                if path == registry:
                    continue
                for number, line in enumerate(
                    path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1
                ):
                    if self.SECOND_COPY.search(line):
                        offenders.append(f"{path.relative_to(REPO_ROOT)}:{number}")
        assert offenders == [], offenders


@pytest.mark.unit
class TestNoScannerReadsAnUndeclaredDatabase:
    """The drift gate for scanners: a new offline-cache scanner must declare its database."""

    @staticmethod
    def _cache_scanners() -> dict[str, type]:
        from automated_security_helper.core.enums import OfflineStrategy
        from automated_security_helper.core.scanner_inventory import (
            _declared_config_class,
            _loaded_scanner_classes,
        )

        found: dict[str, type] = {}
        for cls in _loaded_scanner_classes():
            if (
                getattr(cls, "offline_strategy", None)
                is not OfflineStrategy.CACHE_FLAGS
            ):
                continue
            config_cls = _declared_config_class(cls)
            assert config_cls is not None, cls
            found[str(config_cls.model_fields["name"].default)] = cls
        return found

    def test_every_cache_scanner_is_declared_or_explained(self):
        declared = {name for e in cdb.CONTENT_DATABASES for name in e.readers}
        explained = set(cdb.SCANNERS_WITHOUT_CONTENT_DATABASE)
        assert not declared & explained
        undeclared = sorted(set(self._cache_scanners()) - declared - explained)
        assert undeclared == [], (
            "these scanners keep an offline cache but declare no content database in "
            "utils/content_databases.py and are not listed in "
            f"SCANNERS_WITHOUT_CONTENT_DATABASE: {undeclared}"
        )

    def test_every_declared_scanner_exists(self):
        scanners = self._cache_scanners()
        for name in {n for e in cdb.CONTENT_DATABASES for n in e.readers} | set(
            cdb.SCANNERS_WITHOUT_CONTENT_DATABASE
        ):
            assert name in scanners, name

    def test_the_gate_can_fail(self):
        """A CACHE_FLAGS scanner nobody declared would be reported."""
        scanners = set(self._cache_scanners()) | {"a-new-db-scanner"}
        declared = {name for e in cdb.CONTENT_DATABASES for name in e.readers}
        explained = set(cdb.SCANNERS_WITHOUT_CONTENT_DATABASE)
        assert sorted(scanners - declared - explained) == ["a-new-db-scanner"]


# --------------------------------------------------------------------------- one verdict


class TestAStaleDatabaseIsOneConditionWithTheGateOnOrOff:
    """With the completeness gate on, the stale database is not reported twice.

    ``incomplete_scanners`` lists the stale scanner (above), and the gate's scanner arm
    reads that list. Before ``scan_incompleteness`` carried stale databases in a field of
    their own, the gate-on run exited from the scanner arm with ``partial_coverage`` as
    the MCP reason and install-the-tool advice on the console, while the gate-off run
    exited from the stale arm with no ``ScanIncompleteExit``, so MCP reported ``failed``.
    """

    @staticmethod
    def _stale_model(tmp_path, policy=cdb.STALENESS_FAIL):
        sarif = _sarif("grype")
        staleness.assess_scanner(
            _grype_case(tmp_path, timedelta(days=10)), sarif, policy
        )
        return _model(sarif)

    @pytest.mark.integration
    @pytest.mark.parametrize("gate", [True, False])
    def test_it_is_carried_once_in_its_own_field(self, tmp_path, gate):
        from automated_security_helper.core.unified_metrics import ScannerMetrics
        from automated_security_helper.interactions.run_ash_scan import (
            scan_incompleteness,
        )

        model = self._stale_model(tmp_path)
        metric = ScannerMetrics(scanner_name="grype", status="PASSED")
        with patch(f"{_MODULE}.get_unified_scanner_metrics", return_value=[metric]):
            got = scan_incompleteness(model, gate=gate)
        assert [r.name for r in got.stale_content_databases] == ["grype-db"]
        assert got.scanners == ()
        assert bool(got)
        payload = got.to_payload()
        assert payload["incomplete_scanners"] == []
        assert [d["name"] for d in payload["stale_content_databases"]] == ["grype-db"]
        json.dumps(payload)

    @pytest.mark.integration
    def test_a_stale_scanner_that_also_lost_targets_keeps_its_row(self, tmp_path):
        from automated_security_helper.core.unified_metrics import ScannerMetrics
        from automated_security_helper.interactions.run_ash_scan import (
            scan_incompleteness,
        )

        model = self._stale_model(tmp_path)
        metric = ScannerMetrics(
            scanner_name="grype",
            status="PASSED",
            targets_attempted=10,
            targets_failed=4,
        )
        with patch(f"{_MODULE}.get_unified_scanner_metrics", return_value=[metric]):
            got = scan_incompleteness(model, gate=True)
        assert [name for name, _ in got.scanners] == ["grype"]
        assert "4 of 10 targets unevaluated" in got.scanners[0][1]
        assert [r.name for r in got.stale_content_databases] == ["grype-db"]

    @pytest.mark.integration
    @pytest.mark.parametrize("gate", [True, False])
    def test_it_exits_1_with_the_gate_on_or_off(self, tmp_path, gate):
        model = self._stale_model(tmp_path)
        assert _exit_code(tmp_path, model, fail_on_incomplete_scanners=gate) == 1

    @pytest.mark.integration
    @pytest.mark.parametrize("gate", [True, False])
    def test_the_opt_out_still_passes_with_the_gate_on_or_off(self, tmp_path, gate):
        from automated_security_helper.interactions.run_ash_scan import (
            scan_incompleteness,
        )

        model = self._stale_model(tmp_path, cdb.STALENESS_WARN)
        assert _exit_code(tmp_path, model, fail_on_incomplete_scanners=gate) == 0
        with patch(f"{_MODULE}.get_unified_scanner_metrics", return_value=[]):
            assert not scan_incompleteness(model, gate=gate)

    @pytest.mark.integration
    def test_the_message_gives_the_refresh_advice_and_not_the_install_advice(
        self, tmp_path, capsys
    ):
        from automated_security_helper.interactions.run_ash_scan import (
            print_incompleteness_message,
        )

        model = self._stale_model(tmp_path)
        records = staleness.stale_content_databases(model, enforced_only=True)
        print_incompleteness_message([], [], records)
        # rich colours and wraps the line, so compare the plain text.
        out = " ".join(re.sub(r"\x1b\[[0-9;]*m", "", capsys.readouterr().out).split())
        assert "content database(s) are past their declared age bound" in out
        assert "grype-db" in out
        assert "Install the missing" not in out
        assert "exception" not in out

    @pytest.mark.unit
    def test_the_mcp_coverage_check_sees_it(self):
        from automated_security_helper.core.resource_management.scan_tracking import (
            coverage_has_gap,
        )

        assert coverage_has_gap({"stale_content_databases": [{"name": "grype-db"}]})
        assert not coverage_has_gap({"stale_content_databases": []})


# --------------------------------------------------------------------------- two readers


@pytest.mark.integration
class TestEveryScannerThatReadAStaleDatabaseIsNamed:
    """trivy and trivy-repo both read trivy-db. Records were kept one per database, so
    when both read a stale one, only one scanner was named in every report."""

    @staticmethod
    def _both(tmp_path, trivy_age, repo_age, policy=cdb.STALENESS_FAIL):
        reports = []
        for name, age in (("trivy", trivy_age), ("trivy-repo", repo_age)):
            (tmp_path / name).mkdir()
            exe = fake_trivy(tmp_path / name, datetime.now(UTC) - age)
            scanner = StubScanner(
                name,
                staleness.ProbeContext(env=dict(os.environ), executable=str(exe)),
            )
            sarif = _sarif(name)
            staleness.assess_scanner(scanner, sarif, policy)
            reports.append(sarif)
        return _aggregate(*reports)

    def test_both_scanners_are_named(self, tmp_path):
        model = self._both(tmp_path, _over("trivy-db"), _over("trivy-db"))
        pairs = [("trivy-db", "trivy"), ("trivy-db", "trivy-repo")]
        assert [
            (r.name, r.scanner)
            for r in staleness.stale_content_databases(model, enforced_only=True)
        ] == pairs
        assert [(r.name, r.scanner) for r in staleness.content_db_records(model)] == (
            pairs
        )
        assert _exit_code(tmp_path, model) == 1

        reports = _reports(model)
        stale_md = reports["markdown"].split("### Stale content databases", 1)[1]
        assert "(trivy, failed the scan)" in stale_md
        assert "(trivy-repo, failed the scan)" in stale_md
        assert reports["text"].count("[FAILED THE SCAN]") == 2
        flat = json.loads(reports["flat"])["content_databases"]
        assert [(d["name"], d["scanner"], d["enforced"]) for d in flat] == [
            ("trivy-db", "trivy", True),
            ("trivy-db", "trivy-repo", True),
        ]
        assert len(_notifications(reports["sarif"])) == 2

    def test_a_fresh_reader_does_not_hide_a_stale_one(self, tmp_path):
        model = self._both(tmp_path, _under("trivy-db"), _over("trivy-db"))
        assert [(r.scanner, r.stale) for r in staleness.content_db_records(model)] == [
            ("trivy", False),
            ("trivy-repo", True),
        ]
        assert [r.scanner for r in staleness.stale_content_databases(model, True)] == [
            "trivy-repo"
        ]
        flat = json.loads(_reports(model)["flat"])["content_databases"]
        assert [(d["scanner"], d["stale"], d["enforced"]) for d in flat] == [
            ("trivy", False, False),
            ("trivy-repo", True, True),
        ]

    @pytest.mark.parametrize("stale_first", [True, False])
    def test_one_scanners_stale_record_is_never_hidden_behind_its_fresh_one(
        self, tmp_path, stale_first
    ):
        """One scanner measured per target type writes the database twice."""
        reports = []
        ages = [_over("trivy-db"), _under("trivy-db")]
        for i, age in enumerate(ages if stale_first else reversed(ages)):
            (tmp_path / str(i)).mkdir()
            exe = fake_trivy(tmp_path / str(i), datetime.now(UTC) - age)
            scanner = StubScanner(
                "trivy",
                staleness.ProbeContext(env=dict(os.environ), executable=str(exe)),
            )
            sarif = _sarif("trivy")
            staleness.assess_scanner(scanner, sarif, cdb.STALENESS_FAIL)
            reports.append(sarif)
        model = _aggregate(*reports)
        (record,) = staleness.content_db_records(model)
        assert record.stale and record.scanner == "trivy"
        (stale,) = staleness.stale_content_databases(model, enforced_only=True)
        assert stale.scanner == "trivy"
        assert _exit_code(tmp_path, model) == 1


# --------------------------------------------------------------------------- future-dated


class TestABuildTimeInTheFutureIsNotFresh:
    """``now - built`` is negative for a build time in the future, which every bound
    admits, so a database claiming to be built tomorrow read as fresh indefinitely."""

    @pytest.mark.unit
    def test_is_stale_refuses_a_build_time_past_the_clock_skew_allowance(self):
        entry = cdb.get("trivy-db")
        now = datetime(2026, 10, 11, 12, 0, tzinfo=UTC)
        allowance = cdb.CLOCK_SKEW_ALLOWANCE
        assert not cdb.is_stale(entry, now + allowance, now)
        assert cdb.is_stale(entry, now + allowance + timedelta(seconds=1), now)
        assert cdb.is_stale(entry, now + timedelta(days=365), now)
        assert not cdb.is_stale(entry, now - timedelta(hours=1), now)

    @pytest.mark.parametrize("name", TIERED_CASES)
    def test_it_fails_the_scan_and_says_why(self, tmp_path, name):
        scanner = CASES[name](tmp_path, -timedelta(days=2))
        sarif = _sarif(scanner.config.name)
        (record,) = staleness.assess_scanner(
            scanner, sarif, cdb.DEFAULT_STALENESS_POLICY
        )
        assert record.stale and record.enforced
        message = record.message()
        assert "ahead of this host's clock" in message, message
        assert "cannot be shown to be inside" in message, message
        assert _exit_code(tmp_path, _model(sarif)) == 1

    @pytest.mark.integration
    def test_a_small_skew_is_tolerated(self, tmp_path):
        scanner = _trivy_case(tmp_path, -timedelta(minutes=1))
        (record,) = staleness.assess_scanner(
            scanner, _sarif("trivy-repo"), cdb.DEFAULT_STALENESS_POLICY
        )
        assert not record.stale


# --------------------------------------------------------------------------- spellings


@pytest.mark.unit
@pytest.mark.parametrize(
    "value, built",
    [
        ("YES", True),
        ("yes", True),
        ("true", True),
        ("TRUE", True),
        ("1", True),
        ("NO", False),
        ("false", False),
        ("0", False),
        ("", False),
        (None, False),
    ],
)
def test_the_offline_image_is_recognized_by_every_spelling_ash_offline_takes(
    monkeypatch, value, built
):
    """``built_offline`` takes the spellings ``ASH_OFFLINE`` does, so an image whose
    build argument is ``true`` or ``1`` is the offline image too."""
    from automated_security_helper.core.constants import is_offline_mode

    environ = {} if value is None else {cdb.OFFLINE_IMAGE_ENV: value}
    assert cdb.built_offline(environ) is built
    if value is None:
        monkeypatch.delenv("ASH_OFFLINE", raising=False)
    else:
        monkeypatch.setenv("ASH_OFFLINE", value)
    assert is_offline_mode() is built


# --------------------------------------------------------------------------- what the probes read

#: trivy's config and cache resolution around ``trivy version``, as measured at 0.75.0:
#: ``--config FILE`` loads FILE (an error when it is missing), and without the flag
#: ``trivy.yaml`` in the working directory, never a parent's. The cache is
#: ``--cache-dir``, else TRIVY_CACHE_DIR, else the config's ``cache.dir``, else the
#: default. Config files here are JSON, which is YAML.
FAKE_TRIVY = """\
import json, os, sys
args = sys.argv[1:]
def flag(name):
    for i, arg in enumerate(args):
        if arg == name and i + 1 < len(args):
            return args[i + 1]
        if arg.startswith(name + "="):
            return arg.split("=", 1)[1]
    return None
path = flag("--config")
explicit = path is not None
path = path if explicit else "trivy.yaml"
config = {}
if os.path.isfile(path):
    text = open(path, encoding="utf-8").read()
    config = json.loads(text) if text.strip() else {}
elif explicit:
    sys.exit("config file not found: " + path)
cache = (
    flag("--cache-dir")
    or os.environ.get("TRIVY_CACHE_DIR")
    or (config.get("cache") or {}).get("dir")
    or os.path.join(os.path.expanduser("~"), ".cache", "trivy")
)
with open(os.path.join(cache, "db", "metadata.json"), encoding="utf-8") as f:
    print(json.dumps({"Version": "0.75.0", "VulnerabilityDB": json.load(f)}))
"""

#: grype's around ``grype db status``, as measured at 0.120.1: ``-c FILE`` loads only
#: FILE; without it, ``.grype.yaml`` or ``.grype/config.yaml`` in the working
#: directory. The cache is GRYPE_DB_CACHE_DIR, else the config's ``db.cache-dir``,
#: else the default.
FAKE_GRYPE = """\
import json, os, sys
args = sys.argv[1:]
path = None
for i, arg in enumerate(args):
    if arg in ("-c", "--config") and i + 1 < len(args):
        path = args[i + 1]
if path is None:
    for candidate in (".grype.yaml", os.path.join(".grype", "config.yaml")):
        if os.path.isfile(candidate):
            path = candidate
            break
config = {}
if path is not None:
    text = open(path, encoding="utf-8").read()
    config = json.loads(text) if text.strip() else {}
cache = (
    os.environ.get("GRYPE_DB_CACHE_DIR")
    or (config.get("db") or {}).get("cache-dir")
    or os.path.join(os.path.expanduser("~"), ".cache", "grype", "db")
)
built = open(os.path.join(cache, "6", "built.txt"), encoding="utf-8").read().strip()
db = os.path.join(cache, "6", "vulnerability.db")
print(json.dumps({"built": built, "path": db, "valid": True}))
"""


def _plant_trivy(cache: Path, when: datetime) -> None:
    (cache / "db").mkdir(parents=True, exist_ok=True)
    stamp = _ts(when)
    (cache / "db" / "metadata.json").write_text(
        json.dumps(
            {
                "Version": 2,
                "NextUpdate": stamp,
                "UpdatedAt": stamp,
                "DownloadedAt": stamp,
            }
        ),
        encoding="utf-8",
    )


def _plant_grype(cache: Path, when: datetime) -> None:
    (cache / "6").mkdir(parents=True, exist_ok=True)
    (cache / "6" / "built.txt").write_text(_ts(when), encoding="utf-8")


@pytest.mark.integration
class TestTheProbeReadsNothingTheRepositoryWrote:
    """``cd repo && ash --offline`` with a planted config cannot age a stale database.

    Measured with trivy 0.75.0 and grype 0.120.1: run from a directory holding a
    ``trivy.yaml`` with ``cache.dir``, or a ``.grype.yaml`` or ``.grype/config.yaml``
    with ``db.cache-dir``, naming a planted database built "2099-01-01", the probes
    ASH ran after the scan reported that date. The fake tools below resolve config
    and cache the way the real ones were measured to; the same case against the
    real binaries is tests/integration/scanners/test_content_db_probe_real_tools.py.
    """

    PLANTED = datetime(2099, 1, 1, tzinfo=UTC)

    @pytest.fixture
    def repo(self, tmp_path, monkeypatch):
        from automated_security_helper.utils import subprocess_utils

        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        _executable(bin_dir, "trivy", FAKE_TRIVY)
        _executable(bin_dir, "grype", FAKE_GRYPE)
        monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
        monkeypatch.setattr(subprocess_utils, "_find_executable_cache", {})
        home = tmp_path / "home"
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setenv("USERPROFILE", str(home))
        monkeypatch.setenv("LOCALAPPDATA", str(home / "AppData" / "Local"))
        for name in ("XDG_CACHE_HOME", "TRIVY_CACHE_DIR", "GRYPE_DB_CACHE_DIR"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv("ASH_OFFLINE", "YES")
        source = tmp_path / "repo"
        source.mkdir()
        # ASH's own working directory is the scanned repository.
        monkeypatch.chdir(source)
        return source

    @staticmethod
    def _context(source: Path):
        from automated_security_helper.base.plugin_context import PluginContext

        return PluginContext(
            source_dir=source,
            output_dir=source.parent / "out",
            config=get_default_config(),
        )

    def _assert_fresh(self, record, fresh: datetime) -> None:
        assert record.built is not None, record.error
        assert record.built != self.PLANTED, "the probe read the repository's database"
        assert abs(record.built - fresh) < timedelta(seconds=2)

    def test_trivy_yaml(self, repo, monkeypatch):
        from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
            TrivyRepoScanner,
            TrivyRepoScannerConfig,
        )
        from automated_security_helper.utils.content_db_refresh import (
            default_cache_dir,
        )

        fresh = datetime.now(UTC).replace(microsecond=0) - timedelta(hours=1)
        _plant_trivy(default_cache_dir("trivy"), fresh)
        planted = repo.parent / "planted-trivy"
        _plant_trivy(planted, self.PLANTED)
        (repo / "trivy.yaml").write_text(json.dumps({"cache": {"dir": str(planted)}}))

        scanner = TrivyRepoScanner(
            context=self._context(repo), config=TrivyRepoScannerConfig()
        )
        scanner._process_config_options()
        monkeypatch.setattr(scanner, "validate_plugin_dependencies", lambda: True)
        # A run that ended: the scanner refuses a response with no exit code,
        # so the stand-in answers as a finished tool does, with nothing to read.
        monkeypatch.setattr(
            scanner,
            "_run_subprocess",
            lambda command, **kw: {"returncode": 0, "stdout": "", "stderr": ""},
        )
        scanner.scan(repo, "source")
        record = staleness.measure(
            cdb.get("trivy-db"),
            scanner.content_database_probe_context(),
            cdb.STALENESS_FAIL,
        )
        self._assert_fresh(record, fresh)

    @pytest.mark.parametrize("name", [".grype.yaml", ".grype/config.yaml"])
    def test_grype_config(self, repo, name):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
            GrypeScanner,
            GrypeScannerConfig,
        )
        from automated_security_helper.utils.content_db_refresh import (
            default_cache_dir,
        )

        fresh = datetime.now(UTC).replace(microsecond=0) - timedelta(hours=1)
        _plant_grype(default_cache_dir("grype"), fresh)
        planted = repo.parent / "planted-grype"
        _plant_grype(planted, self.PLANTED)
        config = repo / name
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text(json.dumps({"db": {"cache-dir": str(planted)}}))

        scanner = GrypeScanner(context=self._context(repo), config=GrypeScannerConfig())
        scanner._process_config_options()
        scanner._execute_scan(repo, "source", [])
        record = staleness.measure(
            cdb.get("grype-db"),
            scanner.content_database_probe_context(),
            cdb.STALENESS_FAIL,
        )
        self._assert_fresh(record, fresh)


@pytest.mark.unit
def test_the_probes_pass_the_same_empty_config_the_refresh_does():
    """One object, from the module both import (utils/content_db_shared.py), so
    no copy can drift; the file it names ships with ASH."""
    from automated_security_helper.utils import content_db_refresh, content_db_shared

    assert staleness.EMPTY_TOOL_CONFIG is content_db_shared.EMPTY_TOOL_CONFIG
    assert content_db_refresh.EMPTY_TOOL_CONFIG is content_db_shared.EMPTY_TOOL_CONFIG
    assert content_db_shared.EMPTY_TOOL_CONFIG.is_file()
