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
        return [e for e in cdb.CONTENT_DATABASES if e.scanner == self.config.name]

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


def _over(name: str) -> timedelta:
    return cdb.get(name).max_age + timedelta(hours=1)


def _under(name: str) -> timedelta:
    return cdb.get(name).max_age - timedelta(hours=1)


@pytest.mark.parametrize("name", sorted(CASES))
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

    def test_trivy_without_a_database_is_unknown_and_counts_as_stale(self, tmp_path):
        exe = fake_trivy(tmp_path, None)
        record = staleness.measure(
            cdb.get("trivy-db"),
            staleness.ProbeContext(env=dict(os.environ), executable=str(exe)),
            cdb.STALENESS_FAIL,
        )
        assert record.built is None and record.stale and record.enforced
        assert "could not be read" in record.message()

    def test_a_missing_executable_is_unknown_not_fresh(self):
        record = staleness.measure(
            cdb.get("grype-db"),
            staleness.ProbeContext(env={}, executable=None),
            cdb.STALENESS_FAIL,
        )
        assert record.stale and "not found" in (record.error or "")

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

    def test_a_report_with_no_runs_still_carries_the_record(self, tmp_path):
        """merge_sarif_report drops a runless report, so the record must create a run."""
        scanner = _grype_case(tmp_path, timedelta(days=10))
        sarif = SarifReport(version="2.1.0", runs=[])
        staleness.assess_scanner(scanner, sarif, cdb.STALENESS_FAIL)
        assert staleness.stale_content_databases(_aggregate(sarif), enforced_only=True)


# --------------------------------------------------------------------------- reading it back


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
            (["--allow-stale-content-db"], "content_db_staleness=warn"),
            (["--no-allow-stale-content-db"], "content_db_staleness=fail"),
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
        assert staleness_overrides == ([expected] if expected else [])

    def test_a_runtime_patch_cannot_downgrade_the_policy(self):
        from automated_security_helper.config.ash_config import RuntimeOverridesConfig

        assert "/content_db_staleness" in RuntimeOverridesConfig().denied_paths


# --------------------------------------------------------------------------- the registry


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
        declared = {e.scanner for e in cdb.CONTENT_DATABASES}
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
        for name in {e.scanner for e in cdb.CONTENT_DATABASES} | set(
            cdb.SCANNERS_WITHOUT_CONTENT_DATABASE
        ):
            assert name in scanners, name

    def test_the_gate_can_fail(self):
        """A CACHE_FLAGS scanner nobody declared would be reported."""
        scanners = set(self._cache_scanners()) | {"a-new-db-scanner"}
        declared = {e.scanner for e in cdb.CONTENT_DATABASES}
        explained = set(cdb.SCANNERS_WITHOUT_CONTENT_DATABASE)
        assert sorted(scanners - declared - explained) == ["a-new-db-scanner"]
