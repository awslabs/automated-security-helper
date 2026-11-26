# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Claims about ``ashx dependencies check --offline`` that the docs make on six pages.

how-to/run-offline.md (Check cached database ages) states what the command reads and
what each exit code means. reference/exit-codes.md repeats the exit codes, and
concepts/content-databases.md, getting-started/platform-teams.md and
personas/security-analyst.md send a reader who schedules rebuilds against the age
bounds to the command. Each test follows the pattern of test_page_claims.py in two
halves: ``assert_on_page`` checks that the sentence is still on its page, and the test
then runs the command against planted caches and checks the behavior the sentence
describes. A test goes red when either half moves.

Not pinned: the output text of the command (tests/unit/cli/test_dependencies_offline_check.py
holds it) and what a scan does with a stale database.
"""

from __future__ import annotations

import json
import socket
import sqlite3
import subprocess
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.utils.content_databases import OFFLINE_IMAGE_ENV
from tests.unit.docs.test_page_claims import CONTENT, EXIT_CODES, assert_on_page

pytestmark = pytest.mark.unit

RUN_OFFLINE = "how-to/run-offline.md"
CONTENT_DATABASES = "concepts/content-databases.md"
PLATFORM_TEAMS = "getting-started/platform-teams.md"
SECURITY_ANALYST = "personas/security-analyst.md"

COMMAND = "`ashx dependencies check --offline`"


@pytest.fixture
def host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv(OFFLINE_IMAGE_ENV, raising=False)
    monkeypatch.setenv("GRYPE_DB_CACHE_DIR", str(tmp_path / "grype cache"))
    monkeypatch.setenv("TRIVY_CACHE_DIR", str(tmp_path / "trivy cache"))
    return tmp_path


def _stamp(hours: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()


def _grype(host: Path, built: str, *, model: int = 6) -> Path:
    path = host / "grype cache" / "6" / "vulnerability.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as db, db:
        db.execute(
            "CREATE TABLE db_metadata (build_timestamp datetime NOT NULL, "
            "model integer NOT NULL, revision integer NOT NULL, addition integer NOT NULL)"
        )
        db.execute("INSERT INTO db_metadata VALUES (?, ?, 1, 10)", (built, model))
    return path


def _trivy(host: Path, updated: str, *, version: int = 2) -> Path:
    path = host / "trivy cache" / "db" / "trivy.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"nonempty bbolt stand-in")
    path.with_name("metadata.json").write_text(
        json.dumps({"Version": version, "UpdatedAt": updated}), encoding="utf-8"
    )
    return path


def _check(*args: str) -> Any:
    return CliRunner().invoke(app, ["dependencies", "check", "--offline", *args])


def _refuse_processes_and_network(monkeypatch: pytest.MonkeyPatch) -> List[str]:
    """Make any subprocess or outbound connection fail the test, and say which."""
    attempts: List[str] = []

    def refuse(kind: str):
        def _refused(*args: Any, **kwargs: Any) -> Any:
            attempts.append(kind)
            raise AssertionError(f"the check reached for a {kind}")

        return _refused

    monkeypatch.setattr(subprocess, "Popen", refuse("subprocess"))
    monkeypatch.setattr(subprocess, "run", refuse("subprocess"))
    monkeypatch.setattr(socket.socket, "connect", refuse("network connection"))
    return attempts


def test_exit_zero_means_the_caches_meet_the_policy_including_a_permitted_stale_one(
    host: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """run-offline.md and exit-codes.md (Exit 0).

    A fresh cache exits 0. A stale cache exits 1 under the default policy and 0 under
    ``warn``, and says it is stale either way, so the exit code and the page agree.
    """
    assert_on_page(
        RUN_OFFLINE,
        "Exit 0 means the checked cache metadata meets the policy, including a stale "
        "cache permitted by `warn`.",
    )
    assert_on_page(
        EXIT_CODES,
        "| 0 | Every checked cache meets the policy, including a stale cache that the "
        "policy permits with `warn` |",
    )
    _refuse_processes_and_network(monkeypatch)
    _grype(host, _stamp(1).replace("T", " "))
    _trivy(host, _stamp(1))
    fresh = _check()
    assert fresh.exit_code == 0, fresh.output
    assert "grype: fresh" in fresh.stdout and "trivy: fresh" in fresh.stdout

    _trivy(host, _stamp(30))
    stale_default = _check("--tool", "trivy")
    assert stale_default.exit_code == 1, stale_default.output
    assert "trivy: stale" in stale_default.stdout
    stale_warn = _check("--tool", "trivy", "--allow-stale-content-db")
    assert stale_warn.exit_code == 0, stale_warn.output
    assert "trivy: stale" in stale_warn.stdout
    assert "policy: warn" in stale_warn.stdout


def test_exit_one_means_missing_unreadable_or_blocked_by_policy(
    host: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """run-offline.md and exit-codes.md (Exit 1).

    Missing and unreadable metadata exit 1 even under ``warn``; a stale cache exits 1
    only when the policy is ``fail``. The warn run is the control that tells the three
    reasons apart from a check that always exits 1.
    """
    assert_on_page(
        RUN_OFFLINE,
        "Exit 1 means a cache is missing, its metadata cannot be read, or policy "
        "blocks its age.",
    )
    assert_on_page(
        EXIT_CODES,
        "| 1 | A checked cache is missing, its metadata cannot be read or has an "
        "unsupported schema, or the policy blocks its age |",
    )
    _refuse_processes_and_network(monkeypatch)
    missing = _check("--tool", "grype", "--allow-stale-content-db")
    assert missing.exit_code == 1, missing.output
    assert "grype: missing" in missing.stdout

    _grype(host, _stamp(1), model=5)
    unsupported = _check("--tool", "grype", "--allow-stale-content-db")
    assert unsupported.exit_code == 1, unsupported.output
    assert "grype: invalid" in unsupported.stdout

    path = _trivy(host, _stamp(1))
    path.with_name("metadata.json").write_text("not json", encoding="utf-8")
    unreadable = _check("--tool", "trivy", "--allow-stale-content-db")
    assert unreadable.exit_code == 1, unreadable.output
    assert "trivy: invalid" in unreadable.stdout

    _trivy(host, _stamp(30))
    blocked = _check("--tool", "trivy")
    permitted = _check("--tool", "trivy", "--allow-stale-content-db")
    assert (blocked.exit_code, permitted.exit_code) == (1, 0)


def test_the_check_neither_downloads_nor_starts_a_scanner(
    host: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """run-offline.md (Check cached database ages).

    Subprocesses and outbound connections are refused at the process boundary, and
    every cache file keeps its bytes. The refusal is armed by a control that proves it
    fires, so a check that stopped reaching for either would not pass by accident.
    """
    assert_on_page(
        RUN_OFFLINE, "The check neither downloads data nor starts a scanner."
    )
    attempts = _refuse_processes_and_network(monkeypatch)
    with pytest.raises(AssertionError):
        subprocess.run(["true"])
    assert attempts == ["subprocess"]
    attempts.clear()

    _grype(host, _stamp(1).replace("T", " "))
    _trivy(host, _stamp(1))
    before: Dict[Path, bytes] = {
        p: p.read_bytes() for p in host.rglob("*") if p.is_file()
    }
    result = _check()
    assert result.exit_code == 0, result.output
    assert attempts == []
    assert {p: p.read_bytes() for p in host.rglob("*") if p.is_file()} == before


def test_the_schemas_the_page_names_are_the_ones_the_check_accepts(
    host: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """run-offline.md (Check cached database ages).

    "Grype's schema 6 SQLite metadata and Trivy's schema 2 `metadata.json`": a cache
    with exactly that schema is read; one with the neighboring schema is refused.
    """
    assert_on_page(
        RUN_OFFLINE,
        "The check reads Grype's schema 6 SQLite metadata and Trivy's schema 2 "
        "`metadata.json`.",
    )
    _refuse_processes_and_network(monkeypatch)
    _grype(host, _stamp(1), model=6)
    _trivy(host, _stamp(1), version=2)
    assert _check().exit_code == 0

    grype_path = host / "grype cache" / "6" / "vulnerability.db"
    grype_path.unlink()
    for model in (5, 7):
        _grype(host, _stamp(1), model=model)
        refused = _check("--tool", "grype")
        assert refused.exit_code == 1 and "grype: invalid" in refused.stdout, model
        grype_path.unlink()
    for version in (1, 3):
        _trivy(host, _stamp(1), version=version)
        refused = _check("--tool", "trivy")
        assert refused.exit_code == 1 and "trivy: invalid" in refused.stdout, version


def test_the_other_exit_codes_the_exit_codes_page_lists(
    host: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """exit-codes.md (`ashx dependencies check`).

    A named ``--config`` that does not exist exits 3 and a call without ``--offline``
    exits 5, and neither prints a cache reading.
    """
    assert_on_page(EXIT_CODES, "## `ashx dependencies check` {#dependencies-check}")
    assert_on_page(EXIT_CODES, "| 3 | The `--config` file cannot be used |")
    assert_on_page(
        EXIT_CODES, "| 5 | A usage error, including a call without `--offline` |"
    )
    assert_on_page(
        EXIT_CODES,
        "The check downloads nothing and starts no scanner (Check cached database ages).",
    )
    _refuse_processes_and_network(monkeypatch)
    bad_config = _check("--config", str(host / "missing.yaml"))
    assert bad_config.exit_code == 3, bad_config.output
    assert "grype:" not in bad_config.stdout
    no_offline = CliRunner().invoke(app, ["dependencies", "check"])
    assert no_offline.exit_code == 5, no_offline.output
    assert "grype:" not in no_offline.stdout


@pytest.mark.parametrize(
    "page, sentence",
    [
        (
            CONTENT_DATABASES,
            (
                "To read the age of the cached grype and trivy databases against these "
                "bounds without running a scan, use `ashx dependencies check --offline` "
                "(Check cached database ages)."
            ),
        ),
        (
            PLATFORM_TEAMS,
            (
                "To read the age of the cached grype and trivy databases against those "
                "bounds without running a scan, use `ashx dependencies check --offline` "
                "(Check cached database ages)."
            ),
        ),
        (
            SECURITY_ANALYST,
            (
                "`ashx dependencies check --offline` reads the age of the cached "
                "databases against those bounds without running a scan "
                "(Check cached database ages)."
            ),
        ),
    ],
)
def test_the_pages_that_schedule_rebuilds_route_to_the_check(
    page: str, sentence: str
) -> None:
    """content-databases.md, platform-teams.md and security-analyst.md.

    The sentence is on the page, the command it names exists with the options the
    sentence implies, and the anchor its link ends in is a heading of run-offline.md.
    """
    assert_on_page(page, sentence)
    assert COMMAND.strip("`") in sentence
    assert "{#check-caches}" in (CONTENT / RUN_OFFLINE).read_text(encoding="utf-8")
    assert "(../how-to/run-offline.md#check-caches)" in (CONTENT / page).read_text(
        encoding="utf-8"
    )
    helped = CliRunner().invoke(app, ["dependencies", "check", "--help"])
    assert helped.exit_code == 0, helped.output
    assert "--offline" in helped.stdout
