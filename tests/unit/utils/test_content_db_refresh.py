# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""grype's and trivy's databases are updated outside the sandbox, before the scan.

A scanner sandbox mounts their caches read-only, so neither can update its own
database there: measured, trivy failed online once its database was past
NextUpdate and grype once its database was past its age bound. ASH updates the
database first, unsandboxed and isolated from the scanned repository, and the
scanner then runs with its update turned off. See utils/content_db_refresh.py.
"""

import os
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.utils import content_db_refresh as refresh
from automated_security_helper.utils.sandbox import SandboxRequirements
from automated_security_helper.utils.sandbox.scope import (
    SandboxScope,
    active_scope,
    sandbox_scope,
)


@pytest.fixture(autouse=True)
def _fresh_memo():
    refresh.forget_prepared()
    yield
    refresh.forget_prepared()


def _scope(tmp_path) -> SandboxScope:
    return SandboxScope(
        backend=object(),
        scanner_name="grype",
        requirements=SandboxRequirements(),
        source_dir=tmp_path,
        output_dir=tmp_path / "out",
        results_dir=tmp_path / "out" / "scanners" / "grype",
        scan_target=tmp_path,
        offline=False,
    )


class _Recorder:
    """Stands in for spawn_run and records each call as the tool would see it."""

    def __init__(self, returncode=0, stderr=""):
        self.calls = []
        self.returncode = returncode
        self.stderr = stderr

    def __call__(self, argv, **kwargs):
        config = Path(argv[argv.index("-c" if "-c" in argv else "--config") + 1])
        self.calls.append(
            SimpleNamespace(
                argv=list(argv),
                cwd=Path(kwargs["cwd"]),
                env=dict(kwargs["env"]),
                scope=active_scope(),
                config_text=config.read_text(),
                last_is_empty_dir=Path(argv[-1]).is_dir()
                and not any(Path(argv[-1]).iterdir()),
            )
        )
        return subprocess.CompletedProcess(argv, self.returncode, "", self.stderr)


@pytest.fixture
def recorder(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(refresh, "spawn_run", rec)
    return rec


def test_offline_nothing_runs(recorder, tmp_path):
    refresh.prepare_content_db("grype", tmp_path, offline=True, executable="grype")
    refresh.prepare_content_db("trivy", tmp_path, offline=True, executable="trivy")
    assert recorder.calls == []


def test_grype_is_updated_outside_the_sandbox_and_away_from_the_repo(
    recorder, tmp_path
):
    cache = tmp_path / "grype-db"
    with sandbox_scope(_scope(tmp_path)):
        refresh.prepare_content_db("grype", cache, offline=False, executable="grype")
        # The caller's sandbox is back once the refresh is done.
        assert isinstance(active_scope(), SandboxScope)
    (call,) = recorder.calls
    assert call.scope is None, "the update ran inside the scanner sandbox"
    assert call.argv[:3] == ["grype", "db", "update"]
    assert call.argv[3] == "-c" and call.config_text == ""
    assert call.env["GRYPE_DB_CACHE_DIR"] == cache.as_posix()
    # pytest runs from this checkout: the update must not, so no .grype.yaml in
    # a working directory can reach it.
    assert call.cwd != Path.cwd()
    assert not any((p / ".git").exists() for p in [call.cwd, *call.cwd.parents])


def test_trivy_gets_its_database_and_when_asked_its_checks_bundle(recorder, tmp_path):
    cache = tmp_path / "trivy"
    refresh.prepare_content_db(
        "trivy", cache, offline=False, checks=True, executable="trivy"
    )
    db, checks = recorder.calls
    for call in (db, checks):
        assert call.scope is None
        assert call.config_text == ""
        assert call.argv[call.argv.index("--cache-dir") + 1] == cache.as_posix()
        assert call.cwd != Path.cwd()
    assert db.argv[1:3] == ["image", "--download-db-only"]
    # trivy fetches its checks bundle by checking configuration; here, of nothing.
    assert checks.argv[1] == "config" and checks.last_is_empty_dir


def test_without_checks_trivy_only_updates_its_database(recorder, tmp_path):
    refresh.prepare_content_db("trivy", tmp_path, offline=False, executable="trivy")
    assert [c.argv[1] for c in recorder.calls] == ["image"]


def test_once_per_scan(recorder, tmp_path):
    for _ in range(3):
        refresh.prepare_content_db(
            "grype", tmp_path, offline=False, scan_id="scan-1", executable="grype"
        )
    refresh.prepare_content_db(
        "grype", tmp_path, offline=False, scan_id="scan-2", executable="grype"
    )
    assert len(recorder.calls) == 2


def test_a_failed_update_raises_with_the_tools_words_and_is_retried(
    monkeypatch, tmp_path
):
    failing = _Recorder(returncode=1, stderr="unable to download the database")
    monkeypatch.setattr(refresh, "spawn_run", failing)
    for _ in range(2):
        with pytest.raises(ScannerError, match="unable to download the database"):
            refresh.prepare_content_db(
                "grype", tmp_path, offline=False, scan_id="s", executable="grype"
            )
    assert len(failing.calls) == 2, "a failure must not count as prepared"


def test_the_lock_lives_in_the_cache_or_beside_it(tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    assert refresh.update_lock_path("trivy", cache) == cache / ".ash-trivy-update.lock"
    if os.name != "nt" and os.geteuid() != 0:
        cache.chmod(0o500)
        try:
            outside = refresh.update_lock_path("trivy", cache)
            assert outside.parent != cache
            assert outside.name.startswith("ash-trivy-update-")
        finally:
            cache.chmod(0o700)


def test_the_cache_is_where_the_sandboxed_tool_looks(tmp_path):
    home = Path.home()
    assert refresh.default_cache_dir("grype", {}) == home / ".cache" / "grype" / "db"
    assert refresh.default_cache_dir("trivy", {}) == home / ".cache" / "trivy"
    env = {
        "GRYPE_DB_CACHE_DIR": str(tmp_path / "g"),
        "TRIVY_CACHE_DIR": str(tmp_path / "t"),
    }
    assert refresh.default_cache_dir("grype", env) == tmp_path / "g"
    assert refresh.default_cache_dir("trivy", env) == tmp_path / "t"


def test_threads_of_one_scan_take_turns(monkeypatch, tmp_path):
    spans = []

    def slow(argv, **kwargs):
        start = time.monotonic()
        time.sleep(0.2)  # stands in for a download
        spans.append((start, time.monotonic()))
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(refresh, "spawn_run", slow)
    threads = [
        threading.Thread(
            target=refresh.prepare_content_db,
            args=("trivy", tmp_path, False),
            kwargs={"executable": "trivy"},
        )
        for _ in range(3)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    _assert_no_overlap(spans)


@pytest.mark.skipif(os.name == "nt", reason="the cross-process lock is POSIX flock")
def test_two_scans_in_separate_processes_take_turns(tmp_path):
    """Two ASH processes sharing a cache must not update it at the same time."""
    log = tmp_path / "spans.log"
    tool = tmp_path / "grype"
    tool.write_text(
        textwrap.dedent(
            f"""\
            #!{sys.executable}
            import time
            start = time.time()
            time.sleep(0.5)
            with open({str(log)!r}, "a") as f:
                f.write(f"{{start}} {{time.time()}}\\n")
            """
        )
    )
    tool.chmod(0o755)
    cache = tmp_path / "cache"
    program = textwrap.dedent(
        f"""\
        from automated_security_helper.utils.content_db_refresh import prepare_content_db
        prepare_content_db("grype", {str(cache)!r}, offline=False, executable={str(tool)!r})
        """
    )
    procs = [
        subprocess.Popen([sys.executable, "-c", program])  # nosec B603 - fixed argv
        for _ in range(2)
    ]
    assert [p.wait(timeout=60) for p in procs] == [0, 0]
    spans = [tuple(map(float, line.split())) for line in log.read_text().splitlines()]
    assert len(spans) == 2
    _assert_no_overlap(spans)


def _assert_no_overlap(spans):
    ordered = sorted(spans)
    for (_, end), (start, _) in zip(ordered, ordered[1:]):
        assert start >= end, f"two updates ran at once: {ordered}"


class TestScannersUseThePreparedDatabase:
    """The scanners refresh before a sandboxed online scan, then skip their own."""

    @pytest.fixture
    def prepared(self, monkeypatch):
        calls = []

        def record(tool, cache_dir, offline, **kwargs):
            calls.append(
                SimpleNamespace(
                    tool=tool, cache_dir=Path(cache_dir), offline=offline, **kwargs
                )
            )

        from automated_security_helper.plugin_modules.ash_builtin.scanners import (
            grype_scanner,
        )
        from automated_security_helper.plugin_modules.ash_trivy_plugins import (
            trivy_repo_scanner,
        )

        monkeypatch.setattr(grype_scanner, "prepare_content_db", record)
        monkeypatch.setattr(trivy_repo_scanner, "prepare_content_db", record)
        monkeypatch.delenv("ASH_OFFLINE", raising=False)
        return calls

    def _grype(self, context):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
            GrypeScanner,
            GrypeScannerConfig,
        )

        scanner = GrypeScanner(context=context, config=GrypeScannerConfig())
        scanner._process_config_options()
        return scanner

    def test_grype_sandboxed_online(self, prepared, test_plugin_context, tmp_path):
        scanner = self._grype(test_plugin_context)
        with sandbox_scope(_scope(tmp_path)):
            _, _, env = scanner._execute_scan(tmp_path, "source", [])
        (call,) = prepared
        assert call.tool == "grype" and call.offline is False
        assert call.cache_dir == refresh.default_cache_dir("grype", env)
        for name, value in refresh.GRYPE_PREPARED_ENV.items():
            assert env[name] == value, name

    def test_grype_unsandboxed_updates_itself(
        self, prepared, test_plugin_context, tmp_path
    ):
        scanner = self._grype(test_plugin_context)
        _, _, env = scanner._execute_scan(tmp_path, "source", [])
        assert prepared == []
        assert (env or {}).get("GRYPE_DB_AUTO_UPDATE") != "false"

    def test_grype_sandboxed_offline_refreshes_nothing(
        self, prepared, test_plugin_context, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("ASH_OFFLINE", "YES")
        scanner = self._grype(test_plugin_context)
        with sandbox_scope(_scope(tmp_path)):
            scanner._execute_scan(tmp_path, "source", [])
        assert prepared == []

    def test_trivy_repo_sandboxed_online_skips_its_update(
        self, prepared, test_plugin_context, tmp_path, monkeypatch
    ):
        from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
            TrivyRepoScanner,
            TrivyRepoScannerConfig,
        )

        scanner = TrivyRepoScanner(
            context=test_plugin_context, config=TrivyRepoScannerConfig()
        )
        scanner._process_config_options()
        # trivy need not be installed for this: what is asserted is the command
        # the scanner builds, and the run itself is replaced below.
        monkeypatch.setattr(scanner, "validate_plugin_dependencies", lambda: True)
        commands = []
        monkeypatch.setattr(
            scanner,
            "_run_subprocess",
            lambda command, **kwargs: commands.append(list(command)) or {},
        )
        target = tmp_path / "repo"
        target.mkdir()
        (target / "requirements.txt").write_text("requests==2.19.0\n")
        with sandbox_scope(_scope(tmp_path)):
            scanner.scan(target, "source")
        (call,) = prepared
        assert call.tool == "trivy" and call.offline is False
        assert call.checks == ("misconfig" in scanner.config.options.scanners)
        (command,) = commands
        assert command[:2] == ["trivy", "repository"]
        assert "--skip-db-update" in command
        assert "--cache-backend=memory" in command


def test_grypes_macos_default_is_under_library_caches(monkeypatch, tmp_path):
    """The refresh writes where grype reads on macOS, not under ~/.cache."""
    from automated_security_helper.utils import content_db_refresh

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(content_db_refresh.sys, "platform", "darwin")
    assert content_db_refresh.default_cache_dir("grype", {}) == (
        Path.home() / "Library" / "Caches" / "grype" / "db"
    )
    monkeypatch.setattr(content_db_refresh.sys, "platform", "linux")
    assert content_db_refresh.default_cache_dir("grype", {}) == (
        Path.home() / ".cache" / "grype" / "db"
    )
    assert (
        content_db_refresh.default_cache_dir(
            "grype", {"GRYPE_DB_CACHE_DIR": str(tmp_path / "db")}
        )
        == tmp_path / "db"
    )
