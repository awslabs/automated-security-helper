# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Express mode end to end: the daemon's scan held to the cold run's.

The whole feature rests on one invariant: a scan through the daemon is the
cold run, merely without the startup -- same exit code, same reports, same
findings. These tests run the real CLI as a subprocess (the module entry the
console scripts route through), start the real daemon, and hold an express scan
to a cold scan of the same tree: that parity assertion is the contract that
keeps the daemon honest. Around it: the transparent path (socket exists ->
used), ``--no-express``, the stale-daemon cold fallback, idle exit and ``stop``.

e2e tier, and additionally gated on ``ASH_E2E_EXPRESS=1``: the required e2e jobs
run ``-m e2e`` over the whole tree on five runner labels, and these cells
belong to the advisory ``e2e-express`` job (two labels, one Python; see the
workflow note on that job), so without the variable everything here skips --
except the Windows refusal test at the bottom, which is exactly what the
required Windows e2e leg should say about express.

Every run gets a private XDG_RUNTIME_DIR, so no test and no other user of the
machine shares a daemon with another; it is made short (``mkdtemp`` under the
default temporary directory) because an AF_UNIX socket path is capped near 104
bytes and pytest's tmp_path can be longer than that by itself.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.e2e

#: The CLI as the installed console script runs it, which is the thin entry
#: point: the express client answers before the heavy import, so the measured
#: wall-clock delta is the real one. ``python -m automated_security_helper
#: .cli.main`` would import the whole CLI before the entry point even ran --
#: correct, but it pays cold-start cost on both sides of the parity and buries
#: the saving. The module form stays as the fallback for an environment whose
#: script is not beside the interpreter.
_ASH_SCRIPT = Path(sys.executable).parent / "ash"
if _ASH_SCRIPT.is_file():
    ASH = [os.fspath(_ASH_SCRIPT)]
else:
    ASH = [sys.executable, "-m", "automated_security_helper.cli.main"]
    # Said out loud in the run's output: a parity delta measured through the
    # module form is dominated by the import both sides pay, so a small delta
    # from such a run is the harness's shape, not a defect.
    print(
        "e2e-express: no console script beside the interpreter; running the "
        "module form, whose warm-vs-cold delta understates the real saving.",
        file=sys.stderr,
    )

_GATED = os.environ.get("ASH_E2E_EXPRESS") != "1"
gated = pytest.mark.skipif(
    _GATED,
    reason="express e2e cells run only in the advisory e2e-express job (ASH_E2E_EXPRESS=1)",
)
posix_only = pytest.mark.skipif(os.name != "posix", reason="express mode is unix-only")


def _runtime_base() -> str:
    base = tempfile.mkdtemp(prefix="ash-x")
    if len(base) > 60:
        # The default temporary directory (a CI lane's TMPDIR, say) can be
        # longer than an AF_UNIX socket name allows; /tmp never is.
        shutil.rmtree(base, ignore_errors=True)
        base = tempfile.mkdtemp(prefix="ash-x", dir="/tmp")
    # ~40 bytes of socket name land under this; stay clear of the AF_UNIX cap.
    assert len(base) < 68, f"temporary directory too long for a socket: {base}"
    return base


@pytest.fixture
def express_env():
    """A subprocess environment with a private daemon world, torn down after."""
    base = _runtime_base()
    env = dict(os.environ)
    env["XDG_RUNTIME_DIR"] = base
    env.pop("ASH_EXPRESS_CHILD", None)
    yield env
    _run(env, "express", "stop")
    shutil.rmtree(base, ignore_errors=True)


def _run(env, *argv, cwd=None, timeout=600):
    return subprocess.run(
        [*ASH, *argv],
        env=env,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _write_tree(root) -> None:
    """A tiny tree with one deterministic detect-secrets finding.

    The credential is assembled at run time so no secret-shaped literal sits in
    this repository for other scanners to report.
    """
    root.mkdir(parents=True, exist_ok=True)
    marker = "AKIA" + "IOSFODNN7EXAMPLE"
    (root / "app.py").write_text(
        f'ACCESS_KEY = "{marker}"\n'
        'SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY' + 'EXAMPLEKEY"\n',
        encoding="utf-8",
    )
    (root / "README.md").write_text("a tree for the express parity scan\n")


def _scan(env, tree, out, *extra):
    return _run(
        env,
        "scan",
        "--source-dir",
        os.fspath(tree),
        "--output-dir",
        os.fspath(out),
        "--scanners",
        "detect-secrets",
        "--no-progress",
        "--quiet",
        *extra,
    )


def _rule_ids(results_file) -> list:
    """Every ``ruleId`` in the aggregated results, schema-agnostically."""
    found = []

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "ruleId" and isinstance(value, str):
                    found.append(value)
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(json.loads(results_file.read_text(encoding="utf-8")))
    return sorted(found)


def _report_names(out) -> set:
    reports = out / "reports"
    if not reports.is_dir():
        return set()
    return {path.name for path in reports.iterdir()}


def _status(env) -> dict:
    answer = _run(env, "express", "status", "--json")
    if answer.returncode != 0:
        return {"running": False}
    return json.loads(answer.stdout.strip().splitlines()[-1])


def _socket_path(env) -> str:
    status = _run(env, "express", "status", "--json")
    payload = json.loads(status.stdout.strip().splitlines()[-1])
    return payload["socket"]


@gated
@posix_only
class TestExpressParity:
    def test_a_express_scan_is_the_cold_scan_without_the_startup(
        self, express_env, tmp_path
    ):
        tree = tmp_path / "tree"
        _write_tree(tree)

        # The cold reference: --no-express forces the ordinary in-process run
        # whatever daemons exist.
        cold_out = tmp_path / "cold"
        cold_started = time.monotonic()
        cold = _scan(express_env, tree, cold_out, "--no-express")
        cold_wall = time.monotonic() - cold_started
        assert cold.returncode == 2, (cold.stdout, cold.stderr)

        started = _run(express_env, "express", "start")
        assert started.returncode == 0, (started.stdout, started.stderr)
        before = _status(express_env)
        assert before.get("running") is True

        # The transparent path: no --express flag; the socket's existence routes it.
        express_out = tmp_path / "express"
        express_started = time.monotonic()
        express = _scan(express_env, tree, express_out)
        express_wall = time.monotonic() - express_started
        assert express.returncode == 2, (express.stdout, express.stderr)

        # THE PARITY CONTRACT. Exit codes equal; the same report files were
        # written; the same findings (every SARIF ruleId, multiset) were found.
        # Timestamps and durations differ by nature, so byte-equality is
        # asserted over the invariant content rather than the whole file.
        assert express.returncode == cold.returncode
        assert _report_names(express_out) == _report_names(cold_out)
        cold_rules = _rule_ids(cold_out / "ash_aggregated_results.json")
        express_rules = _rule_ids(express_out / "ash_aggregated_results.json")
        assert express_rules == cold_rules
        assert cold_rules, "the parity ran on an empty finding set"

        after = _status(express_env)
        assert after.get("scans_served", 0) >= before.get("scans_served", 0) + 1, (
            "the transparent scan did not go through the daemon, so the parity "
            "above compared two cold runs"
        )
        # Informational, printed for the job log: the startup the daemon removed.
        print(
            f"express wall {express_wall:.2f}s vs cold wall {cold_wall:.2f}s "
            f"(delta {cold_wall - express_wall:+.2f}s)"
        )

    def test_no_express_is_honored_while_the_daemon_runs(self, express_env, tmp_path):
        tree = tmp_path / "tree"
        _write_tree(tree)
        assert _run(express_env, "express", "start").returncode == 0
        before = _status(express_env)
        cold = _scan(express_env, tree, tmp_path / "out", "--no-express")
        assert cold.returncode == 2, (cold.stdout, cold.stderr)
        after = _status(express_env)
        assert after["scans_served"] == before["scans_served"]

    def test_a_stale_daemon_means_a_cold_run(self, express_env, tmp_path):
        """A fake daemon at the real socket path answers every request with a
        staleness refusal (the shape a changed package set produces). The scan
        must still succeed -- silently and cold on the transparent path, with
        one stderr note under --express -- and never run through the impostor.

        The fake reads the request frame whole before answering and closes the
        descriptors it was passed: answered before the request was read, the
        refusal raced the client's own send (either side could read as a
        generic broken handshake instead of the stale branch), and the passed
        stdout/stderr descriptors held the client's pipes open past its exit,
        which is a hang for anyone collecting its output.
        """
        import socket as socket_module
        import threading

        from automated_security_helper.express import runtime as express_runtime

        probe = _run(express_env, "express", "status", "--json")
        payload = json.loads(probe.stdout.strip().splitlines()[-1])
        socket_path = payload["socket"]
        os.makedirs(os.path.dirname(socket_path), mode=0o700, exist_ok=True)

        server = socket_module.socket(socket_module.AF_UNIX, socket_module.SOCK_STREAM)
        server.bind(socket_path)
        server.listen(4)
        refused = []

        def serve():
            while True:
                try:
                    conn, _ = server.accept()
                except OSError:
                    return
                with conn:
                    fds = []
                    try:
                        _, fds, _, _ = socket_module.recv_fds(conn, 1, 3)
                        request = express_runtime.FrameReader(conn).read_frame()
                        refused.append(request or {})
                        express_runtime.send_frame(
                            conn,
                            {
                                "ok": False,
                                "reason": "the daemon is stale",
                                "stale": True,
                            },
                        )
                    except (OSError, express_runtime.ExpressProtocolError):
                        pass
                    finally:
                        for fd in fds:
                            try:
                                os.close(fd)
                            except OSError:
                                pass

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            tree = tmp_path / "tree"
            _write_tree(tree)
            # The transparent path: silent, cold, correct.
            scan = _scan(express_env, tree, tmp_path / "out")
            assert scan.returncode == 2, (scan.stdout, scan.stderr)
            assert refused, "the client never consulted the daemon socket"
            assert "ash express" not in scan.stderr, scan.stderr
            results = tmp_path / "out" / "ash_aggregated_results.json"
            assert results.is_file(), "the cold fallback did not scan"
            # --express: the stale branch is taken out loud. The client stops
            # the impostor (which ignores the stop), tries to start a fresh
            # daemon, is refused again, says so, and still scans cold.
            loud = _scan(express_env, tree, tmp_path / "out2", "--express")
            assert loud.returncode == 2, (loud.stdout, loud.stderr)
            assert "refused the scan" in loud.stderr, loud.stderr
            assert (tmp_path / "out2" / "ash_aggregated_results.json").is_file()
        finally:
            server.close()
            try:
                os.unlink(socket_path)
            except OSError:
                pass

    def test_idle_exit_retires_the_daemon(self, express_env):
        env = dict(express_env)
        env["ASH_EXPRESS_IDLE_SECONDS"] = "2"
        assert _run(env, "express", "start").returncode == 0
        socket_path = _socket_path(env)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and os.path.exists(socket_path):
            time.sleep(0.5)
        assert not os.path.exists(socket_path), "the idle daemon did not retire"

    def test_stop_retires_the_daemon_and_start_is_idempotent(self, express_env):
        assert _run(env := express_env, "express", "start").returncode == 0
        again = _run(env, "express", "start")
        assert again.returncode == 0
        assert "already running" in again.stdout
        stopped = _run(env, "express", "stop")
        assert stopped.returncode == 0
        status = _run(env, "express", "status")
        assert status.returncode == 1
        assert "not running" in status.stdout


@pytest.mark.skipif(os.name == "posix", reason="the refusal is the non-unix answer")
class TestWindowsRefusal:
    """What the required Windows e2e leg asserts about express: the clean refusal.

    Not gated on ASH_E2E_EXPRESS: this is the one express test that belongs in the
    ordinary e2e tier, because the refusal is the whole of express mode on a
    platform without unix sockets.
    """

    def test_express_start_refuses_cleanly_off_unix(self):
        result = subprocess.run(
            [*ASH, "express", "start"], capture_output=True, text=True, timeout=600
        )
        assert result.returncode == 5
        assert "express mode is unavailable here" in result.stderr
        assert "Traceback" not in result.stderr

    def test_a_scan_with_express_flag_still_parses_off_unix(self):
        """--express is accepted everywhere; off unix it simply means a cold run.
        A help parse proves the flag exists without paying for a scan."""
        result = subprocess.run(
            [*ASH, "scan", "--help"], capture_output=True, text=True, timeout=600
        )
        assert result.returncode == 0
        assert "--express" in result.stdout
        assert "--no-express" in result.stdout
