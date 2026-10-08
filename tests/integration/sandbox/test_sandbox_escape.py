# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A malicious scanner tries to escape; every attempt fails under each sandbox.

The scanner is ``tests/test_data/sandbox_escape``: a third-party-style plugin whose tool
(escape_probe.py) tries to read a planted ~/.ssh key and a file outside the source
tree, write outside its results directory, modify the source tree, open TCP and UDP
sockets under --offline, and read credentials from its environment and from other
processes' /proc/<pid>/environ. It runs through a real ``ashx scan``, so the spawn goes
through the same choke point as a builtin scanner.

``--sandbox off`` is the negative control: every attempt has to succeed there, which is
what proves the attempts are real and that a "blocked" under a sandbox is the sandbox's
doing, not a broken probe.

A backend that is not available on the machine is skipped, unless it is named in
ASH_REQUIRE_SANDBOX_BACKENDS (comma separated), which CI sets so a runner that lost
bubblewrap fails instead of skipping.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Dict, Iterator

import pytest

from automated_security_helper.cli.deprecations import CANONICAL_CLI_NAME
from automated_security_helper.utils.sandbox import clear_backend_cache, resolve_backend
from automated_security_helper.utils.sandbox.scope import SandboxUnavailable

pytestmark = pytest.mark.integration

FIXTURE = Path(__file__).resolve().parents[2] / "test_data" / "sandbox_escape"
CANARY = "ash-sandbox-canary-7b9e2f"
BACKENDS = ["bwrap", "firejail", "landlock", "sandbox-exec"]


def _required() -> set:
    raw = os.environ.get("ASH_REQUIRE_SANDBOX_BACKENDS", "")
    return {name.strip() for name in raw.split(",") if name.strip()}


def _require_backend(name: str) -> None:
    clear_backend_cache()
    try:
        resolve_backend(name)
    except SandboxUnavailable as e:
        if name in _required():
            pytest.fail(f"{name} is required (ASH_REQUIRE_SANDBOX_BACKENDS) but: {e}")
        pytest.skip(f"{name} unavailable: {e}")


class _Listeners:
    """TCP, UDP and Unix-socket echo-ack listeners the probe tries to reach."""

    def __init__(self, unix_path: Path) -> None:
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind(("0.0.0.0", 0))  # nosec B104 - test listener, closed after the test
        self.tcp.listen(8)
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.unix_path = unix_path
        self.unix = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.unix.bind(str(unix_path))
        self.unix.listen(8)
        self.received: list = []
        self._stop = False
        for target in (self._serve_tcp, self._serve_udp, self._serve_unix):
            threading.Thread(target=target, daemon=True).start()

    def _serve_unix(self) -> None:
        self.unix.settimeout(0.5)
        while not self._stop:
            try:
                conn, _ = self.unix.accept()
            except OSError:
                continue
            with conn:
                self.received.append(conn.recv(64))
                conn.sendall(b"ack")

    def _serve_tcp(self) -> None:
        self.tcp.settimeout(0.5)
        while not self._stop:
            try:
                conn, _ = self.tcp.accept()
            except OSError:
                continue
            with conn:
                self.received.append(conn.recv(64))
                conn.sendall(b"ack")

    def _serve_udp(self) -> None:
        self.udp.settimeout(0.5)
        while not self._stop:
            try:
                data, addr = self.udp.recvfrom(64)
            except OSError:
                continue
            self.received.append(data)
            self.udp.sendto(b"ack", addr)

    def close(self) -> None:
        self._stop = True
        self.tcp.close()
        self.udp.close()
        self.unix.close()


def _host_ip() -> str | None:
    """A non-loopback address of this host, or None when it has only loopback."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 9))  # TEST-NET-1; nothing is sent
        address = probe.getsockname()[0]
    except OSError:
        return None
    finally:
        probe.close()
    return None if address.startswith("127.") else address


@pytest.fixture
def listeners(tmp_path_factory) -> Iterator[_Listeners]:
    # A short directory of its own: Unix socket paths are limited to about 100 bytes.
    server = _Listeners(Path(tempfile.mkdtemp(prefix="ash-sbx-")) / "ipc.sock")
    yield server
    server.close()
    shutil.rmtree(server.unix_path.parent, ignore_errors=True)


def _ash_executable() -> str:
    # The canonical command, not the deprecated `ash`, whose own deprecation line
    # would land in the stderr this test reads.
    beside = Path(sys.executable).with_name(CANONICAL_CLI_NAME)
    found = str(beside) if beside.exists() else shutil.which(CANONICAL_CLI_NAME)
    if not found:
        pytest.fail(
            f"the {CANONICAL_CLI_NAME} entry point is not installed beside this "
            "interpreter"
        )
    return found


def _run_escape(tmp_path: Path, listeners: _Listeners, mode: str) -> Dict[str, str]:
    outcomes, result = _scan(tmp_path, listeners, mode)
    assert outcomes is not None, (
        f"the probe wrote no outcome (exit {result.returncode}). The scanner may have "
        f"been MISSING or failed to start.\nstdout:\n{result.stdout[-4000:]}\n"
        f"stderr:\n{result.stderr[-4000:]}"
    )
    return outcomes


def _scan(
    tmp_path: Path, listeners: _Listeners, mode: str
) -> "tuple[Dict[str, str] | None, subprocess.CompletedProcess]":
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "id_rsa").write_text(f"-----BEGIN KEY-----\n{CANARY}\n")
    # Inside $HOME so that every backend, firejail included, is expected to hide it.
    outside = home / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text(CANARY)
    for victim in ("victim-results.txt", "victim-log.txt"):
        (outside / victim).write_text("original\n")
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("print('hello')\n")
    shutil.copy(FIXTURE / "escape_probe.py", source / "escape_probe.py")
    (source / ".ash").mkdir()
    (source / ".ash" / ".ash.yaml").write_text(
        "project_name: sandbox-escape\nash_plugin_modules:\n  - escape_plugins\n"
    )
    output = tmp_path / "out"

    host_ip = _host_ip()
    spec = {
        "probe": str(source / "escape_probe.py"),
        "home": str(home),
        "secret": CANARY,
        "outside_file": str(outside / "secret.txt"),
        "outside_dir": str(outside),
        "output_dir": str(output),
        "source_dir": str(source),
        "tcp_port": listeners.tcp.getsockname()[1],
        "udp_port": listeners.udp.getsockname()[1],
        "host_ip": host_ip or "127.0.0.1",
        "unix_socket": str(listeners.unix_path),
        "victims": {
            "ASH.ScanResults.json": str(outside / "victim-results.txt"),
            "SandboxEscapeScanner.stdout.log": str(outside / "victim-log.txt"),
        },
        "shm_file": (
            f"/dev/shm/ash-sandbox-probe-{os.getpid()}-{mode}"  # nosec B108 - the probe's target; asserted never to appear
            if Path("/dev/shm").is_dir()  # nosec B108 - existence check only
            else ""
        ),
    }
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(json.dumps(spec))
    env = {
        **os.environ,
        "HOME": str(home),
        "PYTHONPATH": os.pathsep.join(
            [str(FIXTURE), os.environ.get("PYTHONPATH", "")]
        ).rstrip(os.pathsep),
        "AWS_SECRET_ACCESS_KEY": CANARY,
        # A path, not the document: ASH_* variables are passed into the sandbox, and
        # the spec carries the canary, which parent_environ would then find in the
        # sandbox's own init process.
        "ASH_SANDBOX_ESCAPE_SPEC": str(spec_file),
    }
    command = [
        _ash_executable(),
        "scan",
        "--source-dir",
        str(source),
        "--output-dir",
        str(output),
        "--scanners",
        "sandbox-escape",
        "--sandbox",
        mode,
        "--offline",
        "--no-progress",
        "--no-fail-on-findings",
    ]
    result = subprocess.run(  # nosec B603 - fixed argv
        command,
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    outcome_file = output / "scanners" / "sandbox-escape" / "source" / "outcome.json"
    if not outcome_file.exists():
        return None, result
    outcomes = json.loads(outcome_file.read_text())
    if host_ip is None:
        outcomes.pop("tcp_connect_host_address", None)
    outcomes["_source_untouched"] = (
        "succeeded"
        if (source / "app.py").read_text() != "print('hello')\n"
        or (source / "pwned.txt").exists()
        else "blocked: source tree unchanged"
    )
    # Planting the links is allowed (it is the scanner's own directory); what must
    # not happen is ASH writing through them afterwards.
    outcomes.pop("plant_symlinks", None)
    victims_intact = all(
        Path(v).read_text() == "original\n" for v in spec["victims"].values()
    )
    outcomes["_parent_writes_contained"] = (
        "blocked: ASH did not write through the planted links"
        if victims_intact
        else "succeeded"
    )
    if spec["shm_file"]:
        # Only the host side counts. bwrap gives the scanner a private /dev/shm, so
        # its write can succeed there without anything reaching the host.
        outcomes.pop("write_dev_shm", None)
        shm = Path(spec["shm_file"])
        outcomes["_shm_untouched"] = (
            "succeeded" if shm.exists() else "blocked: nothing left in /dev/shm"
        )
        shm.unlink(missing_ok=True)
    outcomes["_outside_untouched"] = (
        "succeeded"
        if (outside / "pwned.txt").exists() or (output / "pwned.txt").exists()
        else "blocked: nothing written outside the results directory"
    )
    return outcomes, result


def test_every_attempt_succeeds_without_a_sandbox(tmp_path, listeners):
    """The negative control. If this fails, the probe is broken, not the sandbox."""
    outcomes = _run_escape(tmp_path, listeners, "off")
    failed = {
        k: v
        for k, v in outcomes.items()
        if v != "succeeded" and k not in CONTROL_EXEMPT
    }
    assert not failed, f"attempts that should have succeeded unsandboxed: {failed}"
    assert any(CANARY.encode() in data for data in listeners.received)


#: What a blocked attempt may fail with. Anything else (a NameError, a TypeError,
#: a JSON error) is the probe breaking, which must not be scored as the sandbox
#: blocking it.
BLOCKED_BY = (
    "blocked: PermissionError",
    "blocked: FileNotFoundError",
    "blocked: OSError",
    "blocked: ConnectionRefusedError",
    "blocked: TimeoutError",
    "blocked: RuntimeError: credential not in the environment",
    "blocked: RuntimeError: no readable process environment held the credential",
    "blocked: source tree unchanged",
    "blocked: nothing written outside the results directory",
    "blocked: nothing left in /dev/shm",
    "blocked: ASH did not write through the planted links",
)


#: Attempts the negative control is not expected to make succeed, and why. Empty:
#: unsandboxed, ASH's writes behave exactly as open() and follow a planted link,
#: which is what makes _parent_writes_contained a real control.
CONTROL_EXEMPT: dict = {}

#: Attempts a backend is documented not to block (docs/content/docs/scanner-sandbox.md).
#: Listed here rather than skipped, so each one is asserted to be exactly the known
#: gap: an attempt in this table that starts being blocked fails too, as a stale entry.
KNOWN_GAPS = {
    "landlock": {
        "_shm_untouched": "Landlock cannot make /dev/shm private, and multiprocessing "
        "needs it for semaphores",
    },
}


@pytest.mark.parametrize("backend", BACKENDS)
def test_every_attempt_is_blocked_by_the_sandbox(
    tmp_path, tmp_path_factory, listeners, backend
):
    _require_backend(backend)
    # The negative control first, in the same test, so this test cannot pass on a
    # machine where the probe's attempts would have failed anyway.
    control = _run_escape(tmp_path_factory.mktemp("control"), listeners, "off")
    not_real = {
        k: v for k, v in control.items() if v != "succeeded" and k not in CONTROL_EXEMPT
    }
    assert not not_real, (
        f"the control could not escape either, so proves nothing: {not_real}"
    )
    listeners.received.clear()

    outcomes = _run_escape(tmp_path, listeners, backend)
    assert set(outcomes) == set(control), "the sandboxed run attempted different things"
    gaps = KNOWN_GAPS.get(backend, {})
    for name in gaps:
        if name in outcomes:
            assert outcomes.pop(name) == "succeeded", (
                f"{backend} now blocks {name}; remove it from KNOWN_GAPS and the docs"
            )
    escaped = {k: v for k, v in outcomes.items() if v == "succeeded"}
    assert not escaped, f"{backend} let these through: {json.dumps(escaped, indent=2)}"
    unexplained = {k: v for k, v in outcomes.items() if not v.startswith(BLOCKED_BY)}
    assert not unexplained, (
        f"attempts that failed for a reason other than the sandbox: {unexplained}"
    )
    assert not listeners.received, f"{backend} let data reach a listener"


def test_an_unavailable_sandbox_reports_missing_and_never_runs_the_scanner(
    tmp_path, listeners
):
    """Asking for a backend this machine lacks must not fall back to unsandboxed.

    sandbox-exec exists only on macOS and bwrap only on Linux, so one of the two is
    unavailable on every runner.
    """
    unavailable = "bwrap" if sys.platform == "darwin" else "sandbox-exec"
    outcomes, result = _scan(tmp_path, listeners, unavailable)
    # Whitespace collapsed: the console wraps long log lines at the terminal width.
    output = " ".join((result.stdout + result.stderr).split())
    assert outcomes is None, f"the scanner ran under an unavailable sandbox: {outcomes}"
    assert result.returncode == 1, output[-4000:]
    assert "sandbox-escape: MISSING" in output, output[-4000:]
    assert "scanner sandbox unavailable" in output, output[-4000:]
    results = json.loads((tmp_path / "out" / "ash_aggregated_results.json").read_text())
    row = results["scanner_results"]["sandbox-escape"]
    assert row["status"] == "MISSING"
    assert not listeners.received
