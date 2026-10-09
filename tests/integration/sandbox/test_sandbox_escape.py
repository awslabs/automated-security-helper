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
import uuid
from pathlib import Path
from typing import Callable, Dict, Iterator

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


#: The listeners that stand in for local IPC endpoints, as named in received.
UNIX_LISTENERS = {"unix", "unix_abstract", "unix_datagram"}


class _Listeners:
    """TCP, UDP and Unix-socket echo-ack listeners the probe tries to reach.

    The Unix listeners are in ``directory``, which every sandboxed scan mounts
    (``sandbox.extra_read_paths``), so a refusal has to come from the sandbox's
    socket mediation, not from the socket being out of sight. Unmounted, the test
    passed under bwrap with a FileNotFoundError while a socket in any directory
    bwrap does mount (the Nix daemon's, under /nix) stayed reachable. On Linux
    there is also an abstract stream socket, which has no path at all, and a
    datagram socket, which a datagram socketpair can reach without socket().
    """

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind(("0.0.0.0", 0))  # nosec B104 - test listener, closed after the test
        self.tcp.listen(8)
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.unix_path = directory / "ipc.sock"
        self.unix = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.unix.bind(str(self.unix_path))
        self.unix.listen(8)
        #: (listener, data) for everything any listener received.
        self.received: list = []
        self._stop = False
        self._sockets = [self.tcp, self.udp, self.unix]
        servers = [
            lambda: self._serve_stream("tcp", self.tcp),
            lambda: self._serve_datagram("udp", self.udp, reply=True),
            lambda: self._serve_stream("unix", self.unix),
        ]
        self.kinds = {"tcp", "udp", "unix"}
        self.abstract_name = ""
        self.datagram_path: Path | None = None
        if sys.platform.startswith("linux"):
            self.abstract_name = f"ash-sbx-{uuid.uuid4().hex[:12]}"
            abstract = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            abstract.bind("\0" + self.abstract_name)
            abstract.listen(8)
            self.datagram_path = directory / "ipc.dgram"
            datagram = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            datagram.bind(str(self.datagram_path))
            self._sockets += [abstract, datagram]
            servers += [
                lambda: self._serve_stream("unix_abstract", abstract),
                lambda: self._serve_datagram("unix_datagram", datagram, reply=False),
            ]
            self.kinds |= {"unix_abstract", "unix_datagram"}
        for target in servers:
            threading.Thread(target=target, daemon=True).start()

    def reached(self) -> set:
        """The listeners that received the canary."""
        return {kind for kind, data in self.received if CANARY.encode() in data}

    def _serve_stream(self, kind: str, sock: socket.socket) -> None:
        sock.settimeout(0.5)
        while not self._stop:
            try:
                conn, _ = sock.accept()
            except OSError:
                continue
            with conn:
                self.received.append((kind, conn.recv(64)))
                conn.sendall(b"ack")

    def _serve_datagram(self, kind: str, sock: socket.socket, reply: bool) -> None:
        sock.settimeout(0.5)
        while not self._stop:
            try:
                data, addr = sock.recvfrom(64)
            except OSError:
                continue
            self.received.append((kind, data))
            if reply:
                sock.sendto(b"ack", addr)

    def close(self) -> None:
        self._stop = True
        for sock in self._sockets:
            sock.close()


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
    server = _Listeners(Path(tempfile.mkdtemp(prefix="ash-sbx-")))
    yield server
    server.close()
    shutil.rmtree(server.directory, ignore_errors=True)


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


def _run_escape(
    tmp_path: Path,
    listeners: _Listeners,
    mode: str,
    *,
    online: bool = False,
    output_in_source: "str | None" = None,
) -> "tuple[Dict[str, str], Dict[str, str]]":
    """The probe's attempts, and what it found still working (``works``)."""
    outcomes, works, result = _scan(
        tmp_path, listeners, mode, online=online, output_in_source=output_in_source
    )
    assert outcomes is not None and works is not None, (
        f"the probe wrote no outcome (exit {result.returncode}). The scanner may have "
        f"been MISSING or failed to start.\nstdout:\n{result.stdout[-4000:]}\n"
        f"stderr:\n{result.stderr[-4000:]}"
    )
    return outcomes, works


def _ipc_environment(listeners: _Listeners) -> Dict[str, str]:
    """The variables that name local IPC endpoints, pointing at nothing real."""
    here = listeners.directory
    return {
        "SSH_AUTH_SOCK": str(here / "agent.sock"),
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path={here / 'bus'}",
        "DOCKER_HOST": f"unix://{here / 'docker.sock'}",
        "CONTAINER_HOST": f"unix://{here / 'podman.sock'}",
        "XDG_RUNTIME_DIR": str(here),
    }


def _scan(
    tmp_path: Path,
    listeners: _Listeners,
    mode: str,
    *,
    online: bool = False,
    output_in_source: "str | None" = None,
    plant: "Callable[[Path], None] | None" = None,
) -> "tuple[Dict[str, str] | None, Dict[str, str] | None, subprocess.CompletedProcess]":
    """Run the probe through a real scan.

    ``output_in_source`` puts the output directory at that path inside the source
    tree instead of beside it; ``plant`` is called with the source directory once
    it is built, to commit something into the tree before the scan.
    """
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
    output = source / output_in_source if output_in_source else tmp_path / "out"
    if plant is not None:
        plant(source)
    # The uv cache the scan sees, standing in for the user's: every sandbox
    # mounts it, and a write that lands in it outlives the sandbox.
    host_cache = tmp_path / "uv-cache"
    host_cache.mkdir()
    seed = host_cache / "seed.txt"
    seed.write_text("original\n")
    seed_mtime = seed.stat().st_mtime_ns

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
        "unix_abstract": listeners.abstract_name,
        "unix_datagram_socket": str(listeners.datagram_path or ""),
        "ipc_env": _ipc_environment(listeners),
        "host_cache": str(host_cache),
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
        "UV_CACHE_DIR": str(host_cache),
        **_ipc_environment(listeners),
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
        "--no-progress",
        "--no-fail-on-findings",
        # The listeners' directory is visible in every sandbox; see _Listeners.
        "--config-overrides",
        f"sandbox.extra_read_paths=[{listeners.directory}]",
    ]
    if online:
        # The fixture scanner declares no network need, so it is granted one the
        # way an operator grants it, which an in-tree config cannot do.
        command += ["--config-overrides", "sandbox.network_scanners=[sandbox-escape]"]
        env.pop("ASH_OFFLINE", None)
    else:
        command.append("--offline")
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
        return None, None, result
    outcomes = json.loads(outcome_file.read_text())
    works = outcomes.pop("works")
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
    # Only the host side counts here too: under bwrap the write lands in a
    # throwaway overlay and succeeds without reaching the host.
    outcomes.pop("write_host_cache", None)
    outcomes["_host_cache_untouched"] = (
        "succeeded"
        if seed.read_text() != "original\n"
        or seed.stat().st_mtime_ns != seed_mtime
        or (host_cache / "pwned.txt").exists()
        else "blocked: host cache unchanged"
    )
    outcomes["_outside_untouched"] = (
        "succeeded"
        if (outside / "pwned.txt").exists() or (output / "pwned.txt").exists()
        else "blocked: nothing written outside the results directory"
    )
    return outcomes, works, result


def test_every_attempt_succeeds_without_a_sandbox(tmp_path, listeners):
    """The negative control. If this fails, the probe is broken, not the sandbox."""
    outcomes, works = _run_escape(tmp_path, listeners, "off")
    failed = {
        k: v
        for k, v in outcomes.items()
        if v != "succeeded" and k not in CONTROL_EXEMPT
    }
    assert not failed, f"attempts that should have succeeded unsandboxed: {failed}"
    assert listeners.reached() == listeners.kinds
    assert works == EXPECTED_WORKS


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
    "blocked: RuntimeError: no IPC endpoint variable in the environment",
    "blocked: source tree unchanged",
    "blocked: nothing written outside the results directory",
    "blocked: nothing left in /dev/shm",
    "blocked: host cache unchanged",
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

#: What has to keep working inside every sandbox. uv writes its cache on every run,
#: so wherever UV_CACHE_DIR points has to be writable: the host cache through
#: bwrap's overlay, a private directory under the other backends. Stream and
#: seqpacket socketpairs are how tools make pipes; only the datagram kind, which
#: can reach a path, is refused (probed on Linux only).
EXPECTED_WORKS = {"uv_cache": "works"}
if sys.platform.startswith("linux"):
    EXPECTED_WORKS["socketpair"] = "works"

#: The attempts that need only a network, which a scanner granted one should have.
NETWORK_ATTEMPTS = ("tcp_connect", "tcp_connect_host_address", "udp_send")


def _control(tmp_path_factory, listeners: _Listeners, *, online: bool) -> set:
    """Run the negative control and return the names of its attempts.

    In the same test as the sandboxed run, so that test cannot pass on a machine
    where the probe's attempts would have failed anyway.
    """
    control, works = _run_escape(
        tmp_path_factory.mktemp("control"), listeners, "off", online=online
    )
    not_real = {
        k: v for k, v in control.items() if v != "succeeded" and k not in CONTROL_EXEMPT
    }
    assert not not_real, (
        f"the control could not escape either, so proves nothing: {not_real}"
    )
    assert listeners.reached() == listeners.kinds, (
        "the control did not reach every listener, so proves nothing"
    )
    assert works == EXPECTED_WORKS
    listeners.received.clear()
    return set(control)


def _assert_blocked(backend: str, outcomes: Dict[str, str]) -> None:
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


@pytest.mark.parametrize("backend", BACKENDS)
def test_every_attempt_is_blocked_by_the_sandbox(
    tmp_path, tmp_path_factory, listeners, backend
):
    _require_backend(backend)
    attempted = _control(tmp_path_factory, listeners, online=False)

    outcomes, works = _run_escape(tmp_path, listeners, backend)
    assert set(outcomes) == attempted, "the sandboxed run attempted different things"
    _assert_blocked(backend, outcomes)
    assert works == EXPECTED_WORKS, f"{backend} broke what tools need: {works}"
    assert not listeners.received, f"{backend} let data reach a listener"


@pytest.mark.parametrize("backend", BACKENDS)
def test_no_local_ipc_endpoint_is_reachable_with_a_network(
    tmp_path, tmp_path_factory, listeners, backend
):
    """A scanner granted a network still reaches no Unix socket, nor its variables.

    With a network, bwrap and firejail share the host's network namespace, and
    with it every abstract socket a host process has bound; no mount hides those.
    So this runs the whole probe online. The network attempts must succeed, which
    is what shows the scan really was online; everything else must be blocked
    exactly as it is offline, the Unix-socket attempts and the variables naming
    the Docker socket, the session bus and the SSH agent included.
    """
    _require_backend(backend)
    attempted = _control(tmp_path_factory, listeners, online=True)

    outcomes, works = _run_escape(tmp_path, listeners, backend, online=True)
    assert set(outcomes) == attempted, "the sandboxed run attempted different things"
    network = {k: outcomes.pop(k) for k in NETWORK_ATTEMPTS if k in outcomes}
    offline = {k: v for k, v in network.items() if v != "succeeded"}
    assert not offline, (
        f"{backend} gave the scanner no network, so this run says nothing about "
        f"online mode: {offline}"
    )
    _assert_blocked(backend, outcomes)
    assert works == EXPECTED_WORKS, f"{backend} broke what tools need: {works}"
    reached = listeners.reached() & UNIX_LISTENERS
    assert not reached, f"{backend} let data reach a local IPC listener: {reached}"


def _snapshot(root: Path) -> dict:
    """Everything under ``root`` and its own listing time, to show nothing changed."""
    found = {".": root.stat().st_mtime_ns}
    for path in sorted(root.rglob("*")):
        stat = path.lstat()
        content = path.read_bytes() if path.is_file() and not path.is_symlink() else b""
        found[path.relative_to(root).as_posix()] = (stat.st_mtime_ns, content)
    return found


@pytest.mark.parametrize("backend", BACKENDS)
def test_an_output_directory_reached_through_a_link_in_the_tree_is_refused(
    tmp_path, listeners, backend
):
    """The scanned repository commits ``build`` as a link to a host directory.

    Scanned with ``--output-dir build/ash``, every sandbox would mount that host
    directory, read-only as the output directory and writable below it as the
    results directory, and ASH itself would write and clear subdirectories there.
    The scan has to stop before any of it, leaving the directory as it was.
    """
    _require_backend(backend)
    target = tmp_path / "host-dir"
    target.mkdir()
    (target / "keep.txt").write_text("original\n")
    before = _snapshot(target)
    outcomes, _, result = _scan(
        tmp_path,
        listeners,
        backend,
        output_in_source="build/ash",
        plant=lambda source: (source / "build").symlink_to(
            target, target_is_directory=True
        ),
    )
    # Whitespace collapsed: the console wraps long lines at the terminal width.
    output = " ".join((result.stdout + result.stderr).split())
    assert outcomes is None, (
        f"the scanner ran with a linked output directory: {outcomes}"
    )
    assert result.returncode == 1, output[-4000:]
    assert "is a symlink" in output, output[-4000:]
    assert _snapshot(target) == before, "the scan wrote into the linked directory"
    assert not listeners.received


def test_with_the_sandbox_off_a_linked_output_directory_is_still_used(
    tmp_path, listeners
):
    """Only a sandboxed scan is refused; unsandboxed, the operator chose the path."""
    target = tmp_path / "host-dir"
    target.mkdir()
    outcomes, _, result = _scan(
        tmp_path,
        listeners,
        "off",
        output_in_source="build/ash",
        plant=lambda source: (source / "build").symlink_to(
            target, target_is_directory=True
        ),
    )
    assert outcomes is not None, (result.stdout + result.stderr)[-4000:]
    assert (target / "ash" / "ash_aggregated_results.json").is_file()


@pytest.mark.parametrize("backend", BACKENDS)
def test_the_default_output_directory_inside_the_tree_is_unaffected(
    tmp_path, listeners, backend
):
    """``.ash/ash_output`` under the source directory, the default, still scans."""
    _require_backend(backend)
    outcomes, works = _run_escape(
        tmp_path, listeners, backend, output_in_source=".ash/ash_output"
    )
    _assert_blocked(backend, outcomes)
    assert works == EXPECTED_WORKS, f"{backend} broke what tools need: {works}"
    assert not listeners.received, f"{backend} let data reach a listener"


def test_an_unavailable_sandbox_reports_missing_and_never_runs_the_scanner(
    tmp_path, listeners
):
    """Asking for a backend this machine lacks must not fall back to unsandboxed.

    sandbox-exec exists only on macOS and bwrap only on Linux, so one of the two is
    unavailable on every runner.
    """
    unavailable = "bwrap" if sys.platform == "darwin" else "sandbox-exec"
    outcomes, _, result = _scan(tmp_path, listeners, unavailable)
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
