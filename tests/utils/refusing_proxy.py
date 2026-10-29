"""A local proxy that records every request it receives and refuses all of them.

A test that has to show a tool sends nothing over the network cannot let the tool
reach the network to find out. Instead every proxy variable is pointed at this
server, which listens on 127.0.0.1 only, writes down the first line of each request
(``CONNECT sts.amazonaws.com:443 HTTP/1.1``, ``GET http://host/path HTTP/1.1``) and
answers ``403 Forbidden``. A tool that tried to contact a host shows up in
:attr:`RecordingProxy.requests`; nothing leaves the machine.

Python's ``requests``, Go's ``net/http`` and npm all honor these variables, which
covers the tools ASH starts. ``NO_PROXY`` is set empty so that a host's own
exclusion list (which often names cloud endpoints) cannot route a request around
the recorder.

Use :func:`route_through` with pytest's ``monkeypatch`` so the variables are
restored after the test, and :func:`scrub_cloud_credentials` so that nothing in the
run can authenticate to a cloud provider either.
"""

import os
import socket
import threading
from typing import List

PROXY_VARIABLES = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
)

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}


class RecordingProxy:
    """A refusing HTTP proxy on 127.0.0.1 that remembers what it was asked for."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._requests: List[str] = []
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(("127.0.0.1", 0))
        self._server.listen(64)
        self.port = self._server.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def requests(self) -> List[str]:
        """The first line of every request received, in arrival order."""
        with self._lock:
            return list(self._requests)

    def external_requests(self) -> List[str]:
        """Requests for a host other than this machine's loopback addresses.

        ASH's own tests point AWS SDK clients at ``http://127.0.0.1:9`` so that
        they fail fast; with the proxy variables set, such a request arrives here
        too. It never leaves the machine and is not what a test is looking for.
        """
        return [
            line for line in self.requests if target_host(line) not in _LOOPBACK_HOSTS
        ]

    def close(self) -> None:
        try:
            self._server.close()
        except OSError:
            pass

    def _serve(self) -> None:
        while True:
            try:
                connection, _ = self._server.accept()
            except OSError:
                return
            threading.Thread(
                target=self._handle, args=(connection,), daemon=True
            ).start()

    def _handle(self, connection: socket.socket) -> None:
        data = b""
        connection.settimeout(5)
        try:
            while b"\r\n" not in data and len(data) < 65536:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                data += chunk
        except OSError:
            pass
        first_line = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        if first_line:
            with self._lock:
                self._requests.append(first_line)
        try:
            connection.sendall(
                b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n"
                b"Connection: close\r\n\r\n"
            )
        except OSError:
            pass
        finally:
            connection.close()


def target_host(request_line: str) -> str:
    """The host a proxy request line names (``CONNECT h:443`` or ``GET http://h/``)."""
    parts = request_line.split()
    if len(parts) < 2:
        return ""
    target = parts[1]
    if "://" in target:
        target = target.split("://", 1)[1].split("/", 1)[0]
    if target.startswith("["):
        return target.split("]", 1)[0] + "]"
    return target.rsplit(":", 1)[0] if ":" in target else target


def route_through(monkeypatch, proxy: RecordingProxy) -> None:
    """Point every proxy variable at ``proxy`` for the rest of the test."""
    for name in PROXY_VARIABLES:
        monkeypatch.setenv(name, proxy.url)
    monkeypatch.setenv("NO_PROXY", "")
    monkeypatch.setenv("no_proxy", "")


def scrub_cloud_credentials(monkeypatch) -> None:
    """Leave the run with no usable AWS credentials and a refusing endpoint."""
    for name in (
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_CONFIG_FILE", os.devnull)
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", os.devnull)
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_ENDPOINT_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
