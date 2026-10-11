# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The documentation site builds without the network.

docs_checks.check_site_build reads mkdocs.yml and the pages for external assets the
privacy plugin would download. This builds the site the way the docs job does, with
every proxy variable pointing at a local proxy that records each request and answers
502, and requires that it receives none.

The build is not --strict here. Strictness is the static check's job, and a broken
link elsewhere in the docs must not hide whether the build used the network.

The proxy only sees requests that honor the proxy variables. The planted site below
proves the one that matters does: the privacy plugin's download of an external image
reaches the proxy.
"""

from __future__ import annotations

import os
import socketserver
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from typing_extensions import Self

REPO_ROOT = Path(__file__).resolve().parents[3]
PROXY_VARIABLES = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")


class RecordingProxy:
    """A proxy on 127.0.0.1 that records each request line and answers 502."""

    def __init__(self) -> None:
        self.requests: list[str] = []
        recorded = self.requests

        class Handler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                line = self.rfile.readline(4096).decode("latin-1").strip()
                recorded.append(line or "<empty request>")
                self.wfile.write(
                    b"HTTP/1.1 502 Bad Gateway\r\n"
                    b"Content-Length: 0\r\nConnection: close\r\n\r\n"
                )

        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> Self:
        self.thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()


def _build(config: Path, workdir: Path, proxy: RecordingProxy):
    """mkdocs build, from workdir so the privacy plugin's cache starts empty."""
    env = {
        key: value for key, value in os.environ.items() if "proxy" not in key.lower()
    }
    for name in PROXY_VARIABLES:
        env[name] = env[name.lower()] = proxy.url
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "mkdocs",
            "build",
            "--config-file",
            str(config),
            "--site-dir",
            str(workdir / "site"),
        ],
        cwd=workdir,
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )


@pytest.fixture
def docs_root(request) -> Path:
    option = request.config.getoption("--docs-root", default=None)
    return Path(option).resolve() if option else REPO_ROOT


def test_the_site_builds_without_a_network_request(docs_root, tmp_path):
    with RecordingProxy() as proxy:
        result = _build(docs_root / "mkdocs.yml", tmp_path, proxy)
    assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-3000:]
    assert proxy.requests == [], (
        "the docs build made network requests, so it cannot build offline: "
        f"{proxy.requests}"
    )
    assert (tmp_path / "site" / "index.html").is_file()


def test_the_proxy_sees_a_download_the_privacy_plugin_makes(tmp_path):
    """Planted: an external image no assets_exclude pattern covers is downloaded at
    build time, and that download reaches the recording proxy."""
    site = tmp_path / "planted"
    (site / "docs").mkdir(parents=True)
    (site / "mkdocs.yml").write_text(
        "site_name: planted\ntheme:\n  name: material\n  font: false\n"
        "plugins:\n  - privacy\n",
        encoding="utf-8",
    )
    (site / "docs" / "index.md").write_text(
        "# Planted\n\n![logo](https://example.com/planted-logo.png)\n",
        encoding="utf-8",
    )
    with RecordingProxy() as proxy:
        _build(site / "mkdocs.yml", tmp_path, proxy)
    assert any("example.com" in line for line in proxy.requests), proxy.requests
