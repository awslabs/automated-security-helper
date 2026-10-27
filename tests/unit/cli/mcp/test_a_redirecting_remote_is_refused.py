# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A remote that answers with an HTTP redirect is refused, and the redirect
target is never contacted.

This cell runs the real git binary against two local listeners, so it is meant
for a venue with network sockets and a git binary on PATH.

Everything is local and planted: two ``http.server`` instances on 127.0.0.1
ephemeral ports. The first answers every GET (git's ``info/refs`` probe) with a
302 whose Location points at the second. The clone is built with
``-c http.followRedirects=false`` (``source_delivery._GIT_CONFIG``), so git
refuses the redirect instead of following it: the clone fails, and the second
listener's request log stays empty. The first listener's log is the positive
control that git did contact the URL it was given.

``set_source_git`` refuses a plain ``http://`` url before git runs, and
``_GIT_CONFIG`` allows only the https and ssh protocols, so a listener that
needs no certificate cannot be reached through either. The cell therefore calls
the clone step itself (``_clone``) with ``_GIT_CONFIG`` minus its ``protocol.*``
pairs: the redirect setting under test is the one the delivery builds, and the
protocol policy, which has its own cells, is the only part taken off.
"""

from __future__ import annotations

import http.server
import threading
from typing import List, Tuple

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd


class _Quiet(http.server.BaseHTTPRequestHandler):
    """No stderr chatter from either listener."""

    def log_message(self, *args) -> None:  # pragma: no cover - silence only
        pass


def _serve(handler_cls) -> http.server.ThreadingHTTPServer:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _config_without_the_protocol_policy() -> Tuple[str, ...]:
    """``_GIT_CONFIG`` with the ``protocol.*`` settings taken off.

    ``_GIT_CONFIG`` is a flat run of ``-c``, ``name=value`` pairs. The redirect
    setting must stay, or the cell would measure nothing.
    """
    config = sd._GIT_CONFIG
    pairs = [(config[i], config[i + 1]) for i in range(0, len(config), 2)]
    kept = [pair for pair in pairs if not pair[1].startswith("protocol.")]
    assert ("-c", "http.followRedirects=false") in kept, kept
    assert len(kept) < len(pairs), "control: no protocol setting was taken off"
    return tuple(part for pair in kept for part in pair)


def test_a_redirecting_remote_is_refused_and_its_target_never_contacted(
    tmp_path, monkeypatch
):
    """The clone at the redirecting URL fails; the redirect target sees nothing."""

    target_requests: List[str] = []
    redirector_requests: List[str] = []

    class _Target(_Quiet):
        def do_GET(self) -> None:
            target_requests.append(self.path)
            self.send_response(200)
            self.end_headers()

    target_server = _serve(_Target)
    target_base = f"http://127.0.0.1:{target_server.server_address[1]}"

    class _Redirector(_Quiet):
        def do_GET(self) -> None:
            redirector_requests.append(self.path)
            self.send_response(302)
            self.send_header("Location", target_base + self.path)
            self.end_headers()

    redirect_server = _serve(_Redirector)
    url = f"http://127.0.0.1:{redirect_server.server_address[1]}/repo.git"

    monkeypatch.setattr(sd, "_GIT_CONFIG", _config_without_the_protocol_policy())
    clone_target = tmp_path / "source"
    clone_target.mkdir()

    try:
        with pytest.raises(sd.GitCommandError, match="git clone failed"):
            sd._clone(
                url,
                None,
                depth=1,
                target=clone_target,
                env=sd._git_environment(tmp_path),
            )
    finally:
        redirect_server.shutdown()
        target_server.shutdown()

    # Positive control: git did ask the URL it was given.
    assert redirector_requests, redirector_requests
    # The redirect target was never contacted.
    assert target_requests == [], target_requests
