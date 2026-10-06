# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What ``ashx get-genai-guide`` prints when it succeeds locally and when GitHub fails.

The command finds the guide relative to ``cli/main.py``'s own ``__file__``. Every test
points that at a temp tree holding a guide this file writes, so the snapshot records
the command's wording and not the length of the real guide, which changes with every
docs edit. The network is never reached: ``requests.get`` is replaced in each test
that would call it.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import requests

from automated_security_helper.cli import main as cli_main

GUIDE = "# GenAI guide\n\nUse ash_aggregated_results.json, not the HTML report.\n"


@pytest.fixture
def installed_at(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Pretend ASH is installed under ``tmp_path/install``, with no guide yet."""
    root = tmp_path / "install"
    main_py = root / "automated_security_helper" / "cli" / "main.py"
    main_py.parent.mkdir(parents=True)
    monkeypatch.setattr(cli_main, "__file__", str(main_py))
    return root


def _ship_guide(root: Path) -> None:
    guide = root / "docs" / "content" / "docs" / "genai-steering-guide.md"
    guide.parent.mkdir(parents=True)
    guide.write_text(GUIDE, encoding="utf-8")


def _network_down(*_args, **_kwargs):
    raise requests.ConnectionError("simulated: network is unreachable")


class _NotFound:
    text = "404: Not Found"

    def raise_for_status(self):
        raise requests.HTTPError("404 Client Error: Not Found for url")


def test_local_copy_written(run_cli, snapshot, installed_at, monkeypatch):
    _ship_guide(installed_at)
    monkeypatch.setattr(requests, "get", _network_down)
    seen = run_cli(["get-genai-guide", "--output", "guide.md"])
    assert seen == snapshot
    assert (installed_at.parent / "guide.md").read_text(encoding="utf-8") == GUIDE


def test_from_github_network_failure(run_cli, snapshot, installed_at, monkeypatch):
    _ship_guide(installed_at)
    monkeypatch.setattr(requests, "get", _network_down)
    assert run_cli(["get-genai-guide", "--from-github", "--branch", "v3"]) == snapshot


def test_from_github_http_error(run_cli, snapshot, installed_at, monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **k: _NotFound())
    assert run_cli(["get-genai-guide", "--from-github"]) == snapshot


def test_no_local_copy_falls_back_to_github(
    run_cli, snapshot, installed_at, monkeypatch
):
    monkeypatch.setattr(requests, "get", _network_down)
    assert run_cli(["get-genai-guide"]) == snapshot
