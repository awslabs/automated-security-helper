# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Real tools: a config or ignore file in the scanned tree does not narrow the scan.

Each test runs the tool as it would run without ASH's handling (the control),
showing the in-tree file hides a finding, then runs ASH's scanner over the same
tree and checks the finding is reported. Measured with bandit 1.9.4, grype
0.118.0, syft 1.51.1, semgrep 1.180.0 and opengrep 1.15.1 and 1.30.0:

* bandit finds a ``.bandit`` anywhere under the target unless ``--ini`` names one;
* grype and syft read ``.grype.yaml`` and ``.syft.yaml`` from their working
  directory, the source directory, unless ``--config`` names one;
* semgrep and opengrep honor a ``.semgrepignore`` in the tree unless
  ``--x-ignore-semgrepignore-files`` is passed.

The same holds for where grype's database comes from: one test checks that an
in-tree ``db.update-url`` does not choose the host grype updates from.

Each test is skipped when its tool is not installed; the grype ignore test also
needs a vulnerability database already in its cache.
"""

from __future__ import annotations

import http.server
import json
import os
import shutil
import subprocess
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Set, Tuple

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig

PluginContext.model_rebuild()

MARKER = "ASH_TOOL_CONFIG_MARKER_7f3a"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.name == "nt", reason="POSIX paths"),
]


def _tool(name: str) -> str:
    found = shutil.which(name)
    if found is None:
        pytest.skip(f"{name} is not installed")
    return found


def _context(tmp_path: Path, source: Path) -> PluginContext:
    output = tmp_path / "out"
    output.mkdir(exist_ok=True)
    return PluginContext(source_dir=source, output_dir=output, config=AshConfig())


def _rule_ids(report: Any) -> Set[str]:
    assert report, f"the scanner reported nothing: {report!r}"
    return {r.ruleId for run in report.runs or [] for r in run.results or []}


def _uris(report: Any) -> Set[str]:
    assert report, f"the scanner reported nothing: {report!r}"
    return {
        loc.physicalLocation.root.artifactLocation.uri
        for run in report.runs or []
        for r in run.results or []
        for loc in r.locations or []
    }


# ---------------------------------------------------------------------------
# bandit
# ---------------------------------------------------------------------------


def test_a_dot_bandit_in_the_tree_does_not_skip_tests(tmp_path: Path) -> None:
    from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
        BanditScanner,
        BanditScannerConfig,
    )

    bandit = _tool("bandit")
    source = tmp_path / "repo"
    source.mkdir()
    (source / "app.py").write_text(
        'import subprocess\nsubprocess.call("ls", shell=True)\n', encoding="utf-8"
    )
    (source / ".bandit").write_text("[bandit]\nskips: B602\n", encoding="utf-8")

    control = subprocess.run(  # nosec B603 - fixed argv, bandit from PATH
        [bandit, "-r", str(source), "-f", "json", "-q"],
        capture_output=True,
        text=True,
        check=False,
    )
    control_ids = {item["test_id"] for item in json.loads(control.stdout)["results"]}
    assert "B602" not in control_ids and control_ids, control.stdout

    scanner = BanditScanner(
        context=_context(tmp_path, source), config=BanditScannerConfig()
    )
    assert "B602" in _rule_ids(scanner.scan(target=source, target_type="source"))


# ---------------------------------------------------------------------------
# grype and syft
# ---------------------------------------------------------------------------


def _python_project(tmp_path: Path) -> Path:
    source = tmp_path / "repo"
    source.mkdir()
    (source / "requirements.txt").write_text("requests==2.19.1\n", encoding="utf-8")
    return source


def test_a_grype_yaml_in_the_tree_does_not_ignore_vulnerabilities(
    tmp_path: Path,
) -> None:
    from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
        GrypeScanner,
        GrypeScannerConfig,
        GrypeScannerConfigOptions,
    )

    grype = _tool("grype")
    source = _python_project(tmp_path)
    env: Dict[str, str] = {**os.environ, "GRYPE_DB_AUTO_UPDATE": "false"}
    baseline = subprocess.run(  # nosec B603 - fixed argv, grype from PATH
        [grype, f"dir:{source}", "-o", "json", "-q"],
        cwd=source,
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    if baseline.returncode != 0 or not json.loads(baseline.stdout or "{}").get(
        "matches"
    ):
        pytest.skip("grype has no usable vulnerability database in its cache")

    (source / ".grype.yaml").write_text(
        "ignore:\n  - package:\n      name: requests\n", encoding="utf-8"
    )
    control = subprocess.run(  # nosec B603 - fixed argv, grype from PATH
        [grype, f"dir:{source}", "-o", "json", "-q"],
        cwd=source,
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    assert not json.loads(control.stdout).get("matches"), control.stdout

    scanner = GrypeScanner(
        context=_context(tmp_path, source),
        config=GrypeScannerConfig(options=GrypeScannerConfigOptions(offline=True)),
    )
    assert _rule_ids(scanner.scan(target=source, target_type="source"))


@contextmanager
def _recording_server(status: int) -> Iterator[Tuple[str, List[str]]]:
    """An HTTP server on 127.0.0.1 that answers every request with ``status``.

    Yields its base URL and a list of ``"<method> <target>"``, one per request.
    Used as a proxy it records CONNECT (``CONNECT host:443``) and absolute-URI
    requests and forwards none of them.
    """
    requests: List[str] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def _answer(self) -> None:
            requests.append(f"{self.command} {self.path}")
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.end_headers()

        do_GET = do_HEAD = do_POST = do_CONNECT = _answer

        def log_message(self, *args: Any) -> None:
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)


def test_a_grype_yaml_in_the_tree_does_not_choose_the_database_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An in-tree ``db.update-url`` is not where grype's update check goes.

    No request leaves the machine. The in-tree file names a recording server on
    127.0.0.1, and both runs have HTTPS_PROXY and HTTP_PROXY set to a second one
    that answers 403, so an update aimed at grype's default host ends there. Go's
    proxy selection never proxies a loopback address, so grype reaches the first
    server directly; the control relies on that, and fails if the request went to
    the proxy instead.

    Measured with grype 0.118.0: a run with an update due sends HEAD, then GET,
    for ``<update-url>/v6/latest.json``. GRYPE_DB_MAX_UPDATE_CHECK_FREQUENCY=0s
    makes one due on every run (with the default 2h and a check seconds old, grype
    sent nothing), and so does an empty cache, which grype gets here so the test
    neither needs nor changes a real database.
    """
    from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
        GrypeScanner,
        GrypeScannerConfig,
        GrypeScannerConfigOptions,
    )

    grype = _tool("grype")
    source = _python_project(tmp_path)
    # GRYPE_DB_UPDATE_URL would override the in-tree key in the control and
    # NO_PROXY could exempt grype's default host from the proxy, so neither may
    # come from the caller. The variables set below override no update-url.
    for name in list(os.environ):
        if (
            name.startswith("GRYPE_")
            or name.lower() in {"http_proxy", "https_proxy", "no_proxy", "all_proxy"}
            or name == "ASH_OFFLINE"
        ):
            monkeypatch.delenv(name)

    with (
        _recording_server(404) as (repo_url, repo_requests),
        _recording_server(403) as (proxy_url, proxy_requests),
    ):
        for name in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"):
            monkeypatch.setenv(name, proxy_url)
        monkeypatch.setenv("GRYPE_DB_CACHE_DIR", str(tmp_path / "grype-db"))
        monkeypatch.setenv("GRYPE_DB_MAX_UPDATE_CHECK_FREQUENCY", "0s")
        monkeypatch.setenv("GRYPE_CHECK_FOR_APP_UPDATE", "false")
        (source / ".grype.yaml").write_text(
            f"db:\n  auto-update: true\n  update-url: {repo_url}/databases\n",
            encoding="utf-8",
        )

        subprocess.run(  # nosec B603 - fixed argv, grype from PATH
            [grype, f"dir:{source}", "-o", "json", "-q"],
            cwd=source,
            capture_output=True,
            text=True,
            check=False,
            env=dict(os.environ),
            timeout=120,
        )
        assert repo_requests, f"the control never reached {repo_url}: {proxy_requests}"
        repo_requests.clear()
        proxy_requests.clear()

        # The scan itself fails: the proxy refuses the update and the cache is
        # empty, so grype has no database. Only where it asked for one is checked.
        scanner = GrypeScanner(
            context=_context(tmp_path, source),
            config=GrypeScannerConfig(options=GrypeScannerConfigOptions(offline=False)),
        )
        scanner.scan(target=source, target_type="source")
        assert not repo_requests, repo_requests
        # And it did ask: the update went to the proxy, so the run above is not
        # one that skipped the update check.
        assert any(r.startswith("CONNECT ") for r in proxy_requests), proxy_requests


def test_a_syft_yaml_in_the_tree_does_not_drop_components(tmp_path: Path) -> None:
    from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
        SyftScanner,
        SyftScannerConfig,
    )

    syft = _tool("syft")
    source = _python_project(tmp_path)
    (source / ".syft.yaml").write_text(
        "exclude:\n  - ./requirements.txt\n", encoding="utf-8"
    )
    control = subprocess.run(  # nosec B603 - fixed argv, syft from PATH
        [syft, "scan", f"dir:{source}", "-o", "cyclonedx-json", "-q"],
        cwd=source,
        capture_output=True,
        text=True,
        check=False,
    )
    names = {c["name"] for c in json.loads(control.stdout).get("components", [])}
    assert "requests" not in names, control.stdout

    scanner = SyftScanner(
        context=_context(tmp_path, source), config=SyftScannerConfig()
    )
    report = scanner.scan(target=source, target_type="source")
    assert "requests" in {component.name for component in report.components or []}


# ---------------------------------------------------------------------------
# semgrep and opengrep
# ---------------------------------------------------------------------------


def _grep_tree(tmp_path: Path) -> Path:
    source = tmp_path / "repo"
    for relative in ("app.txt", "hidden/h.txt", "tests/t.txt"):
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{MARKER}\n", encoding="utf-8")
    (source / ".semgrepignore").write_text("hidden/\n", encoding="utf-8")
    return source


def _rule_file(tmp_path: Path) -> Path:
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "rules:\n"
        "  - id: marker\n"
        "    message: marker\n"
        "    severity: WARNING\n"
        "    languages: [generic]\n"
        f"    pattern-regex: {MARKER}\n",
        encoding="utf-8",
    )
    return rules


@pytest.mark.parametrize("tool", ["semgrep", "opengrep"])
def test_a_semgrepignore_in_the_tree_does_not_hide_files(
    tmp_path: Path, tool: str
) -> None:
    binary = _tool(tool)
    source = _grep_tree(tmp_path)
    rules = _rule_file(tmp_path)
    control_out = tmp_path / "control.sarif"
    subprocess.run(  # nosec B603 - fixed argv, the tool from PATH
        [
            binary,
            "scan",
            "--config",
            str(rules),
            *(["--metrics", "off"] if tool == "semgrep" else []),
            "--sarif-output",
            str(control_out),
            str(source),
        ],
        cwd=source,
        capture_output=True,
        check=False,
    )
    control = json.loads(control_out.read_text(encoding="utf-8"))
    control_uris = {
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for run in control["runs"]
        for r in run["results"]
    }
    assert not any("hidden/" in uri for uri in control_uris), control_uris

    if tool == "semgrep":
        from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
            SemgrepScanner as cls,
            SemgrepScannerConfig as cfg,
        )
    else:
        from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
            OpengrepScanner as cls,  # type: ignore[assignment]
            OpengrepScannerConfig as cfg,  # type: ignore[assignment]
        )
    scanner = cls(
        context=_context(tmp_path, source),
        config=cfg.model_validate({"options": {"config": str(rules)}}),
    )
    uris = _uris(scanner.scan(target=source, target_type="source"))
    assert any("hidden/h.txt" in uri for uri in uris), uris
    # The tools' own default exclusions still apply.
    assert not any("tests/t.txt" in uri for uri in uris), uris
