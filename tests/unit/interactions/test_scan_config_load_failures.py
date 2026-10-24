# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash scan`` and ``run_ash_scan`` exit 3 for a config file they cannot load.

A named config file that does not exist, and a named or discovered file that cannot
be read or parsed, refuse the scan with the config exit code (3) before any scanner
runs. Only a source directory with no config file at all scans with the defaults.

The scan itself is never run: ``ASHScanOrchestrator.execute_scan`` is replaced by a
probe that records the config it was handed and returns empty results. Everything
between the command line and that call is the real code, so a test that sees the
probe reached knows the scan would have run, and with which settings.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.models.asharp_model import AshAggregatedResults

GOOD_YAML = """\
fail_on_findings: false
global_settings:
  suppressions:
    - rule_id: B101
      path: "**"
      reason: fixture
"""
BAD_YAML = GOOD_YAML + "  extra: [unclosed\n"
BAD_JSON = '{"fail_on_findings": false,'
NON_UTF8 = b"fail_on_findings: false\n# \xff\xfe\n"
BAD_TOML = "fail_on_findings = false\n[global\n"


@pytest.fixture(autouse=True)
def _no_ash_config_variable(monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)


@pytest.fixture
def scan_started(monkeypatch) -> List[Dict[str, Any]]:
    """Replace the scan with a probe; each entry is the config one scan started with."""
    started: List[Dict[str, Any]] = []

    def _probe(self, phases=None):
        started.append(
            {
                "fail_on_findings": self.config.fail_on_findings,
                "suppressions": len(self.config.global_settings.suppressions or []),
            }
        )
        return AshAggregatedResults()

    monkeypatch.setattr(ASHScanOrchestrator, "execute_scan", _probe)
    return started


def _write(path: Path, content: str | bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    return path


def _dangling_link(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(path.parent / "not-checked-out.yaml")
    return path


# Each case: how to lay out the tree, the extra ``ash scan`` arguments, and the
# environment. ``root`` holds ``src`` (the scanned tree) and files outside it.
Setup = Callable[[Path], Tuple[List[str], Dict[str, str]]]


def _explicit(name: str, content: str | bytes | None) -> Setup:
    def _setup(root: Path) -> Tuple[List[str], Dict[str, str]]:
        path = root / name
        if content is not None:
            _write(path, content)
        return ["--config", str(path)], {}

    return _setup


def _directory_as_config(root: Path) -> Tuple[List[str], Dict[str, str]]:
    (root / "config.yaml").mkdir()
    return ["--config", str(root / "config.yaml")], {}


def _empty_config_argument(root: Path) -> Tuple[List[str], Dict[str, str]]:
    return ["--config", ""], {}


def _variable(name: str, content: str | bytes | None) -> Setup:
    def _setup(root: Path) -> Tuple[List[str], Dict[str, str]]:
        path = root / name
        if content is not None:
            _write(path, content)
        return [], {"ASH_CONFIG": str(path)}

    return _setup


def _discovered(relative: str, content: str | bytes) -> Setup:
    def _setup(root: Path) -> Tuple[List[str], Dict[str, str]]:
        _write(root / "src" / relative, content)
        return [], {}

    return _setup


def _discovered_dangling_link(root: Path) -> Tuple[List[str], Dict[str, str]]:
    _dangling_link(root / "src" / ".ash" / ".ash.yaml")
    return [], {}


REFUSED = [
    pytest.param(_explicit("nope.yaml", None), id="config_option_missing_file"),
    pytest.param(_explicit("cfg.yaml", BAD_YAML), id="config_option_yaml_syntax"),
    pytest.param(_explicit("cfg.json", BAD_JSON), id="config_option_json_syntax"),
    pytest.param(_explicit("cfg.yaml", NON_UTF8), id="config_option_not_utf8"),
    pytest.param(_directory_as_config, id="config_option_names_a_directory"),
    pytest.param(_empty_config_argument, id="config_option_empty_string"),
    pytest.param(_variable("nope.yaml", None), id="ash_config_variable_missing_file"),
    pytest.param(_variable("env.yaml", BAD_YAML), id="ash_config_variable_yaml_syntax"),
    pytest.param(_discovered(".ash/.ash.yaml", BAD_YAML), id="discovered_dot_ash_dir"),
    pytest.param(_discovered(".ash.yaml", BAD_YAML), id="discovered_root_yaml"),
    pytest.param(_discovered(".ash.json", BAD_JSON), id="discovered_root_json"),
    pytest.param(_discovered(".ashrc.yaml", BAD_YAML), id="discovered_ashrc_yaml"),
    pytest.param(
        _discovered(".ash/.ash.yaml", NON_UTF8), id="discovered_dot_ash_dir_not_utf8"
    ),
    pytest.param(_discovered_dangling_link, id="discovered_dangling_symlink"),
]


def _cli_scan(root: Path, setup: Setup) -> Tuple[int, str]:
    (root / "src").mkdir(exist_ok=True)
    (root / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    args, env = setup(root)
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--no-progress",
            "--source-dir",
            str(root / "src"),
            "--output-dir",
            str(root / "out"),
            *args,
        ],
        env=env,
    )
    return result.exit_code, result.output


class TestAshScanCommand:
    @pytest.mark.parametrize("setup", REFUSED)
    def test_config_that_cannot_be_loaded_exits_three(
        self, tmp_path, monkeypatch, scan_started, setup
    ):
        monkeypatch.chdir(tmp_path)
        exit_code, output = _cli_scan(tmp_path, setup)

        assert scan_started == [], f"the scan ran with {scan_started}"
        assert exit_code == 3, output[-2000:]

    def test_control_toml_parse_error_already_exits_three(
        self, tmp_path, monkeypatch, scan_started
    ):
        monkeypatch.chdir(tmp_path)
        exit_code, output = _cli_scan(tmp_path, _discovered(".ashrc.toml", BAD_TOML))

        assert scan_started == []
        assert exit_code == 3, output[-2000:]

    def test_control_loadable_config_option_reaches_the_scan(
        self, tmp_path, monkeypatch, scan_started
    ):
        monkeypatch.chdir(tmp_path)
        exit_code, output = _cli_scan(tmp_path, _explicit("cfg.yaml", GOOD_YAML))

        assert scan_started == [{"fail_on_findings": False, "suppressions": 1}]
        assert exit_code != 3, output[-2000:]

    def test_control_no_config_file_scans_with_the_defaults(
        self, tmp_path, monkeypatch, scan_started
    ):
        monkeypatch.chdir(tmp_path)
        exit_code, output = _cli_scan(tmp_path, lambda root: ([], {}))

        assert scan_started == [{"fail_on_findings": True, "suppressions": 0}]
        assert exit_code != 3, output[-2000:]


def _api_scan(root: Path, config: Optional[str]) -> Optional[int]:
    """run_ash_scan's exit status: the SystemExit code, or None when it returned."""
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    (root / "src").mkdir(exist_ok=True)
    try:
        run_ash_scan(
            source_dir=str(root / "src"),
            output_dir=str(root / "out"),
            config=config,
            show_summary=False,
            progress=False,
        )
    except SystemExit as exc:
        return exc.code
    return None


class TestRunAshScanApi:
    """``run_ash_scan`` is what the MCP server and Python callers run."""

    @pytest.mark.parametrize(
        ("name", "content"),
        [
            pytest.param("nope.yaml", None, id="missing_file"),
            pytest.param("cfg.yaml", BAD_YAML, id="yaml_syntax"),
            pytest.param("cfg.yaml", NON_UTF8, id="not_utf8"),
        ],
    )
    def test_named_config_that_cannot_be_loaded_exits_three(
        self, tmp_path, scan_started, name, content
    ):
        path = tmp_path / name
        if content is not None:
            _write(path, content)

        status = _api_scan(tmp_path, str(path))

        assert scan_started == [], f"the scan ran with {scan_started}"
        assert status == 3

    def test_discovered_config_that_cannot_be_parsed_exits_three(
        self, tmp_path, scan_started
    ):
        _write(tmp_path / "src" / ".ash" / ".ash.yaml", BAD_YAML)

        status = _api_scan(tmp_path, None)

        assert scan_started == [], f"the scan ran with {scan_started}"
        assert status == 3

    def test_control_no_config_file_scans_with_the_defaults(
        self, tmp_path, scan_started
    ):
        status = _api_scan(tmp_path, None)

        assert scan_started == [{"fail_on_findings": True, "suppressions": 0}]
        assert status != 3
