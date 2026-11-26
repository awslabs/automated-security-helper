# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""checkov gets a VCS configuration framework's API token only when it can use it.

checkov's GitLab, GitHub and Bitbucket configuration frameworks each read an API
token from the environment when checkov starts, whichever frameworks the scan
runs: each runner builds its DAL when ``checkov.main`` is imported, and the DAL
reads the token in ``discover()`` (checkov 3.3.26: bitbucket/dal.py:31
``APP_PASSWORD``, github/dal.py:47 ``GITHUB_TOKEN``, gitlab/dal.py:33
``CI_JOB_TOKEN``). So checkov held every token the host's environment had, in an
offline scan, which fetches nothing, and in a scan that leaves the frameworks
out. ASH now leaves a token out of checkov's environment in those scans, and
passes it as before to a framework that runs in an online scan.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    _VCS_CONFIGURATION_FRAMEWORKS,
    CheckovScanner,
    CheckovScannerConfig,
    CheckovScannerConfigOptions,
)
from tests.utils.env_assertions import environ_value

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()

#: The variable each framework's DAL reads its token from, as read at checkov
#: 3.3.26. Written out rather than imported, so the scanner's own table is
#: checked against the measurement.
_TOKEN = {
    "bitbucket_configuration": "APP_PASSWORD",
    "github_configuration": "GITHUB_TOKEN",
    "gitlab_configuration": "CI_JOB_TOKEN",
}

#: A value no real environment holds, so a token found in checkov's environment
#: is the one this module set.
_VALUE = "ash-test-value-not-a-credential"


@pytest.fixture(autouse=True)
def _every_token_set(monkeypatch):
    for variable in _TOKEN.values():
        monkeypatch.setenv(variable, _VALUE)


def _scanner(tmp_path: Path, **opts) -> CheckovScanner:
    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    output = tmp_path / "out"
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )
    return CheckovScanner(
        context=context,
        config=CheckovScannerConfig(options=CheckovScannerConfigOptions(**opts)),
    )


def _child_env(scanner: CheckovScanner, *, offline: bool) -> dict:
    with patch.object(CheckovScanner, "_scanner_offline", return_value=offline):
        _, _, env = scanner._execute_scan(scanner.context.source_dir, "source", [])
    assert env is not None
    return env


def _tokens_in(env: dict) -> set[str]:
    """The token variables ``env`` holds, by their upper-case names."""
    wanted = set(_TOKEN.values())
    return {name.upper() for name in env if name.upper() in wanted}


def _host_tokens_unchanged() -> None:
    for variable in _TOKEN.values():
        assert environ_value(variable) == _VALUE


def test_the_measured_table_covers_every_framework_ash_skips():
    assert sorted(_TOKEN) == sorted(_VCS_CONFIGURATION_FRAMEWORKS)


@pytest.mark.parametrize(
    "opts",
    [
        pytest.param({}, id="default-all"),
        pytest.param({"frameworks": ["terraform"]}, id="no-vcs-framework-named"),
        pytest.param(
            {"frameworks": ["all", "github_configuration"]}, id="all-but-one-skipped"
        ),
    ],
)
def test_an_online_scan_passes_no_token_of_a_framework_that_does_not_run(
    tmp_path, opts
):
    scanner = _scanner(tmp_path, **opts)

    env = _child_env(scanner, offline=False)

    ran = set(opts.get("frameworks", [])) & set(_TOKEN)
    assert _tokens_in(env) == {_TOKEN[framework] for framework in ran}
    _host_tokens_unchanged()


@pytest.mark.parametrize("vcs_fw", _VCS_CONFIGURATION_FRAMEWORKS)
def test_an_offline_scan_passes_no_token_even_to_a_framework_that_runs(
    tmp_path, vcs_fw
):
    scanner = _scanner(tmp_path, frameworks=["all", vcs_fw], offline=True)

    env = _child_env(scanner, offline=True)

    assert _tokens_in(env) == set()
    _host_tokens_unchanged()


@pytest.mark.parametrize("vcs_fw", _VCS_CONFIGURATION_FRAMEWORKS)
@pytest.mark.parametrize(
    "frameworks",
    [
        pytest.param(["all"], id="beside-all"),
        pytest.param([], id="alone"),
    ],
)
def test_an_online_scan_passes_the_token_of_a_framework_that_runs(
    tmp_path, vcs_fw, frameworks
):
    scanner = _scanner(tmp_path, frameworks=[*frameworks, vcs_fw])

    env = _child_env(scanner, offline=False)

    assert env[_TOKEN[vcs_fw]] == _VALUE


@pytest.mark.parametrize("vcs_fw", _VCS_CONFIGURATION_FRAMEWORKS)
def test_an_online_scan_passes_only_the_token_of_the_framework_that_runs(
    tmp_path, vcs_fw
):
    scanner = _scanner(tmp_path, frameworks=["all", vcs_fw])

    env = _child_env(scanner, offline=False)

    assert _tokens_in(env) == {_TOKEN[vcs_fw]}


def test_a_framework_the_config_file_names_keeps_its_token_online(tmp_path):
    config_file = tmp_path / "operator" / ".checkov.yaml"
    config_file.parent.mkdir()
    config_file.write_text(
        "framework:\n  - all\n  - bitbucket_configuration\n", encoding="utf-8"
    )
    scanner = _scanner(tmp_path, config_file=str(config_file))

    env = _child_env(scanner, offline=False)

    assert env["APP_PASSWORD"] == _VALUE
    assert _tokens_in(env) == {"APP_PASSWORD"}


def test_a_token_spelled_in_another_case_is_left_out_too(tmp_path, monkeypatch):
    # Windows reads environment names without case, so the spelling the host has
    # is the token whatever its case.
    monkeypatch.setenv("Ci_Job_Token", _VALUE)
    scanner = _scanner(tmp_path)

    env = _child_env(scanner, offline=False)

    assert _tokens_in(env) == set()
