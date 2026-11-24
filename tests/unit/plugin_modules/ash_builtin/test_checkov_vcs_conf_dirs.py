# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""checkov's VCS configuration frameworks must write below the results directory.

checkov's ``gitlab_configuration`` (and the GitHub and Bitbucket) framework fetches
the repository host's settings in a CI job and writes them to a directory below its
working directory. ASH runs checkov from the filesystem root, so the default
``gitlab_conf`` was ``/gitlab_conf``: a user that is not root cannot create it, the
framework raised ``PermissionError``, checkov exited 2, and ASH reported the scan as
incomplete. The directories are pointed below the scanner's results directory through
the variables checkov reads, and an operator's own value is left alone.
"""

import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
    CheckovScannerConfig,
)

PluginContext.model_rebuild()

VARIABLES = {
    "CKV_GITHUB_CONF_DIR_NAME": "github_conf",
    "CKV_GITLAB_CONF_DIR_NAME": "gitlab_conf",
    "CKV_BITBUCKET_CONF_DIR_NAME": "bitbucket_conf",
}


def _environment(tmp_path: Path):
    source = tmp_path / "src"
    output = tmp_path / "out"
    source.mkdir()
    output.mkdir()
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )
    scanner = CheckovScanner(context=context, config=CheckovScannerConfig())
    _, results_file, env = scanner._execute_scan(source, "source", [])
    return results_file, env


@pytest.fixture(autouse=True)
def _no_operator_values(monkeypatch):
    for variable in VARIABLES:
        monkeypatch.delenv(variable, raising=False)


def test_each_framework_directory_is_below_the_results_directory(tmp_path):
    results_file, env = _environment(tmp_path)

    assert env is not None
    results_dir = results_file.parent
    for variable, name in VARIABLES.items():
        directory = Path(env[variable])
        # Absolute: checkov joins it to its working directory, and an absolute
        # path is used as it is. A relative one would land under `/` again.
        assert directory.is_absolute()
        assert directory == results_dir / "vcs-config" / name
        assert directory.parent.name == "vcs-config"


def test_an_operator_value_is_kept(tmp_path, monkeypatch):
    monkeypatch.setenv("CKV_GITLAB_CONF_DIR_NAME", "/somewhere/else")

    _, env = _environment(tmp_path)

    assert env["CKV_GITLAB_CONF_DIR_NAME"] == "/somewhere/else"
    # The other two are still pointed away from the working directory.
    assert Path(env["CKV_GITHUB_CONF_DIR_NAME"]).is_absolute()
    assert Path(env["CKV_BITBUCKET_CONF_DIR_NAME"]).is_absolute()


def test_the_rest_of_the_environment_reaches_checkov(tmp_path, monkeypatch):
    monkeypatch.setenv("ASH_TEST_MARKER_VARIABLE", "kept")

    _, env = _environment(tmp_path)

    # A dict replaces the child's environment rather than adding to it.
    assert env["ASH_TEST_MARKER_VARIABLE"] == "kept"
    assert env.get("PATH") == os.environ.get("PATH")
