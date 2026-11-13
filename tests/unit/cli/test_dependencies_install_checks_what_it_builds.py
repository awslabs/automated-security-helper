# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash dependencies install`` refuses a bad option only in a plugin it builds.

The command refuses a configuration whose loaded plugin has an unknown or
refused option, exit 3, before it builds any plugin, as a scan refuses it. It
checked every registered plugin, while it builds only the kinds
``--plugin-type`` names and, with ``--tool``, only those tools. A bad option of
a plugin the run does not build is not this run's to refuse: it is reported at
info, as the file treats an unrelated plugin elsewhere.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli import dependencies as dependencies_module
from automated_security_helper.cli.dependencies import dependencies_app

pytestmark = pytest.mark.unit

GOOD_TRIVY = "ignore_unfixed: true"
GOOD_S3 = "bucket_name: demo-bucket"
BAD = "no_such_option: true"


def _install(tmp_path, monkeypatch, trivy: str, s3: str, *args: str):
    """ash dependencies install with trivy-repo and the s3 reporter loaded from
    ash_plugin_modules, each with the given option line. No install runs."""
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(dependencies_module, "run_command", lambda cmd, shell=False: 0)
    config = tmp_path / "op.yaml"
    config.write_text(
        "project_name: demo\n"
        "ash_plugin_modules:\n"
        "  - automated_security_helper.plugin_modules.ash_trivy_plugins\n"
        "  - automated_security_helper.plugin_modules.ash_aws_plugins\n"
        "scanners:\n"
        "  trivy-repo:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      {trivy}\n"
        "reporters:\n"
        "  s3:\n"
        "    enabled: false\n"
        "    options:\n"
        f"      {s3}\n",
        encoding="utf-8",
    )
    result = CliRunner().invoke(
        dependencies_app,
        ["--config", str(config), "--bin-path", str(tmp_path / "bin"), *args],
        env={"COLUMNS": "300"},
    )
    return result, " ".join(f"{result.stdout}\n{result.stderr}".split())


@pytest.mark.parametrize(
    ("trivy", "s3", "args", "where"),
    [
        pytest.param(
            BAD,
            GOOD_S3,
            ("--plugin-type", "reporter"),
            "scanners.trivy-repo.options",
            id="a-scanner-option-on-a-reporter-run",
        ),
        pytest.param(
            GOOD_TRIVY,
            BAD,
            ("--tool", "trivy-repo"),
            "reporters.s3.options",
            id="a-reporter-option-on-a-run-for-one-scanner",
        ),
    ],
)
def test_a_bad_option_of_a_plugin_not_built_is_reported_not_refused(
    tmp_path, monkeypatch, trivy, s3, args, where
):
    result, printed = _install(tmp_path, monkeypatch, trivy, s3, *args)
    assert result.exit_code != 3, printed
    assert "Invalid configuration" not in printed, printed
    # Reported, at info, by its location.
    assert where in printed, printed


@pytest.mark.parametrize(
    ("trivy", "s3", "args", "where"),
    [
        pytest.param(
            GOOD_TRIVY,
            BAD,
            ("--plugin-type", "reporter"),
            "reporters.s3.options",
            id="a-reporter-option-on-a-reporter-run",
        ),
        pytest.param(
            BAD,
            GOOD_S3,
            ("--tool", "trivy-repo"),
            "scanners.trivy-repo.options",
            id="the-option-of-the-tool-requested",
        ),
    ],
)
def test_a_bad_option_of_a_plugin_built_is_refused(
    tmp_path, monkeypatch, trivy, s3, args, where
):
    """The control: in a plugin the run builds, the option still refuses the
    configuration, exit 3."""
    result, printed = _install(tmp_path, monkeypatch, trivy, s3, *args)
    assert result.exit_code == 3, printed
    assert "Invalid configuration" in printed, printed
    assert where in printed, printed


@pytest.mark.parametrize("tool", ["trivy-repo", "bandit"])
def test_a_plugin_named_only_by_building_it_is_checked_on_a_tool_run(
    tmp_path, monkeypatch, tool
):
    """A plugin whose name cannot be read without building it is built on every
    --tool run, to learn its name, so its bad option refuses the configuration,
    exit 3, as it did before the check was narrowed. Not only logged: then its
    own model refused the option while it was built, and a --tool naming it
    became an unknown tool."""
    declared = dependencies_module._declared_install_name

    def trivy_named_only_by_building(plugin_class, plugin_type, resolved_config):
        if plugin_class.__name__ == "TrivyRepoScanner":
            return None
        return declared(plugin_class, plugin_type, resolved_config)

    monkeypatch.setattr(
        dependencies_module, "_declared_install_name", trivy_named_only_by_building
    )
    result, printed = _install(tmp_path, monkeypatch, BAD, GOOD_S3, "--tool", tool)
    assert result.exit_code == 3, printed
    assert "Invalid configuration" in printed, printed
    assert "scanners.trivy-repo.options" in printed, printed
