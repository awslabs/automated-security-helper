# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import subprocess
from pathlib import Path

import pytest
import yaml

from tests.utils.github_expressions import evaluate
from tests.utils.workflow_one_line import write_helper

pytestmark = pytest.mark.integration

WORKFLOW = (
    Path(__file__).resolve().parents[2] / ".github/workflows/run-ash-security-scan.yml"
)
MODULE = "ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_betterleaks_plugins]"


def workflow():
    return yaml.safe_load(WORKFLOW.read_text())


def step(name):
    return next(s for s in workflow()["jobs"]["ash"]["steps"] if s.get("name") == name)


def run_step(tmp_path, name, env):
    steps = workflow()["jobs"]["ash"]["steps"]
    runner = tmp_path / "runner"
    write_helper(steps, runner)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    uvx = bin_dir / "uvx"
    uvx.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$@" > "$ARGV_FILE"\nexit "${UVX_STATUS:-0}"\n'
    )
    uvx.chmod(0o755)
    argv = tmp_path / "argv"
    result = subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", step(name)["run"]],
        cwd=tmp_path,
        env={
            **os.environ,
            "PATH": f"{bin_dir}:/usr/bin:/bin",
            "RUNNER_TEMP": str(runner),
            "ARGV_FILE": str(argv),
            "GITHUB_PATH": str(tmp_path / "path"),
            "ASH_UVX_SOURCE": "ash-source",
            **env,
        },
        capture_output=True,
        text=True,
        check=False,
    )
    return result, argv.read_text().splitlines() if argv.exists() else None


def test_input_and_install_selection():
    inp = workflow()[True]["workflow_call"]["inputs"]["use-betterleaks"]
    assert inp["type"] == "boolean" and inp["default"] is False
    install = step("Install actionlint, cfn-guard, gitleaks and trivy")
    only_gitleaks = {
        "inputs.install-actionlint": False,
        "inputs.install-cfn-guard": False,
        "inputs.install-gitleaks": True,
        "inputs.install-trivy": False,
        "inputs.use-betterleaks": True,
    }
    assert not evaluate(install["if"], only_gitleaks, "success")
    expr = install["env"]["INSTALL_GITLEAKS"][3:-3]
    assert (
        evaluate(
            expr,
            {"inputs.install-gitleaks": True, "inputs.use-betterleaks": True},
            "success",
        )
        is False
    )
    assert (
        evaluate(
            expr,
            {"inputs.install-gitleaks": True, "inputs.use-betterleaks": False},
            "success",
        )
        is True
    )


@pytest.mark.parametrize("status", [0, 2])
def test_installer_propagates_failure_even_with_skip(tmp_path, status):
    result, argv = run_step(
        tmp_path,
        "Install Betterleaks",
        {
            "ASH_TOOL_BIN": str(tmp_path / "runner/ash-tools"),
            "ASH_DEPENDENCIES_UNKNOWN_TOOLS": "skip",
            "UVX_STATUS": str(status),
        },
    )
    assert result.returncode == status
    assert argv == [
        "--from",
        "ash-source",
        "ash",
        "dependencies",
        "install",
        "--tool",
        "betterleaks",
        "--config-overrides",
        MODULE,
        "--bin-path",
        str(tmp_path / "runner/ash-tools"),
    ]


@pytest.mark.parametrize(
    "args, mode, refused",
    [
        ("--mode nix", "local", True),
        ("--mode=container", "local", True),
        ("--mode local", "container", False),
        ("--output-dir --mode", "local", False),
        ("-c --mode", "local", False),
        ("-- --mode=nix", "local", False),
    ],
)
def test_effective_mode(tmp_path, args, mode, refused):
    result, _ = run_step(
        tmp_path,
        "Resolve the base for changed-files-only",
        {
            "ASH_ARGS": args,
            "ASH_MODE": mode,
            "USE_BETTERLEAKS": "true",
            "CHECK_CHANGED_FILES_ONLY": "",
        },
    )
    assert (result.returncode != 0) is refused
    if refused:
        assert "use-betterleaks requires effective ASH mode local" in result.stdout


def test_scan_appends_overrides(tmp_path):
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.config.resolve_config import apply_config_overrides

    result, argv = run_step(
        tmp_path,
        "Run ASH",
        {
            "ASH_ARGS": "--config-overrides scanners.gitleaks.enabled=true",
            "ASH_MODE": "local",
            "ASH_OUTPUT_DIR": "out",
            "FAIL_ON_FINDINGS_PARAM": "--fail-on-findings",
            "VERBOSE": "",
            "CHANGED_FILES_ONLY": "",
            "BASE_REF": "",
            "USE_BETTERLEAKS": "true",
        },
    )
    assert result.returncode == 0, result.stderr
    assert argv[-6:] == [
        "--config-overrides",
        MODULE,
        "--config-overrides",
        "scanners.betterleaks.enabled=true",
        "--config-overrides",
        "scanners.gitleaks.enabled=false",
    ]
    overrides = [
        argv[index + 1] for index, arg in enumerate(argv) if arg == "--config-overrides"
    ]
    default = get_default_config()
    config = apply_config_overrides(default, overrides)
    assert set(default.ash_plugin_modules) <= set(config.ash_plugin_modules)
    assert (
        config.get_plugin_config(plugin_type="scanner", plugin_name="betterleaks")[
            "enabled"
        ]
        is True
    )
    assert config.scanners.gitleaks.enabled is False


def test_mode_validation_runs_for_either_feature():
    validate = step("Resolve the base for changed-files-only")
    for changed, betterleaks in ((False, False), (True, False), (False, True)):
        assert evaluate(
            validate["if"],
            {
                "inputs.changed-files-only": changed,
                "inputs.use-betterleaks": betterleaks,
            },
            "success",
        ) is (changed or betterleaks)
