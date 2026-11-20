# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import shutil
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
INSTALL = "Install actionlint, cfn-guard, gitleaks and trivy"
MODULE = "ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_betterleaks_plugins]"


needs_bash = pytest.mark.skipif(
    os.name == "nt" or shutil.which("bash") is None,
    reason="requires POSIX Bash",
)

NO_INSTALLS = {
    "INSTALL_ACTIONLINT": "",
    "INSTALL_CFN_GUARD": "",
    "INSTALL_GITLEAKS": "",
    "INSTALL_TRIVY": "",
}


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
        '#!/bin/sh\nprintf "%s\\n" "$@" > "$ARGV_FILE"\n'
        '[ -z "${UVX_OUTPUT:-}" ] || printf "%s\\n" "$UVX_OUTPUT"\n'
        'if [ "${UVX_RESPECTS_SKIP:-}" = 1 ] && '
        '[ "${ASH_DEPENDENCIES_UNKNOWN_TOOLS:-}" = skip ]; then exit 0; fi\n'
        'exit "${UVX_STATUS:-0}"\n'
    )
    uvx.chmod(0o755)
    argv = tmp_path / "argv"
    bash = shutil.which("bash")
    assert bash is not None
    result = subprocess.run(
        [str(Path(bash).resolve()), "-e", "-o", "pipefail", "-c", step(name)["run"]],
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
    install = step(INSTALL)
    nothing_else = {
        "inputs.install-actionlint": False,
        "inputs.install-cfn-guard": False,
        "inputs.install-gitleaks": False,
        "inputs.install-trivy": False,
    }
    assert evaluate(
        install["if"], {**nothing_else, "inputs.use-betterleaks": True}, "success"
    )
    assert not evaluate(
        install["if"], {**nothing_else, "inputs.use-betterleaks": False}, "success"
    )
    expr = _expr(install["env"]["USE_BETTERLEAKS"])
    assert evaluate(expr, {"inputs.use-betterleaks": True}, "success")
    assert not evaluate(expr, {"inputs.use-betterleaks": False}, "success")
    # The gitleaks entry is unchanged: use-betterleaks drops it in the script.
    assert install["env"]["INSTALL_GITLEAKS"] == (
        "${{ inputs.install-gitleaks && 'gitleaks' || '' }}"
    )


def _install(tmp_path, env):
    return run_step(
        tmp_path,
        INSTALL,
        {
            **NO_INSTALLS,
            "USE_BETTERLEAKS": "true",
            "ASH_TOOL_BIN": str(tmp_path / "runner/ash-tools"),
            **env,
        },
    )


def _betterleaks_call(tmp_path, *tools):
    args = ["--from", "ash-source", "ash", "dependencies", "install"]
    for tool in tools:
        args += ["--tool", tool]
    return [
        *args,
        "--config-overrides",
        MODULE,
        "--bin-path",
        str(tmp_path / "runner/ash-tools"),
    ]


@needs_bash
@pytest.mark.parametrize("status", [0, 2])
def test_installer_propagates_failure_even_with_skip(tmp_path, status):
    result, argv = _install(
        tmp_path,
        {"ASH_DEPENDENCIES_UNKNOWN_TOOLS": "skip", "UVX_STATUS": str(status)},
    )
    assert result.returncode == status
    assert argv == _betterleaks_call(tmp_path, "betterleaks")


@needs_bash
@pytest.mark.parametrize("respects_skip", ["", "1"], ids=["legacy", "current"])
def test_an_unknown_betterleaks_fails_even_with_skip(tmp_path, respects_skip):
    result, _ = _install(
        tmp_path,
        {
            "ASH_DEPENDENCIES_UNKNOWN_TOOLS": "skip",
            "UVX_RESPECTS_SKIP": respects_skip,
            "UVX_STATUS": "2",
            "UVX_OUTPUT": "Unknown tool(s): betterleaks",
        },
    )
    assert result.returncode == 2
    assert "is not a tool the installed ASH knows" not in result.stdout


@needs_bash
def test_other_unknown_tools_are_still_skipped_with_skip(tmp_path):
    result, _ = _install(
        tmp_path,
        {
            "USE_BETTERLEAKS": "",
            "INSTALL_TRIVY": "trivy",
            "ASH_DEPENDENCIES_UNKNOWN_TOOLS": "skip",
            "UVX_STATUS": "2",
            "UVX_OUTPUT": "Unknown tool(s): trivy",
        },
    )
    assert result.returncode == 0
    assert "trivy is not a tool the installed ASH knows" in result.stdout


@needs_bash
def test_betterleaks_replaces_gitleaks_in_one_install_call(tmp_path):
    result, argv = _install(
        tmp_path, {"INSTALL_GITLEAKS": "gitleaks", "INSTALL_TRIVY": "trivy"}
    )
    assert result.returncode == 0, result.stderr
    assert argv == _betterleaks_call(tmp_path, "trivy", "betterleaks")
    assert "gitleaks" not in argv


@needs_bash
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


@needs_bash
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


def _expr(value):
    assert value.startswith("${{ ") and value.endswith(" }}")
    return value[3:-3]


def test_betterleaks_is_off_unless_the_input_is_set():
    # Opt-in: with the input off (also its default, asserted above) the three steps
    # that read it see it falsy, and the install step adds no tool for it.
    for name in (INSTALL, "Resolve the base for changed-files-only", "Run ASH"):
        expr = _expr(step(name)["env"]["USE_BETTERLEAKS"])
        assert not evaluate(expr, {"inputs.use-betterleaks": False}, "success")
        assert evaluate(expr, {"inputs.use-betterleaks": True}, "success")


def test_install_gitleaks_still_installs_gitleaks_by_default():
    install = step(INSTALL)
    context = {
        "inputs.install-actionlint": False,
        "inputs.install-cfn-guard": False,
        "inputs.install-trivy": False,
        "inputs.install-gitleaks": True,
        "inputs.use-betterleaks": False,
    }
    assert evaluate(install["if"], context, "success")
    expr = _expr(install["env"]["INSTALL_GITLEAKS"])
    assert evaluate(expr, context, "success")
    context["inputs.install-gitleaks"] = False
    assert not evaluate(expr, context, "success")
    assert not evaluate(install["if"], context, "success")


@needs_bash
def test_scan_adds_nothing_when_the_input_is_off(tmp_path):
    env = {
        "ASH_ARGS": "--config-overrides scanners.gitleaks.enabled=true",
        "ASH_MODE": "local",
        "ASH_OUTPUT_DIR": "out",
        "FAIL_ON_FINDINGS_PARAM": "--fail-on-findings",
        "VERBOSE": "",
        "CHANGED_FILES_ONLY": "",
        "BASE_REF": "",
    }
    for extra in ({}, {"USE_BETTERLEAKS": ""}):
        result, argv = run_step(tmp_path, "Run ASH", {**env, **extra})
        assert result.returncode == 0, result.stderr
        assert argv[-2:] == ["--config-overrides", "scanners.gitleaks.enabled=true"]
        assert not any("betterleaks" in arg for arg in argv)


def test_install_runs_after_the_mode_check_and_before_the_scan():
    names = [s.get("name") for s in workflow()["jobs"]["ash"]["steps"]]
    resolve = names.index("Resolve the base for changed-files-only")
    install = names.index(INSTALL)
    assert resolve < install < names.index("Run ASH")
    assert "Install Betterleaks" not in names


def test_install_step_receives_no_secrets_and_no_new_action():
    install = step(INSTALL)
    assert "uses" not in install
    assert install["env"]["USE_BETTERLEAKS"]
    assert "secrets." not in yaml.safe_dump(install)
