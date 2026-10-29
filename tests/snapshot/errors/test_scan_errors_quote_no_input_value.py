# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""No error exit of ``ash scan`` prints a config value pydantic refused.

pydantic's own text for a refused value quotes it (``input_value='...'``), and
a config value can be a secret read from the environment. The scan's error
exits print their message inside Rich markup, which unescaped would read that
bracketed part as a tag and drop it; with the message escaped, so that a
quoted ``[/bold]`` cannot crash the handler, the text is printed as it is. So
each exit is driven with a refused value holding a canary, and the canary must
be in none of stdout, stderr, ash.log and ash.log.jsonl.

A config file's canary is read from the environment, ``${ASH_PROBE_VALUE}``,
the way a secret reaches a config: the refusal then holds the value and not
what the file wrote.

The scanner-selection exits are not driven: their message is built from the
scanner names on the command line, never from a validation error.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

CANARY = "ash-canary-7f3e"
SCAN = ["scan", "--no-progress"]
SECRET = "${ASH_PROBE_VALUE}"
BAD = f"project_name: canary\nfail_on_findings: {SECRET}\n"

# A refused value at each kind of field a config file sets: a global setting,
# a scanner's option (its plugin's model) and a suppression's.
REFUSED_FIELDS = {
    "fail_on_findings": BAD,
    "a scanner option": (
        "project_name: canary\n"
        "scanners:\n"
        "  bandit:\n"
        "    options:\n"
        f"      confidence_level: {SECRET}\n"
    ),
    "a suppression expiration": (
        "project_name: canary\n"
        "global_settings:\n"
        "  suppressions:\n"
        "    - rule_id: B101\n"
        "      path: app.py\n"
        "      reason: probe\n"
        f"      expiration: {SECRET}\n"
    ),
}


@pytest.fixture(autouse=True)
def _secret_and_both_log_files(monkeypatch: pytest.MonkeyPatch) -> None:
    """The canary in the environment, and the scan's logger writing the JSONL
    log as well as ash.log: the two file handlers format the same records
    differently, the JSONL one with each record's traceback as a field."""
    from automated_security_helper.config.ash_config import resolve_env_references
    from automated_security_helper.utils import log

    monkeypatch.setenv("ASH_PROBE_VALUE", CANARY)
    # The control for every test here: the canary's variable is one a
    # configuration reads, so an absent canary is withheld, not unread.
    assert resolve_env_references(SECRET) == CANARY
    get_logger = log.get_logger

    def both(*args, **kwargs):
        kwargs["log_format"] = "BOTH"
        return get_logger(*args, **kwargs)

    # _setup_logger imports it from the module when it runs.
    monkeypatch.setattr(log, "get_logger", both)


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _workspace(root: Path, *, project_config: bool) -> Path:
    project = root / "api"
    _write(project / "app.py", "print('hello')\n")
    if project_config:
        _write(project / ".ash" / ".ash.yaml", BAD)
    return _write(
        root / "demo.code-workspace", json.dumps({"folders": [{"path": "api"}]})
    )


def _log_files(root: Path) -> list[Path]:
    out = root / "out"
    return sorted(
        path
        for path in out.rglob("*")
        if path.is_file() and path.name.endswith((".log", ".log.jsonl"))
    )


def _assert_no_canary(seen: dict, root: Path, *, logged: bool = True) -> None:
    """``logged`` is False for a refusal made before the scan opens its log
    files: the workspace checks every project's config first."""
    assert seen["exit_code"] != 0, seen
    logs = _log_files(root)
    names = {path.name for path in logs}
    if logged:
        # The control: both handlers wrote, so an absent canary is a clean log.
        assert {"ash.log", "ash.log.jsonl"} <= names, names
        assert any(path.stat().st_size for path in logs), "every log file is empty"
    else:
        assert names == set(), names
    channels = {
        "stdout": seen["stdout"],
        "stderr": seen["stderr"],
        "uncaught exception": seen.get("uncaught_exception", ""),
        **{
            path.relative_to(root).as_posix(): path.read_text(
                encoding="utf-8", errors="replace"
            )
            for path in logs
        },
    }
    leaked = [name for name, text in channels.items() if CANARY in text]
    assert leaked == [], (leaked, seen)


@pytest.mark.parametrize("config", REFUSED_FIELDS.values(), ids=REFUSED_FIELDS)
def test_an_invalid_config_file(run_cli, in_tmp, config):
    _write(in_tmp / "app.py", "print('hello')\n")
    _write(in_tmp / "bad.yaml", config)
    seen = run_cli([*SCAN, "--config", "bad.yaml", "--output-dir", "out"])
    _assert_no_canary(seen, in_tmp)


@pytest.mark.parametrize("config", REFUSED_FIELDS.values(), ids=REFUSED_FIELDS)
def test_an_invalid_repository_config(run_cli, in_tmp, config):
    _write(in_tmp / "src" / "app.py", "print('hello')\n")
    _write(in_tmp / "src" / ".ash" / ".ash.yaml", config)
    seen = run_cli([*SCAN, "--source-dir", "src", "--output-dir", "out"])
    _assert_no_canary(seen, in_tmp)


def test_an_invalid_ash_config_file(run_cli, in_tmp, monkeypatch):
    monkeypatch.setenv("ASH_CONFIG", str(_write(in_tmp / "env.yaml", BAD)))
    _write(in_tmp / "src" / "app.py", "print('hello')\n")
    seen = run_cli([*SCAN, "--source-dir", "src", "--output-dir", "out"])
    _assert_no_canary(seen, in_tmp)


def test_an_invalid_project_config_in_a_workspace(run_cli, in_tmp):
    workspace = _workspace(in_tmp, project_config=True)
    seen = run_cli([*SCAN, "--workspace", workspace.name, "--output-dir", "out"])
    _assert_no_canary(seen, in_tmp, logged=False)


def test_an_invalid_ash_config_file_in_a_workspace(run_cli, in_tmp, monkeypatch):
    monkeypatch.setenv("ASH_CONFIG", str(_write(in_tmp / "env.yaml", BAD)))
    workspace = _workspace(in_tmp, project_config=False)
    seen = run_cli([*SCAN, "--workspace", workspace.name, "--output-dir", "out"])
    _assert_no_canary(seen, in_tmp, logged=False)


def test_an_env_read_option_key_of_a_loaded_plugin(run_cli, in_tmp):
    """A plugin from ash_plugin_modules is built from its section, and its model
    would refuse an unknown key quoting it. The scan refuses the configuration
    before any plugin is built (config/plugin_option_check.py), exit 3, and the
    refusal names no key read from the environment: here the canary is the key,
    `${ASH_PROBE_VALUE}: true` under trivy-repo's options."""
    _write(in_tmp / "src" / "app.py", "print('hello')\n")
    _write(
        in_tmp / "src" / ".ash" / ".ash.yaml",
        "project_name: canary\n"
        "ash_plugin_modules:\n"
        "  - automated_security_helper.plugin_modules.ash_trivy_plugins\n"
        "scanners:\n"
        "  trivy-repo:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      {SECRET}: true\n",
    )
    seen = run_cli([*SCAN, "--source-dir", "src", "--output-dir", "out"])
    _assert_no_canary(seen, in_tmp)
    # The control: the refusal is the option check's, before any plugin is built.
    assert seen["exit_code"] == 3, seen
    printed = " ".join(f"{seen['stdout']} {seen['stderr']}".split())
    assert "scanners.trivy-repo.options" in printed, printed
    assert "Unknown key '<value>'" in printed, printed


def _unhidden_refusal():
    """A ValidationError from a model that does not hide its inputs, as a
    plugin's own model might be, so the sinks are tested on their own."""
    from pydantic import BaseModel, ValidationError

    class Unhidden(BaseModel):
        flag: bool

    try:
        Unhidden.model_validate({"flag": CANARY})
    except ValidationError as error:
        assert CANARY in str(error), "the control: this model quotes its input"
        return error
    raise AssertionError("the canary was accepted")


def test_a_workspace_project_that_fails(run_cli, in_tmp, monkeypatch):
    """The per-project failure goes to the log, the unified results file and an
    MCP response, so the canary must be in none of them."""
    refused = _unhidden_refusal()

    def raise_it(*args, **kwargs):
        raise refused

    monkeypatch.setattr(
        "automated_security_helper.core.orchestrator.ASHScanOrchestrator.execute_scan",
        raise_it,
    )
    workspace = _workspace(in_tmp, project_config=False)
    seen = run_cli([*SCAN, "--workspace", workspace.name, "--output-dir", "out"])
    _assert_no_canary(seen, in_tmp)
    written = [path for path in (in_tmp / "out").rglob("*") if path.is_file()]
    assert written, "the run wrote no results"
    leaked = [
        path.relative_to(in_tmp).as_posix()
        for path in written
        if CANARY in path.read_text(encoding="utf-8", errors="replace")
    ]
    assert leaked == [], leaked
    # The control: the failure is recorded, described by its field.
    assert any(
        "Invalid value at 'flag'" in path.read_text(encoding="utf-8", errors="replace")
        for path in written
    ), [path.relative_to(in_tmp).as_posix() for path in written]


@pytest.mark.parametrize("mode", ["local", "workspace"])
def test_a_validation_error_reaching_the_generic_exit(
    run_cli, in_tmp, monkeypatch, mode
):
    """A pydantic error no refusal wraps ends at the generic exit, which logs it
    with its traceback and prints it, and neither one quotes the refused value.

    The error is from a model that quotes its input, so the exit itself is
    what keeps the canary out, not a config model that hides its inputs.
    """
    refused = _unhidden_refusal()

    def raise_it(*args, **kwargs):
        raise refused

    if mode == "local":
        monkeypatch.setattr(
            "automated_security_helper.core.orchestrator.ASHScanOrchestrator.create",
            raise_it,
        )
        _write(in_tmp / "src" / "app.py", "print('hello')\n")
        args = [*SCAN, "--source-dir", "src", "--output-dir", "out"]
    else:
        # run_ash_scan imports it inside _run_workspace_mode.
        monkeypatch.setattr(
            "automated_security_helper.workspace.execution.execute_workspace",
            raise_it,
        )
        workspace = _workspace(in_tmp, project_config=False)
        args = [*SCAN, "--workspace", workspace.name, "--output-dir", "out"]
    seen = run_cli(args)
    _assert_no_canary(seen, in_tmp)
    # The control: the error reached the generic exit, and was described there
    # by its field.
    assert seen["exit_code"] == 1, seen
    printed = " ".join(f"{seen['stdout']} {seen['stderr']}".split())
    assert "Exiting due to exception" in printed, printed
    assert "Invalid value at 'flag'" in printed, printed
