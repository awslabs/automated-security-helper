# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A bound profile is materialized as its file wrote it, references included.

``select_profile`` writes the bound configuration into the session's sandbox,
and the scan is handed that file. Writing the configuration as loaded, each
value read from the environment resolved, would leave the value in the file as
plain text: the scan would read it as a literal, which no redaction knows to
hide, and print it. The file keeps each reference as the profile wrote it
(``${VAR}``, ``!ENV ${VAR}``), so the scan resolves it at load, as it does for
any config file, and redacts it.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from tests.utils.child_tool_starts import POSIX_ONLY, ChildToolStarts
from tests.utils.helpers import checkout_env

CANARY = "ash-canary-7f3e-0123456789"
REFERENCE = "${ASH_PROBE_VALUE}"
PROFILE = (
    f"project_name: {REFERENCE}\n"
    "reporters:\n"
    "  gitlab-cyclonedx:\n"
    "    options:\n"
    f"      language_override: {REFERENCE}\n"
    f"      package_manager_override: !ENV {REFERENCE}\n"
)
SHOWN_SECTION = "Found config for reporter plugin gitlab-cyclonedx"


def _shows_the_value(text: str) -> bool:
    squeezed = re.sub(r"[\s─-╿]", "", text)
    return CANARY in squeezed or CANARY[:12] in squeezed


def _redacted(text: str) -> str:
    """*text* with the probe value replaced, for assertion messages built from
    child output: a failure message must not show what the cell holds hidden."""
    return text.replace(CANARY, "<redacted>").replace(CANARY[:12], "<redacted>")


@pytest.fixture
def bound(tmp_path, monkeypatch):
    """The path select_profile materialized for a profile reading the canary."""
    from automated_security_helper.cli.mcp import profile_registry
    from automated_security_helper.cli.mcp_tools import mcp_select_profile

    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_PROBE_VALUE", CANARY)
    profile_registry.clear_profile_registry()
    profile_registry.clear_all_session_state()
    profile = tmp_path / "operator.ash.yaml"
    profile.write_text(PROFILE, encoding="utf-8")
    profile_registry.set_profile_registry(
        profile_registry.register_profiles([f"op={profile}"])
    )
    try:
        result = mcp_select_profile("op", session_id="session-a")
        assert result["success"] is True, result.get("error")
        yield Path(profile_registry.resolve_session_config_path("session-a"))
    finally:
        profile_registry.clear_profile_registry()
        profile_registry.clear_all_session_state()


@pytest.mark.unit
def test_the_materialized_file_keeps_each_reference(bound):
    text = bound.read_text(encoding="utf-8")
    shown = _shows_the_value(text)
    assert not shown, "the materialized file holds the value"
    assert text.count(REFERENCE) == 3, "a reference was not kept"
    assert f"!ENV {REFERENCE}" in text or f"!ENV '{REFERENCE}'" in text


@pytest.mark.unit
def test_a_patched_profile_keeps_the_references_it_did_not_patch(tmp_path, monkeypatch):
    """Inherit-and-patch: the client's ops are written as the client wrote
    them, and every other reference as the profile wrote it."""
    from automated_security_helper.cli.mcp import profile_registry
    from automated_security_helper.cli.mcp_tools import mcp_select_profile

    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_PROBE_VALUE", CANARY)
    profile_registry.clear_profile_registry()
    profile_registry.clear_all_session_state()
    profile = tmp_path / "operator.ash.yaml"
    profile.write_text(
        PROFILE + "global_settings:\n"
        "  mcp:\n"
        "    runtime_overrides:\n"
        "      enabled: true\n"
        "      allowed_paths:\n"
        "        - /project_name\n"
        "      denied_paths: []\n",
        encoding="utf-8",
    )
    profile_registry.set_profile_registry(
        profile_registry.register_profiles([f"op={profile}"])
    )
    try:
        result = mcp_select_profile(
            "op",
            patch_ops=[{"op": "replace", "path": "/project_name", "value": "patched"}],
            session_id="session-a",
        )
        assert result["success"] is True, result.get("error")
        text = Path(
            profile_registry.resolve_session_config_path("session-a")
        ).read_text(encoding="utf-8")
    finally:
        profile_registry.clear_profile_registry()
        profile_registry.clear_all_session_state()

    # The control: the patch reached the file.
    assert "project_name: patched" in text
    shown = _shows_the_value(text)
    assert not shown, "the materialized file holds the value"
    assert text.count(REFERENCE) == 2, "an unpatched reference was not kept"


@pytest.mark.unit
def test_the_materialized_file_reads_the_value(bound):
    """The control: a scan handed the file reads each reference through."""
    from automated_security_helper.config.resolve_config import resolve_config

    config = resolve_config(bound)
    options = config.reporters.model_dump(by_alias=True)["gitlab-cyclonedx"]["options"]
    read = (
        config.project_name == CANARY
        and options["language_override"] == CANARY
        and options["package_manager_override"] == CANARY
    )
    assert read, "a reference no longer resolves"


@POSIX_ONLY
@pytest.mark.e2e
def test_a_scan_under_the_bound_profile_shows_no_value(bound, tmp_path):
    """The scan the client starts next, as a child process: what it prints and
    logs holds no value, while the debug line showing the reporter's section
    (the control) is printed."""
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("print('hello')\n", encoding="utf-8")
    output = tmp_path / "out"
    started = ChildToolStarts(tmp_path)
    scan = subprocess.run(
        [
            sys.executable,
            "-c",
            started.program(
                "from automated_security_helper.cli.main import app; app()"
            ),
            "scan",
            "--no-progress",
            "--source-dir",
            str(source),
            "--output-dir",
            str(output),
            "--config",
            str(bound),
            "--scanners",
            "detect-secrets",
            "--sandbox",
            "off",
            "--offline",
            "--no-fail-on-findings",
            "--no-fail-on-incomplete-scanners",
            "--debug",
        ],
        capture_output=True,
        text=True,
        timeout=600,
        cwd=tmp_path,
        # The child's probes are answered first (ChildToolStarts.program): it
        # found the uv installed with ASH beside its interpreter, which is
        # asked for before PATH, and detect-secrets' dependency check ran
        # ``uv tool run detect-secrets --version`` for real. The environment is
        # offline anyway, so a start fetches nothing whatever the outer
        # environment is, and has tool and cache directories of the test's
        # own, not the HOME the unit tests' guard checks (ChildToolStarts sets
        # both); the cell holds the starts at none.
        env=checkout_env(
            started.child_env(
                {
                    **os.environ,
                    "COLUMNS": "300",
                }
            )
        ),
        check=False,
    )
    printed = f"{scan.stdout}\n{scan.stderr}"
    # Child output goes into assertion messages only with the probe value
    # replaced: a child that crashed while printing it would otherwise put
    # the value into the failure text, the exact showing these cells refuse.
    diagnosis = _redacted(
        f"ash exited {scan.returncode}\nstdout:\n{scan.stdout[-3000:]}"
        f"\nstderr:\n{scan.stderr[-3000:]}"
    )
    # The child answered its tool probes without starting a tool: nothing
    # reached a stand-in, and no uv left anything in its directories. Read
    # the record first: a shadowed child exits with a bare status, and its
    # reason sits in the log that starts() reads, which a returncode
    # assertion alone would never show.
    assert started.starts() == [], diagnosis
    # Bound first, asserted by name: pytest's assertion rewriting prints the
    # operands of a failing comparison (the CompletedProcess repr with its
    # stdout and stderr, the raw child output) into the explanation, which is
    # the showing these assertions' redacted messages exist to withhold.
    exited_clean = scan.returncode == 0
    assert exited_clean, diagnosis
    section_shown = SHOWN_SECTION in printed
    assert section_shown, _redacted(
        f"the reporter section was not shown (ash exited {scan.returncode})"
    )
    shown = _shows_the_value(printed)
    assert not shown, "the scan printed the value"
    logs = [path for path in output.rglob("ash.log*") if path.is_file()]
    assert logs, "the scan wrote no log"
    logged = [
        path.name
        for path in logs
        if _shows_the_value(path.read_text(encoding="utf-8", errors="replace"))
    ]
    assert logged == [], logged


@pytest.mark.integration
def test_a_canary_a_child_prints_never_reaches_the_failure_text():
    """A child that crashes while printing the probe value must not put the
    value into the assertion message built from its output: the diagnosis is
    read through _redacted before anything of the child's enters it."""
    child = subprocess.run(  # nosec B603 - fixed argv, the interpreter running this test
        [sys.executable, "-c", f"import sys\nprint({CANARY!r})\nsys.exit(3)"],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    diagnosis = _redacted(
        f"ash exited {child.returncode}\nstdout:\n{child.stdout[-3000:]}"
        f"\nstderr:\n{child.stderr[-3000:]}"
    )
    assert child.returncode == 3
    assert CANARY in child.stdout
    assert CANARY not in diagnosis, "the diagnosis shows the value"
    assert CANARY[:12] not in diagnosis, "the diagnosis shows the value's prefix"
