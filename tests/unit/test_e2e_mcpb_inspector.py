# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The decisions scripts/e2e/mcpb_inspector.py makes without a server.

The MCPB e2e leg retargets the shipped bundle at a wheel, translates the shared cases
into the config run_ash_scan takes, and turns the server's answers into the exit code
assert_outcome judges. Each of those is a place where the leg could pass while testing
something other than the bundle or the case, so each is pinned here, including the
inputs it must refuse.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "e2e" / "mcpb_inspector.py"
CASES = REPO_ROOT / "tests" / "e2e" / "fixtures" / "cases.json"
COMMITTED_BUNDLE = (
    REPO_ROOT / "ash-agent-plugins" / "agentic-coding" / "plugins" / "mcpb" / "ash.mcpb"
)


def _load():
    spec = importlib.util.spec_from_file_location("ash_e2e_mcpb_inspector", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


mi = _load()
SCANNERS = [
    "bandit",
    "cdk_nag",
    "cfn_nag",
    "checkov",
    "detect_secrets",
    "grype",
    "npm_audit",
    "opengrep",
    "semgrep",
    "syft",
]


def _case(name):
    return json.loads(CASES.read_text(encoding="utf-8"))["cases"][name]


def _config(args=None, command="uvx"):
    return {
        "command": command,
        "args": args
        or [
            "--from=git+https://github.com/awslabs/automated-security-helper@v3.7.0",
            "ashx",
            "mcp",
        ],
        "env": {"FASTMCP_LOG_LEVEL": "ERROR"},
    }


# --------------------------------------------------------------------------
# The bundle and the rewrite
# --------------------------------------------------------------------------


def test_the_committed_bundle_is_one_manifest_the_rewrite_accepts(tmp_path):
    manifest = mi.read_bundle(COMMITTED_BUNDLE)
    config = mi.mcp_config_of(manifest)
    rewritten = mi.rewrite_from(config, tmp_path / "a.whl")
    changed = [
        i for i, (a, b) in enumerate(zip(config["args"], rewritten["args"])) if a != b
    ]
    assert len(changed) == 1
    assert rewritten["args"][changed[0]] == f"--from={tmp_path / 'a.whl'}"
    assert rewritten["env"] == config["env"]
    assert rewritten["command"] == config["command"]


def test_the_rewrite_does_not_mutate_its_input(tmp_path):
    config = _config()
    before = json.dumps(config, sort_keys=True)
    mi.rewrite_from(config, tmp_path / "a.whl")
    assert json.dumps(config, sort_keys=True) == before


@pytest.mark.parametrize(
    "config, reason",
    [
        (_config(command="npx"), "uvx"),
        (_config(args=["ashx", "mcp"]), "exactly one --from"),
        (
            _config(
                args=[
                    "--from=git+https://github.com/awslabs/automated-security-helper@v1",
                    "--from=git+https://github.com/awslabs/automated-security-helper@v2",
                    "ashx",
                ]
            ),
            "exactly one --from",
        ),
        (_config(args=["--from", "x", "ashx", "mcp"]), "not a --from=git+"),
        (
            _config(args=["--from=git+https://example.com/someone-else@v1", "ashx"]),
            "not a --from=git+",
        ),
    ],
)
def test_the_rewrite_refuses_a_launch_it_cannot_retarget_exactly(
    tmp_path, config, reason
):
    with pytest.raises(mi.Failure, match=re.escape(reason)):
        mi.rewrite_from(config, tmp_path / "a.whl")


def _zip(path: Path, members):
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return path


def test_read_bundle_refuses_a_second_member(tmp_path):
    bundle = _zip(
        tmp_path / "b.mcpb", {"manifest.json": "{}", "vendored/tool.py": "x = 1\n"}
    )
    with pytest.raises(mi.Failure, match="exactly one member"):
        mi.read_bundle(bundle)


def test_read_bundle_refuses_a_non_zip(tmp_path):
    bundle = tmp_path / "b.mcpb"
    bundle.write_bytes(b"not a zip")
    with pytest.raises(mi.Failure, match="not a ZIP"):
        mi.read_bundle(bundle)


def test_mcp_config_of_refuses_a_manifest_without_one():
    with pytest.raises(mi.Failure, match="no server.mcp_config"):
        mi.mcp_config_of({"server": {}})


# --------------------------------------------------------------------------
# Cases into config
# --------------------------------------------------------------------------


def test_the_findings_case_enables_detect_secrets_alone():
    config = mi.case_config(_case("findings"), SCANNERS)
    enabled = sorted(k for k, v in config["scanners"].items() if v["enabled"])
    assert enabled == ["detect-secrets"]
    assert len(config["scanners"]) == len(SCANNERS)


def test_the_incomplete_case_enables_opengrep_and_applies_its_override():
    case = _case("incomplete")
    assert "--config-overrides" in case["args"]
    config = mi.case_config(case, SCANNERS)
    enabled = sorted(k for k, v in config["scanners"].items() if v["enabled"])
    assert enabled == ["detect-secrets", "opengrep"]


def test_an_override_reaches_the_config_even_for_an_unselected_scanner():
    case = dict(
        _case("findings"), args=["--config-overrides", "scanners.bandit.enabled=true"]
    )
    assert mi.case_config(case, SCANNERS)["scanners"]["bandit"]["enabled"] is True


@pytest.mark.parametrize(
    "args",
    [
        ["--no-fail-on-findings"],
        ["--config-overrides"],
        ["--config-overrides", "novalue"],
    ],
)
def test_a_case_arg_without_an_mcp_equivalent_is_refused(args):
    case = dict(_case("findings"), args=args)
    with pytest.raises(mi.Failure):
        mi.case_config(case, SCANNERS)


def test_a_scanner_the_server_does_not_list_is_refused():
    case = dict(_case("findings"), scanners=["detect-secrets", "nope"])
    with pytest.raises(mi.Failure, match="nope"):
        mi.case_config(case, SCANNERS)


# --------------------------------------------------------------------------
# The server's verdict into an exit code
# --------------------------------------------------------------------------


def _progress(status, coverage, incomplete=()):
    return {
        "status": status,
        "coverage_complete": coverage,
        "incomplete_scanners": [
            {"scanner": s, "status": "MISSING"} for s in incomplete
        ],
    }


def _summary(actionable):
    return {"findings_summary": {"by_severity": {"actionable": actionable}}}


@pytest.mark.parametrize(
    "name, progress, summary, rc",
    [
        ("findings", _progress("completed", True), _summary(3), 2),
        ("clean", _progress("completed", True), _summary(0), 0),
        ("incomplete", _progress("incomplete", False, ["opengrep"]), _summary(3), 1),
    ],
)
def test_the_expected_answers_map_to_the_case_exit_code(name, progress, summary, rc):
    problems, derived = mi.verdict_problems(_case(name), progress, summary)
    assert problems == []
    assert derived == rc


@pytest.mark.parametrize(
    "name, progress, summary, needle",
    [
        (
            "findings",
            _progress("incomplete", False, ["opengrep"]),
            _summary(3),
            "status",
        ),
        ("findings", _progress("completed", False), _summary(3), "coverage_complete"),
        ("findings", _progress("completed", None), _summary(3), "coverage_complete"),
        (
            "incomplete",
            _progress("incomplete", False, []),
            _summary(3),
            "incomplete_scanners",
        ),
        (
            "incomplete",
            _progress("incomplete", False, ["opengrep", "bandit"]),
            _summary(3),
            "incomplete_scanners",
        ),
        (
            "findings",
            _progress("completed", True, ["bandit"]),
            _summary(3),
            "incomplete_scanners",
        ),
        ("clean", _progress("failed", None), _summary(0), "no exit code"),
        ("findings", _progress("completed", True), {}, "no exit code"),
    ],
)
def test_a_wrong_answer_is_a_problem(name, progress, summary, needle):
    problems, _ = mi.verdict_problems(_case(name), progress, summary)
    assert any(needle in p for p in problems), problems


def test_a_failed_scan_implies_no_exit_code():
    _, derived = mi.verdict_problems(
        _case("incomplete"), _progress("failed", None), _summary(3)
    )
    assert derived is None


def test_a_completed_scan_with_findings_derives_2_even_against_the_clean_case():
    # The derivation reports what the server said; judging it is assert_outcome's job.
    problems, derived = mi.verdict_problems(
        _case("clean"), _progress("completed", True), _summary(3)
    )
    assert derived == 2
    assert problems == []


# --------------------------------------------------------------------------
# Inspector replies
# --------------------------------------------------------------------------


def test_tool_result_reads_structured_content():
    payload = {"result": {"structuredContent": {"result": {"a": 1}}, "content": []}}
    assert mi.tool_result("t", 0, payload) == {"a": 1}


def test_tool_result_reads_a_list_as_text_items():
    payload = {
        "result": {
            "content": [
                {"type": "text", "text": json.dumps({"name": "bandit"})},
                {"type": "text", "text": json.dumps({"name": "grype"})},
            ]
        }
    }
    assert mi.tool_result("t", 0, payload) == [{"name": "bandit"}, {"name": "grype"}]


@pytest.mark.parametrize(
    "rc, payload",
    [
        (1, {"error": {"message": "Connection closed"}}),
        (0, None),
        (0, {"result": {"isError": True, "content": []}}),
        (0, {"result": {"content": [{"type": "text", "text": "not json"}]}}),
    ],
)
def test_tool_result_refuses_a_failed_call(rc, payload):
    with pytest.raises(mi.Failure):
        mi.tool_result("t", rc, payload)


def test_listed_tools():
    assert mi.listed_tools(
        0, {"result": {"tools": [{"name": "a"}, {"name": "b"}]}}
    ) == ["a", "b"]
    assert mi.listed_tools(1, {"result": {"tools": [{"name": "a"}]}}) is None
    assert mi.listed_tools(0, {"tools": [{"name": "a"}]}) is None
    assert mi.listed_tools(0, None) is None


def test_wheel_version():
    assert (
        mi.wheel_version(Path("automated_security_helper-3.6.0-py3-none-any.whl"))
        == "3.6.0"
    )


# --------------------------------------------------------------------------
# The Inspector pin
# --------------------------------------------------------------------------


def test_the_inspector_pin_matches_validate_mcp():
    action = (
        REPO_ROOT / ".github" / "actions" / "validate-mcp" / "action.yml"
    ).read_text(encoding="utf-8")
    pinned = re.findall(r'INSPECTOR_VERSION:\s*"([^"]+)"', action)
    script = (REPO_ROOT / "scripts" / "e2e" / "mcpb.sh").read_text(encoding="utf-8")
    ours = re.findall(r"E2E_INSPECTOR_VERSION:-([0-9][^}]*)\}", script)
    assert len(pinned) == 1 and len(ours) == 1, (pinned, ours)
    assert ours == pinned
