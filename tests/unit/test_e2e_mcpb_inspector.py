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


def _committed_args():
    """The committed bundle's own launch args.

    Read from the bundle rather than written out, because a literal install ref here
    names one release: `cz bump` does not rewrite test files, so after the next bump
    it would be the one stale pin in the tree.
    """
    return list(mi.mcp_config_of(mi.read_bundle(COMMITTED_BUNDLE))["args"])


def _config(args=None, command="uvx"):
    return {
        "command": command,
        "args": args or _committed_args(),
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
# The Inspector's lockfile
# --------------------------------------------------------------------------

INSPECTOR_LOCK = REPO_ROOT / "scripts" / "e2e" / "inspector"
NPM_REGISTRY = "https://registry.npmjs.org/"


def lock_problems(package: dict, lock: dict) -> list:
    """Every way the inspector lockfile fails to pin what npm ci installs."""
    problems = []
    wanted = package.get("dependencies", {})
    if list(wanted) != ["@modelcontextprotocol/inspector"]:
        problems.append(
            f"package.json depends on {sorted(wanted)}, not the inspector alone"
        )
    version = wanted.get("@modelcontextprotocol/inspector", "")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        problems.append(f"the inspector is {version!r}, not an exact version")
    packages = lock.get("packages", {})
    if packages.get("", {}).get("dependencies") != wanted:
        problems.append(
            "the lockfile's root does not declare package.json's dependencies"
        )
    installed = packages.get("node_modules/@modelcontextprotocol/inspector", {})
    if installed.get("version") != version:
        problems.append(f"the lockfile installs inspector {installed.get('version')!r}")
    for name, entry in packages.items():
        if not name or entry.get("link"):
            continue
        if not str(entry.get("integrity", "")).startswith("sha512-"):
            problems.append(f"{name} has no sha512 integrity hash")
        if not str(entry.get("resolved", "")).startswith(NPM_REGISTRY):
            problems.append(f"{name} resolves from {entry.get('resolved')!r}")
    return problems


def _lock_files():
    package = json.loads((INSPECTOR_LOCK / "package.json").read_text(encoding="utf-8"))
    lock = json.loads(
        (INSPECTOR_LOCK / "package-lock.json").read_text(encoding="utf-8")
    )
    return package, lock


def test_the_inspector_lock_pins_every_dependency():
    package, lock = _lock_files()
    assert lock_problems(package, lock) == []
    assert len(lock["packages"]) > 10, "the lock should carry the transitive closure"


@pytest.mark.parametrize(
    "plant, needle",
    [
        (
            lambda p, l: p["dependencies"].update({"left-pad": "1.3.0"}),
            "not the inspector alone",
        ),
        (
            lambda p, l: p["dependencies"].update(
                {"@modelcontextprotocol/inspector": "^2.9.0"}
            ),
            "not an exact version",
        ),
        (
            lambda p, l: next(e for k, e in l["packages"].items() if k).pop(
                "integrity"
            ),
            "no sha512 integrity hash",
        ),
        (
            lambda p, l: next(e for k, e in l["packages"].items() if k).update(
                {"resolved": "https://mirror.example.invalid/x.tgz"}
            ),
            "resolves from",
        ),
        (
            lambda p, l: l["packages"][
                "node_modules/@modelcontextprotocol/inspector"
            ].update({"version": "0.0.1"}),
            "the lockfile installs inspector",
        ),
    ],
)
def test_a_lock_that_does_not_pin_is_refused(plant, needle):
    package, lock = _lock_files()
    plant(package, lock)
    assert any(needle in problem for problem in lock_problems(package, lock))


def test_the_inspector_pin_matches_validate_mcp():
    action = (
        REPO_ROOT / ".github" / "actions" / "validate-mcp" / "action.yml"
    ).read_text(encoding="utf-8")
    pinned = re.findall(r'INSPECTOR_VERSION:\s*"([^"]+)"', action)
    package, _ = _lock_files()
    assert len(pinned) == 1, pinned
    assert package["dependencies"]["@modelcontextprotocol/inspector"] == pinned[0]


def test_mcpb_sh_installs_the_inspector_from_the_lock_only():
    script = (REPO_ROOT / "scripts" / "e2e" / "mcpb.sh").read_text(encoding="utf-8")
    code = [line for line in script.splitlines() if not line.lstrip().startswith("#")]
    assert any(
        re.search(r"\bnpm ci --prefix \"\$WORK/inspector\"", line) for line in code
    )
    assert not any(re.search(r"\bnpm (install|i)\b", line) for line in code), (
        "an npm install next to the lock would resolve versions the lock does not record"
    )
    assert "E2E_INSPECTOR_VERSION" not in script, (
        "a lock cannot be overridden by a version"
    )


# --------------------------------------------------------------------------
# The bundle's own version and the bundle upgrade
# --------------------------------------------------------------------------


def _pyproject_version():
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    return re.search(r'^version = "([^"]+)"$', text, re.MULTILINE).group(1)


def test_the_committed_bundle_version_is_the_ash_version():
    # What a desktop host compares, tied to what the bundle launches.
    assert mi.read_bundle(COMMITTED_BUNDLE)["version"] == _pyproject_version()


def _bundle(version, name="ash"):
    return {"name": name, "version": version}


def test_a_bundle_upgrade_that_moves_is_accepted():
    assert (
        mi.bundle_upgrade_problems(_bundle("3.0.0"), _bundle("4.0.0"), "3.0.0", "4.0.0")
        == []
    )


@pytest.mark.parametrize(
    "prev, head, needle",
    [
        # The negative control the e2e run also shows: the head bundle kept N-1's version.
        (_bundle("3.0.0"), _bundle("3.0.0"), "not raised"),
        # The state this replaced: every bundle said 1.0.0.
        (_bundle("1.0.0"), _bundle("1.0.0"), "must be the ASH release"),
        (_bundle("4.0.0"), _bundle("3.0.0"), "not raised"),
        (_bundle("3.0.0"), _bundle("4.0.0", name="ash-next"), "two extensions"),
        (_bundle("3.0.0"), _bundle("4.0.0rc1"), "not both MAJOR.MINOR.PATCH"),
    ],
)
def test_a_bundle_upgrade_a_host_would_not_apply_is_refused(prev, head, needle):
    problems = mi.bundle_upgrade_problems(prev, head, "3.0.0", "4.0.0")
    assert any(needle in problem for problem in problems), problems


def test_mcpb_sh_builds_the_prev_bundle_and_hands_it_over():
    script = (REPO_ROOT / "scripts" / "e2e" / "mcpb.sh").read_text(encoding="utf-8")
    assert (
        '"$PREV_TRANSPILER/_base/manifest.json" "v$VERSION" "v$PREV_VERSION"' in script
    )
    assert 'agentic-plugins release mcpb --dist "$WORK/bundle-prev"' in script
    assert '--prev-bundle "$PREV_BUNDLE"' in script


# --------------------------------------------------------------------------
# StdioSession, against a scripted server
# --------------------------------------------------------------------------

FAKE_SERVER = r"""
import json, sys
mode = sys.argv[1]
for line in sys.stdin:
    message = json.loads(line)
    if "id" not in message:
        continue
    method = message["method"]
    if mode == "stray-print" and method == "tools/list":
        print("Scanning...", flush=True)
    if mode == "exit" and method == "tools/list":
        sys.exit(3)
    if method == "initialize":
        result = {"protocolVersion": message["params"]["protocolVersion"], "capabilities": {}, "serverInfo": {"name": "fake", "version": "0"}}
    elif method == "tools/list":
        # A server-to-client request and a notification arrive before the reply.
        print(json.dumps({"jsonrpc": "2.0", "id": "s1", "method": "roots/list"}), flush=True)
        reply = json.loads(sys.stdin.readline())
        sys.stderr.write("client answered roots/list with " + json.dumps(reply) + "\n")
        assert reply["error"]["code"] == -32601, reply
        print(json.dumps({"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info", "data": "hi"}}), flush=True)
        result = {"tools": [{"name": "check_installation"}]}
    elif method == "tools/call":
        result = {"content": [], "structuredContent": {"result": {"success": True, "version": "4.0.0"}}}
    print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}), flush=True)
"""


def _session(tmp_path, mode):
    server = tmp_path / "fake_server.py"
    server.write_text(FAKE_SERVER, encoding="utf-8")
    return mi.StdioSession(
        [sys.executable, str(server), mode], None, tmp_path, tmp_path / "server.log"
    )


def test_the_stdio_session_holds_one_session_across_calls(tmp_path):
    session = _session(tmp_path, "ok")
    try:
        assert session.ready() == ["check_installation"]
        assert session.call("check_installation") == {
            "success": True,
            "version": "4.0.0",
        }
        assert session.call("check_installation")["version"] == "4.0.0"
    finally:
        session.stop()
    assert session.proc.returncode == 0, "closing stdin must end the session"
    trace = (tmp_path / "server.jsonrpc").read_text(encoding="utf-8")
    assert '"notifications/initialized"' in trace
    assert "-32601" in trace, "a server request must get an answer, not silence"


def test_the_stdio_session_refuses_a_stray_line_on_stdout(tmp_path):
    session = _session(tmp_path, "stray-print")
    try:
        with pytest.raises(mi.Failure, match="not a JSON-RPC message: 'Scanning...'"):
            session.ready()
    finally:
        session.stop()


def test_the_stdio_session_reports_a_server_that_exits(tmp_path):
    session = _session(tmp_path, "exit")
    try:
        with pytest.raises(mi.Failure, match="closed stdout"):
            session.ready()
    finally:
        session.stop()


def test_the_e2e_scans_one_case_over_stdio():
    text = SCRIPT.read_text(encoding="utf-8")
    call = re.search(r'"stdio-findings",\s*version,\s*transport="stdio",', text)
    assert call, "the stdio scan must run the findings case with the head version"
