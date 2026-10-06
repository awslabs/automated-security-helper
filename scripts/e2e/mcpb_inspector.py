#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The MCPB channel end to end, driven through the MCP Inspector.

    mcpb_inspector.py --bundle ash-1.0.0.mcpb --wheel N.whl --prev-wheel N-1.whl \\
        --inspector node_modules/.bin/mcp-inspector --work <scratch>

The bundle is what a desktop MCP host installs: one manifest.json whose mcp_config
runs `uvx --from=git+...@<release tag> ashx mcp`. A launched bundle therefore runs a
published release, not this commit. This script rewrites exactly that one `--from=`
argument to a wheel built from this commit, refuses any other difference, and then
launches the bundle's own command through the Inspector.

WHAT IT DOES, IN ORDER

1. Reads the bundle and requires exactly one member, manifest.json, the same
   invariant the release workflow asserts before it attaches the archive.
2. Upgrade, in the order a user meets it. The bundle is pointed at the N-1 wheel,
   launched over stdio, and must report N-1 through `check_installation` and scan the
   findings case. It is then pointed at the head wheel, relaunched with the same uv
   cache, and must report N. The reported version is the server's own answer
   (importlib metadata of the environment uvx built), not a file this script read.
3. Over stdio, the transport a desktop host uses, the head launch must complete the
   handshake and list the tools a scan needs.
4. The three cases from tests/e2e/fixtures/cases.json: `tools/call run_ash_scan`,
   then `get_scan_progress` until the scan is terminal, then `get_scan_summary`.
5. Uninstall. A bundle installs nothing outside the uv cache, so the cache is the
   install. A relaunch with UV_OFFLINE=1 must succeed before `uv cache clean` (the
   control that makes the next step mean something) and must fail after it.
6. Negative controls: a manifest whose `--from=` names a wheel that does not exist
   must fail the handshake; a two-member archive must be refused; and the findings
   case's real output judged as a clean outcome must be rejected.

WHY THE SCAN CASES RUN OVER STREAMABLE HTTP

`mcp-inspector --cli` is one-shot: it spawns the server, makes one request, and
closes the transport, which ends the server process. `run_ash_scan` returns as soon
as the scan has started and the scan runs inside that process, so over stdio the
scan dies with it. Measured with inspector 2.8.0: the reply carried a scan id and
status "running", the process was gone a moment later, and reports/ was empty. The
scan registry is in memory, so a second stdio launch cannot poll the first one's
scan either.

So each case launches the bundle's command with `--transport streamable-http` on a
loopback port appended, and every Inspector call connects to that one long-lived
process. Nothing else about the command changes. The stdio launch is still exercised
by steps 2, 3 and 5 with the command exactly as the bundle has it.

`run_ash_workspace_scan` is synchronous and would work over stdio, and it was
rejected. A workspace answers 2 when a project has findings and an incomplete
scanner at once, deliberately (models/workspace.py, "Precedence"), where a
single-project scan answers 1. Measured: the incomplete case came back exit_code 2
with scan_incomplete true. Judging it would need its own expectations, and the point
of the shared cases is that no channel gets those.

HOW A SCAN IS JUDGED

The MCP surface has no process exit code. Its verdict is the terminal status from
get_scan_progress (`completed` or `incomplete`, with `coverage_complete`), and the
actionable count from get_scan_summary. Both are required to match the case: status
`incomplete` and coverage_complete false with exactly the case's incomplete scanner
for exit 1, status `completed` and coverage_complete true otherwise. The exit code
ASH's CLI would have given is then derived from those answers (incomplete is 1, else
2 when the server reports an actionable finding, else 0) and handed to
assert_outcome.check_outcome with the case's expectations, which reads the SARIF and
aggregated results the server wrote. The derivation uses only what the server
reported, so a server that miscounted fails on assert_outcome's own count.

Scanner selection has no argument on run_ash_scan, so each case gets a config file
passed as `config_path` that disables every scanner `list_scanners` names except the
case's own. The case's args are CLI flags; `--config-overrides K=V` is translated
into the same config, and any other flag is refused rather than dropped. The case's
env is applied to the server process, which is where ASH reads it.

Standard library only, like assert_outcome.py. Exits 0 when every step passes, 1
when one fails, 3 on a usage error.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))

import assert_outcome  # noqa: E402

FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "e2e" / "fixtures"

# The only `--from=` value the shipped manifest may carry: this repository at a ref.
RELEASE_FROM_PREFIX = "--from=git+https://github.com/awslabs/automated-security-helper@"

# Tools the scan legs call. The handshake requires each to be listed.
REQUIRED_TOOLS = (
    "check_installation",
    "list_scanners",
    "run_ash_scan",
    "get_scan_progress",
    "get_scan_summary",
)

TERMINAL_STATUSES = ("completed", "incomplete", "failed", "cancelled")

# Bounds. The first launch of a wheel resolves and installs its dependencies, which
# is most of a minute on a hosted runner; a detect-secrets scan of one file is seconds.
READY_TIMEOUT_S = 300
SCAN_TIMEOUT_S = 600
POLL_INTERVAL_S = 3
INSPECTOR_TIMEOUT_S = 300


class Failure(Exception):
    """One step did not hold. The message says which and why."""


def say(message: str) -> None:
    print(f"== {message}", flush=True)


# --------------------------------------------------------------------------
# The bundle and its manifest
# --------------------------------------------------------------------------


def read_bundle(path: Path) -> Dict[str, Any]:
    """The manifest from an .mcpb archive that holds exactly one member, manifest.json."""
    try:
        with zipfile.ZipFile(path) as archive:
            members = [i.filename for i in archive.infolist() if not i.is_dir()]
            if members != ["manifest.json"]:
                raise Failure(
                    f"{path} must hold exactly one member, manifest.json; "
                    f"found {len(members)}: {members}"
                )
            manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
    except zipfile.BadZipFile as error:
        raise Failure(f"{path} is not a ZIP archive: {error}") from error
    if not isinstance(manifest, dict):
        raise Failure(f"manifest.json in {path} is not a JSON object")
    return manifest


def mcp_config_of(manifest: Dict[str, Any]) -> Dict[str, Any]:
    server = manifest.get("server")
    config = server.get("mcp_config") if isinstance(server, dict) else None
    if not isinstance(config, dict):
        raise Failure("manifest.json has no server.mcp_config object")
    if not isinstance(config.get("command"), str):
        raise Failure("server.mcp_config.command is not a string")
    args = config.get("args")
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        raise Failure("server.mcp_config.args is not a list of strings")
    env = config.get("env", {})
    if not isinstance(env, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in env.items()
    ):
        raise Failure("server.mcp_config.env is not an object of strings")
    return config


def rewrite_from(config: Dict[str, Any], wheel: Path) -> Dict[str, Any]:
    """A copy of mcp_config whose single release `--from=` argument names `wheel`.

    Refuses a command other than uvx, zero or several `--from` arguments, a
    `--from` that does not name this repository's release, and any result that
    differs from the original in more than that one argument.
    """
    if config.get("command") != "uvx":
        raise Failure(
            f"mcp_config.command is {config.get('command')!r}; this channel only "
            "knows how to retarget a uvx launch"
        )
    args: List[str] = list(config["args"])
    indexes = [
        i for i, a in enumerate(args) if a == "--from" or a.startswith("--from=")
    ]
    if len(indexes) != 1:
        raise Failure(
            f"mcp_config.args must carry exactly one --from argument, found "
            f"{len(indexes)} in {args}"
        )
    index = indexes[0]
    if not args[index].startswith(RELEASE_FROM_PREFIX):
        raise Failure(
            f"mcp_config.args[{index}] is {args[index]!r}, not a {RELEASE_FROM_PREFIX}<ref> "
            "launch of this repository"
        )
    rewritten = copy.deepcopy(config)
    rewritten["args"][index] = f"--from={wheel}"
    changed = [
        i for i, (a, b) in enumerate(zip(config["args"], rewritten["args"])) if a != b
    ]
    others = {k: v for k, v in config.items() if k != "args"}
    rewritten_others = {k: v for k, v in rewritten.items() if k != "args"}
    if (
        changed != [index]
        or len(rewritten["args"]) != len(args)
        or others != rewritten_others
    ):
        raise Failure(
            f"the rewrite changed more than args[{index}]: {config} -> {rewritten}"
        )
    return rewritten


# --------------------------------------------------------------------------
# The Inspector
# --------------------------------------------------------------------------


class Inspector:
    """One-shot `mcp-inspector --cli` calls, with their replies parsed."""

    def __init__(self, executable: str, log_dir: Path) -> None:
        self.executable = executable
        self.log_dir = log_dir
        self.calls = 0

    def run(
        self, target: Sequence[str], method: str, extra: Sequence[str] = ()
    ) -> Tuple[int, Any, str]:
        """(exit code, parsed stdout or None, stderr) for one call."""
        command = [
            self.executable,
            "--cli",
            *target,
            "--method",
            method,
            *extra,
            "--format",
            "json",
        ]
        self.calls += 1
        proc = subprocess.run(  # noqa: S603
            command,
            capture_output=True,
            text=True,
            timeout=INSPECTOR_TIMEOUT_S,
            check=False,
        )
        log = self.log_dir / f"inspector-{self.calls:03d}.log"
        log.write_text(
            f"$ {' '.join(command)}\nexit {proc.returncode}\n--- stdout\n{proc.stdout}"
            f"\n--- stderr\n{proc.stderr}\n",
            encoding="utf-8",
        )
        try:
            payload = json.loads(proc.stdout) if proc.stdout.strip() else None
        except json.JSONDecodeError:
            payload = None
        return proc.returncode, payload, proc.stderr

    def tool_names(self, target: Sequence[str]) -> List[str]:
        rc, payload, stderr = self.run(target, "tools/list")
        names = listed_tools(rc, payload)
        if names is None:
            raise Failure(
                f"tools/list failed (inspector exit {rc}): {_brief(payload)} {stderr[-400:]}"
            )
        return names

    def call(
        self,
        target: Sequence[str],
        tool: str,
        arguments: Optional[Dict[str, Any]] = None,
    ) -> Any:
        extra = ["--tool-name", tool]
        if arguments:
            extra += ["--tool-args-json", json.dumps(arguments)]
        rc, payload, stderr = self.run(target, "tools/call", extra)
        return tool_result(tool, rc, payload, stderr)


def listed_tools(rc: int, payload: Any) -> Optional[List[str]]:
    """The tool names from a `tools/list` reply, or None when there was no reply."""
    result = payload.get("result") if isinstance(payload, dict) else None
    tools = result.get("tools") if isinstance(result, dict) else None
    if rc != 0 or not isinstance(tools, list):
        return None
    return [str(t.get("name")) for t in tools if isinstance(t, dict)]


def tool_result(tool: str, rc: int, payload: Any, stderr: str = "") -> Any:
    """The tool's return value from an Inspector `tools/call` reply.

    The server returns a dict as structuredContent.result, and a list as one text
    content item per element.
    """
    if rc != 0 or not isinstance(payload, dict) or "result" not in payload:
        raise Failure(
            f"tools/call {tool} failed (inspector exit {rc}): {_brief(payload)} {stderr[-400:]}"
        )
    result = payload["result"]
    if result.get("isError"):
        raise Failure(f"tools/call {tool} returned an error: {_brief(result)}")
    structured = result.get("structuredContent")
    if isinstance(structured, dict) and "result" in structured:
        return structured["result"]
    texts = [
        c.get("text") for c in result.get("content", []) if c.get("type") == "text"
    ]
    try:
        values = [json.loads(t) for t in texts]
    except (TypeError, json.JSONDecodeError) as error:
        raise Failure(
            f"tools/call {tool} replied with non-JSON text: {texts!r:.400}"
        ) from error
    return values[0] if len(values) == 1 else values


def _brief(value: Any) -> str:
    return json.dumps(value)[:600] if value is not None else "no JSON reply"


def stdio_target(
    work: Path, name: str, config: Dict[str, Any], env: Dict[str, str]
) -> List[str]:
    """Inspector arguments that launch `config` over stdio with `env` added to its env.

    The Inspector starts a stdio server with only the variables its config names
    plus a few of its own (PATH, HOME), so everything the launch needs is written in.
    """
    server = copy.deepcopy(config)
    server["env"] = {**config.get("env", {}), **env}
    path = work / f"inspector-{name}.json"
    path.write_text(
        json.dumps({"mcpServers": {"ash": server}}, indent=2), encoding="utf-8"
    )
    return ["--config", str(path), "--server", "ash"]


# --------------------------------------------------------------------------
# Cases
# --------------------------------------------------------------------------


def _parse_override_value(text: str) -> Any:
    lowered = text.lower()
    if lowered in ("true", "false"):
        return lowered == "true"
    return text


def case_config(case: Dict[str, Any], all_scanners: Sequence[str]) -> Dict[str, Any]:
    """The ASH config that makes run_ash_scan run what `ashx scan` runs for the case.

    `--scanners A,B` becomes every other scanner disabled and A, B enabled. Each
    `--config-overrides K=V` in the case's args is applied on top. Any other arg is
    refused: dropping it silently would scan something other than the case.
    """
    known = {assert_outcome._norm(s) for s in all_scanners}
    selected = [assert_outcome._norm(s) for s in case["scanners"]]
    unknown = [s for s in selected if s not in known]
    if unknown:
        raise Failure(f"the case selects {unknown}, which list_scanners does not name")
    config: Dict[str, Any] = {
        "scanners": {name: {"enabled": name in selected} for name in sorted(known)}
    }
    args = list(case.get("args") or [])
    while args:
        flag = args.pop(0)
        if flag != "--config-overrides" or not args:
            raise Failure(
                f"case arg {flag!r} has no MCP equivalent here; only "
                "`--config-overrides KEY=VALUE` can be translated"
            )
        key, sep, value = args.pop(0).partition("=")
        if not sep or not key:
            raise Failure(f"--config-overrides {key!r} is not KEY=VALUE")
        node = config
        parts = key.split(".")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
            if not isinstance(node, dict):
                raise Failure(f"--config-overrides {key} crosses a non-object value")
        node[parts[-1]] = _parse_override_value(value)
    return config


def expectation_of(case: Dict[str, Any]) -> "assert_outcome.Expectation":
    expected = assert_outcome.Expectation(
        expect_rc=int(case["expect_rc"]),
        findings=case.get("findings"),
        min_findings=case.get("min_findings"),
        require_scanner=case.get("require_scanner"),
        selected=list(case["scanners"]),
        incomplete_scanner=case.get("incomplete_scanner"),
    )
    usage = expected.usage_problems()
    if usage:
        raise Failure(f"the case's expectations are unusable: {usage}")
    return expected


def verdict_problems(
    case: Dict[str, Any], progress: Dict[str, Any], summary: Dict[str, Any]
) -> Tuple[List[str], Optional[int]]:
    """Problems with the server's own verdict, and the exit code it implies.

    The exit code is None when the server's answers do not map onto one (a failed or
    cancelled scan, or no actionable count), which no expectation accepts.
    """
    problems: List[str] = []
    expect_rc = int(case["expect_rc"])
    status = progress.get("status")
    want_status = "incomplete" if expect_rc == 1 else "completed"
    if status != want_status:
        problems.append(
            f"get_scan_progress status is {status!r}, expected {want_status!r} "
            f"(error_message: {progress.get('error_message')!r})"
        )
    coverage = progress.get("coverage_complete")
    if coverage is not (expect_rc != 1):
        problems.append(f"coverage_complete is {coverage!r}, expected {expect_rc != 1}")
    incomplete = sorted(
        assert_outcome._norm(str(row.get("scanner")))
        for row in progress.get("incomplete_scanners") or []
        if isinstance(row, dict)
    )
    want_incomplete = (
        [assert_outcome._norm(case["incomplete_scanner"])] if expect_rc == 1 else []
    )
    if incomplete != want_incomplete:
        problems.append(
            f"incomplete_scanners names {incomplete}, expected {want_incomplete}"
        )

    findings_summary = summary.get("findings_summary")
    by_severity = (
        findings_summary.get("by_severity")
        if isinstance(findings_summary, dict)
        else None
    )
    actionable = (
        by_severity.get("actionable") if isinstance(by_severity, dict) else None
    )
    if status == "incomplete":
        derived: Optional[int] = 1
    elif status == "completed" and isinstance(actionable, int):
        derived = 2 if actionable > 0 else 0
    else:
        derived = None
        problems.append(
            f"no exit code follows from status {status!r} and actionable count "
            f"{actionable!r}"
        )
    return problems, derived


class HttpServer:
    """The bundle's command with a streamable-http transport, for one case."""

    def __init__(
        self, command: List[str], env: Dict[str, str], cwd: Path, log: Path
    ) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}/mcp"
        self.log = log
        self.command = [
            *command,
            "--transport",
            "streamable-http",
            "--host",
            "127.0.0.1",
            "--port",
            str(self.port),
        ]
        self.handle = open(log, "w", encoding="utf-8", errors="replace")
        self.proc = subprocess.Popen(  # noqa: S603
            self.command,
            env=env,
            cwd=cwd,
            stdout=self.handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

    @property
    def target(self) -> List[str]:
        return ["--server-url", self.url, "--transport", "http"]

    def wait_ready(self, inspector: Inspector) -> List[str]:
        deadline = time.monotonic() + READY_TIMEOUT_S
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise Failure(
                    f"the server exited {self.proc.returncode} before answering; "
                    f"log tail:\n{self.tail()}"
                )
            rc, payload, _ = inspector.run(self.target, "tools/list")
            names = listed_tools(rc, payload)
            if names is not None:
                return names
            time.sleep(POLL_INTERVAL_S)
        raise Failure(
            f"the server did not answer within {READY_TIMEOUT_S}s:\n{self.tail()}"
        )

    def tail(self, lines: int = 30) -> str:
        self.handle.flush()
        text = self.log.read_text(encoding="utf-8", errors="replace").splitlines()
        return "\n".join(text[-lines:])

    def stop(self) -> None:
        if self.proc.poll() is None:
            os.killpg(self.proc.pid, signal.SIGTERM)
            try:
                self.proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                os.killpg(self.proc.pid, signal.SIGKILL)
                self.proc.wait(timeout=30)
        self.handle.close()


def run_case(
    inspector: Inspector,
    command: List[str],
    base_env: Dict[str, str],
    work: Path,
    fixtures: Path,
    case_name: str,
    label: str,
    expect_version: str,
) -> Path:
    """Scans one case through run_ash_scan and judges it. Returns its output dir."""
    case = assert_outcome.load_case(fixtures / "cases.json", case_name)
    expected = expectation_of(case)
    root = work / "scans" / label
    if root.exists():
        shutil.rmtree(root)
    src = root / "src"
    shutil.copytree(fixtures / case["source"], src)
    env = {**base_env, **{str(k): str(v) for k, v in (case.get("env") or {}).items()}}
    env["ASH_MCP_ALLOWED_ROOTS"] = str(root)
    env["ASH_MCP_ALLOWED_CONFIG_ROOTS"] = str(root)

    server = HttpServer(command, env, root, root / "server.log")
    try:
        tools = server.wait_ready(inspector)
        missing = [t for t in REQUIRED_TOOLS if t not in tools]
        if missing:
            raise Failure(f"[{label}] the server does not list {missing}")
        listed = inspector.call(server.target, "list_scanners")
        if isinstance(listed, dict):
            listed = [listed]
        names = [
            str(s["name"]) for s in listed if isinstance(s, dict) and s.get("name")
        ]
        if not names:
            raise Failure(
                f"[{label}] list_scanners named no scanners: {_brief(listed)}"
            )
        config_path = root / "ash-e2e.yaml"
        # JSON is YAML, and ASH reads the file with a YAML parser.
        config_path.write_text(
            json.dumps(case_config(case, names), indent=2), encoding="utf-8"
        )

        started = inspector.call(
            server.target,
            "run_ash_scan",
            {"source_dir": str(src), "config_path": str(config_path)},
        )
        if (
            not isinstance(started, dict)
            or not started.get("success")
            or not started.get("scan_id")
        ):
            raise Failure(
                f"[{label}] run_ash_scan did not start a scan: {_brief(started)}"
            )
        scan_id = started["scan_id"]
        say(f"[{label}] run_ash_scan started {scan_id}")

        deadline = time.monotonic() + SCAN_TIMEOUT_S
        polls = 0
        while True:
            progress = inspector.call(
                server.target, "get_scan_progress", {"scan_id": scan_id}
            )
            polls += 1
            if not isinstance(progress, dict) or progress.get("success") is False:
                raise Failure(f"[{label}] get_scan_progress failed: {_brief(progress)}")
            if (
                progress.get("is_complete")
                or progress.get("status") in TERMINAL_STATUSES
            ):
                break
            if time.monotonic() > deadline:
                raise Failure(
                    f"[{label}] the scan was not terminal after {SCAN_TIMEOUT_S}s"
                )
            time.sleep(POLL_INTERVAL_S)
        say(
            f"[{label}] terminal after {polls} poll(s): status={progress.get('status')} "
            f"coverage_complete={progress.get('coverage_complete')}"
        )

        output_dir = Path(str(progress.get("output_directory") or ""))
        problems: List[str] = []
        if output_dir.resolve() != (src / ".ash" / "ash_output").resolve():
            problems.append(
                f"output_directory is {output_dir}, expected {src / '.ash' / 'ash_output'}"
            )
        if str(progress.get("config_path")) != str(config_path):
            problems.append(
                f"the scan ran with config_path {progress.get('config_path')!r}, not "
                f"{str(config_path)!r}, so the case's scanner selection was not applied"
            )
        summary = inspector.call(
            server.target, "get_scan_summary", {"output_dir": str(output_dir)}
        )
        if not isinstance(summary, dict):
            raise Failure(f"[{label}] get_scan_summary replied {_brief(summary)}")
        verdict, rc = verdict_problems(case, progress, summary)
        problems += verdict
        metadata = summary.get("metadata")
        wrote = metadata.get("ash_version") if isinstance(metadata, dict) else None
        if wrote != expect_version:
            problems.append(
                f"the results were written by ASH {wrote!r}, expected {expect_version}"
            )
        (root / "verdict.json").write_text(
            json.dumps(
                {"progress": progress, "summary": summary, "derived_rc": rc},
                indent=2,
                default=str,
            ),
            encoding="utf-8",
        )
        if rc is not None:
            problems += assert_outcome.check_outcome(output_dir, rc, expected)
        if problems:
            for problem in problems:
                print(f"::error::[{label}] {problem}")
            print(f"--- server log tail ({server.log})\n{server.tail()}")
            raise Failure(f"[{label}] {len(problems)} problem(s)")
        say(
            f"OK: [{label}] status={progress.get('status')} derived exit {rc}, "
            f"{case.get('findings')} finding(s) expected, reports in {output_dir}"
        )
        return output_dir
    finally:
        server.stop()


# --------------------------------------------------------------------------
# The legs
# --------------------------------------------------------------------------


def reported_version(inspector: Inspector, target: List[str]) -> str:
    info = inspector.call(target, "check_installation")
    if not isinstance(info, dict) or not info.get("success") or not info.get("version"):
        raise Failure(f"check_installation did not report a version: {_brief(info)}")
    return str(info["version"])


def wheel_version(wheel: Path) -> str:
    # automated_security_helper-3.7.0-py3-none-any.whl
    parts = wheel.name.split("-")
    if len(parts) < 2:
        raise Failure(f"{wheel.name} is not a wheel filename")
    return parts[1]


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--bundle", type=Path, required=True, help="the .mcpb built from head"
    )
    parser.add_argument("--wheel", type=Path, required=True, help="the head wheel (N)")
    parser.add_argument("--prev-wheel", type=Path, required=True, help="the N-1 wheel")
    parser.add_argument(
        "--inspector", required=True, help="the mcp-inspector executable"
    )
    parser.add_argument("--work", type=Path, required=True, help="a scratch directory")
    parser.add_argument("--fixtures", type=Path, default=FIXTURES)
    args = parser.parse_args(argv)

    for path in (args.bundle, args.wheel, args.prev_wheel):
        if not path.is_file():
            print(f"error: no file at {path}", file=sys.stderr)
            return 3
    inspector_exe = shutil.which(args.inspector) or args.inspector
    if not Path(inspector_exe).is_file():
        print(f"error: no inspector at {args.inspector}", file=sys.stderr)
        return 3

    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    logs = work / "logs"
    logs.mkdir(exist_ok=True)
    inspector = Inspector(inspector_exe, logs)
    wheel = args.wheel.resolve()
    prev_wheel = args.prev_wheel.resolve()
    version = wheel_version(wheel)
    prev_version = wheel_version(prev_wheel)
    if version == prev_version:
        print(
            f"error: both wheels are {version}; the upgrade would not move",
            file=sys.stderr,
        )
        return 3

    # A cache of the channel's own: the bundle installs nothing anywhere else, so
    # this directory is the whole install, and clearing it is the uninstall.
    cache = work / "uv-cache"
    harness_env = {"UV_CACHE_DIR": str(cache)}

    try:
        say(f"reading {args.bundle}")
        manifest = read_bundle(args.bundle)
        original = mcp_config_of(manifest)
        say(
            f"bundle {manifest.get('name')} {manifest.get('version')}: {original['command']} {' '.join(original['args'])}"
        )
        head_config = rewrite_from(original, wheel)
        prev_config = rewrite_from(original, prev_wheel)
        say(f"rewrote the --from argument only: {' '.join(head_config['args'])}")

        # Upgrade: N-1 first, as a user who installed the earlier bundle would have it.
        prev_target = stdio_target(work, "prev", prev_config, harness_env)
        got = reported_version(inspector, prev_target)
        if got != prev_version:
            raise Failure(f"the N-1 launch reports {got}, expected {prev_version}")
        say(f"N-1 launch over stdio reports {got}")
        server_env = {**os.environ, **original.get("env", {}), **harness_env}
        prev_command = [prev_config["command"], *prev_config["args"]]
        run_case(
            inspector,
            prev_command,
            server_env,
            work,
            args.fixtures,
            "findings",
            "upgrade-before",
            prev_version,
        )

        head_target = stdio_target(work, "head", head_config, harness_env)
        got = reported_version(inspector, head_target)
        if got != version:
            raise Failure(
                f"after retargeting to the head wheel the launch reports {got}, expected {version}"
            )
        say(f"upgraded: the same cache now launches {got} (was {prev_version})")

        tools = inspector.tool_names(head_target)
        missing = [t for t in REQUIRED_TOOLS if t not in tools]
        if missing:
            raise Failure(
                f"the stdio handshake lists {len(tools)} tools but not {missing}"
            )
        say(
            f"stdio handshake: {len(tools)} tools, including {', '.join(REQUIRED_TOOLS)}"
        )

        head_command = [head_config["command"], *head_config["args"]]
        outputs = {}
        for case_name in ("findings", "clean", "incomplete"):
            outputs[case_name] = run_case(
                inspector,
                head_command,
                server_env,
                work,
                args.fixtures,
                case_name,
                case_name,
                version,
            )

        say(
            "negative control: the findings output judged as a clean outcome must be rejected"
        )
        clean_case = assert_outcome.load_case(args.fixtures / "cases.json", "clean")
        # The real output with its real exit code, judged against the wrong case.
        rejected = assert_outcome.check_outcome(
            outputs["findings"], 2, expectation_of(clean_case)
        )
        if not rejected:
            raise Failure(
                "NEGATIVE CONTROL: assert_outcome accepted a findings output as clean"
            )
        say(f"   OK: rejected ({len(rejected)} problem(s), first: {rejected[0]})")

        # The launch differs from the head launch, which completed this handshake
        # above, only in the --from path (rewrite_from refuses any other change), so
        # the failure is the missing wheel's and not the Inspector's or the config's.
        say(
            "negative control: a --from naming a wheel that does not exist must fail the handshake"
        )
        bogus = rewrite_from(original, work / "does-not-exist" / wheel.name)
        rc, payload, _ = inspector.run(
            stdio_target(work, "bogus", bogus, harness_env), "tools/list"
        )
        if listed_tools(rc, payload) is not None:
            raise Failure(
                "NEGATIVE CONTROL: a launch from a missing wheel completed the handshake"
            )
        say(f"   OK: inspector exit {rc}, {_brief(payload)[:200]}")

        say("negative control: a bundle with a second member must be refused")
        two = work / "two-members.mcpb"
        with zipfile.ZipFile(two, "w") as archive:
            archive.writestr("manifest.json", json.dumps(manifest))
            archive.writestr("vendored/extra.py", "print('not ours to ship')\n")
        try:
            read_bundle(two)
        except Failure as error:
            say(f"   OK: refused: {error}")
        else:
            raise Failure("NEGATIVE CONTROL: a two-member bundle was accepted")

        # Uninstall.
        offline_target = stdio_target(
            work, "offline", head_config, {**harness_env, "UV_OFFLINE": "1"}
        )
        say(
            "uninstall control: an offline relaunch must work while the cache holds the install"
        )
        got = reported_version(inspector, offline_target)
        if got != version:
            raise Failure(f"the offline relaunch reports {got}, expected {version}")
        say(f"   OK: offline relaunch reports {got}")
        clean = subprocess.run(  # noqa: S603
            ["uv", "cache", "clean"],
            env={**os.environ, **harness_env},
            capture_output=True,
            text=True,
            check=False,
        )
        if clean.returncode != 0:
            raise Failure(
                f"uv cache clean exited {clean.returncode}: {clean.stderr[-400:]}"
            )
        leftover = sorted(p.name for p in cache.iterdir()) if cache.exists() else []
        if leftover:
            raise Failure(f"uv cache clean left {leftover} in {cache}")
        rc, payload, _ = inspector.run(offline_target, "tools/list")
        if listed_tools(rc, payload) is not None:
            raise Failure(
                "after uv cache clean an offline relaunch still served; the install was not removed"
            )
        say(f"uninstalled: cache empty, offline relaunch fails (inspector exit {rc})")
    except Failure as error:
        print(f"FAIL: {error}", file=sys.stderr)
        print(f"inspector logs: {logs}", file=sys.stderr)
        return 1

    say(
        f"mcpb e2e passed: N={version}, N-1={prev_version}, {inspector.calls} inspector call(s)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
