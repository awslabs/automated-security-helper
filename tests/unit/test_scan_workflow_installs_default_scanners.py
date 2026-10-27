# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The reusable scan workflow installs the tools of the scanners ASH enables by default.

Why this file exists
--------------------
actionlint, cfn-guard, gitleaks and trivy are builtin scanners, on by default, whose
tools ASH does not install for itself. ``.github/workflows/run-ash-security-scan.yml``
installs them in one step, "Install actionlint, cfn-guard, gitleaks and trivy", one
``install-*`` input per tool. Those inputs first shipped defaulting to false, so a caller
that upgraded ASH without adding them got four MISSING scanners in the default
``ash-mode: local``, and the incomplete-scan gate failed every run with nothing in the
caller's own change to explain it. They default to true instead, at the cost of the
download (about 180 MB for trivy and its database on 2026-10-11), which a caller that
does not need a tool turns off by setting its input to false.

The same held for the older install-grype, install-syft, install-opengrep and
install-cfn-nag inputs, which defaulted to false although grype, syft, opengrep and
cfn-nag are on by default too. Measured on 2026-10-11, a local-mode scan of a small
repository on a host without those tools reported all four MISSING and exited 1.
So every ``install-*`` input defaults to true.

What it checks
--------------
Every input that step reads defaults to true. The inputs are read from the step's own
``if:`` expression rather than listed here, so a tool added to that step is held to the
same default; the four names are also pinned, so a step that stopped being found could
not pass by checking nothing. Every ``install-*`` input of the workflow defaults to true,
names a scanner the default config enables, and says what it downloads and how to turn
it off.

Defaults alone do not prove anything is installed, so the steps are also run. A small
evaluator for the part of GitHub's expression language these steps use decides each
step's ``if:`` and its ``${{ }}`` env values, and the step's ``run:`` script executes
under bash with ``uvx`` replaced by a stub that records its arguments. That checks, for
every combination of the four inputs, that each input that is on reaches ``ash
dependencies install`` as ``--tool <name>`` and each that is off does not, that the
step runs exactly when one of them is on, that the bin directory is added to
GITHUB_PATH, and that the Run ASH step points ``ASH_CFN_GUARD_RULES_DIR`` at the
directory the installer writes the rules to (``utils/rules_bundles.rules_root`` given
the install's ``--bin-path``). Every ``install-*`` input is a boolean and gates at least
one step that can run.

The ash job's env reads ``github.event_name`` (no cache is restored on ``pull_request``
or ``merge_group``), so every run above is repeated for each event in EVENTS: the events
ASH's own callers start the workflow on, which under ``workflow_call`` is what
``github.event_name`` holds. A test holds EVENTS to those callers' triggers and to every
event name the workflow compares ``github.event_name`` with. The evaluator models no
other part of ``github``; ``github.ref`` or the event payload is unsupported.
"""

from __future__ import annotations

import itertools
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Optional

import pytest
import yaml

from tests.utils.workflow_one_line import write_helper

REPO_ROOT = Path(__file__).resolve().parents[2]
SCAN_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "run-ash-security-scan.yml"
INSTALL_STEP = "Install actionlint, cfn-guard, gitleaks and trivy"


def _workflow() -> dict[str, Any]:
    return yaml.safe_load(SCAN_WORKFLOW.read_text(encoding="utf-8"))


def _inputs() -> dict[str, Any]:
    # PyYAML reads the bare key `on` as the boolean True.
    triggers = _workflow().get(True) or _workflow().get("on")
    return triggers["workflow_call"]["inputs"]


def _install_step() -> dict[str, Any]:
    found = [
        step
        for job in _workflow()["jobs"].values()
        for step in job.get("steps") or []
        if step.get("name") == INSTALL_STEP
    ]
    assert len(found) == 1, f"expected one step named {INSTALL_STEP!r}, found {found}"
    return found[0]


def _inputs_the_step_reads() -> list[str]:
    return sorted(
        set(re.findall(r"inputs\.(install-[a-z0-9-]+)", _install_step()["if"]))
    )


def test_the_install_step_reads_the_four_default_scanners_inputs() -> None:
    assert _inputs_the_step_reads() == [
        "install-actionlint",
        "install-cfn-guard",
        "install-gitleaks",
        "install-trivy",
    ]


def test_every_input_the_install_step_reads_defaults_to_true() -> None:
    inputs = _inputs()
    wrong = {
        name: inputs[name].get("default")
        for name in _inputs_the_step_reads()
        if inputs[name].get("default") is not True
    }
    assert not wrong, (
        "these install-* inputs of run-ash-security-scan.yml do not default to true, so "
        f"a caller that does not set them gets those scanners MISSING: {wrong}"
    )


def test_each_of_those_inputs_says_what_it_downloads_and_how_to_turn_it_off() -> None:
    inputs = _inputs()
    for name in _inputs_the_step_reads():
        description = inputs[name]["description"]
        assert "false" in description, (name, description)
    assert "MB" in inputs["install-trivy"]["description"]


def _install_inputs() -> dict[str, Any]:
    return {
        name: spec for name, spec in _inputs().items() if name.startswith("install-")
    }


def test_every_install_input_is_pinned() -> None:
    assert sorted(_install_inputs()) == [
        "install-actionlint",
        "install-cfn-guard",
        "install-cfn-nag",
        "install-gitleaks",
        "install-grype",
        "install-opengrep",
        "install-syft",
        "install-trivy",
    ]


def test_every_install_input_defaults_to_true_and_says_how_to_turn_it_off() -> None:
    wrong = {
        name: spec.get("default")
        for name, spec in _install_inputs().items()
        if spec.get("default") is not True
    }
    assert not wrong, wrong
    for name, spec in _install_inputs().items():
        assert "false" in spec["description"], (name, spec["description"])
        assert "MB" in spec["description"], (name, spec["description"])


def test_every_install_input_names_a_scanner_on_by_default() -> None:
    from automated_security_helper.config.default_config import get_default_config

    scanners = get_default_config().scanners
    enabled = {
        (field.alias or name)
        for name, field in type(scanners).model_fields.items()
        if getattr(getattr(scanners, name), "enabled", False)
    }
    named = {name.removeprefix("install-") for name in _install_inputs()}
    assert named <= enabled, named - enabled


# ---------------------------------------------------------------------------
# Running the steps
# ---------------------------------------------------------------------------


class _Unsupported(Exception):
    """An expression this evaluator does not model (a context or function it lacks)."""


_TOKEN = re.compile(
    r"\s*(?:(?P<str>'(?:[^']|'')*')|(?P<num>\d+(?:\.\d+)?)"
    r"|(?P<op>&&|\|\||==|!=|!|\(|\)|,)"
    r"|(?P<name>[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*)*))"
)


def _tokens(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    pos = 0
    text = text.strip()
    while pos < len(text):
        match = _TOKEN.match(text, pos)
        if not match or match.end() == pos:
            raise _Unsupported(f"cannot tokenize {text[pos:]!r}")
        kind = match.lastgroup or ""
        out.append((kind, match.group(kind)))
        pos = match.end()
        while pos < len(text) and text[pos].isspace():
            pos += 1
    return out


def _parse(text: str) -> Any:
    """GitHub's precedence: ! binds tightest, then == and !=, then &&, then ||."""
    tokens = _tokens(text)
    pos = 0

    def peek() -> Optional[str]:
        return tokens[pos][1] if pos < len(tokens) else None

    def take() -> tuple[str, str]:
        nonlocal pos
        pos += 1
        return tokens[pos - 1]

    def primary() -> Any:
        kind, value = take()
        if value == "(" and kind == "op":
            node = disjunction()
            assert take()[1] == ")", text
            return node
        if kind == "str":
            return ("lit", value[1:-1].replace("''", "'"))
        if kind == "num":
            return ("lit", float(value))
        if kind == "name":
            if value in ("true", "false"):
                return ("lit", value == "true")
            if value == "null":
                return ("lit", None)
            if peek() == "(":
                take()
                args = []
                while peek() != ")":
                    args.append(disjunction())
                    if peek() == ",":
                        take()
                take()
                return ("call", value, args)
            return ("ref", value)
        raise _Unsupported(f"unexpected {value!r} in {text!r}")

    def unary() -> Any:
        if peek() == "!":
            take()
            return ("not", unary())
        return primary()

    def comparison() -> Any:
        left = unary()
        if peek() in ("==", "!="):
            op = take()[1]
            return ("eq" if op == "==" else "ne", left, unary())
        return left

    def conjunction() -> Any:
        node = comparison()
        while peek() == "&&":
            take()
            node = ("and", node, comparison())
        return node

    def disjunction() -> Any:
        node = conjunction()
        while peek() == "||":
            take()
            node = ("or", node, conjunction())
        return node

    tree = disjunction()
    assert pos == len(tokens), f"trailing tokens in {text!r}"
    return tree


def _truthy(value: Any) -> bool:
    return value not in (False, None, 0, "")


def _text(value: Any) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return ""
    return str(value)


def _evaluate(node: Any, ctx: dict[str, Any]) -> Any:
    kind = node[0]
    if kind == "lit":
        return node[1]
    if kind == "ref":
        root, *rest = node[1].split(".")
        if root not in ctx:
            raise _Unsupported(node[1])
        value = ctx[root]
        for part in rest:
            if root == "github" and not (isinstance(value, dict) and part in value):
                # Only what _context models; github.ref and the payload are not.
                raise _Unsupported(node[1])
            value = value.get(part) if isinstance(value, dict) else None
        return value
    if kind == "call":
        if node[1] != "format":
            raise _Unsupported(f"{node[1]}()")
        fmt, *args = [_text(_evaluate(arg, ctx)) for arg in node[2]]
        return re.sub(r"\{(\d+)\}", lambda m: args[int(m.group(1))], fmt)
    if kind == "not":
        return not _truthy(_evaluate(node[1], ctx))
    if kind == "and":
        left = _evaluate(node[1], ctx)
        return _evaluate(node[2], ctx) if _truthy(left) else left
    if kind == "or":
        left = _evaluate(node[1], ctx)
        return left if _truthy(left) else _evaluate(node[2], ctx)
    left, right = _evaluate(node[1], ctx), _evaluate(node[2], ctx)
    if type(left) is not type(right):
        raise _Unsupported(f"comparison of {left!r} and {right!r}")
    return (left == right) if kind == "eq" else (left != right)


def _expression(text: str) -> str:
    match = re.fullmatch(r"\s*\$\{\{(.*)\}\}\s*", text, re.DOTALL)
    return match.group(1) if match else text


def _runs(step: dict[str, Any], ctx: dict[str, Any]) -> bool:
    condition = step.get("if", True)
    if isinstance(condition, bool):
        return condition
    return _truthy(_evaluate(_parse(_expression(str(condition))), ctx))


def _interpolate(value: Any, ctx: dict[str, Any]) -> str:
    if not isinstance(value, str):
        return _text(value)
    return re.sub(
        r"\$\{\{(.*?)\}\}",
        lambda m: _text(_evaluate(_parse(m.group(1)), ctx)),
        value,
    )


def _steps() -> list[dict[str, Any]]:
    return [
        step for job in _workflow()["jobs"].values() for step in job.get("steps") or []
    ]


def _step(name: str) -> dict[str, Any]:
    found = [step for step in _steps() if step.get("name") == name]
    assert len(found) == 1, f"expected one step named {name!r}, found {len(found)}"
    return found[0]


#: The events ASH's own callers start the workflow on; workflow_dispatch is the one the
#: workflow compares github.event_name with nowhere.
EVENTS = ("merge_group", "pull_request", "push", "workflow_dispatch")


def _caller_triggers() -> set[str]:
    """The triggers of every workflow in this repository that calls the scan workflow."""
    found: set[str] = set()
    for path in sorted(SCAN_WORKFLOW.parent.glob("*.y*ml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        jobs = (data.get("jobs") or {}).values()
        if not any(
            SCAN_WORKFLOW.name in str((job or {}).get("uses", "")) for job in jobs
        ):
            continue
        on = data.get(True, data.get("on"))
        found |= {on} if isinstance(on, str) else set(on or ())
    return found


def _compared_event_names() -> set[str]:
    text = SCAN_WORKFLOW.read_text(encoding="utf-8")
    return set(re.findall(r"github\.event_name\s*[!=]=\s*'([a-z_]+)'", text))


def test_the_events_cover_every_trigger_case() -> None:
    callers = _caller_triggers()
    compared = _compared_event_names()
    # Pinned, so a reader that stopped finding them could not pass by finding nothing.
    assert {"pull_request", "push"} <= callers, callers
    assert {"merge_group", "pull_request", "push"} <= compared, compared
    assert callers <= set(EVENTS), callers - set(EVENTS)
    assert compared <= set(EVENTS), compared - set(EVENTS)
    assert set(EVENTS) - compared, "no event takes the workflow's otherwise branch"


def _context(tmp_path: Path, event_name: str, **on: bool) -> dict[str, Any]:
    """Every input at its default, then each install-* input as given (else off)."""
    inputs = {name: spec.get("default") for name, spec in _inputs().items()}
    inputs["config"] = ".ash/.ash.yaml"
    for name in _install_inputs():
        inputs[name] = on.get(name.removeprefix("install-").replace("-", "_"), False)
    return {
        "inputs": inputs,
        "runner": {"temp": str(tmp_path / "runner-temp")},
        "github": {"event_name": event_name},
    }


_UVX_STUB = """#!/bin/sh
{
  printf 'cwd=%s\\n' "$PWD"
  printf 'ash_config=%s\\n' "${ASH_CONFIG-<unset>}"
  for arg in "$@"; do printf 'arg=%s\\n' "$arg"; done
  printf 'end\\n'
} >> "$UVX_LOG"
"""


def _run(step: dict[str, Any], ctx: dict[str, Any], tmp_path: Path) -> dict[str, Any]:
    """Run ``step`` as the runner would, with ``uvx`` stubbed; what it did."""
    stub = tmp_path / "stub-bin"
    stub.mkdir(exist_ok=True)
    (stub / "uvx").write_text(_UVX_STUB, encoding="utf-8")
    (stub / "uvx").chmod(0o755)
    Path(ctx["runner"]["temp"]).mkdir(exist_ok=True)
    # The job's definer runs before every install step, into the same RUNNER_TEMP;
    # the steps load the one_line helper it writes.
    write_helper(_steps(), Path(ctx["runner"]["temp"]))
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    log = tmp_path / "uvx.log"
    github_path = tmp_path / "github-path"
    for path in (log, github_path):
        path.unlink(missing_ok=True)

    workflow = _workflow()
    env = {
        **os.environ,
        "PATH": f"{stub}{os.pathsep}{os.environ['PATH']}",
        "RUNNER_TEMP": ctx["runner"]["temp"],
        "GITHUB_PATH": str(github_path),
        "UVX_LOG": str(log),
    }
    for block in (
        workflow.get("env") or {},
        workflow["jobs"]["ash"].get("env") or {},
        step.get("env") or {},
    ):
        env.update({key: _interpolate(value, ctx) for key, value in block.items()})
    script = tmp_path / "step.sh"
    script.write_text(step["run"], encoding="utf-8")
    result = subprocess.run(  # nosec B603 B607 - the workflow's own step, uvx stubbed
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", str(script)],
        cwd=workspace,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr

    calls: list[dict[str, Any]] = []
    current: dict[str, Any] = {"args": []}
    for line in log.read_text(encoding="utf-8").splitlines() if log.exists() else []:
        key, _, value = line.partition("=")
        if key == "end":
            calls.append(current)
            current = {"args": []}
        elif key == "arg":
            current["args"].append(value)
        else:
            current[key] = value
    tools = set()
    bin_paths = set()
    for call in calls:
        args = call["args"]
        assert "dependencies" in args and "install" in args, args
        tools |= {args[i + 1] for i, arg in enumerate(args) if arg == "--tool"}
        bin_paths |= {args[i + 1] for i, arg in enumerate(args) if arg == "--bin-path"}
    on_path = (
        github_path.read_text(encoding="utf-8").splitlines()
        if github_path.exists()
        else []
    )
    return {"calls": calls, "tools": tools, "bin_paths": bin_paths, "on_path": on_path}


def test_every_install_input_is_a_boolean() -> None:
    """A string input makes `inputs.install-x && 'x' || ''` true for 'false' too."""
    wrong = {
        name: spec.get("type")
        for name, spec in _install_inputs().items()
        if spec.get("type") != "boolean"
    }
    assert not wrong, wrong


_FOUR = ("actionlint", "cfn_guard", "gitleaks", "trivy")
_COMBINATIONS = list(itertools.product((False, True), repeat=len(_FOUR)))


@pytest.mark.parametrize("event_name", EVENTS)
@pytest.mark.parametrize(
    "combination",
    _COMBINATIONS,
    ids=["+".join(t for t, on in zip(_FOUR, c) if on) or "none" for c in _COMBINATIONS],
)
def test_the_install_step_installs_exactly_the_tools_switched_on(
    tmp_path: Path, combination: tuple[bool, ...], event_name: str
) -> None:
    on = dict(zip(_FOUR, combination))
    ctx = _context(tmp_path, event_name, **on)
    step = _install_step()
    wanted = {name.replace("_", "-") for name, enabled in on.items() if enabled}

    assert _runs(step, ctx) is bool(wanted), (
        f"with {sorted(wanted) or 'no tool'} switched on the step's if: is "
        f"{_runs(step, ctx)}; it must be an OR over its inputs: {step['if']}"
    )
    if not wanted:
        return
    ran = _run(step, ctx, tmp_path)
    assert ran["tools"] == wanted, (
        f"switched on {sorted(wanted)}, installed {sorted(ran['tools'])}"
    )
    bin_dir = f"{ctx['runner']['temp']}/ash-tools"
    assert ran["bin_paths"] == {bin_dir}
    assert bin_dir in ran["on_path"], "the bin directory is not added to GITHUB_PATH"
    for call in ran["calls"]:
        assert call["cwd"] == ctx["runner"]["temp"], call
        assert call["ash_config"] == "<unset>", call


@pytest.mark.parametrize("event_name", EVENTS)
@pytest.mark.parametrize("tool", ["grype", "syft"])
@pytest.mark.parametrize("enabled", [True, False])
def test_the_grype_and_syft_steps_install_their_tool(
    tmp_path: Path, tool: str, enabled: bool, event_name: str
) -> None:
    ctx = _context(tmp_path, event_name, **{tool: enabled})
    step = _step(f"Install {tool.capitalize()}")
    assert _runs(step, ctx) is enabled
    if not enabled:
        return
    ran = _run(step, ctx, tmp_path)
    assert ran["tools"] == {tool}
    assert ran["bin_paths"] <= set(ran["on_path"]) and ran["bin_paths"]


@pytest.mark.parametrize("event_name", EVENTS)
def test_every_install_input_gates_a_step_that_can_run(
    tmp_path: Path, event_name: str
) -> None:
    """A step gated on the input whose if: is true with only that input on."""
    gated_nothing = []
    for name in _install_inputs():
        ctx = _context(
            tmp_path,
            event_name,
            **{name.removeprefix("install-").replace("-", "_"): True},
        )
        runnable = []
        for step in _steps():
            condition = step.get("if")
            if not isinstance(condition, str) or f"inputs.{name}" not in condition:
                continue
            try:
                if _runs(step, ctx):
                    runnable.append(step.get("name"))
            except _Unsupported:
                continue
        if not runnable:
            gated_nothing.append(name)
    assert not gated_nothing, (
        f"these inputs gate no step that runs when they are on: {gated_nothing}"
    )


@pytest.mark.parametrize("event_name", EVENTS)
@pytest.mark.parametrize("enabled", [True, False])
def test_the_rules_dir_is_where_the_install_step_writes_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, enabled: bool, event_name: str
) -> None:
    from automated_security_helper.utils.rules_bundles import RULES_DIR_ENV, rules_root

    ctx = _context(tmp_path, event_name, cfn_guard=enabled, actionlint=True)
    scan_env = _step("Run ASH").get("env") or {}
    assert "ASH_CFN_GUARD_RULES_DIR" in scan_env
    pointed_at = _interpolate(scan_env["ASH_CFN_GUARD_RULES_DIR"], ctx)
    if not enabled:
        assert pointed_at == "", "with cfn-guard not installed ASH must use its default"
        return

    ran = _run(_install_step(), ctx, tmp_path)
    assert "cfn-guard" in ran["tools"]
    (bin_path,) = ran["bin_paths"]
    # Where `ash dependencies install --bin-path <bin_path>` puts the rules bundle.
    monkeypatch.setenv("ASH_BIN_PATH", bin_path)
    install_env = _install_step().get("env") or {}
    if RULES_DIR_ENV in install_env:
        monkeypatch.setenv(RULES_DIR_ENV, _interpolate(install_env[RULES_DIR_ENV], ctx))
    else:
        monkeypatch.delenv(RULES_DIR_ENV, raising=False)
    assert Path(pointed_at) == rules_root()


def test_the_evaluator_reads_the_expressions_the_way_github_does() -> None:
    """The control for the harness above: known expressions, known values."""
    ctx = {
        "inputs": {"a": True, "b": False, "s": "x"},
        "runner": {"temp": "/t"},
        "github": {"event_name": "merge_group"},
    }
    restore = (
        "github.event_name != 'pull_request' && github.event_name != 'merge_group'"
    )
    cases = {
        "inputs.a || inputs.b": True,
        "inputs.b || inputs.b": False,
        "inputs.a && inputs.b": False,
        "inputs.a && 'yes' || ''": "yes",
        "inputs.b && 'yes' || ''": "",
        "!inputs.b && inputs.s == 'x'": True,
        "format('{0}/share', runner.temp)": "/t/share",
        "inputs.a && format('{0}/x', runner.temp) || ''": "/t/x",
        "github.event_name == 'merge_group'": True,
        restore: False,
    }
    for text, expected in cases.items():
        assert _evaluate(_parse(text), ctx) == expected, text
    for event_name, expected in [("push", True), ("workflow_dispatch", True)]:
        other = {**ctx, "github": {"event_name": event_name}}
        assert _evaluate(_parse(restore), other) is expected, event_name
    with pytest.raises(_Unsupported):
        _evaluate(_parse("steps.x.outputs.y == 'true'"), ctx)
    with pytest.raises(_Unsupported):
        _evaluate(_parse("github.ref == 'refs/heads/main'"), ctx)
    assert _runs({"if": False}, ctx) is False
