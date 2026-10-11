# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A small model of GitHub Actions for the workflow-structure tests.

Why this exists
---------------
Several tests need to answer questions that depend on how Actions evaluates a
workflow rather than on its text: which ref a reusable workflow installs ASH
from for a given event, whether a tag push starts a job that holds
``contents: write``, or what working directory and environment a step's shell
really hands to ``uvx``. Answering them by matching substrings ties the test to
one spelling of the fix. Evaluating the expressions, the trigger filters and the
step's shell answers them for any spelling.

What it models
--------------
* Expressions (``${{ }}``): literals, context lookups, ``!``, comparisons,
  ``&&``/``||`` returning operands, the ``*`` filter, and the functions the
  workflows here use. Comparison and truthiness follow GitHub's documented
  coercion rules: mismatched types compare as numbers, strings compare
  case-insensitively. Unsupported syntax raises ``ExpressionError`` rather than
  evaluating to something plausible.
* ``on:`` filters for ``push`` (branches, tags, their ``-ignore`` forms and
  ``!`` negation) and ``pull_request`` (base branch). Path filters are assumed
  to match, which is what GitHub does for tag pushes and the conservative reading
  for branch pushes.
* Job permissions as declared (job level, else workflow level). ``None`` means
  nothing is declared, so the repository default applies.
* A step's ``run:`` block executed under the shell Actions would use, in the
  working directory Actions would use, with the environment layered workflow ->
  job -> step, and with ``uv``, ``uvx``, ``curl``, ``bundle``, ``gem``, ``ruby``
  and ``grype`` replaced by stubs that record argv, cwd and selected variables.

What it does not model
----------------------
Runner images, action implementations, ``hashFiles``, job outputs, and anything
that needs the network. ``steps.*.outputs`` and ``needs.*.outputs`` are whatever
the caller puts in the context.
"""

from __future__ import annotations

import json
import math
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"


class ExpressionError(ValueError):
    """The expression uses syntax this model does not evaluate."""


# --------------------------------------------------------------------------- expressions

_TOKEN = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<num>0x[0-9a-fA-F]+|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)
  | (?P<str>'(?:[^']|'')*')
  | (?P<op>&&|\|\||==|!=|<=|>=|<|>|!|\(|\)|\[|\]|\.|,|\*)
  | (?P<ident>[A-Za-z_][A-Za-z0-9_-]*)
    """,
    re.VERBOSE,
)


def _tokenize(text: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    pos = 0
    while pos < len(text):
        match = _TOKEN.match(text, pos)
        if not match:
            raise ExpressionError(f"cannot tokenize {text[pos:]!r} in {text!r}")
        pos = match.end()
        kind = match.lastgroup or ""
        if kind != "ws":
            tokens.append((kind, match.group(kind)))
    return tokens


def _is_nan(value: Any) -> bool:
    return isinstance(value, float) and math.isnan(value)


def _to_number(value: Any) -> float:
    if value is None:
        return 0.0
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        text = value.strip()
        if text == "":
            return 0.0
        try:
            parsed = json.loads(text)
        except ValueError:
            return math.nan
        if isinstance(parsed, (int, float)) and not isinstance(parsed, bool):
            return float(parsed)
        return math.nan
    return math.nan


def truthy(value: Any) -> bool:
    """GitHub's truthiness: false, 0, -0, '', null and NaN are falsy."""
    if value is None or value is False:
        return False
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value != 0 and not _is_nan(value)
    if isinstance(value, str):
        return value != ""
    return True


def _same_kind(a: Any, b: Any) -> bool:
    def kind(v: Any) -> str:
        if v is None:
            return "null"
        if isinstance(v, bool):
            return "bool"
        if isinstance(v, (int, float)):
            return "number"
        if isinstance(v, str):
            return "string"
        return "object"

    return kind(a) == kind(b)


def _equals(a: Any, b: Any) -> bool:
    if _same_kind(a, b):
        if isinstance(a, str):
            return a.lower() == b.lower()
        if isinstance(a, (list, dict)):
            return a is b
        if isinstance(a, float) or isinstance(b, float):
            return not (_is_nan(a) or _is_nan(b)) and a == b
        return a == b
    na, nb = _to_number(a), _to_number(b)
    return not (_is_nan(na) or _is_nan(nb)) and na == nb


def _compare(op: str, a: Any, b: Any) -> bool:
    if isinstance(a, str) and isinstance(b, str):
        x, y = a.lower(), b.lower()
    else:
        x, y = _to_number(a), _to_number(b)
        if _is_nan(x) or _is_nan(y):
            return False
    return {"<": x < y, "<=": x <= y, ">": x > y, ">=": x >= y}[op]


def to_string(value: Any) -> str:
    """How Actions renders a value into a string: null is '', booleans are lowercase."""
    if value is None:
        return ""
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, float):
        if _is_nan(value):
            return "NaN"
        if value.is_integer():
            return str(int(value))
        return repr(value)
    if isinstance(value, (list, dict)):
        return json.dumps(value)
    return str(value)


def _lookup(obj: Any, key: str) -> Any:
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        lowered = key.lower()
        for candidate, value in obj.items():
            if isinstance(candidate, str) and candidate.lower() == lowered:
                return value
        return None
    if isinstance(obj, list):
        return [_lookup(item, key) for item in obj]
    return None


def _format(template: str, *args: Any) -> str:
    out: list[str] = []
    i = 0
    while i < len(template):
        if template.startswith("{{", i):
            out.append("{")
            i += 2
        elif template.startswith("}}", i):
            out.append("}")
            i += 2
        elif template[i] == "{":
            end = template.index("}", i)
            out.append(to_string(args[int(template[i + 1 : end])]))
            i = end + 1
        else:
            out.append(template[i])
            i += 1
    return "".join(out)


def _contains(search: Any, item: Any) -> bool:
    if isinstance(search, list):
        return any(_equals(element, item) for element in search)
    return to_string(item).lower() in to_string(search).lower()


class _Parser:
    def __init__(self, text: str, context: dict[str, Any]):
        self.text = text
        self.tokens = _tokenize(text)
        self.pos = 0
        self.context = context

    # Parsing builds thunks so that && and || can short-circuit like Actions does.
    def parse(self):
        node = self._or()
        if self.pos != len(self.tokens):
            raise ExpressionError(
                f"unexpected {self.tokens[self.pos][1]!r} in {self.text!r}"
            )
        return node

    def _peek(self, value: str | None = None) -> bool:
        if self.pos >= len(self.tokens):
            return False
        return value is None or self.tokens[self.pos][1] == value

    def _take(self, value: str | None = None) -> tuple[str, str]:
        if self.pos >= len(self.tokens):
            raise ExpressionError(f"unexpected end of {self.text!r}")
        token = self.tokens[self.pos]
        if value is not None and token[1] != value:
            raise ExpressionError(
                f"expected {value!r}, found {token[1]!r} in {self.text!r}"
            )
        self.pos += 1
        return token

    def _or(self):
        left = self._and()
        while self._peek("||"):
            self._take()
            right = self._and()
            left = (lambda lft, rgt: lambda: lft() if truthy(lft()) else rgt())(
                left, right
            )
        return left

    def _and(self):
        left = self._eq()
        while self._peek("&&"):
            self._take()
            right = self._eq()
            left = (lambda lft, rgt: lambda: rgt() if truthy(lft()) else lft())(
                left, right
            )
        return left

    def _eq(self):
        left = self._cmp()
        while self._peek("==") or self._peek("!="):
            op = self._take()[1]
            right = self._cmp()
            if op == "==":
                left = (lambda lft, rgt: lambda: _equals(lft(), rgt()))(left, right)
            else:
                left = (lambda lft, rgt: lambda: not _equals(lft(), rgt()))(left, right)
        return left

    def _cmp(self):
        left = self._unary()
        while any(self._peek(op) for op in ("<", "<=", ">", ">=")):
            op = self._take()[1]
            right = self._unary()
            left = (lambda o, lft, rgt: lambda: _compare(o, lft(), rgt()))(
                op, left, right
            )
        return left

    def _unary(self):
        if self._peek("!"):
            self._take()
            operand = self._unary()
            return lambda: not truthy(operand())
        return self._postfix()

    def _postfix(self):
        node = self._primary()
        while True:
            if self._peek("."):
                self._take()
                if self._peek("*"):
                    self._take()
                    node = (lambda n: lambda: _values(n()))(node)
                    continue
                kind, name = self._take()
                if kind != "ident":
                    raise ExpressionError(f"bad property {name!r} in {self.text!r}")
                node = (lambda n, k: lambda: _lookup(n(), k))(node, name)
            elif self._peek("["):
                self._take()
                index = self._or()
                self._take("]")
                node = (lambda n, i: lambda: _index(n(), i()))(node, index)
            else:
                return node

    def _primary(self):
        kind, value = self._take()
        if kind == "num":
            number = (
                float(int(value, 16))
                if value.lower().startswith("0x")
                else float(value)
            )
            return lambda: number
        if kind == "str":
            literal = value[1:-1].replace("''", "'")
            return lambda: literal
        if value == "(":
            node = self._or()
            self._take(")")
            return node
        if kind != "ident":
            raise ExpressionError(f"unexpected {value!r} in {self.text!r}")
        lowered = value.lower()
        if lowered in ("true", "false"):
            boolean = lowered == "true"
            return lambda: boolean
        if lowered == "null":
            return lambda: None
        if self._peek("("):
            self._take()
            args = []
            if not self._peek(")"):
                args.append(self._or())
                while self._peek(","):
                    self._take()
                    args.append(self._or())
            self._take(")")
            return self._function(lowered, args)
        context = self.context
        return lambda: _lookup(context, value)

    def _function(self, name: str, args: list):
        status = self.context.get("__status__", "success")
        if name in ("success", "always", "cancelled", "failure"):
            if args:
                raise ExpressionError(f"{name}() takes no arguments")
            return {
                "success": lambda: status == "success",
                "always": lambda: True,
                "cancelled": lambda: status == "cancelled",
                "failure": lambda: status == "failure",
            }[name]
        if name == "startswith":
            return lambda: (
                to_string(args[0]()).lower().startswith(to_string(args[1]()).lower())
            )
        if name == "endswith":
            return lambda: (
                to_string(args[0]()).lower().endswith(to_string(args[1]()).lower())
            )
        if name == "contains":
            return lambda: _contains(args[0](), args[1]())
        if name == "format":
            return lambda: _format(to_string(args[0]()), *[a() for a in args[1:]])
        if name == "join":
            return lambda: (
                (to_string(args[1]()) if len(args) > 1 else ",").join(
                    to_string(v) for v in args[0]()
                )
                if isinstance(args[0](), list)
                else to_string(args[0]())
            )
        if name == "tojson":
            return lambda: json.dumps(args[0](), indent=2)
        if name == "fromjson":
            return lambda: json.loads(to_string(args[0]()))
        raise ExpressionError(f"function {name}() is not modeled")


def _values(obj: Any) -> list[Any]:
    """The `*` object filter: an object's values, or an array's elements."""
    if isinstance(obj, dict):
        return list(obj.values())
    if isinstance(obj, list):
        return list(obj)
    return []


def _index(obj: Any, key: Any) -> Any:
    if isinstance(obj, list):
        number = _to_number(key)
        if _is_nan(number) or int(number) != number or not 0 <= number < len(obj):
            return None
        return obj[int(number)]
    return _lookup(obj, to_string(key))


def evaluate(expression: str, context: dict[str, Any]) -> Any:
    """Evaluate the inside of one ``${{ }}``."""
    return _Parser(expression, context).parse()()


_EMBEDDED = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)


def render(value: Any, context: dict[str, Any]) -> Any:
    """Expand ``${{ }}`` in a YAML value the way Actions does.

    A string that is exactly one expression keeps the expression's type (that is
    how a boolean reaches a reusable workflow's boolean input); anything else is
    interpolated into a string.
    """
    if not isinstance(value, str):
        return value
    whole = _EMBEDDED.fullmatch(value.strip())
    if whole:
        return evaluate(whole.group(1), context)
    return _EMBEDDED.sub(lambda m: to_string(evaluate(m.group(1), context)), value)


def condition_holds(condition: Any, context: dict[str, Any]) -> bool:
    """Evaluate an ``if:``. An absent condition is ``success()``."""
    if condition is None:
        return context.get("__status__", "success") == "success"
    if isinstance(condition, bool):
        return condition
    text = str(condition).strip()
    whole = _EMBEDDED.fullmatch(text)
    if whole:
        text = whole.group(1)
    return truthy(evaluate(text, context))


# --------------------------------------------------------------------------- workflows


@dataclass
class Workflow:
    path: Path
    data: dict[str, Any]

    @property
    def name(self) -> str:
        return self.path.name

    @property
    def on(self) -> dict[str, Any]:
        # PyYAML reads the bare key `on` as the boolean True (YAML 1.1).
        raw = self.data.get("on", self.data.get(True))
        if isinstance(raw, str):
            return {raw: None}
        if isinstance(raw, list):
            return {str(item): None for item in raw}
        return dict(raw or {})

    @property
    def jobs(self) -> dict[str, dict[str, Any]]:
        return {k: (v or {}) for k, v in (self.data.get("jobs") or {}).items()}


def load_workflow(path: Path) -> Workflow:
    return Workflow(path, yaml.safe_load(path.read_text(encoding="utf-8")) or {})


def all_workflows() -> list[Workflow]:
    paths = sorted(p for p in WORKFLOWS_DIR.iterdir() if p.suffix in (".yml", ".yaml"))
    return [load_workflow(p) for p in paths]


def _pattern_regex(pattern: str) -> re.Pattern[str]:
    out: list[str] = []
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if char == "\\" and i + 1 < len(pattern):
            out.append(re.escape(pattern[i + 1]))
            i += 2
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif char == "*":
            out.append("[^/]*")
            i += 1
        elif char in "?+":
            out.append(char)
            i += 1
        elif char == "[":
            end = pattern.index("]", i)
            out.append("[" + pattern[i + 1 : end] + "]")
            i = end + 1
        else:
            out.append(re.escape(char))
            i += 1
    return re.compile("".join(out))


def filter_matches(patterns: Iterable[str] | str, name: str) -> bool:
    """GitHub's branch/tag filter: ordered, ``!`` excludes what came before it."""
    if isinstance(patterns, str):
        patterns = [patterns]
    matched = False
    for pattern in patterns:
        pattern = str(pattern)
        if pattern.startswith("!"):
            if _pattern_regex(pattern[1:]).fullmatch(name):
                matched = False
        elif _pattern_regex(pattern).fullmatch(name):
            matched = True
    return matched


def _ref_filter(config: dict[str, Any], key: str, name: str) -> bool | None:
    if key in config:
        return filter_matches(config[key] or [], name)
    if f"{key}-ignore" in config:
        return not filter_matches(config[f"{key}-ignore"] or [], name)
    return None


def triggers(workflow: Workflow, context: dict[str, Any]) -> bool:
    """Whether the event in ``context`` starts ``workflow`` at all."""
    github = context["github"]
    event = github["event_name"]
    on = workflow.on
    if event not in on:
        return False
    config = on[event] or {}
    if not isinstance(config, dict):
        return True
    if event == "push":
        ref = github["ref"]
        if ref.startswith("refs/tags/"):
            verdict = _ref_filter(config, "tags", ref[len("refs/tags/") :])
            if verdict is not None:
                return verdict
            return not ("branches" in config or "branches-ignore" in config)
        if ref.startswith("refs/heads/"):
            verdict = _ref_filter(config, "branches", ref[len("refs/heads/") :])
            if verdict is not None:
                return verdict
            return not ("tags" in config or "tags-ignore" in config)
        return True
    if event in ("pull_request", "pull_request_target"):
        verdict = _ref_filter(config, "branches", github.get("base_ref") or "")
        return True if verdict is None else verdict
    return True


_ALL_SCOPES = (
    "actions",
    "attestations",
    "checks",
    "contents",
    "deployments",
    "discussions",
    "id-token",
    "issues",
    "models",
    "packages",
    "pages",
    "pull-requests",
    "repository-projects",
    "security-events",
    "statuses",
)


def normalize_permissions(raw: Any) -> dict[str, str]:
    if raw == "read-all":
        return dict.fromkeys(_ALL_SCOPES, "read")
    if raw == "write-all":
        return dict.fromkeys(_ALL_SCOPES, "write")
    if not raw:
        return {}
    return {str(k): str(v) for k, v in dict(raw).items()}


def job_permissions(workflow: Workflow, job: dict[str, Any]) -> dict[str, str] | None:
    """The token scopes a job declares; None when neither it nor its workflow declares any."""
    if "permissions" in job:
        return normalize_permissions(job["permissions"])
    if "permissions" in workflow.data:
        return normalize_permissions(workflow.data["permissions"])
    return None


def job_runs(job: dict[str, Any], context: dict[str, Any]) -> bool:
    """Evaluate a job's ``if:``; a condition this model cannot read counts as running."""
    try:
        return condition_holds(job.get("if"), context)
    except ExpressionError:
        return True


def local_reusable_workflow(job: dict[str, Any]) -> Workflow | None:
    uses = str(job.get("uses") or "")
    if not uses.startswith("./"):
        return None
    return load_workflow(REPO_ROOT / uses[2:])


def check_names(job_id: str, job: dict[str, Any]) -> list[str]:
    """The check-run names a job produces; a caller's are `<caller> / <called job>`."""
    caller = str(job.get("name") or job_id)
    called = local_reusable_workflow(job)
    if called is None:
        return [caller]
    return [
        f"{caller} / {called_job.get('name') or called_id}"
        for called_id, called_job in called.jobs.items()
    ]


def call_inputs(
    job: dict[str, Any], called: Workflow, context: dict[str, Any]
) -> dict[str, Any]:
    """The ``inputs`` context the called workflow sees: declared defaults, then ``with:``."""
    declared = ((called.on.get("workflow_call") or {}).get("inputs")) or {}
    inputs: dict[str, Any] = {}
    for name, spec in declared.items():
        spec = spec or {}
        default = render(spec.get("default"), context)
        if spec.get("type") == "boolean" and isinstance(default, str):
            default = default.lower() == "true"
        inputs[name] = default
    for name, value in (job.get("with") or {}).items():
        inputs[name] = render(value, context)
    return inputs


def with_inputs(context: dict[str, Any], inputs: dict[str, Any]) -> dict[str, Any]:
    out = dict(context)
    out["inputs"] = inputs
    return out


def render_env(env: dict[str, Any] | None, context: dict[str, Any]) -> dict[str, str]:
    """Render an ``env:`` mapping; each value sees the ones already rendered at its level."""
    rendered: dict[str, str] = {}
    for key, value in (env or {}).items():
        scoped = dict(context)
        scoped["env"] = {**(context.get("env") or {}), **rendered}
        rendered[str(key)] = to_string(render(value, scoped))
    return rendered


# --------------------------------------------------------------------------- step runner

#: The tools the stubs stand in for. Each records one JSON line per call.
STUB_TOOLS = ("uv", "uvx", "curl", "bundle", "gem", "ruby", "grype")

#: Recorded, then handed to the real interpreter with the same argv, stdin and cwd,
#: so a step that parses JSON with ``python3 -c`` still works.
PASS_THROUGH_TOOLS = ("python", "python3")

#: Variables each stub records, so a test can tell "unset" (None) from "empty".
WATCHED_ENV = (
    "ASH_CONFIG",
    "ASH_DEPENDENCIES_UNKNOWN_TOOLS",
    "UV_NO_CONFIG",
    "BUNDLE_GEMFILE",
    "PYTHONPATH",
    "PYTHONSAFEPATH",
)

#: The bytes every stub-installed tool binary holds; STUB_PIN is their SHA-256.
STUB_BINARY = b"#!/bin/sh\nexit 0\n"

_STUB_PROGRAM = r"""
import hashlib, json, os, sys

tool = sys.argv[1]
argv = sys.argv[2:]
record = {
    "tool": tool,
    "argv": argv,
    "cwd": os.path.realpath(os.getcwd()),
    "env": {k: os.environ.get(k) for k in json.loads(os.environ["STUB_WATCHED"])},
}

def value_after(flag):
    for i, arg in enumerate(argv[:-1]):
        if arg == flag:
            return argv[i + 1]
    return None

binary = os.environ["STUB_BINARY"].encode()
status = 0
if tool in ("python", "python3"):
    with open(os.environ["STUB_LOG"], "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")
    real = os.environ["STUB_REAL_PYTHON"]
    os.execv(real, [real] + argv)
if tool == "uv":
    joined = " ".join(argv)
    if "get_tool_asset" in joined:
        print(hashlib.sha256(binary).hexdigest())
    elif "cache-key" in argv:
        print("grype-db-v1-w86400-b0")
elif tool == "uvx":
    if "dependencies" in argv and "install" in argv:
        bin_path = value_after("--bin-path")
        tools = [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == "--tool"]
        if bin_path:
            os.makedirs(bin_path, exist_ok=True)
            for name in tools:
                target = os.path.join(bin_path, name)
                with open(target, "wb") as handle:
                    handle.write(binary)
                os.chmod(target, 0o755)
elif tool == "curl":
    url = next((a for a in argv if a.startswith("http")), "")
    out = value_after("-o")
    record["url"] = url
    if out:
        with open(out, "w", encoding="utf-8") as handle:
            handle.write(f"# fetched from {url}\n")
elif tool == "bundle":
    gemfile = os.environ.get("BUNDLE_GEMFILE")
    if gemfile and os.path.isfile(gemfile):
        record["gemfile_realpath"] = os.path.realpath(gemfile)
        with open(gemfile, encoding="utf-8") as handle:
            record["gemfile_content"] = handle.read()
    if argv[:1] == ["binstubs"]:
        target_dir = value_after("--path")
        if target_dir:
            os.makedirs(target_dir, exist_ok=True)
            target = os.path.join(target_dir, "cfn_nag_scan")
            with open(target, "w", encoding="utf-8") as handle:
                handle.write("#!/bin/sh\nexit 0\n")
            os.chmod(target, 0o755)
elif tool == "grype":
    if argv[:2] == ["db", "status"]:
        print(json.dumps({"built": os.environ.get("STUB_BUILT", "")}))

with open(os.environ["STUB_LOG"], "a", encoding="utf-8") as handle:
    handle.write(json.dumps(record) + "\n")
sys.exit(status)
"""


@dataclass
class StepSandbox:
    """A runner-shaped directory layout: a checkout, RUNNER_TEMP beside it, a HOME."""

    root: Path
    workspace: Path = field(init=False)
    runner_temp: Path = field(init=False)
    home: Path = field(init=False)
    stub_dir: Path = field(init=False)

    def __post_init__(self) -> None:
        # Mirrors /home/runner/work/<repo>/<repo> and /home/runner/work/_temp: the
        # temp directory is a sibling of the checkout, never inside it.
        self.workspace = self.root / "work" / "repo" / "repo"
        self.runner_temp = self.root / "work" / "_temp"
        self.home = self.root / "home"
        self.stub_dir = self.root / "stubs"
        for path in (self.workspace, self.runner_temp, self.home, self.stub_dir):
            path.mkdir(parents=True, exist_ok=True)
        program = self.stub_dir / "_stub.py"
        program.write_text(_STUB_PROGRAM, encoding="utf-8")
        for tool in STUB_TOOLS + PASS_THROUGH_TOOLS:
            self.install_stub(tool, self.stub_dir)

    def install_stub(self, tool: str, directory: Path) -> Path:
        directory.mkdir(parents=True, exist_ok=True)
        wrapper = directory / tool
        wrapper.write_text(
            f'#!/bin/sh\nexec "{sys.executable}" -I "{self.stub_dir / "_stub.py"}" '
            f'{tool} "$@"\n',
            encoding="utf-8",
        )
        wrapper.chmod(0o755)
        return wrapper

    def runner_context(self) -> dict[str, Any]:
        return {"temp": str(self.runner_temp), "os": "Linux", "arch": "X64"}

    def is_inside_workspace(self, path: str | Path) -> bool:
        return Path(os.path.realpath(path)).is_relative_to(
            Path(os.path.realpath(self.workspace))
        )


@dataclass
class StepRun:
    step_name: str
    proc: subprocess.CompletedProcess
    calls: list[dict[str, Any]]

    def calls_to(self, tool: str) -> list[dict[str, Any]]:
        return [c for c in self.calls if c["tool"] == tool]

    def describe(self) -> str:
        calls = "\n  ".join(
            f"{c['tool']} {' '.join(c['argv'])}  (cwd={c['cwd']}, env={c['env']})"
            for c in self.calls
        )
        return (
            f"step {self.step_name!r} exit={self.proc.returncode}\n"
            f"calls:\n  {calls or '(none)'}\n"
            f"stdout: {self.proc.stdout.strip()[-2000:]}\n"
            f"stderr: {self.proc.stderr.strip()[-2000:]}"
        )


def _shell_argv(shell: str | None, script: Path) -> list[str]:
    if shell is None:
        return ["bash", "-e", str(script)]
    if shell == "bash":
        return ["bash", "--noprofile", "--norc", "-eo", "pipefail", str(script)]
    if shell == "sh":
        return ["sh", "-e", str(script)]
    raise ExpressionError(f"shell {shell!r} is not modeled")


def run_step(
    sandbox: StepSandbox,
    workflow: Workflow,
    job: dict[str, Any],
    step: dict[str, Any],
    context: dict[str, Any],
    *,
    extra_env: dict[str, str] | None = None,
    github_env: dict[str, str] | None = None,
) -> StepRun:
    """Run one step's ``run:`` block the way a Linux runner would, with stubs on PATH.

    ``github_env`` is what earlier steps wrote to ``GITHUB_ENV`` (``read_github_env``).
    The runner applies it over the workflow and job ``env:`` and under the step's own
    ``env:`` (actions/runner: job env and file commands both land in the job's global
    environment, in that order, and StepsRunner merges the step's env on top), in the
    process environment and in the ``env`` context alike.
    """
    if "run" not in step:
        raise ExpressionError(f"step {step.get('name')!r} has no run: block")
    ctx = dict(context)
    ctx["runner"] = sandbox.runner_context()
    github = dict(ctx.get("github") or {})
    github["workspace"] = str(sandbox.workspace)
    ctx["github"] = github

    workflow_env = render_env(workflow.data.get("env"), {**ctx, "env": {}})
    ctx["env"] = workflow_env
    job_env = render_env(job.get("env"), ctx)
    file_env = dict(github_env or {})
    ctx["env"] = {**workflow_env, **job_env, **file_env}
    step_env = render_env(step.get("env"), ctx)
    ctx["env"] = {**workflow_env, **job_env, **file_env, **step_env}

    files = sandbox.runner_temp / "_runner_file_commands"
    files.mkdir(exist_ok=True)
    log = sandbox.root / f"stub-calls-{os.getpid()}-{id(step)}.jsonl"
    log.write_text("", encoding="utf-8")
    base_env = {
        "PATH": f"{sandbox.stub_dir}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}",
        "HOME": str(sandbox.home),
        "CI": "true",
        "GITHUB_ACTIONS": "true",
        "RUNNER_OS": "Linux",
        "RUNNER_TEMP": str(sandbox.runner_temp),
        "GITHUB_WORKSPACE": str(sandbox.workspace),
        "GITHUB_PATH": str(files / "path"),
        "GITHUB_ENV": str(files / "env"),
        "GITHUB_OUTPUT": str(files / "output"),
        "GITHUB_STEP_SUMMARY": str(files / "summary"),
        "STUB_LOG": str(log),
        "STUB_WATCHED": json.dumps(list(WATCHED_ENV)),
        "STUB_BINARY": STUB_BINARY.decode(),
        "STUB_REAL_PYTHON": shutil.which("python3", path=os.environ.get("PATH"))
        or sys.executable,
    }
    env = {
        **base_env,
        **workflow_env,
        **job_env,
        **file_env,
        **step_env,
        **(extra_env or {}),
    }

    defaults_run = {
        **((workflow.data.get("defaults") or {}).get("run") or {}),
        **((job.get("defaults") or {}).get("run") or {}),
    }
    working_directory = step.get(
        "working-directory", defaults_run.get("working-directory")
    )
    cwd = sandbox.workspace
    if working_directory:
        rendered = Path(to_string(render(working_directory, ctx)))
        cwd = rendered if rendered.is_absolute() else sandbox.workspace / rendered
    shell = step.get("shell", defaults_run.get("shell"))

    script = sandbox.runner_temp / "_step_script.sh"
    script.write_text(to_string(render(step["run"], ctx)), encoding="utf-8")
    proc = subprocess.run(
        _shell_argv(shell, script),
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    calls = [
        json.loads(line)
        for line in log.read_text(encoding="utf-8").splitlines()
        if line
    ]
    return StepRun(str(step.get("name")), proc, calls)


def read_github_env(sandbox: StepSandbox) -> dict[str, str]:
    """What the steps run so far wrote to ``GITHUB_ENV``, later lines winning.

    Both forms the runner accepts: ``NAME=value``, and ``NAME<<DELIMITER`` followed by
    the value's lines and a line holding only the delimiter.
    """
    path = sandbox.runner_temp / "_runner_file_commands" / "env"
    if not path.exists():
        return {}
    values: dict[str, str] = {}
    lines = path.read_text(encoding="utf-8").splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        i += 1
        if not line:
            continue
        if "<<" in line and ("=" not in line or line.index("<<") < line.index("=")):
            name, delimiter = line.split("<<", 1)
            body = []
            while i < len(lines) and lines[i] != delimiter:
                body.append(lines[i])
                i += 1
            if i >= len(lines):
                raise ExpressionError(
                    f"GITHUB_ENV: no closing {delimiter!r} for {name!r}"
                )
            i += 1
            values[name] = "\n".join(body)
        elif "=" in line:
            name, value = line.split("=", 1)
            values[name] = value
        else:
            raise ExpressionError(f"GITHUB_ENV: cannot read the line {line!r}")
    return values


def interpreter_options(python_argv: list[str]) -> list[str]:
    """The options before `-m`, `-c` or the script in a python argv (argv[0] excluded)."""
    options: list[str] = []
    for arg in python_argv:
        if arg in ("-m", "-c") or not arg.startswith("-"):
            break
        options.append(arg)
    return options


def python_options(call: dict[str, Any]) -> list[str] | None:
    """The interpreter options of a recorded python launch, or None if it is not one.

    Covers a direct `python3 <opts> -c ...` and `uv run ... -- python <opts> -m ...`.
    """
    argv = call["argv"]
    if call["tool"] in PASS_THROUGH_TOOLS:
        return interpreter_options(argv)
    if call["tool"] != "uv" or "--" not in argv:
        return None
    after = argv[argv.index("--") + 1 :]
    if not after or Path(after[0]).name not in ("python", "python3"):
        return None
    return interpreter_options(after[1:])


def isolates_sys_path(options: list[str], env: dict[str, Any]) -> bool:
    """`-I` or `-P` (alone or combined, e.g. `-IS`), or PYTHONSAFEPATH set."""
    for option in options:
        if option.startswith("-") and not option.startswith("--"):
            if {"I", "P"} & set(option[1:]):
                return True
    return bool(env.get("PYTHONSAFEPATH"))


def uv_global_args(uv_argv: list[str]) -> list[str]:
    """uv's own arguments, before the `--` that starts the command it runs."""
    return uv_argv[: uv_argv.index("--")] if "--" in uv_argv else list(uv_argv)


def effective_directory(call: dict[str, Any]) -> str:
    """Where uv resolves the project and its settings: `--directory` if given, else cwd."""
    args = uv_global_args(call["argv"])
    for i, arg in enumerate(args[:-1]):
        if arg == "--directory":
            target = Path(args[i + 1])
            return str(target if target.is_absolute() else Path(call["cwd"]) / target)
        if arg.startswith("--directory="):
            target = Path(arg.split("=", 1)[1])
            return str(target if target.is_absolute() else Path(call["cwd"]) / target)
    return call["cwd"]


def base_context(**github: Any) -> dict[str, Any]:
    """An expression context with every top-level name present."""
    return {
        "github": github,
        "inputs": {},
        "env": {},
        "runner": {"temp": "/home/runner/work/_temp", "os": "Linux", "arch": "X64"},
        "steps": {},
        "needs": {},
        "secrets": {},
        "vars": {},
        "matrix": {},
        "strategy": {},
        "job": {},
    }
