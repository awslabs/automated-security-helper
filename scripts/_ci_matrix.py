"""One reader for the GitHub Actions matrices in .github/workflows.

Tests and generators that read a workflow's matrix need the same answers: which legs a
job has on an event, which runner each leg runs on, and which steps run in it. Four test
modules each expanded the matrix their own way. This file is the one expansion they
share, and the one the support-matrix generators read.

* load_workflow, parse_workflow and triggers read a workflow as GitHub does (a plain
  top-level ``on:`` is the trigger key, not true) and name the events it runs on.
* cells and axis_cells give the jobs GitHub creates for one entry under ``jobs:``, per
  event. PULL_REQUEST_OVERLAY is the one event-conditioned matrix entry the workflows use.
* RUNNER_LABELS, runs_on and check_runner_labels say what each runner label is, and fail
  on a label a workflow names that the table does not list.
* evaluate_condition and step_runs say whether a step's ``if:`` holds in a leg, for the
  few condition shapes the validator steps use.

The file refuses what it cannot read. A matrix, a runs-on or a condition in a shape it
does not know raises a CiMatrixError that names the shape. Nothing is read as true, or as
a match, because it could not be read.

scripts/ is not a package. A caller loads this file by path, and this file loads
scripts/_ci_pipelines.py the same way for its workflow parser.
"""

from __future__ import annotations

import importlib.util
import itertools
import math
import re
import sys
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: The events a matrix is expanded for. Every one of them reads the static axes except
#: ``pull_request``, where the overlay entries (PULL_REQUEST_OVERLAY) take effect.
EVENTS = ("push", "pull_request", "merge_group", "workflow_dispatch")


# -- What this file refuses ---------------------------------------------------------


class CiMatrixError(ValueError):
    """Base of every refusal this file makes."""


class WorkflowError(CiMatrixError):
    """A workflow that does not load as one mapping with jobs."""


class UnsupportedMatrix(CiMatrixError):
    """A matrix this file cannot expand: not a mapping, or an axis that is not a list."""


class UnsupportedExpression(CiMatrixError):
    """A ``${{ }}`` form, condition or runs-on this file does not read.

    ``shape`` names what was refused ("the != operator", "a call to startsWith()") and
    ``text`` is the text it was found in.
    """

    def __init__(self, shape: str, text: str, where: str = "") -> None:
        self.shape = shape
        self.text = text
        prefix = f"{where}: " if where else ""
        super().__init__(f"{prefix}refused {shape}: {text!r}")


class UnknownRunnerLabel(CiMatrixError):
    """A runner label that is not in RUNNER_LABELS."""


# -- Loading a workflow -------------------------------------------------------------


def _ci_pipelines() -> Any:
    """scripts/_ci_pipelines.py, loaded by path for its workflow parser."""
    name = "_ash_ci_matrix_pipelines"
    module = sys.modules.get(name)
    if module is None:
        path = Path(__file__).resolve().parent / "_ci_pipelines.py"
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"cannot load {path}")
        module = importlib.util.module_from_spec(spec)
        # Registered first, so the dataclasses the module defines can resolve.
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
        except BaseException:
            sys.modules.pop(name, None)
            raise
    return module


def parse_workflow(text: str, source: str = "the workflow") -> dict[str, Any]:
    """The workflow in ``text`` as one mapping, read as GitHub reads it.

    The top-level plain ``on:`` key comes back as "on". PyYAML reads it as True, and
    GitHub reads no spelling of it but on. ``source`` names the text in a refusal.
    """
    document, error = _ci_pipelines()._parse_workflow(text)
    if error is not None:
        raise WorkflowError(f"{source} {error}")
    if not isinstance(document, dict):
        raise WorkflowError(
            f"{source} is not one YAML mapping (found {type(document).__name__})"
        )
    if not isinstance(document.get("jobs"), dict):
        raise WorkflowError(f"{source} has no jobs mapping")
    return document


def load_workflow(path: Path | str) -> dict[str, Any]:
    """The workflow file at ``path``, read by parse_workflow."""
    return parse_workflow(Path(path).read_text(encoding="utf-8"), str(path))


@dataclass(frozen=True)
class Trigger:
    """One event a workflow runs on, and whether a path filter narrows it."""

    event: str
    path_filtered: bool


def triggers(workflow: Mapping[str, Any]) -> dict[str, Trigger]:
    """The events ``workflow`` runs on, by name.

    ``workflow`` has to come from load_workflow or parse_workflow: a document read with
    yaml.safe_load has True where the ``on`` key belongs, and is refused. An event is path
    filtered when its ``paths`` or ``paths-ignore`` is not empty.
    """
    if "on" not in workflow:
        raise WorkflowError(
            "the workflow has no `on` key. yaml.safe_load reads a plain `on:` as True; "
            "read the workflow with load_workflow or parse_workflow."
        )
    on = workflow["on"]
    if isinstance(on, str):
        configs: dict[str, Any] = {on: None}
    elif isinstance(on, list):
        configs = dict.fromkeys(str(event) for event in on)
    elif isinstance(on, Mapping):
        configs = {str(event): config for event, config in on.items()}
    else:
        raise WorkflowError(f"`on` is not an event, a list or a mapping: {on!r}")
    return {
        event: Trigger(event, _is_path_filtered(config))
        for event, config in configs.items()
    }


def _is_path_filtered(config: Any) -> bool:
    return isinstance(config, Mapping) and any(
        config.get(key) for key in ("paths", "paths-ignore")
    )


# -- Expanding a matrix -------------------------------------------------------------

#: The one shape of event-conditioned matrix entry the workflows use: the value on a
#: pull request, the empty string (matching no combination) on every other event.
PULL_REQUEST_OVERLAY = re.compile(
    r"^\$\{\{ github\.event_name == 'pull_request' && '([^']*)' \|\| '' \}\}$"
)


def _check_event(event: str) -> None:
    if event not in EVENTS:
        raise ValueError(f"unknown event {event!r}; the events are {EVENTS}")


def resolve_overlay(value: Any, event: str) -> Any:
    """The value a matrix entry has under ``event``; None when the entry is void.

    A plain value is itself on every event. The overlay expression is its quoted value on a
    pull request and void everywhere else, because GitHub evaluates it to '' there and no
    combination has an empty axis value. A string that is not the overlay comes back as
    written: cells refuses it before this is asked.
    """
    _check_event(event)
    if isinstance(value, str):
        match = PULL_REQUEST_OVERLAY.match(value)
        if match:
            return match.group(1) if event == "pull_request" else None
    return value


def _matrix_of(job: Mapping[str, Any]) -> Mapping[str, Any]:
    """The job's ``strategy.matrix``, or an empty mapping when it has none."""
    strategy = job.get("strategy")
    if not strategy:
        return {}
    if not isinstance(strategy, Mapping):
        raise UnsupportedMatrix(f"a strategy that is not a mapping: {strategy!r}")
    matrix = strategy.get("matrix")
    if not matrix:
        return {}
    if isinstance(matrix, str) and "${{" in matrix:
        raise UnsupportedExpression("matrix expression", matrix, "strategy.matrix")
    if not isinstance(matrix, Mapping):
        raise UnsupportedMatrix(f"a matrix that is not a mapping: {matrix!r}")
    return matrix


def _axes(matrix: Mapping[str, Any]) -> dict[str, list[Any]]:
    axes = {k: v for k, v in matrix.items() if k not in ("include", "exclude")}
    for name, values in axes.items():
        if not isinstance(values, list):
            raise UnsupportedMatrix(f"axis {name} is not a list: {values!r}")
    return axes


def _entries(matrix: Mapping[str, Any], name: str) -> list[Mapping[str, Any]]:
    entries = matrix.get(name) or []
    if not isinstance(entries, list) or not all(
        isinstance(entry, Mapping) for entry in entries
    ):
        raise UnsupportedMatrix(f"{name} is not a list of mappings: {entries!r}")
    return entries


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)


def _refuse_unread_expressions(matrix: Mapping[str, Any]) -> None:
    """Refuse a ``${{ }}`` form in the matrix other than the overlay in an exclude.

    The expansion compares every other string as the plain value it is, so an expression
    it cannot evaluate would be compared as its own text and match nothing.
    """
    for name, part in matrix.items():
        for text in _strings(part):
            if "${{" not in text:
                continue
            if name == "exclude" and PULL_REQUEST_OVERLAY.match(text):
                continue
            raise UnsupportedExpression("matrix expression", text, f"matrix {name}")


def axis_cells(matrix: Mapping[str, Any], event: str = "push") -> list[dict[str, Any]]:
    """The axes' product, less the cells an ``exclude`` entry matches on ``event``.

    An ``include`` entry is not applied here: cells applies them. A matrix with no axis has
    no product, so this is empty for one that only includes. An exclude entry with a void
    value (see resolve_overlay) matches nothing.
    """
    _check_event(event)
    _refuse_unread_expressions(matrix)
    axes = _axes(matrix)
    legs = (
        [dict(zip(axes, combo)) for combo in itertools.product(*axes.values())]
        if axes
        else []
    )
    for excluded in _entries(matrix, "exclude"):
        resolved = {
            key: resolve_overlay(value, event) for key, value in excluded.items()
        }
        if any(value is None for value in resolved.values()):
            continue
        legs = [
            leg
            for leg in legs
            if not all(leg.get(key) == value for key, value in resolved.items())
        ]
    return legs


def cells(job: Mapping[str, Any], event: str = "push") -> list[dict[str, Any]]:
    """The jobs GitHub creates for one entry under ``jobs:``, as matrix cells, on ``event``.

    The axes' product, less the cells an ``exclude`` entry matches (axis_cells). An
    ``include`` entry merges into every cell whose axis values it matches, adding none, and
    is a cell of its own only when it matches none; a later include may overwrite a value an
    earlier one added, never an axis value (the matrix rules in GitHub's workflow syntax
    reference). A job with no matrix is one empty cell.
    """
    _check_event(event)
    matrix = _matrix_of(job)
    if not matrix:
        return [{}]
    legs = axis_cells(matrix, event)
    axes = _axes(matrix)
    added: list[dict[str, Any]] = []
    for included in _entries(matrix, "include"):
        matching = [
            leg
            for leg in legs
            if all(leg[key] == value for key, value in included.items() if key in axes)
        ]
        for leg in matching:
            leg.update(included)
        if not matching:
            added.append(dict(included))
    return legs + added


def matrix_values(job: Mapping[str, Any], key: str) -> list[Any]:
    """Every value ``key`` takes in the job's matrix: its axis values, then the value of
    each ``include`` entry that sets it.

    Excludes are not applied, so a value no leg runs still counts: this asks what a matrix
    names, not what it runs.
    """
    matrix = _matrix_of(job)
    if not matrix:
        return []
    _refuse_unread_expressions(matrix)
    values: list[Any] = []
    if key not in ("include", "exclude") and key in matrix:
        values.extend(_axes(matrix)[key])
    values.extend(entry[key] for entry in _entries(matrix, "include") if key in entry)
    return values


# -- Evaluating a step's if: --------------------------------------------------------
#
# The grammar is the one the validator steps use:
#
#     condition  := expression, alone or as the whole of one ${{ }}
#     expression := operand ('&&' operand)*   or   operand ('||' operand)*
#     operand    := comparison | '(' expression ')' | '!cancelled()'
#     comparison := value '==' value
#     value      := a single-quoted string | matrix.<key>
#
# && and || are not mixed without parentheses: GitHub's reference does not say which binds
# tighter, so a reading here would be a guess. ``!cancelled()`` is the one status function
# read, as true: a leg that runs is not cancelled. Everything else is refused by name.

_WRAPPED = re.compile(r"^\s*\$\{\{(?P<body>.*)\}\}\s*$", re.DOTALL)
_CONDITION_TOKEN = re.compile(
    r"""
    \s*
    (?:
        (?P<string>'(?:[^']|'')*')
      | (?P<number>[0-9][0-9A-Za-z.+-]*)
      | (?P<name>[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*)*)
      | (?P<operator>&&|\|\||==|!=|!|\(|\)|\[|\]|\.|,)
      | (?P<other>\S)
    )
    """,
    re.VERBOSE,
)
_NON_STRING_LITERALS = frozenset({"true", "false", "null", "NaN", "Infinity"})
_Token = tuple[str, str]


def _refused(shape: str, text: str) -> UnsupportedExpression:
    return UnsupportedExpression(shape, text, "condition")


def _tokenize(text: str) -> list[_Token]:
    tokens: list[_Token] = []
    position = 0
    while position < len(text):
        match = _CONDITION_TOKEN.match(text, position)
        if match is None:
            break
        position = match.end()
        kind = match.lastgroup or "other"
        value = match.group(kind)
        if kind == "other":
            if value in ("$", "{", "}"):
                raise _refused("a ${{ }} wrapper inside the expression", text)
            if value == "'":
                raise _refused("an unterminated string literal", text)
            raise _refused(f"the character {value!r}", text)
        tokens.append((kind, value))
    return tokens


class _ConditionParser:
    """Reads the grammar above into nested tuples: ("equals", left, right),
    ("and", operands), ("or", operands) and ("cancelled",)."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.tokens = _tokenize(text)
        self.at = 0

    def peek(self) -> _Token | None:
        return self.tokens[self.at] if self.at < len(self.tokens) else None

    def take(self) -> _Token:
        token = self.peek()
        if token is None:
            raise _refused("an incomplete condition", self.text)
        self.at += 1
        return token

    def parse(self) -> tuple[Any, ...]:
        if not self.tokens:
            raise _refused("an empty condition", self.text)
        node = self.expression()
        leftover = self.peek()
        if leftover is not None:
            if leftover[1] == ")":
                raise _refused("an unmatched closing parenthesis", self.text)
            if leftover[0] in ("name", "string", "number"):
                raise _refused("two operands with no && or || between them", self.text)
            raise _refused(f"the operator {leftover[1]!r}", self.text)
        return node

    def expression(self) -> tuple[Any, ...]:
        operands = [self.operand()]
        connective = None
        while True:
            token = self.peek()
            if token is None or token[1] not in ("&&", "||"):
                break
            if connective is not None and token[1] != connective:
                raise _refused("&& and || mixed without parentheses", self.text)
            connective = token[1]
            self.at += 1
            operands.append(self.operand())
        if connective is None:
            return operands[0]
        return ("and" if connective == "&&" else "or", tuple(operands))

    def operand(self) -> tuple[Any, ...]:
        kind, text = self.take()
        if kind == "operator" and text == "(":
            node = self.expression()
            closing = self.peek()
            if closing is None or closing[1] != ")":
                raise _refused("an unclosed parenthesis", self.text)
            self.at += 1
            return node
        if kind == "operator" and text == "!":
            wanted = [("name", "cancelled"), ("operator", "("), ("operator", ")")]
            if self.tokens[self.at : self.at + 3] != wanted:
                raise _refused("negation (!) of anything but cancelled()", self.text)
            self.at += 3
            return ("cancelled",)
        self.at -= 1
        return self.comparison()

    def comparison(self) -> tuple[Any, ...]:
        left = self.value()
        token = self.peek()
        if token is not None and token[1] == "!=":
            raise _refused("the != operator", self.text)
        if token is None or token[1] != "==":
            raise _refused("a value that is not compared with ==", self.text)
        self.at += 1
        return ("equals", left, self.value())

    def value(self) -> tuple[str, str]:
        kind, text = self.take()
        if kind == "string":
            return ("string", text[1:-1].replace("''", "'"))
        if kind == "number":
            raise _refused("a non-string literal", self.text)
        if kind == "name":
            return self.reference(text)
        raise _refused(f"the operator {text!r}", self.text)

    def reference(self, name: str) -> tuple[str, str]:
        following = self.peek()
        if following is not None and following[1] == "(":
            raise _refused(f"a call to {name}()", self.text)
        if following is not None and following[1] == "[":
            raise _refused("index access ([ ])", self.text)
        if name in _NON_STRING_LITERALS:
            raise _refused("a non-string literal", self.text)
        parts = name.split(".")
        if parts[0] != "matrix":
            raise _refused(f"the {parts[0]} context ({name})", self.text)
        if len(parts) == 1:
            raise _refused("a matrix reference that is not matrix.<key>", self.text)
        if len(parts) > 2:
            raise _refused(f"a nested matrix property ({name})", self.text)
        return ("matrix", parts[1])


def _kind(value: Any) -> str:
    """The type GitHub's expressions give a value."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    return "object"


_JSON_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")


def _as_number(value: Any) -> float:
    """A value as GitHub coerces it to a number when the types of an == differ: null is 0,
    a boolean is 1 or 0, a string is the number it spells (0 when empty), anything else is
    NaN."""
    if value is None:
        return 0.0
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        if value == "":
            return 0.0
        if _JSON_NUMBER.fullmatch(value):
            return float(value)
    return math.nan


def _loosely_equal(left: Any, right: Any) -> bool:
    """GitHub's ==: strings compare without regard to case, values of one type compare as
    themselves (an array or object only equals itself), and values of two types compare as
    numbers, where NaN equals nothing."""
    left_kind, right_kind = _kind(left), _kind(right)
    if left_kind != right_kind:
        return _as_number(left) == _as_number(right)
    if left_kind == "string":
        return left.lower() == right.lower()
    if left_kind == "object":
        return left is right
    return bool(left == right)


def _operand(node: tuple[Any, ...], cell: Mapping[str, Any]) -> Any:
    return node[1] if node[0] == "string" else cell.get(node[1])


def _evaluate(node: tuple[Any, ...], cell: Mapping[str, Any]) -> bool:
    tag = node[0]
    if tag == "cancelled":
        return True
    if tag == "and":
        return all(_evaluate(child, cell) for child in node[1])
    if tag == "or":
        return any(_evaluate(child, cell) for child in node[1])
    return _loosely_equal(_operand(node[1], cell), _operand(node[2], cell))


def evaluate_condition(expression: str, cell: Mapping[str, Any]) -> bool:
    """Whether the condition ``expression`` holds in the leg ``cell``.

    A key the cell does not carry is null, as in GitHub. A shape outside the grammar above
    raises UnsupportedExpression naming it, whatever the cell holds and whichever operand
    would have decided the answer.
    """
    if not isinstance(expression, str):
        raise UnsupportedExpression(
            "a condition that is not a string", repr(expression), "condition"
        )
    wrapped = _WRAPPED.match(expression)
    text = (wrapped.group("body") if wrapped else expression).strip()
    return _evaluate(_ConditionParser(text).parse(), cell)


def step_runs(step: Mapping[str, Any], cell: Mapping[str, Any]) -> bool:
    """Whether a step runs in the leg ``cell``. A step with no ``if:`` always does: its
    default is success(), which holds in a run that has not failed or been cancelled."""
    condition = step.get("if")
    if condition is None:
        return True
    return evaluate_condition(condition, cell)


# -- Runner labels ------------------------------------------------------------------


@dataclass(frozen=True)
class RunnerLabel:
    """What a ``runs-on`` label is: its OS family ("linux", "macos" or "windows"), its
    architecture ("x86_64" or "arm64") and the image version the label names, or None when
    it names none (``-latest``, ``ubuntu-slim``)."""

    label: str
    os_family: str
    architecture: str
    image_version: str | None


#: The labels the workflows name, each as GitHub's runner reference lists it for a public
#: repository:
#: https://docs.github.com/en/actions/reference/runners/github-hosted-runners
#: A label joins the table, with its row read from that page, when a workflow first names
#: it; check_runner_labels fails on one that is not here.
RUNNER_LABELS: dict[str, RunnerLabel] = {
    row.label: row
    for row in (
        RunnerLabel("ubuntu-latest", "linux", "x86_64", None),
        RunnerLabel("ubuntu-24.04", "linux", "x86_64", "24.04"),
        RunnerLabel("ubuntu-24.04-arm", "linux", "arm64", "24.04"),
        RunnerLabel("ubuntu-slim", "linux", "x86_64", None),
        RunnerLabel("macos-latest", "macos", "arm64", None),
        RunnerLabel("macos-15", "macos", "arm64", "15"),
        RunnerLabel("windows-latest", "windows", "x86_64", None),
    )
}


def runner_label(label: str) -> RunnerLabel:
    """The RUNNER_LABELS row for ``label``."""
    try:
        return RUNNER_LABELS[label]
    except KeyError:
        raise UnknownRunnerLabel(
            f"runner label {label!r} is not in RUNNER_LABELS; add its row from "
            "GitHub's runner reference"
        ) from None


_RUNS_ON_MATRIX = re.compile(r"^\$\{\{ matrix\.([A-Za-z_][A-Za-z0-9_-]*) \}\}$")
_RUNS_ON_INPUT = re.compile(r"^\$\{\{ inputs\.([A-Za-z_][A-Za-z0-9_-]*) \}\}$")
#: ``(matrix.<axis> == '<value>' && matrix.os == '<os>') && '<label>' || matrix.os``: the
#: legs of one method on one image run on another label (the finch legs, on ubuntu-24.04).
_RUNS_ON_OVERRIDE = re.compile(
    r"^\$\{\{ \(matrix\.(?P<axis>[A-Za-z_][A-Za-z0-9_-]*) == '(?P<value>[^']+)' && "
    r"matrix\.os == '(?P<os>[^']+)'\) && '(?P<label>[^']+)' \|\| matrix\.os \}\}$"
)


def _declared_runs_on(job: Mapping[str, Any]) -> str | None:
    declared = job.get("runs-on")
    if declared is None:
        return None
    if not isinstance(declared, str):
        raise UnsupportedExpression(
            "a runs-on that is not a string", repr(declared), "runs-on"
        )
    return declared


def _input_default(workflow: Mapping[str, Any] | None, name: str, text: str) -> str:
    """The string default of the ``workflow_call`` input ``name``."""
    on = workflow.get("on") if workflow is not None else None
    call = on.get("workflow_call") if isinstance(on, Mapping) else None
    inputs = call.get("inputs") if isinstance(call, Mapping) else None
    declared = inputs.get(name) if isinstance(inputs, Mapping) else None
    default = declared.get("default") if isinstance(declared, Mapping) else None
    if not isinstance(default, str):
        raise UnsupportedExpression(
            "a runs-on input with no string default", text, "runs-on"
        )
    return default


def runs_on_labels(
    job: Mapping[str, Any], workflow: Mapping[str, Any] | None = None
) -> set[str]:
    """Every label the job's ``runs-on`` can name, whichever leg runs.

    Read: a literal label, ``${{ matrix.<key> }}``, the override shape above, and
    ``${{ inputs.<name> }}`` (the default of that ``workflow_call`` input of ``workflow``).
    A job that calls a reusable workflow names none. Anything else raises.
    """
    declared = _declared_runs_on(job)
    if declared is None:
        return set()
    if "${{" not in declared:
        return {declared}
    by_key = _RUNS_ON_MATRIX.match(declared)
    if by_key:
        return {str(value) for value in matrix_values(job, by_key.group(1))}
    override = _RUNS_ON_OVERRIDE.match(declared)
    if override:
        axis_labels = {str(value) for value in matrix_values(job, "os")}
        return axis_labels | {override.group("label")}
    from_input = _RUNS_ON_INPUT.match(declared)
    if from_input:
        return {_input_default(workflow, from_input.group(1), declared)}
    raise UnsupportedExpression("runs-on expression", declared, "runs-on")


def _leg_value(cell: Mapping[str, Any], key: str) -> str:
    if key not in cell:
        raise CiMatrixError(f"the leg has no value for matrix.{key}: {dict(cell)!r}")
    return str(cell[key])


def runs_on(
    job: Mapping[str, Any],
    cell: Mapping[str, Any],
    workflow: Mapping[str, Any] | None = None,
) -> str:
    """The label the leg ``cell`` of ``job`` runs on (the shapes runs_on_labels reads)."""
    declared = _declared_runs_on(job)
    if declared is None:
        raise CiMatrixError("the job names no runner (it calls a reusable workflow)")
    if "${{" not in declared:
        return declared
    by_key = _RUNS_ON_MATRIX.match(declared)
    if by_key:
        return _leg_value(cell, by_key.group(1))
    override = _RUNS_ON_OVERRIDE.match(declared)
    if override:
        axis_matches = cell.get(override.group("axis")) == override.group("value")
        os_matches = cell.get("os") == override.group("os")
        if axis_matches and os_matches:
            return override.group("label")
        return _leg_value(cell, "os")
    from_input = _RUNS_ON_INPUT.match(declared)
    if from_input:
        return _input_default(workflow, from_input.group(1), declared)
    raise UnsupportedExpression("runs-on expression", declared, "runs-on")


def check_runner_labels(workflow: Mapping[str, Any]) -> set[str]:
    """Fail on a runner label ``workflow`` names that RUNNER_LABELS does not list.

    Every job's runs-on labels and every value of its matrix ``os`` are checked, whether or
    not a leg runs them. Raises UnknownRunnerLabel naming each such label and its job, and
    otherwise returns the labels it checked, so a caller can see it read some.
    """
    jobs = workflow.get("jobs")
    if not isinstance(jobs, Mapping):
        raise WorkflowError("the workflow has no jobs mapping")
    checked: set[str] = set()
    unknown: list[str] = []
    for job_id, job in jobs.items():
        named = {("runs-on", label) for label in runs_on_labels(job, workflow)}
        named |= {("matrix os", str(value)) for value in matrix_values(job, "os")}
        for where, label in sorted(named):
            checked.add(label)
            if label not in RUNNER_LABELS:
                unknown.append(f"{job_id} ({where}): {label}")
    if unknown:
        raise UnknownRunnerLabel(
            "runner labels that are not in RUNNER_LABELS (add each row from GitHub's "
            "runner reference): " + "; ".join(unknown)
        )
    return checked
