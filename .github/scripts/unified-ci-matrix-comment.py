#!/usr/bin/env python3
"""Keep one comment on a pull request that shows the Unified CI matrix, cell by cell.

WHAT THE COMMENT SHOWS
----------------------
``.github/workflows/ash-unified-ci.yml`` declares the environments it tests as job
matrices. Every cell of every matrix appears in the comment, expanded the way GitHub
expands it (the axes' product, less the ``exclude`` entries, plus the ``include``
entries), and shows the result of the job the run lists under that cell's name.

Jobs whose ``name:`` templates are the same text share one table: unit-test-linux,
unit-test-macos and unit-test-windows all name their legs
``unit-test (<os>, py<python-version>, shard <shard>)``, so they are one ``unit-test``
table. A ``python-version`` axis becomes the table's columns, a ``shard`` axis is drawn
as the legs side by side inside one cell (in shard order, each linked to its job), and
every other axis is a column of its own on the left. A job without a matrix is a row of
one short table of its own.

A cell the matrix leaves out on this event is drawn as excluded, never as missing: one
icon when another trigger of the workflow runs it (the pull-request cover), another when
no trigger does. A cell that should have run and has no job once the run has finished
has its own icon too.

What each ``runs-on`` label turned out to be (its image, operating system and
architecture) is read from the first lines of one finished job's log per label, which
the runner writes about itself before any step runs. Labels the matrix uses only on
other events are listed as such, so every environment the workflow supports is on the
page.

HOW IT STAYS CURRENT
--------------------
The ``publish`` command runs as the last step of four small jobs at the end of
``ash-unified-ci.yml``. The jobs are chained by ``needs`` (checks, then scans, then
install and unit tests, then everything else), each after the jobs of its own group, so
the comment is rewritten as the run reaches each stage and a stage that is slow only
delays the updates after it. Every run of ``publish`` reads the run's whole job list, so
a job that finished between two links cannot lose a cell, and the chain lets only one
link at a time touch the comment. The last link also runs when an earlier job failed
(``!cancelled()``), reads the runner log heads, and draws the run as completed, with a
conclusion derived from the jobs it lists, since the run itself is still in progress
while the link runs. Its table is also appended to the run's job summary, on every event
and for a pull request from a fork too.

A chain, not a concurrency group, serializes the links. A job superseded in a
concurrency group is cancelled, and one cancelled job turns the whole run's conclusion
to cancelled, even over failures, which the workflow that merges Dependabot pull
requests reads. The queueing form of job concurrency is not accepted by the pinned
actionlint.

Within one run the chain orders the writes. Across runs the comment carries a second
marker line naming the run number and attempt it shows, and a link leaves the comment
alone when it names a later run than the link's own, so a re-run of an older run's
failed jobs cannot overwrite a newer run's table.

The command never fails the run: a read, a parse or a write that goes wrong prints a
warning annotation and exits 0, because a red run would read as a code failure and the
auto-merge workflow acts only on a run that succeeded.

WHAT IT TRUSTS
--------------
The jobs run with a token that can write pull-request comments, so the script comes from
the pull request's base branch, never from the pull request, and nothing from the pull
request is executed. The workflow file the matrices come from is the run's own copy,
read through the contents API at the run's workflow commit and parsed as data; a pull
request from a fork supplies its own copy of that file, so every value in it, job names
above all, is untrusted. The expression evaluator and the cap on a matrix's size
(``MAX_CELLS``) were written with that in mind. Jobs that run this command are found by
that command in their steps and left out of the table, so the table never lists its own
publisher. A job the run lists that matches no cell of the workflow (one whose name no
matrix cell produces, from a matrix this script could not expand, say) is listed under
"Other jobs", so nothing the run did is hidden. Text that came
from the run (job names, branch names, runner labels, log text) reaches the markdown only
inside code spans, with control characters, format characters and backslashes replaced,
so it cannot open a link, an image, a mention, a reference or a table cell of its own.
Every line printed to the job log goes through ``one_line``, so a value cannot start a
workflow command.

A pull request from a fork gets a read-only token whatever a job asks for, so the
comment is skipped there and the job summary carries the table. Every other refused or
failed request, a 403 included, ends in one warning annotation that names the status.

TIME BUDGET
-----------
One run of ``publish`` has ``PUBLISH_BUDGET_SECONDS`` of wall-clock time. The client
stops sleeping for a retry that would end past it, and refuses a request after it; the
settle reads and the runner-header reads stop while ``WRITE_RESERVE_SECONDS`` is still
left, so the comment step keeps the time to write. See the constants.
"""

from __future__ import annotations

import argparse
import base64
import html
import itertools
import json
import math
import os
import re
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

MARKER = "<!-- ash-unified-ci-matrix -->"
#: The author GitHub gives a comment written with the workflow's GITHUB_TOKEN. Only a
#: comment by this author that starts with MARKER is ever edited.
BOT_LOGIN = "github-actions[bot]"
#: GitHub refuses a comment body longer than this many characters.
COMMENT_LIMIT = 65536
#: The renderer drops links to keep a body under this, leaving room below the limit.
BODY_BUDGET = 60000
#: No matrix GitHub runs is larger than 256 jobs; a definition whose product passes this
#: is not expanded, so a hostile or broken file cannot make the job spin.
MAX_CELLS = 4096
#: Axes that become a table's columns, and axes drawn side by side inside one cell.
COLUMN_AXES = ("python-version",)
FOLD_AXES = ("shard",)
DEFAULT_WORKFLOW = ".github/workflows/ash-unified-ci.yml"
USER_AGENT = "ash-unified-ci-matrix-comment"
#: The second line of every body: which run and attempt the table shows. A link leaves
#: alone a comment whose line names a later run than its own.
RUN_LINE = (
    "<!-- ash-unified-ci-matrix-run: run_number={number} run_attempt={attempt} -->"
)
_RUN_LINE = re.compile(
    r"^<!-- ash-unified-ci-matrix-run: run_number=(\d+) run_attempt=(\d+) -->$",
    re.MULTILINE,
)
#: A job whose steps run this command is one of the publishing jobs, which the table
#: leaves out.
POST_COMMAND = "unified-ci-matrix-comment.py publish"
#: The only paths of the run's workflow file this script reads through the contents API.
_WORKFLOW_PATH = re.compile(r"\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml")
MAX_WORKFLOW_BYTES = 4 * 1024 * 1024
MAX_EVENT_BYTES = 16 * 1024 * 1024
#: The final link rereads the job list at most this many more times, this many seconds
#: apart, while a job still reads unfinished: only API lag, since every job has
#: concluded by the time the final link starts.
SETTLE_READS = 3
SETTLE_SECONDS = 10.0
#: The wall-clock budget of one ``publish`` run, counted from its start. A job that reaches
#: its ``timeout-minutes`` is cancelled, and one cancelled job turns the run's conclusion
#: to cancelled, so the script has to end well inside it. The arithmetic: each step of the
#: four jobs has its own ``timeout-minutes`` (checkout 1, setup-python 2, install 1,
#: publish 5; 9 minutes on the longest path, under the job's 10), so a hung step fails
#: instead of the job reaching its limit. The publish step's 300 s cover this budget, 240 s,
#: plus 60 s for requests already in flight when it runs out. The client's 30 s socket
#: timeout bounds each blocking socket operation, not a whole request; the publish step's
#: own limit is what bounds the rest. Rate-limit waits, the settle sleeps and the
#: runner-header reads all count against the budget.
PUBLISH_BUDGET_SECONDS = 240.0
#: Inside the budget, the settle sleeps and the runner-header reads stop while this much
#: is still left, so the comment step keeps the time for its two requests (the comment
#: list and the write), each of which can wait out a rate limit or a slow answer.
WRITE_RESERVE_SECONDS = 60.0
WARNING_PREFIX = "::warning title=Unified CI matrix comment::"


def one_line(text):
    text = "".join(
        " " if unicodedata.category(c) in ("Cc", "Zl", "Zp") else c for c in str(text)
    )
    while "::" in text:
        text = text.replace("::", ": :")
    while "##[" in text:
        text = text.replace("##[", "# #[")
    return text


# --------------------------------------------------------------------------------------
# GitHub's expression language, the part workflow files use in names, runs-on and
# matrices. https://docs.github.com/actions/reference/workflows-and-actions/expressions
# --------------------------------------------------------------------------------------


class ExpressionError(ValueError):
    """An expression this module cannot evaluate."""


class UnknownContext(ExpressionError):
    """An expression reads a context whose value is not known outside the run."""


#: The contexts this module supplies. GitHub also allows vars and needs in matrices and
#: names; their values are not known here, so reading one is UnknownContext.
KNOWN_CONTEXTS = ("github", "matrix", "strategy", "inputs")
UNKNOWN_CONTEXTS = ("vars", "needs", "secrets", "env", "steps", "runner", "job", "jobs")

_TOKEN = re.compile(
    r"""
    (?P<space>\s+)
    |(?P<number>0[xX][0-9a-fA-F]+|(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)
    |(?P<string>'(?:[^']|'')*')
    |(?P<op>==|!=|<=|>=|&&|\|\||[!<>()\[\].,*-])
    |(?P<name>[A-Za-z_][A-Za-z0-9_-]*)
    """,
    re.VERBOSE,
)


class _Filtered(list):
    """The result of an object filter (``x.*``); a property of it maps over the items."""


def _tokens(text: str) -> list[tuple[str, str]]:
    out = []
    pos = 0
    while pos < len(text):
        match = _TOKEN.match(text, pos)
        if match is None:
            raise ExpressionError(f"unexpected character at {pos} in {text!r}")
        pos = match.end()
        kind = match.lastgroup
        if kind != "space":
            out.append((kind, match.group()))
    return out


class _Parser:
    def __init__(self, text: str):
        self.text = text
        self.tokens = _tokens(text)
        self.index = 0

    def _peek(self, value: str | None = None) -> bool:
        if self.index >= len(self.tokens):
            return False
        return value is None or self.tokens[self.index][1] == value

    def _take(self) -> tuple[str, str]:
        if self.index >= len(self.tokens):
            raise ExpressionError(f"unexpected end of {self.text!r}")
        token = self.tokens[self.index]
        self.index += 1
        return token

    def _expect(self, value: str) -> None:
        kind, got = self._take()
        if got != value:
            raise ExpressionError(f"expected {value!r} in {self.text!r}, got {got!r}")

    def parse(self):
        node = self._or()
        if self.index != len(self.tokens):
            raise ExpressionError(
                f"unexpected {self.tokens[self.index][1]!r} in {self.text!r}"
            )
        return node

    def _or(self):
        node = self._and()
        while self._peek("||"):
            self._take()
            node = ("or", node, self._and())
        return node

    def _and(self):
        node = self._equality()
        while self._peek("&&"):
            self._take()
            node = ("and", node, self._equality())
        return node

    def _equality(self):
        node = self._comparison()
        while self._peek("==") or self._peek("!="):
            op = self._take()[1]
            node = ("cmp", op, node, self._comparison())
        return node

    def _comparison(self):
        node = self._unary()
        while any(self._peek(op) for op in ("<", "<=", ">", ">=")):
            op = self._take()[1]
            node = ("cmp", op, node, self._unary())
        return node

    def _unary(self):
        if self._peek("!"):
            self._take()
            return ("not", self._unary())
        if self._peek("-"):
            self._take()
            kind, value = self._take()
            if kind != "number":
                raise ExpressionError(
                    f"'-' is only a sign of a number in {self.text!r}"
                )
            return ("lit", -_number_literal(value))
        return self._postfix()

    def _postfix(self):
        node = self._primary()
        while True:
            if self._peek("."):
                self._take()
                if self._peek("*"):
                    self._take()
                    node = ("star", node)
                    continue
                kind, value = self._take()
                if kind != "name":
                    raise ExpressionError(f"expected a property name in {self.text!r}")
                node = ("prop", node, value)
            elif self._peek("["):
                self._take()
                if self._peek("*"):
                    self._take()
                    self._expect("]")
                    node = ("star", node)
                    continue
                index = self._or()
                self._expect("]")
                node = ("index", node, index)
            else:
                return node

    def _primary(self):
        kind, value = self._take()
        if kind == "number":
            return ("lit", _number_literal(value))
        if kind == "string":
            return ("lit", value[1:-1].replace("''", "'"))
        if kind == "op" and value == "(":
            node = self._or()
            self._expect(")")
            return node
        if kind == "name":
            lowered = value.lower()
            if lowered == "true":
                return ("lit", True)
            if lowered == "false":
                return ("lit", False)
            if lowered == "null":
                return ("lit", None)
            if self._peek("("):
                self._take()
                args = []
                if not self._peek(")"):
                    args.append(self._or())
                    while self._peek(","):
                        self._take()
                        args.append(self._or())
                self._expect(")")
                return ("call", lowered, args)
            return ("ctx", lowered)
        raise ExpressionError(f"unexpected {value!r} in {self.text!r}")


def _number_literal(text: str) -> float | int:
    if text[:2].lower() == "0x":
        return int(text, 16)
    number = float(text)
    return (
        int(number)
        if number.is_integer() and "." not in text and "e" not in text.lower()
        else number
    )


def _kind(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    return "object"


def truthy(value: Any) -> bool:
    """GitHub's falsy values: false, 0, -0, '', null and NaN."""
    if value is None or value is False:
        return False
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return not (value == 0 or math.isnan(value))
    if isinstance(value, str):
        return value != ""
    return True


def _to_number(value: Any) -> float:
    if value is None:
        return 0.0
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return 0.0
        try:
            return float(int(text, 16)) if text[:2].lower() == "0x" else float(text)
        except ValueError:
            return math.nan
    return math.nan


def _equal(left: Any, right: Any) -> bool:
    """GitHub's loose equality: strings ignore case, other mixed kinds compare as numbers."""
    kind = _kind(left)
    if kind == _kind(right):
        if kind == "string":
            return left.casefold() == right.casefold()
        if kind in ("array", "object"):
            return left is right
        return left == right
    if "array" in (kind, _kind(right)) or "object" in (kind, _kind(right)):
        return False
    return _to_number(left) == _to_number(right)


def _compare(op: str, left: Any, right: Any) -> bool:
    if op == "==":
        return _equal(left, right)
    if op == "!=":
        return not _equal(left, right)
    if isinstance(left, str) and isinstance(right, str):
        a, b = left.casefold(), right.casefold()
    else:
        a, b = _to_number(left), _to_number(right)
        if math.isnan(a) or math.isnan(b):
            return False
    return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]


def to_string(value: Any) -> str:
    """How GitHub writes a value into a string (a name, a label, a format argument)."""
    if value is None:
        return ""
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if math.isnan(value):
            return "NaN"
        if math.isinf(value):
            return "Infinity" if value > 0 else "-Infinity"
        return str(int(value)) if value.is_integer() else repr(value)
    if isinstance(value, str):
        return value
    return "Array" if isinstance(value, list) else "Object"


def _format(template: Any, *args: Any) -> str:
    text = to_string(template)
    out = []
    i = 0
    while i < len(text):
        char = text[i]
        if char == "{":
            if text.startswith("{{", i):
                out.append("{")
                i += 2
                continue
            end = text.find("}", i)
            index = text[i + 1 : end] if end > 0 else ""
            if not index.isdigit() or int(index) >= len(args):
                raise ExpressionError(
                    f"format() cannot fill {text!r} from {len(args)} arguments"
                )
            out.append(to_string(args[int(index)]))
            i = end + 1
        elif char == "}":
            if not text.startswith("}}", i):
                raise ExpressionError(f"format() has an unmatched '}}' in {text!r}")
            out.append("}")
            i += 2
        else:
            out.append(char)
            i += 1
    return "".join(out)


def _contains(search: Any, item: Any) -> bool:
    if isinstance(search, list):
        return any(_equal(element, item) for element in search)
    return to_string(item).casefold() in to_string(search).casefold()


def _from_json(text: Any) -> Any:
    try:
        return json.loads(to_string(text))
    except ValueError as err:
        raise ExpressionError(f"fromJSON() could not read {text!r}") from err


_FUNCTIONS: dict[str, Callable[..., Any]] = {
    "format": _format,
    "startswith": lambda s, p: (
        to_string(s).casefold().startswith(to_string(p).casefold())
    ),
    "endswith": lambda s, p: to_string(s).casefold().endswith(to_string(p).casefold()),
    "contains": _contains,
    "join": lambda items, sep=",": (
        to_string(sep).join(to_string(i) for i in items)
        if isinstance(items, list)
        else to_string(items)
    ),
    "tojson": lambda value: json.dumps(value, indent=2),
    "fromjson": _from_json,
}


def _lookup(container: Any, key: Any) -> Any:
    if isinstance(container, _Filtered):
        return _Filtered(_lookup(item, key) for item in container)
    if isinstance(container, dict):
        if isinstance(key, str):
            folded = key.casefold()
            for name, value in container.items():
                if isinstance(name, str) and name.casefold() == folded:
                    return value
        return None
    if (
        isinstance(container, list)
        and isinstance(key, (int, float))
        and not isinstance(key, bool)
    ):
        index = int(key)
        return container[index] if 0 <= index < len(container) else None
    return None


def _evaluate_node(node, contexts: dict[str, Any]) -> Any:
    kind = node[0]
    if kind == "lit":
        return node[1]
    if kind == "ctx":
        name = node[1]
        if name in contexts:
            return contexts[name]
        if name in UNKNOWN_CONTEXTS or name not in KNOWN_CONTEXTS:
            raise UnknownContext(f"the {name} context is not known outside the run")
        return None
    if kind == "prop":
        return _lookup(_evaluate_node(node[1], contexts), node[2])
    if kind == "index":
        return _lookup(
            _evaluate_node(node[1], contexts), _evaluate_node(node[2], contexts)
        )
    if kind == "star":
        value = _evaluate_node(node[1], contexts)
        if isinstance(value, dict):
            return _Filtered(value.values())
        if isinstance(value, list):
            return _Filtered(value)
        return _Filtered()
    if kind == "not":
        return not truthy(_evaluate_node(node[1], contexts))
    if kind == "and":
        left = _evaluate_node(node[1], contexts)
        return _evaluate_node(node[2], contexts) if truthy(left) else left
    if kind == "or":
        left = _evaluate_node(node[1], contexts)
        return left if truthy(left) else _evaluate_node(node[2], contexts)
    if kind == "cmp":
        return _compare(
            node[1],
            _evaluate_node(node[2], contexts),
            _evaluate_node(node[3], contexts),
        )
    if kind == "call":
        function = _FUNCTIONS.get(node[1])
        if function is None:
            raise ExpressionError(f"{node[1]}() is not available outside the run")
        args = [_evaluate_node(arg, contexts) for arg in node[2]]
        try:
            return function(*args)
        except TypeError as err:
            raise ExpressionError(
                f"{node[1]}() was given {len(args)} arguments"
            ) from err
    raise ExpressionError(f"unknown node {kind}")


def evaluate(expression: str, contexts: dict[str, Any]) -> Any:
    """The value of one expression, without its ``${{ }}``."""
    return _evaluate_node(_Parser(expression).parse(), contexts)


def split_template(text: str) -> list[tuple[str, str]]:
    """``text`` as ("text", ...) and ("expr", ...) parts; quotes may contain ``}}``."""
    parts = []
    pos = 0
    while True:
        start = text.find("${{", pos)
        if start < 0:
            if pos < len(text):
                parts.append(("text", text[pos:]))
            return parts
        if start > pos:
            parts.append(("text", text[pos:start]))
        i = start + 3
        quoted = False
        while i < len(text):
            if text[i] == "'":
                quoted = not quoted
            elif not quoted and text.startswith("}}", i):
                break
            i += 1
        else:
            raise ExpressionError(f"an unclosed ${{{{ in {text!r}")
        parts.append(("expr", text[start + 3 : i].strip()))
        pos = i + 2


def evaluate_value(value: Any, contexts: dict[str, Any]) -> Any:
    """A workflow value with its expressions evaluated.

    A string that is exactly one ``${{ }}`` keeps the expression's type, as GitHub does
    for a matrix axis or an exclude value; a string that mixes text and expressions is
    interpolated into a string. Mappings and lists are evaluated item by item.
    """
    if isinstance(value, str):
        parts = split_template(value)
        if not any(kind == "expr" for kind, _ in parts):
            return value
        if len(parts) == 1:
            return evaluate(parts[0][1], contexts)
        return "".join(
            to_string(evaluate(text, contexts)) if kind == "expr" else text
            for kind, text in parts
        )
    if isinstance(value, list):
        return [evaluate_value(item, contexts) for item in value]
    if isinstance(value, dict):
        return {key: evaluate_value(item, contexts) for key, item in value.items()}
    return value


# --------------------------------------------------------------------------------------
# Matrix expansion, after
# https://docs.github.com/actions/how-tos/write-workflows/choose-what-workflows-do/run-job-variations
# --------------------------------------------------------------------------------------


def _same(left: Any, right: Any) -> bool:
    if isinstance(left, bool) or isinstance(right, bool):
        return left is right
    return left == right


def _entries(value: Any, what: str) -> list[dict]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(
        isinstance(entry, dict) for entry in value
    ):
        raise ExpressionError(f"the matrix {what} is not a list of mappings")
    return value


@dataclass
class Expansion:
    """One matrix expanded for one event."""

    axes: list[str]
    #: (values, excluded) in the order a reader expects: the product, then includes.
    display: list[tuple[dict, bool]]
    #: The combinations GitHub runs, in the order it creates their jobs.
    active: list[dict]


def expand_matrix(matrix: Any, contexts: dict[str, Any]) -> Expansion:
    matrix = evaluate_value(matrix, contexts)
    if not isinstance(matrix, dict):
        raise ExpressionError("the matrix is not a mapping")
    axes = [key for key in matrix if key not in ("include", "exclude")]
    lists = []
    size = 1
    for axis in axes:
        values = matrix[axis]
        if not isinstance(values, list):
            raise ExpressionError(f"the matrix axis {axis} is not a list")
        lists.append(values)
        size *= len(values)
        if size > MAX_CELLS:
            raise ExpressionError(f"the matrix has more than {MAX_CELLS} combinations")
    product = (
        [dict(zip(axes, combo)) for combo in itertools.product(*lists)] if axes else []
    )
    excludes = _entries(matrix.get("exclude"), "exclude")
    includes = _entries(matrix.get("include"), "include")
    if len(includes) > MAX_CELLS:
        raise ExpressionError(f"the matrix has more than {MAX_CELLS} include entries")
    excluded = [
        any(
            all(k in combo and _same(combo[k], v) for k, v in entry.items())
            for entry in excludes
        )
        for combo in product
    ]
    active = [dict(combo) for combo, out in zip(product, excluded) if not out]
    axis_set = set(axes)
    appended: list[dict] = []
    for entry in includes:
        merged = False
        for combo in active:
            if all(_same(combo[k], v) for k, v in entry.items() if k in axis_set):
                combo.update({k: v for k, v in entry.items() if k not in axis_set})
                merged = True
        if not merged:
            appended.append(dict(entry))
    display: list[tuple[dict, bool]] = []
    remaining = iter(active)
    for combo, out in zip(product, excluded):
        display.append((dict(combo), True) if out else (next(remaining), False))
    for entry in appended:
        if axes and all(axis in entry for axis in axes):
            display = [
                (values, out)
                for values, out in display
                if not (out and all(_same(values[a], entry[a]) for a in axes))
            ]
        display.append((entry, False))
    return Expansion(axes=axes, display=display, active=active + appended)


# --------------------------------------------------------------------------------------
# The model: the workflow's jobs as groups of cells.
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class State:
    key: str
    icon: str
    label: str


PASSED = State("passed", "✅", "passed")
FAILED = State("failed", "❌", "failed")
TIMED_OUT = State("timed_out", "⏱️", "timed out")
CANCELLED = State("cancelled", "⏹️", "cancelled")
SKIPPED = State("skipped", "⏭️", "skipped")
OTHER = State("other", "⚠️", "another conclusion")
RUNNING = State("running", "⏳", "running")
PENDING = State("pending", "🕒", "pending")
NOT_IN_RUN = State("not_in_run", "❔", "not in this run")
EXCLUDED_HERE = State("excluded_here", "➖", "excluded on this event")
EXCLUDED_ALWAYS = State("excluded_always", "⛔", "excluded on every trigger")
#: Summary order: what needs attention first.
STATES = (
    FAILED,
    TIMED_OUT,
    CANCELLED,
    OTHER,
    NOT_IN_RUN,
    RUNNING,
    PENDING,
    PASSED,
    SKIPPED,
    EXCLUDED_HERE,
    EXCLUDED_ALWAYS,
)
PROBLEM_STATES = (FAILED, TIMED_OUT, CANCELLED, OTHER, NOT_IN_RUN)
_CONCLUSIONS = {
    "success": PASSED,
    "failure": FAILED,
    "cancelled": CANCELLED,
    "skipped": SKIPPED,
    "timed_out": TIMED_OUT,
}


def job_state(job: dict) -> State:
    status = job.get("status")
    if status == "completed":
        return _CONCLUSIONS.get(job.get("conclusion"), OTHER)
    if status == "in_progress":
        return RUNNING
    return PENDING


@dataclass
class Cell:
    id: int
    job_id: str
    values: dict[str, Any]
    #: The job name GitHub gives this cell; None when it could not be evaluated here.
    name: str | None
    runs_on: str | None
    excluded: State | None = None
    #: For a cell excluded on this event: the other triggers whose expansion runs it.
    runs_on_events: tuple[str, ...] = ()


@dataclass
class Group:
    title: str
    job_ids: list[str]
    has_matrix: bool
    dims: list[str] = field(default_factory=list)
    cells: list[Cell] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)


@dataclass
class Model:
    path: str
    event: str
    other_events: tuple[str, ...]
    groups: list[Group]
    #: The name a matrix job carries when GitHub never expands its matrix (a job-level
    #: ``if`` that is false lists the job once, under its raw ``name:`` template), to
    #: the jobs that share that template, in workflow order.
    aliases: dict[str, list[str]]

    def cells(self) -> list[Cell]:
        return [cell for group in self.groups for cell in group.cells]


def triggers(workflow: dict) -> list[str]:
    """The events in a workflow's ``on:``; PyYAML reads the bare key as True."""
    on = workflow.get("on", workflow.get(True))
    if isinstance(on, str):
        return [on]
    if isinstance(on, list):
        return [str(event) for event in on]
    if isinstance(on, dict):
        return [str(event) for event in on]
    return []


def github_context(
    event: str, *, repository: str, default_branch: str, pull: dict | None = None
) -> dict:
    """What github.* reads as for a run of ``event``, as far as it is known here.

    Only the pull-request run's values are real. The other events' refs are the ones
    GitHub would give a run on the default branch; they decide nothing in this
    workflow, whose exclusions read github.event_name only.
    """
    context = {
        "event_name": event,
        "repository": repository,
        "repository_owner": repository.split("/")[0],
        "ref": f"refs/heads/{default_branch}",
        "ref_name": default_branch,
        "base_ref": "",
        "head_ref": "",
        "event": {},
    }
    if event in ("pull_request", "pull_request_target") and pull:
        number = pull.get("number")
        context["ref"] = f"refs/pull/{number}/merge"
        context["ref_name"] = f"{number}/merge"
        context["base_ref"] = str((pull.get("base") or {}).get("ref") or "")
        context["head_ref"] = str((pull.get("head") or {}).get("ref") or "")
    return context


def _title(template: str | None, job_id: str) -> str:
    """The name template with each expression shown as an ellipsis, or the job id.

    ``unit-test (…, py…, shard …)`` and ``integration-test (ubuntu-latest, shard …)``
    stay apart that way, where cutting at the first parenthesis would give two tables
    the one title. A template that opens with an expression says nothing by itself, so
    its job id names the table.
    """
    if not template or template.lstrip().startswith("${{"):
        return job_id
    try:
        parts = split_template(template)
    except ExpressionError:
        return job_id
    text = "".join("…" if kind == "expr" else part for kind, part in parts)
    text = re.sub("…+", "…", text).strip()
    return text or job_id


def _runs_on(job: dict, contexts: dict) -> str | None:
    value = evaluate_value(job.get("runs-on"), contexts)
    if isinstance(value, dict):
        labels = value.get("labels")
        value = labels if labels is not None else value.get("group")
    if isinstance(value, list):
        return ", ".join(to_string(item) for item in value)
    return None if value is None else to_string(value)


def _job_name(
    job_id: str, job: dict, values: dict, contexts: dict, has_matrix: bool
) -> str:
    template = job.get("name")
    if template is None:
        if not has_matrix:
            return job_id
        return f"{job_id} ({', '.join(to_string(v) for v in values.values())})"
    return to_string(evaluate_value(str(template), contexts))


def build_model(
    workflow: dict, *, path: str, event: str, contexts_for: Callable[[str], dict]
) -> Model:
    """Group the workflow's jobs and expand every matrix for ``event``.

    ``contexts_for(event)`` gives the github context of a run of that event; the
    workflow's other triggers are expanded too, to tell a cell left out on this event
    only from one no trigger runs.
    """
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict):
        raise ValueError(f"{path} has no jobs mapping")
    other_events = tuple(e for e in triggers(workflow) if e != event)
    groups: list[Group] = []
    by_key: dict[tuple, Group] = {}
    aliases: dict[str, list[str]] = {}
    next_id = itertools.count()
    for job_id, job in jobs.items():
        job_id = str(job_id)
        if not isinstance(job, dict):
            continue
        template = job.get("name") if isinstance(job.get("name"), str) else None
        strategy = job.get("strategy") if isinstance(job.get("strategy"), dict) else {}
        matrix = strategy.get("matrix")
        has_matrix = matrix is not None
        key = ("name", template) if template and "${{" in template else ("job", job_id)
        group = by_key.get(key)
        if group is None or group.has_matrix != has_matrix:
            group = Group(
                title=_title(template, job_id), job_ids=[], has_matrix=has_matrix
            )
            by_key[key] = group
            groups.append(group)
        group.job_ids.append(job_id)
        base = {
            "github": contexts_for(event),
            "inputs": {},
            "matrix": {},
            "strategy": {},
        }
        if not has_matrix:
            try:
                name = _job_name(job_id, job, {}, base, False)
                runs_on = _runs_on(job, base)
            except ExpressionError as err:
                group.problems.append(f"{job_id}: {err}")
                name, runs_on = None, None
            group.cells.append(Cell(next(next_id), job_id, {}, name, runs_on))
            continue
        aliases.setdefault(template if template is not None else job_id, []).append(
            job_id
        )
        try:
            expansion = expand_matrix(matrix, base)
        except ExpressionError as err:
            group.problems.append(
                f"the matrix of {job_id} is not known until the run: {err}"
            )
            continue
        elsewhere: dict[str, list[dict]] = {}
        for other in other_events:
            try:
                other_base = {**base, "github": contexts_for(other)}
                elsewhere[other] = expand_matrix(matrix, other_base).active
            except ExpressionError:
                continue
        total = len(expansion.active)
        active_index = {id(values): i for i, values in enumerate(expansion.active)}
        for values, out in expansion.display:
            strategy_context = {
                "fail-fast": strategy.get("fail-fast", True),
                "max-parallel": strategy.get("max-parallel", total),
                "job-total": total,
                "job-index": active_index.get(id(values)),
            }
            contexts = {**base, "matrix": values, "strategy": strategy_context}
            try:
                name = _job_name(job_id, job, values, contexts, True)
                runs_on = _runs_on(job, contexts)
            except ExpressionError as err:
                if not group.problems:
                    group.problems.append(f"{job_id}: {err}")
                name, runs_on = None, None
            state = None
            runs_elsewhere: tuple[str, ...] = ()
            if out:
                runs_elsewhere = tuple(
                    other
                    for other, combos in elsewhere.items()
                    if any(
                        all(
                            a in combo and _same(combo[a], values[a])
                            for a in expansion.axes
                        )
                        for combo in combos
                    )
                )
                state = EXCLUDED_HERE if runs_elsewhere else EXCLUDED_ALWAYS
            group.cells.append(
                Cell(
                    next(next_id), job_id, values, name, runs_on, state, runs_elsewhere
                )
            )
            for key_name in values:
                if key_name not in group.dims:
                    group.dims.append(key_name)
    return Model(
        path=path,
        event=event,
        other_events=other_events,
        groups=groups,
        aliases=aliases,
    )


# --------------------------------------------------------------------------------------
# A run's jobs placed on the model's cells.
# --------------------------------------------------------------------------------------


@dataclass
class Placement:
    #: cell id -> the job that ran for it
    jobs: dict[int, dict]
    #: cell ids whose job is the one unexpanded entry of a matrix GitHub never expanded
    collapsed: set[int]
    #: jobs that match no cell
    others: list[dict]
    run_completed: bool

    def state(self, cell: Cell) -> State:
        job = self.jobs.get(cell.id)
        if job is not None:
            return job_state(job)
        if cell.excluded is not None:
            return cell.excluded
        return NOT_IN_RUN if self.run_completed else PENDING


def place_jobs(model: Model, jobs: list[dict], *, run_completed: bool) -> Placement:
    by_name: dict[str, list[dict]] = {}
    for job in sorted(jobs, key=lambda j: j.get("id") or 0):
        by_name.setdefault(str(job.get("name")), []).append(job)
    used: set[int] = set()
    placed: dict[int, dict] = {}
    for cell in model.cells():
        if cell.name is None:
            continue
        for job in by_name.get(cell.name, ()):
            if id(job) not in used:
                used.add(id(job))
                placed[cell.id] = job
                break
    collapsed: set[int] = set()
    for name, job_ids in model.aliases.items():
        waiting = list(job_ids)
        for job in by_name.get(name, ()):
            if id(job) in used:
                continue
            # GitHub lists unexpanded jobs in workflow order, so the n-th job under a
            # shared template is the n-th workflow job with nothing placed yet.
            while waiting:
                job_id = waiting.pop(0)
                targets = [
                    cell
                    for cell in model.cells()
                    if cell.job_id == job_id
                    and cell.excluded is None
                    and cell.id not in placed
                ]
                if targets:
                    used.add(id(job))
                    for cell in targets:
                        placed[cell.id] = job
                        collapsed.add(cell.id)
                    break
    others = [
        job
        for job in sorted(jobs, key=lambda j: j.get("id") or 0)
        if id(job) not in used
    ]
    return Placement(
        jobs=placed, collapsed=collapsed, others=others, run_completed=run_completed
    )


# --------------------------------------------------------------------------------------
# What a runner says about itself in the first lines of a job's log.
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class RunnerFacts:
    image: str | None
    version: str | None
    os: str | None
    arch: str | None


_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_STAMP = re.compile(r"^\ufeff?\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z ?")
_FACT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()+/-]{0,79}$")
#: The header the runner writes comes first; nothing after this many lines is read,
#: so a step's output cannot stand in for it.
HEADER_LINES = 40


def _fact(text: str) -> str | None:
    text = " ".join(text.split())
    return text if _FACT.match(text) else None


def _log_group(lines: list[str], title: str) -> list[str] | None:
    marker = "##[group]" + title
    for index, line in enumerate(lines):
        if line.startswith("##[group]Run "):
            return None
        if line == marker:
            body = []
            for following in lines[index + 1 :]:
                if following.startswith("##[endgroup]"):
                    return body
                body.append(following)
            return None
    return None


def parse_runner_header(raw: bytes) -> RunnerFacts | None:
    """The image, its version, the operating system and the architecture, or None.

    The architecture is read off the image name, which names arm64 for every Arm image
    GitHub hosts (ubuntu-24.04-arm, macos-15-arm64, windows-11-arm) and nothing for an
    x64 one. A runner that writes no image (a self-hosted one) gives no architecture.
    """
    text = raw.decode("utf-8", "replace")
    lines = [
        _STAMP.sub("", _ANSI.sub("", line)).strip()
        for line in text.splitlines()[:HEADER_LINES]
    ]
    system = _log_group(lines, "Operating System")
    image_lines = _log_group(lines, "Runner Image") or []
    image = version = None
    for line in image_lines:
        if line.startswith("Image:"):
            image = _fact(line[len("Image:") :])
        elif line.startswith("Version:"):
            version = _fact(line[len("Version:") :])
    os_name = _fact(" ".join(system)) if system else None
    if image is None and os_name is None:
        return None
    arch = None
    if image is not None:
        arch = "arm64" if "arm" in image.lower() else "x64"
    return RunnerFacts(image=image, version=version, os=os_name, arch=arch)


def label_of(job: dict) -> str:
    return ", ".join(to_string(label) for label in job.get("labels") or [])


# --------------------------------------------------------------------------------------
# Markdown. Every value that came from the workflow or the run goes through code().
# --------------------------------------------------------------------------------------


def _plain(value: Any, limit: int = 100) -> str:
    """``value`` as one line with nothing that could act as markup outside the text.

    Control and line characters become spaces and format characters (bidirectional
    overrides, zero-width marks) are dropped, so a value cannot add a line, reorder what
    a reader sees or hide characters. A backslash becomes U+2216, because a backslash
    before the pipe escape below would turn the escape back into a cell boundary.
    """
    text = value if isinstance(value, str) else to_string(value)
    out = []
    for char in text:
        category = unicodedata.category(char)
        if char == "\\":
            out.append("\u2216")
        elif category in ("Cc", "Zl", "Zp"):
            out.append(" ")
        elif category in ("Cf", "Cs", "Co", "Cn"):
            continue
        else:
            out.append(char)
    text = " ".join("".join(out).split())
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return text


def code(value: Any, *, table: bool = True, limit: int = 100) -> str:
    """``value`` as an inline code span: GitHub reads no markup, mention or link in one.

    The fence is one backtick longer than the longest run of backticks in the value, so
    the value cannot close it. Inside a table a pipe is escaped, which GitHub honors
    inside a code span too. An empty value is an en dash.
    """
    text = _plain(value, limit)
    if not text:
        return "\u2013"
    fence = "`" * (max((len(run) for run in re.findall(r"`+", text)), default=0) + 1)
    if text.startswith("`") or text.endswith("`"):
        text = f" {text} "
    if table:
        text = text.replace("|", "\\|")
    return f"{fence}{text}{fence}"


def html_code(value: Any, limit: int = 100) -> str:
    """``value`` inside ``<code>`` for an HTML context such as ``<summary>``."""
    return f"<code>{html.escape(_plain(value, limit), quote=True)}</code>"


_JOB_URL = re.compile(
    r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/runs/\d+/job/\d+$"
)
_RUN_URL = re.compile(
    r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/runs/\d+$"
)
_TITLE_UNSAFE = re.compile(r'["\\<>]')


def _icon(state: State, job: dict | None, title: str, with_link: bool) -> str:
    """The state's icon, linked to its job when asked, with ``title`` as the hover text.

    ``title`` is built from the workflow's own values, never from the run. It is a table
    cell's text too, so a pipe in it is escaped like any other.
    """
    url = (job or {}).get("html_url")
    if with_link and isinstance(url, str) and _JOB_URL.match(url):
        hover = _TITLE_UNSAFE.sub("", _plain(f"{title}: {state.label}", 120)).replace(
            "|", "\\|"
        )
        return f'[{state.icon}]({url} "{hover}")'
    return state.icon


def _counts(states: list[State]) -> str:
    parts = []
    for state in STATES:
        n = sum(1 for s in states if s is state)
        if n:
            parts.append(f"{state.icon} {n}")
    return " · ".join(parts)


def _counts_words(states: list[State]) -> str:
    parts = []
    for state in STATES:
        n = sum(1 for s in states if s is state)
        if n:
            parts.append(f"{state.icon} {n} {state.label}")
    return " · ".join(parts)


class _Missing:
    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "MISSING"


MISSING = _Missing()


def _value_key(value: Any) -> str:
    return (
        "\x00missing"
        if value is MISSING
        else json.dumps(value, sort_keys=True, default=str)
    )


def _show(value: Any) -> str:
    return "\u2013" if value is MISSING else code(to_string(value))


def _runs_on_column(group: Group) -> bool:
    if "os" not in group.dims:
        return any(cell.runs_on for cell in group.cells)
    return any(
        cell.runs_on is not None and cell.runs_on != to_string(cell.values.get("os"))
        for cell in group.cells
    )


def _link_wanted(mode: str, state: State) -> bool:
    return mode == "all" or (
        mode == "problems" and state in PROBLEM_STATES + (RUNNING,)
    )


def _group_section(group: Group, placement: Placement, mode: str) -> list[str]:
    cells = group.cells
    states = [placement.state(cell) for cell in cells]
    column = next((axis for axis in COLUMN_AXES if axis in group.dims), None)
    fold = next((axis for axis in FOLD_AXES if axis in group.dims), None)
    rows_axes = [axis for axis in group.dims if axis not in (column, fold)]
    with_runs_on = _runs_on_column(group)
    column_values: list[Any] = []
    if column is not None:
        seen = set()
        for cell in cells:
            value = cell.values.get(column, MISSING)
            if _value_key(value) not in seen:
                seen.add(_value_key(value))
                column_values.append(value)
    fold_order: list[Any] = []
    if fold is not None:
        seen = set()
        for cell in cells:
            value = cell.values.get(fold, MISSING)
            if _value_key(value) not in seen:
                seen.add(_value_key(value))
                fold_order.append(value)
    fold_rank = {_value_key(v): i for i, v in enumerate(fold_order)}
    rows: dict[tuple, dict[str, list[tuple[Cell, State]]]] = {}
    row_values: dict[tuple, tuple] = {}
    for cell, state in zip(cells, states):
        values = tuple(cell.values.get(axis, MISSING) for axis in rows_axes)
        key = tuple(_value_key(v) for v in values) + (
            (cell.runs_on or "",) if with_runs_on else ()
        )
        row_values.setdefault(key, values + ((cell.runs_on,) if with_runs_on else ()))
        bucket = _value_key(cell.values.get(column, MISSING)) if column else ""
        rows.setdefault(key, {}).setdefault(bucket, []).append((cell, state))

    open_attr = " open" if any(s in PROBLEM_STATES for s in states) else ""
    jobs_text = ", ".join(code(job_id, table=False) for job_id in group.job_ids)
    summary = (
        f"<details{open_attr}><summary><b>{html_code(group.title)}</b> · "
        f"{len(cells)} cells · {_counts(states)}</summary>"
    )
    lines = [summary, ""]
    layout = [f"{'Jobs' if len(group.job_ids) > 1 else 'Job'} {jobs_text}."]
    if rows_axes:
        layout.append(
            "Rows: " + ", ".join(code(a, table=False) for a in rows_axes) + "."
        )
    if column is not None:
        layout.append(f"Columns: {code(column, table=False)}.")
    if fold is not None:
        layout.append(
            f"Each cell holds the {code(fold, table=False)} legs in order: "
            + " ".join(_show(v) for v in fold_order)
            + "."
        )
    lines.append(" ".join(layout))
    for problem in group.problems:
        lines.append("")
        lines.append(f"⚠️ {code(problem, table=False, limit=200)}")
    lines.append("")
    if not cells:
        lines.extend(
            ["No cells could be derived from this matrix here.", "", "</details>", ""]
        )
        return lines
    headers = [code(axis) for axis in rows_axes]
    if with_runs_on:
        headers.append(code("runs-on"))
    if not headers:
        headers.append("job")
    if column is not None:
        headers.extend(_show(v) for v in column_values)
    else:
        headers.append("result")
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("|" + " --- |" * len(headers))
    buckets = [_value_key(v) for v in column_values] if column is not None else [""]
    for key, bucket_map in rows.items():
        values = row_values[key]
        if rows_axes or with_runs_on:
            row = [_show(v) for v in values[: len(rows_axes)]]
            if with_runs_on:
                row.append(code(values[-1] or ""))
        else:
            row = [", ".join(code(job_id) for job_id in group.job_ids)]
        for bucket in buckets:
            entries = sorted(
                bucket_map.get(bucket, []),
                key=lambda e: (
                    fold_rank.get(_value_key(e[0].values.get(fold, MISSING)), 0)
                    if fold
                    else 0
                ),
            )
            icons = []
            for cell, state in entries:
                job = placement.jobs.get(cell.id)
                title = ", ".join(
                    f"{axis} {to_string(cell.values[axis])}"
                    for axis in (fold, column)
                    if axis and axis in cell.values
                ) or (cell.name or cell.job_id)
                icons.append(_icon(state, job, title, _link_wanted(mode, state)))
            row.append("".join(icons) if icons else " ")
        lines.append("| " + " | ".join(row) + " |")
    lines.extend(["", "</details>", ""])
    return lines


def _single_jobs_section(
    groups: list[Group], placement: Placement, mode: str
) -> list[str]:
    cells = [cell for group in groups for cell in group.cells]
    if not cells:
        return []
    states = [placement.state(cell) for cell in cells]
    open_attr = " open" if any(s in PROBLEM_STATES for s in states) else ""
    summary = (
        f"<details{open_attr}><summary><b>Jobs without a matrix</b> · "
        f"{len(cells)} jobs · {_counts(states)}</summary>"
    )
    lines = [
        summary,
        "",
        f"| job | {code('runs-on')} | result |",
        "| --- | --- | --- |",
    ]
    for cell, state in zip(cells, states):
        job = placement.jobs.get(cell.id)
        icon = _icon(state, job, cell.name or cell.job_id, _link_wanted(mode, state))
        lines.append(
            f"| {code(cell.name or cell.job_id)} | {code(cell.runs_on or '')} | {icon} {state.label} |"
        )
    lines.extend(["", "</details>", ""])
    return lines


def _environments_section(
    model: Model, placement: Placement, jobs: list[dict], facts: dict[str, RunnerFacts]
) -> list[str]:
    used: dict[str, int] = {}
    for job in jobs:
        label = label_of(job)
        if label:
            used[label] = used.get(label, 0) + 1
    declared: dict[str, bool] = {}
    for cell in model.cells():
        if cell.runs_on:
            runs_here = cell.excluded is None
            declared[cell.runs_on] = declared.get(cell.runs_on, False) or runs_here
    labels = list(dict.fromkeys([*declared, *used]))
    if not labels:
        return []
    lines = [
        f"<details><summary><b>Runner environments</b> · {len(labels)} labels</summary>",
        "",
        "What each label ran as, from the header one finished job's log opens with.",
        "",
        f"| {code('runs-on')} | image | operating system | arch | jobs |",
        "| --- | --- | --- | --- | --- |",
    ]
    for label in labels:
        known = facts.get(label)
        count = used.get(label, 0)
        if count:
            jobs_text = str(count)
        elif declared.get(label) is False:
            jobs_text = "0, excluded on this event"
        else:
            jobs_text = "0 so far"
        if known is None:
            image = system = arch = "\u2013"
        else:
            image = (
                " ".join(code(v) for v in (known.image, known.version) if v) or "\u2013"
            )
            system = code(known.os or "")
            arch = code(known.arch or "")
        lines.append(f"| {code(label)} | {image} | {system} | {arch} | {jobs_text} |")
    lines.extend(["", "</details>", ""])
    return lines


def _others_section(placement: Placement, mode: str) -> list[str]:
    if not placement.others:
        return []
    states = [job_state(job) for job in placement.others]
    summary = (
        f"<details open><summary><b>Other jobs in this run</b> · {len(placement.others)} "
        f"· {_counts(states)}</summary>"
    )
    note = (
        "Jobs that match no cell of the workflow's matrices, such as one from a matrix "
        "this script could not expand."
    )
    lines = [
        summary,
        "",
        note,
        "",
        f"| job | {code('runs-on')} | result |",
        "| --- | --- | --- |",
    ]
    for job, state in zip(placement.others, states):
        # The name is the run's, so it stays in its code span and out of the hover text.
        icon = _icon(state, job, "this job", _link_wanted(mode, state))
        lines.append(
            f"| {code(job.get('name') or '')} | {code(label_of(job))} | {icon} {state.label} |"
        )
    lines.extend(["", "</details>", ""])
    return lines


def _legend(model: Model, source: str) -> list[str]:
    elsewhere = sorted(
        {
            e
            for cell in model.cells()
            if cell.excluded is EXCLUDED_HERE
            for e in cell.runs_on_events
        }
    )
    here = code(model.event, table=False)
    runs = ", ".join(code(e, table=False) for e in elsewhere) or "another trigger"
    items = [
        f"{PASSED.icon} passed",
        f"{FAILED.icon} failed",
        f"{TIMED_OUT.icon} timed out",
        f"{CANCELLED.icon} cancelled",
        f"{SKIPPED.icon} skipped",
        f"{OTHER.icon} another conclusion",
        f"{RUNNING.icon} running",
        f"{PENDING.icon} pending: queued, or not started yet",
        f"{NOT_IN_RUN.icon} not in this run: the run finished without a job for the cell",
        f"{EXCLUDED_HERE.icon} left out by the matrix on {here}, run on {runs}",
        f"{EXCLUDED_ALWAYS.icon} left out by the matrix on every trigger",
    ]
    provenance = (
        f"The cells are the matrices of {code(model.path, table=False)} at {source}, "
        "expanded the way GitHub expands them; each cell shows the job the run lists under "
        "the cell's name. Hover an icon for its leg and result."
    )
    return [
        "<details><summary>Legend</summary>",
        "",
        " · ".join(items),
        "",
        provenance,
        "",
        "</details>",
    ]


def render_comment(
    model: Model,
    run: dict,
    jobs: list[dict],
    facts: dict[str, RunnerFacts],
    *,
    source: str,
    mode: str = "all",
) -> str:
    """The whole comment body. ``mode`` is "all", "problems" or "none" (which icons link)."""
    placement = place_jobs(model, jobs, run_completed=run.get("status") == "completed")
    cells = model.cells()
    states = [placement.state(cell) for cell in cells]
    run_url = run.get("html_url") if isinstance(run.get("html_url"), str) else ""
    number = run.get("run_number")
    attempt = run.get("run_attempt")
    run_text = f"run {number}" if isinstance(number, int) else "run"
    title = f"[{run_text}]({run_url})" if _RUN_URL.match(run_url or "") else run_text
    status = run.get("status") or "unknown"
    if status == "completed":
        status = f"completed: {run.get('conclusion') or 'unknown'}"
    head = run.get("head_sha") if isinstance(run.get("head_sha"), str) else ""
    lines = [
        MARKER,
        f"### Platform and test matrix: {code(run.get('name') or 'workflow', table=False)}",
        "",
        " · ".join(
            part
            for part in (
                title,
                f"attempt {attempt}" if isinstance(attempt, int) else "",
                code(run.get("event") or "", table=False),
                f"head {code(head[:7], table=False)}"
                if re.fullmatch(r"[0-9a-f]{40}", head)
                else "",
                f"**{code(status, table=False)}**",
                f"{len(jobs)} jobs listed",
                f"{len(cells)} cells",
            )
            if part
        ),
        "",
        _counts_words(states + [job_state(job) for job in placement.others])
        + (
            f" · {len(placement.others)} of them in other jobs"
            if placement.others
            else ""
        ),
        "",
    ]
    singles = [group for group in model.groups if not group.has_matrix]
    for group in model.groups:
        if group.has_matrix:
            lines.extend(_group_section(group, placement, mode))
    lines.extend(_single_jobs_section(singles, placement, mode))
    lines.extend(_others_section(placement, mode))
    lines.extend(_environments_section(model, placement, jobs, facts))
    lines.extend(_legend(model, source))
    return "\n".join(lines) + "\n"


def render_within_limit(
    model: Model,
    run: dict,
    jobs: list[dict],
    facts: dict[str, RunnerFacts],
    *,
    source: str,
) -> str:
    """The richest body that fits: every icon linked, then only the ones worth a click,
    then none; past that, a cut body that says it was cut."""
    body = ""
    for mode in ("all", "problems", "none"):
        body = render_comment(model, run, jobs, facts, source=source, mode=mode)
        if len(body) <= BODY_BUDGET:
            return body
    note = "\n\n_The matrix is too large for one comment; see the run for the rest._\n"
    return body[: BODY_BUDGET - len(note)] + note


# --------------------------------------------------------------------------------------
# The REST API.
# --------------------------------------------------------------------------------------


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes


class GitHubError(RuntimeError):
    def __init__(self, status: int, what: str):
        super().__init__(f"HTTP {status} from {what}")
        self.status = status


class TransientError(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Hand a redirect back instead of following it, so no header is re-sent."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


def urllib_transport(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None,
    max_bytes: int | None,
) -> Response:
    """One HTTP exchange; never follows a redirect and never re-sends a header."""
    request = urllib.request.Request(url, data=body, method=method)
    for name, value in headers.items():
        # Unredirected: the header is sent to this URL only.
        request.add_unredirected_header(name, value)
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=30) as response:
            data = response.read(max_bytes) if max_bytes else response.read()
            return Response(
                response.status,
                {k.lower(): v for k, v in response.headers.items()},
                data,
            )
    except urllib.error.HTTPError as err:
        data = err.read(65536) if err.fp is not None else b""
        return Response(
            err.code, {k.lower(): v for k, v in (err.headers or {}).items()}, data
        )
    except (urllib.error.URLError, TimeoutError, ConnectionError) as err:
        raise TransientError(
            f"{method} {urllib.parse.urlsplit(url).path}: {err}"
        ) from err


Transport = Callable[[str, str, dict, "bytes | None", "int | None"], Response]
_NEXT = re.compile(r'<([^>]+)>\s*;\s*rel="next"')


class GitHubClient:
    def __init__(
        self,
        token: str,
        api_url: str = "https://api.github.com",
        transport: Transport = urllib_transport,
        sleep: Callable[[float], None] = time.sleep,
        attempts: int = 3,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._token = token
        self.api_url = api_url.rstrip("/")
        self._host = urllib.parse.urlsplit(self.api_url).netloc
        self._transport = transport
        self._sleep = sleep
        self._attempts = attempts
        self._clock = clock
        #: The monotonic time after which no request is sent and no retry sleeps; None
        #: until start_budget is called.
        self.deadline: float | None = None

    def start_budget(self, seconds: float) -> None:
        """Give the requests that follow ``seconds`` of wall-clock time, counted from now."""
        self.deadline = self._clock() + seconds

    def time_left(self) -> float:
        """Seconds until the deadline, or infinity when no budget was started."""
        return float("inf") if self.deadline is None else self.deadline - self._clock()

    def budget_spent(self) -> bool:
        return self.time_left() <= 0

    def _url(self, path: str, params: dict | None) -> str:
        if path.startswith("https://"):
            parts = urllib.parse.urlsplit(path)
            if parts.netloc != self._host:
                raise GitHubError(0, f"a link to another host ({parts.netloc})")
            url = path
        else:
            url = self.api_url + path
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
        return url

    def request(
        self,
        method: str,
        path: str,
        params: dict | None = None,
        payload: Any = None,
    ) -> Response:
        url = self._url(path, params)
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self._token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": USER_AGENT,
        }
        body = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        response = None
        for attempt in range(self._attempts):
            if self.budget_spent():
                raise TransientError(
                    f"{method} {urllib.parse.urlsplit(url).path}: "
                    "the time budget for this run of the command is spent"
                )
            response = self._transport(method, url, headers, body, None)
            wait = self._retry_after(response, attempt)
            if wait is None:
                return response
            if attempt + 1 < self._attempts:
                if wait > self.time_left():
                    raise TransientError(
                        f"{method} {urllib.parse.urlsplit(url).path}: HTTP "
                        f"{response.status}, and waiting {wait:g} s to retry would "
                        "end past the time budget"
                    )
                self._sleep(wait)
        return response

    @staticmethod
    def _retry_after(response: Response, attempt: int) -> float | None:
        if response.status in (500, 502, 503, 504):
            return 2.0 * (attempt + 1)
        if response.status in (403, 429):
            headers = response.headers
            if "retry-after" in headers:
                try:
                    return min(float(headers["retry-after"]), 120.0)
                except ValueError:
                    return 60.0
            if headers.get("x-ratelimit-remaining") == "0":
                try:
                    reset = float(headers.get("x-ratelimit-reset", "0"))
                except ValueError:
                    reset = 0.0
                return min(max(reset - time.time(), 1.0), 120.0)
        return None

    def get_json(self, path: str, params: dict | None = None) -> Any:
        response = self.request("GET", path, params)
        if response.status != 200:
            raise GitHubError(response.status, f"GET {path}")
        return json.loads(response.body)

    def paginate(
        self,
        path: str,
        params: dict | None = None,
        key: str | None = None,
        max_pages: int = 30,
    ) -> list:
        items: list = []
        url: str | None = path
        query = params
        for _ in range(max_pages):
            response = self.request("GET", url, query)
            if response.status != 200:
                raise GitHubError(response.status, f"GET {path}")
            data = json.loads(response.body)
            page = data.get(key) if key else data
            if not isinstance(page, list):
                raise GitHubError(response.status, f"GET {path} (not a list)")
            items.extend(page)
            match = _NEXT.search(response.headers.get("link", ""))
            if match is None:
                return items
            url, query = match.group(1), None
        return items

    def send_json(self, method: str, path: str, payload: Any) -> Any:
        response = self.request(method, path, payload=payload)
        if response.status not in (200, 201):
            raise GitHubError(response.status, f"{method} {path}")
        return json.loads(response.body)

    def log_head(self, path: str, max_bytes: int = 16384) -> bytes:
        """The first bytes of a log the API answers with a redirect to.

        The redirect goes to a signed storage URL on another host, which is fetched with
        no Authorization header: the token is for the API and goes nowhere else.
        """
        response = self.request("GET", path)
        if response.status not in (301, 302, 303, 307, 308):
            raise GitHubError(response.status, f"GET {path}")
        location = response.headers.get("location", "")
        if urllib.parse.urlsplit(location).scheme != "https":
            raise GitHubError(response.status, f"GET {path} (redirect is not https)")
        data = self._transport(
            "GET",
            location,
            {"User-Agent": USER_AGENT, "Range": f"bytes=0-{max_bytes - 1}"},
            None,
            max_bytes,
        )
        if data.status not in (200, 206):
            raise GitHubError(data.status, "the log storage")
        return data.body[:max_bytes]


# --------------------------------------------------------------------------------------
# The pull request, the run to show and the one comment.
# --------------------------------------------------------------------------------------


def marked_comments(client: GitHubClient, repo: str, number: int) -> list[dict]:
    """The bot's comments that start with the marker, oldest first."""
    found = [
        comment
        for comment in client.paginate(
            f"/repos/{repo}/issues/{number}/comments", {"per_page": "100"}
        )
        if (comment.get("user") or {}).get("login") == BOT_LOGIN
        and (comment.get("user") or {}).get("type") == "Bot"
        and str(comment.get("body") or "").startswith(MARKER)
    ]
    return sorted(found, key=lambda comment: int(comment.get("id") or 0))


def find_comment(client: GitHubClient, repo: str, number: int) -> dict | None:
    """The oldest marked bot comment, or None."""
    found = marked_comments(client, repo, number)
    return found[0] if found else None


@dataclass
class Posted:
    comment_id: int | None = None
    body: str | None = None


def upsert_comment(
    client: GitHubClient,
    repo: str,
    number: int,
    body: str,
    posted: Posted,
    *,
    lookup: bool = True,
) -> str:
    """Write ``body`` into the pull request's one marked comment; say what was done.

    ``lookup=False`` says the caller already searched and ``posted`` holds what it found.
    """
    if posted.body == body:
        return "unchanged"
    if posted.comment_id is None and lookup:
        existing = find_comment(client, repo, number)
        if existing is not None:
            posted.comment_id = int(existing["id"])
            if existing.get("body") == body:
                posted.body = body
                return "unchanged"
    if posted.comment_id is not None:
        response = client.request(
            "PATCH",
            f"/repos/{repo}/issues/comments/{posted.comment_id}",
            payload={"body": body},
        )
        if response.status == 200:
            posted.body = body
            return "updated"
        if response.status != 404:
            raise GitHubError(response.status, f"PATCH comment on #{number}")
        posted.comment_id = None
    created = client.send_json(
        "POST", f"/repos/{repo}/issues/{number}/comments", {"body": body}
    )
    posted.comment_id = int(created["id"])
    posted.body = body
    return "created"


def read_runner_facts(
    client: GitHubClient,
    repo: str,
    jobs: list[dict],
    facts: dict[str, RunnerFacts],
    tries: dict[str, int],
    log: Callable[[str], None],
) -> bool:
    """Fill ``facts`` with one finished job's header per label; at most 3 tries a label.

    Stops reading while no more than ``WRITE_RESERVE_SECONDS`` of the client's time budget
    is left, so the comment step keeps the time to write, and says so by returning False.
    """
    first: dict[str, dict] = {}
    for job in sorted(jobs, key=lambda j: j.get("id") or 0):
        label = label_of(job)
        if (
            label
            and job.get("status") == "completed"
            and job.get("runner_name")
            and job.get("steps")
        ):
            first.setdefault(label, job)
    for label, job in first.items():
        if label in facts or tries.get(label, 0) >= 3:
            continue
        if client.time_left() <= WRITE_RESERVE_SECONDS:
            return False
        tries[label] = tries.get(label, 0) + 1
        try:
            head = client.log_head(f"/repos/{repo}/actions/jobs/{int(job['id'])}/logs")
        except (GitHubError, TransientError) as err:
            log(f"could not read the runner header for {label}: {err}")
            continue
        parsed = parse_runner_header(head)
        if parsed is not None:
            facts[label] = parsed
    return True


# --------------------------------------------------------------------------------------
# The publish command and the command line.
# --------------------------------------------------------------------------------------


def parse_workflow(text: str, what: str) -> dict:
    """The workflow file's text as data; nothing in it is run."""
    import yaml

    if len(text) > MAX_WORKFLOW_BYTES:
        raise ValueError(f"{what} is larger than 4 MiB")
    data = yaml.safe_load(text)
    if not isinstance(data, dict) or not isinstance(data.get("jobs"), dict):
        raise ValueError(f"{what} is not a workflow")
    return data


def load_workflow(path: str) -> dict:
    with open(path, encoding="utf-8") as handle:
        text = handle.read(MAX_WORKFLOW_BYTES + 1)
    return parse_workflow(text, path)


def post_job_ids(workflow: dict) -> list[str]:
    """The jobs whose steps run this script's ``publish`` command, in workflow order."""
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict):
        return []
    found = []
    for job_id, job in jobs.items():
        steps = job.get("steps") if isinstance(job, dict) else None
        if isinstance(steps, list) and any(
            isinstance(step, dict) and POST_COMMAND in str(step.get("run") or "")
            for step in steps
        ):
            found.append(str(job_id))
    return found


def without_post_jobs(workflow: dict) -> tuple[dict, list[str]]:
    """The workflow with the publishing jobs removed, and their ids."""
    ids = post_job_ids(workflow)
    kept = {k: v for k, v in workflow["jobs"].items() if str(k) not in ids}
    return {**workflow, "jobs": kept}, ids


def post_job_names(workflow: dict, ids: list[str], contexts: dict) -> set[str]:
    """The names GitHub lists the publishing jobs under (none of them has a matrix)."""
    names: set[str] = set()
    for job_id in ids:
        job = workflow["jobs"][job_id]
        try:
            names.add(_job_name(job_id, job, {}, contexts, False))
        except ExpressionError:
            names.add(job_id)
    return names


def fetch_workflow(client: GitHubClient, repo: str, path: str, sha: str) -> dict:
    """The run's own workflow file at the run's workflow commit, parsed as data."""
    if not _WORKFLOW_PATH.fullmatch(path):
        raise ValueError(
            "the run's workflow path is not a file under .github/workflows"
        )
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("GITHUB_WORKFLOW_SHA is not a full commit sha")
    data = client.get_json(f"/repos/{repo}/contents/{path}", {"ref": sha})
    if (
        not isinstance(data, dict)
        or data.get("encoding") != "base64"
        or not isinstance(data.get("content"), str)
    ):
        raise ValueError("the contents API did not return the workflow as base64")
    if isinstance(data.get("size"), int) and data["size"] > MAX_WORKFLOW_BYTES:
        raise ValueError("the workflow file is larger than 4 MiB")
    raw = base64.b64decode(data["content"])
    if len(raw) > MAX_WORKFLOW_BYTES:
        raise ValueError("the workflow file is larger than 4 MiB")
    return parse_workflow(raw.decode("utf-8"), path)


def derived_conclusion(jobs: list[dict]) -> str:
    """What the run will conclude as, from the jobs it lists, in this order: cancelled if
    any job was cancelled, else failure if any failed, timed out or failed to start,
    else success.

    A cancelled job outranks a failed one. Two push runs on main show it: run
    45848350222 had two jobs cancelled before they started, 325 failed and 56 succeeded,
    and concluded cancelled; run 45848402299, 19 seconds later, had none cancelled, 327
    failed and 56 succeeded, and concluded failure.
    """
    conclusions = {job.get("conclusion") for job in jobs}
    if "cancelled" in conclusions:
        return "cancelled"
    if conclusions & {"failure", "timed_out", "startup_failure"}:
        return "failure"
    return "success"


def run_line_of(body: Any) -> tuple[int, int] | None:
    """The (run_number, run_attempt) a comment body names, or None."""
    match = _RUN_LINE.search(str(body or ""))
    return (int(match.group(1)), int(match.group(2))) if match else None


def build_publish_body(
    client: GitHubClient,
    *,
    repo: str,
    run_id: int,
    event_name: str,
    event: dict,
    workflow_sha: str,
    final: bool,
    sleep: Callable[[float], None],
    log: Callable[[str], None],
    notes: list[str],
) -> tuple[str, dict]:
    """The comment body for the run as it is now, and the run object it was read from.

    ``notes`` collects what was left undone because the time budget ran out.
    """
    run = client.get_json(f"/repos/{repo}/actions/runs/{run_id}")
    if not isinstance(run, dict):
        raise ValueError("the run is not an object")
    number, attempt = run.get("run_number"), run.get("run_attempt")
    if not isinstance(number, int) or not isinstance(attempt, int):
        raise ValueError("the run has no run_number and run_attempt")
    workflow = fetch_workflow(client, repo, str(run.get("path") or ""), workflow_sha)
    shown, post_ids = without_post_jobs(workflow)
    pull = event.get("pull_request") if event_name == "pull_request" else None
    default_branch = str(
        (event.get("repository") or {}).get("default_branch") or "main"
    )

    def contexts_for(name: str) -> dict:
        return github_context(
            name,
            repository=repo,
            default_branch=default_branch,
            pull=pull if isinstance(pull, dict) else None,
        )

    path = str(run["path"])
    model = build_model(
        shown,
        path=path,
        event=str(run.get("event") or event_name),
        contexts_for=contexts_for,
    )
    own_names = post_job_names(
        workflow,
        post_ids,
        {
            "github": contexts_for(event_name),
            "inputs": {},
            "matrix": {},
            "strategy": {},
        },
    )

    def read_jobs() -> list[dict]:
        listed = client.paginate(
            f"/repos/{repo}/actions/runs/{run_id}/jobs",
            {"filter": "latest", "per_page": "100"},
            key="jobs",
        )
        return [job for job in listed if str(job.get("name")) not in own_names]

    jobs = read_jobs()
    facts: dict[str, RunnerFacts] = {}
    shown_run = run
    if final:
        for _ in range(SETTLE_READS):
            if all(job.get("status") == "completed" for job in jobs):
                break
            if client.time_left() <= SETTLE_SECONDS + WRITE_RESERVE_SECONDS:
                notes.append(
                    "the job list was not read again while a job still read unfinished"
                )
                break
            sleep(SETTLE_SECONDS)
            jobs = read_jobs()
        if not read_runner_facts(client, repo, jobs, facts, {}, log):
            notes.append("the remaining runner headers were not read")
        # The run is still in progress while this job runs, so the table shows it as
        # completed with the conclusion its jobs add up to.
        shown_run = dict(run, status="completed", conclusion=derived_conclusion(jobs))
    sha = workflow_sha
    body = render_within_limit(
        model, shown_run, jobs, facts, source=f"commit {code(sha[:7], table=False)}"
    )
    marker_line = RUN_LINE.format(number=number, attempt=attempt)
    return body.replace(MARKER + "\n", MARKER + "\n" + marker_line + "\n", 1), run


def comment_on_pull_request(
    client: GitHubClient,
    *,
    repo: str,
    event_name: str,
    event: dict,
    run: dict,
    body: str,
    log: Callable[[str], None],
) -> None:
    """Write the one comment, or say in one log line why not (no pull request, or a fork).

    Any failed request raises, and ``publish`` turns it into one warning annotation.
    """
    pull = event.get("pull_request") if event_name == "pull_request" else None
    if not isinstance(pull, dict):
        log(f"no comment: a {event_name} run has no pull request")
        return
    number = pull.get("number")
    if not isinstance(number, int) or isinstance(number, bool):
        log("no comment: the event names no pull request number")
        return
    head_repo = str(((pull.get("head") or {}).get("repo") or {}).get("full_name") or "")
    if head_repo != repo:
        log(
            f"no comment on #{number}: it comes from a fork, whose token is read-only; "
            "the job summary has the table"
        )
        return
    found = marked_comments(client, repo, number)
    if len(found) > 1:
        log(f"{len(found)} comments on #{number} carry the marker; using the oldest")
    existing = found[0] if found else None
    here = (int(run["run_number"]), int(run["run_attempt"]))
    there = run_line_of(existing.get("body")) if existing else None
    if there is not None and there > here:
        log(
            f"comment on #{number} shows run {there[0]} attempt {there[1]}, "
            "later than this run; left as it is"
        )
        return
    posted = Posted()
    if existing is not None:
        posted = Posted(int(existing["id"]), str(existing.get("body") or ""))
    outcome = upsert_comment(client, repo, number, body, posted, lookup=False)
    log(f"comment on #{number} {outcome}")


def publish(
    client: GitHubClient,
    *,
    repo: str,
    run_id: int,
    event_name: str,
    event: dict,
    workflow_sha: str,
    final: bool = False,
    summary_path: str = "",
    log: Callable[[str], None] = print,
    warn: Callable[[str], None] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    budget_seconds: float = PUBLISH_BUDGET_SECONDS,
) -> int:
    """Write the table into the pull request's comment, and the job summary when final.

    Never fails: every error becomes a warning annotation and a return of 0, because the
    table is a view and must not change what a run concludes. The whole call has
    ``budget_seconds`` of wall-clock time (see PUBLISH_BUDGET_SECONDS); what the budget
    cut short is named in one warning annotation.
    """
    client.start_budget(budget_seconds)

    def warning(message: str) -> None:
        if warn is not None:
            warn(message)
        else:
            print(WARNING_PREFIX + one_line(message), flush=True)

    def note_in_summary(text: str) -> None:
        if final and summary_path:
            try:
                with open(summary_path, "a", encoding="utf-8") as handle:
                    handle.write(text if text.endswith("\n") else text + "\n")
            except OSError as err:
                warning(f"could not write the job summary: {err}")

    notes: list[str] = []
    try:
        body, run = build_publish_body(
            client,
            repo=repo,
            run_id=run_id,
            event_name=event_name,
            event=event,
            workflow_sha=workflow_sha,
            final=final,
            sleep=sleep,
            log=log,
            notes=notes,
        )
    except Exception as err:  # noqa: BLE001 - a view never fails the run, whatever broke
        warning(f"could not build the matrix table: {err}")
        note_in_summary("The Unified CI matrix table could not be built for this run.")
        return 0
    note_in_summary(body)
    if client.budget_spent():
        # Not even the comment's first request could be sent; skip it with a note
        # rather than raise a second warning for a request the deadline refuses.
        notes.append("the comment was not written")
    else:
        try:
            comment_on_pull_request(
                client,
                repo=repo,
                event_name=event_name,
                event=event,
                run=run,
                body=body,
                log=log,
            )
        except Exception as err:  # noqa: BLE001 - the same
            warning(f"could not write the comment: {err}")
    if notes:
        warning("too little of the time budget was left, so " + "; ".join(notes))
    return 0


def _jobs_from_file(data: Any) -> list[dict]:
    if isinstance(data, dict):
        data = [data]
    jobs: list[dict] = []
    for item in data:
        if isinstance(item, dict) and isinstance(item.get("jobs"), list):
            jobs.extend(item["jobs"])
        elif isinstance(item, dict):
            jobs.append(item)
    return jobs


def main(argv: list[str] | None = None, environ: dict | None = None) -> int:
    environ = dict(os.environ if environ is None else environ)
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    sub = parser.add_subparsers(dest="command", required=True)
    publish_parser = sub.add_parser(
        "publish", help="write the run's table into the comment, and the job summary"
    )
    publish_parser.add_argument(
        "--final",
        action="store_true",
        help="the last link: settle the job list, read runner headers, draw the run "
        "as completed and write the job summary",
    )
    render_parser = sub.add_parser(
        "render", help="print the comment for saved API responses"
    )
    render_parser.add_argument("--workflow", default=DEFAULT_WORKFLOW)
    render_parser.add_argument(
        "--run", required=True, help="a saved GET .../actions/runs/<id>"
    )
    render_parser.add_argument(
        "--jobs", required=True, help="saved GET .../runs/<id>/jobs pages"
    )
    render_parser.add_argument(
        "--repository", default="awslabs/automated-security-helper"
    )
    args = parser.parse_args(argv)

    def log(message: str) -> None:
        print(one_line(message), flush=True)

    if args.command == "render":
        with open(args.run, encoding="utf-8") as handle:
            run = json.load(handle)
        with open(args.jobs, encoding="utf-8") as handle:
            jobs = _jobs_from_file(json.load(handle))
        model = build_model(
            load_workflow(args.workflow),
            path=args.workflow,
            event=str(run.get("event") or "pull_request"),
            contexts_for=lambda event: github_context(
                event, repository=args.repository, default_branch="main"
            ),
        )
        sys.stdout.write(
            render_within_limit(model, run, jobs, {}, source="the given path")
        )
        return 0

    def warn(message: str) -> None:
        print(WARNING_PREFIX + one_line(message), flush=True)

    repo = environ.get("GITHUB_REPOSITORY", "")
    token = environ.get("GITHUB_TOKEN", "")
    run_id = environ.get("GITHUB_RUN_ID", "")
    event_name = environ.get("GITHUB_EVENT_NAME", "")
    event_path = environ.get("GITHUB_EVENT_PATH", "")
    workflow_sha = environ.get("GITHUB_WORKFLOW_SHA", "")
    api_url = environ.get("GITHUB_API_URL", "https://api.github.com")
    summary_path = environ.get("GITHUB_STEP_SUMMARY", "")
    problems = [
        name
        for name, ok in (
            (
                "GITHUB_REPOSITORY",
                re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo),
            ),
            ("GITHUB_TOKEN", token),
            ("GITHUB_RUN_ID", re.fullmatch(r"[0-9]{1,20}", run_id)),
            ("GITHUB_EVENT_NAME", re.fullmatch(r"[a-z_]{1,40}", event_name)),
            ("GITHUB_EVENT_PATH", event_path),
            ("GITHUB_WORKFLOW_SHA", re.fullmatch(r"[0-9a-f]{40}", workflow_sha)),
            ("GITHUB_API_URL", re.fullmatch(r"https://[A-Za-z0-9_.:/-]+", api_url)),
        )
        if not ok
    ]
    if problems:
        warn("these variables are missing or malformed: " + ", ".join(problems))
        return 0
    try:
        with open(event_path, encoding="utf-8") as handle:
            text = handle.read(MAX_EVENT_BYTES + 1)
        event = json.loads(text) if len(text) <= MAX_EVENT_BYTES else None
    except (OSError, ValueError) as err:
        warn(f"could not read the event payload: {err}")
        return 0
    if not isinstance(event, dict):
        warn("the event payload is not a JSON object, or is larger than 16 MiB")
        return 0
    return publish(
        GitHubClient(token, api_url),
        repo=repo,
        run_id=int(run_id),
        event_name=event_name,
        event=event,
        workflow_sha=workflow_sha,
        final=args.final,
        summary_path=summary_path,
        log=log,
        warn=warn,
    )


def _guarded_main() -> int:
    """main(), with any unexpected error printed through one_line.

    A traceback's text can contain a value from the run, and the runner would read a
    workflow command out of an unfiltered line of it. The publish command never fails
    the run, so there it ends with a warning annotation and a 0.
    """
    try:
        return main()
    except Exception:  # noqa: BLE001 - the whole point is that nothing escapes unfiltered
        import traceback

        for line in traceback.format_exc().splitlines():
            print(one_line(line), flush=True)
        if sys.argv[1:2] == ["publish"]:
            print(
                WARNING_PREFIX + "the publish command raised; see the log", flush=True
            )
            return 0
        return 1


if __name__ == "__main__":
    sys.exit(_guarded_main())
