# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Reading what a pipeline run left behind: findings, kept reports, expected results.

* Findings by file come from ASH's ``ash_aggregated_results.json``, counted the way
  ASH counts actionable findings for its exit code: not suppressed, and at or above the
  scan's severity threshold. A finding's file is the URI as ASH wrote it, relative to
  the scanned directory, or its last component when it is an absolute path inside a
  job container.
* Reports are looked for where the page's pipeline keeps them: an artifact act's
  artifact server stored, a GitLab job's artifacts, a Jenkins build's archive, the
  CodeBuild agent's artifact directory (as files or a zip), the CircleCI report copy.
  What is kept for upload leaves out every symbolic link, every dot entry and every
  secret-shaped name; an ``.ash/ash_output`` directory is kept as ``ash_output``.
* The result each job of a GitHub workflow should have follows from what it runs: a
  job that runs ``ash scan``, ``ash merge`` or ``ash`` with options (a scan) without
  ``--no-fail-on-findings``, or
  the job of the reusable scan workflow when its caller leaves ``fail-on-findings``
  on, fails, because every runnable block runs on a fixture with findings; any other
  job passes. A job that calls a reusable workflow is expected under the job ids of
  the workflow it calls, with its matrix runs counted.
"""

from __future__ import annotations

import calendar
import json
import math
import os
import re
import shutil
import struct
import xml.etree.ElementTree as ET
import zipfile
import zlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from .verdict import log_texts

AGGREGATED = "ash_aggregated_results.json"
DEFAULT_THRESHOLD = "MEDIUM"
#: ASH's reusable scan workflow, whose scan job gates on its caller's input.
SCAN_WORKFLOW = "run-ash-security-scan.yml"
#: ASH's reusable workflow that uploads the SARIF report to code scanning.
SARIF_WORKFLOW = "upload-ash-sarif.yml"
#: How many characters of a log a failure message quotes at most.
TAIL_CHARS = 4000
#: What reading a zip can raise: a bad archive or header (BadZipFile), a value that
#: does not parse (ValueError, which BadZipFile extends), a file error, corrupt
#: deflate data (zlib.error), a truncated member (EOFError), an encrypted member
#: (RuntimeError) and an unsupported compression method (NotImplementedError). A
#: reader that catches these reports the archive and goes on.
_ZIP_ERRORS = (
    OSError,
    ValueError,
    zipfile.BadZipFile,
    zlib.error,
    EOFError,
    RuntimeError,
    NotImplementedError,
)

#: What separates ``ash`` from its first argument: blanks, and backslash-newline
#: continuations. A plain line break ends the command, as it does in a script or a
#: literal YAML block, so in ``cd ash`` followed by ``merge.sh`` on the next line,
#: ``merge`` is not ASH's. RUNS_SCAN and RUNS_SCAN_OR_MERGE are matched against the
#: commands a parsed workflow or job holds, against each string a YAML block loads to
#: (YAML joins the lines of a folded or plain scalar), and against a Jenkinsfile or a
#: text of no kind as written (pipelines.runs_ash).
_ASH_SPACE = r"(?:[ \t]|\\\r?\n)+"
#: The separator for a YAML block that does not parse, read as written: any
#: whitespace, line breaks included, since a scalar YAML would have joined may split
#: ``ash`` from its argument there. It errs toward counting a block as running ASH.
_ANY_SPACE = r"(?:\s|\\\r?\n)+"
#: An option: ``-`` and a letter, or ``--`` and a letter. ``ash --help`` and
#: ``ash --version``, with that option in first position, only print; ``ash -v
#: --version`` and the like are still counted as scans, which fails closed. The
#: letter keeps a dash that starts no option (``ash - security scan``, a YAML list
#: marker on the next line) from counting.
_OPTION_SCAN = r"-(?:[A-Za-z]|-(?!(?:help|version)(?![\w-]))[A-Za-z])"


def _runs_ash(subcommands: str, space: str = _ASH_SPACE) -> re.Pattern[str]:
    """``ash`` followed by one of ``subcommands`` or by an option."""
    return re.compile(rf"(?<![\w.-])ash{space}(?:(?:{subcommands})\b|{_OPTION_SCAN})")


#: A command that runs an ASH scan: ``ash scan``, or ``ash`` followed by an option,
#: since the scan is the CLI's default command (``ash --source-dir .`` scans).
RUNS_SCAN = _runs_ash("scan")
#: A command that runs an ASH scan or ``ash merge``.
RUNS_SCAN_OR_MERGE = _runs_ash("scan|merge")
#: RUNS_SCAN_OR_MERGE for a YAML block that does not parse, read as written.
RUNS_SCAN_OR_MERGE_ANY_LINE = _runs_ash("scan|merge", _ANY_SPACE)
_GATES = RUNS_SCAN_OR_MERGE
_MATRIX = re.compile(r"\$\{\{\s*matrix\.([\w-]+)\s*\}\}")
_RUNS_ASH = re.compile(r"(?<![\w.-])uvx\b.*?(?<![\w.-])ash(?![\w.-])")
#: Names the kept copies leave out: Jenkins' keys and secrets, and private keys.
_SECRET_SHAPED = re.compile(
    r"^(?:secrets|secret\.key.*|identity\.key\.enc)$|\.(?:key|pem)$", re.IGNORECASE
)
#: A Jenkins home's keys (instance secret, controller key directory, instance
#: identity), and the entries beside them that only a Jenkins home has.
_JENKINS_KEYS = ("secret.key", "secrets", "identity.key.enc")
_JENKINS_LAYOUT = ("jobs", "config.xml")


def load_workflow(text: str) -> dict[str, Any]:
    """A GitHub workflow as a mapping, with YAML 1.1's ``True`` key read back as ``on``."""
    document = yaml.safe_load(text)
    if not isinstance(document, dict):
        raise ValueError("a workflow is a mapping")
    if True in document:
        document["on"] = document.pop(True)
    return document


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


def _threshold(aggregated: Mapping[str, Any]) -> str:
    config = aggregated.get("ash_config")
    if isinstance(config, Mapping):
        settings = config.get("global_settings")
        if isinstance(settings, Mapping) and settings.get("severity_threshold"):
            return str(settings["severity_threshold"]).upper()
    return DEFAULT_THRESHOLD


def _file_of(result: Mapping[str, Any]) -> str:
    for location in result.get("locations") or []:
        uri = (
            (location or {})
            .get("physicalLocation", {})
            .get("artifactLocation", {})
            .get("uri")
        )
        if isinstance(uri, str) and uri:
            path = re.sub(r"^file://", "", uri)
            if path.startswith("/"):
                return PurePosixPath(path).name
            return PurePosixPath(path).as_posix().removeprefix("./")
    return "<no location>"


def findings_by_file(aggregated: Mapping[str, Any]) -> dict[str, int]:
    """Actionable findings per file in ASH's aggregated results.

    Counted with ASH's own ``count_actionable_results``, the count its exit code
    gates on, so this checks where the findings are, not ASH's definition of one.
    """
    from automated_security_helper.workspace.aggregation import (
        count_actionable_results,
    )

    threshold = _threshold(aggregated)
    by_file: dict[str, list[Mapping[str, Any]]] = {}
    sarif = aggregated.get("sarif") or {}
    for run in sarif.get("runs") or []:
        for result in (run or {}).get("results") or []:
            if isinstance(result, Mapping):
                by_file.setdefault(_file_of(result), []).append(result)
    counts = {
        name: count_actionable_results(results, threshold)
        for name, results in by_file.items()
    }
    return {name: count for name, count in counts.items() if count}


def aggregated_results_at(path: Path) -> list[tuple[str, dict[str, Any]]]:
    """The aggregated results at ``path``, as a one-item list, or [] when there are none."""
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        return []
    try:
        return [(str(path), json.loads(path.read_text(encoding="utf-8")))]
    except (OSError, ValueError):
        return []


def aggregated_results_in(root: Path) -> list[tuple[str, dict[str, Any]]]:
    """The shallowest ``ash_aggregated_results.json`` under ``root``, files or zipped.

    Where a runner keeps an output directory as it is, as a zip, or one level down
    depends on the runner, so this looks through all of it and keeps the copies
    nearest the top: ASH writes one per output directory, at its top.
    """
    found: list[tuple[int, str, dict[str, Any]]] = []
    root = Path(root)
    if not root.is_dir():
        return []
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        depth = len(path.relative_to(root).parts)
        if path.name == AGGREGATED:
            found += [
                (depth, where, data) for where, data in aggregated_results_at(path)
            ]
        elif path.suffix == ".zip":
            try:
                with zipfile.ZipFile(path) as archive:
                    for member in archive.namelist():
                        if PurePosixPath(member).name == AGGREGATED:
                            found.append(
                                (
                                    depth + len(PurePosixPath(member).parts),
                                    f"{path}!{member}",
                                    json.loads(archive.read(member)),
                                )
                            )
            except _ZIP_ERRORS:
                continue
    if not found:
        return []
    top = min(depth for depth, _, _ in found)
    return [(where, data) for depth, where, data in found if depth == top]


def findings_problems(
    aggregated: list[tuple[str, Mapping[str, Any]]], expected: Mapping[str, int]
) -> list[str]:
    """The one aggregated result the run kept must list exactly ``expected``."""
    if not aggregated:
        return [f"the run kept no {AGGREGATED}"]
    if len(aggregated) > 1:
        return [
            f"the run kept {len(aggregated)} copies of {AGGREGATED}: "
            + ", ".join(where for where, _ in aggregated)
        ]
    where, data = aggregated[0]
    found = findings_by_file(data)
    if found == dict(expected):
        return []
    files = sorted(set(found) | set(expected))
    return [
        f"{where}: {name} has {found.get(name, 0)} actionable findings, expected "
        f"{expected.get(name, 0)}"
        for name in files
        if found.get(name, 0) != expected.get(name, 0)
    ]


def copy_without_links(source: Path, target: Path) -> None:
    """Copy ``source`` to ``target``, leaving out every symbolic link.

    The copies are uploaded with the run's logs, and a link could carry a file from
    outside the run into the upload.
    """
    source = Path(source)
    target = Path(target)
    if source.is_symlink() or not source.exists():
        return
    if source.is_file():
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        return
    for directory, dirs, files in os.walk(source):
        here = Path(directory)
        dirs[:] = [d for d in dirs if not (here / d).is_symlink()]
        (target / here.relative_to(source)).mkdir(parents=True, exist_ok=True)
        for name in files:
            path = here / name
            if not path.is_symlink() and path.is_file():
                shutil.copyfile(path, target / path.relative_to(source))


def _is_jenkins_home(path: Path) -> bool:
    """Whether ``path`` holds one of a Jenkins home's keys beside its job tree or its
    configuration, as every Jenkins home does once Jenkins has started in it."""
    return any((path / name).exists() for name in _JENKINS_KEYS) and any(
        (path / name).exists() for name in _JENKINS_LAYOUT
    )


def keep_tree(source: Path, target: Path) -> None:
    """Copy ``source`` to ``target`` for upload: no links, dot entries or secrets.

    The run's output directory is uploaded, and the upload skips hidden files, so an
    ``.ash/ash_output`` directory is copied as ``ash_output`` and every other entry
    whose name starts with a dot is left behind, as is every symbolic link and every
    secret-shaped name (Jenkins' ``secret.key``, ``secrets/``, ``identity.key.enc``,
    ``*.key``, ``*.pem``). A Jenkins home is left behind whole, wherever it sits.
    """
    source = Path(source)
    target = Path(target)
    if source.is_symlink() or not source.is_dir() or _is_jenkins_home(source):
        return
    target.mkdir(parents=True, exist_ok=True)
    for path in sorted(source.iterdir()):
        if path.is_symlink() or _SECRET_SHAPED.search(path.name):
            continue
        if path.name.startswith("."):
            output = path / "ash_output"
            if path.name == ".ash" and not output.is_symlink() and output.is_dir():
                keep_tree(output, target / "ash_output")
            continue
        if path.is_dir():
            keep_tree(path, target / path.name)
        elif path.is_file():
            shutil.copyfile(path, target / path.name)


def junit_counts(root: Path) -> tuple[int, int]:
    """(tests, failed tests) over every JUnit XML file under ``root``, plain or inside
    a zip: the CodeBuild agent keeps each report group as ``reports-<name>.zip``.

    A test failed when it has a ``failure`` or an ``error``. A file that is not JUnit
    XML counts nothing, and so does a file that is not a zip.
    """
    tests = failures = 0
    root = Path(root)
    if not root.is_dir():
        return 0, 0
    documents: list[bytes] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        if path.suffix == ".xml":
            try:
                documents.append(path.read_bytes())
            except OSError:
                continue
        elif path.suffix == ".zip":
            try:
                with zipfile.ZipFile(path) as archive:
                    documents += [
                        archive.read(member)
                        for member in archive.namelist()
                        if member.endswith(".xml")
                    ]
            except _ZIP_ERRORS:
                continue
    for data in documents:
        try:
            document = ET.fromstring(data)
        except ET.ParseError:
            continue
        for case in document.iter("testcase"):
            tests += 1
            if case.find("failure") is not None or case.find("error") is not None:
                failures += 1
    return tests, failures


# ---------------------------------------------------------------------------
# GitHub workflows under act
# ---------------------------------------------------------------------------


def _gates(command: str) -> bool:
    return bool(_GATES.search(command)) and "--no-fail-on-findings" not in command


def _steps(job: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return [step for step in job.get("steps") or [] if isinstance(step, Mapping)]


def _job_gates(job: Mapping[str, Any]) -> bool:
    return any(_gates(str(step.get("run", ""))) for step in _steps(job))


def _input_on(inputs: Any, name: str) -> bool:
    value = inputs.get(name, True) if isinstance(inputs, Mapping) else True
    return value not in (False, "false")


def matrix_entries(matrix: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The runs of a ``strategy.matrix``, expanded as GitHub expands it.

    The product of the list-valued keys, less each ``exclude`` entry it matches; an
    ``include`` entry is added to every run whose original values it keeps, or else
    becomes a run of its own. A matrix built by an expression cannot be counted before
    the run, and is an error.
    """
    keys = [key for key in matrix if key not in ("include", "exclude")]
    for key in keys:
        if not isinstance(matrix[key], list):
            raise ValueError(
                f"matrix key {key} is {matrix[key]!r}, not a list; its runs cannot be "
                "counted before the run"
            )
    runs: list[dict[str, Any]] = [{}] if keys else []
    for key in keys:
        runs = [{**run, key: value} for run in runs for value in matrix[key]]
    for name in ("exclude", "include"):
        if not isinstance(matrix.get(name) or [], list):
            raise ValueError(f"matrix {name} is {matrix[name]!r}, not a list")
    for exclude in matrix.get("exclude") or []:
        runs = [
            run
            for run in runs
            if not all(run.get(key) == value for key, value in exclude.items())
        ]
    for include in matrix.get("include") or []:
        matched = False
        for run in runs:
            if all(run[key] == value for key, value in include.items() if key in keys):
                run.update({k: v for k, v in include.items() if k not in keys})
                matched = True
        if not matched:
            runs.append(dict(include))
    return runs


def matrix_runs(job: Mapping[str, Any]) -> int:
    """How many times ``job`` runs: once per matrix entry, or once."""
    strategy = job.get("strategy")
    if strategy is None:
        return 1
    matrix = strategy.get("matrix") if isinstance(strategy, Mapping) else None
    if matrix is None:
        return 1
    if not isinstance(matrix, Mapping):
        raise ValueError(
            f"a matrix given as {matrix!r} cannot be counted before the run"
        )
    if not matrix:
        return 1
    return len(matrix_entries(matrix))


@dataclass(frozen=True)
class JobPlan:
    """What act should report for one job id: its result, its runs, whether it gates.

    ``caller`` is the job of the block that calls the reusable workflow this job is
    from, or None for a job of the block itself; ``workflow`` is that reusable
    workflow's file name, and ``inputs`` what the call gives it (the caller's ``with``
    over the workflow's declared defaults), both None for a job of the block itself.
    """

    result: str
    runs: int
    gates: bool
    caller: str | None = None
    workflow: str | None = None
    inputs: Mapping[str, Any] | None = None


#: A job-level ``if``, with or without the ``${{ }}`` around it.
_EXPRESSION_WRAP = re.compile(r"^\s*\$\{\{(?P<body>.*)\}\}\s*$", re.DOTALL)
_EXPRESSION_TOKEN = re.compile(
    r"\s*(?:(?P<string>'(?:[^']|'')*')|(?P<op>&&|\|\||==|!=|!|\(|\))"
    r"|(?P<number>-?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?)"
    r"|(?P<path>[A-Za-z_][\w.-]*(?:\(\))?))"
)
#: A string GitHub's expressions read as a number: a decimal with an optional sign,
#: fraction and exponent (JavaScript's Number() of the trimmed text; hexadecimal is
#: left out). Anything else, `1_000`, `inf`, `nan`, `Infinity` and words included, is
#: NaN.
_NUMBER_TEXT = re.compile(r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?")
#: The literals GitHub's expressions know, as the values this reader uses for them:
#: ``null`` is the empty string, which reads false and compares as GitHub's null does
#: (both become the number 0).
_LITERALS: dict[str, Any] = {"true": True, "false": False, "null": ""}


class _JobCondition:
    """What a job's ``if`` can be read as before the run; None where it cannot.

    ``results`` maps the jobs ``needs`` may name to their planned result, "skipped"
    for one the plan left out; ``called`` names those that call a reusable workflow,
    whose outputs act does not deliver (the ``if`` of a job that reads them is
    false under act, measured: the job never starts); ``inputs`` are the values a
    reusable workflow's ``inputs.<name>`` have for this call. Anything else
    (``github.*``, ``env.*``, a plain job's outputs) is unknown, and an unknown
    condition keeps the job expected, so a job act then skips is named, never passed
    over.
    """

    def __init__(
        self,
        results: Mapping[str, str],
        called: Iterable[str] = (),
        inputs: Mapping[str, Any] | None = None,
        needs_of: Mapping[str, Iterable[str]] | None = None,
    ) -> None:
        self.results = dict(results)
        self.called = set(called)
        self.inputs = dict(inputs or {})
        self.needs_of = {job: list(needs) for job, needs in (needs_of or {}).items()}

    def runs(self, job: Mapping[str, Any]) -> bool:
        """Whether GitHub starts ``job`` given its ``needs`` and ``if``.

        An ``if`` that names no status function (``success()``, ``failure()``,
        ``always()``, ``cancelled()``) is read as ``success() && (<if>)``, as GitHub
        and act read it: a dependent of a failed job with ``if: needs.x.result ==
        'failure'`` or ``if: github.event_name == 'push'`` does not start.
        """
        needs = _needs_of(job)
        condition = job.get("if")
        if condition is None:
            return self._success(needs)
        if isinstance(condition, bool):
            return _and_values(self._success(needs), condition) is not False
        try:
            tokens = _tokens(_expression_body(str(condition)))
            value, rest = self._or(tokens, needs)
            if rest:
                raise ValueError(f"unread tail {rest!r}")
        except ValueError:
            # An ``if`` this reader cannot parse (a function it does not know) has an
            # unknown value, but the implicit ``success()`` still applies when its text
            # names no status function: a dependent of a failed job does not start.
            if any(function in str(condition) for function in _STATUS_FUNCTIONS):
                return True
            return _and_values(self._success(needs), None) is not False
        if not any(token in _STATUS_FUNCTIONS for token in tokens):
            value = _and_values(self._success(needs), value)
        return value is not False

    def _success(self, needs: list[str]) -> bool:
        """``success()``: every job in ``needs``, and every job they need, transitively,
        ended as success, as GitHub and act read it (act walks the needs closure): a
        job below an ``always()`` job that ran after a failed job does not start
        without an ``if`` of its own, although its direct need succeeded."""
        return all(self.results.get(job) == "success" for job in self._ancestors(needs))

    def _failure(self, needs: list[str]) -> bool:
        """``failure()``: a job in ``needs``, or one they need, transitively, failed."""
        return any(self.results.get(job) == "failure" for job in self._ancestors(needs))

    def _ancestors(self, needs: list[str]) -> list[str]:
        """``needs`` and every job they need, transitively, each once; a cycle in
        ``needs_of`` ends when every job in it has been seen."""
        pending = [str(need) for need in needs]
        seen: list[str] = []
        while pending:
            job = pending.pop()
            if job in seen:
                continue
            seen.append(job)
            pending += [str(need) for need in self.needs_of.get(job, [])]
        return seen

    def evaluate(self, text: str, needs: list[str]) -> Any:
        """The value of expression ``text`` alone, without the implicit ``success()``."""
        tokens = _tokens(_expression_body(text))
        value, rest = self._or(tokens, needs)
        if rest:
            raise ValueError(f"unread tail {rest!r}")
        return value

    def _or(self, tokens: list[str], needs: list[str]) -> tuple[Any, list[str]]:
        value, tokens = self._and(tokens, needs)
        while tokens and tokens[0] == "||":
            other, tokens = self._and(tokens[1:], needs)
            left, right = _truth(value), _truth(other)
            value = (
                True
                if left or right
                else (False if left is False and right is False else None)
            )
        return value, tokens

    def _and(self, tokens: list[str], needs: list[str]) -> tuple[Any, list[str]]:
        value, tokens = self._not(tokens, needs)
        while tokens and tokens[0] == "&&":
            other, tokens = self._not(tokens[1:], needs)
            value = _and_values(value, other)
        return value, tokens

    def _not(self, tokens: list[str], needs: list[str]) -> tuple[Any, list[str]]:
        if tokens and tokens[0] == "!":
            value, tokens = self._not(tokens[1:], needs)
            truth = _truth(value)
            return (None if truth is None else not truth), tokens
        return self._comparison(tokens, needs)

    def _comparison(self, tokens: list[str], needs: list[str]) -> tuple[Any, list[str]]:
        value, tokens = self._primary(tokens, needs)
        if tokens and tokens[0] in ("==", "!="):
            other, rest = self._primary(tokens[1:], needs)
            if value is None or other is None:
                return None, rest
            equal = _github_equal(value, other)
            return (equal if tokens[0] == "==" else not equal), rest
        return value, tokens

    def _primary(self, tokens: list[str], needs: list[str]) -> tuple[Any, list[str]]:
        if not tokens:
            raise ValueError("an operand is missing")
        token, rest = tokens[0], tokens[1:]
        if token == "(":
            value, rest = self._or(rest, needs)
            if not rest or rest[0] != ")":
                raise ValueError("a parenthesis is not closed")
            return value, rest[1:]
        if token.startswith("'"):
            return token[1:-1].replace("''", "'"), rest
        if token in _LITERALS:
            return _LITERALS[token], rest
        if _NUMBER_TEXT.fullmatch(token):
            return float(token), rest
        return self._path(token, needs), rest

    def _path(self, token: str, needs: list[str]) -> Any:
        if token == "always()":
            return True
        if token == "cancelled()":
            return False
        if token == "success()":
            return self._success(needs)
        if token == "failure()":
            return self._failure(needs)
        parts = token.split(".")
        if parts[0] == "needs" and len(parts) >= 3:
            job = parts[1]
            if parts[2] == "result" and len(parts) == 3:
                return self.results.get(job)
            if parts[2] == "outputs" and len(parts) == 4 and job in self.called:
                return ""
            return None
        if parts[0] == "inputs" and len(parts) == 2:
            value = self.inputs.get(parts[1])
            # A value the caller gives as an expression is unknown before the run.
            return None if _is_expression(value) else value
        return None


class _StepCondition(_JobCondition):
    """A step's ``if`` before the run: ``inputs.<name>`` are the call's values as for a
    job, ``always()`` is true and ``cancelled()`` false, and ``success()`` and
    ``failure()`` are unknown, because at step level they read the steps before this
    one, which the plan does not run."""

    def _path(self, token: str, needs: list[str]) -> Any:
        if token in ("success()", "failure()"):
            return None
        return super()._path(token, needs)

    def step_runs(self, step: Mapping[str, Any]) -> bool | None:
        """True when the step's ``if`` reads true (or it has none), False when it reads
        false, None when it cannot be read before the run."""
        condition = step.get("if")
        if condition is None:
            return True
        if isinstance(condition, bool):
            return condition
        try:
            return _truth(self.evaluate(str(condition), []))
        except ValueError:
            return None


def _tokens(text: str) -> list[str]:
    tokens = []
    position = 0
    text = text.strip()
    while position < len(text):
        match = _EXPRESSION_TOKEN.match(text, position)
        if match is None or match.end() == position:
            raise ValueError(f"cannot read {text[position:]!r}")
        tokens.append(
            match["string"] or match["op"] or match["number"] or match["path"]
        )
        position = match.end()
    return tokens


def _truth(value: Any) -> bool | None:
    """GitHub's truth of an expression value: false, null (read as ''), the empty
    string, 0 and NaN are false; every other string is true, the strings 'false' and
    '0' included (a boolean input a caller writes in quotes is such a string); None is
    unknown."""
    if value is None:
        return None
    if isinstance(value, str):
        return value != ""
    if isinstance(value, float):
        return value != 0 and not math.isnan(value)
    return bool(value)


def _as_number(value: Any) -> float:
    """GitHub's coercion of an expression value to a number for a comparison of two
    values of different types: null and '' are 0, booleans 1 and 0, a string that
    reads as a number is that number and any other string is NaN."""
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if text == "":
        return 0.0
    if _NUMBER_TEXT.fullmatch(text):
        return float(text)
    return math.nan


def _github_equal(left: Any, right: Any) -> bool:
    """GitHub's loose equality: two strings compare without case; values of different
    types are both coerced to numbers (_as_number), and NaN equals nothing, so a
    boolean input compared to the string 'true' reads false."""
    if isinstance(left, str) and isinstance(right, str):
        return left.lower() == right.lower()
    if isinstance(left, bool) and isinstance(right, bool):
        return left == right
    a, b = _as_number(left), _as_number(right)
    if math.isnan(a) or math.isnan(b):
        return False
    return a == b


def _and_values(left: Any, right: Any) -> bool | None:
    """``left && right`` over GitHub truth, None where either side is unknown and the
    other is not false."""
    a, b = _truth(left), _truth(right)
    if a is False or b is False:
        return False
    return True if a and b else None


def _is_expression(value: Any) -> bool:
    """Whether a workflow value is written as a ``${{ }}`` expression, whose value the
    plan cannot know before the run."""
    return isinstance(value, str) and "${{" in value


#: The status functions of a job-level ``if``; an ``if`` naming none of them is read
#: with an implicit ``success() &&`` in front, as GitHub and act read it.
_STATUS_FUNCTIONS = frozenset({"success()", "failure()", "always()", "cancelled()"})


def _expression_body(text: str) -> str:
    """``text`` without the ``${{ }}`` around it, when it has one."""
    wrapped = _EXPRESSION_WRAP.match(text)
    return wrapped["body"] if wrapped else text


def _needs_of(job: Mapping[str, Any]) -> list[str]:
    needs = job.get("needs")
    return [str(needs)] if isinstance(needs, str) else [str(n) for n in needs or []]


def call_inputs(job: Mapping[str, Any], target: Mapping[str, Any]) -> dict[str, Any]:
    """The inputs a call of reusable workflow ``target`` gives: the caller's ``with``
    over the workflow's declared defaults."""
    declared = ((target.get("on") or {}).get("workflow_call") or {}).get("inputs")
    inputs: dict[str, Any] = {}
    for name, spec in (declared or {}).items() if isinstance(declared, Mapping) else []:
        if isinstance(spec, Mapping) and "default" in spec:
            inputs[str(name)] = spec["default"]
    given = job.get("with")
    if isinstance(given, Mapping):
        inputs.update({str(name): value for name, value in given.items()})
    return inputs


def _in_dependency_order(
    jobs: Mapping[str, Any],
) -> list[tuple[str, Mapping[str, Any]]]:
    """The jobs with each one after the jobs it needs; an unknown or cyclic need is
    kept in file order after the rest."""
    pending = [(str(k), v) for k, v in jobs.items() if isinstance(v, Mapping)]
    ordered: list[tuple[str, Mapping[str, Any]]] = []
    done: set[str] = set()
    while pending:
        progress = False
        for job_id, job in list(pending):
            needs = job.get("needs")
            needs = [needs] if isinstance(needs, str) else list(needs or [])
            if all(
                str(need) in done or str(need) not in dict(pending) for need in needs
            ):
                ordered.append((job_id, job))
                done.add(job_id)
                pending.remove((job_id, job))
                progress = True
        if not progress:
            ordered += pending
            break
    return ordered


def act_job_plan(
    workflow: Mapping[str, Any], called: Mapping[str, Mapping[str, Any]]
) -> dict[str, JobPlan]:
    """Every job act runs for ``workflow``, keyed by the job id act reports.

    A job that calls a reusable workflow runs that workflow's jobs, which act reports
    under the called workflow's own job ids; ``called`` holds the called workflows by
    file name. A job GitHub does not start is left out: one whose ``needs`` include a
    job planned to fail and that has no ``if`` admitting that (``always()``,
    ``!cancelled()``, ``failure()``), one whose ``if`` reads false from what the plan
    knows (``needs.<job>.result``, ``inputs.<name>`` of a reusable call), and one whose
    ``if`` reads the outputs of a job that calls a reusable workflow, which act does
    not deliver. A call of a workflow that is not in ``called``, a nested call, and two
    jobs that would report under one id are errors naming them.
    """
    plan: dict[str, JobPlan] = {}
    missing = []
    results: dict[str, str] = {}
    callers: set[str] = set()
    jobs = workflow.get("jobs") or {}
    needs_of = {str(k): _needs_of(v) for k, v in jobs.items() if isinstance(v, Mapping)}

    def add(job_id: str, entry: JobPlan) -> None:
        if job_id in plan:
            raise ValueError(
                f"two jobs would report as {job_id}: "
                f"{plan[job_id].caller or job_id} and {entry.caller or job_id}"
            )
        plan[job_id] = entry

    for job_id, job in _in_dependency_order(jobs):
        uses = str(job.get("uses") or "")
        runs = matrix_runs(job)
        if not _JobCondition(results, callers, needs_of=needs_of).runs(job):
            results[job_id] = "skipped"
            continue
        if not uses:
            gates = _job_gates(job)
            result = "failure" if gates else "success"
            results[job_id] = result
            add(job_id, JobPlan(result, runs, gates))
            continue
        callers.add(job_id)
        name = PurePosixPath(uses.split("@", 1)[0]).name
        target = called.get(name)
        if target is None:
            missing.append(f"job {job_id} calls {uses}")
            continue
        inputs = call_inputs(job, target)
        called_results: dict[str, str] = {}
        called_jobs = target.get("jobs") or {}
        called_needs = {
            str(k): _needs_of(v)
            for k, v in called_jobs.items()
            if isinstance(v, Mapping)
        }
        for called_id, called_job in _in_dependency_order(called_jobs):
            if called_job.get("uses"):
                raise ValueError(
                    f"{name}'s job {called_id} calls another workflow, "
                    f"{called_job['uses']}"
                )
            condition = _JobCondition(
                called_results, inputs=inputs, needs_of=called_needs
            )
            if not condition.runs(called_job):
                called_results[called_id] = "skipped"
                continue
            if name == SCAN_WORKFLOW:
                gates = _input_on(job.get("with"), "fail-on-findings") and any(
                    _RUNS_ASH.search(str(step.get("run", "")))
                    for step in _steps(called_job)
                )
            else:
                gates = _job_gates(called_job)
            result = "failure" if gates else "success"
            called_results[called_id] = result
            add(
                called_id,
                JobPlan(
                    result,
                    runs * matrix_runs(called_job),
                    gates,
                    caller=job_id,
                    workflow=name,
                    inputs=inputs,
                ),
            )
        # The caller's own result is the called workflow's: failed when any of its
        # jobs did (GitHub), which is what a dependent of the caller reads.
        results[job_id] = (
            "failure" if "failure" in called_results.values() else "success"
        )
    if missing:
        raise ValueError(
            "the workflows a block calls must be copied into the fixture: "
            + "; ".join(missing)
        )
    return plan


def expected_act_results(
    workflow: Mapping[str, Any], called: Mapping[str, Mapping[str, Any]] | None = None
) -> dict[str, str]:
    """The result act should report for each job id of ``workflow`` and its calls."""
    return {
        job: entry.result for job, entry in act_job_plan(workflow, called or {}).items()
    }


#: A shell heredoc in a step's ``run``: its body is a file the step writes, not a
#: command the step runs.
_HEREDOC = re.compile(
    r"<<-?[ \t]*(?P<quote>['\"]?)(?P<tag>\w+)(?P=quote)[^\n]*\n.*?\n[ \t]*(?P=tag)"
    r"[ \t]*(?=\n|$)",
    re.DOTALL,
)
#: A command line that runs the stop-commands wrapper the scan workflow's helper
#: file defines, ``with_commands_stopped <command>``; the line that defines the
#: function, ``with_commands_stopped() {``, is not one.
_WRAPPER_CALL = re.compile(
    r"(?m)^[ \t]*(?:\w+=\S*[ \t]+)*with_commands_stopped(?![\w(])"
)
_STOP_COMMANDS = "::stop-commands::"


def wraps_commands(run: str) -> bool:
    """Whether a step's ``run`` stops workflow commands around a command: it prints
    ``::stop-commands::`` itself, or calls ``with_commands_stopped``.

    A heredoc's body is left out: the scan workflow's helper step writes the wrapper's
    definition, ``printf '::stop-commands::...'`` included, to a file through one, and
    prints nothing itself.
    """
    text = _HEREDOC.sub("", run)
    return _STOP_COMMANDS in text or bool(_WRAPPER_CALL.search(text))


def wrapped_job_steps(workflows: Iterable[Mapping[str, Any]]) -> list[tuple[str, str]]:
    """(job id, step name) of each step that stops workflow commands around its
    command (wraps_commands), in order.

    A wrapped step without a name is an error: act names an unnamed step after its
    command, so its log could not be matched to it.
    """
    pairs: list[tuple[str, str]] = []
    for workflow in workflows:
        for job_id, job in (workflow.get("jobs") or {}).items():
            if not isinstance(job, Mapping):
                continue
            for step in _steps(job):
                if not wraps_commands(str(step.get("run", ""))):
                    continue
                if not step.get("name"):
                    raise ValueError(
                        f"job {job_id} has a step that stops workflow commands and has "
                        "no name"
                    )
                pair = (str(job_id), str(step["name"]))
                if pair not in pairs:
                    pairs.append(pair)
    return pairs


def conditional_steps(
    workflow: Mapping[str, Any],
    called: Mapping[str, Mapping[str, Any]] | None = None,
) -> set[tuple[str, str]]:
    """(job id, step name) of each named step whose ``if`` reads false or cannot be
    read before the run (_StepCondition), in the workflow's own jobs and in those of
    each reusable workflow it calls, with the call's inputs (call_inputs) known.

    A step whose ``if`` reads true (``always()``, ``!cancelled()``, a known input that
    is on) is not in the set: it ran in every run of its job, and a log with no run of
    it is a problem, as for a step with no ``if``.
    """
    pairs: set[tuple[str, str]] = set()

    def collect(job_id: str, job: Mapping[str, Any], inputs: Mapping[str, Any]) -> None:
        condition = _StepCondition({}, inputs=inputs)
        for step in _steps(job):
            if step.get("name") and condition.step_runs(step) is not True:
                pairs.add((job_id, str(step["name"])))

    for job_id, job in (workflow.get("jobs") or {}).items():
        if not isinstance(job, Mapping):
            continue
        uses = str(job.get("uses") or "")
        if not uses:
            collect(str(job_id), job, {})
            continue
        target = (called or {}).get(PurePosixPath(uses.split("@", 1)[0]).name)
        if target is None:
            continue
        inputs = call_inputs(job, target)
        for called_id, called_job in (target.get("jobs") or {}).items():
            if isinstance(called_job, Mapping):
                collect(str(called_id), called_job, inputs)
    return pairs


def gating_step(workflow: Mapping[str, Any], command: str) -> tuple[str, str] | None:
    """(job, step name) of the first step that runs ``ash <command>``."""
    for job_id, job in (workflow.get("jobs") or {}).items():
        for step in (job or {}).get("steps") or []:
            run = str((step or {}).get("run", ""))
            if re.search(rf"(?<![\w.-])ash{_ASH_SPACE}{command}\b", run):
                return str(job_id), str(step.get("name") or "")
    return None


#: ``${{ inputs.<name> }}``, and the scan workflow's ``${{ steps.inputs.outputs.<name>
#: }}``: its input-checking step copies every input to an output of the same name
#: with ``-`` as ``_``.
_INPUT_EXPRESSION = re.compile(
    r"\$\{\{\s*(?:inputs\.(?P<input>[\w-]+)|steps\.inputs\.outputs\.(?P<output>\w+))"
    r"\s*\}\}"
)


def resolve_inputs(text: str, inputs: Mapping[str, Any]) -> str:
    """``text`` with each ``${{ inputs.<name> }}`` replaced by the call's value of that
    input (call_inputs), and each ``${{ steps.inputs.outputs.<name> }}`` by the value
    of the input of that name, ``_`` read as ``-``. An expression with no value stays
    as written, so its reader can say so."""

    def replace(match: re.Match[str]) -> str:
        if match["input"] is not None:
            candidates = [match["input"]]
        else:
            candidates = [match["output"], match["output"].replace("_", "-")]
        for name in candidates:
            if name in inputs:
                return str(inputs[name])
        return match.group(0)

    return _INPUT_EXPRESSION.sub(replace, text)


def uploaded_artifact_names(
    workflow: Mapping[str, Any],
    called: Mapping[str, Mapping[str, Any]] | None = None,
    plan: Mapping[str, JobPlan] | None = None,
) -> list[str]:
    """The artifact names the workflow's upload-artifact steps use, per matrix run,
    and those of each reusable workflow it calls, with the call's inputs resolved
    (resolve_inputs). With ``plan``, only the jobs the plan expects to run count."""
    names: list[str] = []

    def collect(job: Mapping[str, Any], inputs: Mapping[str, Any]) -> None:
        matrix = ((job.get("strategy") or {}).get("matrix")) or {}
        for step in _steps(job):
            if not str(step.get("uses", "")).startswith("actions/upload-artifact@"):
                continue
            name = str((step.get("with") or {}).get("name") or "artifact")
            for expanded in _expand_matrix(resolve_inputs(name, inputs), matrix):
                if expanded not in names:
                    names.append(expanded)

    for job_id, job in (workflow.get("jobs") or {}).items():
        if not isinstance(job, Mapping):
            continue
        uses = str(job.get("uses") or "")
        if not uses:
            if plan is None or str(job_id) in plan:
                collect(job, {})
            continue
        target = (called or {}).get(PurePosixPath(uses.split("@", 1)[0]).name)
        if target is None:
            continue
        inputs = call_inputs(job, target)
        for called_id, called_job in (target.get("jobs") or {}).items():
            if not isinstance(called_job, Mapping):
                continue
            if plan is None or str(called_id) in plan:
                collect(called_job, inputs)
    return names


#: The code scanning upload action, as a step of the block's own job or of the SARIF
#: upload workflow.
_UPLOAD_SARIF_ACTION = "github/codeql-action/upload-sarif@"


def sarif_upload_expected(
    plan: Mapping[str, JobPlan],
    event: str | None,
    workflow: Mapping[str, Any] | None = None,
) -> bool:
    """Whether the planned run uploads ASH's SARIF report: a planned job of the block
    itself runs the upload action as a step (the sharded page's merge job), a job of
    the SARIF upload workflow is planned, or a call of the scan workflow leaves
    ``collect-sarif-report`` on and the event is a pull request, the one event its own
    upload step runs on."""
    jobs = (workflow or {}).get("jobs") or {}
    for job_id, entry in plan.items():
        if entry.workflow is None:
            job = jobs.get(job_id)
            if isinstance(job, Mapping) and any(
                str(step.get("uses", "")).startswith(_UPLOAD_SARIF_ACTION)
                for step in _steps(job)
            ):
                return True
            continue
        if entry.workflow == SARIF_WORKFLOW:
            return True
        if entry.workflow == SCAN_WORKFLOW and event == "pull_request":
            value = (entry.inputs or {}).get("collect-sarif-report", True)
            # An input given as an expression is unknown before the run, and an
            # unknown input keeps the upload expected, so a missing one is named.
            if _truth(None if _is_expression(value) else value) is not False:
                return True
    return False


def _expand_matrix(name: str, matrix: Mapping[str, Any]) -> list[str]:
    keys = _MATRIX.findall(name)
    if not keys:
        return [name]
    values = [matrix.get(key) for key in keys]
    if not all(isinstance(v, list) and v for v in values):
        return [name]
    expanded = [name]
    for key, options in zip(keys, values):
        pattern = re.compile(r"\$\{\{\s*matrix\." + re.escape(key) + r"\s*\}\}")
        expanded = [
            pattern.sub(str(option), item) for item in expanded for option in options
        ]
    return expanded


def _holds_something(path: Path) -> bool:
    if path.is_symlink():
        return False
    if path.is_file():
        return True
    return path.is_dir() and any(p.is_file() for p in path.rglob("*"))


def artifact_problems(artifact_dir: Path, names: Iterable[str]) -> list[str]:
    """Each named artifact must be in act's artifact store, and hold something.

    act's store keeps each artifact under its name, as a directory or a ``.zip``.
    """
    artifact_dir = Path(artifact_dir)
    names = list(names)
    if not artifact_dir.is_dir():
        return [f"act's artifact store {artifact_dir} is missing"] if names else []
    problems = []
    for name in names:
        candidates = [*artifact_dir.rglob(name), *artifact_dir.rglob(f"{name}.zip")]
        if not any(_holds_something(path) for path in candidates):
            problems.append(
                f"act's artifact store {artifact_dir} holds no artifact {name}"
            )
    return problems


#: The SARIF report ASH writes beside its aggregated results, for code scanning.
GHAS_SARIF = PurePosixPath("reports") / "ash.ghas.sarif"


@dataclass(frozen=True)
class ArtifactResults:
    """ASH's aggregated results as one artifact in act's store holds them.

    ``name`` is the artifact's name in the store: the stem of its ``.zip``, or the
    directory holding the results file. ``where`` names the results themselves, as
    ``aggregated_results_in`` does (``<zip>!<member>`` for a zipped copy). ``sarif`` is
    the bytes of ``reports/ash.ghas.sarif`` beside the results, or None when the
    artifact holds none. ``mtime`` is when the store entry was written: the zip's, or
    the stored results file's. ``source`` is the zip, or the stored results file, and
    ``member`` the results file's name inside the zip (None for a stored file); the
    two are what ``unpack_artifact`` reads. ``entry`` is the store entry the results
    came from, the artifact's own directory under the store (``<store>/<run>/<name>``),
    set by ``results_from_artifact_store`` for a stored copy; it is what groups the
    copies one artifact holds (``artifact_key``).
    """

    name: str
    where: str
    aggregated: dict[str, Any]
    sarif: bytes | None
    mtime: float
    source: Path
    member: str | None = None
    entry: str | None = None


def artifact_key(results: ArtifactResults) -> str:
    """The store entry the results came from: the zip, or the artifact's directory in
    the store for a stored results file (``entry``, else the file's own directory);
    two results with one key are copies inside one artifact."""
    source = Path(results.source)
    if results.member is not None:
        return str(source)
    return results.entry if results.entry is not None else str(source.parent)


def _zipped_results(path: Path, depth: int) -> list[tuple[int, ArtifactResults]]:
    found: list[tuple[int, ArtifactResults]] = []
    try:
        mtime = path.stat().st_mtime
        with zipfile.ZipFile(path) as archive:
            members = archive.namelist()
            for member in members:
                if PurePosixPath(member).name != AGGREGATED:
                    continue
                sarif_member = str(PurePosixPath(member).parent / GHAS_SARIF)
                found.append(
                    (
                        depth + len(PurePosixPath(member).parts),
                        ArtifactResults(
                            name=path.stem,
                            where=f"{path}!{member}",
                            aggregated=json.loads(archive.read(member)),
                            sarif=archive.read(sarif_member)
                            if sarif_member in members
                            else None,
                            mtime=mtime,
                            source=path,
                            member=member,
                        ),
                    )
                )
    except _ZIP_ERRORS:
        return []
    return found


def _stored_results(path: Path, depth: int) -> list[tuple[int, ArtifactResults]]:
    aggregated = aggregated_results_at(path)
    if not aggregated:
        return []
    where, data = aggregated[0]
    sarif_path = path.parent / Path(*GHAS_SARIF.parts)
    sarif = None
    if not sarif_path.is_symlink() and sarif_path.is_file():
        try:
            sarif = sarif_path.read_bytes()
        except OSError:
            sarif = None
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return []
    return [
        (
            depth,
            ArtifactResults(
                name=path.parent.name,
                where=where,
                aggregated=data,
                sarif=sarif,
                mtime=mtime,
                source=path,
            ),
        )
    ]


def results_from_artifact_store(store: Path) -> list[ArtifactResults] | None:
    """The aggregated results the artifacts in act's store hold, or None if none does.

    act's host executor writes the scan's output under a cache copy of the project,
    not under the project's ``.ash/ash_output``, so what a run produced is read from
    the artifact the job uploaded, which the store keeps under the artifact's name as
    a directory or a ``.zip`` (the walk ``artifact_problems`` makes). As in
    ``aggregated_results_in``, the copies nearest the top of the store are the
    artifacts' own, and all of them at that depth are returned, in path order, so a
    sharded page's ``ash-shard-0`` to ``ash-shard-3`` come back as four entries and
    the caller judges them. A store that does not exist holds no results.
    """
    store = Path(store)
    if not store.is_dir():
        return None
    found: list[tuple[int, ArtifactResults]] = []
    for path in sorted(store.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        parts = path.relative_to(store).parts
        depth = len(parts)
        if path.name == AGGREGATED:
            # The artifact's own directory, <store>/<run>/<name>: the copies a
            # workspace scan's upload holds under projects/* share it.
            entry = (
                str(store.joinpath(*parts[: min(2, depth - 1)])) if depth > 1 else None
            )
            found += [
                (found_depth, replace(results, entry=entry))
                for found_depth, results in _stored_results(path, depth)
            ]
        elif path.suffix == ".zip":
            found += _zipped_results(path, depth)
    if not found:
        return None
    top = min(depth for depth, _ in found)
    return [results for depth, results in found if depth == top]


#: The word in an artifact's name that marks it as a merge job's output: the sharded
#: page uploads its merged reports and results as ``ash-merged``, beside the shards'
#: ``ash-shard-<n>``.
MERGED_WORD = "merged"
_NAME_WORDS = re.compile(r"[-_.]")


def is_merged_artifact(name: str) -> bool:
    """Whether an artifact's name marks it as the merged output, by the word
    ``merged`` between dashes, underscores or dots (``ash-merged``, ``ash_merged.zip``),
    not by a substring (``unmerged`` is not it)."""
    return MERGED_WORD in _NAME_WORDS.split(name.lower())


def results_to_judge(
    found: list[ArtifactResults] | None,
) -> tuple[ArtifactResults | None, list[str]]:
    """Which of a store's results the run is judged on, and why none when none.

    The copies are grouped by the store entry they came from (``artifact_key``), so
    one artifact holding two results files at one depth (a workspace scan's
    ``projects/*/ash_aggregated_results.json`` uploaded without the top-level file)
    is reported as that, apart from a run that kept several artifacts. One artifact
    with one results file is the run's output. Several artifacts are a sharded run,
    and the one whose name marks it as the merged output is judged; without one the
    shards are named, because the findings and the SARIF the merge wrote are then in
    no artifact. None is the missing-results problem, in ``findings_problems``'s
    words.
    """
    if not found:
        return None, findings_problems([], {})
    by_artifact: dict[str, list[ArtifactResults]] = {}
    for results in found:
        by_artifact.setdefault(artifact_key(results), []).append(results)
    crowded = [copies for copies in by_artifact.values() if len(copies) > 1]
    if crowded:
        return None, [
            (
                f"the artifact {copies[0].name} holds {len(copies)} copies of "
                f"{AGGREGATED} at one depth ({', '.join(c.where for c in copies)}), "
                "so none of them is the run's own results file"
            )
            for copies in crowded
        ]
    artifacts = [copies[0] for copies in by_artifact.values()]
    if len(artifacts) == 1:
        return artifacts[0], []
    merged = [results for results in artifacts if is_merged_artifact(results.name)]
    if len(merged) == 1:
        return merged[0], []
    names = ", ".join(results.name for results in artifacts)
    if merged:
        return None, [
            f"{len(merged)} artifacts are named as the merged output: "
            + ", ".join(results.name for results in merged)
            + f" (the run kept {len(artifacts)} artifacts with results: {names})"
        ]
    return None, [
        (
            f"the run kept {len(artifacts)} artifacts with results ({names}) and "
            "none named as the merged output, so the merge job uploaded no artifact "
            "and its findings and SARIF are in none"
        )
    ]


#: The zip "extended timestamp" extra field, which carries a member's mtime to the
#: second as a POSIX time. Without it a member has only the zip's own date_time: a
#: calendar time with 2-second resolution and no zone, which upload-artifact's zip
#: writer (the archiver stack of @actions/artifact) records as UTC and without this
#: field. Measured on the zips act's artifact server stored for two hosted legs
#: (upload-artifact v4.6.2 under act 0.2.89, 2026-10-29): every member carries
#: date_time only, and that date_time is the FILE's own mtime, not the time the writer
#: added it: the results of a single-job run read 23:51:06Z, the second its scan step
#: ended, while its upload step started 23:51:09Z; each shard's members read the second
#: its scan ended, 2 to 4 s before its upload step; the merged results read 23:49:36Z
#: and the reports 23:49:38Z, under the merge job's own upload step. So a written-after
#: check on an unpacked member reads when ASH wrote the file, to 2 s, and a stale file
#: the merge left in place would carry its earlier mtime and fail it.
_EXTENDED_TIMESTAMP = 0x5455


def _zip_mtime(info: zipfile.ZipInfo) -> float:
    """A zip member's mtime as a POSIX time: the extended timestamp when the entry
    carries one, else its date_time read as UTC, whatever the reader's own zone."""
    extra = info.extra
    while len(extra) >= 4:
        tag, size = struct.unpack("<HH", extra[:4])
        data, extra = extra[4 : 4 + size], extra[4 + size :]
        if tag == _EXTENDED_TIMESTAMP and len(data) >= 5 and data[0] & 1:
            return float(struct.unpack("<i", data[1:5])[0])
    return float(calendar.timegm((*info.date_time, 0, 0, 0)))


def unpack_artifact(results: ArtifactResults, target: Path) -> tuple[Path, list[str]]:
    """Unpack the artifact's output under ``target``; return the directory that holds
    its ``ash_aggregated_results.json``, with every file's own mtime, and the problems.

    act's host executor runs each job in a directory it removes at the job's end, so
    the uploaded artifact is the only copy of ASH's output; the checks that read a
    path (the SARIF the upload stub was given; whether the results were written after
    the merge step started) read this copy. A zipped artifact is extracted member by
    member, those under the results file's own directory in the zip, each with the
    mtime its entry records; a stored directory is copied with its files' mtimes and
    without its symbolic links. An artifact that cannot be unpacked (a zip that
    changed or broke since it was read, a file that cannot be read or written) is one
    problem naming it, and the directory is returned as far as it got, so the checks
    that read it still run and report what is missing.
    """
    target = Path(target)
    if results.member is None:
        output = target
    else:
        output = target.joinpath(*PurePosixPath(results.member).parent.parts)
    try:
        if results.member is None:
            _copy_stored_artifact(Path(results.source).parent, target)
        else:
            _extract_zipped_artifact(results, target)
    except _ZIP_ERRORS as error:
        return output, [
            (
                f"the artifact {results.name} ({results.where}) could not be "
                f"unpacked: {error}"
            )
        ]
    return output, []


def _copy_stored_artifact(source: Path, target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    for directory, dirs, files in os.walk(source):
        here = Path(directory)
        dirs[:] = [d for d in dirs if not (here / d).is_symlink()]
        (target / here.relative_to(source)).mkdir(parents=True, exist_ok=True)
        for name in files:
            path = here / name
            if not path.is_symlink() and path.is_file():
                shutil.copy2(path, target / path.relative_to(source))


def _extract_zipped_artifact(results: ArtifactResults, target: Path) -> None:
    prefix = PurePosixPath(results.member or "").parent.parts
    with zipfile.ZipFile(results.source) as archive:
        for info in archive.infolist():
            if (
                info.is_dir()
                or PurePosixPath(info.filename).parts[: len(prefix)] != prefix
            ):
                continue
            extracted = archive.extract(info, target)
            mtime = _zip_mtime(info)
            os.utime(extracted, (mtime, mtime))


_ASH_NAME = r"automated[-_]security[-_]helper"
#: A download of ASH from a package index: its URL, pip's ``Downloading <file>`` and
#: uv's ``Downloading <name> (<size>)``.
_INDEX_DOWNLOAD = re.compile(
    rf"(?:files\.pythonhosted\.org|pypi\.org)\S*{_ASH_NAME}"
    rf"|\bDownloading\s+{_ASH_NAME}",
    re.IGNORECASE,
)
#: uv's summary line of an installed distribution: `` + <name>==<version>``.
_UV_INSTALLED = re.compile(rf"(?:^|\s)\+\s+{_ASH_NAME}==\S+", re.IGNORECASE)
_UV_FROM_UNDER_TEST = re.compile(r"\(from (?:file://|git\+)")


def index_download_problems(log: str) -> list[str]:
    """The log must not show ASH fetched from a package index; the runs install only the
    wheel or the commit under test.

    Seen: an index URL naming ASH, pip's and uv's ``Downloading`` line for it, and uv's
    `` + automated-security-helper==<version>`` without ``(from file://...)`` or
    ``(from git+...)``, which is how uv lists a distribution it took from an index.
    """
    for text in log_texts(log):
        index = _INDEX_DOWNLOAD.search(text)
        uv = _UV_INSTALLED.search(text)
        if index or (uv and not _UV_FROM_UNDER_TEST.search(text)):
            return [
                f"the log shows ASH fetched from a package index: {text.strip()[:200]}"
            ]
    return []


def tail(path: Path, lines: int = 20, chars: int = TAIL_CHARS) -> str:
    """The end of ``path`` for a failure message: its last ``lines`` lines, and at most
    ``chars`` characters of them."""
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        return f"({path} cannot be read: {error})"
    end = "\n".join(text.splitlines()[-lines:])
    return end[-chars:] if chars > 0 else ""
