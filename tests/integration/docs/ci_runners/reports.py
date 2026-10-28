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

import json
import os
import re
import shutil
import xml.etree.ElementTree as ET
import zipfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from .verdict import log_texts

AGGREGATED = "ash_aggregated_results.json"
DEFAULT_THRESHOLD = "MEDIUM"
#: ASH's reusable scan workflow, whose scan job gates on its caller's input.
SCAN_WORKFLOW = "run-ash-security-scan.yml"
#: How many characters of a log a failure message quotes at most.
TAIL_CHARS = 4000

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
            except (OSError, ValueError, zipfile.BadZipFile):
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
    """(tests, failed tests) over every JUnit XML file under ``root``.

    A test failed when it has a ``failure`` or an ``error``. A file that is not JUnit
    XML counts nothing.
    """
    tests = failures = 0
    root = Path(root)
    if not root.is_dir():
        return 0, 0
    for path in sorted(root.rglob("*.xml")):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            document = ET.parse(path).getroot()
        except (OSError, ET.ParseError):
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
    from, or None for a job of the block itself.
    """

    result: str
    runs: int
    gates: bool
    caller: str | None = None


def act_job_plan(
    workflow: Mapping[str, Any], called: Mapping[str, Mapping[str, Any]]
) -> dict[str, JobPlan]:
    """Every job act runs for ``workflow``, keyed by the job id act reports.

    A job that calls a reusable workflow runs that workflow's jobs, which act reports
    under the called workflow's own job ids; ``called`` holds the called workflows by
    file name. A call of a workflow that is not in ``called``, a nested call, and two
    jobs that would report under one id are errors naming them.
    """
    plan: dict[str, JobPlan] = {}
    missing = []

    def add(job_id: str, entry: JobPlan) -> None:
        if job_id in plan:
            raise ValueError(
                f"two jobs would report as {job_id}: "
                f"{plan[job_id].caller or job_id} and {entry.caller or job_id}"
            )
        plan[job_id] = entry

    for job_id, job in (workflow.get("jobs") or {}).items():
        if not isinstance(job, Mapping):
            continue
        uses = str(job.get("uses") or "")
        runs = matrix_runs(job)
        if not uses:
            gates = _job_gates(job)
            add(str(job_id), JobPlan("failure" if gates else "success", runs, gates))
            continue
        name = PurePosixPath(uses.split("@", 1)[0]).name
        target = called.get(name)
        if target is None:
            missing.append(f"job {job_id} calls {uses}")
            continue
        for called_id, called_job in (target.get("jobs") or {}).items():
            if not isinstance(called_job, Mapping):
                continue
            if called_job.get("uses"):
                raise ValueError(
                    f"{name}'s job {called_id} calls another workflow, "
                    f"{called_job['uses']}"
                )
            if name == SCAN_WORKFLOW:
                gates = _input_on(job.get("with"), "fail-on-findings") and any(
                    _RUNS_ASH.search(str(step.get("run", "")))
                    for step in _steps(called_job)
                )
            else:
                gates = _job_gates(called_job)
            add(
                str(called_id),
                JobPlan(
                    "failure" if gates else "success",
                    runs * matrix_runs(called_job),
                    gates,
                    caller=str(job_id),
                ),
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


def wrapped_job_steps(workflows: Iterable[Mapping[str, Any]]) -> list[tuple[str, str]]:
    """(job id, step name) of each step that prints ``::stop-commands::`` around its
    command, in order.

    A wrapped step without a name is an error: act names an unnamed step after its
    command, so its log could not be matched to it.
    """
    pairs: list[tuple[str, str]] = []
    for workflow in workflows:
        for job_id, job in (workflow.get("jobs") or {}).items():
            if not isinstance(job, Mapping):
                continue
            for step in _steps(job):
                if "::stop-commands::" not in str(step.get("run", "")):
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


def gating_step(workflow: Mapping[str, Any], command: str) -> tuple[str, str] | None:
    """(job, step name) of the first step that runs ``ash <command>``."""
    for job_id, job in (workflow.get("jobs") or {}).items():
        for step in (job or {}).get("steps") or []:
            run = str((step or {}).get("run", ""))
            if re.search(rf"(?<![\w.-])ash{_ASH_SPACE}{command}\b", run):
                return str(job_id), str(step.get("name") or "")
    return None


def uploaded_artifact_names(workflows: Iterable[Mapping[str, Any]]) -> list[str]:
    """The artifact names the workflows' upload-artifact steps use, per matrix run."""
    names: list[str] = []
    for workflow in workflows:
        for job in (workflow.get("jobs") or {}).values():
            if not isinstance(job, Mapping):
                continue
            matrix = ((job.get("strategy") or {}).get("matrix")) or {}
            for step in job.get("steps") or []:
                if not isinstance(step, Mapping):
                    continue
                if not str(step.get("uses", "")).startswith("actions/upload-artifact@"):
                    continue
                name = str((step.get("with") or {}).get("name") or "artifact")
                for expanded in _expand_matrix(name, matrix):
                    if expanded not in names:
                        names.append(expanded)
    return names


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
