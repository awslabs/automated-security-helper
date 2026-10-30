# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What a CI runner says happened, read from its log and the files it leaves.

A failed pipeline is not proof that ASH found something: it fails just as well when the
install step breaks. So a run is judged on two things that must agree: the runner's
own result (act's ``jobResult`` per job and matrix run, the exit code of the others, the
BUILD phase's state for the CodeBuild agent), and ASH's verdict line,
``ERROR (2) Exiting due to <n> actionable findings found in ASH scan`` (``... across the
merged shards`` for ``ash merge``). A run without that line is VERDICT_MISSING.

Logs are read as the runners write them: act's ``--json`` lines (the output text is
each entry's ``msg``), and plain logs with ANSI color codes, carriage returns and a
container-name prefix on every line. Lines are matched anywhere, never anchored.

Every check reads the raw lines of the log. None depends on act acting on a workflow
command (an ``::error::`` annotation, an output, a mask): act keeps the stop-commands
state of ``::stop-commands::`` for the rest of the job where GitHub keeps it for one
step, so under act a command may be ignored that GitHub would act on, or the other way
round. resume_token_problems checks that each step that stops commands also prints
its resume line, on a line of its own.

Standard library only, so check_junit.py can load it on its own.
"""

from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

VERDICT_MISSING = "ASH verdict line missing"
#: The exit code ASH's verdict line gives for actionable findings.
FINDINGS_EXIT_CODE = 2

_ANSI = re.compile(
    r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]"
)
_SCAN = re.compile(
    r"ERROR \((\d+)\) Exiting due to (\d+) actionable findings? found in ASH scan"
)
_MERGE = re.compile(
    r"ERROR \((\d+)\) Exiting due to (\d+) actionable findings? across the merged shards"
)
_PHASE = re.compile(r"Phase complete:\s*([A-Z_]+)\s+State:\s*([A-Z_]+)")
_FRACTION = re.compile(r"(\.\d{6})\d+")
#: act's step boundaries in its ``--json`` messages.
_STEP_START = re.compile(r"^⭐\s*Run Main (?P<step>.+?)\s*$")
_STEP_END = re.compile(
    r"^(?:✅|❌)\s*(?:Success|Failure) - Main (?P<step>.+?)(?:\s+\[[^\]]*\])?\s*$"
)
#: What act and the shell put in front of a command or an output line.
_LINE_PREFIX = re.compile(r"^[\s|⚙❓]*")
_STOP_COMMANDS = "::stop-commands::"


@dataclass(frozen=True)
class Verdict:
    code: int
    actionable: int
    source: str


@dataclass(frozen=True)
class ActJobResult:
    job: str
    matrix: dict = field(default_factory=dict)
    result: str = ""


def _entries(log: str) -> Iterator[dict | None]:
    """Each line of ``log`` as an act JSON entry, or None for a plain line."""
    for line in log.splitlines():
        stripped = line.strip()
        if stripped.startswith("{"):
            try:
                entry = json.loads(stripped)
            except ValueError:
                entry = None
            if isinstance(entry, dict):
                yield entry
                continue
        yield None


def _segments(text: str) -> Iterator[str]:
    for segment in text.split("\r"):
        yield _ANSI.sub("", segment)


def log_texts(log: str) -> Iterator[str]:
    """The text of every line, ANSI codes removed, each carriage-return segment apart.

    For an act JSON line the text is its ``msg``; for any other line, the line.
    """
    for line, entry in zip(log.splitlines(), _entries(log)):
        text = entry.get("msg") if entry is not None else line
        if not isinstance(text, str):
            continue
        yield from _segments(text)


_texts = log_texts


def log_lines(log: str) -> Iterator[tuple[str, str]]:
    """Each line's text, as log_texts gives it, and where it came from.

    ``"step"`` for what a step printed, which act marks ``raw_output`` in its
    ``--json`` log; ``"act"`` for act's own messages (a step's start and result, the
    job's, act's errors); ``"plain"`` for a line that is not an act entry, as every
    line of the other runners' logs is.
    """
    for line, entry in zip(log.splitlines(), _entries(log)):
        if entry is None:
            text, kind = line, "plain"
        else:
            text = entry.get("msg")
            kind = "step" if entry.get("raw_output") is True else "act"
        if not isinstance(text, str):
            continue
        for segment in _segments(text):
            yield segment, kind


def _act_run(entry: Mapping | None) -> tuple[str, str]:
    """(job id, matrix as sorted JSON) of an act entry; ("", "{}") for a plain line."""
    if entry is None:
        return "", "{}"
    matrix = entry.get("matrix")
    return (
        str(entry.get("jobID") or entry.get("job") or ""),
        json.dumps(dict(matrix) if isinstance(matrix, Mapping) else {}, sort_keys=True),
    )


def act_log_groups(log: str) -> dict[tuple[str, str], list[str]]:
    """The raw lines of act's ``--json`` log by (job id, matrix as sorted JSON).

    A line that is not an act entry is kept under ("", "{}").
    """
    groups: dict[tuple[str, str], list[str]] = {}
    for line, entry in zip(log.splitlines(), _entries(log)):
        groups.setdefault(_act_run(entry), []).append(line)
    return groups


def _verdicts_in(text: str) -> list[Verdict]:
    verdicts = []
    for pattern, source in ((_SCAN, "scan"), (_MERGE, "merge")):
        for match in pattern.finditer(text):
            verdicts.append(Verdict(int(match[1]), int(match[2]), source))
    return verdicts


def ash_verdicts(log: str) -> list[Verdict]:
    """ASH's verdict lines in ``log``, in order."""
    verdicts = []
    for text in _texts(log):
        verdicts += _verdicts_in(text)
    return verdicts


def gitlab_job_verdicts(
    log: str, jobs: Iterable[str]
) -> dict[str | None, list[Verdict]]:
    """ASH's verdicts in gitlab-ci-local's log, by the job of ``jobs`` whose output
    line holds each.

    gitlab-ci-local prints a job's output line as ``<job name, padded> > <line>``. A
    verdict on a line without a known job's prefix is kept under None.
    """
    names = sorted(jobs, key=len, reverse=True)
    prefixes = [(name, re.compile(rf"^\s*{re.escape(name)}\s+>\s")) for name in names]
    found: dict[str | None, list[Verdict]] = {}
    for text in _texts(log):
        verdicts = _verdicts_in(text)
        if not verdicts:
            continue
        job = next((name for name, prefix in prefixes if prefix.match(text)), None)
        found.setdefault(job, []).extend(verdicts)
    return found


def _verdict_value_problems(
    verdict: Verdict, actionable: int | None, where: str = ""
) -> list[str]:
    problems = []
    if verdict.code != FINDINGS_EXIT_CODE:
        problems.append(
            f"ASH's verdict line{where} exits {verdict.code}, not "
            f"{FINDINGS_EXIT_CODE}, the code for actionable findings"
        )
    if actionable is not None and verdict.actionable != actionable:
        problems.append(
            f"ASH reported {verdict.actionable} actionable findings{where} where the "
            f"run expects {actionable}"
        )
    return problems


def verdict_problems(
    log: str, *, source: str = "scan", actionable: int | None = None
) -> list[str]:
    """[] when ASH's ``source`` verdict is in ``log``, exiting 2, with the expected count.

    With ``source="merge"`` the shards must give no verdict of their own: a shard that
    reports findings means the sharded run did not leave the verdict to the merge.
    """
    if source not in ("scan", "merge"):
        raise ValueError(f"no verdict source {source!r}")
    verdicts = ash_verdicts(log)
    problems = []
    if source == "merge":
        scans = [v for v in verdicts if v.source == "scan"]
        if scans:
            problems.append(
                f"a shard's scan gave its own verdict ({scans[0].actionable} actionable "
                "findings); in a sharded run only the merge gives one"
            )
    mine = [v for v in verdicts if v.source == source]
    if not mine:
        return [VERDICT_MISSING, *problems]
    for verdict in mine:
        problems += _verdict_value_problems(verdict, actionable)
    return problems


def _run_name(job: str, matrix: str) -> str:
    return f"job {job or '(outside any job)'}" + (
        "" if matrix == "{}" else f" {matrix}"
    )


def act_verdict_problems(
    log: str,
    *,
    gating: Mapping[str, int],
    source: str = "scan",
    actionable: int | None = None,
) -> list[str]:
    """Each job in ``gating`` gives one ``source`` verdict per run, and no other job one.

    ``gating`` maps each job that gates on findings to the number of times it runs
    (one per matrix entry). Verdicts are attributed by act's ``jobID`` and ``matrix``.
    """
    if source not in ("scan", "merge"):
        raise ValueError(f"no verdict source {source!r}")
    found: dict[tuple[str, str], list[Verdict]] = {}
    for line, entry in zip(log.splitlines(), _entries(log)):
        text = entry.get("msg") if entry is not None else line
        if not isinstance(text, str):
            continue
        for segment in _segments(text):
            for verdict in _verdicts_in(segment):
                found.setdefault(_act_run(entry), []).append(verdict)
    problems = []
    for (job, matrix), verdicts in sorted(found.items()):
        if job not in gating:
            problems.append(
                f"{_run_name(job, matrix)} gave a verdict ({verdicts[0].actionable} "
                "actionable findings), and it does not gate on findings"
            )
            continue
        others = [v for v in verdicts if v.source != source]
        if others:
            problems.append(
                f"{_run_name(job, matrix)} gave a {others[0].source} verdict where its "
                f"verdict is the {source}'s"
            )
    for job, runs in sorted(gating.items()):
        mine = {
            matrix: [v for v in verdicts if v.source == source]
            for (name, matrix), verdicts in found.items()
            if name == job
        }
        mine = {matrix: verdicts for matrix, verdicts in mine.items() if verdicts}
        if not mine:
            problems.append(f"job {job} gave no verdict: {VERDICT_MISSING}")
            continue
        if len(mine) != runs:
            problems.append(
                f"job {job} gave a verdict in {len(mine)} of its {runs} runs; each run "
                "gates on findings"
            )
        for matrix, verdicts in sorted(mine.items()):
            if len(verdicts) != 1:
                problems.append(
                    f"{_run_name(job, matrix)} gave {len(verdicts)} verdicts, not one"
                )
            for verdict in verdicts:
                problems += _verdict_value_problems(
                    verdict, actionable, f" of {_run_name(job, matrix)}"
                )
    return problems


def act_job_results(log: str) -> list[ActJobResult]:
    """Each job's result from act's ``--json`` log, one per job and matrix run."""
    results = []
    for entry in _entries(log):
        if entry is None or "jobResult" not in entry:
            continue
        matrix = entry.get("matrix")
        results.append(
            ActJobResult(
                job=str(entry.get("jobID") or entry.get("job") or ""),
                matrix=dict(matrix) if isinstance(matrix, Mapping) else {},
                result=str(entry.get("jobResult")),
            )
        )
    return results


def act_result_problems(
    log: str, expected: Mapping[str, str], runs: Mapping[str, int] | None = None
) -> list[str]:
    """Every job in ``expected`` must have ended, in every matrix run, as expected, and
    no other job may have run.

    With ``runs``, a job must also have ended exactly that many times. ``expected`` is
    the plan: a job it leaves out is one whose ``if`` the plan read as false before the
    run, so act may report it skipped, or not at all, and nothing else; any other
    result for it (a success, and above all a failure) means the plan's reading was
    wrong and the job's own outcome would otherwise go unchecked.
    """
    results = act_job_results(log)
    problems = []
    for run in results:
        if run.job in expected or run.result == "skipped":
            continue
        matrix = f" {json.dumps(run.matrix, sort_keys=True)}" if run.matrix else ""
        problems.append(
            f"job {run.job}{matrix} ended {run.result}, though the plan expected act "
            "not to run it"
        )
    for job, want in expected.items():
        ended = [r for r in results if r.job == job]
        if not ended:
            problems.append(f"act reported no result for job {job}")
            continue
        if runs is not None and job in runs and len(ended) != runs[job]:
            problems.append(
                f"act reported {len(ended)} results for job {job}, which runs "
                f"{runs[job]} times"
            )
        for run in ended:
            if run.result != want:
                matrix = (
                    f" {json.dumps(run.matrix, sort_keys=True)}" if run.matrix else ""
                )
                problems.append(
                    f"job {job}{matrix} ended {run.result}, expected {want}"
                )
    return problems


def act_step_start(log: str, *, job: str, step: str) -> float | None:
    """When act started step ``step`` of job ``job``, as a POSIX time; None if never."""
    starts = []
    for entry in _entries(log):
        if entry is None or (entry.get("jobID") or entry.get("job")) != job:
            continue
        message = _ANSI.sub("", str(entry.get("msg", ""))).strip()
        if not message.endswith(f"Run Main {step}"):
            continue
        stamp = entry.get("time")
        if not isinstance(stamp, str):
            continue
        stamp = _FRACTION.sub(r"\1", stamp.replace("Z", "+00:00"))
        try:
            moment = datetime.fromisoformat(stamp)
        except ValueError:
            continue
        if moment.tzinfo is None:
            continue
        starts.append(moment.timestamp())
    return min(starts) if starts else None


@dataclass
class _StepRun:
    job: str
    matrix: str
    step: str
    lines: list[str] = field(default_factory=list)


def _act_step_runs(log: str) -> list[_StepRun]:
    """Each run of a main step in act's ``--json`` log, with the messages it printed.

    A step runs from act's ``Run Main <step>`` message to its ``Success - Main`` or
    ``Failure - Main`` message, in one job and matrix run.
    """
    runs: list[_StepRun] = []
    open_runs: dict[tuple[str, str], _StepRun] = {}
    for entry in _entries(log):
        if entry is None or not isinstance(entry.get("msg"), str):
            continue
        key = _act_run(entry)
        for text in _segments(entry["msg"]):
            message = text.strip()
            start = _STEP_START.match(message)
            if start:
                open_runs[key] = _StepRun(key[0], key[1], start["step"])
                runs.append(open_runs[key])
                continue
            end = _STEP_END.match(message)
            current = open_runs.get(key)
            if end and current is not None and end["step"] == current.step:
                del open_runs[key]
                continue
            if current is not None:
                current.lines.append(text)
    return runs


def _command_text(text: str) -> str:
    """A line with act's marks and the output bar in front of it taken off."""
    return _LINE_PREFIX.sub("", text).rstrip()


def resume_token_problems(
    log: str,
    steps: Iterable[str | tuple[str, str]],
    optional: Iterable[tuple[str, str]] = (),
) -> list[str]:
    """Each run of each step in ``steps`` stops workflow commands and prints its resume.

    ``steps`` names each wrapped step as a ``(job, step)`` pair, or by its name alone
    for any job. The steps print ``::stop-commands::<token>`` before their command and
    ``::<token>::`` after it. Read from act's raw log: the resume token must stand on a
    line of its own after the stop line. A wanted step must also have run, in each
    run of its job (each matrix entry) that act reported a result for, since a step
    that never ran was never checked; a step named alone, in some job, once act
    reported any job's result. A pair in ``optional`` (a step with an ``if``) is
    checked in each run it had, and may have had none. A job act reported no result
    for is not this check's: act_result_problems names it.
    """
    wanted = list(steps)
    names = {step for step in wanted if isinstance(step, str)}
    pairs = {tuple(step) for step in wanted if not isinstance(step, str)}
    may_skip = {tuple(step) for step in optional}
    runs = _act_step_runs(log)
    problems = []
    for run in runs:
        if run.step not in names and (run.job, run.step) not in pairs:
            continue
        name = f"step {run.step!r} of {_run_name(run.job, run.matrix)}"
        lines = [_command_text(line) for line in run.lines]
        stops = [
            (index, line[len(_STOP_COMMANDS) :].strip())
            for index, line in enumerate(lines)
            if line.startswith(_STOP_COMMANDS)
        ]
        if not stops:
            problems.append(
                f"{name} printed no {_STOP_COMMANDS} line, so its command's output was "
                "read as workflow commands"
            )
            continue
        for index, token in stops:
            if not token or f"::{token}::" not in lines[index + 1 :]:
                problems.append(
                    f"{name} stopped workflow commands and never printed its resume "
                    "token on a line of its own"
                )
    reported = sorted(
        {
            (result.job, json.dumps(result.matrix, sort_keys=True))
            for result in act_job_results(log)
        }
    )
    ran = {(run.job, run.matrix, run.step) for run in runs}
    for step in wanted:
        if isinstance(step, str):
            if reported and not any(run.step == step for run in runs):
                problems.append(
                    f"step {step!r} never ran in any job act reported a result for, "
                    "so whether it stops workflow commands was never checked"
                )
            continue
        job, name = step
        if (job, name) in may_skip:
            continue
        for matrix in [
            matrix for reported_job, matrix in reported if reported_job == job
        ]:
            if (job, matrix, name) not in ran:
                problems.append(
                    f"step {name!r} of {_run_name(job, matrix)} never ran, though act "
                    "reported that run's result, so whether it stops workflow "
                    "commands was never checked"
                )
    return problems


def codebuild_phase_states(log: str) -> dict[str, str]:
    """The last state the CodeBuild agent's log gives each phase."""
    states: dict[str, str] = {}
    for text in _texts(log):
        for match in _PHASE.finditer(text):
            states[match[1]] = match[2]
    return states


def codebuild_build_state(log: str) -> str | None:
    """The BUILD phase's state in the CodeBuild agent's log, or None if it has none."""
    return codebuild_phase_states(log).get("BUILD")


def _parse_xml(path: Path) -> ET.Element:
    """Parse ``path``, accepting the XML 1.1 declaration Jenkins writes."""
    text = path.read_text(encoding="utf-8")
    text = re.sub(r"^\s*<\?xml[^>]*\?>", "", text, count=1)
    return ET.fromstring(text)


def jenkins_junit_problems(
    jenkins_home: Path, *, failures: int, job: str = "job"
) -> list[str]:
    """The first build's JUnit record must exist and hold ``failures`` failed tests.

    ``junit allowEmptyResults: true`` passes a build that found no report, so the
    record itself is the evidence that the report was read.
    """
    path = Path(jenkins_home) / "jobs" / job / "builds" / "1" / "junitResult.xml"
    if not path.is_file():
        return [
            f"{path} is missing: Jenkins recorded no JUnit result (junitResult.xml)"
        ]
    try:
        root = _parse_xml(path)
    except (OSError, ET.ParseError, UnicodeDecodeError) as error:
        return [f"{path} (junitResult.xml) cannot be read: {error}"]
    cases = list(root.iter("case"))
    failed = [
        case
        for case in cases
        if (
            case.find("errorStackTrace") is not None
            or case.find("errorDetails") is not None
        )
        and (case.findtext("skipped") or "false").strip() != "true"
    ]
    problems = []
    if not cases:
        problems.append(f"{path} records 0 tests")
    if len(failed) != failures:
        problems.append(
            f"{path} records {len(failed)} failed tests, expected {failures}"
        )
    return problems


def junit_census_problems(
    junit_xml: Path, *, expected: int, counted: str = "census blocks of the leg"
) -> list[str]:
    """The runner tests' own junit file must show exactly ``expected`` tests run.

    Each testsuite's ``tests`` count must also be the number of its testcases: pytest
    writes a testcase for each test it collected even when none ran, as under
    ``--setup-plan``, and then counts ``tests="0"``. ``counted`` says what the
    expected tests are, for the message.
    """
    path = Path(junit_xml)
    if not path.is_file():
        return [f"{path} is missing"]
    try:
        root = _parse_xml(path)
    except (OSError, ET.ParseError, UnicodeDecodeError) as error:
        return [f"{path} cannot be read: {error}"]
    cases = list(root.iter("testcase"))
    skipped = [case for case in cases if case.find("skipped") is not None]
    problems = [
        f"{case.get('classname', '')}::{case.get('name', '')} was skipped; a census "
        "block that does not run fails the leg"
        for case in skipped
    ]
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    for suite in suites:
        listed = len(list(suite.iter("testcase")))
        tests = (suite.get("tests") or "").strip()
        if not tests.isdigit() or int(tests) != listed:
            problems.append(
                f"testsuite {suite.get('name', '')!r} of {path} counts "
                f"tests={suite.get('tests')!r} for the {listed} testcases it lists; "
                "pytest counts every test it reported, and 0 under --setup-plan"
            )
    executed = len(cases) - len(skipped)
    if executed != expected:
        problems.append(f"{executed} tests ran for the {expected} {counted}")
    return problems


def stub_sarif_problems(sarif: Path, stub_record: Path) -> list[str]:
    """The upload stub must have been given exactly this SARIF file."""
    sarif = Path(sarif)
    record_path = Path(stub_record)
    if not sarif.is_file():
        return [f"{sarif} is missing"]
    try:
        record = json.loads(record_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        return [f"the upload stub's record {record_path} cannot be read: {error}"]
    digest = hashlib.sha256(sarif.read_bytes()).hexdigest()
    if not isinstance(record, Mapping) or record.get("sha256") != digest:
        recorded = record.get("sha256") if isinstance(record, Mapping) else None
        return [
            (
                f"the upload stub was given a file with sha256 {recorded}, not {sarif} "
                f"({digest})"
            )
        ]
    return []


#: The slack a file's mtime gets against a step's start: a file unpacked from an
#: artifact zip carries its zip entry's date_time, which has 2-second resolution and
#: rounds down, so a file written within 2 s after the step started can read up to
#: 2 s before it.
DOS_TIME_SLACK_S = 2.0


def written_after_problems(path: Path, *, started: float) -> list[str]:
    """``path`` must exist and have been written at or after ``started``, a POSIX time,
    within ``DOS_TIME_SLACK_S``.

    act's host executor runs each job in its own copy of the project and removes it at
    the job's end (measured: the project's own ``.ash/ash_output`` is never written, so
    the harness reads the artifact the job uploaded), so ``path`` is a file unpacked
    from that artifact with the mtime its zip entry recorded, which is the file's own
    (reports._EXTENDED_TIMESTAMP). A file the job's checkout already held, or one a step
    that did not write left in place, carries an mtime before the step started; only one
    written after the step started can be that step's output.
    """
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        return [f"{path} is missing"]
    if path.stat().st_mtime < started - DOS_TIME_SLACK_S:
        return [
            (
                f"{path} was last written before the step that writes it started, so "
                "it is not that step's output"
            )
        ]
    return []


def merged_sarif_problems(
    sarif: Path, *, merge_started: float, stub_record: Path
) -> list[str]:
    """The merged SARIF must be written by the merge step and be the one uploaded.

    ``sarif`` is the file unpacked from the merge job's own uploaded artifact, with the
    mtime its zip entry recorded (written_after_problems says why); a SARIF the merge
    step did not write, one its checkout held or a download left in place, carries an
    mtime before the merge step started, and only one written after it can be the
    merge's output.
    """
    sarif = Path(sarif)
    problems = []
    if sarif.is_file() and sarif.stat().st_mtime < merge_started - DOS_TIME_SLACK_S:
        problems.append(
            f"{sarif} was last written before the merge step started, so it is not "
            "the merge's output"
        )
    return problems + stub_sarif_problems(sarif, stub_record)
