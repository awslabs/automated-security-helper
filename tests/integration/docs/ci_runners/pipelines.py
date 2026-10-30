# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Running one census block under its runner, and what the run must show.

For each block the census gives a leg, ``prepare`` composes the block (a fragment is
merged into the pipeline it extends), rewrites it to install the ASH under test
(rewrite.py), and commits it into a new fixture repository (fixture.py). A GitHub
workflow's local calls of ASH's reusable workflows are copied in beside it, each
rewritten to print the provenance of the ASH it runs. ``launch`` starts the leg's
runner on it through its launcher, with a new, empty HOME and the session's time
limit, every log written under the run's output directory. ``run_problems`` then lists
every way the run fails to show what the page claims:

* the runner's own result: every job act runs (a reusable call's jobs under the called
  workflow's ids, once per matrix entry) ended as its commands say it should, the
  gate job failed (gitlab-ci-local), the build failed (Jenkinsfile Runner, the
  CircleCI CLI), the BUILD phase failed (the CodeBuild agent);
* ASH's verdict line, exiting 2, with the count the fixture plants: three findings in
  app.py, one more in changed.py on a pull or merge request branch, only that one for
  a scan of the changed files; exactly one verdict from each job that gates on
  findings (under act, in each of its runs) and none from any other job;
* the reports where the page says the pipeline keeps them: act's artifact store, the
  GitLab job's artifacts and every file its gate exits with, the Jenkins build's archive
  and JUnit record, the CodeBuild agent's artifacts and its JUnit report, the CircleCI
  report copy; the check run and the pull request comment the reusable scan publishes;
* the aggregated results' actionable findings, by file;
* which ASH was installed: the PEP 610 direct_url.json the rewrite prints after each
  install (the wheel and its sha256, or the head commit of the base repository),
  exactly one record per job run that has a print, and the wheel file hashed again
  after the launch, since uv never checks the sha256 it is given; nothing fetched from
  a package index; for the job on the image the run built, that image's id and one
  record of the ASH the image holds, from the head commit (a record that differs
  leaves the wheel's files and their sha256s in built-wheel-manifest.json);
* for the sharded example, merged results and a merged SARIF written after the merge
  step started, and the SARIF the upload stub was given;
* each GitHub step that stops workflow commands printing its resume token.

``control_problems`` is the other half: with an install that cannot succeed (a wheel
path that does not exist, a commit no repository has) the job's script must start,
its installer must refuse that input in its own words in what the script printed,
and the run must fail with no verdict line, so a pipeline that passes or fails for
any other reason is not taken for one that ran the ASH under test.

What a run keeps for upload holds no dot entry and nothing secret-shaped: the Jenkins
homes stay in the run's work directory, which may not overlap --ci-runner-out, and
only the build record is copied out; every kept ``.ash/ash_output`` is copied as
``ash_output``.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import math
import os
import re
import shutil
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from . import census, env, manifest, reports, verdict
from . import (
    run_act,
    run_circleci,
    run_codebuild_agent,
    run_gitlab_ci_local,
    run_jenkinsfile_runner,
)
from .census import CensusRun

REPO_ROOT = census.REPO_ROOT
BUILT_IMAGE = "registry.example.com/security/automated-security-helper:ci"
#: How an install line of a release starts on the pages; the version follows. Built in
#: parts so this file holds no install reference of its own.
RELEASE_INSTALL = (
    "automated-security-helper[cdk] @ git+https://github.com/awslabs/"
    "automated-security-helper"
    ".git@v"
)
REUSABLE = "awslabs/automated-security-helper/.github/workflows/"
PIPELINE_PATHS = {
    "github-actions": ".github/workflows/ash.yml",
    "gitlab-ci": ".gitlab-ci.yml",
    "jenkinsfile": "Jenkinsfile",
    "buildspec": "buildspec.yml",
    "circleci": ".circleci/config.yml",
}
#: A commit id no repository has, for the git install's negative control.
ABSENT_COMMIT = hashlib.sha1(
    b"no repository has this commit", usedforsecurity=False
).hexdigest()
#: A wheel that is never built, for the wheel install's negative control.
ABSENT_WHEEL_NAME = "automated_security_helper-0.0.0-py3-none-any.whl"
#: The install mechanisms a negative control breaks.
CONTROLLED_MECHANISMS = ("wheel", "git")
#: Mounted wheels are seen by the installer at this path.
WHEEL_MOUNT = PurePosixPath(run_gitlab_ci_local.WHEEL_MOUNT)
TAIL_LINES = 20
TAIL_CHARS = reports.TAIL_CHARS
#: The file the GitLab example's scan job keeps ASH's exit code in for its gate job.
EXIT_CODE_FILE = "ash-exit-code.txt"
#: The Jenkins build whose record is kept: Jenkinsfile Runner's one job, first build.
JENKINS_BUILD = ("jobs", "job", "builds", "1")
JENKINS_BUILD_FILES = ("log", "build.xml", "junitResult.xml")
#: Where a failed check of the built image's record leaves the wheel's side of it, in
#: the run's output directory: paths and sha256s of the package, nothing secret.
BUILT_WHEEL_MANIFEST = "built-wheel-manifest.json"

#: A line each runner prints once the job's own script has started, read from the
#: log's text (act's ``msg``, ANSI codes removed).
SCRIPT_STARTED = {
    "act": re.compile(r"⭐\s*Run Main\s"),
    "gitlab-ci-local": re.compile(r"^\S+\s+\$\s"),
    "jenkinsfile-runner-lts": re.compile(r"^\[Pipeline\] sh\b"),
    "jenkinsfile-runner-bundled": re.compile(r"^\[Pipeline\] sh\b"),
    "codebuild-agent": re.compile(r"Running command\s"),
    "circleci": re.compile(
        r"^====>> (?!Spin up environment$|Preparing environment variables$"
        r"|Checkout code$)\S"
    ),
}
#: A line in which a runner shows a command before running it. An input named only
#: there was not necessarily read by the installer. The CircleCI agent prints each run
#: command under its shell's ``#!/bin/bash -eo pipefail`` line; the command's own lines
#: are told apart by their text (script_output). act's own messages are told apart by
#: act's ``raw_output`` mark.
COMMAND_ECHO = {
    "gitlab-ci-local": re.compile(r"^\S+\s+\$\s"),
    "jenkinsfile-runner-lts": re.compile(r"^\+ "),
    "jenkinsfile-runner-bundled": re.compile(r"^\+ "),
    "codebuild-agent": re.compile(r"Running command\s"),
    "circleci": re.compile(r"^\s*#!/bin/(?:ba)?sh\b"),
}
#: What an installer the pages use prints when the input a negative control broke is
#: not there, on the line that names that input. For a wheel path: uv's
#: ``Distribution not found at: <url>``, and pip's OSError,
#: ``[Errno 2] No such file or directory: '<path>'``. For a commit the repository does
#: not have, git's own refusal, which uv and pip pass on: ``upload-pack: not our ref
#: <sha>`` from the server, or ``couldn't find remote ref <sha>``; or uv's, when it
#: fetched the branches and tags and found no such commit among them: ``failed to find
#: branch, tag, or commit `<sha>```. uv and pip name the whole requirement in their
#: own messages, so a fetch that failed for any other reason, a network error, names
#: the commit too.
REFUSALS = {
    "wheel": re.compile(r"Distribution not found at:|No such file or directory"),
    "git": re.compile(
        r"not our ref|couldn't find remote ref|failed to find branch, tag, or commit"
    ),
}
#: A command that runs an ASH scan or merge: ``ash scan``, ``ash merge``, or ``ash``
#: followed by an option, which scans (reports.RUNS_SCAN_OR_MERGE).
_RUNS_ASH = reports.RUNS_SCAN_OR_MERGE


class HarnessError(RuntimeError):
    """The run could not be set up as the page describes."""


def _harness(stem: str):
    """rewrite.py, fixture.py or provenance.py, imported when first needed."""
    return importlib.import_module(f".{stem}", __package__)


# ---------------------------------------------------------------------------
# What a block is
# ---------------------------------------------------------------------------


def install_mechanism(runner: str, text: str) -> str | None:
    """How the block installs ASH: ``wheel``, ``git`` or ``built``; None if it does not.

    A call of ASH's reusable workflow installs from a commit; an install line of the
    release becomes the wheel, except under the CodeBuild agent, which cannot mount it
    and installs the head commit; a job on the image the run builds needs no install.
    """
    if REUSABLE in text:
        return "git"
    if RELEASE_INSTALL in text:
        return "git" if runner == "codebuild-agent" else "wheel"
    if BUILT_IMAGE in text:
        return "built"
    return None


#: The pipeline kinds whose blocks are YAML; a Jenkinsfile is Groovy.
_YAML_KINDS = frozenset(PIPELINE_PATHS) - {"jenkinsfile"}


class _TagTolerantLoader(yaml.SafeLoader):
    """PyYAML's safe loader, reading a node under a local tag (GitLab's ``!reference``)
    as the plain sequence, mapping or string it tags. Only a GitLab block is read with
    it (runs_ash): GitLab defines a local tag, and no other pipeline kind's CI system
    does."""


def _untagged(loader: yaml.SafeLoader, _suffix: str, node: yaml.Node) -> Any:
    """A tagged node, built as a plain list, mapping or string."""
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node, deep=True)
    return loader.construct_scalar(node)


_TagTolerantLoader.add_multi_constructor("!", _untagged)


def _yaml_strings(node: Any) -> Iterator[str]:
    """Every string in a loaded YAML document, keys and values."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, Mapping):
        for key, value in node.items():
            yield from _yaml_strings(key)
            yield from _yaml_strings(value)
    elif isinstance(node, list):
        for item in node:
            yield from _yaml_strings(item)


def runs_ash(text: str, kind: str | None = None) -> bool:
    """Whether the block runs ASH: ``ash scan``, ``ash merge``, ``ash`` followed by an
    option (the scan is the CLI's default command), or ASH's reusable workflow.

    A block of a YAML ``kind`` is read as YAML loads it, as the act plan and the
    GitLab checks read a pipeline: each string is matched on its own, so a folded or
    plain multi-line scalar is one command with its lines joined, a literal block
    keeps its line breaks, each ending a command, and a comment runs nothing. Every
    document of the block is read, and in a GitLab block a node under a tag such as
    ``!reference`` as the plain value it tags (_TagTolerantLoader). The run checks
    see neither: the rewrite loads a pipeline with the plain safe loader, so it
    refuses such a block before the run (rewrite.py), and the run checks load only
    the pipeline it wrote. A Jenkinsfile and a text of no kind are read as written.
    So is a YAML block that does not parse, a block of another kind that holds a tag
    included, with ``ash`` and its first argument allowed on separate lines
    (reports.RUNS_SCAN_OR_MERGE_ANY_LINE), so it errs toward counting the block as
    running ASH and asking for a control."""
    if REUSABLE in text:
        return True
    if kind in _YAML_KINDS:
        loader = _TagTolerantLoader if kind == "gitlab-ci" else yaml.SafeLoader
        try:
            documents = list(yaml.load_all(text, Loader=loader))
        except yaml.YAMLError:
            return bool(reports.RUNS_SCAN_OR_MERGE_ANY_LINE.search(text))
        return any(_RUNS_ASH.search(each) for each in _yaml_strings(documents))
    return bool(_RUNS_ASH.search(text))


def pipeline_path(
    kind: str, *, save_as: str | None = None, extends: str | None = None
) -> str:
    """Where the block's pipeline file goes in the fixture."""
    if kind == "github-actions" and (save_as or extends):
        return str(save_as or extends)
    if kind not in PIPELINE_PATHS:
        raise HarnessError(f"config kind={kind} has no runner")
    return PIPELINE_PATHS[kind]


def composed_text(run: CensusRun) -> str:
    """The block's pipeline, with a fragment merged into the one it extends."""
    return census.docs_checks().ci_pipeline_text(
        census.page(run.page), census.block(run)
    )


def negative_controls(
    runs: Iterable[CensusRun], *, composed: Callable[[CensusRun], str] = composed_text
) -> list[tuple[CensusRun, str]]:
    """The first block of each leg, page and install mechanism, with that mechanism.

    One control per way a leg's blocks on a page install ASH (the wheel, or a commit);
    a block on the image the run builds, or one with no install, has none.
    """
    seen: set[tuple[str, str, str]] = set()
    controls = []
    for run in runs:
        mechanism = install_mechanism(run.runner, composed(run))
        if mechanism not in CONTROLLED_MECHANISMS:
            continue
        key = (run.runner, run.page, mechanism)
        if key in seen:
            continue
        seen.add(key)
        controls.append((run, mechanism))
    return controls


# ---------------------------------------------------------------------------
# The session: options, the ASH under test, shared directories
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Options:
    bin_dir: Path
    wheel: Path
    out: Path
    jenkins_dir: Path | None
    launch_timeout: float

    @classmethod
    def from_config(cls, config) -> Options:
        names = ("bin", "wheel", "out")
        values = {n: config.getoption(f"--ci-runner-{n}") for n in names}
        missing = [f"--ci-runner-{n}" for n, v in values.items() if not v]
        if missing:
            raise HarnessError(f"the CI-runner tests need {', '.join(missing)}")
        wheel = Path(values["wheel"]).resolve()
        if not wheel.is_file() or wheel.suffix != ".whl":
            raise HarnessError(f"--ci-runner-wheel {wheel} is not a wheel")
        jenkins = config.getoption("--ci-runner-jenkins-dir")
        given = config.getoption("--ci-runner-launch-timeout")
        try:
            timeout = float(given)
        except (TypeError, ValueError):
            timeout = math.nan
        if not (math.isfinite(timeout) and timeout > 0):
            raise HarnessError(
                f"--ci-runner-launch-timeout is {given!r}; each launch needs a time "
                "limit of more than 0 seconds"
            )
        return cls(
            bin_dir=Path(values["bin"]).resolve(),
            wheel=wheel,
            out=Path(values["out"]).resolve(),
            jenkins_dir=Path(jenkins).resolve() if jenkins else None,
            launch_timeout=timeout,
        )


@dataclass(frozen=True)
class UnderTest:
    """The ASH a run installs: the wheel built from the checkout, or its head commit."""

    wheel: Path
    wheel_sha256: str
    head_sha: str
    repository: str

    @classmethod
    def from_environment(cls, wheel: Path, environ: Mapping[str, str]) -> UnderTest:
        rewrite = _harness("rewrite")
        return cls(
            wheel=Path(wheel),
            wheel_sha256=_sha256(Path(wheel)),
            head_sha=rewrite.head_sha(environ),
            repository=rewrite.base_repository(environ),
        )

    def broken(self, mechanism: str) -> UnderTest:
        """The same, with the install of ``mechanism`` made to fail."""
        if mechanism == "wheel":
            absent = self.wheel.with_name(ABSENT_WHEEL_NAME)
            if absent.exists():
                raise HarnessError(
                    f"{absent} exists; the control needs a missing wheel"
                )
            return replace(self, wheel=absent)
        if mechanism == "git":
            return replace(self, head_sha=ABSENT_COMMIT)
        raise ValueError(f"no negative control for {mechanism}")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def system_ash_problem(path: str = env.SYSTEM_PATH) -> str | None:
    """A problem naming the ``ash`` on ``path``, the runners' system PATH, or None.

    Every runner starts with that PATH after its own directory, so a pipeline that
    skipped its install or broke its PATH line would run such an ash and pass.
    """
    found = shutil.which("ash", path=path)
    if found is None:
        return None
    return (
        f"{found} is an ash on the system PATH the runners start with ({path}); a "
        "pipeline that skipped its install would run it, so the runs cannot start"
    )


@dataclass
class Session:
    options: Options
    under_test: UnderTest
    pins: dict[str, Any]
    work: Path
    tool_cache: Path
    #: Each image the session built: its build's exit code and the image id.
    images: dict[str, tuple[int, str | None]] = field(default_factory=dict)
    poisoned_ash: Path | None = None
    sentinel: Path | None = None

    def __post_init__(self) -> None:
        work = Path(self.work).resolve()
        out = Path(self.options.out).resolve()
        if work == out or work.is_relative_to(out) or out.is_relative_to(work):
            raise HarnessError(
                f"the work directory {work} and --ci-runner-out {out} overlap: the "
                "work directory (pytest's basetemp) holds the Jenkins homes, with "
                "their keys, and --ci-runner-out is uploaded, so neither may hold the "
                "other"
            )

    @classmethod
    def start(cls, options: Options, work: Path) -> Session:
        problem = system_ash_problem()
        if problem is not None:
            raise HarnessError(problem)
        tool_cache = Path(work) / "ash-tool-download-cache"
        tool_cache.mkdir(parents=True, exist_ok=True)
        options.out.mkdir(parents=True, exist_ok=True)
        return cls(
            options=options,
            under_test=UnderTest.from_environment(options.wheel, os.environ),
            pins=manifest.load_manifest(),
            work=Path(work),
            tool_cache=tool_cache,
        )

    def directories(self, name: str) -> tuple[Path, Path]:
        """A new output directory and a new work directory for one run."""
        out = self.options.out / name
        work = self.work / name
        out.mkdir(parents=True)
        work.mkdir(parents=True)
        return out, work

    def program(self, key: str) -> Path:
        return manifest.tool_executable(self.pins, self.options.bin_dir, key)


def session_with_poisoned_ash(config, work: Path) -> Iterator[Session]:
    """The session for a pytest session fixture, with the poisoned outer ash armed.

    The outer ash goes first on this process's PATH for the whole session. Every
    runner starts in an environment of its own, so no pipeline may ever reach it; if
    one did, its sentinel exists at the end and the session's last test errors.
    """
    env.require_github_hosted(os.environ)
    session = Session.start(Options.from_config(config), work)
    poison = session.options.out / "poisoned-ash"
    session.sentinel = poison / "sentinel"
    session.poisoned_ash = env.write_poisoned_ash(poison / "bin", session.sentinel)
    path = os.environ.get("PATH", "")
    os.environ["PATH"] = f"{session.poisoned_ash.parent}{os.pathsep}{path}"
    try:
        yield session
    finally:
        os.environ["PATH"] = path
    problem = env.poisoned_ash_problem(session.sentinel)
    if problem:
        raise AssertionError(problem)


# ---------------------------------------------------------------------------
# Preparing a run
# ---------------------------------------------------------------------------


@dataclass
class Prepared:
    run: CensusRun
    under_test: UnderTest
    path: str
    composed: str
    rewritten: str
    applied: list
    fixture: Any
    out: Path
    work: Path
    #: Actionable findings the run must report, by file.
    expected: dict[str, int] = field(default_factory=dict)
    #: The reusable workflows copied into the fixture, by file name, as rewritten.
    called: dict[str, str] = field(default_factory=dict)
    #: The rewrite records of those workflows.
    called_applied: list = field(default_factory=list)

    @property
    def project(self) -> Path:
        return Path(self.fixture.project)

    @property
    def mechanism(self) -> str | None:
        return install_mechanism(self.run.runner, self.composed)


def rewrite_context(runner: str, under_test: UnderTest, pins: Mapping[str, Any]):
    """The rewrite context that installs ``under_test`` under ``runner``."""
    rewrite = _harness("rewrite")
    images: dict[str, str] = {}
    built: frozenset[str] = frozenset()
    report_mount = None
    if runner == "gitlab-ci-local":
        images["python:3.12"] = manifest.image_ref(pins, run_gitlab_ci_local.JOB_IMAGE)
        built = frozenset({BUILT_IMAGE})
    if runner == "circleci":
        images["cimg/python:3.12-node"] = manifest.image_ref(
            pins, run_circleci.JOB_IMAGE
        )
        report_mount = run_circleci.REPORT_MOUNT
    return rewrite.RewriteContext(
        runner=runner,
        install_spec=rewrite.install_spec(
            runner,
            wheel=under_test.wheel,
            wheel_sha256=under_test.wheel_sha256,
            head_sha=under_test.head_sha,
            repository=under_test.repository,
        ),
        head_sha=under_test.head_sha,
        repository=under_test.repository,
        version=census.docs_checks().current_version(str(REPO_ROOT)),
        images=images,
        built_images=built,
        report_mount=report_mount,
    )


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _record(out: Path, name: str, argv: Iterable[Any]) -> None:
    """Append the command line of one launch to the run's commands.jsonl."""
    with (out / "commands.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"name": name, "argv": [str(a) for a in argv]}) + "\n")


def _applied_records(applied: Iterable[Any], file: str) -> list[dict[str, Any]]:
    return [
        {
            "file": file,
            "rule": a.rule,
            "old": a.old,
            "new": a.new,
            "count": a.count,
            "job": getattr(a, "job", None),
            "matrix": getattr(a, "matrix", False),
        }
        for a in applied
    ]


def _copy_called_workflows(
    text: str, *, project: Path, where: str
) -> tuple[dict[str, str], list, list[dict[str, Any]]]:
    """Copy the workflows and actions ``text`` calls into ``project``, and rewrite each
    workflow so it prints the provenance of the ASH it runs.

    Returns the rewritten workflows by file name, their rewrite records, and those
    records as rewrites.json lists them.
    """
    rewrite = _harness("rewrite")
    workflows = project / ".github" / "workflows"
    called: dict[str, str] = {}
    applied: list = []
    records: list[dict[str, Any]] = []
    for path in run_act.copy_local_uses(text, source_root=REPO_ROOT, project=project):
        if path.parent != workflows or path.suffix not in (".yml", ".yaml"):
            continue
        result = rewrite.rewrite_called_workflow(
            path.name,
            path.read_text(encoding="utf-8"),
            where=f"{path.name}, called by {where}",
        )
        path.write_text(result.text, encoding="utf-8")
        called[path.name] = result.text
        applied += list(result.applied)
        records += _applied_records(
            result.applied, path.relative_to(project).as_posix()
        )
    return called, applied, records


def prepare(
    run: CensusRun, under_test: UnderTest, *, session: Session, out: Path, work: Path
) -> Prepared:
    """Compose, rewrite and commit ``run``'s pipeline into a new fixture."""
    checks = census.docs_checks()
    block = census.block(run)
    marker = checks.ci_marker(block)
    composed = composed_text(run)
    path = pipeline_path(
        run.kind,
        save_as=getattr(marker, "save_as", None),
        extends=getattr(marker, "extends", None),
    )
    where = f"{run.page}:{run.line}"
    context = rewrite_context(run.runner, under_test, session.pins)
    result = _harness("rewrite").rewrite_pipeline(
        run.kind, composed, context, where=where
    )
    name = PurePosixPath(path).name
    _write(out / f"composed-{name}", composed)
    _write(out / name, result.text)
    fixture_module = _harness("fixture")
    fixture = fixture_module.make_fixture(
        work / "fixture", pipeline_path=path, pipeline_text=result.text, event=run.event
    )
    called: dict[str, str] = {}
    called_applied: list = []
    records = _applied_records(result.applied, path)
    if run.kind == "github-actions":
        called, called_applied, called_records = _copy_called_workflows(
            result.text, project=Path(fixture.project), where=where
        )
        records += called_records
        for called_name, text in called.items():
            _write(out / f"called-{called_name}", text)
    _write(out / "rewrites.json", json.dumps(records, indent=2) + "\n")
    return Prepared(
        run=run,
        under_test=under_test,
        path=path,
        composed=composed,
        rewritten=result.text,
        applied=list(result.applied),
        fixture=fixture,
        out=out,
        work=work,
        expected=dict(
            fixture_module.expected_findings(run.event, changed_files=run.changed_files)
        ),
        called=called,
        called_applied=called_applied,
    )


# ---------------------------------------------------------------------------
# Launching
# ---------------------------------------------------------------------------


@dataclass
class Launched:
    log: Path
    code: int
    steps: dict[str, int | None] = field(default_factory=dict)
    #: Why the launch was stopped, when it ran out of time; None when it finished.
    timed_out: str | None = None
    #: The id of the image the run built for the block, when it built one.
    image_id: str | None = None

    def text(self) -> str:
        try:
            return self.log.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""


def _timed(start: Callable[[], int]) -> tuple[int, str | None]:
    """The exit code of ``start()``, or -1 and why it ran out of time."""
    try:
        return start(), None
    except env.LaunchTimedOut as error:
        return -1, str(error)


def launch(prepared: Prepared, session: Session) -> Launched:
    """Start ``prepared``'s leg on it and wait for the runner to finish."""
    runner = prepared.run.runner
    if runner == "act":
        return _launch_act(prepared, session)
    if runner == "gitlab-ci-local":
        return _launch_gitlab(prepared, session)
    if runner in run_jenkinsfile_runner.CORES:
        return _launch_jenkins(prepared, session)
    if runner == "codebuild-agent":
        return _launch_codebuild(prepared, session)
    if runner == "circleci":
        return _launch_circleci(prepared, session)
    raise HarnessError(f"no launcher for {runner}")


def _launch_act(prepared: Prepared, session: Session) -> Launched:
    project, out, fixture = prepared.project, prepared.out, prepared.fixture
    texts = [
        path.read_text(encoding="utf-8")
        for path in sorted((project / ".github" / "workflows").glob("*.y*ml"))
    ]
    event_name = prepared.run.event or "push"
    event = run_act.act_event(
        event_name,
        head_sha=fixture.head_sha,
        base_sha=fixture.base_sha,
        branch=fixture.branch,
        repository=prepared.under_test.repository,
    )
    _write(out / "event.json", json.dumps(event, indent=2) + "\n")
    program = session.program(run_act.ACT_TOOL)
    argv = run_act.act_argv(
        program=program,
        event_name=event_name,
        workflow=project / prepared.path,
        event_path=out / "event.json",
        project=project,
        artifact_dir=out / "artifacts",
        cache_dir=prepared.work / "act-cache",
        stub_records=out / "stubs",
        writer_refs=run_act.writer_action_refs(texts),
        repository=prepared.under_test.repository,
    )
    _record(out, "act", argv)
    log = out / "act.log"
    code, timed_out = _timed(
        lambda: run_act.run_act(
            argv,
            runner_bin=program.parent,
            cwd=project,
            home=Path(fixture.home),
            tool_cache=session.tool_cache,
            outer=os.environ,
            log=log,
            timeout=session.options.launch_timeout,
        )
    )
    # Nothing is copied from the project's .ash/ash_output: act's host executor does
    # not write there, and the run is judged from the artifact store under out.
    return Launched(log=log, code=code, timed_out=timed_out)


def _build_image(session: Session, name: str, argv: list[str]) -> str | None:
    """Build an image the GitLab leg uses, once per session; return its id."""
    if name not in session.images:
        logs = session.options.out / "images"
        logs.mkdir(parents=True, exist_ok=True)
        iidfile = session.work / "images" / f"{name}.iid"
        iidfile.parent.mkdir(parents=True, exist_ok=True)
        argv = [*argv[:2], "--iidfile", str(iidfile), *argv[2:]]
        _record(logs, name, argv)
        code, timed_out = _timed(
            lambda: run_gitlab_ci_local.build_image(
                argv,
                runner_bin=session.program(
                    run_gitlab_ci_local.GITLAB_CI_LOCAL_TOOL
                ).parent,
                cwd=REPO_ROOT,
                home=env.fresh_home(session.work / "image-homes", name),
                tool_cache=session.tool_cache,
                outer=os.environ,
                log=logs / f"{name}.log",
                timeout=session.options.launch_timeout,
            )
        )
        if timed_out is not None:
            raise HarnessError(
                f"building the {name} image ran out of time: {timed_out}"
            )
        image_id = (
            iidfile.read_text(encoding="utf-8").strip() if iidfile.is_file() else None
        )
        session.images[name] = (code, image_id or None)
    code, image_id = session.images[name]
    if code != 0:
        log = session.options.out / "images" / f"{name}.log"
        raise HarnessError(
            f"building the {name} image exited {code}:\n"
            + reports.tail(log, TAIL_LINES, TAIL_CHARS)
        )
    return image_id


def _launch_gitlab(prepared: Prepared, session: Session) -> Launched:
    project, out, fixture = prepared.project, prepared.out, prepared.fixture
    _build_image(
        session, "gitlab-helper", run_gitlab_ci_local.helper_image_build_argv()
    )
    image_id = None
    if BUILT_IMAGE in prepared.rewritten:
        image_id = _build_image(
            session,
            "ci",
            _harness("rewrite").ci_image_build_argv(
                REPO_ROOT / "Dockerfile", tag=BUILT_IMAGE
            ),
        )
    program = session.program(run_gitlab_ci_local.GITLAB_CI_LOCAL_TOOL)
    argv = run_gitlab_ci_local.gitlab_ci_local_argv(
        program=program,
        project=project,
        wheel_dir=session.options.wheel.parent,
        event=prepared.run.event,
        base_sha=fixture.base_sha,
        cwd=project,
    )
    _record(out, "gitlab-ci-local", argv)
    log = out / "gitlab-ci-local.log"
    code, timed_out = _timed(
        lambda: run_gitlab_ci_local.run_gitlab_ci_local(
            argv,
            runner_bin=program.parent,
            cwd=project,
            home=Path(fixture.home),
            tool_cache=session.tool_cache,
            outer=os.environ,
            log=log,
            timeout=session.options.launch_timeout,
        )
    )
    reports.keep_tree(project / ".gitlab-ci-local" / "artifacts", out / "artifacts")
    return Launched(log=log, code=code, timed_out=timed_out, image_id=image_id)


def keep_jenkins_build(jenkins_home: Path, out: Path) -> None:
    """Copy the build's log, build.xml, JUnit record and archive to ``out``.

    Only those: the Jenkins home also holds the instance's keys (secret.key,
    secrets/, identity.key.enc), and it stays in the run's work directory. The
    archive's ``.ash/ash_output`` is kept as ``ash_output``.
    """
    build = Path(jenkins_home).joinpath(*JENKINS_BUILD)
    target = Path(out) / "jenkins-build"
    for name in JENKINS_BUILD_FILES:
        path = build / name
        if path.is_file() and not path.is_symlink():
            target.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target / name)
    reports.keep_tree(build / "archive", target / "archive")


def _launch_jenkins(prepared: Prepared, session: Session) -> Launched:
    project, out, fixture, work = (
        prepared.project,
        prepared.out,
        prepared.fixture,
        prepared.work,
    )
    leg = prepared.run.runner
    if session.options.jenkins_dir is None:
        raise HarnessError(f"{leg} needs --ci-runner-jenkins-dir")
    common = {
        "bin_dir": session.options.bin_dir,
        "jenkins_dir": session.options.jenkins_dir,
        "jenkinsfile": project / prepared.path,
        "tool_cache": session.tool_cache,
        "outer": os.environ,
        "timeout": session.options.launch_timeout,
    }
    # Jenkinsfile Runner explodes the WAR into a new directory of its working directory
    # on every start. Neither start runs in the project, which ash scans, or the exploded
    # core's files would be scanned as the project's own.
    lint_cwd, run_cwd = work / "jenkins-cwd-lint", work / "jenkins-cwd-run"
    lint_cwd.mkdir()
    run_cwd.mkdir()
    lint_log = out / "jenkinsfile-runner-lint.log"
    lint, timed_out = _timed(
        lambda: run_jenkinsfile_runner.run_jenkinsfile_runner(
            leg,
            command="lint",
            cwd=lint_cwd,
            jenkins_home=work / "jenkins-home-lint",
            workspace=None,
            plugin_copy=work / "plugins-lint",
            home=env.fresh_home(work, "home-lint"),
            log=lint_log,
            **common,
        )
    )
    if timed_out is not None:
        return Launched(
            log=lint_log, code=lint, steps={"lint": None}, timed_out=timed_out
        )
    log = out / "jenkinsfile-runner.log"
    code, timed_out = _timed(
        lambda: run_jenkinsfile_runner.run_jenkinsfile_runner(
            leg,
            command="run",
            cwd=run_cwd,
            jenkins_home=work / "jenkins-home",
            workspace=project,
            plugin_copy=work / "plugins-run",
            home=Path(fixture.home),
            log=log,
            **common,
        )
    )
    keep_jenkins_build(work / "jenkins-home", out)
    return Launched(log=log, code=code, steps={"lint": lint}, timed_out=timed_out)


def _launch_codebuild(prepared: Prepared, session: Session) -> Launched:
    project, out, fixture = prepared.project, prepared.out, prepared.fixture
    script = session.program(run_codebuild_agent.SCRIPT_TOOL)
    for directory in run_codebuild_agent.codebuild_dirs(prepared.work):
        directory.mkdir(parents=True, exist_ok=True)
    argv = run_codebuild_agent.codebuild_argv(
        session.pins, script=script, source=project, out_dir=prepared.work
    )
    _record(out, "codebuild-agent", argv)
    log = out / "codebuild.log"
    code, timed_out = _timed(
        lambda: run_codebuild_agent.run_codebuild_agent(
            argv,
            runner_bin=script.parent,
            cwd=project,
            home=Path(fixture.home),
            tool_cache=session.tool_cache,
            outer=os.environ,
            log=log,
            timeout=session.options.launch_timeout,
        )
    )
    for directory in run_codebuild_agent.codebuild_dirs(prepared.work):
        reports.keep_tree(directory, out / directory.name)
    return Launched(log=log, code=code, timed_out=timed_out)


def _circleci_job(text: str) -> str:
    jobs = (yaml.safe_load(text) or {}).get("jobs") or {}
    if len(jobs) != 1:
        raise HarnessError(
            f"the CircleCI block has {len(jobs)} jobs; local execute runs one"
        )
    return str(next(iter(jobs)))


def _launch_circleci(prepared: Prepared, session: Session) -> Launched:
    project, out, fixture = prepared.project, prepared.out, prepared.fixture
    config = session.program(run_circleci.CONFIG_TOOL)
    local = session.program(run_circleci.LOCAL_EXECUTE_TOOL)
    steps: dict[str, int | None] = {}
    for command in ("validate", "process"):
        argv = run_circleci.circleci_config_argv(
            program=config, command=command, config_path=prepared.path
        )
        _record(out, f"circleci config {command}", argv)
        step_log = out / f"circleci-config-{command}.log"
        steps[command], timed_out = _timed(
            lambda argv=argv, command=command, step_log=step_log: (
                run_circleci.run_circleci(
                    "config",
                    argv,
                    runner_bin=config.parent,
                    cwd=project,
                    home=env.fresh_home(prepared.work, f"home-{command}"),
                    tool_cache=session.tool_cache,
                    outer=os.environ,
                    log=step_log,
                    timeout=session.options.launch_timeout,
                )
            )
        )
        if timed_out is not None:
            return Launched(log=step_log, code=-1, steps=steps, timed_out=timed_out)
    report_dir = out / "circleci-reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    # The job container runs as the image's own user (circleci in the cimg images),
    # not as the runner's user who owns this directory, and the report copy writes
    # into it. It is a directory of this run's output on a runner that is thrown
    # away after the job.
    report_dir.chmod(0o777)
    argv = run_circleci.circleci_local_execute_argv(
        session.pins,
        program=local,
        job=_circleci_job(prepared.rewritten),
        wheel_dir=session.options.wheel.parent,
        report_dir=report_dir,
        config_path=prepared.path,
    )
    _record(out, "circleci local execute", argv)
    log = out / "circleci-local-execute.log"
    code, timed_out = _timed(
        lambda: run_circleci.run_circleci(
            "local-execute",
            argv,
            runner_bin=local.parent,
            cwd=project,
            home=Path(fixture.home),
            tool_cache=session.tool_cache,
            outer=os.environ,
            log=log,
            timeout=session.options.launch_timeout,
        )
    )
    return Launched(log=log, code=code, steps=steps, timed_out=timed_out)


# ---------------------------------------------------------------------------
# Which ASH the run installed
# ---------------------------------------------------------------------------


def _wheel_seen_as(prepared: Prepared) -> PurePosixPath:
    """The wheel's path as the installer in the pipeline sees it."""
    if prepared.run.runner in ("gitlab-ci-local", "circleci"):
        return WHEEL_MOUNT / prepared.under_test.wheel.name
    return PurePosixPath(prepared.under_test.wheel.as_posix())


def wheel_hash_problems(prepared: Prepared) -> list[str]:
    """The wheel file must still be the one the session hashed.

    uv installs a wheel named with ``#sha256=`` in its URL without checking the file,
    and records the URL as given, so the record alone cannot say what the file held.
    The file is the host's, also the one the container runners mount.
    """
    if prepared.mechanism != "wheel":
        return []
    wheel = prepared.under_test.wheel
    if wheel.is_symlink() or not wheel.is_file():
        return [f"{wheel}, the wheel under test, is not a file after the run"]
    digest = _sha256(wheel)
    if digest != prepared.under_test.wheel_sha256:
        return [
            (
                f"{wheel} has sha256 {digest} after the run, not "
                f"{prepared.under_test.wheel_sha256}, the sha256 the session hashed"
            )
        ]
    return []


def _insertions(prepared: Prepared) -> list:
    """The rewrite's provenance prints: the block's, and those of the workflows it
    calls."""
    return [a for a in prepared.applied if a.rule == "provenance"] + [
        a for a in prepared.called_applied if a.rule == "called-provenance"
    ]


def _record_kind(prepared: Prepared, rule: str) -> str:
    """``git`` or ``wheel``: what a print of ``rule`` must show was installed."""
    if rule == "called-provenance" or prepared.run.runner == "codebuild-agent":
        return "git"
    return "wheel"


def _record_problems(prepared: Prepared, record: Any, kind: str) -> list[str]:
    provenance = _harness("provenance")
    under_test = prepared.under_test
    if kind == "wheel":
        return provenance.wheel_provenance_problems(
            record, wheel=_wheel_seen_as(prepared), sha256=under_test.wheel_sha256
        )
    return provenance.git_provenance_problems(
        record, head_sha=under_test.head_sha, repository=under_test.repository
    )


def _act_provenance_problems(
    prepared: Prepared, log: str, insertions: list
) -> list[str]:
    """Exactly the records each act job run with a print gives, attributed by act's
    ``jobID`` and ``matrix``."""
    provenance = _harness("provenance")
    try:
        plan = reports.act_job_plan(
            reports.load_workflow(prepared.rewritten),
            {
                name: reports.load_workflow(text)
                for name, text in prepared.called.items()
            },
        )
    except ValueError as error:
        return [f"the job runs of {prepared.path} cannot be counted: {error}"]
    found: dict[str, dict[str, list[Any]]] = {}
    for (job, matrix), lines in verdict.act_log_groups(log).items():
        records = provenance.direct_urls_in_log("\n".join(lines))
        if records:
            found.setdefault(job, {})[matrix] = records
    per_run: dict[str | None, int] = {}
    rules: dict[str | None, str] = {}
    for insertion in insertions:
        per_run[insertion.job] = per_run.get(insertion.job, 0) + insertion.count
        rules[insertion.job] = insertion.rule
    problems = []
    for job, count in per_run.items():
        if job is None or job not in plan:
            problems.append(
                f"the rewrite added a print to job {job}, which act does not run"
            )
            continue
        runs = plan[job].runs
        printed = found.get(job, {})
        if len(printed) != runs:
            problems.append(
                f"job {job} printed install records in {len(printed)} of its {runs} "
                "runs; each run installs ASH and prints its record"
            )
        for matrix, records in sorted(printed.items()):
            if len(records) != count:
                name = f"job {job}" + ("" if matrix == "{}" else f" {matrix}")
                problems.append(
                    f"{name} printed {len(records)} install records, expected {count}"
                )
            for record in records:
                problems += _record_problems(
                    prepared, record, _record_kind(prepared, rules[job])
                )
    for job, printed in sorted(found.items()):
        if job not in per_run:
            total = sum(len(records) for records in printed.values())
            problems.append(
                f"job {job or '(outside any job)'} printed {total} install records, "
                "and the rewrite added no print there"
            )
    return problems


def _built_wheel_manifest_problem(prepared: Prepared, provenance) -> str:
    """Write the wheel's side of the built-image record to the run's output directory,
    and name the file; or say why it was not written."""
    under_test = prepared.under_test
    try:
        manifest = provenance.built_wheel_manifest(
            under_test.wheel, wheel_sha256=under_test.wheel_sha256
        )
    except ValueError as error:
        return f"no {BUILT_WHEEL_MANIFEST} was written: {error}"
    path = prepared.out / BUILT_WHEEL_MANIFEST
    try:
        _write(path, json.dumps(manifest, indent=2) + "\n")
    except OSError as error:
        return f"{path} could not be written: {error}"
    return (
        f"{path} holds the wheel's side of the record, each file it counts with its "
        "sha256, to compare with the same listing of the image's files"
    )


def built_record_problems(prepared: Prepared, log: str) -> list[str]:
    """The job on the image the run built shows which ASH that image holds.

    The rewrite inserts one print (rule ``built-provenance``) into each such job; its
    runs under gitlab-ci-local are not told apart in the log, so the job has no matrix,
    and the log holds exactly one record per print. Each record must pass
    provenance.built_provenance_problems against the wheel the session built from the
    same checkout, and its sha256. The image's id is checked on its own
    (built_image_problems).

    The record holds a count and a digest of the image's files, not their names, so
    when a record fails, the wheel's side of the check (provenance.built_wheel_manifest)
    is written once to BUILT_WHEEL_MANIFEST in the run's output directory, and the
    failure names it.
    """
    insertions = [a for a in prepared.applied if a.rule == "built-provenance"]
    if not insertions:
        return [
            (
                "the block runs on the image the run builds, and the rewrite added no "
                "step that prints the record of the ASH in it"
            )
        ]
    problems = []
    if any(getattr(a, "matrix", False) for a in insertions):
        problems.append(
            "the rewrite added a print of the built image's record to a job with a "
            f"matrix, whose runs {prepared.run.runner}'s log does not tell apart"
        )
    provenance = _harness("provenance")
    expected = sum(a.count for a in insertions)
    records = provenance.direct_urls_in_log(log)
    if len(records) != expected:
        problems.append(
            f"the rewrite added {expected} prints of the built image's install record, "
            f"and the log holds {len(records)}"
        )
    under_test = prepared.under_test
    failed = False
    for record in records:
        found = provenance.built_provenance_problems(
            record,
            head_sha=under_test.head_sha,
            wheel=under_test.wheel,
            wheel_sha256=under_test.wheel_sha256,
        )
        failed = failed or bool(found)
        problems += found
    if failed:
        problems.append(_built_wheel_manifest_problem(prepared, provenance))
    return problems


def provenance_problems(prepared: Prepared, log: str) -> list[str]:
    """The install must be the ASH under test, and nothing from a package index.

    Each print the rewrite added must give exactly one record per run: under act, per
    job and matrix run; under the other runners, whose jobs each run once, in total.
    """
    mechanism = prepared.mechanism
    problems = reports.index_download_problems(log)
    if mechanism == "built":
        return problems + built_record_problems(prepared, log)
    insertions = _insertions(prepared)
    if not insertions:
        return [
            *problems,
            (
                f"the block installs ASH by {mechanism}, and the rewrite added no step "
                "that prints the install's direct_url.json"
            ),
        ]
    if prepared.run.runner == "act":
        return problems + _act_provenance_problems(prepared, log, insertions)
    if any(getattr(a, "matrix", False) for a in insertions):
        problems.append(
            f"the rewrite added a print to a job with a matrix, whose runs "
            f"{prepared.run.runner}'s log does not tell apart"
        )
    expected = sum(a.count for a in insertions)
    records = _harness("provenance").direct_urls_in_log(log)
    if len(records) != expected:
        problems.append(
            f"the rewrite added {expected} prints of the install's direct_url.json, "
            f"and the log holds {len(records)}"
        )
    for record in records:
        problems += _record_problems(
            prepared, record, _record_kind(prepared, "provenance")
        )
    return problems


# ---------------------------------------------------------------------------
# What the run must show
# ---------------------------------------------------------------------------


def run_problems(
    prepared: Prepared, launched: Launched, session: Session | None
) -> list[str]:
    """Every way the run fails to show what the page says it does."""
    if launched.timed_out is not None:
        return [f"the run did not finish in time: {launched.timed_out}"]
    log = launched.text()
    expected = prepared.expected
    runner = prepared.run.runner
    if runner == "act":
        problems = _act_problems(prepared, launched, log, expected)
    elif runner == "gitlab-ci-local":
        problems = _gitlab_problems(prepared, launched, log, expected)
    elif runner in run_jenkinsfile_runner.CORES:
        problems = _jenkins_problems(prepared, launched, log, expected)
    elif runner == "codebuild-agent":
        problems = _codebuild_problems(prepared, launched, log, expected)
    else:
        problems = _circleci_problems(prepared, launched, log, expected)
    return problems + provenance_problems(prepared, log) + wheel_hash_problems(prepared)


#: Top-level keys of a GitLab pipeline that are not jobs.
_GITLAB_KEYWORDS = frozenset(
    {
        "after_script",
        "before_script",
        "cache",
        "default",
        "image",
        "include",
        "services",
        "stages",
        "variables",
        "workflow",
    }
)


def _gitlab_jobs(document: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {
        str(name): job
        for name, job in document.items()
        if isinstance(job, Mapping)
        and str(name) not in _GITLAB_KEYWORDS
        and not str(name).startswith(".")
    }


def scan_verdict_problems(prepared: Prepared, log: str) -> list[str]:
    """ASH's verdict, exiting 2 with the planted count, once in each job that runs ASH.

    gitlab-ci-local prints each output line of a job as ``<job> > <line>``, so each
    verdict is attributed to its job: every job whose script runs ``ash scan``,
    ``ash merge`` or ``ash`` with options gives exactly one, and no other job, nor a
    line outside every job, gives one. Jenkinsfile Runner, the CodeBuild agent and
    ``circleci local execute`` each run one build or job per launch, and their logs
    do not tell its steps apart; each page's block scans once in it, so the log holds
    exactly one verdict.
    Under act, act_verdict_problems attributes them by act's job ids instead.
    """
    actionable = sum(prepared.expected.values())
    problems = verdict.verdict_problems(log, actionable=actionable)
    if verdict.VERDICT_MISSING in problems:
        return problems
    runner = prepared.run.runner
    if runner == "gitlab-ci-local":
        jobs = _gitlab_jobs(yaml.safe_load(prepared.rewritten) or {})
        gating = [
            name
            for name, job in jobs.items()
            if any(_RUNS_ASH.search(line) for line in _script_lines(job))
        ]
        found = verdict.gitlab_job_verdicts(log, jobs)
        for job, verdicts in sorted(found.items(), key=lambda item: item[0] or ""):
            if job not in gating:
                where = f"job {job}" if job else "a line outside every job"
                problems.append(
                    f"{where} gave a verdict ({verdicts[0].actionable} actionable "
                    "findings), and it does not run ASH"
                )
        for job in gating:
            count = len(found.get(job, []))
            if count != 1:
                problems.append(f"job {job} gave {count} verdicts, not one")
        return problems
    count = len([v for v in verdict.ash_verdicts(log) if v.source == "scan"])
    if count != 1:
        problems.append(
            f"the log holds {count} verdicts, not one: {runner} runs one build per "
            "launch, and the block scans once in it"
        )
    return problems


def _uses(text: str, action: str) -> bool:
    return f"{action}@" in text


def _called_writers(prepared: Prepared) -> tuple[bool, bool]:
    """Whether a called workflow publishes a JUnit check run, and posts a comment.

    Read from the block's calls: a called workflow that runs the action, with the
    caller leaving its input on (``collect-junit-xml-report``, ``post-pr-comment``).
    """
    junit = comment = False
    workflow = reports.load_workflow(prepared.rewritten)
    for job in (workflow.get("jobs") or {}).values():
        if not isinstance(job, Mapping) or not job.get("uses"):
            continue
        name = PurePosixPath(str(job["uses"]).split("@", 1)[0]).name
        text = prepared.called.get(name)
        if text is None:
            continue
        inputs = job.get("with") if isinstance(job.get("with"), Mapping) else {}
        if _uses(text, "mikepenz/action-junit-report") and inputs.get(
            "collect-junit-xml-report", True
        ) not in (False, "false"):
            junit = True
        if _uses(text, "mshick/add-pr-comment") and inputs.get(
            "post-pr-comment", True
        ) not in (False, "false"):
            comment = True
    return junit, comment


def _stub_records(prepared: Prepared, name: str) -> list[tuple[Path, Any]]:
    records = []
    paths = sorted(
        (prepared.out / "stubs").glob(f"{name}-*.json"),
        key=lambda p: (
            int(p.stem.rsplit("-", 1)[-1]) if p.stem.rsplit("-", 1)[-1].isdigit() else 0
        ),
    )
    for path in paths:
        try:
            records.append((path, json.loads(path.read_text(encoding="utf-8"))))
        except (OSError, ValueError):
            records.append((path, None))
    return records


def stub_problems(prepared: Prepared) -> list[str]:
    """The check run and the comment the called scan workflow publishes, as recorded.

    The JUnit check run's failed tests are ASH's actionable findings; the comment is
    posted on a pull request, whose number the stub needs, so a push posts none.
    """
    junit, comment = _called_writers(prepared)
    actionable = sum(prepared.expected.values())
    problems = []
    if junit:
        records = _stub_records(prepared, "action-junit-report")
        if not records:
            problems.append(
                "the called workflow publishes a JUnit check run with "
                "mikepenz/action-junit-report, and the action-junit-report stub "
                "recorded none"
            )
        for path, record in records:
            failures = record.get("failures") if isinstance(record, Mapping) else None
            if failures != actionable:
                problems.append(
                    f"the action-junit-report stub recorded {failures!r} failed tests "
                    f"in {path.name}, expected {actionable}, the actionable findings"
                )
    if comment and prepared.run.event == "pull_request":
        records = _stub_records(prepared, "add-pr-comment")
        posted = [
            record
            for _, record in records
            if isinstance(record, Mapping)
            and record.get("issue")
            and any(
                str(name).endswith("ash.summary.md")
                for name in (record.get("files") or {})
            )
        ]
        if not posted:
            problems.append(
                "the called workflow comments on the pull request with "
                "mshick/add-pr-comment, and the add-pr-comment stub recorded no "
                "comment of ash.summary.md"
            )
    return problems


def _act_problems(prepared, launched, log, expected) -> list[str]:
    out = prepared.out
    workflow = reports.load_workflow(prepared.rewritten)
    called = {
        name: reports.load_workflow(text) for name, text in prepared.called.items()
    }
    try:
        plan = reports.act_job_plan(workflow, called)
    except ValueError as error:
        return [f"what act should report for {prepared.path} cannot be read: {error}"]
    problems = []
    if not plan:
        problems.append(
            f"{prepared.path} has no job act would run, so there is nothing to expect"
        )
    # The number of results is checked for the block's own jobs only: whether act
    # also reports a result for the job that calls a reusable workflow, under its own
    # id, is not known before the first run.
    problems += verdict.act_result_problems(
        log,
        {job: entry.result for job, entry in plan.items()},
        runs={job: entry.runs for job, entry in plan.items() if entry.caller is None},
    )
    merge = reports.gating_step(workflow, "merge")
    gating = {job: entry.runs for job, entry in plan.items() if entry.gates}
    if plan and not gating:
        problems.append(
            f"no job of {prepared.path} gates on findings, so no verdict ties the run "
            "to the ASH under test"
        )
    if gating:
        problems += verdict.act_verdict_problems(
            log,
            gating=gating,
            source="merge" if merge else "scan",
            actionable=sum(expected.values()),
        )
    # The names are read with each call's inputs resolved; a name the harness still
    # cannot read before the run is named, never looked up as literal text.
    names = reports.uploaded_artifact_names(workflow, called, plan)
    problems += [
        f"the artifact name {name!r} is an expression the harness cannot read before "
        "the run"
        for name in names
        if "${{" in name
    ]
    problems += reports.artifact_problems(
        out / "artifacts", [name for name in names if "${{" not in name]
    )
    # act's host executor runs the job in a directory it removes at the job's end and
    # never writes the project's .ash/ash_output, so the artifact the job uploaded is
    # the only copy of ASH's output: it is unpacked under out/ash_output, with each
    # file's own mtime, and the checks below read it there.
    judged, selection = reports.results_to_judge(
        reports.results_from_artifact_store(out / "artifacts")
    )
    problems += selection
    output = out / "ash_output"
    if judged is not None:
        output, unpacked = reports.unpack_artifact(judged, output)
        problems += unpacked
        problems += reports.findings_problems(
            reports.aggregated_results_at(output / reports.AGGREGATED), expected
        )
    aggregated = output / reports.AGGREGATED
    started = None
    if merge:
        job, step = merge
        started = verdict.act_step_start(log, job=job, step=step)
        if started is None:
            problems.append(f"act's log has no start of step {step!r} of job {job}")
        else:
            problems += verdict.written_after_problems(aggregated, started=started)
    # An upload is expected from the jobs the plan expects to run: a block whose SARIF
    # job calls upload-ash-sarif.yml behind an ``if`` act cannot satisfy, or whose scan
    # call turns collect-sarif-report off, uploads nothing under act.
    if reports.sarif_upload_expected(plan, prepared.run.event, workflow):
        sarif = output / "reports" / "ash.ghas.sarif"
        uploads = [path for path, _ in _stub_records(prepared, "upload-sarif")]
        if not uploads:
            problems.append(
                "the workflow uploads its SARIF, and no upload was recorded"
            )
        elif started is not None:
            problems += verdict.merged_sarif_problems(
                sarif, merge_started=started, stub_record=uploads[-1]
            )
        elif not merge:
            for upload in uploads:
                problems += verdict.stub_sarif_problems(sarif, upload)
    problems += stub_problems(prepared)
    workflows = [workflow, *called.values()]
    try:
        wrapped = reports.wrapped_job_steps(workflows)
    except ValueError as error:
        problems.append(str(error))
        wrapped = []
    # A wrapped step whose ``if`` reads false or unknown before the run is checked in
    # the runs it had, and may have none; one whose ``if`` reads true must have run.
    problems += verdict.resume_token_problems(
        log, wrapped, optional=reports.conditional_steps(workflow, called)
    )
    return problems


def _gitlab_scan_job(document: Mapping[str, Any]) -> tuple[str, Mapping[str, Any]]:
    for name, job in document.items():
        if not isinstance(job, Mapping):
            continue
        if any(reports.RUNS_SCAN.search(line) for line in _script_lines(job)):
            return str(name), job
    raise HarnessError("the GitLab pipeline has no job that runs an ASH scan")


def _script_lines(job: Mapping[str, Any]) -> list[str]:
    lines: list[str] = []
    for key in ("before_script", "script", "after_script"):
        value = job.get(key) or []
        lines += [str(value)] if isinstance(value, str) else [str(v) for v in value]
    return lines


_WRITES_EXIT_CODE = re.compile(r">>?\s*" + re.escape(EXIT_CODE_FILE))
#: A job's script exiting with the output of a command.
_EXITS_WITH_OUTPUT = re.compile(r"\bexit\s+[\"']?\$\(")
#: ... and that command reading one file: ``exit "$(cat <file>)"`` or ``$(< <file>)``.
_EXITS_WITH_FILE = re.compile(
    r"\bexit\s+[\"']?\$\(\s*(?:cat\s+|<\s*)[\"']?([^\s\"')]+)[\"']?\s*\)"
)


def gitlab_exit_code_problems(prepared: Prepared) -> list[str]:
    """The exit code the scan job keeps for the gate job must be ASH's 2.

    Every file another job exits with (``exit "$(cat <file>)"``) must be in the scan
    job's kept artifacts and hold 2, and so must ash-exit-code.txt whenever a job
    reads it or the scan job keeps it, wherever the artifact paths put it. The gate
    fails on that file, so a run whose gate failed for another reason would otherwise
    pass for one that found the findings; a gate whose file is missing fails too,
    since ``exit ""`` is a usage error, which exits 2. A job that exits with the
    output of a command the harness cannot read one file from is a problem of its
    own.
    """
    document = yaml.safe_load(prepared.rewritten) or {}
    name, job = _gitlab_scan_job(document)
    problems = []
    read: dict[str, list[str]] = {}
    for other_name, other in _gitlab_jobs(document).items():
        if other_name == name:
            continue
        for line in _script_lines(other):
            if EXIT_CODE_FILE in line and not _WRITES_EXIT_CODE.search(line):
                read.setdefault(EXIT_CODE_FILE, []).append(other_name)
            if not _EXITS_WITH_OUTPUT.search(line):
                continue
            reads = _EXITS_WITH_FILE.search(line)
            if reads is None:
                problems.append(
                    f"job {other_name} exits with the output of a command the harness "
                    f"cannot tell the file of ({line.strip()[:200]!r}), so what its "
                    "gate failed on is not checked"
                )
                continue
            path = reads[1].removeprefix("./")
            if other_name not in read.setdefault(path, []):
                read[path].append(other_name)
    paths = [str(p) for p in ((job.get("artifacts") or {}).get("paths") or [])]
    if EXIT_CODE_FILE in paths:
        read.setdefault(EXIT_CODE_FILE, [])
    kept = prepared.project / ".gitlab-ci-local" / "artifacts" / name
    for path, readers in read.items():
        exit_file = kept / path
        recorded = (
            exit_file.read_text(encoding="utf-8").strip()
            if exit_file.is_file() and not exit_file.is_symlink()
            else None
        )
        if recorded != str(verdict.FINDINGS_EXIT_CODE):
            read_by = ", ".join(dict.fromkeys(readers)) if readers else "the pipeline"
            problems.append(
                f"{path}, which {read_by} reads, holds {recorded!r} in {name}'s kept "
                f"artifacts, not ASH's exit code {verdict.FINDINGS_EXIT_CODE}"
            )
    return problems


def built_image_problems(prepared: Prepared, launched: Launched) -> list[str]:
    """A block on the image the run builds must run that image, by its id."""
    if prepared.mechanism != "built":
        return []
    image_id = launched.image_id
    if not image_id:
        return [
            (
                "the run recorded no id of the image it built for the block, so which "
                "image the job ran is unknown"
            )
        ]
    log = launched.text()
    short = image_id.removeprefix("sha256:")[:12]
    if image_id not in log and not (len(short) == 12 and short in log):
        return [
            (
                f"the log does not show the job running {image_id}, the image this "
                "run built"
            )
        ]
    return []


def _gitlab_problems(prepared, launched, log, expected) -> list[str]:
    problems = []
    if launched.code == 0:
        problems.append(
            "gitlab-ci-local exited 0; the gate job must fail on the planted findings"
        )
    problems += scan_verdict_problems(prepared, log)
    name, _ = _gitlab_scan_job(yaml.safe_load(prepared.rewritten) or {})
    kept = prepared.project / ".gitlab-ci-local" / "artifacts" / name
    problems += gitlab_exit_code_problems(prepared)
    problems += reports.findings_problems(
        reports.aggregated_results_at(
            kept / ".ash" / "ash_output" / reports.AGGREGATED
        ),
        expected,
    )
    problems += built_image_problems(prepared, launched)
    return problems


def _jenkins_problems(prepared, launched, log, expected) -> list[str]:
    out = prepared.out
    problems = []
    if launched.steps.get("lint") != 0:
        problems.append(
            f"Jenkinsfile Runner's lint exited {launched.steps.get('lint')}:\n"
            + reports.tail(out / "jenkinsfile-runner-lint.log", TAIL_LINES, TAIL_CHARS)
        )
    if launched.code == 0:
        problems.append(
            "the Jenkins build passed; its sh step must fail with ASH's exit 2"
        )
    if "script returned exit code 2" not in log:
        problems.append("the build log does not show the sh step exiting with ASH's 2")
    problems += scan_verdict_problems(prepared, log)
    home = prepared.work / "jenkins-home"
    problems += verdict.jenkins_junit_problems(home, failures=sum(expected.values()))
    archive = home.joinpath(*JENKINS_BUILD) / "archive" / ".ash" / "ash_output"
    problems += reports.findings_problems(
        reports.aggregated_results_at(archive / reports.AGGREGATED), expected
    )
    return problems


def _codebuild_problems(prepared, launched, log, expected) -> list[str]:
    artifacts, report_dir = run_codebuild_agent.codebuild_dirs(prepared.work)
    actionable = sum(expected.values())
    problems = []
    state = verdict.codebuild_build_state(log)
    if state != "FAILED":
        problems.append(f"the CodeBuild BUILD phase ended {state}, not FAILED")
    problems += scan_verdict_problems(prepared, log)
    tests, failures = reports.junit_counts(report_dir)
    if tests == 0:
        problems.append(f"the agent kept no JUnit report under {report_dir}")
    elif failures != actionable:
        problems.append(
            f"the agent's JUnit report under {report_dir} records {failures} failed "
            f"tests, expected {actionable}, the actionable findings"
        )
    problems += reports.findings_problems(
        reports.aggregated_results_in(artifacts), expected
    )
    return problems


def _circleci_problems(prepared, launched, log, expected) -> list[str]:
    out = prepared.out
    problems = []
    for command in ("validate", "process"):
        if launched.steps.get(command) != 0:
            problems.append(
                f"circleci config {command} exited {launched.steps.get(command)}:\n"
                + reports.tail(
                    out / f"circleci-config-{command}.log", TAIL_LINES, TAIL_CHARS
                )
            )
    if launched.code == 0:
        problems.append(
            "circleci local execute exited 0; the job must fail on findings"
        )
    problems += scan_verdict_problems(prepared, log)
    problems += reports.findings_problems(
        reports.aggregated_results_in(out / "circleci-reports"), expected
    )
    return problems


# ---------------------------------------------------------------------------
# Negative controls
# ---------------------------------------------------------------------------


def _run_command_lines(text: str) -> frozenset[str]:
    """Every line of every run step's command in a CircleCI config, stripped."""
    try:
        config = yaml.safe_load(text) or {}
    except yaml.YAMLError:
        return frozenset()
    jobs = config.get("jobs") if isinstance(config, Mapping) else None
    lines: set[str] = set()
    for job in jobs.values() if isinstance(jobs, Mapping) else ():
        steps = job.get("steps") if isinstance(job, Mapping) else None
        for step in steps if isinstance(steps, list) else ():
            run = step.get("run") if isinstance(step, Mapping) else None
            command = run.get("command") if isinstance(run, Mapping) else run
            if isinstance(command, str):
                lines.update(line.strip() for line in command.splitlines())
    lines.discard("")
    return frozenset(lines)


def script_output(prepared: Prepared, log: str) -> list[str] | None:
    """The lines the job's own commands printed, from the first line that shows its
    script started (SCRIPT_STARTED); None when no line shows that.

    Lines before the start are the runner's own. A runner's echo of a command is not
    the command's output (COMMAND_ECHO), nor, under the CircleCI agent, which prints
    each run command under ``#!/bin/bash -eo pipefail`` before it runs it, a line that
    is a line of one of the config's run commands. Under act only what a step printed
    counts, which act marks ``raw_output``; act's own messages (a step's name, its
    errors) do not.
    """
    runner = prepared.run.runner
    started = SCRIPT_STARTED.get(runner)
    lines = list(verdict.log_lines(log))
    first = next(
        (
            index
            for index, (text, _) in enumerate(lines)
            if started is not None and started.search(text)
        ),
        None,
    )
    if first is None:
        return None
    echo = COMMAND_ECHO.get(runner)
    commands = (
        _run_command_lines(prepared.rewritten) if runner == "circleci" else frozenset()
    )
    output = []
    for text, kind in lines[first + 1 :]:
        if runner == "act" and kind != "step":
            continue
        if echo is not None and echo.search(text):
            continue
        if text.strip() in commands:
            continue
        output.append(text)
    return output


def control_problems(prepared: Prepared, launched: Launched) -> list[str]:
    """With an install that cannot succeed, the run must fail on it, with no verdict.

    The job's script must have started; after it started, a line the script printed
    must name the input the control broke (the absent wheel, or the absent commit)
    with the installer's own refusal of it (REFUSALS); and the runner must report a
    failure. A runner that never started, an install that failed on something else,
    or one that names the input only in an echo of its command, in a line printed
    before the script started, or in a message about another failure (a network
    error names the commit too) proves nothing about the check.
    """
    if launched.timed_out is not None:
        return [f"the control did not finish in time: {launched.timed_out}"]
    log = launched.text()
    runner = prepared.run.runner
    problems = []
    verdicts = verdict.ash_verdicts(log)
    if verdicts:
        problems.append(
            f"ASH gave a verdict ({verdicts[0].actionable} actionable findings) although "
            "the install under test could not succeed, so another ASH ran"
        )
    elif verdict.verdict_problems(log) != [verdict.VERDICT_MISSING]:
        problems.append("the verdict check did not report the missing verdict")
    output = script_output(prepared, log)
    if output is None:
        problems.append(
            f"{runner}'s log shows no sign that the job's script started, so the "
            "control shows nothing about the install"
        )
    mechanism = prepared.mechanism
    refusal = REFUSALS.get(mechanism or "")
    if refusal is None:
        problems.append(
            f"the block installs ASH by {mechanism}, which no control breaks"
        )
    else:
        broken = ABSENT_WHEEL_NAME if mechanism == "wheel" else ABSENT_COMMIT
        if not any(broken in line and refusal.search(line) for line in output or []):
            problems.append(
                f"no line the job's script printed after it started names {broken}, "
                f"the input this control broke, with the installer's refusal of it "
                f"({refusal.pattern}), so the install did not fail on it"
            )
    if runner == "act":
        failed = any(r.result == "failure" for r in verdict.act_job_results(log))
    elif runner == "codebuild-agent":
        failed = "FAILED" in verdict.codebuild_phase_states(log).values()
    else:
        failed = launched.code != 0
    if not failed:
        problems.append(
            f"{runner} reported success for a pipeline whose install failed"
        )
    return problems


def failure_message(problems: list[str], launched: Launched | None) -> str:
    """The problems, and a short tail of the runner's log."""
    lines = [f"- {problem}" for problem in problems]
    if launched is not None:
        lines.append(f"the end of {launched.log}:")
        lines.append(reports.tail(launched.log, TAIL_LINES, TAIL_CHARS))
    return "\n".join(lines)
