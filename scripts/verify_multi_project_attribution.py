# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Prove a workspace scan keeps its projects apart.

Run with: python scripts/verify_multi_project_attribution.py

Why this exists
---------------
``scripts/verify_external_target_scan.py`` proves ASH can scan one directory that
is not its working directory, and asserts on what came back. Workspace mode
multiplies that by N, and the failures it can produce are ones a single-directory
gate structurally cannot see:

* A finding from project A reported against project B. The counts still add up,
  the exit code is still plausible, and the operator fixes the wrong file.
* Project A's suppression silencing the same rule at the same relative path in
  project B. Silent, and a false negative in a security tool -- the worst
  direction for this to fail in.
* Both projects judged against one threshold. Every project then reports a
  verdict, and one of them is the wrong verdict.
* Two projects sharing an output directory, so the second scanner run overwrites
  the first's raw output.

None of those show up as an error. All four produce a complete, well-formed
results file, which is exactly why they need a positive gate rather than an exit
status check.

How the fixture is built to catch each one
------------------------------------------
Four projects, generated at runtime outside the repository:

* ``project-a`` -- threshold LOW, with a suppression for one rule at
  ``src/insecure.py``. Marker rule B101.
* ``project-b`` -- threshold LOW, no suppression. Same threshold as A on purpose,
  so the two are directly comparable: any difference between them is the
  suppression and nothing else. Marker rule B311.
* ``src`` -- threshold CRITICAL. Named ``src`` deliberately: container mode mounts
  the workspace root at ``/src``, so this project is ``/src/src``, the shape that
  re-enters the basename heuristic in ``sarif_utils`` (#361). It also carries the
  looser threshold, so it produces the same shared findings as B and a different
  verdict. Marker rule B403.
* ``apps/admin`` -- threshold LOW, and **nested**, so its key (``apps-admin``) is
  not its path. That distinction is not cosmetic: a check comparing a
  workspace-relative URI against the project *key* rejects every finding in this
  project while looking perfectly reasonable, and without a project of this shape
  in the fixture the bug is invisible. Marker rule B405.

Every project holds a byte-identical ``src/insecure.py``. That is what makes
attribution testable at all: with four different files, "the finding is
attributed to A" would be satisfied by matching on the filename, and a broken
attribution that credited every finding to the project whose file it came from
would pass.

The marker rules are the other half, and they exist because identical files alone
are not enough. Each project also holds ``src/marker.py`` -- same path everywhere,
different content -- tripping one bandit rule no other project trips. The reason
is that the aggregator stamps the project key onto the SARIF run and onto every
result in it from one variable in one loop, so any check comparing those two
values compares a value with itself. Exchange two runs' attributions and the
payload stays perfectly self-consistent while every finding is mislabelled. The
marker's ground truth is source on disk rather than the payload, so nothing in the
pipeline can move both sides together.

Deliberate choices
------------------
* Assertions on thresholds are *relative*, not absolute. Bandit's per-rule
  severities move between releases, so asserting "project-b has 4 actionable
  findings" turns an upstream release into a red branch -- which has happened to
  this project before. What cannot move is that CRITICAL is looser than LOW over
  identical findings, so the gate asserts ``src < project-b`` and that
  ``project-b`` is non-zero. Strictly less, not "no more than": equal counts are
  what "the threshold was never applied" looks like, and tolerating them made the
  check unable to fail on its own subject.
* Every project must report findings, not merely status ``completed``. A project
  that scanned nothing satisfies every attribution assertion by giving them
  nothing to inspect, so three of four projects could silently not run.
* Two producers, and both matter. Bandit carries the marker rules and the
  suppression, because it is Python-only, installed on every runner, and reports a
  per-finding ``issue_severity``. Checkov reads the ``.tf`` file and contributes
  roughly as many findings again; without a second scanner family the rollup check
  could not show one scanner's count leaking into another's. No credential-shaped
  literal appears anywhere, because detect-secrets matches line by line rather
  than on an AST and this file is itself scanned by ASH's own self-scan.
* Only bandit's findings are thresholdable, which the threshold check depends on.
  Measured on this fixture: checkov emits no ``properties.issue_severity``, so
  those findings are gated by SARIF level instead, and the ladder maps ``error`` to
  CRITICAL -- actionable at every threshold, CRITICAL included. Raising a project
  to CRITICAL therefore silences bandit's non-critical findings and none of
  checkov's. Pre-existing behaviour, shared with ``_compute_exit_code``; recorded
  here because it is the opposite of what "CRITICAL gates almost nothing" suggests
  and it is what sets the margin the threshold assertion relies on.
* ``--phases scan`` only. The report phase is the next PR's subject and would add
  minutes without adding signal here.
* ``--scanners bandit --scanners checkov``, so the gate runs only the two
  producers it reads. This is about determinism rather than runtime: opengrep and
  semgrep default to the ``p/ci`` ruleset, which is fetched over the network, and
  four concurrent projects make four concurrent fetches. A lost fetch is scanner
  status ERROR, which ``check_no_scanner_errors`` refuses to tolerate -- correctly,
  since tolerating ERROR is how a total functional failure reached main earlier in
  this project. The gate was therefore red on a flake in a producer no assertion
  reads. See ``GATE_SCANNERS``.
* The scan is invoked as ``<python> -m automated_security_helper.cli.main`` with
  ``cwd`` set to the repository root, so ``-m`` puts the working tree on
  ``sys.path`` rather than whatever copy is pip-installed on the runner.

Known limitations
-----------------
* Local mode only. There is no OCI runtime on these runners, so the containerised
  workspace path is covered by unit tests over the assembled command and the
  per-project basename guard, not by a real container run.
* A green gate is evidence about bandit and checkov, and about nothing else. The
  other scanners are not run at all (``GATE_SCANNERS``), so this gate says nothing
  about whether they work in workspace mode. It did not say much before either:
  measured on this fixture they all returned PASSED with zero findings, so the only
  claim lost is "they did not ERROR". Covering them needs a fixture with input they
  actually match, which is a different gate.
* If bandit cannot be installed the gate fails rather than passing quietly. A
  gate that silently tests nothing is worse than a red one.
* The suppression assertion needs the suppressed rule to actually fire. If a
  bandit release stops reporting it at all, the gate says so explicitly rather
  than treating "absent everywhere" as "correctly suppressed". The same holds for
  the suppressing project alone: the rule missing from it while present in the
  others is reported, because that project has to show the rule with its
  suppression on it.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import shlex
import shutil
import signal
import subprocess  # nosec B404 -- the gate runs ASH as a child process
import sys
import tempfile
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple
from urllib.parse import unquote

RESULTS_FILENAME = "ash_aggregated_results.json"
WORKSPACE_FILENAME = "fixture.code-workspace"

STATUS_ERROR = "ERROR"
STATUS_MISSING = "MISSING"
STATUS_SKIPPED = "SKIPPED"
#: Not a product status: the rollup marks a scanner the configuration excluded
#: with an ``excluded`` flag beside whatever status it carries. The flag is
#: folded into the status here so the did-it-run check reads one value.
STATUS_EXCLUDED = "EXCLUDED"

# Workspace exit codes: 0 success, 1 internal error, 2 actionable findings at or
# above threshold, 3 invalid project config, 4 workspace definition or policy error,
# 5 a usage error (for example a --scanners selection no project could run).
# The fixture is built to produce actionable findings in project-a and project-b,
# so 2 is expected. 0 is tolerated only when no completed project reports
# exceeds_threshold (check_exit_code judges the code against the projects). The
# fixture does not turn fail_on_findings off; if a future default did,
# check_verdicts_match_their_counts would refuse the payload first, because
# exceeds_threshold would then disagree with every non-zero actionable count.
#
# Tolerating 2 is safe precisely because the definition error is 4. Were they the
# same number, this tuple would silently accept a workspace that resolved to
# nothing -- the gate would pass having scanned no projects at all.
# check_workspace_status() still cross-checks the payload's own status and
# exit_code, so a drift on either side surfaces rather than being tolerated.
TOLERATED_EXIT_CODES = (0, 2)

#: What a refused workspace exits with. Never tolerated: it means no project ran.
WORKSPACE_ERROR_EXIT_CODE = 4

# The job runs this script under timeout-minutes: 30 (1800 s). The scan timeout
# has to stay under that, or GitHub cancels the job before this script prints its
# tables. What the job spends besides the scan comes out of the difference: the
# steps before the scan (checkout, the ASH install, the tool downloads, the
# fixture build) and, after a timed-out scan, the stop and the drain of the
# child (up to 2 * (SHUTDOWN_GRACE_SECONDS + DRAIN_SECONDS), 60 s). So the
# default leaves 540 s for the setup, and --timeout is checked when parsed
# against MAX_SCAN_TIMEOUT_SECONDS, the budget less a setup floor and the
# shutdown, rather than against the bare budget: a value such as 1700 stayed
# under 1800 and was accepted, and GitHub then cancelled the job before this
# script's diagnostics could print.
JOB_TIMEOUT_BUDGET_SECONDS = 1800.0
DEFAULT_SCAN_TIMEOUT_SECONDS = 1200.0
#: The least the job's steps before the scan are given, whatever --timeout says.
SETUP_MARGIN_SECONDS = 300.0
LOG_TAIL_LINES = 60

#: The only scanners this gate reads, so the only ones it runs.
#:
#: Restricting the run is a correctness property, not a speed optimisation. Every
#: assertion below reads bandit (the marker rules, the suppression, the
#: thresholdable severities) or checkov (the second scanner family the rollup
#: check needs); nothing reads any other producer. Leaving the rest enabled
#: therefore added no signal and one dependency: opengrep and semgrep default to
#: the ``p/ci`` ruleset, which is fetched from a rule registry over the network.
#: With four projects running concurrently that is four simultaneous fetches, and
#: a fetch that loses gives the scanner status ERROR -- which check_no_scanner_errors
#: correctly refuses to tolerate. So the gate went red on a network flake in a
#: producer it asserts nothing about.
#:
#: An allowlist rather than excluding the two grep scanners by name: a future
#: scanner that reaches the network on startup would silently reintroduce the
#: flake through a denylist, and would have to be named here to reintroduce it
#: through this one.
GATE_SCANNERS: Tuple[str, ...] = ("bandit", "checkov")


# ---------------------------------------------------------------------------
# Fixture content
#
# Written to disk at runtime, never committed: ASH scans its own repository in
# CI, so a committed fixture would fail the repository scan. Every construct is a
# stable bandit finding. They appear here as string literals, which is safe --
# bandit parses an AST, so a string constant in this file is not a finding.
# ---------------------------------------------------------------------------

FIXTURE_PYTHON = '''"""Deliberately insecure module. Scan fixture only -- never imported."""

import hashlib
import subprocess


def weak_digest(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def run_untrusted(command: str) -> int:
    return subprocess.call(command, shell=True)


def evaluate(expression: str):
    return eval(expression)
'''

FIXTURE_TERRAFORM = """resource "aws_s3_bucket" "gate_fixture" {
  bucket = "ash-multi-project-gate-fixture"
}
"""

#: The rule project-a suppresses. B324 is hashlib.md5 -- present in every bandit
#: release this project has run against, and independent of the other two
#: findings so suppressing it does not change whether project-a has a verdict.
SUPPRESSED_RULE_ID = "B324"

#: Where the fixture files live inside every project. Identical across all three,
#: which is what makes the suppression and attribution scoping testable.
FIXTURE_RELATIVE_PATH = "src/insecure.py"

#: A second producer, and not decoration: it doubles the scanner families the
#: gate asserts on and it is what makes the scanner-rollup check meaningful,
#: since a single-scanner rollup cannot show one scanner's count leaking into
#: another's.
#:
#: It was added while chasing the absolute-URI defect, on the expectation that
#: checkov would emit the separator-stripped absolute shape
#: (``ws/api/src/x.tf``) that used to be mis-prefixed. Measured: in workspace
#: mode it does NOT -- ``sanitize_sarif_paths`` runs with the project as
#: ``source_dir`` and has already relativized the path by the time the aggregator
#: sees it, so both scanners hand over ``src/...``. The absolute shapes recorded
#: in ``verify_external_target_scan.py`` are therefore not reachable through this
#: fixture. That measurement is also why ``project_relative_uri`` reads every
#: unrooted URI as project-relative and never tries the separator-stripped
#: shape as absolute (a src-layout project's own relative URIs spell its
#: absolute path); the coverage for the rooted shapes is the parametrised unit
#: tests in ``tests/unit/workspace/test_aggregation.py::TestAbsoluteScannerUris``,
#: not this gate. Stated here so nobody reads a green gate as proof of it.
FIXTURE_TERRAFORM_RELATIVE_PATH = "src/insecure_bucket.tf"

# ---------------------------------------------------------------------------
# Per-project marker rules: the independent ground truth for attribution
#
# Every project holds a file at the SAME relative path, with content that trips
# exactly one bandit rule no other project trips. That combination is what makes
# attribution checkable rather than merely self-consistent.
#
# The problem it solves. The aggregator stamps the project key onto the SARIF run
# and onto every result in that run from one local variable in one loop, so
# comparing "the run says A" against "the result says A" compares a value with
# itself: the check cannot fail, and it passed for that reason rather than
# because attribution worked. Swap two runs' attributions and both sides move
# together, leaving every finding consistently mislabelled and the gate green.
#
# A marker rule breaks that. The run's claimed project comes from the payload;
# the rule that fired comes from source on disk. Nothing in the pipeline can move
# both, so if project A's run contains B's marker, the scan filed B's file under
# A -- which is exactly the shape a shared scanner instance produces.
#
# Chosen against bandit 1.9.4 and verified not to overlap the shared file's
# rules, which are B307, B324, B404 and B602. All four markers are LOW severity,
# so the threshold comparison stays a comparison of like with like.
# ---------------------------------------------------------------------------

#: Where each project's marker lives. Identical across projects on purpose: a
#: distinct filename per project would let attribution be satisfied by matching
#: on the name, which is the hole this fixture is built to close.
FIXTURE_MARKER_RELATIVE_PATH = "src/marker.py"

#: bandit rule id -> the source that trips it and nothing else in this fixture.
MARKER_SOURCES: Dict[str, str] = {
    # B101 assert_used
    "B101": '"""Marker module. Scan fixture only -- never imported."""\n'
    "\n"
    "\n"
    "def check(value):\n"
    "    assert value is not None\n"
    "    return value\n",
    # B311 random -- not suitable for security or cryptographic purposes
    "B311": '"""Marker module. Scan fixture only -- never imported."""\n'
    "\n"
    "import random\n"
    "\n"
    "\n"
    "def pick() -> float:\n"
    "    return random.random()\n",
    # B403 blacklist -- importing pickle
    "B403": '"""Marker module. Scan fixture only -- never imported."""\n'
    "\n"
    "import pickle\n"
    "\n"
    "\n"
    "def name() -> str:\n"
    "    return pickle.__name__\n",
    # B405 blacklist -- importing xml.etree.ElementTree
    "B405": '"""Marker module. Scan fixture only -- never imported."""\n'
    "\n"
    "import xml.etree.ElementTree\n"
    "\n"
    "\n"
    "def name() -> str:\n"
    "    return xml.etree.ElementTree.__name__\n",
}

#: The rules the shared insecure module trips in every project. Recorded so the
#: fixture self-check can prove no marker collides with one -- a marker that also
#: fired everywhere would identify nothing.
SHARED_FILE_RULE_IDS = frozenset({"B307", "B324", "B404", "B602"})

#: Every fixture file that is identical in every project, by project-relative
#: path. The marker file is deliberately not here: its path is shared but its
#: content is per project.
FIXTURE_FILES: Dict[str, str] = {
    FIXTURE_RELATIVE_PATH: FIXTURE_PYTHON,
    FIXTURE_TERRAFORM_RELATIVE_PATH: FIXTURE_TERRAFORM,
}

CONFIG_TEMPLATE = """project_name: {name}
global_settings:
  severity_threshold: {threshold}
"""

CONFIG_WITH_SUPPRESSION_TEMPLATE = """project_name: {name}
global_settings:
  severity_threshold: {threshold}
  suppressions:
    - rule_id: {rule_id}
      path: {path}
      reason: Fixture-only finding, suppressed to prove per-project scoping
"""

#: The execution knobs the workspace root's config sets. The payload reports the
#: values the run used, and check_execution_knobs_reached_the_run compares them:
#: the config used to be written and never asserted, so the documented check
#: that the knobs are read from the root could not fail.
ROOT_MAX_PARALLEL_PROJECTS = 4
ROOT_PROJECT_TIMEOUT_SECONDS = 600

#: Read by the workspace root's config. Exercises that the execution knobs are
#: picked up from the root rather than from a project.
WORKSPACE_ROOT_CONFIG = f"""project_name: multi-project-gate
workspace:
  max_parallel_projects: {ROOT_MAX_PARALLEL_PROJECTS}
  project_timeout: {ROOT_PROJECT_TIMEOUT_SECONDS}
"""


@dataclass(frozen=True)
class FixtureProject:
    """One project in the generated workspace.

    ``key`` and ``relative_path`` are separate fields because they are separate
    things, and conflating them was a real defect: resolution derives the key from
    the path by replacing separators with dashes, so a nested project has a key
    that is not its path. A check written against the key then rejects the
    project's own perfectly correct workspace-relative paths.
    """

    key: str
    relative_path: str
    threshold: str
    marker_rule: str
    suppress_rule: str | None = None


FIXTURE_PROJECTS: Tuple[FixtureProject, ...] = (
    FixtureProject(
        key="project-a",
        relative_path="project-a",
        threshold="LOW",
        marker_rule="B101",
        suppress_rule=SUPPRESSED_RULE_ID,
    ),
    FixtureProject(
        key="project-b",
        relative_path="project-b",
        threshold="LOW",
        marker_rule="B311",
    ),
    # Named 'src' on purpose: the workspace root is /src in container mode, so
    # this is the folder-inside-its-own-name shape from #361.
    FixtureProject(
        key="src",
        relative_path="src",
        threshold="CRITICAL",
        marker_rule="B403",
    ),
    # Nested, so its key ('apps-admin') differs from its path ('apps/admin').
    # Without a project of this shape, a check comparing a workspace-relative URI
    # against the project *key* is wrong and still green.
    FixtureProject(
        key="apps-admin",
        relative_path="apps/admin",
        threshold="LOW",
        marker_rule="B405",
    ),
)

#: The project that configures a suppression. Every other project is compared
#: against it, rather than one hand-picked partner -- an earlier version named a
#: single pair and so never looked at two of the projects at all.
SUPPRESSING_PROJECT = "project-a"

#: The pair whose only difference is the threshold.
THRESHOLD_PAIR = ("project-b", "src")

#: project key -> the one bandit rule only that project's source trips.
MARKER_RULE_BY_PROJECT: Dict[str, str] = {
    project.key: project.marker_rule for project in FIXTURE_PROJECTS
}

#: project key -> its path relative to the workspace root.
RELATIVE_PATH_BY_PROJECT: Dict[str, str] = {
    project.key: project.relative_path for project in FIXTURE_PROJECTS
}

#: Every marker rule, for asking "does this run contain someone else's marker".
ALL_MARKER_RULES = frozenset(MARKER_RULE_BY_PROJECT.values())


# ---------------------------------------------------------------------------
# Parsed views of the results file
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProjectOutcome:
    """One entry of ``workspace.projects``, normalized."""

    key: str
    relative_path: str
    status: str
    threshold: str
    finding_count: int
    actionable_finding_count: int
    exceeds_threshold: bool
    output_path: str
    sarif_run_index: int | None
    error: str | None


@dataclass(frozen=True)
class RunEvidence:
    """One SARIF run, reduced to what the gate asserts on."""

    index: int
    attributed_project: str | None
    uri_base: str | None
    #: rule id -> (unsuppressed count, suppressed count)
    rules: Dict[str, Tuple[int, int]] = field(default_factory=dict)
    #: every workspace_uri seen, in encounter order
    workspace_uris: Tuple[str, ...] = ()
    #: every raw artifact uri seen, in encounter order
    raw_uris: Tuple[str, ...] = ()
    #: every originalUriBaseIds entry of the run: base id -> uri. ``uri_base`` is
    #: the PROJECTROOT entry's uri, else the first of them (collect_runs); a
    #: result names its own with artifactLocation.uriBaseId.
    uri_bases: Dict[str, str] = field(default_factory=dict)
    #: the uriBaseId each raw uri was anchored to, parallel to ``raw_uris``; None
    #: for a location that names none.
    raw_uri_bases: Tuple[str | None, ...] = ()
    #: results that offered no location at all. Such a finding has no path to
    #: lose, so the path-loss accounting leaves it out of its denominator.
    results_without_location: int = 0
    #: project keys named by results inside this run
    result_projects: Tuple[str, ...] = ()
    #: one (workspace_uri, artifact uris of the same result) pair for every result
    #: that carries a workspace_uri, in encounter order. ``workspace_uris`` and
    #: ``raw_uris`` are flat, so only this field can say which file a value is for.
    located_results: Tuple[Tuple[str, Tuple[str, ...]], ...] = ()
    #: every result in the run, whatever properties it carries. The denominator
    #: for "every finding carries a workspace path": counting only the results
    #: that carry a project attribution let a result with no properties at all
    #: pass both sides of that accounting.
    result_count: int = 0


@dataclass
class GateOutcome:
    violations: List[str] = field(default_factory=list)
    projects: Tuple[ProjectOutcome, ...] = ()
    runs: Tuple[RunEvidence, ...] = ()
    scanner_statuses: Dict[str, str] = field(default_factory=dict)
    #: Violations that explain other violations. A scanner reporting ERROR
    #: produced no findings, so a downstream "rule X is missing from project Y"
    #: or "two thresholds saw equal counts" may follow from it rather than being
    #: an independent defect. Reporting one dead scanner as ten problems sends
    #: the reader chasing nine symptoms; the report groups the rest under it as
    #: candidates, not as proven consequences, since a missing output directory
    #: or a wrong exit code does not follow from a dead scanner. Kept as a
    #: subset of ``violations`` so ``passed`` and the exit status are unchanged.
    root_violations: List[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.violations

    @property
    def consequential_violations(self) -> List[str]:
        """Violations that are not themselves a named root cause."""
        roots = set(self.root_violations)
        return [v for v in self.violations if v not in roots]

    @property
    def errored_scanners(self) -> List[str]:
        return sorted(
            name
            for name, status in self.scanner_statuses.items()
            if status == STATUS_ERROR
        )


# ---------------------------------------------------------------------------
# Pure assertion logic
#
# Everything below takes an already-parsed results dict and returns violation
# strings. No subprocesses, no filesystem, no global state -- so every check is
# unit-testable without running a scan.
# ---------------------------------------------------------------------------


def normalize_status(raw: Any) -> str:
    text = str(raw if raw is not None else "").strip()
    if "." in text:
        text = text.rsplit(".", 1)[-1]
    return text.upper()


def _as_int(value: Any) -> int:
    """``value`` as an int, or 0 for anything that is not one.

    OverflowError is caught too: ``json.loads`` accepts ``Infinity``, and
    ``int(float("inf"))`` raises it rather than ValueError.
    """
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return 0


def _as_optional_int(value: Any) -> int | None:
    """``value`` as an int, or None when it is absent or not an integer.

    For a field whose absence means something (``sarif_run_index``,
    ``workspace.exit_code``), reading garbage or nothing as 0 selected the first
    run or matched a process that exited 0; None lets the check say so instead.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, float) and not value.is_integer():
        return None
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def check_results_shape(results: Any) -> List[str]:
    """Verify the keys every other check reads actually exist.

    Without this, a renamed key makes every downstream assertion vacuously true
    and the gate reports success having inspected nothing. ``scanner_results``
    is checked here too: a non-object value used to reach ``.items()`` in the
    rollup check and end the gate in an AttributeError instead of a violation.
    """
    if not isinstance(results, Mapping):
        return [
            (
                f"results is not a JSON object (got {type(results).__name__}); expected "
                f"the parsed contents of {RESULTS_FILENAME}"
            )
        ]

    violations: List[str] = []
    workspace = results.get("workspace")
    if not isinstance(workspace, Mapping):
        violations.append(
            "results has no 'workspace' object. Either the scan ran in "
            "single-directory mode, or the payload moved. Top-level keys: "
            f"{sorted(str(key) for key in results)}"
        )
    else:
        if not isinstance(workspace.get("projects"), list):
            violations.append(
                "'workspace.projects' is not a list -- every per-project "
                "assertion below would inspect nothing"
            )
        elif not workspace["projects"]:
            violations.append("'workspace.projects' is empty -- no project ran")

    if not isinstance(results.get("sarif"), Mapping):
        violations.append(
            "results has no top-level 'sarif' object -- the attribution "
            "assertions below would inspect nothing"
        )
    scanner_results = results.get("scanner_results")
    if scanner_results is not None and not isinstance(scanner_results, Mapping):
        violations.append(
            f"'scanner_results' is a {type(scanner_results).__name__}, not an "
            "object -- the scanner rollup assertions below would inspect nothing"
        )
    return violations


def parse_projects(results: Mapping[str, Any]) -> Tuple[ProjectOutcome, ...]:
    workspace = results.get("workspace") or {}
    outcomes: List[ProjectOutcome] = []
    for entry in workspace.get("projects") or []:
        record: Mapping[str, Any] = entry if isinstance(entry, Mapping) else {}
        outcomes.append(
            ProjectOutcome(
                key=str(record.get("project") or ""),
                relative_path=str(record.get("relative_path") or ""),
                status=str(record.get("status") or "").lower(),
                threshold=str(record.get("severity_threshold") or ""),
                finding_count=_as_int(record.get("finding_count")),
                actionable_finding_count=_as_int(
                    record.get("actionable_finding_count")
                ),
                exceeds_threshold=bool(record.get("exceeds_threshold", False)),
                output_path=str(record.get("output_path") or ""),
                # None for an absent value and for garbage alike: a non-integer
                # used to coerce to 0 and select the first run.
                sarif_run_index=_as_optional_int(record.get("sarif_run_index")),
                error=(
                    str(record["error"]) if record.get("error") is not None else None
                ),
            )
        )
    return tuple(outcomes)


def _result_property(result: Mapping[str, Any], name: str) -> str | None:
    properties = result.get("properties")
    if not isinstance(properties, Mapping):
        return None
    raw = properties.get(name)
    if raw is None:
        return None
    text = str(raw).strip()
    return text or None


def _artifact_location(location: Any) -> Mapping[str, Any] | None:
    if not isinstance(location, Mapping):
        return None
    physical = location.get("physicalLocation")
    if not isinstance(physical, Mapping):
        return None
    artifact = physical.get("artifactLocation")
    return artifact if isinstance(artifact, Mapping) else None


def _location_uri(location: Any) -> str | None:
    artifact = _artifact_location(location)
    if artifact is None:
        return None
    uri = artifact.get("uri")
    if uri is None:
        return None
    text = str(uri).strip()
    return text or None


def _location_base_id(location: Any) -> str | None:
    """The ``uriBaseId`` a location anchors its uri to, or None for an unanchored one."""
    artifact = _artifact_location(location)
    if artifact is None:
        return None
    base_id = artifact.get("uriBaseId")
    if base_id is None:
        return None
    text = str(base_id).strip()
    return text or None


def _scanner_results_of(results: Mapping[str, Any]) -> Mapping[str, Any]:
    """The ``scanner_results`` object, or an empty one when it is not an object."""
    scanner_results = results.get("scanner_results")
    return scanner_results if isinstance(scanner_results, Mapping) else {}


def collect_runs(results: Mapping[str, Any]) -> Tuple[RunEvidence, ...]:
    """One RunEvidence per SARIF run, in file order."""
    sarif = results.get("sarif")
    if not isinstance(sarif, Mapping):
        return ()

    evidence: List[RunEvidence] = []
    for index, run in enumerate(sarif.get("runs") or []):
        if not isinstance(run, Mapping):
            continue

        properties = run.get("properties")
        attributed = None
        if isinstance(properties, Mapping) and properties.get("workspace_project"):
            attributed = str(properties["workspace_project"])

        uri_bases: Dict[str, str] = {}
        bases = run.get("originalUriBaseIds")
        if isinstance(bases, Mapping):
            for base_id, value in bases.items():
                if isinstance(value, Mapping) and value.get("uri"):
                    uri_bases[str(base_id)] = str(value["uri"])
        # The project's own root is the PROJECTROOT entry, by key. The rebase
        # keeps a scanner's declared bases (%SRCROOT%, say) in the table ahead
        # of it, so the first entry is not always the project's; the first entry
        # is the fallback for a run that declares no PROJECTROOT.
        uri_base = uri_bases.get("PROJECTROOT") or next(iter(uri_bases.values()), None)

        rules: Dict[str, Tuple[int, int]] = {}
        workspace_uris: List[str] = []
        raw_uris: List[str] = []
        raw_uri_bases: List[str | None] = []
        result_projects: List[str] = []
        located_results: List[Tuple[str, Tuple[str, ...]]] = []
        result_count = 0
        results_without_location = 0

        for result in run.get("results") or []:
            if not isinstance(result, Mapping):
                continue
            result_count += 1
            rule_id = result.get("ruleId")
            if rule_id is not None:
                key = str(rule_id)
                live, suppressed = rules.get(key, (0, 0))
                if result.get("suppressions"):
                    rules[key] = (live, suppressed + 1)
                else:
                    rules[key] = (live + 1, suppressed)
            workspace_uri = _result_property(result, "workspace_uri")
            if workspace_uri:
                workspace_uris.append(workspace_uri)
            project = _result_property(result, "workspace_project")
            if project:
                result_projects.append(project)
            result_uris: List[str] = []
            for location in result.get("locations") or []:
                uri = _location_uri(location)
                if uri:
                    raw_uris.append(uri)
                    raw_uri_bases.append(_location_base_id(location))
                    result_uris.append(uri)
            if not result_uris:
                results_without_location += 1
            if workspace_uri:
                located_results.append((workspace_uri, tuple(result_uris)))

        evidence.append(
            RunEvidence(
                index=index,
                attributed_project=attributed,
                uri_base=uri_base,
                rules=rules,
                workspace_uris=tuple(workspace_uris),
                raw_uris=tuple(raw_uris),
                uri_bases=uri_bases,
                raw_uri_bases=tuple(raw_uri_bases),
                result_projects=tuple(result_projects),
                located_results=tuple(located_results),
                result_count=result_count,
                results_without_location=results_without_location,
            )
        )
    return tuple(evidence)


def collect_scanner_statuses(results: Mapping[str, Any]) -> Dict[str, str]:
    """The workspace-level per-scanner rollup, normalized.

    A scanner the configuration excluded reads ``EXCLUDED`` whatever status it
    carries beside the flag: the sibling gate treats excluded as not run, and
    this one read the status alone, so an excluded checkov reporting PASSED
    passed the did-it-run check.
    """
    return _statuses_of(_scanner_results_of(results))


def _statuses_of(scanner_results: Mapping[str, Any]) -> Dict[str, str]:
    """One normalized status per entry of a ``scanner_results`` object."""
    statuses: Dict[str, str] = {}
    for name, entry in scanner_results.items():
        record: Mapping[str, Any] = entry if isinstance(entry, Mapping) else {}
        if record.get("excluded"):
            statuses[str(name)] = STATUS_EXCLUDED
        else:
            statuses[str(name)] = normalize_status(record.get("status"))
    return statuses


def check_every_project_ran(projects: Sequence[ProjectOutcome]) -> List[str]:
    """Each fixture project must appear, complete, and have actually found things.

    The findings requirement is the point, not decoration. Status ``completed``
    with zero findings satisfies every attribution assertion below by giving them
    nothing to inspect: there is no finding to credit to the wrong project, no
    suppression to leak, no path to mis-prefix. So a workspace where three of four
    projects were silently not scanned used to pass. Every fixture project
    contains known-insecure Python, so zero findings means the scan is broken, not
    that the project is clean.

    The key and relative_path are checked against the fixture too. Resolution
    derives the key from the path, and getting that derivation wrong for a nested
    project is a real failure -- ``apps/admin`` must become ``apps-admin`` and not
    two directory levels that could collide with a project named ``apps``.
    """
    by_key = {project.key: project for project in projects}
    violations: List[str] = []
    for fixture in FIXTURE_PROJECTS:
        outcome = by_key.get(fixture.key)
        if outcome is None:
            violations.append(
                f"project '{fixture.key}' is missing from workspace.projects; "
                f"present: {sorted(by_key)}"
            )
            continue
        if outcome.status != "completed":
            violations.append(
                f"project '{fixture.key}' has status '{outcome.status}' rather "
                f"than 'completed'" + (f": {outcome.error}" if outcome.error else "")
            )
            continue
        if outcome.finding_count <= 0:
            violations.append(
                f"project '{fixture.key}' completed with {outcome.finding_count} "
                f"finding(s). Its source contains known-insecure Python, so zero "
                f"means it was not really scanned -- and a project that found "
                f"nothing satisfies every attribution check below by giving them "
                f"nothing to look at"
            )
        if outcome.relative_path != fixture.relative_path:
            violations.append(
                f"project '{fixture.key}' reports relative_path "
                f"'{outcome.relative_path}' but the workspace declares it at "
                f"'{fixture.relative_path}'"
            )
    return violations


def check_no_scanner_errors(statuses: Mapping[str, str]) -> List[str]:
    """No scanner may report ERROR in the workspace rollup.

    ERROR means a scanner was invoked and broke. MISSING means the tool is not
    installed on this runner; for a scanner outside GATE_SCANNERS that is
    tolerated, and for one of the two the gate selects it is reported by
    check_gate_scanners_ran, which names the scanner, while the workspace's own
    exit code moves to 1 as well.
    """
    return [
        f"scanner '{name}' reported status ERROR in the workspace rollup"
        for name, status in sorted(statuses.items())
        if status == STATUS_ERROR
    ]


def check_gate_scanners_found_something(results: Mapping[str, Any]) -> List[str]:
    """Each selected scanner must have reported findings in the rollup.

    The fixture gives both scanners a file of their own to trip (``.py`` for
    bandit, ``.tf`` for checkov), so a selected scanner that ran and found
    nothing did not read its file. Nothing used to assert this, so the gate
    went green as a bandit-only check whenever checkov found nothing.
    """
    scanner_results = _scanner_results_of(results)
    violations: List[str] = []
    for scanner in GATE_SCANNERS:
        entry = scanner_results.get(scanner)
        if not isinstance(entry, Mapping):
            # check_gate_scanners_ran reports the absent scanner.
            continue
        status = normalize_status(entry.get("status"))
        if status in (STATUS_MISSING, STATUS_SKIPPED, STATUS_ERROR):
            # Reported by check_gate_scanners_ran or check_no_scanner_errors.
            continue
        if _as_int(entry.get("finding_count")) <= 0:
            violations.append(
                f"scanner '{scanner}' ran with status {status} and reported zero "
                f"findings in the rollup. The fixture gives it its own file to "
                f"trip in every project, so zero means it did not read them, and "
                f"the gate would be asserting on one scanner family while "
                f"claiming two"
            )
    return violations


def check_gate_scanners_ran(statuses: Mapping[str, str]) -> List[str]:
    """Both scanners this gate selects must have run in the workspace rollup.

    The gate's own text names checkov as the second producer the rollup check
    needs, yet nothing refused a run in which checkov was MISSING (tool not
    installed) or SKIPPED (nothing to scan, the fixture's Terraform file lost).
    Every assertion that reads checkov then passed by reading nothing from it, and
    the gate printed PASS having exercised one scanner while claiming two. Absent
    from the rollup altogether is the same state with less evidence, and so are
    an entry the configuration excluded and an entry with no status at all
    (``normalize_status`` reads a missing status as ``""``); both passed here
    while the sibling gate refused them.
    """
    violations: List[str] = []
    for scanner in GATE_SCANNERS:
        status = statuses.get(scanner)
        if status is None:
            violations.append(
                f"scanner '{scanner}' is one of the two this gate selects "
                f"(--scanners) but is absent from scanner_results; present: "
                f"{sorted(statuses) or 'none'}"
            )
        elif status in (STATUS_MISSING, STATUS_SKIPPED, STATUS_EXCLUDED) or not status:
            violations.append(
                f"scanner '{scanner}' is one of the two this gate selects but "
                f"reports {status or 'no status'}, so every check that reads its "
                f"findings passed on an empty set. The gate asserts two scanner "
                f"families and this run supplied one"
            )
    return violations


def check_one_run_per_project(
    projects: Sequence[ProjectOutcome], runs: Sequence[RunEvidence]
) -> List[str]:
    """Every scanned project contributes exactly one run, with its own root.

    A consumer that ingests SARIF against a single repository root -- GitHub code
    scanning above all -- mis-locates or rejects a result whose path is relative
    to a different root than its run declares. One run per project is what keeps
    each run coherent with exactly one root.
    """
    violations: List[str] = []
    scanned = [p for p in projects if p.status == "completed"]

    attributed = [run.attributed_project for run in runs]
    if len(runs) != len(scanned):
        violations.append(
            f"{len(scanned)} project(s) completed but the aggregated SARIF has "
            f"{len(runs)} run(s). Runs are attributed to: {attributed}"
        )

    # Over the runs that name a project. Two runs without one used to read as
    # "two runs claim the same project: [None, None]", which is a different
    # defect and is reported per run below.
    named = [project for project in attributed if project is not None]
    if len(set(named)) != len(named):
        violations.append(
            f"two SARIF runs claim the same project: {attributed}. Per-project "
            "extraction by run index is then ambiguous"
        )

    for run in runs:
        if run.attributed_project is None:
            violations.append(
                f"SARIF run {run.index} carries no properties.workspace_project, "
                "so nothing can say which project it describes"
            )
        if run.uri_base is None:
            violations.append(
                f"SARIF run {run.index} declares no originalUriBaseIds entry, so "
                "its project-relative result paths have no root to resolve against"
            )

    roots = [run.uri_base for run in runs if run.uri_base]
    if len(set(roots)) != len(roots):
        violations.append(
            f"two SARIF runs declare the same project root: {roots}. Two projects "
            "sharing a root is the shape one merged run would have produced"
        )

    # By the run's own index in the SARIF runs array, not by position in this
    # tuple: collect_runs skips a non-object entry, so positions shift while the
    # recorded indexes do not. A negative index is refused rather than read from
    # the end of the tuple.
    runs_by_index = {run.index: run for run in runs}
    for project in scanned:
        if project.sarif_run_index is None:
            violations.append(
                f"project '{project.key}' completed but records no usable "
                "sarif_run_index (absent, or not an integer), so its run cannot "
                "be selected"
            )
            continue
        if project.sarif_run_index < 0:
            violations.append(
                f"project '{project.key}' records sarif_run_index "
                f"{project.sarif_run_index}, which is not an index into the runs"
            )
            continue
        run = runs_by_index.get(project.sarif_run_index)
        if run is None:
            violations.append(
                f"project '{project.key}' records sarif_run_index "
                f"{project.sarif_run_index} but no SARIF run has that index "
                f"(runs present: {sorted(runs_by_index)})"
            )
            continue
        if run.attributed_project != project.key:
            violations.append(
                f"project '{project.key}' records sarif_run_index "
                f"{project.sarif_run_index}, but that run is attributed to "
                f"'{run.attributed_project}'"
            )
    return violations


def _forward_slashes(text: str) -> str:
    """``text`` with every backslash written as a separator."""
    return text.replace("\\", "/")


def _is_the_findings_own_path(
    workspace_uri: str, project_path: str, artifact_uris: Sequence[str]
) -> bool:
    """Whether ``workspace_uri`` is ``project_path`` plus one of ``artifact_uris``.

    The aggregator keeps artifact uris project-relative inside a run and writes the
    workspace-relative form beside them (``workspace/aggregation.py``), so for a
    plain relative uri the two differ by exactly the project's path. Backslashes
    are read as separators on both sides, the way
    ``check_result_paths_resolve_against_their_run_root`` reads them, because the
    aggregator turns a Windows project's backslashes into separators. A finding
    may offer several locations and the aggregator uses the first one it can
    place, so any one of them can be the source.
    """
    candidates = {f"{project_path}/{_forward_slashes(uri)}" for uri in artifact_uris}
    return _forward_slashes(workspace_uri) in candidates


def check_findings_are_attributed_to_their_own_project(
    runs: Sequence[RunEvidence],
) -> List[str]:
    """Internal consistency of the attribution the payload claims.

    Necessary but not sufficient, and the distinction matters. The aggregator
    writes the run-level ``workspace_project`` and every result's
    ``workspace_project`` from one variable in one loop, so the first assertion
    below compares a value against itself and cannot fail on its own. It is kept
    because a future change that writes the two separately would make it real, and
    because it produces a precise message when it does fire.

    The check that can actually fail today is
    ``check_each_project_shows_only_its_own_marker_rule``. Read that one for the
    attribution guarantee; this one is a consistency assertion about the payload.

    It also compares each ``workspace_uri`` with the artifact path of the result it
    sits on. A prefix test alone cannot fail for the project named ``src``, whose
    fixture files all begin with ``src/`` already, and it never reads the rest of
    the value.
    """
    violations: List[str] = []
    for run in runs:
        if run.attributed_project is None:
            continue
        foreign = sorted(
            {
                project
                for project in run.result_projects
                if project != run.attributed_project
            }
        )
        if foreign:
            violations.append(
                f"SARIF run {run.index} is attributed to "
                f"'{run.attributed_project}' but contains finding(s) credited to "
                f"{foreign}"
            )
        if run.result_projects and not run.workspace_uris:
            violations.append(
                f"SARIF run {run.index} has findings but none carry a "
                "workspace_uri, so no finding has a workspace-relative path"
            )
        # The project's PATH, not its key. A workspace_uri is workspace-relative,
        # and for a nested project the key ('apps-admin') is not a path component
        # of it ('apps/admin/src/marker.py'). Comparing against the key reported
        # every finding in every nested project as misattributed -- a check that
        # fails on correct output is worse than one that cannot fail, because the
        # cheapest way to make it green is to delete it.
        expected_prefix = RELATIVE_PATH_BY_PROJECT.get(
            run.attributed_project, run.attributed_project
        )
        wrong_prefix = sorted(
            {
                uri
                for uri in run.workspace_uris
                if not uri.startswith(f"{expected_prefix}/")
            }
        )
        if wrong_prefix:
            violations.append(
                f"SARIF run {run.index} is attributed to "
                f"'{run.attributed_project}' (at '{expected_prefix}') but has "
                f"workspace_uri value(s) outside that project: {wrong_prefix[:5]}"
            )
        # A value that failed the prefix test is reported above, once. One that
        # passed it must also be the project's path plus the artifact path of its
        # own result: the prefix cannot fail for 'src' and never reads the rest.
        not_own_path = sorted(
            {
                f"{uri} (finding at {', '.join(artifacts) or 'no location'})"
                for uri, artifacts in run.located_results
                if uri.startswith(f"{expected_prefix}/")
                and not _is_the_findings_own_path(uri, expected_prefix, artifacts)
            }
        )
        if not_own_path:
            violations.append(
                f"SARIF run {run.index} is attributed to "
                f"'{run.attributed_project}' (at '{expected_prefix}') but has "
                f"workspace_uri value(s) that are not '{expected_prefix}/' plus "
                f"the finding's own artifact path: {not_own_path[:5]}"
            )
    return violations


def check_each_project_shows_only_its_own_marker_rule(
    runs: Sequence[RunEvidence],
) -> List[str]:
    """Attribution, checked against the fixture's source rather than the payload.

    This is the load-bearing attribution assertion. Each project holds a file at
    the same relative path whose content trips one bandit rule no other project
    trips, so the ground truth lives in source on disk while the claimed project
    lives in the payload. Nothing in the pipeline can move both.

    That closes the shape every other check here is blind to: exchange two runs'
    attributions and the payload stays perfectly self-consistent -- run says A,
    every result in it says A, every path is prefixed A -- while every finding
    belongs to B. With markers, A's run is holding B's rule and says so.
    """
    violations: List[str] = []
    seen_markers: Dict[str, str] = {}

    for run in runs:
        if run.attributed_project is None:
            # check_one_run_per_project reports the missing attribution.
            continue
        project = run.attributed_project
        expected = MARKER_RULE_BY_PROJECT.get(project)
        if expected is None:
            violations.append(
                f"SARIF run {run.index} is attributed to '{project}', which is not "
                f"a fixture project. Known projects: "
                f"{sorted(MARKER_RULE_BY_PROJECT)}"
            )
            continue

        present = set(run.rules)
        if expected not in present:
            violations.append(
                f"project '{project}' should show its own marker rule {expected} "
                f"from '{FIXTURE_MARKER_RELATIVE_PATH}', but run {run.index} "
                f"contains {sorted(present)}. Either the project was not scanned, "
                f"or its findings were filed under another project"
            )
        intruders = sorted((present & ALL_MARKER_RULES) - {expected})
        if intruders:
            owners = {
                rule: owner
                for owner, rule in MARKER_RULE_BY_PROJECT.items()
                if rule in intruders
            }
            violations.append(
                f"project '{project}' (run {run.index}) contains marker rule(s) "
                f"{intruders} belonging to {sorted(owners.values())}. Another "
                f"project's file was scanned and credited to this one -- the "
                f"attribution is wrong even though the payload is self-consistent"
            )
        if expected in seen_markers and seen_markers[expected] != project:
            violations.append(
                f"marker rule {expected} appears in both "
                f"'{seen_markers[expected]}' and '{project}'. Only one project's "
                f"source can trip it, so one of the two is holding the other's "
                f"findings"
            )
        if expected in present:
            seen_markers[expected] = project

    # Against every run, not only the runs that showed their own marker: when
    # two runs' attributions are exchanged each marker IS in a run, the wrong
    # one, and that is reported above. Saying it appears in no run and advising
    # an edit to MARKER_SOURCES was false in exactly that case.
    present_anywhere = set()
    for run in runs:
        present_anywhere.update(run.rules)
    unclaimed = sorted(set(MARKER_RULE_BY_PROJECT.values()) - present_anywhere)
    if unclaimed and runs:
        violations.append(
            f"marker rule(s) {unclaimed} appear in no run at all. The project(s) "
            f"that own them contributed nothing, or bandit stopped reporting the "
            f"rule -- in which case update MARKER_SOURCES rather than deleting "
            f"this check"
        )
    return violations


def check_the_fixture_can_discriminate() -> List[str]:
    """The fixture's own ability to tell the projects apart.

    Every marker assertion is meaningless if two projects share a marker, or if a
    marker is a rule the shared file trips in every project anyway. Both are a
    one-line edit away and nothing else would notice, so they are asserted rather
    than assumed -- the same class of hole as a check comparing a value with
    itself.
    """
    violations: List[str] = []
    markers = [project.marker_rule for project in FIXTURE_PROJECTS]
    if len(set(markers)) != len(markers):
        violations.append(
            f"two fixture projects share a marker rule ({markers}), so a "
            f"misattribution between them cannot be detected"
        )
    collisions = sorted(set(markers) & SHARED_FILE_RULE_IDS)
    if collisions:
        violations.append(
            f"marker rule(s) {collisions} are also tripped by the shared file "
            f"'{FIXTURE_RELATIVE_PATH}', which every project holds. A rule that "
            f"fires everywhere identifies nothing"
        )
    missing_sources = sorted(set(markers) - set(MARKER_SOURCES))
    if missing_sources:
        violations.append(
            f"marker rule(s) {missing_sources} have no entry in MARKER_SOURCES, "
            f"so the project(s) claiming them would be written without a marker"
        )
    keys = [project.key for project in FIXTURE_PROJECTS]
    if len(set(keys)) != len(keys):
        violations.append(f"two fixture projects share a key: {keys}")
    if SUPPRESSING_PROJECT not in keys:
        violations.append(
            f"SUPPRESSING_PROJECT '{SUPPRESSING_PROJECT}' is not a fixture "
            f"project, so the suppression scope check compares nothing"
        )
    return violations


def _uri_base_to_path(uri_base: str) -> Path:
    """Turn a ``file://`` directory URI back into a local path.

    Textual rather than via ``urlsplit`` so a Windows ``file:///C:/x`` reduces to
    ``C:/x`` rather than to a path with a stray leading separator.

    Percent-escapes are decoded: a URI spells a space as ``%20`` and a non-ASCII
    character as its UTF-8 bytes, so a workspace root with either in its path
    resolved to a directory that does not exist and every run failed the
    root-resolution check for a reason that was not about the run.
    """
    text = uri_base
    if text.lower().startswith("file://"):
        text = unquote(text[len("file://") :])
        if len(text) > 2 and text[0] == "/" and text[2] == ":":
            text = text[1:]
    return Path(text)


def check_result_paths_resolve_against_their_run_root(
    runs: Sequence[RunEvidence],
) -> List[str]:
    """Result URIs must resolve to a real file under their run's declared root.

    This is the direct statement of "one run, one root": inside a run the paths
    are relative to that run's ``originalUriBaseIds`` entry, so joining the two
    has to land on a file that exists. Rewriting the paths to workspace-relative
    would break it, and so would a run declaring the wrong root.

    An earlier version of this check tested whether a URI started with the
    project key, and the ``src`` project in this very fixture proved it wrong:
    that project's file is at ``src/insecure.py``, which legitimately begins with
    ``src/``. A string-prefix test cannot tell a wrongly-prefixed path from a file
    that happens to sit in a directory named after its project -- which is
    precisely the collision the ``src`` project exists to surface. Resolving
    against the declared root has no such ambiguity.

    Each location is resolved against the base its own ``uriBaseId`` names. A
    location anchored to a base the run does not declare is dangling and is
    reported; one that names no base resolves against the run's root base (the
    PROJECTROOT entry, else the first declared one, as ``collect_runs`` picks
    it), as every location used to. "Under the root" is checked after a strict
    resolution, so an absolute URI or one that climbs out with ``..`` is refused
    even when the file it reaches exists: joining and testing existence alone
    accepted both.
    """
    violations: List[str] = []
    for run in runs:
        if run.uri_base is None:
            # check_one_run_per_project already reports the missing root.
            continue
        root = _uri_base_to_path(run.uri_base)
        # The root has to be THIS project's directory. Every fixture project holds
        # the same relative paths, so a run that declared another project's root
        # still resolved every URI to an existing file and passed; the root's
        # tail is compared against the attributed project's workspace-relative
        # path, which no other project shares.
        expected_tail = RELATIVE_PATH_BY_PROJECT.get(run.attributed_project or "")
        if expected_tail is not None:
            tail_parts = PurePosixPath(expected_tail).parts
            root_parts = root.parts
            if root_parts[-len(tail_parts) :] != tail_parts:
                violations.append(
                    f"SARIF run {run.index} is attributed to project "
                    f"'{run.attributed_project}' at '{expected_tail}' but declares "
                    f"its root as '{root}', which is not that project's directory. "
                    f"Every project holds the same relative paths, so the URIs "
                    f"would still resolve; the root itself is wrong"
                )
        unresolvable: List[str] = []
        dangling: List[str] = []
        base_ids = run.raw_uri_bases or (None,) * len(run.raw_uris)
        for uri, base_id in zip(run.raw_uris, base_ids):
            normalized = uri.replace("\\", "/")
            while normalized.startswith("./"):
                normalized = normalized[2:]
            if not normalized:
                continue
            location_root = root
            if base_id is not None:
                declared = run.uri_bases.get(base_id)
                if declared is None:
                    dangling.append(f"{uri} (uriBaseId {base_id!r})")
                    continue
                location_root = _uri_base_to_path(declared)
            if not _is_a_file_under(location_root, normalized):
                unresolvable.append(uri)
        if dangling:
            violations.append(
                f"SARIF run {run.index} (project '{run.attributed_project}') has "
                f"artifact URI(s) anchored to a uriBaseId the run does not declare "
                f"in originalUriBaseIds ({sorted(run.uri_bases) or 'none'}): "
                f"{sorted(set(dangling))[:5]}. A consumer has no root to resolve "
                "them against"
            )
        if unresolvable:
            violations.append(
                f"SARIF run {run.index} (project "
                f"'{run.attributed_project}') has artifact URI(s) that do not "
                f"resolve to a file under its own declared root '{root}': "
                f"{sorted(set(unresolvable))[:5]}. Inside a run the paths must be "
                "relative to that run's originalUriBaseIds entry, and must stay "
                "under it"
            )
    return violations


def _is_a_file_under(root: Path, relative: str) -> bool:
    """Whether ``relative`` names an existing path under ``root``, after resolution.

    ``(root / relative).exists()`` alone accepted an absolute ``relative`` (the
    join discards ``root``) and a ``..`` that climbs out of the root, whenever
    the file they reached existed somewhere.
    """
    try:
        resolved_root = root.resolve(strict=True)
        candidate = (root / relative).resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return False
    return candidate.is_relative_to(resolved_root)


def _rule_counts(
    runs: Sequence[RunEvidence], project: str
) -> Dict[str, Tuple[int, int]]:
    for run in runs:
        if run.attributed_project == project:
            return dict(run.rules)
    return {}


def check_suppression_is_project_scoped(runs: Sequence[RunEvidence]) -> List[str]:
    """One project's suppression must not silence the same rule in any other.

    Every project carries a byte-identical file at the same relative path, so the
    only difference between the suppressing project and each of the others is the
    suppression itself. If it leaks, the other project's copy of the rule goes
    quiet -- a false negative that leaves no trace anywhere in the output.

    Checked against *every* other project, not one hand-picked partner. An earlier
    version named a single pair and therefore never inspected two of the four
    projects, so a leak that reached only those two would have passed. The nested
    project is exactly the one most likely to be reached by a path-matching bug,
    and it was one of the two going unexamined.

    In the suppressing project itself the proof is positive: the rule has to be
    there with a suppression on it, and no other rule may carry one. "No
    unsuppressed occurrence" alone was accepted as proof, but it is also what a
    shared file that was never scanned in that project looks like, and what a
    finding dropped rather than marked suppressed looks like. The project
    configures one rule at one path (CONFIG_WITH_SUPPRESSION_TEMPLATE), so a
    suppression on any other rule has reached beyond what was configured.
    """
    violations: List[str] = []
    suppressing_rules = _rule_counts(runs, SUPPRESSING_PROJECT)
    others = [
        project.key
        for project in FIXTURE_PROJECTS
        if project.key != SUPPRESSING_PROJECT
    ]
    other_rules = {key: _rule_counts(runs, key) for key in others}

    if not suppressing_rules and not any(other_rules.values()):
        return [
            (
                f"neither '{SUPPRESSING_PROJECT}' nor any of {others} produced any "
                "rule, so the suppression assertion could not be evaluated. bandit "
                "probably did not run"
            )
        ]

    attributed_runs = {run.attributed_project for run in runs}
    for key in others:
        rules = other_rules[key]
        live, suppressed = rules.get(SUPPRESSED_RULE_ID, (0, 0))
        if key not in attributed_runs:
            # No run at all is not "the rule no longer fires", and advising an
            # edit to SUPPRESSED_RULE_ID for it sent the reader the wrong way.
            violations.append(
                f"no SARIF run is attributed to '{key}', so the suppression scope "
                f"cannot be judged for it. check_one_run_per_project reports the "
                f"missing run"
            )
            continue
        if live == 0 and suppressed == 0:
            violations.append(
                f"rule {SUPPRESSED_RULE_ID} does not appear in '{key}' at all, "
                f"neither live nor suppressed. Either bandit no longer reports it "
                f"(then update SUPPRESSED_RULE_ID to a rule the fixture still "
                f"trips), or the finding was removed rather than marked suppressed, "
                f"which is what a leaked suppression that drops findings looks "
                f"like. Rules seen in '{key}': {sorted(rules)}"
            )
            continue
        if suppressed:
            violations.append(
                f"rule {SUPPRESSED_RULE_ID} is suppressed in '{key}', which "
                f"configures no suppression. '{SUPPRESSING_PROJECT}' suppression "
                f"has leaked across the project boundary -- a silent false "
                f"negative"
            )
        if live == 0:
            violations.append(
                f"rule {SUPPRESSED_RULE_ID} has no unsuppressed occurrence in "
                f"'{key}' even though it fires there. Its finding has been "
                f"silenced by another project's configuration"
            )

    live_in_suppressing, suppressed_in_suppressing = suppressing_rules.get(
        SUPPRESSED_RULE_ID, (0, 0)
    )
    if live_in_suppressing:
        violations.append(
            f"rule {SUPPRESSED_RULE_ID} has {live_in_suppressing} unsuppressed "
            f"occurrence(s) in '{SUPPRESSING_PROJECT}', which does configure a "
            f"suppression for it at '{FIXTURE_RELATIVE_PATH}'. The project's own "
            f"suppression did not apply"
        )
    elif not suppressed_in_suppressing:
        # Neither unsuppressed nor suppressed: the rule is not in this project's
        # run at all, which is not a suppression that applied.
        violations.append(
            f"rule {SUPPRESSED_RULE_ID} does not appear in '{SUPPRESSING_PROJECT}' "
            f"at all, neither unsuppressed nor suppressed, so nothing shows that its "
            f"suppression applied. A missing finding is also what a shared file "
            f"that was never scanned looks like, or a finding dropped rather than "
            f"marked suppressed. Rules seen in '{SUPPRESSING_PROJECT}': "
            f"{sorted(suppressing_rules)}"
        )

    for rule, (_, suppressed_count) in sorted(suppressing_rules.items()):
        if rule != SUPPRESSED_RULE_ID and suppressed_count:
            violations.append(
                f"rule {rule} is suppressed in '{SUPPRESSING_PROJECT}', whose "
                f"configuration suppresses only {SUPPRESSED_RULE_ID} at "
                f"'{FIXTURE_RELATIVE_PATH}'. The suppression reached beyond its own "
                f"rule and path -- a silent false negative inside the project that "
                f"configures it"
            )
    return violations


def check_thresholds_are_per_project(
    projects: Sequence[ProjectOutcome],
) -> List[str]:
    """Each project's verdict comes from its own threshold.

    Asserted relatively rather than against absolute counts: bandit's per-rule
    severities move between releases, and pinning them turns an upstream release
    into a red branch. What cannot move is that CRITICAL gates fewer findings
    than LOW over an identical file.
    """
    by_key = {project.key: project for project in projects}
    strict_key, lax_key = THRESHOLD_PAIR
    strict = by_key.get(strict_key)
    lax = by_key.get(lax_key)
    violations: List[str] = []

    # Every project first, not only the pair. Each fixture project writes its own
    # severity_threshold into its config, and the payload reports the threshold
    # the project was judged by; the two must agree for every project. Comparing
    # the pair alone let a threshold leak into project-a or apps-admin, or a
    # per-project config that never reached its scan, pass unseen.
    for fixture in FIXTURE_PROJECTS:
        outcome = by_key.get(fixture.key)
        if outcome is None:
            continue  # check_every_project_ran reports the missing project
        if outcome.threshold != fixture.threshold:
            violations.append(
                f"project '{fixture.key}' reports severity_threshold "
                f"'{outcome.threshold}' but its own config sets "
                f"'{fixture.threshold}'. Either its config never reached its scan "
                f"or another project's threshold was applied to it"
            )

    if strict is None or lax is None:
        return violations + [
            (
                f"cannot compare thresholds: '{strict_key}' or '{lax_key}' is missing "
                f"from workspace.projects (present: {sorted(by_key)})"
            )
        ]

    if strict.threshold == lax.threshold:
        violations.append(
            f"'{strict_key}' and '{lax_key}' both report threshold "
            f"'{strict.threshold}'. Each project's own config is not reaching its "
            f"scan, so the per-project verdict is untested"
        )

    if strict.finding_count == 0:
        violations.append(
            f"'{strict_key}' reported zero findings. The fixture contains known "
            f"insecure Python, so zero means scanning is broken, not that the "
            f"project is clean"
        )

    if strict.actionable_finding_count == 0:
        violations.append(
            f"'{strict_key}' has threshold '{strict.threshold}' and "
            f"{strict.finding_count} finding(s) but zero actionable. At the "
            f"stricter of the two thresholds at least one finding must qualify"
        )

    # Strictly fewer, not "no more than". Tolerating equality was the hole: if the
    # threshold were never applied at all, both projects would report the same
    # actionable count and the check would pass having proved nothing about
    # per-project thresholds.
    #
    # What makes the strict inequality hold, measured rather than assumed. On this
    # fixture 'src' at CRITICAL reports 7 actionable of 12, and 'project-b' at LOW
    # reports 12 of 12. The margin is exactly bandit's five severity-carrying
    # findings (HIGH x2, MEDIUM x1, LOW x2), which a CRITICAL threshold gates out.
    # Checkov's seven are NOT gated out, and that is worth knowing rather than
    # glossing: they carry no properties.issue_severity, so count_actionable_results
    # falls through to the SARIF level arm, where severity_ladder maps `error` to
    # CRITICAL -- and CRITICAL is actionable at every threshold including CRITICAL.
    # A scanner that omits issue_severity therefore cannot be thresholded down at
    # all. That is pre-existing behaviour shared with _compute_exit_code, not
    # something workspace mode introduces, but it is why "CRITICAL gates nothing"
    # is false here and why this comment does not claim it.
    #
    # So the inequality breaks only if bandit stops emitting issue_severity or
    # stops firing on the fixture, and both of those already fail their own checks
    # above with a clearer message.
    if lax.actionable_finding_count >= strict.actionable_finding_count:
        violations.append(
            f"'{lax_key}' (threshold {lax.threshold}) has "
            f"{lax.actionable_finding_count} actionable finding(s) and "
            f"'{strict_key}' (threshold {strict.threshold}) has "
            f"{strict.actionable_finding_count}, over the same shared file. The "
            f"looser threshold must gate strictly fewer; equal counts mean the "
            f"per-project threshold was not applied at all"
        )
    return violations


def check_verdicts_match_their_counts(
    projects: Sequence[ProjectOutcome],
) -> List[str]:
    """Every project's verdict must agree with its own actionable count.

    Applied to all projects rather than only the threshold pair, because the
    invariant is per project and the two fields are written from the same place:
    if they can disagree anywhere, a consumer reading one gets a different answer
    than one reading the other. ``fail_on_findings: false`` would break this
    legitimately, and the fixture does not set it.
    """
    return [
        f"'{project.key}' reports exceeds_threshold={project.exceeds_threshold} "
        f"with {project.actionable_finding_count} actionable finding(s); the two "
        f"disagree"
        for project in projects
        if project.status == "completed"
        and project.exceeds_threshold != (project.actionable_finding_count > 0)
    ]


def check_per_project_subtrees(
    projects: Sequence[ProjectOutcome], output_dir: Path
) -> List[str]:
    """Each project owns its own output subtree, and no two share one.

    Two projects sharing a scanner output directory means the second run silently
    overwrites the first's raw output, and the aggregated counts still add up.
    """
    violations: List[str] = []
    seen: Dict[str, str] = {}

    for project in projects:
        if project.status != "completed":
            continue
        if not project.output_path:
            violations.append(f"project '{project.key}' records no output_path")
            continue
        # Compared as a normalized path, not as the recorded string: two
        # spellings of one directory ('a/b' and 'a//b', 'a/./b', a trailing
        # separator) are one shared directory, and the string test read them as
        # two.
        same_dir = os.path.normpath(_forward_slashes(project.output_path))
        if same_dir in seen:
            violations.append(
                f"projects '{seen[same_dir]}' and '{project.key}' "
                f"share the output path '{project.output_path}'"
            )
        seen[same_dir] = project.key

        subtree = output_dir / project.output_path
        if not _is_under(output_dir, subtree):
            violations.append(
                f"project '{project.key}' names output_path "
                f"'{project.output_path}', which does not stay inside the output "
                f"directory '{output_dir}'. A subtree outside it is not the "
                f"workspace's own output"
            )
            continue
        if not subtree.is_dir():
            violations.append(
                f"project '{project.key}' names output_path "
                f"'{project.output_path}' but '{subtree}' is not a directory"
            )
            continue
        if not (subtree / RESULTS_FILENAME).is_file():
            violations.append(
                f"project '{project.key}' has no {RESULTS_FILENAME} of its own at "
                f"'{subtree}', so its subtree is not a usable single-project "
                f"output tree"
            )
        scanners_dir = subtree / "scanners"
        if not scanners_dir.is_dir():
            violations.append(
                f"project '{project.key}' has no 'scanners' directory at "
                f"'{scanners_dir}', so its raw scanner output went somewhere else"
            )
    return violations


def _is_under(parent: Path, path: Path) -> bool:
    """Whether ``path`` stays inside ``parent`` once both are made absolute."""
    try:
        return (
            Path(os.path.abspath(path))
            .resolve()
            .is_relative_to(Path(os.path.abspath(parent)).resolve())
        )
    except (OSError, RuntimeError, ValueError):
        return False


def _own_scanner_results(
    projects: Sequence[ProjectOutcome], output_dir: Path
) -> Iterable[Tuple[ProjectOutcome, Mapping[str, Any]]]:
    """Each completed project's own ``scanner_results``, read from its subtree.

    A project whose own results file is missing, unreadable or not an object is
    left out; check_per_project_subtrees reports the missing file.
    """
    for project in projects:
        if project.status != "completed" or not project.output_path:
            continue
        own = output_dir / project.output_path / RESULTS_FILENAME
        try:
            own_results = json.loads(own.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(own_results, Mapping):
            continue
        yield project, _scanner_results_of(own_results)


def check_gate_scanners_ran_in_every_project(
    projects: Sequence[ProjectOutcome], output_dir: Path
) -> List[str]:
    """Both selected scanners must have run, and found something, in every project.

    check_gate_scanners_ran and check_gate_scanners_found_something read the
    workspace rollup, and the rollup cannot show one project: its status is the
    worst across the projects (FAILED outranks MISSING and SKIPPED in the
    aggregator's order) and its finding_count is their sum. So checkov SKIPPED
    in one project, its Terraform file lost, hid behind three projects' FAILED
    status and non-zero counts, and the gate passed while its own violation text
    claimed the scanner tripped its own file in every project. Each project's own
    results file carries its own ``scanner_results``, so the claim is checked
    there. ERROR is left to check_no_scanner_errors: it outranks every other
    status, so the rollup shows it. Names are compared stripped and lowered,
    the fold the aggregator joins the projects' rows by, since one results file
    can spell a scanner ``Bandit`` where another spells it ``bandit``.
    """
    violations: List[str] = []
    for project, raw_own in _own_scanner_results(projects, output_dir):
        own = {str(name).strip().lower(): entry for name, entry in raw_own.items()}
        statuses = _statuses_of(own)
        for scanner in GATE_SCANNERS:
            status = statuses.get(scanner)
            if status is None:
                violations.append(
                    f"project '{project.key}' records no scanner_results entry for "
                    f"'{scanner}' in its own results file, so the scanner did not "
                    f"run there; present: {sorted(statuses) or 'none'}"
                )
            elif (
                status in (STATUS_MISSING, STATUS_SKIPPED, STATUS_EXCLUDED)
                or not status
            ):
                violations.append(
                    f"project '{project.key}' reports scanner '{scanner}' as "
                    f"{status or 'no status'} in its own results file. The "
                    f"workspace rollup shows the worst status across the projects "
                    f"and the sum of their counts, so a project in which a selected "
                    f"scanner did not run hides behind the others there"
                )
            elif status == STATUS_ERROR:
                continue
            else:
                entry = own.get(scanner)
                count = (
                    _as_int(entry.get("finding_count"))
                    if isinstance(entry, Mapping)
                    else 0
                )
                if count <= 0:
                    violations.append(
                        f"project '{project.key}' reports scanner '{scanner}' with "
                        f"status {status} and {count} finding(s) in its own results "
                        f"file. The fixture gives the scanner its own file to trip in "
                        f"every project, so zero means it did not read this one's, "
                        f"whatever the rollup's sum says"
                    )
    return violations


def check_scanner_rollup_per_scanner(
    projects: Sequence[ProjectOutcome], output_dir: Path
) -> List[str]:
    """Each scanner's rollup count must equal the sum of that scanner over the projects.

    The cross-scanner totals compared by the rollup check cannot show one
    scanner's count leaking into another's, which is the property checkov was
    added to test. Each project writes its own results file in its subtree with
    its own per-scanner ``scanner_results``, so the per-scanner sum is on disk;
    the workspace rollup is read from the same file. A project whose own file
    is missing or unreadable is left out here and reported by
    check_per_project_subtrees.
    """
    aggregated = output_dir / RESULTS_FILENAME
    try:
        rollup = _scanner_results_of(json.loads(aggregated.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return []
    per_scanner: Dict[str, int] = {}
    for _project, own in _own_scanner_results(projects, output_dir):
        for name, entry in own.items():
            if isinstance(entry, Mapping):
                per_scanner[str(name)] = per_scanner.get(str(name), 0) + _as_int(
                    entry.get("finding_count")
                )
    violations: List[str] = []
    for scanner in GATE_SCANNERS:
        entry = rollup.get(scanner)
        if not isinstance(entry, Mapping) or scanner not in per_scanner:
            continue
        rolled = _as_int(entry.get("finding_count"))
        if rolled != per_scanner[scanner]:
            violations.append(
                f"scanner_results['{scanner}'].finding_count is {rolled} in the "
                f"workspace rollup but the projects' own results sum to "
                f"{per_scanner[scanner]} for it. One scanner's count has leaked "
                f"into another's, which the cross-scanner totals cannot show"
            )
    return violations


def check_scanner_rollup_agrees_with_the_projects(
    results: Mapping[str, Any], projects: Sequence[ProjectOutcome]
) -> List[str]:
    """The workspace-level rollup must not contradict the per-project truth.

    ``scanner_results[*].actionable_finding_count`` was previously zero by
    construction -- initialised, defaulted, read, never incremented. It is not
    inert: ``core/resource_management/result_filters.py`` reads it and republishes
    it as ``actionable_findings``, so a consumer reading the rollup rather than
    ``workspace.projects`` concluded a workspace with real findings had none.
    Fail-open, with the correct value two keys away in the same file.
    """
    scanner_results = _scanner_results_of(results)
    if not scanner_results:
        return ["'scanner_results' is empty -- the rollup recorded no scanners"]

    rollup_actionable = sum(
        _as_int(entry.get("actionable_finding_count"))
        for entry in scanner_results.values()
        if isinstance(entry, Mapping)
    )
    rollup_findings = sum(
        _as_int(entry.get("finding_count"))
        for entry in scanner_results.values()
        if isinstance(entry, Mapping)
    )
    project_actionable = sum(project.actionable_finding_count for project in projects)
    project_findings = sum(project.finding_count for project in projects)

    violations: List[str] = []
    if project_actionable and not rollup_actionable:
        violations.append(
            f"the projects report {project_actionable} actionable finding(s) but "
            f"the scanner_results rollup reports 0. A consumer reading the rollup "
            f"-- result_filters.py does -- would conclude this workspace is clean"
        )
    elif rollup_actionable != project_actionable:
        violations.append(
            f"scanner_results actionable total is {rollup_actionable} but the "
            f"projects sum to {project_actionable}; the two views of the same run "
            f"disagree"
        )
    if rollup_findings != project_findings:
        violations.append(
            f"scanner_results finding total is {rollup_findings} but the projects "
            f"sum to {project_findings}; the two views of the same run disagree"
        )
    return violations


def check_no_finding_lost_its_workspace_path(
    results: Mapping[str, Any], runs: Sequence[RunEvidence]
) -> List[str]:
    """Every finding must carry a workspace-relative path, and be counted if not.

    An absolute scanner URI used to be prefixed rather than relativized --
    ``/ws/api/src/app.py`` became ``api/ws/api/src/app.py``, naming nothing, and
    *without* incrementing the counter, so two of three broken shapes were
    invisible in the payload.

    This check is a backstop rather than the primary coverage. Measured on this
    fixture, both scanners hand the aggregator already-relative paths, so the
    absolute branch is not reached here; the per-shape coverage lives in
    ``tests/unit/workspace/test_aggregation.py::TestAbsoluteScannerUris``. What
    this does catch is the general case of a finding losing its path silently --
    counted or not -- whatever shape caused it.
    """
    workspace = results.get("workspace") or {}
    counted = _as_int(workspace.get("unconvertible_finding_paths"))
    located = sum(len(run.workspace_uris) for run in runs)
    # Every result, not only those carrying a project attribution. The two
    # properties are written together, so a result that lost both was absent
    # from both sides of this accounting and passed silently. A result that
    # offered no location at all is left out of the denominator: the aggregator
    # correctly gives it no workspace path and counts it nowhere, so it is not
    # a path lost silently and used to be reported as one.
    unlocated = sum(run.results_without_location for run in runs)
    total = sum(run.result_count for run in runs) - unlocated
    attributed = sum(len(run.result_projects) for run in runs)

    violations: List[str] = []
    if counted:
        violations.append(
            f"{counted} finding(s) could not be given a workspace-relative path. "
            f"Every fixture file lives inside its project, so all of them should "
            f"convert -- this points at the absolute-URI handling in "
            f"workspace/aggregation.py"
        )
    if total and located != total:
        violations.append(
            f"{total} located finding(s) are in the SARIF but only {located} carry "
            f"a workspace_uri ({attributed} carry a project attribution, "
            f"{unlocated} offered no location and are left out), and "
            f"{counted} were counted as unconvertible. The difference is findings "
            f"that lost their path silently"
        )
    return violations


def check_workspace_status(results: Mapping[str, Any], exit_code: int) -> List[str]:
    """The payload's own status must agree with having scanned something.

    This is the discriminator for the ambiguous exit code 2. See
    automated_security_helper/models/workspace.py.
    """
    workspace = results.get("workspace") or {}
    status = str(workspace.get("status") or "")
    violations: List[str] = []
    if status != "completed":
        violations.append(
            f"workspace.status is '{status}' rather than 'completed', but a "
            f"results file exists and projects ran. Exit code {exit_code} is then "
            f"indistinguishable from a refused workspace"
        )
    recorded = _as_optional_int(workspace.get("exit_code"))
    if recorded is None:
        # Read as 0 before, which agreed with a process that exited 0 and made
        # the cross-check pass on a payload that recorded no exit code at all.
        violations.append(
            f"workspace.exit_code is absent or not an integer "
            f"({workspace.get('exit_code')!r}) while the process exited "
            f"{exit_code}; the payload does not say what it exited with"
        )
    elif recorded != exit_code:
        violations.append(
            f"workspace.exit_code is {recorded} but the process exited "
            f"{exit_code}; a consumer reading the payload would draw a different "
            f"conclusion than one reading the status"
        )
    return violations


def check_execution_knobs_reached_the_run(results: Mapping[str, Any]) -> List[str]:
    """The root config's execution knobs must be the values the run reports.

    WORKSPACE_ROOT_CONFIG sets ``max_parallel_projects`` and ``project_timeout``
    at the workspace root so the gate exercises that they are read from there,
    and the payload records the values the run used. The config was written and
    never asserted, so the exercise could not fail.
    """
    workspace = results.get("workspace") or {}
    violations: List[str] = []
    bound = _as_optional_int(workspace.get("max_parallel_projects"))
    if bound != ROOT_MAX_PARALLEL_PROJECTS:
        violations.append(
            f"workspace.max_parallel_projects is "
            f"{workspace.get('max_parallel_projects')!r} but the root config sets "
            f"{ROOT_MAX_PARALLEL_PROJECTS}; the root's execution knobs did not "
            f"reach the run"
        )
    timeout = workspace.get("project_timeout")
    try:
        timeout_seconds = float(timeout)
    except (TypeError, ValueError):
        timeout_seconds = None
    if timeout_seconds != float(ROOT_PROJECT_TIMEOUT_SECONDS):
        violations.append(
            f"workspace.project_timeout is {timeout!r} but the root config sets "
            f"{ROOT_PROJECT_TIMEOUT_SECONDS}; the root's execution knobs did not "
            f"reach the run"
        )
    return violations


def check_findings_are_from_the_fixture(
    runs: Sequence[RunEvidence], repo_root: Path
) -> List[str]:
    """Every finding must point at the generated fixture, not this checkout.

    The inverse regression: workspace mode ignores its projects and scans the
    process working directory. Every other assertion would still pass.
    """
    root = repo_root.resolve()
    expected_basenames = frozenset(
        PurePosixPath(relative).name
        for relative in (*FIXTURE_FILES, FIXTURE_MARKER_RELATIVE_PATH)
    )
    wrong_basename: List[str] = []
    inside_repository: List[str] = []

    for run in runs:
        for uri in run.raw_uris:
            normalized = uri.replace("\\", "/")
            while normalized.startswith("./"):
                normalized = normalized[2:]
            if not normalized:
                continue
            if PurePosixPath(normalized).name not in expected_basenames:
                wrong_basename.append(uri)
            candidate = Path(root, normalized)
            with suppress(OSError, ValueError):
                candidate = candidate.resolve()
            if candidate.is_relative_to(root) and candidate.exists():
                inside_repository.append(uri)

    violations: List[str] = []
    if wrong_basename:
        violations.append(
            f"finding(s) name a file that is not part of the fixture. Expected a "
            f"basename in {sorted(expected_basenames)}; got "
            f"{sorted(set(wrong_basename))[:5]}"
        )
    if inside_repository:
        violations.append(
            "finding(s) name files inside the repository, which means the scan "
            "read the process working directory instead of the workspace "
            f"projects: {sorted(set(inside_repository))[:5]}"
        )
    return violations


def check_exit_code(
    exit_code: int, projects: Sequence[ProjectOutcome] = ()
) -> List[str]:
    """The process exit code must say what the projects say.

    Both tolerated codes are tolerated only in their own case. The fixture is
    built so that project-a and project-b exceed their thresholds, so the
    expected code is 2; tolerating 0 unconditionally let a workspace whose
    projects reported exceeds_threshold pass with an exit code that says clean,
    which is exactly the regression a consumer of the exit code would be hurt by.
    When no project outcome is given (the pure logic called on its own) the two
    codes are both accepted, as before.
    """
    if exit_code in TOLERATED_EXIT_CODES:
        exceeding = sorted(
            project.key
            for project in projects
            if project.status == "completed" and project.exceeds_threshold
        )
        if exit_code == 0 and exceeding:
            return [
                (
                    f"the workspace scan exited 0 although project(s) {exceeding} "
                    f"report exceeds_threshold=true. The exit code says clean while "
                    f"the payload says actionable findings; a CI consumer reading "
                    f"the code would pass this workspace"
                )
            ]
        if exit_code == 2 and projects and not exceeding:
            return [
                (
                    "the workspace scan exited 2 (actionable findings) but no "
                    "completed project reports exceeds_threshold=true; the exit "
                    "code and the payload disagree"
                )
            ]
        return []
    if exit_code == WORKSPACE_ERROR_EXIT_CODE:
        return [
            (
                f"the workspace scan exited {exit_code} -- a workspace definition or "
                "policy error, meaning no project was scanned. The generated fixture "
                "should always resolve, so this points at the fixture or at "
                "resolution, not at the projects"
            )
        ]
    return [
        (
            f"the workspace scan exited {exit_code}; expected one of "
            f"{list(TOLERATED_EXIT_CODES)} (0 success, 2 actionable findings). "
            "1 is an internal error or a selected scanner that did not run "
            "(fail_on_incomplete_scanners defaults on; check_gate_scanners_ran "
            "names the scanner), 3 is an invalid project config and 5 is a "
            "usage error: ASH refused this script's command line"
        )
    ]


def check_paths_outside_repo(repo_root: Path, *paths: Path) -> List[str]:
    root = repo_root.resolve()
    violations: List[str] = []
    for path in paths:
        resolved = path.resolve()
        if resolved == root or resolved.is_relative_to(root):
            violations.append(
                f"'{resolved}' is inside the repository at '{root}'. The gate "
                "must build its workspace outside the repository, or ASH's own "
                "self-scan finds the fixture"
            )
    return violations


def evaluate_results(
    results: Any,
    output_dir: Path,
    exit_code: int | None = None,
    repo_root: Path | None = None,
) -> GateOutcome:
    """Run every assertion against a parsed results dict.

    Shape violations short-circuit: if the keys are not where they should be, the
    remaining checks pass by inspecting nothing, which is worse than failing.
    """
    outcome = GateOutcome()
    shape_violations = check_results_shape(results)
    if shape_violations:
        outcome.violations.extend(shape_violations)
        return outcome

    projects = parse_projects(results)
    runs = collect_runs(results)
    statuses = collect_scanner_statuses(results)
    outcome.projects = projects
    outcome.runs = runs
    outcome.scanner_statuses = statuses

    # The fixture's own discriminating power first: if two projects share a
    # marker, the attribution checks below cannot fail and say nothing about it.
    outcome.violations.extend(check_the_fixture_can_discriminate())
    outcome.violations.extend(check_every_project_ran(projects))
    scanner_errors = check_no_scanner_errors(statuses)
    outcome.violations.extend(scanner_errors)
    # A dead scanner explains the marker-rule, suppression and threshold
    # violations below, so name it as the root cause rather than letting it sit
    # first in a flat list of ten.
    outcome.root_violations.extend(scanner_errors)
    # A selected scanner that never ran explains the same downstream silence.
    scanner_gaps = check_gate_scanners_ran(statuses)
    outcome.violations.extend(scanner_gaps)
    outcome.root_violations.extend(scanner_gaps)
    outcome.violations.extend(check_gate_scanners_found_something(results))
    outcome.violations.extend(check_execution_knobs_reached_the_run(results))
    outcome.violations.extend(check_one_run_per_project(projects, runs))
    outcome.violations.extend(check_findings_are_attributed_to_their_own_project(runs))
    outcome.violations.extend(check_each_project_shows_only_its_own_marker_rule(runs))
    outcome.violations.extend(check_result_paths_resolve_against_their_run_root(runs))
    outcome.violations.extend(check_suppression_is_project_scoped(runs))
    outcome.violations.extend(check_thresholds_are_per_project(projects))
    outcome.violations.extend(check_verdicts_match_their_counts(projects))
    outcome.violations.extend(
        check_scanner_rollup_agrees_with_the_projects(results, projects)
    )
    outcome.violations.extend(check_no_finding_lost_its_workspace_path(results, runs))
    outcome.violations.extend(check_per_project_subtrees(projects, output_dir))
    outcome.violations.extend(check_scanner_rollup_per_scanner(projects, output_dir))
    # The rollup's worst-status and summed-count view cannot show one project in
    # which a selected scanner did not run; like a rollup-level gap, that explains
    # the downstream silence in the project's run.
    project_gaps = check_gate_scanners_ran_in_every_project(projects, output_dir)
    outcome.violations.extend(project_gaps)
    outcome.root_violations.extend(project_gaps)
    if exit_code is not None:
        outcome.violations.extend(check_workspace_status(results, exit_code))
        outcome.violations.extend(check_exit_code(exit_code, projects))
    if repo_root is not None:
        outcome.violations.extend(check_findings_are_from_the_fixture(runs, repo_root))
    return outcome


def format_project_table(projects: Sequence[ProjectOutcome]) -> str:
    """A plain-ASCII table. Windows consoles cannot encode box-drawing or emoji."""
    headers = (
        "project",
        "status",
        "threshold",
        "findings",
        "actionable",
        "verdict",
        "run",
    )
    rows = [
        (
            project.key,
            project.status or "-",
            project.threshold or "-",
            str(project.finding_count),
            str(project.actionable_finding_count),
            "FAIL" if project.exceeds_threshold else "pass",
            "-" if project.sarif_run_index is None else str(project.sarif_run_index),
        )
        for project in projects
    ]
    widths = [
        max(len(headers[column]), *(len(row[column]) for row in rows))
        if rows
        else len(headers[column])
        for column in range(len(headers))
    ]

    def render(values: Sequence[str]) -> str:
        cells = [values[column].ljust(widths[column]) for column in range(3)]
        cells.extend(
            values[column].rjust(widths[column]) for column in range(3, len(headers))
        )
        return "  ".join(cells).rstrip()

    lines = [render(headers), "  ".join("-" * width for width in widths)]
    lines.extend(render(row) for row in rows)
    return "\n".join(lines)


def format_attribution_evidence(runs: Sequence[RunEvidence]) -> str:
    """Which rules landed in which run, from the same source the checks read."""
    lines: List[str] = []
    for run in runs:
        live = {
            rule: counts[0] for rule, counts in sorted(run.rules.items()) if counts[0]
        }
        muted = {
            rule: counts[1] for rule, counts in sorted(run.rules.items()) if counts[1]
        }
        lines.append(
            f"run {run.index} -> {run.attributed_project}: "
            f"live {live or '{}'}, suppressed {muted or '{}'}"
        )
        lines.append(f"    root: {run.uri_base}")
        lines.append(
            f"    paths: raw {sorted(set(run.raw_uris))[:3]}, "
            f"workspace {sorted(set(run.workspace_uris))[:3]}"
        )
    return "\n".join(lines) or "no SARIF runs"


# ---------------------------------------------------------------------------
# Fixture and subprocess wrappers
# ---------------------------------------------------------------------------


def write_fixture(workspace_root: Path) -> Path:
    """Materialize the workspace and return the definition path."""
    workspace_root.mkdir(parents=True, exist_ok=True)

    for project in FIXTURE_PROJECTS:
        # relative_path, not key: a nested project must land at 'apps/admin', and
        # writing it to a directory named after its key would make the workspace
        # definition point at nothing.
        project_dir = workspace_root / project.relative_path
        for relative, content in FIXTURE_FILES.items():
            source_file = project_dir / relative
            source_file.parent.mkdir(parents=True, exist_ok=True)
            source_file.write_text(content, encoding="utf-8")

        # Same path in every project, different content: the marker.
        marker_file = project_dir / FIXTURE_MARKER_RELATIVE_PATH
        marker_file.parent.mkdir(parents=True, exist_ok=True)
        marker_file.write_text(MARKER_SOURCES[project.marker_rule], encoding="utf-8")

        config_dir = project_dir / ".ash"
        config_dir.mkdir(parents=True, exist_ok=True)
        if project.suppress_rule:
            content = CONFIG_WITH_SUPPRESSION_TEMPLATE.format(
                name=project.key,
                threshold=project.threshold,
                rule_id=project.suppress_rule,
                path=FIXTURE_RELATIVE_PATH,
            )
        else:
            content = CONFIG_TEMPLATE.format(
                name=project.key, threshold=project.threshold
            )
        (config_dir / "ash.yaml").write_text(content, encoding="utf-8")

    root_config = workspace_root / ".ash"
    root_config.mkdir(parents=True, exist_ok=True)
    (root_config / "ash.yaml").write_text(WORKSPACE_ROOT_CONFIG, encoding="utf-8")

    definition = workspace_root / WORKSPACE_FILENAME
    definition.write_text(
        json.dumps(
            {
                "folders": [
                    {"path": project.relative_path} for project in FIXTURE_PROJECTS
                ]
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return definition


def build_scan_command(definition: Path, output_dir: Path) -> List[str]:
    """The scan invocation, as a list -- never a shell string.

    ``--scanners`` restricts the run to the two producers every assertion here
    actually reads. See GATE_SCANNERS for why that is a correctness property of
    the gate and not a speed optimisation.
    """
    command = [
        sys.executable,
        "-m",
        "automated_security_helper.cli.main",
        "scan",
        "--workspace",
        str(definition),
        "--output-dir",
        str(output_dir),
        "--phases",
        "scan",
        "--no-progress",
        "--simple",
    ]
    for scanner in GATE_SCANNERS:
        command += ["--scanners", scanner]
    return command


def child_environment(base: Mapping[str, str] | None = None) -> Dict[str, str]:
    """The environment the scan child runs under: no ``ASH_*`` variable.

    The product reads options from the environment too (``ASH_EXCLUDED_SCANNERS``,
    ``ASH_SCANNERS``, ``ASH_CONFIG``, ``ASH_WORKSPACE_CONFIG``, the shard
    variables), so an operator's shell could change which run this gate judges
    with no trace in its output. The gate's inputs are its command line and the
    fixture it wrote. UTF-8 is forced both ways for the child's Rich table.

    PYTHONSAFEPATH is dropped too: with it set, ``-m`` no longer puts the
    working directory on ``sys.path``, so the child would import whatever ASH is
    installed instead of the working tree this gate says it exercises.
    """
    source = os.environ if base is None else base
    env = {key: value for key, value in source.items() if not key.startswith("ASH_")}
    env.pop("PYTHONSAFEPATH", None)
    env["PYTHONIOENCODING"] = "utf-8"
    env.setdefault("PYTHONUTF8", "1")
    return env


#: Seconds the scan child gets to shut down after SIGTERM before it is killed.
SHUTDOWN_GRACE_SECONDS = 15.0

#: Seconds to keep reading the child's output once it has been stopped.
DRAIN_SECONDS = 15.0

#: The most --timeout may ask for: the job budget less the setup floor and the
#: shutdown a timed-out scan costs (the stop waits the grace period twice, and
#: the drain waits its deadline twice). Above it the scan can still be stopped
#: in time, but the job is cancelled before the tables print.
MAX_SCAN_TIMEOUT_SECONDS = (
    JOB_TIMEOUT_BUDGET_SECONDS
    - SETUP_MARGIN_SECONDS
    - 2 * (SHUTDOWN_GRACE_SECONDS + DRAIN_SECONDS)
)


def _kill_process_group(process: Any) -> None:
    """SIGKILL the child's process group, or the child alone without groups."""
    if hasattr(os, "killpg") and hasattr(signal, "SIGKILL"):
        with suppress(ProcessLookupError, PermissionError):
            os.killpg(process.pid, signal.SIGKILL)
    elif process.poll() is None:
        process.kill()


def _stop_process_group(
    process: Any, grace_seconds: float = SHUTDOWN_GRACE_SECONDS
) -> None:
    """Stop the scan child and the tools it started, SIGTERM first.

    ``subprocess.run(timeout=...)`` kills only the ASH process, with SIGKILL, so
    the scanner tools ASH had started were orphaned and kept writing into the
    kept evidence directory. The child is started as the leader of its own
    process group: SIGTERM goes to the group so ASH runs its own shutdown, which
    is what stops the tools ASH starts in sessions of their own (its spawn plan
    decides that per tool; the group signals never reach those), then a grace
    period, then SIGKILL to the group. Without process groups the child alone is
    terminated, then killed.

    The group gets the SIGKILL sweep even when the child exited in time: a tool
    that traps SIGTERM, or one ASH did not wait for, can outlive the child in
    the group, keep the output pipes open and keep writing into the evidence
    directory. ``ProcessLookupError`` from an empty group is expected and
    suppressed, so the sweep costs nothing when there is nothing left.
    """
    group_signals = hasattr(os, "killpg") and hasattr(signal, "SIGKILL")
    if group_signals:
        with suppress(ProcessLookupError, PermissionError):
            os.killpg(process.pid, signal.SIGTERM)
    elif process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        _kill_process_group(process)
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=grace_seconds)
        return
    _kill_process_group(process)


def _drain_output(
    process: Any, drain_seconds: float = DRAIN_SECONDS
) -> Tuple[str, str]:
    """Read what a stopped child wrote, without waiting for ever.

    A process that outlives the child, outside its group, can hold the output
    pipes open, and a bare ``communicate()`` then blocks until that process
    exits. Read for *drain_seconds*; if the pipes are still open, kill the group
    once more and read for the same time again; if they are still open after
    that, return the output read so far and let the caller close the pipes.
    """
    try:
        return process.communicate(timeout=drain_seconds)
    except subprocess.TimeoutExpired:
        _kill_process_group(process)
    try:
        return process.communicate(timeout=drain_seconds)
    except subprocess.TimeoutExpired as still_open:
        return _as_text(still_open.stdout), _as_text(still_open.stderr)


def run_scan(
    repo_root: Path, definition: Path, output_dir: Path, timeout: float
) -> subprocess.CompletedProcess[str]:
    """Run one workspace scan from a working directory that is not the workspace.

    ``cwd=repo_root`` is load-bearing: it is passed to the child rather than set
    with ``os.chdir``, because this project deliberately removed process-wide cwd
    dependence.

    Raises ``subprocess.TimeoutExpired`` carrying the output read so far when the
    scan outlives *timeout*; the child and its tools are stopped first and its
    output is read for a bounded time.
    """
    command = build_scan_command(definition, output_dir)
    popen_options: Dict[str, Any] = {}
    if hasattr(os, "setsid"):
        popen_options["start_new_session"] = True
    with subprocess.Popen(  # nosec B603 -- list args, no shell, argv[0] is sys.executable
        command,
        cwd=str(repo_root),
        env=child_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        **popen_options,
    ) as process:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as expired:
            _stop_process_group(process)
            stdout, stderr = _drain_output(process)
            raise subprocess.TimeoutExpired(
                command, timeout, output=stdout, stderr=stderr
            ) from expired
        except BaseException:
            # Ctrl-C, a CI cancel or a SIGTERM to the gate turned into
            # SystemExit. The child leads its own session, so the terminal's
            # SIGINT never reached it, and Popen.__exit__ assumes it did: it
            # waits a moment and returns with the child still running. Stop the
            # group before the exception unwinds.
            _stop_process_group(process)
            raise
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


class ResultsUnreadable(Exception):
    """The results file exists but could not be read or decoded.

    Raised for invalid UTF-8 and for a read error, which used to escape ``main``
    as a traceback in place of the gate's FAIL report and its scan log tail.
    """


def load_results(output_dir: Path) -> Any:
    results_path = output_dir / RESULTS_FILENAME
    if not results_path.exists():
        raise FileNotFoundError(str(results_path))
    try:
        text = results_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as bad_bytes:
        raise ResultsUnreadable(
            f"the results file is not valid UTF-8: {bad_bytes}"
        ) from bad_bytes
    except OSError as unreadable:
        raise ResultsUnreadable(
            f"the results file could not be read: {unreadable}"
        ) from unreadable
    return json.loads(text)


def _scan_timeout(text: str) -> float:
    """The ``--timeout`` value: a finite number of seconds, positive and within the job budget.

    ``type=float`` alone accepted 0, a negative number, ``nan`` and ``inf``,
    none of which stops a hung scan before the job's own cancellation, and a
    value at or above JOB_TIMEOUT_BUDGET_SECONDS, which the help text said must
    stay under the budget but nothing enforced. Checking against the bare budget
    was not enough either: the setup steps and the shutdown after a timeout
    spend from the same budget, so a value that stayed under it by less than
    their sum was accepted and lost the race it was meant to win. The bound is
    MAX_SCAN_TIMEOUT_SECONDS, which takes both off.
    """
    try:
        seconds = float(text)
    except ValueError as bad:
        raise argparse.ArgumentTypeError(f"not a number of seconds: {text!r}") from bad
    if not math.isfinite(seconds) or seconds <= 0:
        raise argparse.ArgumentTypeError(
            f"the timeout must be a positive, finite number of seconds, not {text!r}"
        )
    if seconds > MAX_SCAN_TIMEOUT_SECONDS:
        raise argparse.ArgumentTypeError(
            f"the timeout may be at most {MAX_SCAN_TIMEOUT_SECONDS:g}s: the job's "
            f"{JOB_TIMEOUT_BUDGET_SECONDS:g}s budget less {SETUP_MARGIN_SECONDS:g}s "
            f"for the steps before the scan and "
            f"{2 * (SHUTDOWN_GRACE_SECONDS + DRAIN_SECONDS):g}s to stop and drain a "
            f"timed-out scan, so this script's diagnostics win the race; not {text!r}"
        )
    return seconds


def _remove_hint(path: Path) -> str:
    """The cleanup command printed for a kept temp directory, shell-quoted."""
    return f"rm -rf {shlex.quote(str(path))}"


def sanitize_for_console(text: str) -> str:
    """Make captured child output safe to print on a cp1252 console."""
    import re

    plain = re.sub(
        r"\x1b(?:\[[0-9;?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])",
        "",
        text or "",
    )
    return plain.encode("ascii", "replace").decode("ascii")


def _tail(text: str, limit: int = LOG_TAIL_LINES) -> str:
    lines = (text or "").splitlines()
    if len(lines) <= limit:
        return "\n".join(lines)
    return "\n".join(
        [f"... {len(lines) - limit} earlier line(s) omitted ..."] + lines[-limit:]
    )


def _as_text(stream: Any) -> str:
    if stream is None:
        return ""
    if isinstance(stream, bytes):
        return stream.decode("utf-8", "replace")
    return str(stream)


def _print_block(title: str, body: Any) -> None:
    text = _as_text(body)
    if not text.strip():
        return
    print(f"--- {title} ---")
    print(sanitize_for_console(text))


#: Cap on a single scanner stderr log printed as evidence. Generous enough that
#: no real traceback is touched, small enough that a pathological log cannot push
#: the scan stdout/stderr blocks after it past a truncated job log. "Not tailed"
#: and "unbounded" are separable, and only the first is wanted.
SCANNER_LOG_PRINT_BUDGET_BYTES = 200_000


def _clamp_keeping_both_ends(text: str, budget: int) -> str:
    """Trim the middle, never the ends.

    A tail cut loses the head; a head cut loses the deepest frame and the
    exception line. When a log has to be trimmed at all, the ends are the part
    worth keeping, so the middle goes and says how much it took.
    """
    if len(text) <= budget:
        return text
    half = budget // 2
    omitted = len(text) - (half * 2)
    return (
        text[:half]
        + f"\n\n... {omitted} byte(s) omitted from the middle of this log ...\n\n"
        + text[-half:]
    )


def find_scanner_error_logs(output_dir: Path, scanner: str) -> List[Path]:
    """Every stderr log a scanner wrote, across projects and target types.

    ASH sends each scanner's stderr to
    ``projects/<project>/scanners/<scanner>/<target>/<Name>Scanner.stderr.log``.
    When a scanner dies at import, that file holds the whole traceback while the
    aggregated results hold only ``status: ERROR``. The gate used to print
    neither, so the one artifact naming the cause went unread and every failure
    of this kind cost a round trip into the uploaded evidence.
    """
    scanner_dir = output_dir / "projects"
    if not scanner_dir.is_dir():
        return []
    return sorted(scanner_dir.glob(f"*/scanners/{scanner}/*/*.stderr.log"))


def print_scanner_error_evidence(output_dir: Path, scanners: Sequence[str]) -> None:
    """Print, in full, the stderr of each scanner that reported ERROR.

    Deliberately not tail-truncated: the useful frames of an import-time
    traceback are the *last* ones, but the deepest frame is what names the
    failing library, and a tail cut mid-frame is what makes these reports
    unactionable. Bounded rather than unbounded, though -- a log over
    ``SCANNER_LOG_PRINT_BUDGET_BYTES`` loses its middle, not either end, so the
    blocks printed after it still reach a truncated job log. Identical logs are
    collapsed, since a workspace scan runs the same tool once per project and
    typically fails the same way in each.
    """
    for scanner in scanners:
        logs = find_scanner_error_logs(output_dir, scanner)
        if not logs:
            print(
                f"--- scanner '{scanner}' reported ERROR but wrote no stderr log "
                f"under {output_dir / 'projects'} ---"
            )
            continue
        by_content: Dict[str, List[Path]] = {}
        for log in logs:
            try:
                body = log.read_text(encoding="utf-8", errors="replace")
            except OSError as err:  # pragma: no cover - unreadable evidence
                body = f"<could not read {log}: {err}>"
            by_content.setdefault(body, []).append(log)
        for body, paths in by_content.items():
            shown = ", ".join(str(p.relative_to(output_dir)) for p in paths)
            suffix = f" (identical in {len(paths)} projects)" if len(paths) > 1 else ""
            _print_block(
                f"scanner '{scanner}' stderr{suffix}: {shown}",
                _clamp_keeping_both_ends(body, SCANNER_LOG_PRINT_BUDGET_BYTES),
            )


def _configure_stdout_for_utf8() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        with suppress(OSError, ValueError):
            reconfigure(encoding="utf-8", errors="replace")


def _remove_tree(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)
    if path.exists():
        print(f"WARNING: could not fully remove temp directory '{path}'")


def _parse_args(argv: Iterable[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Scan a generated multi-project workspace outside this repository and "
            "assert that its projects stay apart."
        )
    )
    parser.add_argument(
        "--timeout",
        type=_scan_timeout,
        default=DEFAULT_SCAN_TIMEOUT_SECONDS,
        help=(
            "seconds to allow the scan subprocess (default: "
            f"{DEFAULT_SCAN_TIMEOUT_SECONDS:g}; a positive finite number of at most "
            f"{MAX_SCAN_TIMEOUT_SECONDS:g}, which is the job's "
            f"{JOB_TIMEOUT_BUDGET_SECONDS:g}s timeout-minutes budget less the setup "
            "steps and the shutdown of a timed-out scan, so this script's own "
            "diagnostics win the race)"
        ),
    )
    parser.add_argument(
        "--keep-temp",
        action="store_true",
        help=(
            "leave the workspace and output directories behind for inspection. "
            "They are kept automatically whenever the gate fails"
        ),
    )
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Iterable[str] | None = None) -> int:
    args = _parse_args(argv)
    _configure_stdout_for_utf8()

    repo_root = Path(__file__).resolve().parents[1]
    temp_root = Path(tempfile.mkdtemp(prefix="ash-multi-project-"))
    workspace_root = temp_root / "workspace"
    output_dir = temp_root / "output"

    # Set only on the success path; the failure messages point the reader at the
    # kept evidence. Until the fixture is written there is nothing to keep: a
    # failed precondition used to leave the empty temp directory behind (inside
    # the checkout, when that was the precondition that failed) and name paths
    # that were never created.
    succeeded = False
    evidence_written = False
    try:
        precondition_violations = check_paths_outside_repo(
            repo_root, workspace_root, output_dir
        )
        if precondition_violations:
            print("FAIL: the gate's own preconditions are not met")
            for violation in precondition_violations:
                print(f"  - {violation}")
            return 1

        definition = write_fixture(workspace_root)
        evidence_written = True
        output_dir.mkdir(parents=True, exist_ok=True)

        print("ASH multi-project attribution gate")
        print(f"  repository root (subprocess cwd): {repo_root}")
        print(f"  workspace definition:             {definition}")
        print(f"  scan output (--output-dir):       {output_dir}")
        print(
            "  projects:                         "
            + ", ".join(
                f"{p.relative_path}@{p.threshold} [{p.marker_rule}]"
                + (f" (suppresses {p.suppress_rule})" if p.suppress_rule else "")
                for p in FIXTURE_PROJECTS
            )
        )
        print(f"  every project holds a byte-identical {FIXTURE_RELATIVE_PATH}, and a")
        print(f"  {FIXTURE_MARKER_RELATIVE_PATH} tripping only its own bracketed rule.")
        print("  Same paths, one distinct rule each: that is what makes attribution")
        print("  checkable against source rather than against the payload itself.")
        print()

        try:
            completed = run_scan(repo_root, definition, output_dir, args.timeout)
        except subprocess.TimeoutExpired as expired:
            print(f"FAIL: the scan did not finish within {args.timeout:g} seconds")
            _print_block("partial scan stdout (tail)", _tail(_as_text(expired.stdout)))
            _print_block("partial scan stderr (tail)", _tail(_as_text(expired.stderr)))
            return 1

        print(f"scan exited {completed.returncode}")

        try:
            results = load_results(output_dir)
        except FileNotFoundError as missing:
            print(f"FAIL: the scan wrote no results file at '{missing}'")
            _print_block("scan stdout (tail)", _tail(completed.stdout))
            _print_block("scan stderr (tail)", _tail(completed.stderr))
            return 1
        except json.JSONDecodeError as bad_json:
            # The scan log says what wrote a half file; it used to be withheld
            # on this path while the missing-file path printed it.
            print(f"FAIL: the results file is not valid JSON: {bad_json}")
            _print_block("scan stdout (tail)", _tail(completed.stdout))
            _print_block("scan stderr (tail)", _tail(completed.stderr))
            return 1
        except ResultsUnreadable as unreadable:
            print(f"FAIL: {unreadable}")
            _print_block("scan stdout (tail)", _tail(completed.stdout))
            _print_block("scan stderr (tail)", _tail(completed.stderr))
            return 1

        outcome = evaluate_results(
            results,
            output_dir,
            exit_code=completed.returncode,
            repo_root=repo_root,
        )

        print()
        print(format_project_table(outcome.projects))
        print()
        print(format_attribution_evidence(outcome.runs))
        print()

        if outcome.passed:
            print(
                f"PASS: {len(outcome.projects)} project(s), one SARIF run each, "
                "every project holding only its own marker rule, one project's "
                "suppression scoped to it, and each verdict from its own threshold"
            )
            succeeded = True
            return 0

        roots = outcome.root_violations
        downstream = outcome.consequential_violations
        if roots:
            print(
                f"FAIL: {len(outcome.violations)} problem(s) found -- "
                f"{len(roots)} root cause, {len(downstream)} likely consequence(s)"
            )
            print()
            print("ROOT CAUSE:")
            for violation in roots:
                print(f"  - {violation}")
            if downstream:
                print()
                print(
                    "LIKELY DOWNSTREAM of the above -- a scanner that reported "
                    "ERROR or did not run produced no findings, so violations "
                    "about missing rules, suppressions and thresholds may follow "
                    "from it. Fix the root cause first, then re-read whatever is "
                    "still reported; a missing output directory or a wrong exit "
                    "code does not follow from it:"
                )
                for violation in downstream:
                    print(f"  - {violation}")
        else:
            print(f"FAIL: {len(outcome.violations)} problem(s) found")
            for violation in outcome.violations:
                print(f"  - {violation}")
        print()
        # The scanner's own stderr log names the cause; the aggregated results
        # only say ERROR. Print it before the scan's console output, which is
        # tail-truncated and much noisier.
        print_scanner_error_evidence(output_dir, outcome.errored_scanners)
        _print_block("scan stdout (tail)", _tail(completed.stdout))
        _print_block("scan stderr (tail)", _tail(completed.stderr))
        return 1
    finally:
        if not evidence_written or (succeeded and not args.keep_temp):
            _remove_tree(temp_root)
        else:
            reason = "--keep-temp" if succeeded else "the gate failed"
            print()
            print(f"EVIDENCE KEPT ({reason}):")
            print(f"  workspace:   {workspace_root}")
            print(f"  scan output: {output_dir}")
            print(f"  remove with: {_remove_hint(temp_root)}")


if __name__ == "__main__":
    raise SystemExit(main())
