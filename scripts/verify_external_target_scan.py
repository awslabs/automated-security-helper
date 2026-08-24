# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Prove ASH can scan a target directory that is not its own working directory.

Run with: python scripts/verify_external_target_scan.py

Why this exists
---------------
ASH scans the directory named by ``--source-dir``. Scanning a directory that is not
the process working directory *already happens* in CI:
``.github/actions/validate-install/action.yml`` (lines 32, 52, 70),
``.github/actions/validate-mcp/action.yml`` (line 48) and
``.github/workflows/ash-upgrade-paths.yml`` (line 167) all pass ``--source-dir``.
So the gap this job fills is not the flag. It is that nothing has ever asserted on
what came back.

Those existing jobs cannot catch the bugs below, for two compounding reasons:

* Their fixture is ``echo 'print("hello")' > /tmp/ash-selftest/test_sample.py`` -- a
  clean file that yields zero findings even when every scanner works perfectly.
  There is nothing there to notice the absence of.
* Their only assertion is the step's exit status, and a scanner at ERROR cannot
  reach the exit status. ``_compute_exit_code`` in
  ``automated_security_helper/interactions/run_ash_scan.py`` returns 1 only when
  ``results is None``; past that guard it counts actionable findings and returns 2
  or 0, never inspecting any scanner's status.

Do not delete this job as redundant with validate-install. What is missing there is
the positive assertion, not the external target.

Two production bugs lived in that gap.

1. ``ScannerExecutor._extract_metrics_from_sarif`` returned a single pydantic model
   where the caller unpacked a 2-tuple. Pydantic models are iterable, so the unpack
   raised "too many values to unpack (expected 2)" at runtime only, and the error was
   swallowed into a scanner status. Every scanner reported ERROR with zero findings
   while 49,968 unit-test executions across 18 platform jobs stayed green.
2. checkov's config probe used ``Path(".ash/.checkov.yaml").exists()`` against the
   *process* working directory, while checkov's subprocess runs with
   ``cwd=source_dir``. Invoked from ASH's own checkout the probe matched ASH's
   committed config and handed checkov a path it could not open, so checkov reported
   ERROR. Invisible in the repository self-scan, because there cwd and source_dir
   are the same directory.

Both are fixed. This script exists so neither class of bug can merge again: it scans
a throwaway directory built outside the repository, from a working directory that is
deliberately the repository root, and asserts three things -- that no scanner broke,
that the findings the fixture is designed to produce actually came back, and that
they came back from the fixture rather than from the repository.

Why the positive assertion matters
----------------------------------
"No scanner reported ERROR" alone is not enough -- that is exactly how the broken
build looked healthy, because a scanner that produces nothing also produces no
errors. So the gate also requires a non-zero finding count and requires that the
specific rules the fixture is built to trip appear in the aggregated SARIF,
attributed to the scanner that should have produced them.

Attribution is not decoration. Each SARIF result carries
``properties.scanner_name``, and matching a rule pattern against one flat global
histogram would let an attribution regression pass: bandit and checkov would both
report zero findings in the summary table while the rule-evidence block two lines
below printed "bandit: 4 rule(s)...". Manufactured evidence in the exact block a
maintainer reads to confirm the gate did real work is worse than no evidence.

Why the fixture-scoping assertion matters
-----------------------------------------
Consider the inverse regression: ASH ignores ``--source-dir`` and scans the process
working directory. Every other assertion still passes -- the repository yields
findings, ASH's own Python trips bandit, the anchors plausibly appear, the exit code
is 0 or 2 -- while the gate has tested the exact opposite of its premise. So the
gate also checks where each finding came from.

Deliberate choices
------------------
* The fixture is generated at runtime under ``tempfile.mkdtemp()``. It is never
  committed: ASH scans its own repository in CI, so a committed fixture would be
  found by ASH's own self-scan and would fail the repository scan.
* The fixture trips bandit (Python AST rules) and checkov (Terraform policy rules)
  and deliberately does *not* plant a credential. A credential-shaped line would
  have to appear as a string literal in this file, and detect-secrets matches line
  by line with regexes rather than on an AST, so this file would itself become a
  finding in ASH's own repository scan. bandit and checkov are two independent
  scanner families, which is enough positive signal without that risk.
* Scanner status MISSING means the underlying tool is not installed on this runner.
  That is tolerated. ERROR means the scanner ran and broke, and fails the gate.
* The scan is invoked as ``<python> -m automated_security_helper.cli.main`` with
  ``cwd`` set to the repository root. ``-m`` prepends the working directory to
  ``sys.path``, so the gate always exercises the working tree rather than whatever
  copy happens to be pip-installed on the runner.

Known limitations
-----------------
* **A green gate is evidence about bandit and checkov, not about all scanners.** On a
  typical runner only those two produce findings from this fixture; detect-secrets,
  npm-audit, opengrep and semgrep return PASSED with zero findings because the
  fixture does not trip them. For those four the gate asserts only "not ERROR", and
  ``check_findings_present`` sums across scanners, so their zeroes are masked by
  bandit's and checkov's non-zeroes. Widening the fixture to trip them would widen
  the guarantee.
* If neither bandit nor checkov can be installed on a runner, the gate fails rather
  than passing quietly. A gate that silently tests nothing is worse than a red one,
  so this is intentional -- but it does mean a broken tool install reads as a gate
  failure. The message names that cause explicitly, and the workflow runs
  ``ash dependencies install`` as its own step so an install flake fails there
  instead.
* ``validation_checkpoints`` errors and discrepancies are reported as diagnostic
  context for a scanner at ERROR. They are not themselves a failure condition.
* The gate asserts rule *families* per scanner plus at least one concrete anchor
  rule ID. Requiring an exact rule-ID set would turn any upstream scanner release
  into a red branch, which has happened to this project before.
* **The fixture-scoping check matches on basename, not on a relative path, because
  the aggregated SARIF does not relativize URIs against source_dir when
  ``cwd != source_dir``.** Measured on this branch, one healthy run produced three
  different URI shapes for the same fixture directory: bandit
  ``/abs/path/to/target/insecure_app.py``, checkov
  ``abs/path/to/target/insecure_bucket.tf`` (absolute, leading separator stripped),
  and detect-secrets ``../../../../abs/path/to/target/app.py`` (relative to the
  *process* cwd). The same scan of the repository itself, where cwd and source_dir
  coincide, produces clean relative URIs such as
  ``automated_security_helper/core/phases/scanner_executor.py``. That difference is
  itself an unfixed cwd-versus-source_dir defect in
  ``sanitize_sarif_paths``/``_sanitize_uri``, and it is the reason this check cannot
  assert "the URI equals the fixture file name" or "the URI is not absolute" -- both
  would fail on every healthy run today. Basename plus a not-inside-the-repository
  test is immune to all three shapes while still catching the inverse regression,
  whose URIs would be repository-relative and would resolve to real repository
  files. If the URI normalization is ever fixed, tighten this check.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple
from urllib.parse import urlsplit

RESULTS_FILENAME = "ash_aggregated_results.json"

# ScannerStatus values as they appear in ash_aggregated_results.json. FAILED means
# findings were found at or above the configured threshold -- a successful scan, not
# a gate failure.
STATUS_ERROR = "ERROR"
STATUS_MISSING = "MISSING"
STATUS_SKIPPED = "SKIPPED"

# ASH_EXIT_CODES in automated_security_helper.core.constants documents these as
# 0 success, 1 "scan errors / scanner failures", 2 actionable findings above
# threshold, 3 invalid config. The fixture is built to produce actionable findings,
# so 2 is the expected code, and 0 is accepted in case a future default turns
# fail_on_findings off.
#
# The 1 in that table is aspirational, and this matters: a scanner at ERROR does NOT
# produce exit 1. _compute_exit_code in run_ash_scan.py returns 1 only when
# `results is None`; past that guard it counts actionable findings and returns 2 or
# 0 without ever reading a scanner's status. Mutation runs on this branch confirm it
# -- both deliberately broken trees exited 0 and 2 and sailed straight through
# check_exit_code. So check_exit_code is NOT a backstop for
# check_no_scanner_errors. Do not trim either one believing the other covers it.
#
# One more wrinkle: click/Typer raise UsageError as exit 2, which is inside this
# tuple. That is harmless today only because a usage error also writes no results
# file, so load_results fails first and reports the missing file. If the tolerated
# set ever grows, re-check that assumption.
TOLERATED_EXIT_CODES = (0, 2)

# The job that runs this script sets timeout-minutes: 25 (1500s). The default here
# must stay below that budget, or GitHub cancels the job first and the operator gets
# no summary table, no rule evidence and no log tail -- only a cancellation notice.
# The workflow also passes --timeout explicitly so both numbers are visible together.
JOB_TIMEOUT_BUDGET_SECONDS = 1500.0
DEFAULT_SCAN_TIMEOUT_SECONDS = 1200.0

# Log tail printed when something fails. Enough to see the scanner errors without
# dumping the whole Rich-rendered scan output into the job log.
LOG_TAIL_LINES = 60

# CSI, OSC and two-character escape sequences. The scan child renders a coloured
# Rich table; echoing the escapes verbatim into a CI log makes it unreadable.
_ANSI_ESCAPE = re.compile(
    r"\x1b(?:\[[0-9;?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])"
)


# ---------------------------------------------------------------------------
# Fixture content
#
# Written to disk at runtime, never committed. Every construct below is a known,
# stable finding for the scanner named in EXPECTED_PRODUCERS. These appear here as
# string literals; bandit, semgrep and opengrep all work on a parsed AST, so a
# string constant in this file is not itself a finding, and checkov only reads files
# whose name marks them as IaC.
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
  bucket = "ash-external-target-gate-fixture"
}
"""

FIXTURE_FILES: Dict[str, str] = {
    "insecure_app.py": FIXTURE_PYTHON,
    "insecure_bucket.tf": FIXTURE_TERRAFORM,
}


@dataclass(frozen=True)
class ExpectedProducer:
    """A scanner the fixture is built to trip, and the evidence it must leave.

    ``rule_pattern`` is matched against rule IDs in the aggregated SARIF and is the
    hard requirement. ``anchor_rule_ids`` are concrete IDs observed from this
    fixture; at least one must be present. "At least one" rather than "all" keeps an
    upstream rule rename from reddening the branch while still pinning real IDs.
    """

    scanner: str
    fixture_file: str
    rule_pattern: str
    anchor_rule_ids: Tuple[str, ...]


EXPECTED_PRODUCERS: Tuple[ExpectedProducer, ...] = (
    # B307 eval, B324 insecure hash, B602 subprocess with shell=True.
    ExpectedProducer(
        scanner="bandit",
        fixture_file="insecure_app.py",
        rule_pattern=r"^B\d{3}$",
        anchor_rule_ids=("B307", "B324", "B602"),
    ),
    # A bare aws_s3_bucket trips seven CKV rules today. The exact set moves with
    # every checkov release, so the pattern is the requirement and the anchors are
    # a representative sample.
    ExpectedProducer(
        scanner="checkov",
        fixture_file="insecure_bucket.tf",
        rule_pattern=r"^CKV\d*_",
        anchor_rule_ids=(
            "CKV_AWS_18",
            "CKV_AWS_21",
            "CKV_AWS_144",
            "CKV_AWS_145",
            "CKV2_AWS_6",
        ),
    ),
)


@dataclass(frozen=True)
class ScannerState:
    """One entry of ``scanner_results``, normalized."""

    name: str
    status: str
    finding_count: int
    actionable_finding_count: int
    exit_code: int
    dependencies_satisfied: bool
    excluded: bool

    @property
    def ran(self) -> bool:
        """True when the scanner actually executed.

        A scanner at ERROR did run -- it ran and broke -- so it counts as having
        run. MISSING means the tool is not installed, SKIPPED means it was not
        invoked; neither produced a verdict.
        """
        if self.excluded:
            return False
        return self.status not in (STATUS_MISSING, STATUS_SKIPPED)


@dataclass(frozen=True)
class SarifEvidence:
    """What the aggregated SARIF says, keyed by the scanner that said it.

    ``by_scanner`` holds rule counts for results that carried
    ``properties.scanner_name``; ``unattributed`` holds them for results that did
    not. Keeping the two apart is what lets ``rules_for`` decide whether attribution
    is available at all, instead of silently mixing scanners into one histogram.

    ``uris`` is every finding location, in encounter order, and
    ``results_without_location`` counts findings that carried none -- those can
    neither confirm nor deny that the fixture was scanned.
    """

    by_scanner: Dict[str, Dict[str, int]] = field(default_factory=dict)
    unattributed: Dict[str, int] = field(default_factory=dict)
    uris: Tuple[str, ...] = ()
    results_without_location: int = 0

    @property
    def has_attribution(self) -> bool:
        """True when at least one result named the scanner that produced it."""
        return bool(self.by_scanner)

    def rules_for(self, scanner: str) -> Dict[str, int]:
        """Rules attributed to one scanner, or the union when nothing is attributed.

        The union fallback exists so an older or future results file that omits
        ``properties.scanner_name`` still works rather than failing closed on a
        cosmetic difference. Partial attribution counts as attribution: the named
        buckets are authoritative and unattributed results are credited to nobody,
        because guessing an owner is how the flat-histogram defect worked.
        """
        if self.has_attribution:
            return dict(self.by_scanner.get(scanner, {}))
        return dict(self.unattributed)

    def all_rule_ids(self) -> Tuple[str, ...]:
        """Every rule ID present, regardless of attribution. Diagnostics only."""
        seen = set(self.unattributed)
        for bucket in self.by_scanner.values():
            seen.update(bucket)
        return tuple(sorted(seen))

    @property
    def total_results(self) -> int:
        return len(self.uris) + self.results_without_location


@dataclass
class GateOutcome:
    """What the gate concluded, so callers can report without re-deriving it."""

    violations: List[str] = field(default_factory=list)
    states: Tuple[ScannerState, ...] = ()
    evidence: SarifEvidence = field(default_factory=SarifEvidence)

    @property
    def passed(self) -> bool:
        return not self.violations


# ---------------------------------------------------------------------------
# Pure assertion logic
#
# Everything below this point takes an already-parsed results dict (or data derived
# from one) and returns violation strings. No subprocesses, no filesystem, no
# global state -- so the checks are unit-testable without running a scan. That
# separation is the point: the bug this gate prevents lived in a seam between a
# producer and a consumer, and a seam only stays honest if both sides can be pinned
# independently.
# ---------------------------------------------------------------------------


def normalize_status(raw: Any) -> str:
    """Return a bare uppercase status name.

    Tolerates both ``"PASSED"`` and a stringified enum such as
    ``"ScannerStatus.PASSED"``, so a change in how the model serializes does not
    silently turn every status comparison false.
    """
    text = str(raw if raw is not None else "").strip()
    if "." in text:
        text = text.rsplit(".", 1)[-1]
    return text.upper()


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def check_results_shape(results: Any) -> List[str]:
    """Verify the keys every other check reads actually exist.

    Without this, renaming a key makes every downstream assertion vacuously true
    and the gate reports success while inspecting nothing. That failure mode is
    already live elsewhere in this repository, so it is not hypothetical.
    """
    if not isinstance(results, Mapping):
        return [
            (
                f"results is not a JSON object (got {type(results).__name__}); "
                f"expected the parsed contents of {RESULTS_FILENAME}"
            )
        ]

    violations: List[str] = []
    scanner_results = results.get("scanner_results")
    if not isinstance(scanner_results, Mapping):
        violations.append(
            "results has no 'scanner_results' object -- every scanner assertion "
            "below would inspect nothing. Available top-level keys: "
            f"{sorted(str(key) for key in results)}"
        )
    elif not scanner_results:
        violations.append(
            "'scanner_results' is empty -- the scan recorded no scanners at all"
        )

    if not isinstance(results.get("sarif"), Mapping):
        violations.append(
            "results has no top-level 'sarif' object -- the rule-ID assertions "
            "below would inspect nothing"
        )
    return violations


def parse_scanner_states(results: Mapping[str, Any]) -> Tuple[ScannerState, ...]:
    """Normalize ``scanner_results`` into a sorted tuple of ScannerState."""
    scanner_results = results.get("scanner_results") or {}
    states: List[ScannerState] = []
    for name, entry in scanner_results.items():
        record: Mapping[str, Any] = entry if isinstance(entry, Mapping) else {}
        states.append(
            ScannerState(
                name=str(name),
                status=normalize_status(record.get("status")),
                finding_count=_as_int(record.get("finding_count")),
                actionable_finding_count=_as_int(
                    record.get("actionable_finding_count")
                ),
                exit_code=_as_int(record.get("exit_code")),
                dependencies_satisfied=bool(record.get("dependencies_satisfied", True)),
                excluded=bool(record.get("excluded", False)),
            )
        )
    return tuple(sorted(states, key=lambda state: state.name))


def _result_scanner_name(result: Mapping[str, Any]) -> str | None:
    """The scanner credited with a SARIF result, from ``properties.scanner_name``.

    ASH merges every scanner into one run whose driver is
    "AWS Labs - Automated Security Helper", so the driver name says nothing about
    which tool found what. This property is the only attribution available, and it
    is what ScannerStatisticsCalculator uses to derive per-scanner counts.
    """
    properties = result.get("properties")
    if not isinstance(properties, Mapping):
        return None
    raw = properties.get("scanner_name")
    if raw is None:
        return None
    name = str(raw).strip()
    return name or None


def _location_uri(location: Any) -> str | None:
    """The artifact URI of one SARIF location, or None."""
    if not isinstance(location, Mapping):
        return None
    physical = location.get("physicalLocation")
    if not isinstance(physical, Mapping):
        return None
    artifact = physical.get("artifactLocation")
    if not isinstance(artifact, Mapping):
        return None
    uri = artifact.get("uri")
    if uri is None:
        return None
    text = str(uri).strip()
    return text or None


def collect_sarif_evidence(results: Mapping[str, Any]) -> SarifEvidence:
    """Walk the aggregated SARIF once, collecting rules per scanner and every URI.

    One pass, because the rule histogram and the location set are two views of the
    same results and must not be allowed to disagree about what the scan produced.
    """
    by_scanner: Dict[str, Dict[str, int]] = {}
    unattributed: Dict[str, int] = {}
    uris: List[str] = []
    without_location = 0

    sarif = results.get("sarif")
    if not isinstance(sarif, Mapping):
        return SarifEvidence()

    for run in sarif.get("runs") or []:
        if not isinstance(run, Mapping):
            continue
        for result in run.get("results") or []:
            if not isinstance(result, Mapping):
                continue

            rule_id = result.get("ruleId")
            if rule_id is not None:
                scanner = _result_scanner_name(result)
                bucket = (
                    by_scanner.setdefault(scanner, {})
                    if scanner is not None
                    else unattributed
                )
                key = str(rule_id)
                bucket[key] = bucket.get(key, 0) + 1

            located = False
            for location in result.get("locations") or []:
                uri = _location_uri(location)
                if uri:
                    uris.append(uri)
                    located = True
            if not located:
                without_location += 1

    return SarifEvidence(
        by_scanner=by_scanner,
        unattributed=unattributed,
        uris=tuple(uris),
        results_without_location=without_location,
    )


def collect_recorded_errors(
    results: Mapping[str, Any],
) -> Dict[str, Tuple[str, ...]]:
    """Gather whatever error detail the results file holds, keyed by scanner.

    ``ScannerTargetStatusInfo`` allows extra fields, so a scanner entry may carry
    error text under a name this script cannot know ahead of time; any key whose
    name mentions "error" is collected. ``validation_checkpoints`` entries that
    name the scanner are folded in as additional context.
    """
    scanner_results = results.get("scanner_results") or {}
    checkpoint_messages: List[str] = []
    for checkpoint in results.get("validation_checkpoints") or []:
        if not isinstance(checkpoint, Mapping):
            continue
        label = str(checkpoint.get("checkpoint_name") or "checkpoint")
        for key in ("errors", "discrepancies"):
            for entry in checkpoint.get(key) or []:
                checkpoint_messages.append(f"{label}.{key}: {entry}")

    collected: Dict[str, Tuple[str, ...]] = {}
    for name, entry in scanner_results.items():
        messages: List[str] = []
        if isinstance(entry, Mapping):
            for key, value in sorted(entry.items(), key=lambda item: str(item[0])):
                if "error" in str(key).lower() and value:
                    messages.append(f"{key}: {value}")
        lowered = str(name).lower()
        messages.extend(
            message for message in checkpoint_messages if lowered in message.lower()
        )
        collected[str(name)] = tuple(messages)
    return collected


def check_no_scanner_errors(
    states: Sequence[ScannerState],
    recorded_errors: Mapping[str, Sequence[str]] | None = None,
) -> List[str]:
    """Negative assertion: no scanner may report status ERROR.

    ERROR means the scanner was invoked and something went wrong inside it. That is
    the state every scanner was silently stuck in while CI stayed green.
    """
    recorded_errors = recorded_errors or {}
    violations: List[str] = []
    for state in states:
        if state.status != STATUS_ERROR:
            continue
        lines = [
            (
                f"scanner '{state.name}' reported status ERROR "
                f"(exit_code={state.exit_code}, finding_count={state.finding_count}, "
                f"dependencies_satisfied={state.dependencies_satisfied})"
            )
        ]
        detail = recorded_errors.get(state.name) or ()
        if detail:
            lines.extend(f"    {message}" for message in detail)
        else:
            lines.append(
                "    no error detail was recorded in the results file; see the scan "
                f"log above and the '{state.name}' subdirectory of the output dir"
            )
        violations.append("\n".join(lines))
    return violations


def check_some_scanner_ran(states: Sequence[ScannerState]) -> List[str]:
    """A gate where every scanner is MISSING has tested nothing, so it must fail."""
    if not states:
        return ["no scanners appear in scanner_results at all"]
    if any(state.ran for state in states):
        return []
    statuses = ", ".join(f"{state.name}={state.status}" for state in states)
    return [
        (
            "every scanner is MISSING, SKIPPED or excluded, so the scan exercised "
            f"nothing. Statuses: {statuses}"
        )
    ]


def check_findings_present(states: Sequence[ScannerState]) -> List[str]:
    """Positive assertion: the scanners that ran must have found something.

    Absence of errors is not evidence of a working scan. A scanner that cannot
    produce findings also cannot produce errors, which is precisely how the broken
    build passed CI.
    """
    ran = [state for state in states if state.ran]
    if not ran:
        # check_some_scanner_ran already reports this; do not double-count it.
        return []
    total = sum(state.finding_count for state in ran)
    if total > 0:
        return []
    names = ", ".join(state.name for state in ran)
    return [
        (
            f"the fixture produced zero findings across every scanner that ran "
            f"({names}). The fixture contains known insecure Python and a "
            "non-compliant aws_s3_bucket, so zero findings means scanning is "
            "broken, not that the target is clean"
        )
    ]


def check_expected_producers_available(
    states: Sequence[ScannerState],
) -> List[str]:
    """At least one scanner whose findings the gate asserts on must have run."""
    by_name = {state.name: state for state in states}
    available = [
        producer.scanner
        for producer in EXPECTED_PRODUCERS
        if producer.scanner in by_name and by_name[producer.scanner].ran
    ]
    if available:
        return []
    expected = ", ".join(producer.scanner for producer in EXPECTED_PRODUCERS)
    return [
        (
            f"none of the scanners this gate asserts on ({expected}) ran on this "
            "runner, so no finding could be verified. This usually means the tool "
            "install failed rather than that the product is broken -- check the "
            "scan log for dependency resolution errors"
        )
    ]


def check_expected_rules_present(
    states: Sequence[ScannerState],
    evidence: SarifEvidence,
) -> List[str]:
    """Positive assertion: each available producer left its own rules in the SARIF.

    Matches within the producer's own attribution bucket, never against a global
    histogram. A rule that matches bandit's pattern but is attributed to another
    scanner does not satisfy bandit -- that is the whole point of keying by scanner.

    Skips any producer whose scanner is MISSING, SKIPPED or excluded: the tool is
    not installed on this runner and requirement (e) says that must not fail.
    """
    by_name = {state.name: state for state in states}
    violations: List[str] = []
    for producer in EXPECTED_PRODUCERS:
        state = by_name.get(producer.scanner)
        if state is None or not state.ran:
            continue
        rules = evidence.rules_for(producer.scanner)
        matched = sorted(
            rule_id for rule_id in rules if re.match(producer.rule_pattern, rule_id)
        )
        if not matched:
            violations.append(
                f"scanner '{producer.scanner}' ran with status {state.status} but no "
                f"rule matching {producer.rule_pattern!r} is attributed to it in the "
                f"aggregated SARIF; '{producer.fixture_file}' should have produced "
                f"one. Attributed to it: {sorted(rules) or 'none'}. Every rule ID "
                f"present: {list(evidence.all_rule_ids()) or 'none'}"
            )
            continue
        if producer.anchor_rule_ids and not any(
            anchor in rules for anchor in producer.anchor_rule_ids
        ):
            violations.append(
                f"scanner '{producer.scanner}' produced rules {matched} but none of "
                f"the expected anchors {list(producer.anchor_rule_ids)}. Either "
                f"'{producer.fixture_file}' no longer trips the rules it was "
                "written for, or the anchors need updating for a new scanner "
                "version"
            )
    return violations


def _normalize_uri(uri: str) -> str:
    """Strip a ``file://`` scheme, normalize separators, drop leading ``./``.

    Separators are normalized because ``str(Path)`` uses backslashes on Windows and
    a scanner may emit either. Everything downstream compares path components, not
    slash-joined strings.
    """
    text = str(uri).strip()
    if text.lower().startswith("file://"):
        text = urlsplit(text).path
    text = text.replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return text


def _sample(values: Sequence[str], limit: int = 5) -> str:
    """Deduplicated, order-preserving, capped rendering for failure messages."""
    unique: List[str] = []
    for value in values:
        if value not in unique:
            unique.append(value)
    shown = unique[:limit]
    suffix = f" (+{len(unique) - limit} more)" if len(unique) > limit else ""
    return f"{shown}{suffix}"


def check_findings_are_from_the_fixture(
    evidence: SarifEvidence,
    repo_root: Path,
) -> List[str]:
    """Positive assertion: every finding must point at a fixture file.

    This is the property the job is named for. Without it the gate cannot tell a
    scan of the fixture from a scan of the repository, and the inverse regression --
    ASH ignoring --source-dir and scanning the process working directory -- passes
    every other check in this file.

    Two independent tests per URI. Both are needed because the aggregated SARIF does
    not relativize URIs against source_dir when cwd != source_dir; see the Known
    limitations section for the three shapes measured on a healthy run.

    1. The basename must be one of FIXTURE_FILES. Immune to all three shapes, and on
       its own enough to catch a scan of the repository, whose basenames would be
       scanner_executor.py, Dockerfile, action.yml and so on.
    2. The URI must not resolve to a file that exists inside the repository. This is
       the direct statement of "not the repository", and it closes the gap where a
       repository file happens to share a fixture basename.
    """
    root = repo_root.resolve()
    fixture_basenames = frozenset(FIXTURE_FILES)
    wrong_basename: List[str] = []
    inside_repository: List[str] = []

    for uri in evidence.uris:
        normalized = _normalize_uri(uri)
        if not normalized:
            continue

        # PurePosixPath because separators are already normalized to "/"; using it
        # rather than Path keeps the parse identical on every platform.
        if PurePosixPath(normalized).name not in fixture_basenames:
            wrong_basename.append(uri)

        # Path joining discards the base when the right operand is absolute, so an
        # absolute URI resolves to itself and lands outside the repository, which is
        # exactly the verdict we want for it.
        candidate = Path(root, normalized)
        with suppress(OSError, ValueError):
            candidate = candidate.resolve()
        if candidate.is_relative_to(root) and candidate.exists():
            inside_repository.append(uri)

    violations: List[str] = []
    if not evidence.uris:
        if evidence.results_without_location:
            violations.append(
                f"none of the {evidence.results_without_location} finding(s) carry a "
                "location URI, so the gate cannot tell whether the fixture or the "
                "repository was scanned. Either the SARIF location shape moved or "
                "locations are being dropped"
            )
        # Zero results at all is check_findings_present's verdict, not this one's.
        return violations

    if wrong_basename:
        violations.append(
            "finding(s) name a file that is not part of the fixture. Expected a "
            f"basename in {sorted(fixture_basenames)}; got "
            f"{_sample(wrong_basename)}"
        )
    if inside_repository:
        violations.append(
            "finding(s) name files inside the repository, which means the scan read "
            "the process working directory instead of --source-dir: "
            f"{_sample(inside_repository)}"
        )
    return violations


def check_exit_code(exit_code: int) -> List[str]:
    """The scan process itself must not have failed or rejected its config."""
    if exit_code in TOLERATED_EXIT_CODES:
        return []
    return [
        (
            f"ash scan exited {exit_code}; expected one of "
            f"{list(TOLERATED_EXIT_CODES)} (0 success, 2 actionable findings). "
            "Exit 1 is a scan error and exit 3 is an invalid config"
        )
    ]


def check_paths_outside_repo(repo_root: Path, *paths: Path) -> List[str]:
    """The whole point of the gate is that the target is not the repository.

    Compares resolved ``Path`` objects rather than joined strings: ``str(Path)``
    uses backslashes on Windows, so any substring or ``endswith`` check on a
    slash-joined path is wrong there.
    """
    root = repo_root.resolve()
    violations: List[str] = []
    for path in paths:
        resolved = path.resolve()
        if resolved == root or resolved.is_relative_to(root):
            violations.append(
                f"'{resolved}' is inside the repository at '{root}'. The gate must "
                "scan a directory outside the repository, otherwise cwd and "
                "source_dir coincide and the bug class this gate exists for stays "
                "invisible"
            )
    return violations


def evaluate_results(
    results: Any,
    exit_code: int | None = None,
    repo_root: Path | None = None,
) -> GateOutcome:
    """Run every assertion against a parsed results dict.

    Shape violations short-circuit: if the keys are not where they should be, the
    remaining checks would pass by inspecting nothing, which is worse than failing.

    ``repo_root`` gates the fixture-scoping check. It is optional so the pure logic
    stays callable without a checkout, but the gate itself always passes it -- the
    check is not decoration.
    """
    outcome = GateOutcome()
    shape_violations = check_results_shape(results)
    if shape_violations:
        outcome.violations.extend(shape_violations)
        return outcome

    states = parse_scanner_states(results)
    evidence = collect_sarif_evidence(results)
    outcome.states = states
    outcome.evidence = evidence

    outcome.violations.extend(
        check_no_scanner_errors(states, collect_recorded_errors(results))
    )
    outcome.violations.extend(check_some_scanner_ran(states))
    outcome.violations.extend(check_findings_present(states))
    outcome.violations.extend(check_expected_producers_available(states))
    outcome.violations.extend(check_expected_rules_present(states, evidence))
    if repo_root is not None:
        outcome.violations.extend(
            check_findings_are_from_the_fixture(evidence, repo_root)
        )
    if exit_code is not None:
        outcome.violations.extend(check_exit_code(exit_code))
    return outcome


def format_summary_table(states: Sequence[ScannerState]) -> str:
    """A plain-ASCII table. Windows consoles cannot encode box-drawing or emoji."""
    headers = ("scanner", "status", "findings", "actionable", "exit")
    rows = [
        (
            state.name,
            state.status or "-",
            str(state.finding_count),
            str(state.actionable_finding_count),
            str(state.exit_code),
        )
        for state in states
    ]
    widths = [
        max(len(headers[column]), *(len(row[column]) for row in rows))
        if rows
        else len(headers[column])
        for column in range(len(headers))
    ]

    def render(values: Sequence[str]) -> str:
        cells = [values[0].ljust(widths[0]), values[1].ljust(widths[1])]
        cells.extend(
            values[column].rjust(widths[column]) for column in range(2, len(headers))
        )
        return "  ".join(cells).rstrip()

    lines = [render(headers), "  ".join("-" * width for width in widths)]
    lines.extend(render(row) for row in rows)
    return "\n".join(lines)


def format_rule_evidence(
    states: Sequence[ScannerState],
    evidence: SarifEvidence,
) -> str:
    """Show which rules each asserted-on scanner actually produced.

    Reads ``evidence.rules_for`` -- the same source check_expected_rules_present
    asserts on -- so the printed evidence cannot claim rules the assertion did not
    credit to that scanner. Reporting from a different source than the assertion is
    how a passing gate came to print manufactured evidence.
    """
    by_name = {state.name: state for state in states}
    lines: List[str] = []
    if not evidence.has_attribution and evidence.all_rule_ids():
        lines.append(
            "note: no result carried properties.scanner_name, so rules below are the "
            "unattributed union rather than per-scanner"
        )
    for producer in EXPECTED_PRODUCERS:
        state = by_name.get(producer.scanner)
        if state is None:
            lines.append(f"{producer.scanner}: not present in scanner_results")
            continue
        if not state.ran:
            lines.append(
                f"{producer.scanner}: {state.status} (tool unavailable; not asserted)"
            )
            continue
        rules = evidence.rules_for(producer.scanner)
        matched = sorted(
            rule_id for rule_id in rules if re.match(producer.rule_pattern, rule_id)
        )
        anchors = [anchor for anchor in producer.anchor_rule_ids if anchor in rules]
        lines.append(
            f"{producer.scanner}: {len(matched)} rule(s) matching "
            f"{producer.rule_pattern} -- {matched}; anchors seen: {anchors}"
        )
    scanners = sorted(evidence.by_scanner) or ["none"]
    lines.append(
        f"finding locations: {len(evidence.uris)} URI(s) from scanner(s) {scanners}; "
        f"{evidence.results_without_location} finding(s) carried no location"
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Subprocess and temp-directory wrappers
#
# Thin shells around the pure logic above: build a fixture, run one scan, load one
# JSON file, hand it to evaluate_results.
# ---------------------------------------------------------------------------


def write_fixture(target_dir: Path) -> Tuple[Path, ...]:
    """Materialize FIXTURE_FILES under ``target_dir`` and return the paths.

    Always UTF-8: ``write_text`` defaults to the locale codepage on Windows.
    """
    target_dir.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []
    for name, content in FIXTURE_FILES.items():
        path = target_dir / name
        path.write_text(content, encoding="utf-8")
        written.append(path)
    return tuple(written)


def build_scan_command(source_dir: Path, output_dir: Path) -> List[str]:
    """The scan invocation, as a list -- never a shell string.

    ``--phases scan`` is enough to write the aggregated results file, and skipping
    the report phase keeps the gate fast.
    """
    return [
        sys.executable,
        "-m",
        "automated_security_helper.cli.main",
        "scan",
        "--source-dir",
        str(source_dir),
        "--output-dir",
        str(output_dir),
        "--phases",
        "scan",
        "--no-progress",
        "--simple",
    ]


def run_scan(
    repo_root: Path,
    source_dir: Path,
    output_dir: Path,
    timeout: float,
) -> subprocess.CompletedProcess[str]:
    """Run one scan of ``source_dir`` from a working directory that is not it.

    ``cwd=repo_root`` is the load-bearing part of this whole script. It is passed to
    the child rather than set with ``os.chdir``: this project deliberately removed
    process-wide cwd dependence, and reintroducing a global chdir previously took
    the unit suite from 2677 passed to 107 failed.
    """
    command = build_scan_command(source_dir, output_dir)
    env = dict(os.environ)
    # The child renders a Rich table. Force UTF-8 both ways so a cp1252 default on
    # Windows cannot turn a passing scan into an encoding traceback.
    env["PYTHONIOENCODING"] = "utf-8"
    env.setdefault("PYTHONUTF8", "1")
    return subprocess.run(  # nosec B603 -- list args, no shell, argv[0] is sys.executable
        command,
        cwd=str(repo_root),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


def load_results(output_dir: Path) -> Any:
    """Read and parse the aggregated results file, explicitly as UTF-8."""
    results_path = output_dir / RESULTS_FILENAME
    if not results_path.exists():
        raise FileNotFoundError(str(results_path))
    return json.loads(results_path.read_text(encoding="utf-8"))


def sanitize_for_console(text: str) -> str:
    """Make captured child output safe to print on any console.

    Both reasons are Windows ones. The scan child renders a Rich table using
    box-drawing characters, and a default Windows console is cp1252, so echoing
    them raises UnicodeEncodeError -- the same failure mode that has already broken
    jobs in this repository. Stripping the ANSI escapes at the same time turns the
    failure output from a wall of colour codes into something readable in a CI log.

    Decoration is the only thing lost: scanner names, statuses and error text are
    all ASCII already.
    """
    plain = _ANSI_ESCAPE.sub("", text or "")
    return plain.encode("ascii", "replace").decode("ascii")


def _tail(text: str, limit: int = LOG_TAIL_LINES) -> str:
    lines = (text or "").splitlines()
    if len(lines) <= limit:
        return "\n".join(lines)
    return "\n".join(
        [f"... {len(lines) - limit} earlier line(s) omitted ..."] + lines[-limit:]
    )


def _as_text(stream: Any) -> str:
    """Decode a captured stream that may be str, bytes or None.

    ``TimeoutExpired`` carries whatever had been read when the timer fired, and it
    is bytes even when ``subprocess.run`` was given ``text=True``.
    """
    if stream is None:
        return ""
    if isinstance(stream, bytes):
        return stream.decode("utf-8", "replace")
    return str(stream)


def _print_block(title: str, body: Any) -> None:
    """The single choke point for echoing captured child output."""
    text = _as_text(body)
    if not text.strip():
        return
    print(f"--- {title} ---")
    print(sanitize_for_console(text))


def _configure_stdout_for_utf8() -> None:
    """Force this process's own stdout to UTF-8, replacing what it cannot encode.

    The child's environment already asks for UTF-8, but that says nothing about the
    parent. The parent prints scanner error text read out of the results JSON, SARIF
    rule IDs, and a temp-directory path from inside a ``finally`` block -- where an
    encoding error would convert a PASS into a traceback. The exposure is small on
    these runners and entirely in the branch where the output matters most.

    Guarded because ``reconfigure`` only exists on TextIOWrapper: under pytest's
    capture, or any redirection to a plain object, stdout may not have it.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        with suppress(OSError, ValueError):
            reconfigure(encoding="utf-8", errors="replace")


def _remove_tree(path: Path) -> None:
    """Best-effort cleanup. Windows can hold locks on just-written files."""
    shutil.rmtree(path, ignore_errors=True)
    if path.exists():
        print(f"WARNING: could not fully remove temp directory '{path}'")


def _parse_args(argv: Iterable[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Scan a throwaway directory outside this repository and assert both "
            "that no scanner errored and that the expected findings came back."
        )
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_SCAN_TIMEOUT_SECONDS,
        help=(
            "seconds to allow the scan subprocess (default: "
            f"{DEFAULT_SCAN_TIMEOUT_SECONDS:g}; must stay under the job's "
            f"{JOB_TIMEOUT_BUDGET_SECONDS:g}s timeout-minutes budget so this "
            "script's own diagnostics win the race)"
        ),
    )
    parser.add_argument(
        "--keep-temp",
        action="store_true",
        help=(
            "leave the fixture and output directories behind for inspection. They "
            "are kept automatically whenever the gate fails"
        ),
    )
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Iterable[str] | None = None) -> int:
    args = _parse_args(argv)
    _configure_stdout_for_utf8()

    # Derived from __file__, not from Path.cwd(): the gate must not depend on where
    # it was invoked from, since that dependence is the bug class under test.
    repo_root = Path(__file__).resolve().parents[1]

    temp_root = Path(tempfile.mkdtemp(prefix="ash-external-target-"))
    target_dir = temp_root / "target"
    output_dir = temp_root / "output"

    # Set only on the success path. Anything else -- a violation, a timeout, an
    # unhandled exception -- leaves the fixture and the scan output on disk, because
    # the failure messages tell the reader to go and look at them.
    succeeded = False
    try:
        precondition_violations = check_paths_outside_repo(
            repo_root, target_dir, output_dir
        )
        if precondition_violations:
            print("FAIL: the gate's own preconditions are not met")
            for violation in precondition_violations:
                print(f"  - {violation}")
            return 1

        written = write_fixture(target_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        print("ASH external-target scan gate")
        print(f"  repository root (subprocess cwd): {repo_root}")
        print(f"  scan target (--source-dir):       {target_dir}")
        print(f"  scan output (--output-dir):       {output_dir}")
        print(f"  fixture files:                    {[p.name for p in written]}")
        print("  cwd != source_dir, which is the condition this gate exists for")
        print()

        try:
            completed = run_scan(repo_root, target_dir, output_dir, args.timeout)
        except subprocess.TimeoutExpired as expired:
            print(f"FAIL: the scan did not finish within {args.timeout:g} seconds")
            # TimeoutExpired carries whatever had been read when the timer fired.
            # Discarding it leaves the operator a one-line failure and nothing to
            # act on; a partial scan log usually names the scanner that hung.
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
            print(f"FAIL: the results file is not valid JSON: {bad_json}")
            return 1

        outcome = evaluate_results(
            results, exit_code=completed.returncode, repo_root=repo_root
        )

        print()
        print(format_summary_table(outcome.states))
        print()
        print(format_rule_evidence(outcome.states, outcome.evidence))
        print()

        if outcome.passed:
            ran = [state for state in outcome.states if state.ran]
            total = sum(state.finding_count for state in ran)
            print(
                f"PASS: {len(ran)} scanner(s) ran, none errored, {total} finding(s) "
                "reported, every finding located in the fixture outside the "
                "repository"
            )
            succeeded = True
            return 0

        print(f"FAIL: {len(outcome.violations)} problem(s) found")
        for violation in outcome.violations:
            print(f"  - {violation}")
        print()
        _print_block("scan stdout (tail)", _tail(completed.stdout))
        _print_block("scan stderr (tail)", _tail(completed.stderr))
        return 1
    finally:
        if succeeded and not args.keep_temp:
            _remove_tree(temp_root)
        else:
            reason = "--keep-temp" if succeeded else "the gate failed"
            print()
            print(f"EVIDENCE KEPT ({reason}):")
            print(f"  fixture:     {target_dir}")
            print(f"  scan output: {output_dir}")
            print(f"  remove with: rm -rf {temp_root}")


if __name__ == "__main__":
    raise SystemExit(main())
