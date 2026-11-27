# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Characterization of what the OCSF reporter counts and numbers across results.

The reporter builds each finding one result at a time (a pydantic record with a
guarded read per field and a degraded fallback), and what it does across the
results is algebra: the occurrence number of results that share an identity key,
and the tallies of the run's outcomes. These tests pin that algebra against a
verbatim copy of the code that did it row by row, and against the log lines that
state the tallies, so the same answers hold when it is computed on a frame.
"""

import random
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters import (
    ocsf_reporter as ocsf_module,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.ocsf_reporter import (
    _IDENTITY_SEPARATOR,
    DEGRADED_FINDING_LABEL,
    OcsfReporter,
    _fallback_identities,
    _identity_key,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Kind,
    Kind1,
    Level,
    Location,
    Message,
    Message1,
    PhysicalLocation,
    PhysicalLocation2,
    Region,
    Result,
    Run,
    SarifReport,
    Suppression,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.sarif_utils import (
    result_rule_id,
    result_states_no_finding,
)

pytestmark = pytest.mark.unit

AshAggregatedResults.model_rebuild()


def _oracle(results: List[Any], shared_ids: List[Optional[str]]) -> List[Optional[str]]:
    """The identity pass as it was written before it ran on a frame, verbatim."""
    seen: Dict[str, int] = {}
    identities: List[Optional[str]] = []
    for result, shared_id in zip(results, shared_ids):
        if shared_id or result_states_no_finding(result):
            identities.append(None)
            continue
        key = _identity_key(result, result_rule_id(result) or "Unknown Rule")
        count = seen.get(key, 0)
        seen[key] = count + 1
        if count:
            key = _IDENTITY_SEPARATOR.join([key, "occurrence", str(count)])
        identities.append(key)
    return identities


def _result(rule="R1", text="m", uri=None, line=None, kind=None, level=Level.error):
    values: Dict[str, Any] = {
        "ruleId": rule,
        "level": level,
        "message": Message(root=Message1(text=text)),
    }
    if kind is not None:
        values["kind"] = kind
    if uri is not None:
        values["locations"] = [
            Location(
                physicalLocation=PhysicalLocation(
                    root=PhysicalLocation2(
                        artifactLocation=ArtifactLocation(uri=uri),
                        region=Region(startLine=line) if line else None,
                    )
                )
            )
        ]
    return Result(**values)


def _unvalidated(rule, text, uri):
    """A result that holds a lone surrogate, which validation would refuse."""
    result = _result(rule=rule, text="x", uri="a.py", line=1)
    object.__setattr__(result, "ruleId", rule)
    result.message.root.text = text
    result.locations[0].physicalLocation.root.artifactLocation.uri = uri
    return result


class TestTheIdentitiesAgreeWithTheRowByRowPass:
    def test_identical_results_are_numbered_in_order(self):
        results = [_result(uri="a.py", line=1) for _ in range(4)]
        got = _fallback_identities(results, [None] * 4)
        assert got == _oracle(results, [None] * 4)
        assert "occurrence" not in got[0]
        assert got[3].endswith("|occurrence|3")

    def test_interleaved_keys_each_keep_their_own_count(self):
        a = lambda: _result(rule="A", uri="a.py", line=1)  # noqa: E731
        b = lambda: _result(rule="B", uri="a.py", line=1)  # noqa: E731
        results = [a(), b(), a(), a(), b(), _result(rule="C")]
        got = _fallback_identities(results, [None] * 6)
        assert got == _oracle(results, [None] * 6)
        assert got[2].endswith("|occurrence|1") and got[3].endswith("|occurrence|2")
        assert got[4].endswith("|occurrence|1")

    def test_a_shared_id_or_a_non_finding_has_none_and_takes_no_number(self):
        finding = _result(uri="a.py", line=1)
        passed = _result(uri="a.py", line=1, kind=Kind.pass_, level=Level.none)
        twin = _result(uri="a.py", line=1)
        results = [finding, passed, twin, _result(uri="a.py", line=1)]
        shared = [None, None, None, "shared-1"]
        got = _fallback_identities(results, shared)
        assert got == _oracle(results, shared)
        assert got[1] is None and got[3] is None
        assert got[2].endswith("|occurrence|1")

    def test_an_empty_run_has_no_identities(self):
        assert _fallback_identities([], []) == []

    def test_a_result_with_a_lone_surrogate_in_its_path_or_message(self):
        lone = "dir/\udcff.py"
        results = [
            _unvalidated("R1", "m", lone),
            _unvalidated("R1", "m", lone),
            # the two texts that a lossy encode (errors="replace") would merge
            _unvalidated("R1", "m", "dir/�.py"),
            _unvalidated("R1", "m", "dir/\udc80.py"),
            _unvalidated("R1", "m", "dir/\udc81.py"),
            _unvalidated("R1", "\udcfftext", lone),
            _unvalidated("R1", "\udcfftext", lone),
        ]
        got = _fallback_identities(results, [None] * len(results))
        assert got == _oracle(results, [None] * len(results))
        occurrences = [g.count("occurrence") for g in got]
        assert occurrences == [0, 1, 0, 0, 0, 0, 1]

    def test_a_corpus_of_repeated_and_distinct_results(self):
        rng = random.Random(20261124)
        rules = ["R1", "R2", "R3"]
        texts = ["m", "n", "café", "\udcfe", "a|b", "a\\|b"]
        plain_paths = ["a.py", "b/c.py", "d\\e.py", "x|y.py"]
        paths = plain_paths + [None, "\udcff.py"]
        results, shared = [], []
        for _ in range(150):
            results.append(
                _unvalidated(rng.choice(rules), rng.choice(texts), rng.choice(paths))
                if rng.random() < 0.5
                else _result(
                    rule=rng.choice(rules),
                    text=rng.choice(texts[:3] + texts[4:]),
                    uri=rng.choice(plain_paths),
                    line=rng.choice([1, 2, 3]),
                    kind=rng.choice([None, None, None, Kind.pass_]),
                    level=Level.error,
                )
            )
            shared.append(rng.choice([None, None, None, None, "s"]))
        # A pass result here is built at level error, so it contradicts its kind:
        # the reporter reads the whole result, and that one is a finding.
        assert _fallback_identities(results, shared) == _oracle(results, shared)


class _Recorder:
    def __init__(self):
        self.lines: List[tuple] = []

    def __getattr__(self, name):
        if name in {"debug", "info", "warning", "error", "exception"}:

            def _record(message, *args, **kwargs):
                self.lines.append((name, str(message)))

            return _record
        raise AttributeError(name)


def _model(results):
    model = AshAggregatedResults()
    model.sarif = SarifReport(
        version="2.1.0",
        runs=[Run(tool=Tool(driver=ToolComponent(name="ASH")), results=results)],
    )
    return model


@pytest.fixture
def reporter(test_plugin_context):
    return OcsfReporter(context=test_plugin_context)


def _suppressed(rule):
    result = _result(rule=rule, uri="s.py", line=1)
    result.suppressions = [Suppression(kind=Kind1.external, justification="risk")]
    return result


class TestTheRunsTalliesAreStatedAsTheyWere:
    def _lines(self, reporter, monkeypatch, results, fail=(), degrade=()):
        recorder = _Recorder()
        monkeypatch.setattr(ocsf_module, "ASH_LOGGER", recorder)
        real = OcsfReporter._create_vulnerability_finding

        def _build(self, result, *args, **kwargs):
            if result.ruleId in fail:
                raise RuntimeError("fails")
            finding = real(self, result, *args, **kwargs)
            if result.ruleId in degrade:
                finding.metadata.labels = list(finding.metadata.labels or []) + [
                    DEGRADED_FINDING_LABEL
                ]
            return finding

        monkeypatch.setattr(OcsfReporter, "_create_vulnerability_finding", _build)
        reporter.report(_model(results))
        return [m for level, m in recorder.lines if level in ("info", "warning")]

    def test_a_mixed_run_states_each_count(self, reporter, monkeypatch):
        results = [
            _result(rule="OK1", uri="a.py", line=1),
            _result(rule="OK2", uri="a.py", line=2),
            _suppressed("SUP"),
            _result(rule="PASS", kind=Kind.pass_, level=Level.none),
            _result(rule="BAD", uri="a.py", line=3),
            _result(rule="DEG", uri="a.py", line=4),
        ]
        lines = self._lines(
            reporter, monkeypatch, results, fail={"BAD"}, degrade={"DEG"}
        )
        assert (
            "OCSF report processing complete: 3/5 findings created whole, "
            "1 degraded, 1 failed (60.0% success rate)"
        ) in lines
        assert "Finding status breakdown: 3 active, 1 suppressed" in lines
        assert (
            "1 findings failed to process and were skipped (20.0% failure rate)"
        ) in lines
        assert (
            "1 SARIF result(s) state no problem (kind pass, "
            "notApplicable or informational) and are not OCSF findings"
        ) in lines

    def test_a_clean_run_reports_no_failures_or_degradation(
        self, reporter, monkeypatch
    ):
        results = [_result(rule=f"R{n}", uri="a.py", line=n + 1) for n in range(3)]
        lines = self._lines(reporter, monkeypatch, results)
        assert (
            "OCSF report processing complete: 3/3 findings created whole, "
            "0 degraded, 0 failed (100.0% success rate)"
        ) in lines
        assert "Finding status breakdown: 3 active, 0 suppressed" in lines
        assert not any("failed to process" in m for m in lines)
        assert not any("state no problem" in m for m in lines)

    def test_a_run_of_only_non_findings_has_no_rates(self, reporter, monkeypatch):
        results = [_result(rule="P", kind=Kind.pass_, level=Level.none)]
        lines = self._lines(reporter, monkeypatch, results)
        assert not any("OCSF report processing complete" in m for m in lines)
