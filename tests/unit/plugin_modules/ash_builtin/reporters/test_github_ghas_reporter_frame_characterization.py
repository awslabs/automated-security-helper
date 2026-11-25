# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The GHAS reporter's per-result grouping and ranking, pinned against the
implementations it had before they ran on a frame.

The reporter ranks its results by severity, scores each rule by its most severe
result, partitions the rules by whether an emitted result names them, and names
the rules whose results carry no location. Those are group-bys, a stable sort
and a semi-join over one row per result. The oracles below are the loops they
were written as, kept verbatim, so a change to how the reporter computes them
is held to what they returned: every input here goes through both and the
answers must be equal, element for element and in order.

Rule ids are scanner text, so the inputs include a lone surrogate, a character
outside the BMP and ids that differ only past a shared prefix: a polars string
column holds UTF-8 and ``str.encode`` refuses a surrogate, which the oracle's
dict and ``sorted`` never did.
"""

import json
import random
from typing import Any, Dict, List, Tuple

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters import (
    github_ghas_reporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.github_ghas_reporter import (
    GHASReporter,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Level,
    Location,
    Message,
    PhysicalLocation,
    PropertyBag,
    Region,
    ReportingDescriptor,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.severity_ladder import SEVERITIES

pytestmark = pytest.mark.unit

AshAggregatedResults.model_rebuild()

Graded = List[Tuple[str, Dict[str, Any]]]

_RULE_IDS = (
    "R1",
    "R2",
    "CVE-2024-0001",
    "CVE-2024-0002",
    "a/R1",
    "\ud800",
    "x\udc80y",
    "\U0001f600",
    "régle",
    "￿",
    "\U0010ffff",
)


def _oracle_most_severe(graded: Graded, count: int) -> Graded:
    ranked = sorted(graded, key=lambda item: SEVERITIES.index(item[0]))
    return ranked[:count]


def _oracle_rule_severities(graded: Graded) -> Dict[str, str]:
    levels: Dict[str, str] = {}
    for severity, slim in graded:
        rule_id = slim.get("ruleId")
        if not rule_id:
            continue
        current = levels.get(rule_id)
        if current is None or SEVERITIES.index(severity) < SEVERITIES.index(current):
            levels[rule_id] = severity
    return levels


def _graded(rng: random.Random, size: int) -> Graded:
    graded: Graded = []
    for position in range(size):
        slim: Dict[str, Any] = {"message": {"text": f"m{position}"}}
        rule_id = rng.choice(_RULE_IDS + (None, ""))
        if rule_id is not None:
            slim["ruleId"] = rule_id
        graded.append((rng.choice(SEVERITIES), slim))
    return graded


@pytest.mark.parametrize("seed", range(40))
class TestRankingAndScoringAgainstTheLoopsTheyWere:
    def test_the_most_severe_are_the_same_results_in_the_same_order(self, seed):
        rng = random.Random(seed)
        graded = _graded(rng, rng.randint(0, 60))
        count = rng.randint(0, len(graded) + 3)

        kept = github_ghas_reporter._most_severe(graded, count)

        assert kept == _oracle_most_severe(graded, count)
        assert all(a is b for a, b in zip(kept, _oracle_most_severe(graded, count)))

    def test_each_rule_is_scored_by_its_most_severe_result(self, seed):
        rng = random.Random(1000 + seed)
        graded = _graded(rng, rng.randint(0, 60))

        assert github_ghas_reporter._rule_severities(graded) == _oracle_rule_severities(
            graded
        )


class TestTheEmptyAndTheTied:
    def test_nothing_ranks_to_nothing(self):
        assert github_ghas_reporter._most_severe([], 5) == []
        assert github_ghas_reporter._rule_severities([]) == {}

    def test_a_count_of_zero_keeps_nothing(self):
        graded = [("HIGH", {"ruleId": "R"})]
        assert github_ghas_reporter._most_severe(graded, 0) == []

    def test_equal_severities_keep_their_original_order(self):
        graded = [("HIGH", {"ruleId": f"R{i}"}) for i in range(10)]
        kept = github_ghas_reporter._most_severe(graded, 4)
        assert [slim["ruleId"] for _, slim in kept] == ["R0", "R1", "R2", "R3"]

    def test_a_result_with_no_rule_scores_no_rule(self):
        graded = [("CRITICAL", {}), ("LOW", {"ruleId": ""}), ("LOW", {"ruleId": "R"})]
        assert github_ghas_reporter._rule_severities(graded) == {"R": "LOW"}


def _oracle_unlocated(slim_results: List[Dict[str, Any]]) -> Tuple[int, List[str]]:
    names = sorted(
        {
            str(result.get("ruleId") or "<no rule>")
            for result in slim_results
            if "locations" not in result
        }
    )
    return sum(1 for r in slim_results if "locations" not in r), names


def _oracle_named_first(slim_rules, slim_results, cap):
    referenced = {result.get("ruleId") for result in slim_results}
    named = [rule for rule in slim_rules if rule["id"] in referenced]
    unnamed = [rule for rule in slim_rules if rule["id"] not in referenced]
    return (named + unnamed)[:cap], len(named)


@pytest.mark.parametrize("seed", range(40))
class TestLocationsAndRulePartitionAgainstTheLoopsTheyWere:
    def test_the_unlocated_rules_and_their_count(self, seed):
        rng = random.Random(2000 + seed)
        slim_results = []
        for _ in range(rng.randint(0, 40)):
            slim: Dict[str, Any] = {}
            rule_id = rng.choice(_RULE_IDS + (None,))
            if rule_id is not None:
                slim["ruleId"] = rule_id
            if rng.random() < 0.5:
                slim["locations"] = [{}]
            slim_results.append(slim)

        assert github_ghas_reporter._unlocated(slim_results) == _oracle_unlocated(
            slim_results
        )

    def test_the_named_rules_go_first_and_the_cap_cuts_the_rest(self, seed):
        rng = random.Random(3000 + seed)
        ids = list(_RULE_IDS)
        rng.shuffle(ids)
        slim_rules = [{"id": rule_id, "n": n} for n, rule_id in enumerate(ids)]
        slim_results = [
            {"ruleId": rng.choice(_RULE_IDS + (None,))}
            for _ in range(rng.randint(0, 12))
        ]
        cap = rng.randint(0, len(ids) + 2)

        order, named_count = github_ghas_reporter._named_first(
            [rule["id"] for rule in slim_rules],
            (result.get("ruleId") for result in slim_results),
        )

        assert ([slim_rules[i] for i in order][:cap], named_count) == (
            _oracle_named_first(slim_rules, slim_results, cap)
        )


def _result(rule_id: str, severity: str, *, located: bool = True) -> Result:
    return Result(
        ruleId=rule_id,
        level=Level.error,
        message=Message(text=f"{rule_id} {severity}"),
        properties=PropertyBag(issue_severity=severity),
        locations=(
            [
                Location(
                    physicalLocation=PhysicalLocation(
                        artifactLocation=ArtifactLocation(uri="src/a.py"),
                        region=Region(startLine=1),
                    )
                )
            ]
            if located
            else None
        ),
    )


def _model(results: List[Result]) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.sarif = SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="ASH")),
                results=results,
            )
        ],
    )
    return model


def _spelled(rule_id: str) -> str:
    """*rule_id* as the SARIF model holds it: a lone surrogate is already
    rewritten to its escape text there, so the document carries that spelling."""
    return _result(rule_id, "LOW").ruleId


@pytest.fixture
def reporter(test_plugin_context):
    return GHASReporter(context=test_plugin_context)


class TestARuleIdTheWireCannotCarryAsUtf8:
    """The whole document, with ids a UTF-8 column would refuse as written."""

    def test_a_lone_surrogate_rule_survives_scoring_and_the_cap(
        self, reporter, monkeypatch
    ):
        monkeypatch.setattr(github_ghas_reporter, "_MAX_RESULTS_PER_RUN", 2)
        results = [
            _result("\ud800", "LOW"),
            _result("\ud800", "CRITICAL"),
            _result("plain", "HIGH"),
            _result("\U0001f600", "MEDIUM"),
        ]

        out = reporter.report(_model(results))

        assert out is not None
        doc = json.loads(out)["runs"][0]
        assert [r["ruleId"] for r in doc["results"]] == [_spelled("\ud800"), "plain"]
        assert doc["results"][0]["message"]["text"].endswith(" CRITICAL")
        scores = {
            rule["id"]: rule["properties"]["security-severity"]
            for rule in doc["tool"]["driver"]["rules"]
        }
        # The cut LOW of the surrogate rule and the cut MEDIUM of the emoji rule
        # score nothing: the rules are scored from the results still in the file.
        assert scores == {
            _spelled("\ud800"): "9.5",
            "plain": "8.0",
            "\U0001f600": "6.0",
        }

    def test_the_rules_past_the_cap_are_the_unnamed_ones_whatever_their_spelling(
        self, reporter, monkeypatch
    ):
        monkeypatch.setattr(github_ghas_reporter, "_MAX_RULES_PER_RUN", 2)
        model = _model([_result("\U0010ffff", "HIGH"), _result("x\udc80y", "HIGH")])
        model.sarif.runs[0].tool.driver.rules = [
            ReportingDescriptor(id="\udc80unused-first"),
            ReportingDescriptor(id="\U0010ffff"),
            ReportingDescriptor(id=_spelled("x\udc80y")),
            ReportingDescriptor(id="unused-last"),
        ]

        doc = json.loads(reporter.report(model))["runs"][0]

        assert [rule["id"] for rule in doc["tool"]["driver"]["rules"]] == [
            "\U0010ffff",
            _spelled("x\udc80y"),
        ]

    def test_the_rules_with_no_located_result_are_named_sorted_in_the_warning(
        self, reporter, monkeypatch
    ):
        messages: List[str] = []

        class _Logger:
            def warning(self, message):
                messages.append(message)

            def __getattr__(self, name):
                return lambda *args, **kwargs: None

        monkeypatch.setattr(github_ghas_reporter, "ASH_LOGGER", _Logger())
        results = [
            _result("\U0001f600", "HIGH", located=False),
            _result("b", "HIGH", located=False),
            _result("\ud800", "HIGH", located=False),
            _result("a", "HIGH", located=False),
            _result("a", "LOW", located=False),
            _result("kept", "HIGH"),
        ]

        reporter.report(_model(results))

        (message,) = [m for m in messages if "carry no location" in m]
        assert message.startswith("GHAS report: 5 result(s) carry no location")
        expected = sorted({"a", "b", _spelled("\ud800"), "\U0001f600"})
        assert message.endswith("rules: " + ", ".join(expected))
