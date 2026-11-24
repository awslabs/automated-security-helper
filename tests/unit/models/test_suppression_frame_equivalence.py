# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The frame layer decides exactly what the one-pair-at-a-time matcher decided.

``REFERENCE`` below is the predicate matching as it was written before
``utils/suppression_frame.py`` replaced it, kept verbatim as an oracle (it calls
the same leaf helpers: ``path_matching``, ``scope_value_matches``, the scope
registry). A wrong match silences a real finding or un-silences a suppressed one,
so these tests generate findings and suppressions from deliberately awkward
value spaces (glob characters, brackets, case, unicode, ``**``, backslashes,
absent fields, huge and negative line numbers) and require the new layer and the
oracle to agree on:

* the verdict for a pair,
* the index ``first_match`` picks from a list,
* every observable side effect: which symbol-resolver and engine-plugin calls
  were made (and in what order), and the warn-once set.
"""

import fnmatch
from datetime import date

import pytest
from hypothesis import HealthCheck, given, reject, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from automated_security_helper.models import core as core_module
from automated_security_helper.models.core import AshSuppression, scope_value_matches
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils import suppression_frame
from automated_security_helper.utils import suppression_scope_registry as registry
from automated_security_helper.utils.path_matching import _path_pattern_matches
from automated_security_helper.utils.suppression_matcher import should_suppress_finding
from automated_security_helper.utils.symbol_spans import is_valid_symbol
from automated_security_helper.utils.unknown_keys import TOLERATE_STORED_CONFIG

pytestmark = pytest.mark.unit

ENGINE = "eq-engine"


# ---------------------------------------------------------------------------
# the oracle: the matcher as it was, one pair at a time
# ---------------------------------------------------------------------------


class REFERENCE:
    @staticmethod
    def matches(entry, finding, symbol_resolver=None, warned_engines=None) -> bool:
        if entry.is_expired or entry.has_unknown_keys:
            return False
        if entry.symbol is not None and not is_valid_symbol(entry.symbol):
            return False
        if entry.rule_id is not None and not entry.rule_id.strip():
            return False

        if entry.rule_id:
            if finding.rule_id is None:
                return False
            if finding.rule_id.lower() != entry.rule_id.lower() and not fnmatch.fnmatch(
                finding.rule_id.lower(), entry.rule_id.lower()
            ):
                if entry.scope is None:
                    return False
                base, qualifier = registry.split_rule_qualifier_for(
                    finding.scanner, finding.rule_id
                )
                if qualifier is None or (
                    base.lower() != entry.rule_id.lower()
                    and not fnmatch.fnmatch(base.lower(), entry.rule_id.lower())
                ):
                    return False

        if not _path_pattern_matches(finding.file_path, entry.path):
            return False
        if not REFERENCE.line_range(entry, finding):
            return False
        if not REFERENCE.package(entry, finding):
            return False
        if not REFERENCE.scope(entry, finding, warned_engines):
            return False
        if entry.symbol is not None:
            if symbol_resolver is None:
                return False
            return symbol_resolver.contains(
                finding.file_path, finding.line_start, finding.line_end, entry.symbol
            )
        return True

    @staticmethod
    def scope(entry, finding, warned_engines) -> bool:
        if entry._scope_conflict:
            return False
        scope = entry.scope
        if scope is None:
            return True
        if scope.selects_nothing or scope.has_unknown_keys:
            return False
        if scope.resource_id is not None:
            if finding.resource_id is None:
                return False
            if not scope_value_matches(
                finding.resource_id, scope.resource_id, case_sensitive=True
            ):
                return False
        if scope.resource_type is not None:
            if finding.resource_type is None:
                return False
            if not scope_value_matches(
                finding.resource_type, scope.resource_type, case_sensitive=False
            ):
                return False
        if scope.engines is not None:
            if finding.scanner is None or finding.scanner not in scope.engines:
                return False
            hooks = registry.engine_hooks_for(finding.scanner)
            if hooks is None:
                registry.warn_once_unmatched_engine(finding.scanner, warned_engines)
                return False
            if not hooks.suppression_scope_matches(
                scope.engines[finding.scanner], finding
            ):
                return False
        return True

    @staticmethod
    def package(entry, finding) -> bool:
        for pattern, value in (
            (entry.package_name, finding.package_name),
            (entry.package_version, finding.package_version),
        ):
            if pattern is None:
                continue
            if value is None or not fnmatch.fnmatch(value.lower(), pattern.lower()):
                return False
        if entry.package_path is not None:
            if finding.package_path is None:
                return False
            if not _path_pattern_matches(finding.package_path, entry.package_path):
                return False
        return True

    @staticmethod
    def line_range(entry, finding) -> bool:
        if entry.line_start is None and entry.line_end is None:
            return True
        if finding.line_start is None:
            return False
        finding_end = (
            finding.line_end if finding.line_end is not None else finding.line_start
        )
        if entry.line_start is not None and entry.line_end is None:
            return finding_end >= entry.line_start
        if entry.line_start is None and entry.line_end is not None:
            return finding_end <= entry.line_end
        return (finding.line_start <= (entry.line_end or 0)) and (
            finding_end >= (entry.line_start or 0)
        )

    @staticmethod
    def first(entries, finding, symbol_resolver=None, warned_engines=None):
        for index, entry in enumerate(entries):
            if REFERENCE.matches(entry, finding, symbol_resolver, warned_engines):
                return index
        return None


# ---------------------------------------------------------------------------
# doubles that record every call the matcher makes
# ---------------------------------------------------------------------------


class Journal:
    """Every call a matcher makes into a plugin or resolver, in order."""

    def __init__(self) -> None:
        self.events: list = []


class JournalResolver:
    def __init__(self, journal: Journal, answers: dict) -> None:
        self.journal, self.answers = journal, answers

    def contains(self, file_path, line_start, line_end, symbol) -> bool:
        self.journal.events.append(("symbol", file_path, line_start, line_end, symbol))
        return self.answers.get(symbol, False)


def install_hooks(journal: Journal):
    class Hooks:
        @classmethod
        def validate_suppression_scope(cls, block):
            return []

        @classmethod
        def suppression_scope_matches(cls, block, finding):
            journal.events.append(("block", block.get("marker"), finding.rule_id))
            return block.get("marker") == finding.rule_id

        @classmethod
        def split_rule_qualifier(cls, rule_id):
            journal.events.append(("split", rule_id))
            open_at = rule_id.find("[")
            if open_at == -1 or not rule_id.endswith("]"):
                return rule_id, None
            return rule_id[:open_at], rule_id[open_at + 1 : -1] or None

    return Hooks


# ---------------------------------------------------------------------------
# generators
# ---------------------------------------------------------------------------

RULE_ALPHABET = "BbCc026-_*?[]!:/äÄßsS "
RULES = st.one_of(
    st.sampled_from(
        [
            "B602",
            "b602",
            "B6*",
            "B?02",
            "[BC]602",
            "[!B]602",
            "*",
            "",
            " ",
            "Rule[Resource::*]",
            "Rule",
            "rule",
            "Rule[Resource::a]",
            "Rule[",
            "ÄB",
            "straße",
            "STRASSE",
        ]
    ),
    st.text(RULE_ALPHABET, max_size=8),
)

COMPONENTS = st.sampled_from(
    ["src", "tests", "a.py", "B.PY", "café", "ß", "日本", "..", ".", "a b", "x[1]", "x*", "?"]
)
PATH_PATTERN_PARTS = st.sampled_from(
    ["src", "tests", "*", "**", "*.py", "a.py", "café", "ß", "[ab]*", "?", ".", ""]
)
SEPARATORS = st.sampled_from(["/", "/", "/", "\\"])
FILE_PATHS = st.one_of(
    st.none(),
    st.sampled_from(["", ".", "a.py", "src/a.py", "src/sub/deep/a.py", "tests/t.py"]),
    st.builds(
        lambda parts, sep: sep.join(parts),
        st.lists(COMPONENTS, min_size=1, max_size=4),
        SEPARATORS,
    ),
    # a path read from disk that is not text: an unpaired surrogate
    st.just("src/\udc80.py"),
)
PATH_PATTERNS = st.one_of(
    st.sampled_from(["**", "*", "src/*.py", "src/**/*.py", "build/", "./", "", "."]),
    st.builds(
        lambda parts, sep, tail: sep.join(parts) + tail,
        st.lists(PATH_PATTERN_PARTS, min_size=1, max_size=4),
        SEPARATORS,
        st.sampled_from(["", "", "", "/"]),
    ),
    st.just("src/\udc80.py"),
)

LINES = st.one_of(
    st.none(),
    st.integers(-3, 25),
    st.sampled_from([0, 10**30, -(10**30), 2**63, 2**63 - 1, -(2**63)]),
)
PACKAGE_NAMES = st.one_of(
    st.none(), st.sampled_from(["lodash", "Lodash", "lod*", "LOD*", "[l]odash", "x"])
)
PACKAGE_PATHS = st.one_of(
    st.none(),
    st.sampled_from(["", "node_modules/a", "node_modules/**", "node_modules/a/", "**"]),
)
RESOURCE_VALUES = st.one_of(
    st.none(),
    st.sampled_from(
        ["Stack/Role", "stack/role", "Stack/*", "AWS::IAM::Policy", "aws::iam::policy", "a[b]c", "a[b]*"]
    ),
)
SCANNERS = st.sampled_from([ENGINE, "ghost", "bandit"])
SYMBOLS = st.one_of(st.none(), st.sampled_from(["f", "Cls.method", "${SYMBOL}"]))
SCOPES = st.one_of(
    st.none(),
    st.fixed_dictionaries({}, optional={"resource_id": RESOURCE_VALUES.filter(bool)}),
    st.fixed_dictionaries(
        {},
        optional={
            "resource_id": RESOURCE_VALUES.filter(bool),
            "resource_type": RESOURCE_VALUES.filter(bool),
            "engines": st.dictionaries(
                st.sampled_from([ENGINE, "ghost"]),
                st.fixed_dictionaries({"marker": st.sampled_from(["B602", "Rule", "x"])}),
                max_size=2,
            ),
            "bogus": st.just(1),
        },
    ),
)
EXPIRES = st.sampled_from([None, None, None, "2000-01-01", "2999-12-31", "not-a-date", ""])


def build_finding(values) -> FlatVulnerability:
    return FlatVulnerability.model_construct(
        id="f",
        title="t",
        description="d",
        severity="HIGH",
        scanner_type="SAST",
        **values,
    )


@st.composite
def findings(draw):
    return build_finding(
        {
            "scanner": draw(SCANNERS),
            "rule_id": draw(st.one_of(st.none(), RULES)),
            "file_path": draw(FILE_PATHS),
            "line_start": draw(LINES),
            "line_end": draw(LINES),
            "package_name": draw(PACKAGE_NAMES),
            "package_version": draw(st.one_of(st.none(), st.sampled_from(["1.0.0", "2.x"]))),
            "package_path": draw(PACKAGE_PATHS),
            "resource_id": draw(RESOURCE_VALUES),
            "resource_type": draw(RESOURCE_VALUES),
        }
    )


@st.composite
def suppressions(draw):
    values = {
        "path": draw(PATH_PATTERNS),
        "reason": "r",
        "rule_id": draw(st.one_of(st.none(), RULES)),
        "line_start": draw(LINES),
        "line_end": draw(LINES),
        "package_name": draw(PACKAGE_NAMES),
        "package_version": draw(st.one_of(st.none(), st.sampled_from(["1.0.0", "2.*", "x"]))),
        "package_path": draw(PACKAGE_PATHS),
        "symbol": draw(SYMBOLS),
        "expires": draw(EXPIRES),
    }
    scope = draw(SCOPES)
    if scope is not None:
        values["scope"] = scope
    values = {k: v for k, v in values.items() if v is not None}
    # every entry is built the way a results file keeps one, the one route that
    # admits the shapes a config refuses (blank ids, bad dates, unknown keys)
    if draw(st.booleans()):
        values["bogus_key"] = 1
    try:
        return AshSuppression.model_validate(
            values, context={TOLERATE_STORED_CONFIG: []}
        )
    except (ValidationError, ValueError):
        reject()


def resolver_answers(draw_bool):
    return {"f": draw_bool, "Cls.method": not draw_bool}


@pytest.fixture
def pinned_today(monkeypatch):
    monkeypatch.setattr(core_module, "current_date", lambda: date(2030, 6, 15))


def run_both(operation, entries, finding, answers):
    """Run ``operation(impl_name)`` under a fresh journal, for the oracle and the layer."""
    out = []
    for impl in ("reference", "frame"):
        journal = Journal()
        hooks = install_hooks(journal)
        previous = dict(registry._ENGINE_HOOKS)
        registry._ENGINE_HOOKS[ENGINE] = hooks
        registry.reset_unmatched_engine_warnings()
        warned: set = set()
        resolver = JournalResolver(journal, answers)
        try:
            verdict = operation(impl, entries, finding, resolver, warned)
        finally:
            registry._ENGINE_HOOKS.clear()
            registry._ENGINE_HOOKS.update(previous)
        out.append((verdict, journal.events, sorted(warned), sorted(registry._NO_ENGINE_WARNED)))
        registry.reset_unmatched_engine_warnings()
    return out


SETTINGS = settings(
    max_examples=400,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)


@pytest.mark.usefixtures("pinned_today")
class TestFrameLayerAgreesWithTheReference:
    @SETTINGS
    @given(entry=suppressions(), finding=findings(), answer=st.booleans(), use_resolver=st.booleans())
    def test_a_pair_verdict_and_every_call_made(self, entry, finding, answer, use_resolver):
        def operation(impl, entries, f, resolver, warned):
            r = resolver if use_resolver else None
            if impl == "reference":
                return REFERENCE.matches(entries[0], f, r, warned)
            return suppression_frame.matches(entries[0], f, r, warned)

        reference, frame = run_both(operation, [entry], finding, resolver_answers(answer))
        assert frame == reference

    @SETTINGS
    @given(entry=suppressions(), finding=findings(), answer=st.booleans())
    def test_the_public_method_is_the_layer(self, entry, finding, answer):
        def operation(impl, entries, f, resolver, warned):
            if impl == "reference":
                return REFERENCE.matches(entries[0], f, resolver, warned)
            return entries[0].matches(f, resolver, warned)

        reference, frame = run_both(operation, [entry], finding, resolver_answers(answer))
        assert frame == reference

    @SETTINGS
    @given(
        entries=st.lists(suppressions(), min_size=0, max_size=40),
        finding=findings(),
        answer=st.booleans(),
    )
    def test_the_first_match_and_nothing_read_after_it(self, entries, finding, answer):
        def operation(impl, entries, f, resolver, warned):
            if impl == "reference":
                return REFERENCE.first(entries, f, resolver, warned)
            hit = should_suppress_finding(f, entries, resolver, warned_engines=warned)
            return None if hit[1] is None else next(
                i for i, e in enumerate(entries) if e is hit[1]
            )

        reference, frame = run_both(operation, entries, finding, resolver_answers(answer))
        assert frame == reference

    @SETTINGS
    @given(finding=findings(), answer=st.booleans(), data=st.data())
    def test_a_list_longer_than_one_chunk_keeps_list_order(self, finding, answer, data):
        base = data.draw(st.lists(suppressions(), min_size=1, max_size=4))
        entries = (base * 40)[:130]

        def operation(impl, entries, f, resolver, warned):
            if impl == "reference":
                return REFERENCE.first(entries, f, resolver, warned)
            hit = should_suppress_finding(f, entries, resolver, warned_engines=warned)
            return None if hit[1] is None else next(
                i for i, e in enumerate(entries) if e is hit[1]
            )

        reference, frame = run_both(operation, entries, finding, resolver_answers(answer))
        assert frame == reference

    @SETTINGS
    @given(entry=suppressions(), finding=findings())
    def test_the_line_range_column_alone(self, entry, finding):
        assert suppression_frame.line_range_overlaps(finding, [entry]) == [
            REFERENCE.line_range(entry, finding)
        ]
        assert entry._line_range_matches(finding) is REFERENCE.line_range(entry, finding)
